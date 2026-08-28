use std::sync::Arc;
use std::time::Duration;

use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{ConnectErrorKind, LocalEndpoint, TargetAddr, TargetHostRef};
use ferrum2_crypto::{Clock, SecureRandom};
use ferrum2_dns::ApplicationResolverAdapter;
use ferrum2_net::{DialOptions, RouteNetworkOptions, TcpResolver};
use ferrum2_runtime::MAX_RESOLVED_CANDIDATES;
#[cfg(test)]
use ferrum2_shadowsocks::{BufferObserver, FlowObserver};
use ferrum2_shadowsocks::{ShadowsocksError, TransportIo};
#[cfg(test)]
use std::net::SocketAddr;

use super::context::{ClientOutboundContext, ClientRequestOrigin, SelectedEgress};
#[cfg(all(windows, not(test)))]
use super::network::ClientNetworkSocketService;
#[cfg(test)]
use super::network::system_application_resolver;
use super::network::{
    ClientDnsResetAction, ClientEgressNetworkResetState, ClientNetworkResetHub,
    ClientNetworkResetTargetRegistration, ClientPhysicalConnector, DefaultClientConnector,
    PolicyConnector,
};
use super::udp::{ClientUdpAssociation, ClientUdpContext};
use super::{tcp, udp};
#[cfg(all(windows, not(test)))]
use crate::run::RunError;

pub(in crate::run) struct ClientEgressEngine<
    C = DefaultClientConnector,
    T = ferrum2_crypto::SystemClock,
    R = ferrum2_crypto::SystemRandom,
> {
    pub(in crate::run) outbounds: Arc<[ClientOutboundContext]>,
    pub(in crate::run::egress) connector: Arc<C>,
    proxy_connectors: Arc<[PolicyConnector<C>]>,
    pub(in crate::run) clock: T,
    pub(in crate::run) random: R,
    pub(in crate::run::egress) phase_deadlines: (Duration, Duration),
    pub(in crate::run) udp: Option<ClientUdpContext>,
    pub(in crate::run) application_resolver: ApplicationResolverAdapter,
    pub(in crate::run::egress) direct_resolvers: Arc<[Option<ApplicationResolverAdapter>]>,
    pub(in crate::run) route_network: RouteNetworkOptions,
    network_reset_state: Arc<ClientEgressNetworkResetState>,
    network_reset_hub: ClientNetworkResetHub,
    _network_reset_registration: ClientNetworkResetTargetRegistration,
    #[cfg(test)]
    pub(in crate::run) udp_id_random: Option<Arc<dyn SecureRandom>>,
}

impl<C, T, R> ClientEgressEngine<C, T, R> {
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(in crate::run) fn new(
        outbounds: Arc<[ClientOutboundContext]>,
        connector: C,
        clock: T,
        random: R,
        phase_deadlines: (Duration, Duration),
        udp: Option<ClientUdpContext>,
        #[cfg(test)] udp_id_random: Option<Arc<dyn SecureRandom>>,
    ) -> Self {
        Self::new_with_application_resolver(
            outbounds,
            connector,
            clock,
            random,
            phase_deadlines,
            udp,
            system_application_resolver(),
            #[cfg(test)]
            udp_id_random,
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(in crate::run) fn new_with_application_resolver(
        outbounds: Arc<[ClientOutboundContext]>,
        connector: C,
        clock: T,
        random: R,
        phase_deadlines: (Duration, Duration),
        udp: Option<ClientUdpContext>,
        application_resolver: ApplicationResolverAdapter,
        #[cfg(test)] udp_id_random: Option<Arc<dyn SecureRandom>>,
    ) -> Self {
        let direct_resolvers = outbounds
            .iter()
            .map(|outbound| {
                matches!(outbound, ClientOutboundContext::Direct { .. })
                    .then(|| application_resolver.clone())
            })
            .collect::<Vec<_>>()
            .into();
        Self::new_with_direct_resolvers(
            outbounds,
            connector,
            clock,
            random,
            phase_deadlines,
            udp,
            application_resolver,
            direct_resolvers,
            #[cfg(test)]
            udp_id_random,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::run) fn new_with_direct_resolvers(
        outbounds: Arc<[ClientOutboundContext]>,
        connector: C,
        clock: T,
        random: R,
        phase_deadlines: (Duration, Duration),
        udp: Option<ClientUdpContext>,
        application_resolver: ApplicationResolverAdapter,
        direct_resolvers: Arc<[Option<ApplicationResolverAdapter>]>,
        #[cfg(test)] udp_id_random: Option<Arc<dyn SecureRandom>>,
    ) -> Self {
        debug_assert_eq!(outbounds.len(), direct_resolvers.len());
        let connector = Arc::new(connector);
        let route_network = RouteNetworkOptions::default();
        let network_reset_state = Arc::new(ClientEgressNetworkResetState::new(udp.as_ref()));
        let network_reset_hub = ClientNetworkResetHub::default();
        let network_reset_registration = network_reset_hub
            .register(&network_reset_state)
            .expect("a private client reset hub always accepts its only engine");
        let proxy_connectors = outbounds
            .iter()
            .map(|outbound| PolicyConnector {
                connector: Arc::clone(&connector),
                dial_options: outbound.dial_options().clone(),
                route_network: route_network.clone(),
            })
            .collect::<Vec<_>>()
            .into();
        Self {
            outbounds,
            connector,
            proxy_connectors,
            clock,
            random,
            phase_deadlines,
            udp,
            application_resolver,
            direct_resolvers,
            route_network,
            network_reset_state,
            network_reset_hub,
            _network_reset_registration: network_reset_registration,
            #[cfg(test)]
            udp_id_random,
        }
    }

    pub(in crate::run) fn with_route_network(mut self, route_network: RouteNetworkOptions) -> Self {
        self.proxy_connectors = self
            .outbounds
            .iter()
            .map(|outbound| PolicyConnector {
                connector: Arc::clone(&self.connector),
                dial_options: outbound.dial_options().clone(),
                route_network: route_network.clone(),
            })
            .collect::<Vec<_>>()
            .into();
        self.route_network = route_network;
        self
    }

    #[cfg(all(windows, not(test)))]
    pub(in crate::run) fn with_shared_network_reset(
        mut self,
        service: &ClientNetworkSocketService,
    ) -> Result<Self, RunError> {
        let hub = service.reset_hub();
        let registration = hub
            .register(&self.network_reset_state)
            .map_err(|()| RunError::StartupProtocol)?;
        self._network_reset_registration = registration;
        self.network_reset_hub = hub;
        Ok(self)
    }

    pub(in crate::run) fn register_dns_reset_action(
        &self,
        action: &Arc<ClientDnsResetAction>,
    ) -> Result<(), ()> {
        self.network_reset_state.register_dns_action(action)
    }

    pub(in crate::run) fn reset_network(&self) -> usize {
        self.network_reset_hub.reset()
    }

    fn classify_selected(
        &self,
        origin: ClientRequestOrigin,
        plan: Option<&EgressPlanSnapshot>,
        target: Option<&TargetAddr>,
    ) -> Result<SelectedEgress, ClientPlanFailure> {
        if origin != ClientRequestOrigin::Socks && target.is_none() {
            return Err(ClientPlanFailure::Invalid);
        }
        let Some(plan) = plan else {
            return if matches!(
                origin,
                ClientRequestOrigin::Dns | ClientRequestOrigin::RuleSet
            ) && target.and_then(TargetAddr::as_socket_addr).is_some()
            {
                Ok(SelectedEgress::Direct { outbound: None })
            } else {
                Err(ClientPlanFailure::Invalid)
            };
        };
        let hops = plan.hops();
        if hops.is_empty() || hops.len() > udp::MAX_UDP_PLAN_HOPS {
            return Err(ClientPlanFailure::Invalid);
        }
        let mut direct = 0;
        for hop in hops {
            match self.outbounds.get(*hop) {
                Some(ClientOutboundContext::Shadowsocks(_)) => {}
                Some(ClientOutboundContext::Direct { .. }) => direct += 1,
                None => return Err(ClientPlanFailure::Invalid),
            }
        }
        if direct == 1 && hops.len() == 1 {
            return Ok(SelectedEgress::Direct {
                outbound: Some(hops[0]),
            });
        }
        if direct != 0 {
            return Err(ClientPlanFailure::Invalid);
        }
        Ok(SelectedEgress::Shadowsocks {
            first_outbound: hops[0],
            first_server: self.outbounds[hops[0]]
                .shadowsocks()
                .expect("classified Shadowsocks plan")
                .udp_server,
        })
    }

    pub(in crate::run) async fn open_tcp_for_ingress<'a>(
        &'a self,
        origin: ClientRequestOrigin,
        ingress: usize,
        plan: Option<EgressPlanSnapshot>,
        application_target: &TargetAddr,
        timeout_limit: Option<Duration>,
        #[cfg(test)] observers: Option<(&'a dyn BufferObserver, &'a dyn FlowObserver)>,
    ) -> Result<tcp::ClientTcpFlow<'a, C::Stream, T>, ClientOpenFailure>
    where
        C: ClientPhysicalConnector,
        C::Stream: TransportIo + LocalEndpoint + 'a,
        T: Clock + Sync,
        R: SecureRandom,
    {
        let selected = self
            .classify_selected(origin, plan.as_ref(), Some(application_target))
            .map_err(ClientOpenFailure::Plan)?;
        if let SelectedEgress::Direct { outbound } = selected {
            let deadline = timeout_limit
                .unwrap_or(self.phase_deadlines.0)
                .min(self.phase_deadlines.0);
            let deadline = tokio::time::Instant::now() + deadline;
            let candidates = match application_target.host() {
                TargetHostRef::Ip(_) => vec![application_target.clone()],
                TargetHostRef::Domain(host) => {
                    let resolver = match outbound {
                        Some(outbound) => self
                            .direct_resolvers
                            .get(outbound)
                            .and_then(Option::as_ref)
                            .ok_or(ClientOpenFailure::Connect(
                                ConnectErrorKind::HostUnreachable,
                            ))?,
                        None => &self.application_resolver,
                    }
                    .for_ingress(ingress);
                    let resolved = match tokio::time::timeout_at(
                        deadline,
                        TcpResolver::resolve(&resolver, host, application_target.port().get()),
                    )
                    .await
                    {
                        Ok(Ok(resolved)) => resolved,
                        Ok(Err(_)) => {
                            return Err(ClientOpenFailure::Connect(
                                ConnectErrorKind::HostUnreachable,
                            ));
                        }
                        Err(_) => {
                            return Err(ClientOpenFailure::Connect(ConnectErrorKind::Timeout));
                        }
                    };
                    resolved
                        .into_iter()
                        .take(MAX_RESOLVED_CANDIDATES)
                        .filter_map(|candidate| TargetAddr::ip(candidate).ok())
                        .collect()
                }
            };
            let default_dial_options = DialOptions::default();
            let dial_options = outbound
                .and_then(|index| self.outbounds.get(index))
                .map_or(&default_dial_options, ClientOutboundContext::dial_options);
            let mut attempted = false;
            let mut last = ConnectErrorKind::HostUnreachable;
            for target in candidates {
                if tokio::time::Instant::now() >= deadline {
                    return Err(ClientOpenFailure::Connect(ConnectErrorKind::Timeout));
                }
                attempted = true;
                let connect =
                    self.connector
                        .connect_physical(&target, dial_options, &self.route_network);
                match tokio::time::timeout_at(deadline, connect).await {
                    Ok(Ok(stream)) => return Ok(tcp::ClientTcpFlow::Direct(stream)),
                    Ok(Err(error)) => last = error.kind(),
                    Err(_) => {
                        return Err(ClientOpenFailure::Connect(ConnectErrorKind::Timeout));
                    }
                }
            }
            return Err(ClientOpenFailure::Connect(if attempted {
                last
            } else {
                ConnectErrorKind::HostUnreachable
            }));
        }
        let plan = plan.expect("classified proxy plan has a snapshot");
        let SelectedEgress::Shadowsocks { first_outbound, .. } = selected else {
            unreachable!("classified proxy plan")
        };
        let deadlines = timeout_limit.map_or(self.phase_deadlines, |limit| {
            (
                limit.min(self.phase_deadlines.0),
                limit.min(self.phase_deadlines.1),
            )
        });
        let open = tcp::open(
            &self.outbounds,
            plan.hops(),
            &self.proxy_connectors[first_outbound],
            &self.clock,
            &self.random,
            application_target,
            deadlines,
            #[cfg(test)]
            observers,
        );
        match open.await? {
            tcp::ClientProxyTcpFlow::Single(flow) if origin == ClientRequestOrigin::Socks => {
                Ok(tcp::ClientTcpFlow::SingleProxy(flow))
            }
            tcp::ClientProxyTcpFlow::Single(flow) => {
                Ok(tcp::ClientTcpFlow::Proxy(flow.into_boxed()))
            }
            tcp::ClientProxyTcpFlow::Chain(flow) => Ok(tcp::ClientTcpFlow::Proxy(flow)),
        }
    }

    pub(in crate::run) async fn prepare_udp_for_ingress(
        &self,
        origin: ClientRequestOrigin,
        ingress: usize,
        plan: Option<EgressPlanSnapshot>,
        target: Option<&TargetAddr>,
    ) -> Result<ClientUdpAssociation, ClientUdpPrepareFailure>
    where
        C: ClientPhysicalConnector,
    {
        let selected = self
            .classify_selected(origin, plan.as_ref(), target)
            .map_err(ClientUdpPrepareFailure::Plan)?;
        udp::prepare(
            self,
            origin,
            ingress,
            plan,
            selected,
            target,
            tokio::net::UdpSocket::bind,
        )
        .await
        .map_err(|()| ClientUdpPrepareFailure::Unavailable)
    }

    #[cfg(test)]
    pub(in crate::run) async fn prepare_udp_with<F, Fut>(
        &self,
        plan: EgressPlanSnapshot,
        bind: F,
    ) -> Result<ClientUdpAssociation, ClientUdpPrepareFailure>
    where
        C: ClientPhysicalConnector,
        F: FnMut(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = std::io::Result<tokio::net::UdpSocket>>,
    {
        let selected = self
            .classify_selected(ClientRequestOrigin::Socks, Some(&plan), None)
            .map_err(ClientUdpPrepareFailure::Plan)?;
        udp::prepare(
            self,
            ClientRequestOrigin::Socks,
            0,
            Some(plan),
            selected,
            None,
            bind,
        )
        .await
        .map_err(|()| ClientUdpPrepareFailure::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::run) enum ClientPlanFailure {
    Invalid,
}

#[derive(Debug)]
pub(in crate::run) enum ClientOpenFailure {
    Plan(ClientPlanFailure),
    Connect(ferrum2_core::ConnectErrorKind),
    Protocol(ShadowsocksError),
    HandshakeTimeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::run) enum ClientUdpPrepareFailure {
    Plan(ClientPlanFailure),
    Unavailable,
}

#[cfg(test)]
#[path = "m16_tests/mod.rs"]
mod m16_tests;
