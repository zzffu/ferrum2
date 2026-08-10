mod tcp;
mod udp;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{Connector, LocalEndpoint, TargetAddr};
use ferrum2_crypto::{Clock, MethodSinglePskProvider, SecureRandom};
use ferrum2_shadowsocks::{BoxedClientFlow, MethodKeyAdapter, ShadowsocksError, TransportIo};
#[cfg(test)]
use ferrum2_shadowsocks::{BufferObserver, FlowObserver};

use super::RunError;
use super::tokio_io::TokioConnector;

pub(super) use udp::{
    ClientUdpAssociation, ClientUdpContext, UdpPlanResponseError, UdpSendError,
    composed_udp_plan_limit, send_with_lifecycle,
};
#[cfg(test)]
pub(super) use udp::{
    IdSequenceRandom, MAX_UDP_PLAN_HOPS, UdpIoFaultPlan, UdpIoOperation,
    composed_udp_request_limit, composed_udp_response_limit,
};

pub(super) enum ClientOutboundContext {
    Shadowsocks(ClientShadowsocksContext),
    Direct,
}

pub(super) struct ClientShadowsocksContext {
    pub(super) tcp_server: TargetAddr,
    pub(super) udp_server: SocketAddr,
    pub(super) keys: MethodKeyAdapter<MethodSinglePskProvider>,
}

impl ClientOutboundContext {
    pub(super) fn shadowsocks(&self) -> Option<&ClientShadowsocksContext> {
        match self {
            Self::Shadowsocks(outbound) => Some(outbound),
            Self::Direct => None,
        }
    }
}

pub(super) fn prepare_client_outbounds(
    outbounds: Vec<ferrum2_config::ClientOutboundConfig>,
) -> Result<Arc<[ClientOutboundContext]>, RunError> {
    if outbounds.is_empty() {
        return Err(RunError::StartupProtocol);
    }
    outbounds
        .into_iter()
        .map(|outbound| {
            Ok(match outbound {
                ferrum2_config::ClientOutboundConfig::Shadowsocks { server, psk } => {
                    ClientOutboundContext::Shadowsocks(ClientShadowsocksContext {
                        tcp_server: TargetAddr::ip(server)
                            .map_err(|_| RunError::StartupProtocol)?,
                        udp_server: server,
                        keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(psk)),
                    })
                }
                ferrum2_config::ClientOutboundConfig::Direct => ClientOutboundContext::Direct,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Arc::from)
}

pub(super) struct ClientEgressEngine<
    C = TokioConnector<ferrum2_runtime::TcpConnector>,
    T = ferrum2_crypto::SystemClock,
    R = ferrum2_crypto::SystemRandom,
> {
    pub(super) outbounds: Arc<[ClientOutboundContext]>,
    connector: C,
    pub(super) clock: T,
    pub(super) random: R,
    phase_deadlines: (Duration, Duration),
    pub(super) udp: Option<ClientUdpContext>,
    #[cfg(test)]
    pub(super) udp_id_random: Option<Arc<dyn SecureRandom>>,
}

impl<C, T, R> ClientEgressEngine<C, T, R> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        outbounds: Arc<[ClientOutboundContext]>,
        connector: C,
        clock: T,
        random: R,
        phase_deadlines: (Duration, Duration),
        udp: Option<ClientUdpContext>,
        #[cfg(test)] udp_id_random: Option<Arc<dyn SecureRandom>>,
    ) -> Self {
        Self {
            outbounds,
            connector,
            clock,
            random,
            phase_deadlines,
            udp,
            #[cfg(test)]
            udp_id_random,
        }
    }

    pub(super) fn classify_selected_hops(
        &self,
        hops: &[usize],
    ) -> Result<SocketAddr, ClientPlanFailure> {
        if hops.is_empty() || hops.len() > udp::MAX_UDP_PLAN_HOPS {
            return Err(ClientPlanFailure::Invalid);
        }
        let mut direct = 0;
        for hop in hops {
            match self.outbounds.get(*hop) {
                Some(ClientOutboundContext::Shadowsocks(_)) => {}
                Some(ClientOutboundContext::Direct) => direct += 1,
                None => return Err(ClientPlanFailure::Invalid),
            }
        }
        if direct != 0 {
            return Err(if direct == 1 && hops.len() == 1 {
                ClientPlanFailure::DirectUnsupported
            } else {
                ClientPlanFailure::Invalid
            });
        }
        Ok(self.outbounds[hops[0]]
            .shadowsocks()
            .expect("classified Shadowsocks plan")
            .udp_server)
    }

    pub(super) async fn open_tcp<'a>(
        &'a self,
        plan: EgressPlanSnapshot,
        application_target: &TargetAddr,
        timeout_limit: Option<Duration>,
        #[cfg(test)] observers: Option<(&'a dyn BufferObserver, &'a dyn FlowObserver)>,
    ) -> Result<BoxedClientFlow<'a>, ClientOpenFailure>
    where
        C: Connector,
        C::Stream: TransportIo + LocalEndpoint + 'a,
        T: Clock + Sync,
        R: SecureRandom,
    {
        self.classify_selected_hops(plan.hops())
            .map_err(ClientOpenFailure::Plan)?;
        let deadlines = timeout_limit.map_or(self.phase_deadlines, |limit| {
            (
                limit.min(self.phase_deadlines.0),
                limit.min(self.phase_deadlines.1),
            )
        });
        tcp::open(
            &self.outbounds,
            plan.hops(),
            &self.connector,
            &self.clock,
            &self.random,
            application_target,
            deadlines,
            #[cfg(test)]
            observers,
        )
        .await
    }

    pub(super) async fn prepare_udp<F, Fut>(
        &self,
        plan: EgressPlanSnapshot,
        bind: F,
    ) -> Result<ClientUdpAssociation, ClientUdpPrepareFailure>
    where
        F: FnMut(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = std::io::Result<tokio::net::UdpSocket>>,
    {
        let first_server = self
            .classify_selected_hops(plan.hops())
            .map_err(ClientUdpPrepareFailure::Plan)?;
        udp::prepare(self, plan, first_server, bind)
            .await
            .map_err(|()| ClientUdpPrepareFailure::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClientPlanFailure {
    DirectUnsupported,
    Invalid,
}

#[derive(Debug)]
pub(super) enum ClientOpenFailure {
    Plan(ClientPlanFailure),
    Protocol(ShadowsocksError),
    HandshakeTimeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClientUdpPrepareFailure {
    Plan(ClientPlanFailure),
    Unavailable,
}

#[cfg(test)]
mod m16_tests {
    use super::*;
    use crate::run::test_support::*;

    fn proxy() -> ferrum2_config::ClientOutboundConfig {
        ferrum2_config::ClientOutboundConfig::Shadowsocks {
            server: "127.0.0.1:8388".parse().unwrap(),
            psk: ferrum2_crypto::MethodPsk::aes128([0; 16]),
        }
    }

    fn selected(hops: Vec<usize>) -> EgressPlanSnapshot {
        let route = compile_selector_plans_with_roots(
            &[TaggedInbound::new("entry", 0)],
            &[
                TaggedOutbound::new("direct-a", 0),
                TaggedOutbound::new("direct-b", 1),
                TaggedOutbound::new("proxy", 2),
            ],
            &[TaggedPlan::new("selected", hops)],
            &[],
            TaggedRoute::Static(vec![TaggedStaticBinding::new("entry", "selected")]),
            &["direct-a", "direct-b", "proxy"],
        )
        .expect("selected plan")
        .0;
        route.select_plan_snapshot(
            0,
            ferrum2_core::route::Network::Tcp,
            &TargetAddr::domain("snapshot.invalid", 443).unwrap(),
        )
    }

    #[tokio::test]
    async fn m16_direct_pre_socket_classifies_actual_snapshot_without_side_effects() {
        assert_eq!(
            prepare_client_outbounds(Vec::new()).err().unwrap(),
            RunError::StartupProtocol
        );
        let outbounds = prepare_client_outbounds(vec![
            ferrum2_config::ClientOutboundConfig::Direct,
            ferrum2_config::ClientOutboundConfig::Direct,
            proxy(),
        ])
        .expect("closed outbound catalog");
        let connector_calls = Arc::new(AtomicUsize::new(0));
        let bind_calls = Arc::new(AtomicUsize::new(0));
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let engine = ClientEgressEngine::new(
            outbounds,
            TokioConnector::new(FailingConnector {
                calls: Arc::clone(&connector_calls),
            }),
            SystemClock::new(),
            FixedRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some(ClientUdpContext {
                manager: UdpSessionManager::new(UdpRuntimeLimits::default(), registry.clone()),
                live_ids: Arc::new(Mutex::new(HashSet::new())),
            }),
            None,
        );
        assert_eq!(
            engine.classify_selected_hops(&[]),
            Err(ClientPlanFailure::Invalid)
        );
        assert_eq!(
            engine.classify_selected_hops(&[2]),
            Ok("127.0.0.1:8388".parse().unwrap())
        );

        let target = TargetAddr::domain("application.invalid", 443).unwrap();
        for (name, plan, expected) in [
            (
                "singleton direct",
                ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned(),
                ClientPlanFailure::DirectUnsupported,
            ),
            ("mixed", selected(vec![0, 2]), ClientPlanFailure::Invalid),
            (
                "multi direct",
                selected(vec![0, 1]),
                ClientPlanFailure::Invalid,
            ),
            (
                "out of range",
                ferrum2_core::route::EgressPlanHandle::direct(3).snapshot_owned(),
                ClientPlanFailure::Invalid,
            ),
        ] {
            assert!(
                matches!(
                    engine.open_tcp(plan.clone(), &target, None, None).await,
                    Err(ClientOpenFailure::Plan(actual)) if actual == expected
                ),
                "TCP {name}"
            );
            let calls = Arc::clone(&bind_calls);
            assert_eq!(
                engine
                    .prepare_udp(plan, move |_| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        async { Err(io::Error::other("binder must not run")) }
                    })
                    .await
                    .err(),
                Some(ClientUdpPrepareFailure::Plan(expected)),
                "UDP {name}"
            );
            assert_eq!(connector_calls.load(Ordering::SeqCst), 0, "TCP {name}");
            assert_eq!(bind_calls.load(Ordering::SeqCst), 0, "UDP {name}");
            assert_eq!(registry.snapshot(), baseline, "owners {name}");
        }
    }
}
