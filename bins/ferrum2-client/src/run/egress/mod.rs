mod tcp;
mod udp;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{Connector, LocalEndpoint, TargetAddr};
use ferrum2_crypto::{Clock, MethodSinglePskProvider, SecureRandom};
#[cfg(test)]
use ferrum2_shadowsocks::{BufferObserver, FlowObserver};
use ferrum2_shadowsocks::{MethodKeyAdapter, ShadowsocksError, TransportIo};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClientRequestOrigin {
    Socks,
    Tun,
    Dns,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectedEgress {
    Direct,
    Shadowsocks { first_server: SocketAddr },
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
            return if origin == ClientRequestOrigin::Dns {
                Ok(SelectedEgress::Direct)
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
                Some(ClientOutboundContext::Direct) => direct += 1,
                None => return Err(ClientPlanFailure::Invalid),
            }
        }
        if direct == 1 && hops.len() == 1 {
            #[cfg(windows)]
            if origin == ClientRequestOrigin::Tun
                && target
                    .and_then(TargetAddr::as_socket_addr)
                    .is_some_and(|target| target.is_ipv6())
            {
                return Err(ClientPlanFailure::DirectIpv6Unsupported);
            }
            return Ok(SelectedEgress::Direct);
        }
        if direct != 0 {
            return Err(ClientPlanFailure::Invalid);
        }
        Ok(SelectedEgress::Shadowsocks {
            first_server: self.outbounds[hops[0]]
                .shadowsocks()
                .expect("classified Shadowsocks plan")
                .udp_server,
        })
    }

    pub(super) async fn open_tcp<'a>(
        &'a self,
        origin: ClientRequestOrigin,
        plan: Option<EgressPlanSnapshot>,
        application_target: &TargetAddr,
        timeout_limit: Option<Duration>,
        #[cfg(test)] observers: Option<(&'a dyn BufferObserver, &'a dyn FlowObserver)>,
    ) -> Result<tcp::ClientTcpFlow<'a, C::Stream>, ClientOpenFailure>
    where
        C: Connector,
        C::Stream: TransportIo + LocalEndpoint + 'a,
        T: Clock + Sync,
        R: SecureRandom,
    {
        let selected = self
            .classify_selected(origin, plan.as_ref(), Some(application_target))
            .map_err(ClientOpenFailure::Plan)?;
        if selected == SelectedEgress::Direct {
            let deadline = timeout_limit
                .unwrap_or(self.phase_deadlines.0)
                .min(self.phase_deadlines.0);
            return match tokio::time::timeout(deadline, self.connector.connect(application_target))
                .await
            {
                Ok(Ok(stream)) => Ok(tcp::ClientTcpFlow::Direct(stream)),
                Ok(Err(error)) => Err(ClientOpenFailure::Connect(error.kind())),
                Err(_) => Err(ClientOpenFailure::Connect(
                    ferrum2_core::ConnectErrorKind::Timeout,
                )),
            };
        }
        let plan = plan.expect("classified proxy plan has a snapshot");
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
        .map(tcp::ClientTcpFlow::Proxy)
    }

    pub(super) async fn prepare_udp(
        &self,
        origin: ClientRequestOrigin,
        plan: Option<EgressPlanSnapshot>,
        target: Option<&TargetAddr>,
    ) -> Result<ClientUdpAssociation, ClientUdpPrepareFailure> {
        let selected = self
            .classify_selected(origin, plan.as_ref(), target)
            .map_err(ClientUdpPrepareFailure::Plan)?;
        udp::prepare(self, plan, selected, tokio::net::UdpSocket::bind)
            .await
            .map_err(|()| ClientUdpPrepareFailure::Unavailable)
    }

    #[cfg(test)]
    pub(super) async fn prepare_udp_with<F, Fut>(
        &self,
        plan: EgressPlanSnapshot,
        bind: F,
    ) -> Result<ClientUdpAssociation, ClientUdpPrepareFailure>
    where
        F: FnMut(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = std::io::Result<tokio::net::UdpSocket>>,
    {
        let selected = self
            .classify_selected(ClientRequestOrigin::Socks, Some(&plan), None)
            .map_err(ClientUdpPrepareFailure::Plan)?;
        udp::prepare(self, Some(plan), selected, bind)
            .await
            .map_err(|()| ClientUdpPrepareFailure::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClientPlanFailure {
    #[cfg(windows)]
    DirectIpv6Unsupported,
    Invalid,
}

#[derive(Debug)]
pub(super) enum ClientOpenFailure {
    Plan(ClientPlanFailure),
    Connect(ferrum2_core::ConnectErrorKind),
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

    #[derive(Clone, Default)]
    struct TraceCapture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for &TraceCapture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("trace capture")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn proxy() -> ferrum2_config::ClientOutboundConfig {
        ferrum2_config::ClientOutboundConfig::Shadowsocks {
            server: "198.51.100.222:62016".parse().unwrap(),
            psk: ferrum2_crypto::MethodPsk::aes128(*b"m16-secret-key!!"),
        }
    }

    fn selected(hops: Vec<usize>) -> EgressPlanSnapshot {
        let route = compile_selector_plans_with_roots(
            &[TaggedInbound::new("entry", 0)],
            &[
                TaggedOutbound::new("direct-a", 0),
                TaggedOutbound::new("direct-b", 1),
                TaggedOutbound::new("m16-tag-sentinel", 2),
            ],
            &[TaggedPlan::new("selected", hops)],
            &[],
            TaggedRoute::Static(vec![TaggedStaticBinding::new("entry", "selected")]),
            &["direct-a", "direct-b", "m16-tag-sentinel"],
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
    async fn m16_direct_pre_socket_and_m16_redaction_classify_without_side_effects() {
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
        let target = TargetAddr::domain("m16-target-sentinel.invalid", 443).unwrap();
        for (name, plan, expected) in [
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
                    engine
                        .open_tcp(
                            ClientRequestOrigin::Socks,
                            Some(plan.clone()),
                            &target,
                            None,
                            None,
                        )
                        .await,
                    Err(ClientOpenFailure::Plan(actual)) if actual == expected
                ),
                "TCP {name}"
            );
            let calls = Arc::clone(&bind_calls);
            assert_eq!(
                engine
                    .prepare_udp_with(plan, move |_| {
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

        assert!(matches!(
            engine
                .open_tcp(ClientRequestOrigin::Socks, None, &target, None, None)
                .await,
            Err(ClientOpenFailure::Plan(ClientPlanFailure::Invalid))
        ));
        assert_eq!(connector_calls.load(Ordering::SeqCst), 0);

        let mixed = selected(vec![0, 2]);
        let redacted_tcp = format!(
            "{:?}",
            engine
                .open_tcp(
                    ClientRequestOrigin::Socks,
                    Some(mixed.clone()),
                    &target,
                    None,
                    None,
                )
                .await
                .err()
                .unwrap()
        );
        let redacted_udp = format!(
            "{:?}",
            engine
                .prepare_udp(ClientRequestOrigin::Socks, Some(mixed), Some(&target))
                .await
                .err()
                .unwrap()
        );
        let dns_target = TargetAddr::domain("m16-dns-sentinel.invalid", 53).unwrap();
        let direct = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
        let packet_registry = OwnerRegistry::new();
        let packet_live_ids = Arc::new(Mutex::new(HashSet::new()));
        let packet_engine = ClientEgressEngine::new(
            prepare_client_outbounds(vec![ferrum2_config::ClientOutboundConfig::Direct])
                .expect("packet direct outbound"),
            TokioConnector::new(ferrum2_runtime::TcpConnector::new(Duration::from_secs(1))),
            ferrum2_crypto::SystemClock::new(),
            ferrum2_crypto::SystemRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some(ClientUdpContext {
                manager: UdpSessionManager::new(
                    UdpRuntimeLimits::default(),
                    packet_registry.clone(),
                ),
                live_ids: Arc::clone(&packet_live_ids),
            }),
            None,
        );
        let mut association = packet_engine
            .prepare_udp(
                ClientRequestOrigin::Dns,
                Some(direct.clone()),
                Some(&dns_target),
            )
            .await
            .expect("redaction direct UDP association");
        let mut packet = vec![0_u8; ferrum2_runtime::MAX_UDP_WIRE_DATAGRAM_BYTES + 1];
        packet[..19].copy_from_slice(b"m16-packet-sentinel");
        let packet_error = match association.prepare_application_request(
            &packet_engine,
            &packet_engine.outbounds,
            dns_target.clone(),
            &packet,
            Instant::now(),
        ) {
            Err(UdpPlanResponseError::Packet(error)) => format!("{error:?}"),
            Err(UdpPlanResponseError::Runtime(_)) | Ok(_) => panic!("fixed packet bound error"),
        };
        drop(association);
        assert_eq!(packet_registry.snapshot(), OwnerSnapshot::default());
        assert!(
            packet_live_ids
                .lock()
                .expect("packet SIP022 IDs")
                .is_empty()
        );

        let connect_kind = match engine
            .open_tcp(
                ClientRequestOrigin::Dns,
                Some(direct),
                &dns_target,
                None,
                None,
            )
            .await
        {
            Err(ClientOpenFailure::Connect(kind)) => kind,
            _ => panic!("fixed direct connect failure"),
        };
        assert_eq!(connect_kind, ferrum2_core::ConnectErrorKind::Other);
        let reason = ferrum2_observability::Reason::RelayIo;
        let metrics = Metrics::new();
        metrics.failure(
            ferrum2_observability::Role::Client,
            ferrum2_observability::Stage::Relay,
            reason,
        );
        let trace = Arc::new(TraceCapture::default());
        let subscriber = ferrum2_observability::json_subscriber(
            Arc::clone(&trace),
            ferrum2_observability::LogLevel::Trace,
        );
        let dispatch = tracing::Dispatch::new(subscriber);
        tracing::dispatcher::with_default(&dispatch, || {
            ferrum2_observability::emit(
                ferrum2_observability::TraceRecord::new(
                    ferrum2_observability::LogLevel::Warn,
                    ferrum2_observability::Event::Failure,
                    ferrum2_observability::Role::Client,
                    ferrum2_observability::Stage::Relay,
                    ferrum2_observability::Outcome::Failed,
                )
                .with_reason(reason),
            );
        });
        let trace = String::from_utf8(trace.0.lock().expect("trace capture").clone()).unwrap();
        let metrics = metrics.encode_text().expect("closed metrics");
        assert_eq!(redacted_tcp, "Plan(Invalid)");
        assert_eq!(redacted_udp, "Plan(Invalid)");
        assert_eq!(packet_error, "Bounds");
        for sentinel in [
            "m16-target-sentinel.invalid",
            "198.51.100.222:62016",
            "m16-dns-sentinel.invalid",
            "m16-tag-sentinel",
            "m16-packet-sentinel",
            "m16-secret-key!!",
        ] {
            for output in [
                &redacted_tcp,
                &redacted_udp,
                &packet_error,
                &trace,
                &metrics,
            ] {
                assert!(!output.contains(sentinel), "leaked sentinel in {output}");
            }
        }
        assert_eq!(connector_calls.load(Ordering::SeqCst), 1);
        assert_eq!(registry.snapshot(), baseline);

        #[cfg(windows)]
        {
            let ipv6 = TargetAddr::ip("[2001:db8::1]:443".parse().unwrap()).unwrap();
            let plan = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
            let tcp = engine
                .open_tcp(
                    ClientRequestOrigin::Tun,
                    Some(plan.clone()),
                    &ipv6,
                    None,
                    None,
                )
                .await;
            assert!(
                matches!(
                    tcp,
                    Err(ClientOpenFailure::Plan(
                        ClientPlanFailure::DirectIpv6Unsupported
                    ))
                ),
                "TUN TCP direct IPv6"
            );
            assert_eq!(
                engine
                    .prepare_udp(ClientRequestOrigin::Tun, Some(plan), Some(&ipv6))
                    .await
                    .err(),
                Some(ClientUdpPrepareFailure::Plan(
                    ClientPlanFailure::DirectIpv6Unsupported
                )),
                "TUN UDP direct IPv6"
            );
            assert_eq!(connector_calls.load(Ordering::SeqCst), 1);
            assert_eq!(registry.snapshot(), baseline);
        }

        let direct = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
        assert!(matches!(
            engine
                .open_tcp(
                    ClientRequestOrigin::Socks,
                    Some(direct),
                    &TargetAddr::ip("[::1]:443".parse().unwrap()).unwrap(),
                    None,
                    None,
                )
                .await,
            Err(ClientOpenFailure::Connect(
                ferrum2_core::ConnectErrorKind::Other
            ))
        ));
        assert_eq!(connector_calls.load(Ordering::SeqCst), 2);
    }
}
