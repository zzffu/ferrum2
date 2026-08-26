use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum2_core::{ConnectErrorKind, Connector, LocalEndpoint, TargetAddr};
use ferrum2_crypto::{Clock, SecureRandom};
use ferrum2_shadowsocks::{
    BoxedClientFlow, ClientTcpOutbound, FlowTerminal, PlainDuplex, ShadowsocksError, TransportIo,
    TransportPhase,
};
#[cfg(test)]
use ferrum2_shadowsocks::{BufferObserver, FlowObserver};

use super::{ClientOpenFailure, ClientOutboundContext};

pub(in crate::run) enum ClientTcpFlow<'a, S> {
    Direct(S),
    Proxy(BoxedClientFlow<'a>),
}

impl<S> LocalEndpoint for ClientTcpFlow<'_, S>
where
    S: LocalEndpoint,
{
    fn local_socket_addr(&self) -> std::net::SocketAddr {
        match self {
            Self::Direct(stream) => stream.local_socket_addr(),
            Self::Proxy(flow) => flow.local_socket_addr(),
        }
    }
}

impl<S> PlainDuplex for ClientTcpFlow<'_, S>
where
    S: TransportIo + LocalEndpoint,
{
    fn poll_read_plain(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, ShadowsocksError>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream)
                .poll_read(context, destination)
                .map_err(|_| ShadowsocksError::Transport(TransportPhase::Read)),
            Self::Proxy(flow) => Pin::new(flow).poll_read_plain(context, destination),
        }
    }

    fn poll_write_plain(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, ShadowsocksError>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream)
                .poll_write(context, source)
                .map_err(|_| ShadowsocksError::Transport(TransportPhase::Write)),
            Self::Proxy(flow) => Pin::new(flow).poll_write_plain(context, source),
        }
    }

    fn poll_flush_plain(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), ShadowsocksError>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream)
                .poll_flush(context)
                .map_err(|_| ShadowsocksError::Transport(TransportPhase::Flush)),
            Self::Proxy(flow) => Pin::new(flow).poll_flush_plain(context),
        }
    }

    fn poll_shutdown_plain(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), ShadowsocksError>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream)
                .poll_shutdown(context)
                .map_err(|_| ShadowsocksError::Transport(TransportPhase::Shutdown)),
            Self::Proxy(flow) => Pin::new(flow).poll_shutdown_plain(context),
        }
    }

    fn mark_abortive_plain(&mut self) -> Result<(), ShadowsocksError> {
        match self {
            Self::Direct(stream) => stream
                .mark_abortive()
                .map_err(|_| ShadowsocksError::Transport(TransportPhase::Shutdown)),
            Self::Proxy(flow) => flow.mark_abortive_plain(),
        }
    }

    fn terminal(&self) -> Option<FlowTerminal> {
        match self {
            Self::Direct(_) => None,
            Self::Proxy(flow) => flow.terminal(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn open<'a, C, T, R>(
    outbounds: &'a [ClientOutboundContext],
    plan: &[usize],
    connector: &'a C,
    clock: &'a T,
    random: &'a R,
    application_target: &TargetAddr,
    deadlines: (Duration, Duration),
    #[cfg(test)] observers: Option<(&'a dyn BufferObserver, &'a dyn FlowObserver)>,
) -> Result<BoxedClientFlow<'a>, ClientOpenFailure>
where
    C: Connector,
    C::Stream: TransportIo + LocalEndpoint + 'a,
    T: Clock + Sync,
    R: SecureRandom,
{
    let first = outbounds[plan[0]]
        .shadowsocks()
        .expect("classified Shadowsocks plan");
    let outbound = ClientTcpOutbound::new(
        first.tcp_server.clone(),
        &first.keys,
        connector,
        clock,
        random,
    );
    #[cfg(test)]
    let outbound = match observers {
        Some((buffer, flow)) => outbound.with_observers(buffer, flow),
        None => outbound,
    };
    let connected = tokio::time::timeout(deadlines.0, outbound.connect_server())
        .await
        .map_err(|_| {
            ClientOpenFailure::Protocol(ShadowsocksError::Connect(ConnectErrorKind::Timeout))
        })?
        .map_err(ClientOpenFailure::Protocol)?;
    tokio::time::timeout(deadlines.1, async {
        let first_target = plan.get(1).map_or(application_target, |next| {
            &outbounds[*next]
                .shadowsocks()
                .expect("classified Shadowsocks plan")
                .tcp_server
        });
        let mut flow = connected.write_request(first_target).await?.into_boxed();
        for (position, index) in plan.iter().copied().enumerate().skip(1) {
            let hop = outbounds[index]
                .shadowsocks()
                .expect("classified Shadowsocks plan");
            let next_target = plan.get(position + 1).map_or(application_target, |next| {
                &outbounds[*next]
                    .shadowsocks()
                    .expect("classified Shadowsocks plan")
                    .tcp_server
            });
            let outbound =
                ClientTcpOutbound::new(hop.tcp_server.clone(), &hop.keys, connector, clock, random);
            #[cfg(test)]
            let outbound = match observers {
                Some((buffer, flow)) => outbound.with_observers(buffer, flow),
                None => outbound,
            };
            flow = outbound
                .write_request_on(flow, next_target)
                .await?
                .into_boxed();
        }
        if plan.len() > 1 {
            std::future::poll_fn(|cx| Pin::new(&mut flow).poll_flush_plain(cx)).await?;
        }
        Ok(flow)
    })
    .await
    .map_err(|_| ClientOpenFailure::HandshakeTimeout)?
    .map_err(ClientOpenFailure::Protocol)
}

#[cfg(test)]
mod tests {
    use super::super::ClientRequestOrigin;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use ferrum2_config::RouteAction;
    use ferrum2_core::route::Network;
    use ferrum2_core::{ConnectErrorKind, TargetAddr};
    use ferrum2_crypto::{
        Clock, MethodProfile, MethodSinglePskProvider, MethodTcpSalt, SystemClock,
    };
    use ferrum2_rule::{RouteMetadata, RouteProgramAction};
    use ferrum2_shadowsocks::{
        DetectionReason, FlowTerminal, MethodKeyAdapter, ShadowsocksError, ShadowsocksTcpInbound,
        TcpKeyProvider, TcpReplayStore, encode_response_first_write,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use crate::run::test_support::*;

    fn selected_plan(
        route: &ferrum2_config::CompiledRoute,
        inbound: usize,
        network: Network,
        target: &TargetAddr,
    ) -> ferrum2_core::route::EgressPlanSnapshot {
        let mut scratch = route.evaluation_scratch().expect("route scratch");
        let mut evaluation = route.evaluate_with_scratch(inbound, network, target, &mut scratch);
        loop {
            match evaluation.next(RouteMetadata::new(None, None)) {
                Some(RouteProgramAction::Continue(_)) => {}
                Some(RouteProgramAction::Terminal(RouteAction::Route(plan)))
                | Some(RouteProgramAction::Final(RouteAction::Route(plan))) => {
                    return plan.snapshot_owned();
                }
                other => panic!("unexpected route action: {other:?}"),
            }
        }
    }

    fn tcp_chain_test_setup(
        methods: [MethodProfile; 4],
        first_port: u16,
    ) -> (
        Arc<[ClientOutboundContext]>,
        ferrum2_config::CompiledRoute,
        ferrum2_rule::SelectorControl,
    ) {
        let servers: [SocketAddrV4; 4] = std::array::from_fn(|hop| {
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, first_port + hop as u16)
        });
        let outbounds = prepare_client_outbounds(
            servers
                .into_iter()
                .zip(methods)
                .map(
                    |(server, method)| ferrum2_config::ClientOutboundConfig::Shadowsocks {
                        server: server.into(),
                        psk: Arc::new(psk_for_method(method)),
                        dial_options: Default::default(),
                    },
                )
                .collect(),
        )
        .expect("checked runtime outbounds");
        let listen = reserve_address();
        let mut source = format!(
            "schema_version = 2\n\
             [[inbounds]]\n\
             tag = \"entry\"\n\
             listen = \"{listen}\"\n\
             outbound = \"manual\"\n"
        );
        for (index, server) in servers.into_iter().enumerate() {
            let tag = ['a', 'b', 'c', 'd'][index];
            source.push_str(&format!(
                "[[outbounds]]\n\
                 tag = \"{tag}\"\n\
                 type = \"shadowsocks\"\n\
                 server = \"{server}\"\n\
                 method = \"2022-blake3-aes-128-gcm\"\n\
                 psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n"
            ));
        }
        source.push_str(
            "[[chains]]\n\
             tag = \"a-b\"\n\
             hops = [\"a\", \"b\"]\n\
             [[chains]]\n\
             tag = \"c-d\"\n\
             hops = [\"c\", \"d\"]\n\
             [[selectors]]\n\
             tag = \"manual\"\n\
             outbounds = [\"a-b\", \"c-d\"]\n\
             default = \"a-b\"\n",
        );
        let path = write_client_test_source(&source);
        let config = ferrum2_config::load_client(&path).expect("chain selector");
        std::fs::remove_file(path).expect("remove chain selector config");
        let selector = config.selector_control();
        (outbounds, config.route, selector)
    }

    #[tokio::test]
    async fn direct_tcp_socks_uses_the_numeric_target_and_raw_half_close() {
        let aborts = Arc::new(AtomicUsize::new(0));
        let (stream, mut peer) = tokio::io::duplex(1_024);
        let target =
            TargetAddr::ip("192.0.2.44:443".parse().expect("numeric target")).expect("target");
        let engine = ClientEgressEngine::new(
            vec![ClientOutboundContext::direct(
                ferrum2_runtime::DialOptions::default(),
            )]
            .into(),
            DeadlineConnector {
                delay: Duration::ZERO,
                targets: Mutex::new(Vec::new()),
                stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::duplex(
                    stream,
                    SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
                    Arc::clone(&aborts),
                )))),
            },
            SystemClock::new(),
            FixedRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            None,
            None,
        );
        let opened = engine
            .open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                0,
                Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
                &target,
                None,
                None,
            )
            .await
            .expect("direct open");
        let mut opened = TokioFramed::new(opened);
        opened.write_all(b"raw-direct").await.expect("raw write");
        opened.shutdown().await.expect("raw half-close");
        let mut raw = Vec::new();
        peer.read_to_end(&mut raw).await.expect("raw EOF");
        assert_eq!(raw, b"raw-direct");
        assert_eq!(
            engine.connector.targets.lock().expect("targets").as_slice(),
            &[target]
        );
        assert_eq!(aborts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn tcp_chain_opens_hops_in_order_with_distinct_credentials_and_no_fallback() {
        for (case, (first_method, second_method)) in [
            (
                MethodProfile::Blake3Aes128Gcm2022,
                MethodProfile::Blake3Aes256Gcm2022,
            ),
            (
                MethodProfile::Blake3Aes256Gcm2022,
                MethodProfile::Blake3ChaCha20Poly13052022,
            ),
            (
                MethodProfile::Blake3ChaCha20Poly13052022,
                MethodProfile::Blake3Aes128Gcm2022,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let (outbounds, route, selector) = tcp_chain_test_setup(
                [first_method, second_method, second_method, first_method],
                42_001 + case as u16 * 10,
            );
            let application = TargetAddr::ipv4(SocketAddrV4::new(
                Ipv4Addr::new(192, 0, 2, 1),
                443 + case as u16,
            ))
            .expect("application target");
            let snapshot = selected_plan(&route, 0, Network::Tcp, &application);
            assert_eq!(snapshot.hops(), &[0, 1], "rotation {case}");
            selector.switch("manual", "c-d").expect("switch next flow");
            assert_eq!(snapshot.hops(), &[0, 1], "captured rotation {case}");
            let next_snapshot = selected_plan(&route, 0, Network::Tcp, &application);
            assert_eq!(next_snapshot.hops(), &[2, 3], "next rotation {case}");
            let clock = SystemClock::new();
            let random = FixedRandom;
            for (label, plan) in [("captured", &snapshot), ("next", &next_snapshot)] {
                let [first, second] = *plan.hops() else {
                    panic!("two-hop {label} plan")
                };
                let aborts = Arc::new(AtomicUsize::new(0));
                let (stream, mut peer) = tokio::io::duplex(65_536);
                let engine = ClientEgressEngine::new(
                    Arc::clone(&outbounds),
                    DeadlineConnector {
                        delay: Duration::ZERO,
                        targets: Mutex::new(Vec::new()),
                        stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::duplex(
                            stream,
                            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
                            Arc::clone(&aborts),
                        )))),
                    },
                    SystemClock::new(),
                    FixedRandom,
                    (Duration::from_secs(1), Duration::from_secs(1)),
                    None,
                    None,
                );
                let observer = ChainObserver::default();
                let flow = engine
                    .open_tcp_for_ingress(
                        ClientRequestOrigin::Socks,
                        0,
                        Some(plan.clone()),
                        &application,
                        None,
                        Some((&observer, &observer)),
                    )
                    .await
                    .expect("selected chain");
                assert_eq!(
                    engine
                        .connector
                        .targets
                        .lock()
                        .expect("dial targets")
                        .as_slice(),
                    &[outbounds[first].shadowsocks().unwrap().tcp_server.clone()],
                    "sole {label} raw dial: rotation {case}"
                );
                assert_two_layer_buffers(&observer, format_args!("{label}: rotation {case}"));
                drop(flow);
                assert_eq!(observer.owner_drops.load(Ordering::SeqCst), 2);
                let mut raw = Vec::new();
                peer.read_to_end(&mut raw).await.expect("complete raw wire");

                let outer_replay = TcpReplayStore::new(1024).expect("outer replay");
                let outer_inbound = ShadowsocksTcpInbound::new(
                    &outbounds[first].shadowsocks().unwrap().keys,
                    &clock,
                    &random,
                    &outer_replay,
                );
                let outer = outer_inbound
                    .accept_stream(scripted_input(&raw).await)
                    .await
                    .expect("configured outer credential");
                assert_eq!(
                    outer.target,
                    outbounds[second].shadowsocks().unwrap().tcp_server,
                    "{label} first targets second: rotation {case}"
                );
                assert!(outer.initial_payload.is_empty(), "{label}: rotation {case}");
                let mut outer_stream = TokioFramed::new(outer.stream);
                let mut inner_wire = [0_u8; 4_096];
                let inner_len = outer_stream
                    .read(&mut inner_wire)
                    .await
                    .expect("authenticated inner wire");

                let inner_replay = TcpReplayStore::new(1024).expect("inner replay");
                let inner_inbound = ShadowsocksTcpInbound::new(
                    &outbounds[second].shadowsocks().unwrap().keys,
                    &clock,
                    &random,
                    &inner_replay,
                );
                let inner = inner_inbound
                    .accept_stream(scripted_input(&inner_wire[..inner_len]).await)
                    .await
                    .expect("configured inner credential");
                assert_eq!(inner.target, application, "{label}: rotation {case}");
                assert!(inner.initial_payload.is_empty(), "{label}: rotation {case}");

                if case == 0 && label == "captured" {
                    let wrong_keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
                        ferrum2_crypto::MethodPsk::aes128([0x91; 16]),
                    ));
                    for keys in [&outbounds[second].shadowsocks().unwrap().keys, &wrong_keys] {
                        let replay = TcpReplayStore::new(1024).expect("invalid replay");
                        let inbound = ShadowsocksTcpInbound::new(keys, &clock, &random, &replay);
                        assert!(
                            inbound
                                .accept_stream(scripted_input(&raw).await)
                                .await
                                .is_err(),
                            "swapped/wrong outer credential"
                        );
                    }
                    let mut truncated = raw.clone();
                    truncated.pop().expect("nonempty wire");
                    let replay = TcpReplayStore::new(1024).expect("truncated replay");
                    let inbound = ShadowsocksTcpInbound::new(
                        &outbounds[first].shadowsocks().unwrap().keys,
                        &clock,
                        &random,
                        &replay,
                    );
                    let truncated_outer = inbound
                        .accept_stream(scripted_input(&truncated).await)
                        .await
                        .expect("valid outer before truncated inner");
                    let mut truncated_stream = TokioFramed::new(truncated_outer.stream);
                    assert!(truncated_stream.read(&mut inner_wire).await.is_err());
                }
                assert_eq!(aborts.load(Ordering::SeqCst), 0, "{label}: rotation {case}");
            }
            assert_eq!(selector.selected("manual"), Ok("c-d"));
            assert_eq!(snapshot.hops(), &[0, 1], "captured rotation {case}");
            assert_eq!(next_snapshot.hops(), &[2, 3], "next rotation {case}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_chain_failure_and_cancellation_drop_every_layer() {
        let (outbounds, route, selector) = tcp_chain_test_setup(
            [
                MethodProfile::Blake3Aes256Gcm2022,
                MethodProfile::Blake3ChaCha20Poly13052022,
                MethodProfile::Blake3Aes128Gcm2022,
                MethodProfile::Blake3Aes256Gcm2022,
            ],
            42_011,
        );
        let application = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 443))
            .expect("application target");
        let snapshot = selected_plan(&route, 0, Network::Tcp, &application);
        assert_eq!(snapshot.hops(), &[0, 1]);
        let clock = SystemClock::new();
        let random = FixedRandom;

        let calls = Arc::new(AtomicUsize::new(0));
        let unavailable = TokioConnector::new(FailingConnector {
            calls: Arc::clone(&calls),
        });
        let unavailable_engine = ClientEgressEngine::new(
            Arc::clone(&outbounds),
            unavailable,
            SystemClock::new(),
            FixedRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            None,
            None,
        );
        let unavailable_observer = ChainObserver::default();
        assert!(matches!(
            unavailable_engine
                .open_tcp_for_ingress(
                    ClientRequestOrigin::Socks,
                    0,
                    Some(snapshot.clone()),
                    &application,
                    None,
                    Some((&unavailable_observer, &unavailable_observer)),
                )
                .await,
            Err(ClientOpenFailure::Protocol(ShadowsocksError::Connect(
                ConnectErrorKind::Other
            )))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            unavailable_observer
                .buffers
                .lock()
                .expect("unavailable buffers")
                .is_empty()
        );
        assert_eq!(unavailable_observer.owner_drops.load(Ordering::SeqCst), 0);
        assert_eq!(selector.selected("manual"), Ok("a-b"));

        for cancel in [false, true] {
            let drops = Arc::new(AtomicUsize::new(0));
            let aborts = Arc::new(AtomicUsize::new(0));
            let observer = ChainObserver::default();
            let engine = ClientEgressEngine::new(
                Arc::clone(&outbounds),
                DeadlineConnector {
                    delay: Duration::ZERO,
                    targets: Mutex::new(Vec::new()),
                    stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::stall_after(
                        1,
                        Arc::clone(&drops),
                        Arc::clone(&aborts),
                    )))),
                },
                SystemClock::new(),
                FixedRandom,
                (Duration::from_secs(1), Duration::from_millis(10)),
                None,
                None,
            );
            let mut opened = Box::pin(engine.open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                0,
                Some(snapshot.clone()),
                &application,
                None,
                Some((&observer, &observer)),
            ));
            assert_open_pending(&mut opened).await;
            assert_two_layer_buffers(&observer, format_args!("cancel={cancel}"));
            assert_eq!(observer.owner_drops.load(Ordering::SeqCst), 0);
            if cancel {
                drop(opened);
            } else {
                tokio::time::advance(Duration::from_millis(10)).await;
                assert!(matches!(
                    opened.await,
                    Err(ClientOpenFailure::HandshakeTimeout)
                ));
            }
            assert_eq!(observer.owner_drops.load(Ordering::SeqCst), 2);
            assert!(
                observer
                    .terminals
                    .lock()
                    .expect("pending terminals")
                    .is_empty()
            );
            assert_eq!(drops.load(Ordering::SeqCst), 1, "cancel={cancel}");
            assert_eq!(aborts.load(Ordering::SeqCst), 0, "cancel={cancel}");
            assert_eq!(
                engine
                    .connector
                    .targets
                    .lock()
                    .expect("dial targets")
                    .as_slice(),
                &[outbounds[0].shadowsocks().unwrap().tcp_server.clone()],
                "cancel={cancel}"
            );
            assert_eq!(selector.selected("manual"), Ok("a-b"));
        }

        let drops = Arc::new(AtomicUsize::new(0));
        let aborts = Arc::new(AtomicUsize::new(0));
        let write_zero_wire = Arc::new(Mutex::new(Vec::new()));
        let write_zero_calls = Arc::new(AtomicUsize::new(0));
        let write_zero_observer = ChainObserver::default();
        let write_zero = ClientEgressEngine::new(
            Arc::clone(&outbounds),
            DeadlineConnector {
                delay: Duration::ZERO,
                targets: Mutex::new(Vec::new()),
                stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::write_limit_after(
                    1,
                    0,
                    Arc::clone(&write_zero_wire),
                    Arc::clone(&write_zero_calls),
                    Arc::clone(&drops),
                    Arc::clone(&aborts),
                )))),
            },
            SystemClock::new(),
            FixedRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            None,
            None,
        );
        assert!(matches!(
            write_zero
                .open_tcp_for_ingress(
                    ClientRequestOrigin::Socks,
                    0,
                    Some(snapshot.clone()),
                    &application,
                    None,
                    Some((&write_zero_observer, &write_zero_observer)),
                )
                .await,
            Err(ClientOpenFailure::Protocol(ShadowsocksError::Transport(_)))
        ));
        assert_eq!(write_zero_observer.owner_drops.load(Ordering::SeqCst), 2);
        assert_two_layer_buffers(&write_zero_observer, "write zero");
        assert_eq!(
            write_zero_observer
                .terminals
                .lock()
                .expect("write-zero terminals")
                .len(),
            2
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(aborts.load(Ordering::SeqCst), 0);
        assert_eq!(write_zero_calls.load(Ordering::SeqCst), 2);
        assert!(!write_zero_wire.lock().expect("write-zero wire").is_empty());
        assert_eq!(
            write_zero
                .connector
                .targets
                .lock()
                .expect("write-zero targets")
                .as_slice(),
            &[outbounds[0].shadowsocks().unwrap().tcp_server.clone()]
        );
        assert_eq!(selector.selected("manual"), Ok("a-b"));

        let drops = Arc::new(AtomicUsize::new(0));
        let aborts = Arc::new(AtomicUsize::new(0));
        let partial_wire = Arc::new(Mutex::new(Vec::new()));
        let partial_calls = Arc::new(AtomicUsize::new(0));
        let partial_observer = ChainObserver::default();
        let partial = ClientEgressEngine::new(
            Arc::clone(&outbounds),
            DeadlineConnector {
                delay: Duration::ZERO,
                targets: Mutex::new(Vec::new()),
                stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::write_limit_after(
                    1,
                    1,
                    Arc::clone(&partial_wire),
                    Arc::clone(&partial_calls),
                    Arc::clone(&drops),
                    Arc::clone(&aborts),
                )))),
            },
            SystemClock::new(),
            FixedRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            None,
            None,
        );
        let partial_flow = partial
            .open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                0,
                Some(snapshot.clone()),
                &application,
                None,
                Some((&partial_observer, &partial_observer)),
            )
            .await
            .expect("nonzero partial raw write resumes");
        let mut partial_framed = TokioFramed::new(partial_flow);
        partial_framed
            .shutdown()
            .await
            .expect("partial recursive half-close");
        drop(partial_framed);
        assert_eq!(
            partial_calls.load(Ordering::SeqCst),
            3,
            "full initial, one-byte partial, resumed remainder"
        );
        assert_eq!(partial_observer.owner_drops.load(Ordering::SeqCst), 2);
        assert_two_layer_buffers(&partial_observer, "nonzero partial");
        assert!(
            partial_observer
                .terminals
                .lock()
                .expect("partial terminals")
                .is_empty()
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(aborts.load(Ordering::SeqCst), 0);
        assert_eq!(
            partial
                .connector
                .targets
                .lock()
                .expect("partial targets")
                .as_slice(),
            &[outbounds[0].shadowsocks().unwrap().tcp_server.clone()]
        );
        assert_eq!(selector.selected("manual"), Ok("a-b"));
        let raw = partial_wire.lock().expect("partial wire").clone();
        let outer_replay = TcpReplayStore::new(1024).expect("partial outer replay");
        let outer = ShadowsocksTcpInbound::new(
            &outbounds[0].shadowsocks().unwrap().keys,
            &clock,
            &random,
            &outer_replay,
        )
        .accept_stream(scripted_input(&raw).await)
        .await
        .expect("partial outer wire");
        assert_eq!(outer.target, outbounds[1].shadowsocks().unwrap().tcp_server);
        let mut outer_stream = TokioFramed::new(outer.stream);
        let mut inner_wire = [0_u8; 4_096];
        let inner_len = outer_stream
            .read(&mut inner_wire)
            .await
            .expect("partial inner wire");
        let inner_replay = TcpReplayStore::new(1024).expect("partial inner replay");
        let inner = ShadowsocksTcpInbound::new(
            &outbounds[1].shadowsocks().unwrap().keys,
            &clock,
            &random,
            &inner_replay,
        )
        .accept_stream(scripted_input(&inner_wire[..inner_len]).await)
        .await
        .expect("partial complete inner wire");
        assert_eq!(inner.target, application);
        assert!(inner.initial_payload.is_empty());

        let aborts = Arc::new(AtomicUsize::new(0));
        let detection_observer = ChainObserver::default();
        let (detection_stream, mut detection_peer) = tokio::io::duplex(65_536);
        let detection_engine = ClientEgressEngine::new(
            Arc::clone(&outbounds),
            DeadlineConnector {
                delay: Duration::ZERO,
                targets: Mutex::new(Vec::new()),
                stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::duplex(
                    detection_stream,
                    SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
                    Arc::clone(&aborts),
                )))),
            },
            SystemClock::new(),
            FixedRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            None,
            None,
        );
        let detection_flow = detection_engine
            .open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                0,
                Some(snapshot.clone()),
                &application,
                None,
                Some((&detection_observer, &detection_observer)),
            )
            .await
            .expect("opened detection chain");
        let request_salt = MethodTcpSalt::try_from_slice(
            outbounds[0].shadowsocks().unwrap().keys.tcp_profile(),
            &[0x42; 32],
        )
        .expect("outer request salt");
        let inner_request_salt = MethodTcpSalt::try_from_slice(
            outbounds[1].shadowsocks().unwrap().keys.tcp_profile(),
            &[0x42; 32],
        )
        .expect("inner request salt");
        let response_salt = MethodTcpSalt::try_from_slice(
            outbounds[0].shadowsocks().unwrap().keys.tcp_profile(),
            &[0x43; 32],
        )
        .expect("outer response salt");
        let inner_response_salt = MethodTcpSalt::try_from_slice(
            outbounds[1].shadowsocks().unwrap().keys.tcp_profile(),
            &[0x44; 32],
        )
        .expect("inner response salt");
        let wrong_inner_keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
            ferrum2_crypto::MethodPsk::chacha20_poly1305([0x99; 32]),
        ));
        let invalid_inner = encode_response_first_write(
            &wrong_inner_keys,
            &inner_response_salt,
            clock.unix_seconds().expect("response time"),
            &inner_request_salt,
            b"must not reach application",
        )
        .expect("wrong-key inner response");
        let authenticated_outer = encode_response_first_write(
            &outbounds[0].shadowsocks().unwrap().keys,
            &response_salt,
            clock.unix_seconds().expect("response time"),
            &request_salt,
            &invalid_inner,
        )
        .expect("authenticated outer response");
        detection_peer
            .write_all(&authenticated_outer)
            .await
            .expect("later-hop response");
        let mut detection_framed = TokioFramed::new(detection_flow);
        let mut application_output = [0x5a_u8; 1];
        assert!(
            detection_framed
                .read(&mut application_output)
                .await
                .is_err()
        );
        assert_eq!(application_output, [0x5a]);
        drop(detection_framed);
        assert_eq!(detection_observer.owner_drops.load(Ordering::SeqCst), 2);
        assert_two_layer_buffers(&detection_observer, "detection");
        assert_eq!(
            detection_observer
                .terminals
                .lock()
                .expect("detection terminals")
                .as_slice(),
            &[FlowTerminal::Detection(DetectionReason::Authentication)]
        );
        assert_eq!(aborts.load(Ordering::SeqCst), 1);
        assert_eq!(
            detection_engine
                .connector
                .targets
                .lock()
                .expect("detection targets")
                .as_slice(),
            &[outbounds[0].shadowsocks().unwrap().tcp_server.clone()]
        );
        assert_eq!(selector.selected("manual"), Ok("a-b"));

        let valid_observer = ChainObserver::default();
        let (valid_stream, mut valid_peer) = tokio::io::duplex(65_536);
        let valid_engine = ClientEgressEngine::new(
            Arc::clone(&outbounds),
            DeadlineConnector {
                delay: Duration::ZERO,
                targets: Mutex::new(Vec::new()),
                stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::duplex(
                    valid_stream,
                    SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
                    Arc::new(AtomicUsize::new(0)),
                )))),
            },
            SystemClock::new(),
            FixedRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            None,
            None,
        );
        let valid_flow = valid_engine
            .open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                0,
                Some(snapshot.clone()),
                &application,
                None,
                Some((&valid_observer, &valid_observer)),
            )
            .await
            .expect("valid open after isolated failures");
        let mut valid_framed = TokioFramed::new(valid_flow);
        valid_framed.shutdown().await.expect("recursive half-close");
        drop(valid_framed);
        assert_eq!(valid_observer.owner_drops.load(Ordering::SeqCst), 2);
        assert_two_layer_buffers(&valid_observer, "valid half-close");
        let mut valid_wire = Vec::new();
        valid_peer
            .read_to_end(&mut valid_wire)
            .await
            .expect("recursive raw half-close");
        assert!(!valid_wire.is_empty());
        assert_eq!(
            valid_engine
                .connector
                .targets
                .lock()
                .expect("valid targets")
                .as_slice(),
            &[outbounds[0].shadowsocks().unwrap().tcp_server.clone()]
        );
        assert_eq!(selector.selected("manual"), Ok("a-b"));
    }

    pub(in crate::run) async fn assert_open_pending<F>(future: &mut Pin<Box<F>>)
    where
        F: std::future::Future,
    {
        tokio::select! {
            biased;
            _ = future.as_mut() => panic!("open completed before its controlled phase"),
            _ = tokio::task::yield_now() => {}
        }
    }

    async fn run_timeout_case(
        label: &str,
        runtime: RuntimeConfig,
        connect_delay: Duration,
        handshake: bool,
        timeout_limit: Option<Duration>,
        expected_timeout: Duration,
        key: u8,
    ) {
        let drops = Arc::new(AtomicUsize::new(0));
        let aborts = Arc::new(AtomicUsize::new(0));
        let connector = DeadlineConnector {
            delay: connect_delay,
            targets: Mutex::new(Vec::new()),
            stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::pending(
                Arc::clone(&drops),
                Arc::clone(&aborts),
            )))),
        };
        let server_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 41_002);
        let server = TargetAddr::ipv4(server_address).expect(label);
        let engine = ClientEgressEngine::new(
            vec![ClientOutboundContext::Shadowsocks(
                ClientShadowsocksContext {
                    tcp_server: server,
                    udp_server: server_address.into(),
                    keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(
                        ferrum2_crypto::MethodPsk::aes128([key; 16]),
                    )),
                    dial_options: ferrum2_runtime::DialOptions::default(),
                },
            )]
            .into(),
            connector,
            SystemClock::new(),
            FixedRandom,
            (runtime.connect_timeout, runtime.handshake_timeout),
            None,
            None,
        );
        let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect(label);
        let mut opened = Box::pin(engine.open_tcp_for_ingress(
            ClientRequestOrigin::Socks,
            0,
            Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
            &target,
            timeout_limit,
            None,
        ));
        assert_open_pending(&mut opened).await;
        if handshake {
            tokio::time::advance(connect_delay).await;
            assert_open_pending(&mut opened).await;
        }
        tokio::time::advance(expected_timeout - Duration::from_millis(1)).await;
        assert_open_pending(&mut opened).await;
        tokio::time::advance(Duration::from_millis(1)).await;
        let error = match opened.await {
            Ok(_) => panic!("{label}"),
            Err(error) => error,
        };
        assert!(
            if handshake {
                matches!(error, ClientOpenFailure::HandshakeTimeout)
            } else {
                matches!(
                    error,
                    ClientOpenFailure::Protocol(ShadowsocksError::Connect(
                        ConnectErrorKind::Timeout
                    ))
                )
            },
            "{label}"
        );
        drop(engine);
        assert_eq!(drops.load(Ordering::SeqCst), 1, "{label}");
        assert_eq!(aborts.load(Ordering::SeqCst), 0, "{label}");
    }

    #[tokio::test(start_paused = true)]
    async fn phase_deadline_contract_table_preserves_defaults_overrides_and_first_write() {
        let defaults = RuntimeConfig {
            max_connections: std::num::NonZeroU16::new(4_096).expect("non-zero"),
            listen_backlog: std::num::NonZeroU16::new(1_024).expect("non-zero"),
            handshake_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            shutdown_grace: Duration::from_secs(30),
        };
        let custom = RuntimeConfig {
            connect_timeout: Duration::from_millis(2_300),
            handshake_timeout: Duration::from_millis(3_700),
            ..defaults
        };
        let actual = [
            (defaults.connect_timeout, defaults.handshake_timeout),
            (custom.connect_timeout, custom.handshake_timeout),
        ];
        let expected = [
            (Duration::from_secs(10), Duration::from_secs(5)),
            (Duration::from_millis(2_300), Duration::from_millis(3_700)),
        ];
        assert_eq!(actual, expected);
        let cases = [
            (
                "default connect",
                defaults,
                defaults.connect_timeout + Duration::from_secs(1),
                false,
                None,
                Duration::from_secs(10),
                0x11,
            ),
            (
                "fresh handshake",
                defaults,
                Duration::from_secs(9),
                true,
                None,
                Duration::from_secs(5),
                0x12,
            ),
            (
                "custom connect",
                custom,
                custom.connect_timeout + Duration::from_secs(1),
                false,
                None,
                Duration::from_millis(2_300),
                0x13,
            ),
            (
                "custom handshake",
                custom,
                Duration::from_secs(2),
                true,
                None,
                Duration::from_millis(3_700),
                0x14,
            ),
            (
                "DNS connect timeout cap",
                defaults,
                Duration::from_secs(1),
                false,
                Some(Duration::from_millis(700)),
                Duration::from_millis(700),
                0x16,
            ),
        ];
        for (label, runtime, delay, handshake, timeout_limit, expected_timeout, key) in cases {
            run_timeout_case(
                label,
                runtime,
                delay,
                handshake,
                timeout_limit,
                expected_timeout,
                key,
            )
            .await;
        }

        let aborts = Arc::new(AtomicUsize::new(0));
        let (stream, mut peer) = tokio::io::duplex(2_048);
        let connector = DeadlineConnector {
            delay: Duration::ZERO,
            targets: Mutex::new(Vec::new()),
            stream: Mutex::new(Some(TokioTransport::new(ScriptedIo::duplex(
                stream,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152),
                Arc::clone(&aborts),
            )))),
        };
        let server = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 41_002);
        let engine = ClientEgressEngine::new(
            vec![ClientOutboundContext::Shadowsocks(
                ClientShadowsocksContext {
                    tcp_server: TargetAddr::ipv4(server).expect("server"),
                    udp_server: server.into(),
                    keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(
                        ferrum2_crypto::MethodPsk::aes128([0x15; 16]),
                    )),
                    dial_options: ferrum2_runtime::DialOptions::default(),
                },
            )]
            .into(),
            connector,
            SystemClock::new(),
            FixedRandom,
            (custom.connect_timeout, custom.handshake_timeout),
            None,
            None,
        );
        let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("target");
        let flow = engine
            .open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                0,
                Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
                &target,
                None,
                None,
            )
            .await
            .expect("first write");
        assert_eq!(
            flow.local_socket_addr(),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152))
        );
        let mut written = [0_u8; 2_048];
        assert!(peer.read(&mut written).await.expect("handshake wire") > 0);
        assert_eq!(aborts.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn routed_tcp_selects_after_target_and_never_falls_back() {
        let upstreams = [
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("A"),
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("B"),
        ];
        let servers: Vec<SocketAddrV4> = upstreams
            .iter()
            .map(|socket| match socket.local_addr().expect("upstream") {
                SocketAddr::V4(address) => address,
                SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
            })
            .collect();
        let listens = [reserve_address(), reserve_address()];
        let mappings = [(listens[0], servers[0]), (listens[1], servers[1])];
        let (path, mut config) = tagged_client_test_config(&mappings, false);
        let dead = reserve_address();
        config
            .outbounds
            .push(ferrum2_config::ClientOutboundConfig::Shadowsocks {
                server: dead.into(),
                psk: Arc::new(psk_for_method(MethodProfile::Blake3Aes128Gcm2022)),
                dial_options: Default::default(),
            });
        let route_source = format!(
            r#"schema_version = 2
[[inbounds]]
tag = "i0"
listen = "{}"
[[inbounds]]
tag = "i1"
listen = "{}"
[[outbounds]]
tag = "o0"
type = "direct"
[[outbounds]]
tag = "o1"
type = "direct"
[[outbounds]]
tag = "dead"
type = "direct"
[[selectors]]
tag = "manual"
outbounds = ["o0", "o1", "dead"]
default = "o0"
[route]
final = "manual"
[[route.rules]]
inbound = "i1"
network = "tcp"
action = "route"
outbound = "manual"
[[route.rules]]
network = "tcp"
ip = "192.0.2.1"
port = 80
action = "route"
outbound = "manual"
"#,
            listens[0], listens[1]
        );
        let route_path = write_client_test_source(&route_source);
        let route_config = ferrum2_config::load_client(&route_path).expect("selector route");
        std::fs::remove_file(route_path).expect("remove selector route config");
        config.route = route_config.route;
        let selector = config.selector_control();
        let registry = OwnerRegistry::new();
        let (stop, task) = spawn_test_client(config, &registry);
        for listen in listens {
            wait_until_bound(listen).await;
        }
        let (mut first, reply) = socks_connect_port(listens[0], 80).await;
        assert_eq!(&reply[..2], &[5, 0]);
        let (mut first_upstream, _) = upstreams[0].accept().await.expect("selected A");
        let mut wire = [0; 256];
        assert!(
            first_upstream
                .read(&mut wire)
                .await
                .expect("initial A wire")
                > 0
        );
        while first_upstream.try_read(&mut wire).is_ok() {}
        selector.switch("manual", "o1").expect("switch to B");
        first
            .write_all(b"captured A")
            .await
            .expect("open flow write");
        assert!(
            tokio::time::timeout(Duration::from_secs(2), first_upstream.read(&mut wire))
                .await
                .expect("captured A timeout")
                .expect("captured A wire")
                > 0
        );
        for (inbound, port) in [(1, 81), (0, 80), (0, 81)] {
            let (control, reply) = socks_connect_port(listens[inbound], port).await;
            assert_eq!(&reply[..2], &[5, 0]);
            let (selected, _) = tokio::time::timeout(Duration::from_secs(2), upstreams[1].accept())
                .await
                .expect("selected B timeout")
                .expect("selected B");
            drop((control, selected));
        }
        drop((first, first_upstream));
        selector
            .switch("manual", "dead")
            .expect("switch to unavailable member");
        let (_, reply) = socks_connect_port(listens[0], 82).await;
        assert_ne!(reply[1], 0);
        assert_eq!(selector.selected("manual"), Ok("dead"));
        let fallback = tokio::join!(
            tokio::time::timeout(Duration::from_millis(50), upstreams[0].accept()),
            tokio::time::timeout(Duration::from_millis(50), upstreams[1].accept()),
        );
        assert!(fallback.0.is_err() && fallback.1.is_err());
        stop.send(()).expect("stop");
        assert_eq!(task.await.expect("client"), Ok(()));
        std::fs::remove_file(path).expect("remove config");
    }
}
