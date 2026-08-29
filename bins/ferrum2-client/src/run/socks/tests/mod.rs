use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::AsyncWriteExt as _;

use ferrum2_core::route::Network;
use ferrum2_runtime::BoundedSupervisor;
#[cfg(feature = "candidate-udp-owned-headroom")]
use ferrum2_runtime::{UdpBufferBudget, UdpRuntimeLimits, UdpSessionManager};
use ferrum2_socks5::{SocksStream, decode_udp_datagram};

use super::association::{relay_udp_association, run_udp_association};
use super::endpoint::SocksUdpEndpoint;
use crate::run::egress::{
    ClientUdpAssociation, IdSequenceRandom, MAX_UDP_PLAN_HOPS, UdpIoFaultPlan, UdpIoOperation,
    UdpSendError, composed_udp_plan_limit, composed_udp_request_limit, composed_udp_response_limit,
    send_with_lifecycle,
};
use crate::run::routing::ClientTerminalRoute;
use crate::run::test_support::*;
use ferrum2_shadowsocks::{UdpPacketError, UdpPacketScratch};

mod boundaries;
mod chain;
mod endpoint;
mod lifecycle;
mod listener;
mod routing;

use ferrum2_socks5::MAX_SOCKS_UDP_DATAGRAM_BYTES;
pub(in crate::run) use lifecycle::RunningUdpRelay;

#[cfg(feature = "candidate-udp-owned-headroom")]
fn standalone_udp_buffer_budget() -> UdpBufferBudget {
    UdpSessionManager::new(UdpRuntimeLimits::default(), OwnerRegistry::new()).buffer_budget()
}

#[cfg(feature = "candidate-udp-owned-headroom")]
fn context_udp_buffer_budget(context: &ClientContext) -> UdpBufferBudget {
    context
        .egress
        .udp
        .as_ref()
        .expect("UDP context")
        .manager
        .buffer_budget()
}

fn udp_test_context(registry: OwnerRegistry) -> (PathBuf, Arc<ClientContext>, SocketAddrV4) {
    let server = reserve_address();
    let (path, context) = udp_test_context_for_server(registry, server);
    (path, context, server)
}

async fn execute_test_udp_association<IO, F, Fut>(
    association: SocksUdpAssociate<IO>,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    bind: F,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnMut(SocketAddr) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = io::Result<UdpSocket>> + Send + 'static,
{
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("token listener");
    let address = listener.local_addr().expect("token address");
    let supervisor = BoundedSupervisor::new(
        listener,
        1,
        Duration::from_secs(1),
        context.registry.clone(),
    )
    .expect("token supervisor");
    let association = Arc::new(Mutex::new(Some(association)));
    let bind = Arc::new(Mutex::new(Some(bind)));
    let (done_sender, done_receiver) = tokio::sync::oneshot::channel();
    let done_sender = Arc::new(Mutex::new(Some(done_sender)));
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
    let run_task = tokio::spawn(supervisor.run_until(
        move |_stream, mut cancellation| {
            let association = association
                .lock()
                .expect("association")
                .take()
                .expect("one handler");
            let bind = bind.lock().expect("bind").take().expect("one binder");
            let context = Arc::clone(&context);
            let routing = Arc::clone(&routing);
            let done_sender = Arc::clone(&done_sender);
            async move {
                run_udp_association(
                    association,
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    Ipv4Addr::LOCALHOST,
                    &mut cancellation,
                    context,
                    (0, &routing),
                    bind,
                )
                .await;
                done_sender
                    .lock()
                    .expect("done sender")
                    .take()
                    .expect("one completion")
                    .send(())
                    .expect("completion receiver");
            }
        },
        async {
            let _ = shutdown_receiver.await;
        },
    ));
    let _trigger = tokio::net::TcpStream::connect(address)
        .await
        .expect("token handler");
    done_receiver.await.expect("association completion");
    shutdown_sender.send(()).expect("token shutdown");
    assert_eq!(run_task.await.expect("token supervisor"), Ok(()));
}

async fn start_udp_relay(
    endpoint: SocksUdpEndpoint,
    prepared: ClientUdpAssociation,
    control: SocksStream<tokio::io::DuplexStream>,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
) -> RunningUdpRelay {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("relay owner listener");
    let address = listener.local_addr().expect("relay owner address");
    let supervisor = BoundedSupervisor::new(
        listener,
        1,
        Duration::from_secs(1),
        context.registry.clone(),
    )
    .expect("relay owner supervisor");
    let endpoint = Arc::new(Mutex::new(Some(endpoint)));
    let prepared = Arc::new(Mutex::new(Some(prepared)));
    let control = Arc::new(Mutex::new(Some(control)));
    let (done_sender, done) = tokio::sync::oneshot::channel();
    let done_sender = Arc::new(Mutex::new(Some(done_sender)));
    let (shutdown, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(supervisor.run_until(
        move |_stream, mut cancellation| {
            let mut endpoint = endpoint
                .lock()
                .expect("endpoint")
                .take()
                .expect("one endpoint");
            let mut prepared = prepared
                .lock()
                .expect("prepared")
                .take()
                .expect("one relay");
            let mut control = control
                .lock()
                .expect("control")
                .take()
                .expect("one control");
            let context = Arc::clone(&context);
            let routing = Arc::clone(&routing);
            let done_sender = Arc::clone(&done_sender);
            async move {
                relay_udp_association(
                    &mut endpoint,
                    &mut prepared,
                    &mut control,
                    &mut cancellation,
                    &context,
                    &routing,
                    None,
                )
                .await;
                let _ = done_sender
                    .lock()
                    .expect("done")
                    .take()
                    .expect("one done")
                    .send(());
            }
        },
        async {
            let _ = shutdown_receiver.await;
        },
    ));
    let trigger = tokio::net::TcpStream::connect(address)
        .await
        .expect("relay owner trigger");
    RunningUdpRelay {
        task,
        done,
        shutdown,
        _trigger: trigger,
    }
}

async fn finish_udp_relay(running: RunningUdpRelay) {
    tokio::time::timeout(Duration::from_secs(2), running.done)
        .await
        .expect("relay completion timeout")
        .expect("relay completion");
    running.shutdown.send(()).expect("relay owner shutdown");
    assert_eq!(running.task.await.expect("relay owner task"), Ok(()));
}

async fn receive_request_and_send_response(
    socket: &UdpSocket,
    server: &UdpServer,
    scratch: &mut UdpPacketScratch,
    payload: &[u8],
) -> SocketAddr {
    let (peer, wire, _) =
        receive_request_and_encode_response(socket, server, scratch, payload, 0).await;
    socket
        .send_to(&wire, peer)
        .await
        .expect("upstream response");
    peer
}

async fn receive_request_and_encode_response(
    socket: &UdpSocket,
    server: &UdpServer,
    scratch: &mut UdpPacketScratch,
    payload: &[u8],
    advance: u64,
) -> (SocketAddr, Vec<u8>, Vec<u8>) {
    let mut wire = [0; MAX_UDP_WIRE_LEN];
    let (length, peer) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut wire))
        .await
        .expect("upstream request timeout")
        .expect("upstream request");
    let clock = SystemClock::new();
    let random = SystemRandom;
    let pending = server
        .prepare_request(&clock, &wire[..length], scratch)
        .expect("authenticated request");
    let target = pending.datagram().target().clone();
    let (_, commit) = pending.into_parts();
    let accepted = server
        .commit_request(commit, peer, clock.monotonic_now(), &random)
        .expect("request commit");
    let response = test_datagram(target, payload);
    let mut first = Vec::new();
    let mut last = Vec::new();
    for index in 0..=advance {
        let encoded = server
            .encode_response(
                accepted.capability(),
                &clock,
                &random,
                &response,
                0,
                &mut wire,
            )
            .expect("response encode");
        if index == 0 {
            first = wire[..encoded.wire_len()].to_vec();
        }
        if index == advance {
            last = wire[..encoded.wire_len()].to_vec();
        }
    }
    (peer, first, last)
}

async fn wait_for_metric(metrics: &Metrics, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let text = metrics.encode_text().expect("metrics");
        if text.contains(needle) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "metric not observed: {needle}\n{text}"
        );
        tokio::task::yield_now().await;
    }
}

async fn eight_hop_udp_chain_rejects_before_admission_and_uses_fixed_buffers() {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let mut upstreams = Vec::new();
    for _ in 0..MAX_UDP_PLAN_HOPS {
        upstreams.push(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("eight-hop upstream"),
        );
    }
    let servers = upstreams
        .iter()
        .map(
            |socket| match socket.local_addr().expect("upstream address") {
                SocketAddr::V4(address) => address,
                SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
            },
        )
        .collect::<Vec<_>>();
    let methods = (0..MAX_UDP_PLAN_HOPS)
        .map(|hop| MethodProfile::ALL[hop % MethodProfile::ALL.len()])
        .collect::<Vec<_>>();
    let outbounds = prepare_client_outbounds(
        servers
            .iter()
            .copied()
            .zip(methods.iter().copied())
            .map(
                |(server, method)| ferrum2_config::ClientOutboundConfig::Shadowsocks {
                    server: server.into(),
                    psk: Arc::new(psk_for_method(method)),
                    dial_options: Default::default(),
                },
            )
            .collect(),
    )
    .expect("eight-hop outbounds");
    let mut source = format!(
        "schema_version = 2\n[[inbounds]]\ntag = \"entry\"\nlisten = \"{}\"\noutbound = \"chain\"\n",
        reserve_address()
    );
    for (hop, server) in servers.iter().copied().enumerate() {
        source.push_str(&test_shadowsocks_outbound_source(
            &format!("o{hop}"),
            server,
        ));
    }
    let hop_tags = (0..MAX_UDP_PLAN_HOPS)
        .map(|hop| format!("\"o{hop}\""))
        .collect::<Vec<_>>()
        .join(", ");
    source.push_str(&format!(
        "[[chains]]\ntag = \"chain\"\nhops = [{hop_tags}]\n"
    ));
    let route_path = write_client_test_source(&source);
    let prepared = ferrum2_config::prepare_client(&route_path).expect("prepare eight-hop route");
    let route_config =
        ferrum2_config::finish_client_v2(prepared, ferrum2_config::ClientV2Resources::default())
            .expect("finish eight-hop route");
    std::fs::remove_file(route_path).expect("remove eight-hop route config");
    let selector = route_config.selector_control();
    let routing = Arc::new(ClientRouting {
        program: route_config.route,
        outbounds,
        selector,
    });
    let route_target = TargetAddr::domain("eight-hop.test", 53).expect("eight-hop target");
    let mut route_scratch = routing.route_scratch().expect("eight-hop route scratch");
    let ClientTerminalRoute::Route(plan) = routing
        .select_terminal_with_scratch(
            0,
            Network::Udp,
            &route_target,
            None,
            &Metrics::new(),
            &mut route_scratch,
        )
        .expect("eight-hop route selection")
    else {
        panic!("eight-hop route terminal")
    };
    let hops = (0..MAX_UDP_PLAN_HOPS).collect::<Vec<_>>();
    let (path, mut context) = udp_test_context_for_psk(
        registry.clone(),
        servers[0],
        Some(psk_for_method(methods[0])),
    );
    Arc::get_mut(
        &mut Arc::get_mut(&mut context)
            .expect("unique eight-hop context")
            .egress,
    )
    .expect("unique eight-hop egress")
    .outbounds = Arc::clone(&routing.outbounds);
    let endpoint = SocksUdpEndpoint::bind(
        Ipv4Addr::LOCALHOST,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        #[cfg(feature = "candidate-udp-owned-headroom")]
        context_udp_buffer_budget(&context),
        UdpSocket::bind,
    )
    .await
    .expect("eight-hop SOCKS endpoint");
    let relay = endpoint.local_addr().expect("relay");
    let prepared = context
        .egress
        .prepare_udp_with(plan, UdpSocket::bind)
        .await
        .expect("eight-hop preparation");
    let manager = context.egress.udp.as_ref().expect("UDP").manager.clone();
    let (association, peer) = parsed_udp_association().await;
    let running = start_udp_relay(
        endpoint,
        prepared,
        association.control,
        Arc::clone(&context),
        Arc::clone(&routing),
    )
    .await;
    drop(association.reply);
    let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("application");
    while registry.snapshot().active_supervisor_children != 1 {
        tokio::task::yield_now().await;
    }
    let target = TargetAddr::ip("[2001:db8::1]:53".parse().expect("IPv6 target")).expect("target");
    let limit = composed_udp_plan_limit(&routing.outbounds, &hops, false, 19);
    let mut socks = vec![0; MAX_SOCKS_UDP_DATAGRAM_BYTES];
    let one_over = encode_udp_datagram(&target, &vec![0x5a; limit + 1], &mut socks)
        .expect("SOCKS-valid eight-hop maximum+1");
    let stable = registry.snapshot();
    application
        .send_to(&socks[..one_over], relay)
        .await
        .expect("maximum+1 send");
    wait_for_metric(
        &context.metrics,
        "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"rejected\"} 1",
    )
    .await;
    assert_eq!(registry.snapshot(), stable);
    assert_eq!(
        manager.session_count(),
        1,
        "UDP setup owner stays pending after an over-bound packet"
    );
    assert_eq!(
        context
            .egress
            .udp
            .as_ref()
            .expect("UDP")
            .live_ids
            .lock()
            .expect("live IDs")
            .len(),
        0
    );
    for socket in &upstreams {
        assert_eq!(
            socket
                .try_recv(&mut [0])
                .expect_err("maximum+1 emitted no hop")
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }

    let payload = vec![0x6b; limit];
    let exact =
        encode_udp_datagram(&target, &payload, &mut socks).expect("exact eight-hop maximum");
    application
        .send_to(&socks[..exact], relay)
        .await
        .expect("exact send");
    let mut wire = vec![0; MAX_UDP_WIRE_LEN];
    let (wire_len, request_peer) =
        tokio::time::timeout(Duration::from_secs(2), upstreams[0].recv_from(&mut wire))
            .await
            .expect("eight-hop request timeout")
            .expect("eight-hop request");
    assert_eq!(wire_len, MAX_UDP_WIRE_LEN);
    let clock = SystemClock::new();
    let random = SystemRandom;
    let mut nested = wire[..wire_len].to_vec();
    for layer in 0..MAX_UDP_PLAN_HOPS {
        let server = UdpServer::new(&routing.outbounds[layer].shadowsocks().unwrap().keys)
            .expect("hop server");
        let mut scratch = UdpPacketScratch::new();
        let pending = server
            .prepare_request(&clock, &nested, &mut scratch)
            .expect("hop credential");
        let expected = if layer + 1 == MAX_UDP_PLAN_HOPS {
            target.clone()
        } else {
            TargetAddr::ipv4(servers[layer + 1]).expect("next hop")
        };
        assert_eq!(pending.datagram().target(), &expected, "hop {layer}");
        let next = pending.datagram().payload().to_vec();
        let (_, commit) = pending.into_parts();
        let accepted = server
            .commit_request(commit, request_peer, clock.monotonic_now(), &random)
            .expect("hop commit");
        assert_eq!(
            server
                .session_snapshot(accepted.capability())
                .expect("hop snapshot")
                .expect("hop session")
                .highest_packet_id(),
            Some(0),
            "hop {layer} packet ID"
        );
        nested = next;
    }
    assert_eq!(nested, payload);
    for socket in upstreams.iter().skip(1) {
        assert_eq!(
            socket
                .try_recv(&mut [0])
                .expect_err("only hop A receives")
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }
    assert_eq!(
        context
            .egress
            .udp
            .as_ref()
            .expect("UDP")
            .live_ids
            .lock()
            .expect("live IDs")
            .len(),
        MAX_UDP_PLAN_HOPS
    );
    assert_eq!(registry.snapshot().udp_queued_datagrams, 0);

    drop(peer);
    finish_udp_relay(running).await;
    assert!(
        context
            .egress
            .udp
            .as_ref()
            .expect("UDP")
            .live_ids
            .lock()
            .expect("live IDs")
            .is_empty()
    );
    assert_eq!(registry.snapshot(), baseline);
    drop(UdpSocket::bind(relay).await.expect("relay rebind"));
    std::fs::remove_file(path).expect("remove config");
}

async fn stock_udp_chain_case(methods: [MethodProfile; 2], invalid_inner: bool) {
    let listen = reserve_address();
    let upstreams = [
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("outer upstream"),
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("inner upstream"),
    ];
    let servers: [SocketAddrV4; 2] = upstreams.each_ref().map(|socket| {
        let SocketAddr::V4(address) = socket.local_addr().expect("upstream address") else {
            unreachable!("IPv4 upstream")
        };
        address
    });
    let (path, config) = client_udp_chain_test_config(listen, servers, methods);
    let bound_outbounds = prepare_client_outbounds(
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
    .expect("bound outbounds");
    let keys = methods
        .map(|method| MethodKeyAdapter::new(MethodSinglePskProvider::new(psk_for_method(method))));
    let protocols = keys
        .each_ref()
        .map(|keys| UdpServer::new(keys).expect("protocol server"));
    let registry = OwnerRegistry::new();
    let (stop, task) = spawn_test_client(config, &registry);
    wait_until_bound(listen).await;
    let (control, application, relay) = udp_association(listen).await;
    let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
    let mut socks = vec![0; MAX_SOCKS_UDP_DATAGRAM_BYTES];
    let socks_len = encode_udp_datagram(&target, b"ping", &mut socks).expect("SOCKS request");
    application
        .send_to(&socks[..socks_len], relay)
        .await
        .expect("application send");

    let clock = SystemClock::new();
    let random = SystemRandom;
    let mut scratch = UdpPacketScratch::new();
    let mut wire = vec![0; MAX_UDP_WIRE_LEN];
    let (outer_len, peer) =
        tokio::time::timeout(Duration::from_secs(2), upstreams[0].recv_from(&mut wire))
            .await
            .expect("outer request timeout")
            .expect("outer request");
    let outer = protocols[0]
        .prepare_request(&clock, &wire[..outer_len], &mut scratch)
        .expect("outer credential");
    let wrong_outer_keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
        other_psk_for_method(methods[0]),
    ));
    assert!(
        UdpServer::new(&wrong_outer_keys)
            .expect("wrong outer server")
            .prepare_request(&clock, &wire[..outer_len], &mut scratch)
            .is_err(),
        "wrong outer PSK authenticated"
    );
    assert_eq!(
        outer.datagram().target(),
        &TargetAddr::ipv4(servers[1]).expect("inner target")
    );
    let inner_wire = outer.datagram().payload().to_vec();
    let (_, outer_commit) = outer.into_parts();
    let outer_accepted = protocols[0]
        .commit_request(outer_commit, peer, clock.monotonic_now(), &random)
        .expect("outer commit");
    let inner = protocols[1]
        .prepare_request(&clock, &inner_wire, &mut scratch)
        .expect("inner credential");
    let wrong_inner_keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
        other_psk_for_method(methods[1]),
    ));
    assert!(
        UdpServer::new(&wrong_inner_keys)
            .expect("wrong inner server")
            .prepare_request(&clock, &inner_wire, &mut scratch)
            .is_err(),
        "wrong inner PSK authenticated"
    );
    assert_eq!(inner.datagram().target(), &target);
    assert_eq!(inner.datagram().payload(), b"ping");
    assert_eq!(
        upstreams[1]
            .try_recv(&mut [0])
            .expect_err("only first hop receives network traffic")
            .kind(),
        io::ErrorKind::WouldBlock
    );
    let (_, inner_commit) = inner.into_parts();
    let inner_accepted = protocols[1]
        .commit_request(inner_commit, peer, clock.monotonic_now(), &random)
        .expect("inner commit");

    let inner_response = protocols[1]
        .encode_response(
            inner_accepted.capability(),
            &clock,
            &random,
            &test_datagram(target.clone(), b"pong"),
            0,
            &mut wire,
        )
        .expect("inner response");
    let inner_wire = wire[..inner_response.wire_len()].to_vec();
    if invalid_inner {
        let stable = active(registry.snapshot());
        let wrong_intermediate = protocols[0]
            .encode_response(
                outer_accepted.capability(),
                &clock,
                &random,
                &test_datagram(target.clone(), &inner_wire),
                0,
                &mut wire,
            )
            .expect("wrong intermediate wrapper");
        upstreams[0]
            .send_to(&wire[..wrong_intermediate.wire_len()], peer)
            .await
            .expect("wrong intermediate send");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), application.recv(&mut socks))
                .await
                .is_err(),
            "wrong intermediate reached the application"
        );
        assert_eq!(active(registry.snapshot()), stable);

        let mut tampered = inner_wire.clone();
        *tampered.last_mut().expect("inner wire") ^= 1;
        let invalid_outer = protocols[0]
            .encode_response(
                outer_accepted.capability(),
                &clock,
                &random,
                &test_datagram(
                    TargetAddr::ipv4(servers[1]).expect("inner target"),
                    &tampered,
                ),
                0,
                &mut wire,
            )
            .expect("invalid inner wrapper");
        upstreams[0]
            .send_to(&wire[..invalid_outer.wire_len()], peer)
            .await
            .expect("invalid response send");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), application.recv(&mut socks))
                .await
                .is_err(),
            "invalid inner reached the application"
        );
        assert_eq!(active(registry.snapshot()), stable);

        let outer_tamper = protocols[0]
            .encode_response(
                outer_accepted.capability(),
                &clock,
                &random,
                &test_datagram(
                    TargetAddr::ipv4(servers[1]).expect("inner target"),
                    &inner_wire,
                ),
                0,
                &mut wire,
            )
            .expect("outer tamper wrapper");
        let mut outer_tamper = wire[..outer_tamper.wire_len()].to_vec();
        *outer_tamper.last_mut().expect("outer wire") ^= 1;
        upstreams[0]
            .send_to(&outer_tamper, peer)
            .await
            .expect("outer tamper send");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), application.recv(&mut socks))
                .await
                .is_err(),
            "tampered outer reached the application"
        );
        assert_eq!(active(registry.snapshot()), stable);
    }
    let outer_response = protocols[0]
        .encode_response(
            outer_accepted.capability(),
            &clock,
            &random,
            &test_datagram(
                TargetAddr::ipv4(servers[1]).expect("inner target"),
                &inner_wire,
            ),
            0,
            &mut wire,
        )
        .expect("outer response");
    upstreams[0]
        .send_to(&wire[..outer_response.wire_len()], peer)
        .await
        .expect("outer response send");
    let received = tokio::time::timeout(Duration::from_secs(2), application.recv(&mut socks))
        .await
        .expect("application response timeout")
        .expect("application response");
    let response = decode_udp_datagram(&socks[..received]).expect("SOCKS response");
    assert_eq!(response.to_target_addr(), target);
    assert_eq!(response.payload(), b"pong");

    if invalid_inner {
        let stable = active(registry.snapshot());
        upstreams[0]
            .send_to(&wire[..outer_response.wire_len()], peer)
            .await
            .expect("outer replay send");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), application.recv(&mut socks))
                .await
                .is_err(),
            "outer replay reached the application"
        );
        assert_eq!(active(registry.snapshot()), stable);

        let fresh_outer = protocols[0]
            .encode_response(
                outer_accepted.capability(),
                &clock,
                &random,
                &test_datagram(
                    TargetAddr::ipv4(servers[1]).expect("inner target"),
                    &inner_wire,
                ),
                0,
                &mut wire,
            )
            .expect("fresh outer replayed inner");
        upstreams[0]
            .send_to(&wire[..fresh_outer.wire_len()], peer)
            .await
            .expect("fresh outer send");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), application.recv(&mut socks))
                .await
                .is_err(),
            "fresh outer replayed inner reached the application"
        );
        assert_eq!(active(registry.snapshot()), stable);

        let next_inner = protocols[1]
            .encode_response(
                inner_accepted.capability(),
                &clock,
                &random,
                &test_datagram(target.clone(), b"next"),
                0,
                &mut wire,
            )
            .expect("next inner response");
        let next_inner = wire[..next_inner.wire_len()].to_vec();
        let next_outer = protocols[0]
            .encode_response(
                outer_accepted.capability(),
                &clock,
                &random,
                &test_datagram(
                    TargetAddr::ipv4(servers[1]).expect("inner target"),
                    &next_inner,
                ),
                0,
                &mut wire,
            )
            .expect("next outer response");
        upstreams[0]
            .send_to(&wire[..next_outer.wire_len()], peer)
            .await
            .expect("next response send");
        let received = tokio::time::timeout(Duration::from_secs(2), application.recv(&mut socks))
            .await
            .expect("next response timeout")
            .expect("next response");
        assert_eq!(
            decode_udp_datagram(&socks[..received])
                .expect("next SOCKS response")
                .payload(),
            b"next"
        );
    }

    if !invalid_inner {
        for (case, (target, encoded_target_len)) in [
            (
                TargetAddr::ipv4("192.0.2.2:53".parse().expect("IPv4")).expect("target"),
                7,
            ),
            (TargetAddr::domain("example.test", 53).expect("domain"), 16),
            (
                TargetAddr::ip("[2001:db8::1]:53".parse().expect("IPv6")).expect("target"),
                19,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let limit =
                composed_udp_plan_limit(&bound_outbounds, &[0, 1], false, encoded_target_len);
            let before = protocols[0]
                .session_snapshot(outer_accepted.capability())
                .expect("outer snapshot")
                .expect("outer generation")
                .highest_packet_id();
            let too_large = vec![0; limit + 1];
            let length = encode_udp_datagram(&target, &too_large, &mut socks)
                .expect("SOCKS-valid nested maximum+1");
            application
                .send_to(&socks[..length], relay)
                .await
                .expect("maximum+1 send");
            assert!(
                tokio::time::timeout(Duration::from_millis(100), upstreams[0].recv(&mut wire))
                    .await
                    .is_err(),
                "nested maximum+1 reached outer hop"
            );
            assert_eq!(
                protocols[0]
                    .session_snapshot(outer_accepted.capability())
                    .expect("outer snapshot")
                    .expect("outer generation")
                    .highest_packet_id(),
                before
            );

            let exact = vec![case as u8; limit];
            let length =
                encode_udp_datagram(&target, &exact, &mut socks).expect("exact nested maximum");
            application
                .send_to(&socks[..length], relay)
                .await
                .expect("exact send");
            let (length, request_peer) =
                tokio::time::timeout(Duration::from_secs(2), upstreams[0].recv_from(&mut wire))
                    .await
                    .expect("exact request timeout")
                    .expect("exact request");
            let outer = protocols[0]
                .prepare_request(&clock, &wire[..length], &mut scratch)
                .expect("exact outer");
            assert_eq!(
                outer.datagram().target(),
                &TargetAddr::ipv4(servers[1]).expect("inner target")
            );
            let inner_wire = outer.datagram().payload().to_vec();
            let (_, commit) = outer.into_parts();
            protocols[0]
                .commit_request(commit, request_peer, clock.monotonic_now(), &random)
                .expect("exact outer commit");
            let inner = protocols[1]
                .prepare_request(&clock, &inner_wire, &mut scratch)
                .expect("exact inner");
            assert_eq!(inner.datagram().target(), &target);
            assert_eq!(inner.datagram().payload(), exact);
            let (_, commit) = inner.into_parts();
            protocols[1]
                .commit_request(commit, request_peer, clock.monotonic_now(), &random)
                .expect("exact inner commit");
            assert_eq!(
                protocols[0]
                    .session_snapshot(outer_accepted.capability())
                    .expect("outer snapshot")
                    .expect("outer generation")
                    .highest_packet_id(),
                Some(case as u64 + 1)
            );
        }
    }

    stop.send(()).expect("stop client");
    assert_eq!(task.await.expect("client"), Ok(()));
    drop((control, application));
    std::fs::remove_file(path).expect("remove chain config");
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
}
