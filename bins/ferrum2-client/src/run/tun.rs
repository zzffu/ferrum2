use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use ferrum2_config::TunConfig;
use ferrum2_core::TargetAddr;
use ferrum2_core::route::{EgressPlanSnapshot, Network};
use ferrum2_dns::{ProxyIngress, ProxyTransport};
use ferrum2_observability::{Direction, Outcome, Role};
use ferrum2_runtime::{ProcessCancellation, ProcessRoot, relay_lifecycle};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;
use tokio::time::Instant;

use super::RunError;
use super::context::{ClientContext, ClientRouting};
use super::egress::{UdpPlanResponseError, composed_udp_plan_limit};
use super::routing::{ClientTerminalRoute, ReplayIo, relay_hijacked_tcp};
use super::tokio_io::TokioFramed;

pub(super) fn process_root(
    config: TunConfig,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
) -> ProcessRoot<RunError> {
    let udp_sources = [
        IpAddr::V4(config.ipv4_address.addr()),
        IpAddr::V6(config.ipv6_address.addr()),
    ];
    let metrics = Arc::clone(&context.metrics);
    let accepted_metrics = Arc::clone(&metrics);
    let handler_context = Arc::clone(&context);
    let udp_context = Arc::clone(&context);
    let tcp_routing = Arc::clone(&routing);
    ferrum2_tun::process_root(
        ferrum2_tun::Config {
            adapter_name: config.adapter_name,
            ipv4: config.ipv4_address.addr(),
            ipv4_prefix: config.ipv4_address.prefix_len(),
            ipv6: config.ipv6_address.addr(),
            ipv6_prefix: config.ipv6_address.prefix_len(),
            mtu: config.mtu,
            ring_capacity: config.ring_capacity,
            ready_timeout: config.ready_timeout,
            max_tcp_flows: config.max_tcp_flows,
            tcp_buffer_bytes: config.tcp_buffer_bytes,
            tcp_timeout: context.runtime.idle_timeout,
            max_udp_mappings: config.max_udp_mappings,
            max_udp_buffered_bytes: config.max_udp_buffered_bytes,
            owned_buffer_bytes: config.owned_buffer_bytes,
        },
        RunError::StartupProtocol,
        RunError::RuntimeRoot,
        RunError::ShutdownCleanup,
        move |flow, cancellation| {
            let context = Arc::clone(&handler_context);
            let routing = Arc::clone(&tcp_routing);
            Box::pin(run_tcp(
                flow.target(),
                flow,
                cancellation,
                context,
                routing,
                inbound,
            ))
        },
        move |candidate, cancellation| {
            let context = Arc::clone(&udp_context);
            let routing = Arc::clone(&routing);
            Box::pin(run_udp(
                candidate,
                cancellation,
                context,
                routing,
                inbound,
                udp_sources,
            ))
        },
        (
            move || accepted_metrics.tun_packet_accepted(),
            move || metrics.tun_packet_foundation_dropped(),
        ),
    )
}

#[derive(Clone)]
enum TunUdpTerminal {
    Route(EgressPlanSnapshot),
    HijackDns,
    Reject,
}

async fn run_udp(
    candidate: ferrum2_tun::UdpCandidate<TunUdpTerminal>,
    cancellation: ProcessCancellation,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
    udp_sources: [IpAddr; 2],
) {
    let tuple = candidate.tuple();
    if !udp_sources.contains(&tuple.source().ip()) {
        return;
    }
    let Ok(target) = TargetAddr::ip(tuple.target()) else {
        return;
    };
    let Some((terminal, selected_bound)) = select_udp_terminal(
        &routing,
        inbound,
        &target,
        candidate.payload(),
        candidate.packet_payload_bound(),
        &context.metrics,
    ) else {
        return;
    };
    let Ok(mapping) = candidate.commit(terminal, selected_bound).await else {
        return;
    };
    match mapping.terminal().clone() {
        TunUdpTerminal::Route(plan) => {
            run_udp_route(mapping, plan, cancellation, context, routing).await;
        }
        TunUdpTerminal::HijackDns => {
            run_udp_dns(mapping, cancellation, context, inbound).await;
        }
        TunUdpTerminal::Reject => run_udp_reject(mapping, cancellation).await,
    }
}

fn select_udp_terminal(
    routing: &ClientRouting,
    inbound: usize,
    target: &TargetAddr,
    payload: &[u8],
    packet_payload_bound: usize,
    metrics: &ferrum2_observability::Metrics,
) -> Option<(TunUdpTerminal, usize)> {
    let terminal = routing.select_terminal(inbound, Network::Udp, target, Some(payload), metrics);
    let selected = match terminal {
        ClientTerminalRoute::Route(plan) => {
            let encoded_target_len = match target.as_socket_addr()? {
                SocketAddr::V4(_) => 7,
                SocketAddr::V6(_) => 19,
            };
            let bound =
                composed_udp_plan_limit(&routing.outbounds, plan.hops(), false, encoded_target_len)
                    .min(packet_payload_bound);
            (TunUdpTerminal::Route(plan), bound)
        }
        ClientTerminalRoute::HijackDns => (TunUdpTerminal::HijackDns, packet_payload_bound),
        ClientTerminalRoute::Reject => (TunUdpTerminal::Reject, packet_payload_bound),
    };
    if payload.len() > selected.1 {
        None
    } else {
        Some(selected)
    }
}

async fn run_udp_route(
    mut mapping: ferrum2_tun::UdpMapping<TunUdpTerminal>,
    plan: EgressPlanSnapshot,
    cancellation: ProcessCancellation,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
) {
    let Some(server) = plan
        .hops()
        .first()
        .and_then(|hop| routing.outbounds.get(*hop))
        .map(|outbound| outbound.udp_server)
    else {
        return;
    };
    if !server.ip().is_loopback()
        || mapping.tuple().target().ip().is_loopback()
        || mapping.tuple().source().ip().is_loopback()
    {
        return;
    }
    let mut force = cancellation.clone();
    let prepared = tokio::select! {
        () = force.forced() => return,
        prepared = context.egress.prepare_udp(plan, server, UdpSocket::bind) => prepared,
    };
    let Ok(mut association) = prepared else {
        return;
    };
    if association.activate(&context.egress).is_err() {
        return;
    }
    let Ok(mut session_cancelled) = association.cancellation() else {
        return;
    };
    loop {
        let Ok(idle_deadline) = association.idle_deadline() else {
            return;
        };
        let mut forced = cancellation.clone();
        tokio::select! {
            () = forced.forced() => return,
            changed = session_cancelled.changed() => {
                let _ = changed;
                return;
            }
            () = tokio::time::sleep_until(idle_deadline) => {
                if association.idle_expired(idle_deadline) {
                    return;
                }
            }
            datagram = mapping.receive() => {
                let Some(datagram) = datagram else { return };
                let payload_len = datagram.payload().len();
                let Ok(target) = TargetAddr::ip(datagram.tuple().target()) else { return };
                let wire_len = match association.prepare_application_request(
                    &context.egress,
                    &routing.outbounds,
                    target,
                    datagram.payload(),
                    Instant::now(),
                ) {
                    Ok(length) => length,
                    Err(UdpPlanResponseError::Packet(_)
                        | UdpPlanResponseError::Runtime(_)) => continue,
                };
                drop(datagram);
                let mut send_forced = cancellation.clone();
                let sent = tokio::select! {
                    () = send_forced.forced() => return,
                    changed = session_cancelled.changed() => {
                        let _ = changed;
                        return;
                    }
                    result = association.send_encoded_request(wire_len) => result,
                };
                if !matches!(sent, Ok(sent) if sent == wire_len) {
                    return;
                }
                context.metrics.udp_datagram(
                    Role::Client,
                    Direction::ClientToTarget,
                    Outcome::Accepted,
                );
                context.metrics.add_udp_bytes(
                    Role::Client,
                    Direction::ClientToTarget,
                    payload_len as u64,
                );
            }
            received = association.receive_response_wire() => {
                let Ok(wire_len) = received else { return };
                let Ok((source, payload)) = association.prepare_application_response(
                    &context.egress,
                    &routing.outbounds,
                    wire_len,
                ) else {
                    continue;
                };
                let Some(source) = source.as_socket_addr() else { continue };
                if mapping.send_response(source, &payload) {
                    context.metrics.udp_datagram(
                        Role::Client,
                        Direction::TargetToClient,
                        Outcome::Accepted,
                    );
                    context.metrics.add_udp_bytes(
                        Role::Client,
                        Direction::TargetToClient,
                        payload.len() as u64,
                    );
                }
            }
        }
    }
}

async fn run_udp_dns(
    mut mapping: ferrum2_tun::UdpMapping<TunUdpTerminal>,
    cancellation: ProcessCancellation,
    context: Arc<ClientContext>,
    inbound: usize,
) {
    let Some(proxy) = context
        .dns
        .as_ref()
        .and_then(|proxy| proxy.get())
        .map(Arc::clone)
    else {
        return;
    };
    loop {
        let mut forced = cancellation.clone();
        let datagram = tokio::select! {
            () = forced.forced() => return,
            datagram = mapping.receive() => datagram,
        };
        let Some(datagram) = datagram else { return };
        let response = proxy
            .answer(
                ProxyIngress::Ordinary(inbound),
                ProxyTransport::Udp,
                datagram.payload(),
            )
            .await;
        if let Some(response) = response {
            let _ = mapping.send_response(datagram.tuple().target(), &response);
        }
    }
}

async fn run_udp_reject(
    mut mapping: ferrum2_tun::UdpMapping<TunUdpTerminal>,
    cancellation: ProcessCancellation,
) {
    loop {
        let mut forced = cancellation.clone();
        if tokio::select! {
            () = forced.forced() => None,
            datagram = mapping.receive() => datagram,
        }
        .is_none()
        {
            return;
        }
    }
}

async fn run_tcp<IO>(
    target: SocketAddr,
    mut flow: IO,
    mut cancellation: ProcessCancellation,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let Ok(target) = TargetAddr::ip(target) else {
        return;
    };
    let Some(selection) = routing
        .select_tcp(
            inbound,
            &target,
            &mut flow,
            cancellation.clone().forced(),
            &context.registry,
            &context.metrics,
        )
        .await
    else {
        return;
    };
    let mut flow = ReplayIo::new(flow, selection.prefix);
    match selection.terminal {
        ClientTerminalRoute::Reject => {}
        ClientTerminalRoute::HijackDns => {
            let Some(proxy) = context
                .dns
                .as_ref()
                .and_then(|proxy| proxy.get())
                .map(Arc::clone)
            else {
                return;
            };
            relay_hijacked_tcp(
                &mut flow,
                inbound,
                &proxy,
                context.runtime.idle_timeout,
                cancellation.forced(),
            )
            .await;
        }
        ClientTerminalRoute::Route(plan) => {
            let opened = tokio::select! {
                _ = cancellation.forced() => return,
                opened = context.egress.open_tcp(
                    plan,
                    &target,
                    None,
                    #[cfg(test)]
                    None,
                ) => opened,
            };
            let Ok(opened) = opened else {
                return;
            };
            let mut opened = TokioFramed::new(opened);
            let _ = relay_lifecycle(
                &mut flow,
                &mut opened,
                context.runtime.idle_timeout,
                &context.registry,
                cancellation.forced(),
            )
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;
    use std::sync::Arc;
    use std::time::Duration;

    use ferrum2_dns::{DnsUpstreamSpec, DnsUpstreamTransport, TaggedResolver};
    use ferrum2_runtime::{
        OwnerRegistry, PreparedProcessRoot, ProcessCancellation, ProcessFuture, ProcessRoot,
        ProcessSupervisor,
    };
    use tokio::sync::Notify;

    use super::super::test_support::*;
    use super::super::{RunError, report_result};
    use super::{TunUdpTerminal, run_tcp, select_udp_terminal};

    struct NeverPrepared;

    impl PreparedProcessRoot<RunError> for NeverPrepared {
        fn activate(&mut self) -> Result<(), RunError> {
            Ok(())
        }

        fn run(
            self: Box<Self>,
            _cancellation: ProcessCancellation,
        ) -> ProcessFuture<Result<(), RunError>> {
            Box::pin(async { Ok(()) })
        }

        fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn tun_udp_over_limit_is_mapping_free_then_selector_snapshot_is_fixed() {
        let (outbounds, route, selector) = chain_test_setup(
            [
                ferrum2_crypto::MethodProfile::Blake3Aes128Gcm2022,
                ferrum2_crypto::MethodProfile::Blake3Aes256Gcm2022,
                ferrum2_crypto::MethodProfile::Blake3ChaCha20Poly13052022,
                ferrum2_crypto::MethodProfile::Blake3Aes128Gcm2022,
            ],
            20_000,
        );
        let routing = ClientRouting {
            legacy: route,
            program: None,
            outbounds,
        };
        let target = TargetAddr::ip("192.0.2.1:53".parse().expect("target")).expect("target");
        let metrics = ferrum2_observability::Metrics::new();
        let (_, bound) = select_udp_terminal(&routing, 0, &target, b"first", 1_392, &metrics)
            .expect("first selector snapshot");
        assert!(
            select_udp_terminal(&routing, 0, &target, &vec![0; bound + 1], 1_392, &metrics)
                .is_none(),
            "selected-plan maximum+1 creates no terminal token"
        );

        selector
            .switch("manual", "c-d")
            .expect("switch after rejected candidate");
        let (terminal, _) = select_udp_terminal(&routing, 0, &target, b"valid", 1_392, &metrics)
            .expect("current selector after no-commit");
        let TunUdpTerminal::Route(snapshot) = terminal else {
            panic!("route terminal");
        };
        assert_eq!(snapshot.hops(), &[2, 3]);
        selector
            .switch("manual", "a-b")
            .expect("switch after terminal snapshot");
        assert_eq!(
            snapshot.hops(),
            &[2, 3],
            "committed terminal token owns an immutable plan snapshot"
        );
    }

    #[test]
    fn tun_dns_and_reject_are_client_owned_terminal_modes_without_route_fallback() {
        let (path, _) = client_test_config(reserve_address(), reserve_address());
        std::fs::write(
            &path,
            r#"schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
[[outbounds]]
tag = "fallback"
server = "192.0.2.10:8388"
[route]
final = "fallback"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "192.0.2.53"
port = 53
action = "hijack-dns"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "192.0.2.54"
port = 53
action = "reject"
[dns]
[[dns.inbounds]]
tag = "dns-control"
listen = "127.0.0.1:5300"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "127.0.0.1:5301"
[dns.route]
final = "resolver"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#,
        )
        .expect("TUN UDP modes config");
        let config = ferrum2_config::load_client(&path).expect("validated TUN UDP modes");
        std::fs::remove_file(path).expect("remove TUN UDP modes config");
        let inbound = config.inbounds.len();
        let outbounds = prepare_client_outbounds(config.outbounds, config.outbound_psks)
            .expect("outbound contexts");
        let routing = ClientRouting {
            legacy: config.route,
            program: config.route_program,
            outbounds,
        };
        let metrics = ferrum2_observability::Metrics::new();
        for (address, expected) in [("192.0.2.53:53", "dns"), ("192.0.2.54:53", "reject")] {
            let target = TargetAddr::ip(address.parse().expect("target")).expect("target");
            let (terminal, bound) =
                select_udp_terminal(&routing, inbound, &target, b"query", 1_392, &metrics)
                    .expect("terminal mode");
            assert_eq!(bound, 1_392);
            assert!(
                matches!(
                    (terminal, expected),
                    (TunUdpTerminal::HijackDns, "dns") | (TunUdpTerminal::Reject, "reject")
                ),
                "ordinary route fallback did not replace the terminal mode"
            );
        }
    }

    #[tokio::test]
    async fn cancelled_prepare_cleanup_failure_maps_to_shutdown_cleanup() {
        let entered = Arc::new(Notify::new());
        let prepare_entered = Arc::clone(&entered);
        let root = ProcessRoot::new_cancellable(move |mut cancellation| async move {
            prepare_entered.notify_one();
            cancellation.cancelled().await;
            Err::<Option<NeverPrepared>, _>(RunError::ShutdownCleanup)
        });
        let supervisor =
            ProcessSupervisor::new(vec![root], Duration::from_secs(1), OwnerRegistry::new())
                .expect("one required root");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(supervisor.run_until(async move {
            let _ = shutdown_rx.await;
        }));

        entered.notified().await;
        shutdown_tx.send(()).expect("shutdown");
        let report = run.await.expect("process owner");
        assert_eq!(report_result(report), Err(RunError::ShutdownCleanup));
    }

    #[tokio::test]
    async fn tun_tcp_dns_answer_failure_closes_flow_without_route_or_fallback_attempt() {
        let fallback = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("fallback listener");
        let fallback_address = match fallback.local_addr().expect("fallback address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 fallback"),
        };
        let dns_upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("DNS upstream");
        let dns_address = dns_upstream.local_addr().expect("DNS upstream address");
        let dns_inbound = reserve_address();
        let (path, _) = client_test_config(reserve_address(), fallback_address);
        std::fs::write(
            &path,
            format!(
                r#"schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
[[outbounds]]
tag = "fallback"
server = "{fallback_address}"
[route]
final = "fallback"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
ip = "192.0.2.53"
port = 53
action = "hijack-dns"
[dns]
[[dns.inbounds]]
tag = "dns-control"
listen = "{dns_inbound}"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "{dns_address}"
[dns.route]
final = "resolver"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#
            ),
        )
        .expect("TUN DNS failure config");
        let config = ferrum2_config::load_client(&path).expect("validated TUN DNS config");
        std::fs::remove_file(&path).expect("remove TUN DNS config");
        let runtime = config.runtime;
        let test_server = config.server;
        let outbounds = prepare_client_outbounds(config.outbounds, config.outbound_psks)
            .expect("test outbounds");
        let routing = Arc::new(ClientRouting {
            legacy: config.route,
            program: config.route_program,
            outbounds: Arc::clone(&outbounds),
        });
        let (resolver, mut resolver_owner) = TaggedResolver::direct(
            vec![DnsUpstreamSpec {
                transport: DnsUpstreamTransport::Udp,
                address: dns_address,
                detour: None,
            }],
            Duration::from_secs(1),
            NonZeroU16::new(1).expect("one DNS query"),
        )
        .expect("test resolver");
        resolver_owner.ready().await.expect("resolver ready");
        let proxy = Arc::new(DnsProxy::new(Arc::new(resolver), |_, _, _, _| Some(0)));
        let dns = Arc::new(std::sync::OnceLock::new());
        assert!(dns.set(proxy).is_ok(), "one DNS proxy");
        let registry = OwnerRegistry::new();
        let context = Arc::new(ClientContext {
            inbound: Socks5Inbound::new(),
            egress: Arc::new(ClientEgressEngine::new(
                outbounds,
                TokioConnector::new(TcpConnector::new(runtime.connect_timeout)),
                SystemClock::new(),
                SystemRandom,
                (runtime.connect_timeout, runtime.handshake_timeout),
                None,
                None,
            )),
            keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(config.psk)),
            runtime,
            udp_associate_enabled: false,
            registry: registry.clone(),
            metrics: Arc::new(Metrics::new()),
            dns: Some(dns),
            test_udp_server: test_server,
        });

        let (cancellation_sender, cancellation_receiver) = tokio::sync::oneshot::channel();
        let root = ProcessRoot::new_cancellable(move |mut cancellation| async move {
            cancellation_sender
                .send(cancellation.clone())
                .expect("one cancellation view");
            cancellation.cancelled().await;
            Ok::<Option<NeverPrepared>, RunError>(None)
        });
        let cancellation_registry = OwnerRegistry::new();
        let supervisor = ProcessSupervisor::new(
            vec![root],
            Duration::from_secs(1),
            cancellation_registry.clone(),
        )
        .expect("cancellation root");
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let supervisor = tokio::spawn(supervisor.run_until(async move {
            let _ = shutdown_receiver.await;
        }));
        let cancellation = cancellation_receiver.await.expect("active cancellation");

        let target: SocketAddr = "192.0.2.53:53".parse().expect("DNS target");
        let (flow, mut peer) = tokio::io::duplex(64);
        peer.write_all(&[0, 1, 0])
            .await
            .expect("malformed DNS frame");
        peer.shutdown().await.expect("DNS request half-close");
        run_tcp(target, flow, cancellation, Arc::clone(&context), routing, 0).await;
        assert_eq!(peer.read(&mut [0; 1]).await.expect("terminal close"), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), fallback.accept())
                .await
                .is_err(),
            "DNS failure evaluated the final route or fallback egress"
        );
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());

        shutdown_sender.send(()).expect("stop cancellation root");
        assert_eq!(
            report_result(supervisor.await.expect("cancellation supervisor")),
            Ok(())
        );
        drop(context);
        resolver_owner.shutdown().await.expect("resolver shutdown");
        assert_eq!(
            active(cancellation_registry.snapshot()),
            OwnerSnapshot::default()
        );
    }
}
