use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ferrum2_config::TunConfig;
use ferrum2_core::TargetAddr;
use ferrum2_core::route::{EgressPlanSnapshot, Network};
use ferrum2_dns::{ProxyIngress, ProxyTransport};
use ferrum2_observability::{Direction, Outcome, Role};
use ferrum2_runtime::{ProcessCancellation, ProcessRoot, relay_lifecycle};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

use super::RunError;
use super::context::{ClientContext, ClientRouting};
use super::egress::{ClientRequestOrigin, UdpPlanResponseError, composed_udp_plan_limit};
use super::routing::{ClientTerminalRoute, ReplayIo, relay_hijacked_tcp};
use super::tokio_io::TokioFramed;

pub(super) fn process_root(
    config: TunConfig,
    udp_idle_timeout: Duration,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
    underlay: ferrum2_tun::UnderlayPublisher,
    direct_binder: bool,
) -> ProcessRoot<RunError> {
    let ipv4_dns_address = config.ipv4_dns_address;
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
            udp_timeout: udp_idle_timeout,
            max_udp_mappings: config.max_udp_mappings,
            max_udp_buffered_bytes: config.max_udp_buffered_bytes,
            owned_buffer_bytes: config.owned_buffer_bytes,
            capture_routes: config
                .capture_routes
                .into_iter()
                .map(|route| (route.network(), route.prefix_len()))
                .collect(),
            physical_endpoints: config.physical_endpoints,
            default_binder: direct_binder,
            ipv4_dns_address,
        },
        underlay,
        RunError::StartupProtocol,
        RunError::RuntimeRoot,
        RunError::ShutdownCleanup,
        context.registry.clone(),
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
                ipv4_dns_address,
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
                ipv4_dns_address,
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
    ipv4_dns_address: Option<std::net::Ipv4Addr>,
) {
    let tuple = candidate.tuple();
    let Ok(target) = TargetAddr::ip(tuple.target()) else {
        return;
    };
    let Ok(mut route_scratch) = routing.route_scratch() else {
        return;
    };
    let request = TunUdpRouteRequest {
        routing: &routing,
        inbound,
        ipv4_dns_address,
        target: &target,
        payload: candidate.payload(),
        packet_payload_bound: candidate.packet_payload_bound(),
        metrics: &context.metrics,
    };
    let Ok(Some((terminal, selected_bound))) =
        select_udp_terminal_with_scratch(request, route_scratch.as_mut())
    else {
        return;
    };
    let Ok(mapping) = candidate.commit(terminal, selected_bound).await else {
        return;
    };
    match mapping.terminal().clone() {
        TunUdpTerminal::Route(plan) => {
            run_udp_route(mapping, plan, cancellation, context, routing, inbound).await;
        }
        TunUdpTerminal::HijackDns => {
            run_udp_dns(mapping, cancellation, context, inbound).await;
        }
        TunUdpTerminal::Reject => run_udp_reject(mapping, cancellation).await,
    }
}

struct TunUdpRouteRequest<'a> {
    routing: &'a ClientRouting,
    inbound: usize,
    ipv4_dns_address: Option<std::net::Ipv4Addr>,
    target: &'a TargetAddr,
    payload: &'a [u8],
    packet_payload_bound: usize,
    metrics: &'a ferrum2_observability::Metrics,
}

fn select_udp_terminal_with_scratch(
    request: TunUdpRouteRequest<'_>,
    scratch: Option<&mut ferrum2_rule::RuleEvaluationScratch>,
) -> Result<Option<(TunUdpTerminal, usize)>, ferrum2_rule::RuleCompileError> {
    if is_synthetic_dns_target(request.target, request.ipv4_dns_address) {
        return Ok((request.payload.len() <= request.packet_payload_bound)
            .then_some((TunUdpTerminal::HijackDns, request.packet_payload_bound)));
    }
    let terminal = request.routing.select_terminal_with_scratch(
        request.inbound,
        Network::Udp,
        request.target,
        Some(request.payload),
        request.metrics,
        scratch,
    )?;
    let selected = match terminal {
        ClientTerminalRoute::Route(plan) => {
            let Some(target) = request.target.as_socket_addr() else {
                return Ok(None);
            };
            let encoded_target_len = match target {
                SocketAddr::V4(_) => 7,
                SocketAddr::V6(_) => 19,
            };
            let bound = composed_udp_plan_limit(
                &request.routing.outbounds,
                plan.hops(),
                false,
                encoded_target_len,
            )
            .min(request.packet_payload_bound);
            (TunUdpTerminal::Route(plan), bound)
        }
        ClientTerminalRoute::HijackDns => (TunUdpTerminal::HijackDns, request.packet_payload_bound),
        ClientTerminalRoute::Reject => (TunUdpTerminal::Reject, request.packet_payload_bound),
    };
    if request.payload.len() > selected.1 {
        Ok(None)
    } else {
        Ok(Some(selected))
    }
}

#[cfg(test)]
fn select_udp_terminal(
    routing: &ClientRouting,
    inbound: usize,
    ipv4_dns_address: Option<std::net::Ipv4Addr>,
    target: &TargetAddr,
    payload: &[u8],
    packet_payload_bound: usize,
    metrics: &ferrum2_observability::Metrics,
) -> Option<(TunUdpTerminal, usize)> {
    let mut scratch = routing.route_scratch().ok().flatten();
    select_udp_terminal_with_scratch(
        TunUdpRouteRequest {
            routing,
            inbound,
            ipv4_dns_address,
            target,
            payload,
            packet_payload_bound,
            metrics,
        },
        scratch.as_mut(),
    )
    .ok()
    .flatten()
}

async fn run_udp_route(
    mut mapping: ferrum2_tun::UdpMapping<TunUdpTerminal>,
    plan: EgressPlanSnapshot,
    cancellation: ProcessCancellation,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
) {
    let mut force = cancellation.clone();
    let Ok(original_target) = TargetAddr::ip(mapping.tuple().target()) else {
        return;
    };
    let prepared = tokio::select! {
        () = force.forced() => return,
        prepared = context.egress.prepare_udp_for_ingress(
            ClientRequestOrigin::Tun,
            inbound,
            Some(plan),
            Some(&original_target),
        ) => prepared,
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
                let Ok(response) = association.prepare_application_response(
                    &context.egress,
                    &routing.outbounds,
                    wire_len,
                ) else {
                    continue;
                };
                let Some(source) = response.datagram().target().as_socket_addr() else { continue };
                let payload = response.datagram().payload();
                if mapping.send_response(source, payload) {
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
                association.recycle_application_response(response);
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
    ipv4_dns_address: Option<std::net::Ipv4Addr>,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    if is_synthetic_dns_socket(target, ipv4_dns_address) {
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
        return;
    }
    let Ok(target) = TargetAddr::ip(target) else {
        return;
    };
    let Ok(Some(selection)) = routing
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
                opened = context.egress.open_tcp_for_ingress(
                    ClientRequestOrigin::Tun,
                    inbound,
                    Some(plan),
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

fn is_synthetic_dns_target(
    target: &TargetAddr,
    ipv4_dns_address: Option<std::net::Ipv4Addr>,
) -> bool {
    target
        .as_socket_addr()
        .is_some_and(|target| is_synthetic_dns_socket(target, ipv4_dns_address))
}

fn is_synthetic_dns_socket(
    target: SocketAddr,
    ipv4_dns_address: Option<std::net::Ipv4Addr>,
) -> bool {
    matches!(target, SocketAddr::V4(target) if target.port() == 53 && Some(*target.ip()) == ipv4_dns_address)
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

    #[tokio::test]
    async fn tun_udp_over_limit_is_mapping_free_then_selector_snapshot_is_fixed() {
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
        let (_, bound) = select_udp_terminal(&routing, 0, None, &target, b"first", 1_392, &metrics)
            .expect("first selector snapshot");
        assert!(
            select_udp_terminal(
                &routing,
                0,
                None,
                &target,
                &vec![0; bound + 1],
                1_392,
                &metrics,
            )
            .is_none(),
            "selected-plan maximum+1 creates no terminal token"
        );

        selector
            .switch("manual", "c-d")
            .expect("switch after rejected candidate");
        let (terminal, _) =
            select_udp_terminal(&routing, 0, None, &target, b"valid", 1_392, &metrics)
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

        let registry = OwnerRegistry::new();
        let live_ids = Arc::new(Mutex::new(HashSet::new()));
        let outbounds = prepare_client_outbounds(vec![
            ferrum2_config::ClientOutboundConfig::Direct {
                domain_resolver: ferrum2_config::DirectDomainResolver::System,
            },
            ferrum2_config::ClientOutboundConfig::Shadowsocks {
                server: "192.0.2.77:8388".parse().unwrap(),
                psk: Arc::new(default_test_psk()),
            },
        ])
        .expect("direct and proxy outbounds");
        let (route, direct_selector) = compile_selector_plans(
            &[TaggedInbound::new("tun", 0)],
            &[
                TaggedOutbound::new("direct", 0),
                TaggedOutbound::new("proxy", 1),
            ],
            &[],
            &[SelectorDefinition::new(
                "manual",
                vec!["direct", "proxy"],
                Some("direct"),
            )],
            TaggedRoute::Static(vec![TaggedStaticBinding::new("tun", "manual")]),
        )
        .expect("direct selector route");
        let routing = ClientRouting {
            legacy: route,
            program: None,
            outbounds: Arc::clone(&outbounds),
        };
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("direct TUN UDP target");
        let target = TargetAddr::ip(echo.local_addr().unwrap()).unwrap();
        let (terminal, bound) = select_udp_terminal(
            &routing,
            0,
            None,
            &target,
            b"tun-direct",
            1_392,
            &Metrics::new(),
        )
        .expect("direct TUN UDP selection");
        assert_eq!(bound, 1_392, "Direct does not subtract SIP022 overhead");
        let TunUdpTerminal::Route(direct) = terminal else {
            panic!("direct route terminal");
        };
        assert_eq!(direct.hops(), &[0]);
        direct_selector
            .switch("manual", "proxy")
            .expect("switch after direct snapshot");
        assert_eq!(direct.hops(), &[0], "Direct TUN mapping is immutable");
        let engine = ClientEgressEngine::new(
            outbounds,
            TokioConnector::new(TcpConnector::new(Duration::from_secs(1))),
            SystemClock::new(),
            SystemRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some(ClientUdpContext {
                manager: UdpSessionManager::new(UdpRuntimeLimits::default(), registry.clone()),
                live_ids: Arc::clone(&live_ids),
            }),
            None,
        );
        let mut association = engine
            .prepare_udp(
                super::super::egress::ClientRequestOrigin::Tun,
                Some(direct),
                Some(&target),
            )
            .await
            .expect("direct TUN UDP association");
        #[cfg(windows)]
        assert_eq!(engine.managed_binding_calls(), 1);
        association.activate(&engine).expect("direct activation");
        let length = association
            .prepare_application_request(
                &engine,
                &routing.outbounds,
                target.clone(),
                b"tun-direct",
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("direct TUN request"));
        association
            .send_encoded_request(length)
            .await
            .expect("direct TUN send");
        let mut raw = [0_u8; 32];
        let (length, peer) = echo.recv_from(&mut raw).await.expect("direct TUN receive");
        assert_eq!(&raw[..length], b"tun-direct");
        echo.send_to(b"tun-reply", peer).await.unwrap();
        let length = association.receive_response_wire().await.unwrap();
        let response = association
            .prepare_application_response(&engine, &routing.outbounds, length)
            .unwrap_or_else(|_| panic!("direct TUN response"));
        assert_eq!(response.datagram().target(), &target);
        assert_eq!(response.datagram().payload(), b"tun-reply");
        association.recycle_application_response(response);
        assert!(live_ids.lock().expect("live SIP022 IDs").is_empty());
    }

    #[test]
    fn tun_auto_dns_and_explicit_terminals_precede_ordinary_route_fallback() {
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
        let outbounds = prepare_client_outbounds(config.outbounds).expect("outbound contexts");
        let routing = ClientRouting {
            legacy: config.route,
            program: config.route_program,
            outbounds,
        };
        let metrics = ferrum2_observability::Metrics::new();
        for (address, expected) in [("192.0.2.53:53", "dns"), ("192.0.2.54:53", "reject")] {
            let target = TargetAddr::ip(address.parse().expect("target")).expect("target");
            let (terminal, bound) =
                select_udp_terminal(&routing, inbound, None, &target, b"query", 1_392, &metrics)
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

        let synthetic = Ipv4Addr::new(198, 18, 0, 1);
        for (target, configured, hijacked) in [
            ("198.18.0.1:53", Some(synthetic), true),
            ("198.18.0.1:54", Some(synthetic), false),
            ("198.18.0.2:53", Some(synthetic), false),
            ("198.18.0.1:53", None, false),
            ("[fd00::1]:53", Some(synthetic), false),
        ] {
            let target = TargetAddr::ip(target.parse().unwrap()).unwrap();
            let (terminal, _) = select_udp_terminal(
                &routing, inbound, configured, &target, b"query", 1_392, &metrics,
            )
            .expect("bounded synthetic candidate");
            assert_eq!(
                matches!(terminal, TunUdpTerminal::HijackDns),
                hijacked,
                "synthetic target {target:?}"
            );
        }
    }

    #[tokio::test]
    async fn managed_tun_lifecycle_cancelled_prepare_cleanup_failure_maps_to_shutdown_cleanup() {
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
    async fn tun_auto_dns_tcp_answer_failure_closes_flow_before_ordinary_route() {
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
        let test_server = match config.outbounds[0].server().unwrap() {
            SocketAddr::V4(server) => server,
            SocketAddr::V6(_) => panic!("IPv4 test server"),
        };
        let outbounds = prepare_client_outbounds(config.outbounds).expect("test outbounds");
        let routing = Arc::new(ClientRouting {
            legacy: config.route,
            program: config.route_program,
            outbounds: Arc::clone(&outbounds),
        });
        let (resolver, mut resolver_owner) = TaggedResolver::direct(
            vec![DnsUpstreamSpec {
                transport: DnsUpstreamTransport::Udp,
                target: TargetAddr::ip(dns_address).expect("numeric DNS target"),
                resolved_targets: Box::new([]),
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
                TokioConnector::new(TcpConnector::with_resolution_adapters(
                    ferrum2_runtime::SystemSocketInspector,
                    ferrum2_runtime::SystemTcpDialer,
                    crate::run::egress::system_application_resolver(),
                    runtime.connect_timeout,
                )),
                SystemClock::new(),
                SystemRandom,
                (runtime.connect_timeout, runtime.handshake_timeout),
                None,
                None,
            )),
            keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(default_test_psk())),
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
        run_tcp(
            target,
            flow,
            cancellation.clone(),
            Arc::clone(&context),
            routing,
            0,
            Some(Ipv4Addr::new(192, 0, 2, 53)),
        )
        .await;
        assert_eq!(peer.read(&mut [0; 1]).await.expect("terminal close"), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), fallback.accept())
                .await
                .is_err(),
            "DNS failure evaluated the final route or fallback egress"
        );
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());

        let direct_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("direct TUN TCP target");
        let direct_target = direct_listener.local_addr().expect("direct TUN target");
        let direct_registry = OwnerRegistry::new();
        let direct_outbounds =
            prepare_client_outbounds(vec![ferrum2_config::ClientOutboundConfig::Direct {
                domain_resolver: ferrum2_config::DirectDomainResolver::System,
            }])
            .expect("direct TUN outbound");
        let direct_routing = Arc::new(ClientRouting {
            legacy: ferrum2_rule::RouteTable::static_bindings(vec![0]).expect("direct TUN route"),
            program: None,
            outbounds: Arc::clone(&direct_outbounds),
        });
        let direct_context = Arc::new(ClientContext {
            inbound: Socks5Inbound::new(),
            egress: Arc::new(ClientEgressEngine::new(
                direct_outbounds,
                TokioConnector::new(TcpConnector::with_resolution_adapters(
                    ferrum2_runtime::SystemSocketInspector,
                    ferrum2_runtime::SystemTcpDialer,
                    crate::run::egress::system_application_resolver(),
                    context.runtime.connect_timeout,
                )),
                SystemClock::new(),
                SystemRandom,
                (
                    context.runtime.connect_timeout,
                    context.runtime.handshake_timeout,
                ),
                None,
                None,
            )),
            keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(default_test_psk())),
            runtime: context.runtime,
            udp_associate_enabled: false,
            registry: direct_registry.clone(),
            metrics: Arc::new(Metrics::new()),
            dns: None,
            test_udp_server: reserve_address(),
        });
        let target = tokio::spawn(async move {
            let (mut stream, _) = direct_listener.accept().await.expect("direct TUN accept");
            let mut request = Vec::new();
            stream
                .read_to_end(&mut request)
                .await
                .expect("direct TUN target read");
            stream
                .write_all(b"tun-reply")
                .await
                .expect("direct TUN target reply");
            stream
                .shutdown()
                .await
                .expect("direct TUN target half close");
            request
        });
        let (flow, mut peer) = tokio::io::duplex(64);
        let direct = tokio::spawn(run_tcp(
            direct_target,
            flow,
            cancellation.clone(),
            direct_context,
            direct_routing,
            0,
            None,
        ));
        peer.write_all(b"tun-direct")
            .await
            .expect("direct TUN write");
        peer.shutdown().await.expect("direct TUN half close");
        let mut response = Vec::new();
        peer.read_to_end(&mut response)
            .await
            .expect("direct TUN response");
        assert_eq!(response, b"tun-reply");
        assert_eq!(
            target.await.expect("direct TUN target owner"),
            b"tun-direct"
        );
        direct.await.expect("direct TUN relay owner");
        assert_eq!(active(direct_registry.snapshot()), OwnerSnapshot::default());

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
