use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum2_config::{DnsServerConfig, DnsTransport};
use ferrum2_core::TargetAddr;
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_dns::{
    BoxedDnsDatagramIo, BoxedDnsTcpIo, DnsDatagramIo, DnsEgress, DnsEgressResourceKind,
    DnsEgressTaskKind, DnsIoFuture, DnsTaskRegistrar, DnsUpstreamSpec, DnsUpstreamTransport,
    SystemDnsEgress,
};
use ferrum2_shadowsocks::MAX_UDP_WIRE_LEN;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::TokioFramed;
use super::egress::{ClientEgressEngine, ClientUdpAssociation};

type Packet = (Vec<u8>, SocketAddr);
type ReserveFuture = Pin<
    Box<dyn Future<Output = Result<mpsc::OwnedPermit<Packet>, mpsc::error::SendError<()>>> + Send>,
>;
type DnsUdpPool = Arc<Mutex<Vec<IdleDnsUdp>>>;

pub(super) fn dns_runtime_specs(servers: &[DnsServerConfig]) -> Vec<DnsUpstreamSpec> {
    servers
        .iter()
        .map(|server| {
            let transport = match server.transport {
                DnsTransport::Udp => DnsUpstreamTransport::Udp,
                DnsTransport::Tcp => DnsUpstreamTransport::Tcp,
                DnsTransport::Dot => DnsUpstreamTransport::Dot {
                    server_name: server
                        .server_name
                        .clone()
                        .expect("validated DoT server name"),
                },
                DnsTransport::Doh => DnsUpstreamTransport::Doh {
                    server_name: server
                        .server_name
                        .clone()
                        .expect("validated DoH server name"),
                    path: server.path.clone().expect("validated DoH path"),
                },
            };
            DnsUpstreamSpec {
                transport,
                address: server.address,
                detour: server.detour.clone(),
            }
        })
        .collect()
}

pub(super) struct ClientDnsEgress {
    engine: Arc<ClientEgressEngine>,
    udp_pool: DnsUdpPool,
}

impl ClientDnsEgress {
    pub(super) fn new(engine: Arc<ClientEgressEngine>) -> Self {
        Self {
            engine,
            udp_pool: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[derive(Eq, PartialEq)]
struct DnsUdpPoolKey {
    first_server: std::net::SocketAddrV4,
    plan: EgressPlanSnapshot,
}

struct IdleDnsUdp {
    key: DnsUdpPoolKey,
    association: ClientUdpAssociation,
}

struct PooledDnsUdp {
    idle: Option<IdleDnsUdp>,
    pool: DnsUdpPool,
    reusable: bool,
}

impl PooledDnsUdp {
    fn begin_request(&mut self) {
        self.reusable = false;
    }

    async fn relay_request(
        &mut self,
        engine: &ClientEgressEngine,
        plan: &EgressPlanSnapshot,
        first_server: SocketAddrV4,
        destination: SocketAddr,
        packet: Vec<u8>,
        responses: &mpsc::Sender<Packet>,
    ) -> io::Result<bool> {
        self.begin_request();
        let (response, fully_reusable) = self
            .idle
            .as_mut()
            .expect("pooled DNS UDP owner")
            .association
            .relay(engine, plan, first_server, destination, packet)
            .await?;
        responses
            .send(response)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "DNS UDP response closed"))?;
        self.reusable = fully_reusable;
        Ok(fully_reusable)
    }
}

impl Drop for PooledDnsUdp {
    fn drop(&mut self) {
        if !self.reusable {
            return;
        }
        let Some(idle) = self.idle.take() else {
            return;
        };
        if let Ok(mut pool) = self.pool.lock() {
            pool.push(idle);
        }
    }
}

fn take_dns_udp(
    pool: &DnsUdpPool,
    key: &DnsUdpPoolKey,
) -> io::Result<(Option<IdleDnsUdp>, Option<IdleDnsUdp>)> {
    let mut idle = pool.lock().map_err(|_| invalid_target())?;
    Ok(match idle.iter().position(|idle| idle.key == *key) {
        Some(index) => (Some(idle.swap_remove(index)), None),
        None => (None, idle.pop()),
    })
}

impl DnsEgress for ClientDnsEgress {
    fn connect_tcp(
        &self,
        target: SocketAddr,
        plan: Option<EgressPlanSnapshot>,
        timeout: Duration,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo> {
        let Some(plan) = plan else {
            return SystemDnsEgress.connect_tcp(target, None, timeout, tasks);
        };
        let engine = Arc::clone(&self.engine);
        Box::pin(async move {
            let target = TargetAddr::ip(target).map_err(|_| invalid_target())?;
            if plan.hops().iter().any(|hop| *hop >= engine.outbounds.len()) {
                return Err(invalid_target());
            }
            let queue = tasks.own(DnsEgressResourceKind::Queue);
            let buffer = tasks.own(DnsEgressResourceKind::Buffer);
            let (client, mut bridge_front) = tokio::io::duplex(2_048);
            let (mut bridge_back, mut session_io) = tokio::io::duplex(2_048);
            tasks.spawn(DnsEgressTaskKind::Bridge, async move {
                let (_queue, _buffer) = (queue, buffer);
                let _ = tokio::io::copy_bidirectional(&mut bridge_front, &mut bridge_back).await;
            });
            tasks.spawn(DnsEgressTaskKind::Session, async move {
                let Ok(flow) = engine
                    .open_tcp(
                        plan,
                        &target,
                        Some(timeout),
                        #[cfg(test)]
                        None,
                    )
                    .await
                else {
                    return;
                };
                let mut upstream = TokioFramed::new(flow);
                let _ = tokio::io::copy_bidirectional(&mut session_io, &mut upstream).await;
            });
            Ok(Box::new(client) as BoxedDnsTcpIo)
        })
    }

    fn bind_udp(
        &self,
        target: SocketAddr,
        plan: Option<EgressPlanSnapshot>,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo> {
        let Some(plan) = plan else {
            return SystemDnsEgress.bind_udp(target, None, tasks);
        };
        let engine = Arc::clone(&self.engine);
        let pool = Arc::clone(&self.udp_pool);
        Box::pin(async move {
            let target = TargetAddr::ip(target).map_err(|_| invalid_target())?;
            let first_server = plan
                .hops()
                .first()
                .and_then(|hop| engine.outbounds.get(*hop))
                .map(|outbound| outbound.udp_server)
                .ok_or_else(invalid_target)?;
            let key = DnsUdpPoolKey {
                first_server,
                plan: plan.clone(),
            };
            let (idle, stale) = take_dns_udp(&pool, &key)?;
            let reusable = idle.is_some();
            drop(stale);
            let idle = match idle {
                Some(idle) => idle,
                None => IdleDnsUdp {
                    key,
                    association: engine
                        .prepare_udp(
                            Ipv4Addr::LOCALHOST,
                            Some((plan.clone(), first_server)),
                            UdpSocket::bind,
                        )
                        .await
                        .map_err(|_| io::Error::other("DNS UDP egress unavailable"))?,
                },
            };
            let mut prepared = PooledDnsUdp {
                idle: Some(idle),
                pool,
                reusable,
            };

            let (outgoing, mut outbound) = mpsc::channel::<Packet>(1);
            let (inbound, incoming) = mpsc::channel::<Packet>(1);
            let (session_requests, mut requests) = mpsc::channel::<Packet>(1);
            let (session_responses, mut responses) = mpsc::channel::<Packet>(1);
            let outbound_queue = tasks.own(DnsEgressResourceKind::Queue);
            let inbound_queue = tasks.own(DnsEgressResourceKind::Queue);
            let request_queue = tasks.own(DnsEgressResourceKind::Queue);
            let response_queue = tasks.own(DnsEgressResourceKind::Queue);
            let buffer = tasks.own(DnsEgressResourceKind::Buffer);
            tasks.spawn(DnsEgressTaskKind::Bridge, async move {
                let (_outbound_queue, _inbound_queue, _request_queue, _response_queue, _buffer) = (
                    outbound_queue,
                    inbound_queue,
                    request_queue,
                    response_queue,
                    buffer,
                );
                while let Some((packet, destination)) = outbound.recv().await {
                    if destination != target.as_socket_addr().expect("numeric DNS target")
                        || session_requests.send((packet, destination)).await.is_err()
                    {
                        break;
                    }
                    let Some(response) = responses.recv().await else {
                        break;
                    };
                    if inbound.send(response).await.is_err() {
                        break;
                    }
                }
            });
            tasks.spawn(DnsEgressTaskKind::Session, async move {
                while let Some((packet, destination)) = requests.recv().await {
                    let reusable = prepared
                        .relay_request(
                            &engine,
                            &plan,
                            first_server,
                            destination,
                            packet,
                            &session_responses,
                        )
                        .await;
                    let Ok(fully_reusable) = reusable else {
                        break;
                    };
                    if !fully_reusable {
                        break;
                    }
                }
            });
            Ok(Box::new(ClientDnsDatagram {
                outgoing,
                reserve: Mutex::new(None),
                incoming: Mutex::new(incoming),
            }) as BoxedDnsDatagramIo)
        })
    }
}

struct ClientDnsDatagram {
    outgoing: mpsc::Sender<Packet>,
    reserve: Mutex<Option<ReserveFuture>>,
    incoming: Mutex<mpsc::Receiver<Packet>>,
}

impl DnsDatagramIo for ClientDnsDatagram {
    fn poll_recv_from(
        &self,
        context: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let Ok(mut incoming) = self.incoming.lock() else {
            return Poll::Ready(Err(io::Error::other("DNS UDP receive lock")));
        };
        match incoming.poll_recv(context) {
            Poll::Ready(Some((packet, source))) if packet.len() <= buffer.len() => {
                buffer[..packet.len()].copy_from_slice(&packet);
                Poll::Ready(Ok((packet.len(), source)))
            }
            Poll::Ready(Some(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS UDP receive too large",
            ))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_send_to(
        &self,
        context: &mut Context<'_>,
        buffer: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        if buffer.len() > MAX_UDP_WIRE_LEN {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS UDP send too large",
            )));
        }
        let Ok(mut reserve) = self.reserve.lock() else {
            return Poll::Ready(Err(io::Error::other("DNS UDP send lock")));
        };
        if reserve.is_none() {
            *reserve = Some(Box::pin(self.outgoing.clone().reserve_owned()));
        }
        match reserve
            .as_mut()
            .expect("reserve future")
            .as_mut()
            .poll(context)
        {
            Poll::Ready(Ok(permit)) => {
                reserve.take();
                permit.send((buffer.to_vec(), target));
                Poll::Ready(Ok(buffer.len()))
            }
            Poll::Ready(Err(_)) => {
                reserve.take();
                Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

fn invalid_target() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS egress target")
}

#[cfg(test)]
mod tests {
    use super::*;

    use ferrum2_core::route::{EgressPlanHandle, Network, compile_selector_plans};
    use ferrum2_core::selector::{
        SelectorDefinition, TaggedInbound, TaggedOutbound, TaggedPlan, TaggedRoute,
        TaggedStaticBinding,
    };
    use ferrum2_crypto::{MethodSinglePskProvider, SystemClock, SystemRandom};
    use ferrum2_shadowsocks::{MethodKeyAdapter, UdpPacketScratch, UdpServer};

    use crate::run::egress::{UdpIoFaultPlan, UdpIoOperation};
    use crate::run::tests::{
        default_test_psk, relay_dns_udp_hop_once, udp_test_context_for_server,
    };

    #[test]
    fn dns_runtime_specs_preserve_validated_server_values() {
        let cases = [
            (DnsTransport::Udp, 5300, None, None, false),
            (DnsTransport::Udp, 5301, None, None, true),
            (DnsTransport::Tcp, 5302, None, None, false),
            (DnsTransport::Tcp, 5303, None, None, true),
            (
                DnsTransport::Dot,
                8530,
                Some("dot-direct.test"),
                None,
                false,
            ),
            (DnsTransport::Dot, 8531, Some("dot-detour.test"), None, true),
            (
                DnsTransport::Doh,
                4430,
                Some("doh-direct.test"),
                Some("/dns-query/direct"),
                false,
            ),
            (
                DnsTransport::Doh,
                4431,
                Some("doh-detour.test"),
                Some("/dns-query/detour"),
                true,
            ),
        ];
        let servers: Vec<_> = cases
            .iter()
            .enumerate()
            .map(
                |(index, &(transport, port, server_name, path, detoured))| DnsServerConfig {
                    transport,
                    address: SocketAddr::from(([192, 0, 2, 53], port)),
                    server_name: server_name.map(Into::into),
                    path: path.map(Into::into),
                    detour: detoured.then(|| EgressPlanHandle::direct(index)),
                },
            )
            .collect();
        let configured_plan_ptrs: Vec<_> = servers
            .iter()
            .map(|server| {
                server
                    .detour
                    .as_ref()
                    .map(|detour| detour.snapshot_owned().hops().as_ptr())
            })
            .collect();

        for (
            index,
            ((spec, (transport, port, server_name, path, detoured)), configured_plan_ptr),
        ) in dns_runtime_specs(&servers)
            .into_iter()
            .zip(cases)
            .zip(configured_plan_ptrs)
            .enumerate()
        {
            assert_eq!(spec.address, SocketAddr::from(([192, 0, 2, 53], port)));
            match (detoured, spec.detour.as_ref()) {
                (true, Some(detour)) => {
                    let converted = detour.snapshot_owned();
                    assert_eq!(converted.hops(), &[index]);
                    assert_eq!(Some(converted.hops().as_ptr()), configured_plan_ptr);
                }
                (false, None) => {}
                _ => panic!("DNS runtime detour mapping drift"),
            }
            match (transport, spec.transport) {
                (DnsTransport::Udp, DnsUpstreamTransport::Udp)
                | (DnsTransport::Tcp, DnsUpstreamTransport::Tcp) => {
                    assert_eq!((server_name, path), (None, None));
                }
                (
                    DnsTransport::Dot,
                    DnsUpstreamTransport::Dot {
                        server_name: actual,
                    },
                ) => {
                    assert_eq!(actual.as_ref(), server_name.expect("DoT name"));
                    assert!(path.is_none());
                }
                (
                    DnsTransport::Doh,
                    DnsUpstreamTransport::Doh {
                        server_name: actual_name,
                        path: actual_path,
                    },
                ) => {
                    assert_eq!(actual_name.as_ref(), server_name.expect("DoH name"));
                    assert_eq!(actual_path.as_ref(), path.expect("DoH path"));
                }
                _ => panic!("DNS runtime transport mapping drift"),
            }
        }

        let source = include_str!("dns_egress.rs");
        assert!(source.contains(&["engine: Arc<", "ClientEgressEngine", ">"].concat()));
        let dns_connect_tcp = source
            .split_once("fn connect_tcp(")
            .expect("DNS TCP adapter")
            .1
            .split_once("fn bind_udp(")
            .expect("DNS UDP adapter")
            .0;
        assert!(dns_connect_tcp.contains(&[".", "open_tcp("].concat()));
        let dns_udp = source
            .split_once("fn bind_udp(")
            .expect("DNS UDP adapter")
            .1
            .split_once("struct ClientDnsDatagram")
            .expect("DNS UDP adapter end")
            .0;
        assert!(dns_udp.contains(&[".", "prepare_udp("].concat()));
        assert!(dns_udp.contains(&[".", "relay_request("].concat()));
        for forbidden in [
            ["Prepared", "ClientUdp"].concat(),
            ["activate", "_udp_plan"].concat(),
            ["reserve", "_application_datagram"].concat(),
            ["encode", "_udp_plan_request"].concat(),
            ["accept", "_udp_plan_response"].concat(),
        ] {
            assert!(!source.contains(&forbidden), "DNS UDP bypass: {forbidden}");
        }
        for forbidden in [
            ["Client", "Context"].concat(),
            ["Client", "Routing"].concat(),
            ["open_chain", "_with_deadlines"].concat(),
        ] {
            assert!(!source.contains(&forbidden), "DNS TCP bypass: {forbidden}");
        }

        let engine = [
            include_str!("run/egress/mod.rs"),
            include_str!("run/egress/tcp.rs"),
            include_str!("run/egress/udp.rs"),
        ]
        .concat();
        for forbidden in [
            ["Route", "Table"].concat(),
            ["Selector", "Control"].concat(),
            ["Socks5", "Inbound"].concat(),
        ] {
            assert!(
                !engine.contains(&forbidden),
                "TCP engine owns policy/ingress: {forbidden}"
            );
        }

        let run_source = include_str!("run.rs");
        let socks_connect = run_source
            .split_once("async fn client_connection(")
            .expect("SOCKS production session")
            .1
            .split_once("async fn run_udp_association")
            .expect("SOCKS production session end")
            .0;
        assert!(socks_connect.contains(&[".", "open_tcp("].concat()));
        let outside_engine = [run_source, source].concat();
        let forbidden_executor = ["Client", "TcpOutbound"].concat();
        assert!(
            !outside_engine.contains(&forbidden_executor),
            "TCP executor outside engine: {forbidden_executor}"
        );
    }

    #[tokio::test]
    async fn dns_udp_pool_reuses_only_exact_success_and_discards_failed_or_partial_state() {
        let (route, selector) = compile_selector_plans(
            &[TaggedInbound::new("entry", 0)],
            &[
                TaggedOutbound::new("a", 0),
                TaggedOutbound::new("b", 1),
                TaggedOutbound::new("c", 2),
            ],
            &[
                TaggedPlan::new("a-b", vec![0, 1]),
                TaggedPlan::new("b-a", vec![1, 0]),
            ],
            &[SelectorDefinition::new(
                "manual",
                vec!["a-b", "b-a", "c"],
                Some("a-b"),
            )],
            TaggedRoute::Static(vec![TaggedStaticBinding::new("entry", "manual")]),
        )
        .expect("DNS UDP pool plans");
        let target = TargetAddr::domain("pool.test", 53).expect("pool target");
        let selected = route.select_plan_snapshot(0, Network::Udp, &target);
        selector.switch("manual", "b-a").expect("reverse plan");
        let reversed = route.select_plan_snapshot(0, Network::Udp, &target);
        selector.switch("manual", "c").expect("later plan");
        let later = route.select_plan_snapshot(0, Network::Udp, &target);
        let first_server = std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53_001);
        let key_cases = [
            (
                "same server/equal snapshot",
                DnsUdpPoolKey {
                    first_server,
                    plan: selected.clone(),
                },
                true,
            ),
            (
                "different first server",
                DnsUdpPoolKey {
                    first_server: std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53_002),
                    plan: selected.clone(),
                },
                false,
            ),
            (
                "different hop order",
                DnsUdpPoolKey {
                    first_server,
                    plan: reversed,
                },
                false,
            ),
            (
                "selector switched plan",
                DnsUdpPoolKey {
                    first_server,
                    plan: later,
                },
                false,
            ),
        ];

        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("association mutation server");
        let first_server = match server.local_addr().expect("mutation server address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 mutation server"),
        };
        let registry = ferrum2_runtime::OwnerRegistry::new();
        let baseline = registry.snapshot();
        let (path, context) = udp_test_context_for_server(registry.clone(), first_server);
        let plan = EgressPlanHandle::direct(0).snapshot_owned();
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("mutation DNS upstream");
        let destination = upstream.local_addr().expect("mutation upstream address");
        let keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(default_test_psk()));
        let protocol_server = UdpServer::new(&keys).expect("mutation protocol server");
        let clock = SystemClock::new();
        let random = SystemRandom;
        let mut scratch = UdpPacketScratch::new();
        for (case, candidate, reusable) in key_cases {
            let association = context
                .egress
                .prepare_udp(
                    Ipv4Addr::LOCALHOST,
                    Some((selected.clone(), first_server)),
                    UdpSocket::bind,
                )
                .await
                .expect("key association");
            let pool = Arc::new(Mutex::new(vec![IdleDnsUdp {
                key: DnsUdpPoolKey {
                    first_server: std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53_001),
                    plan: selected.clone(),
                },
                association,
            }]));
            let (matched, stale) = take_dns_udp(&pool, &candidate).expect("key lookup");
            assert_eq!(matched.is_some(), reusable, "{case}");
            assert_eq!(stale.is_some(), !reusable, "{case}");
            drop((matched, stale));
            assert_eq!(registry.snapshot(), baseline, "{case}");
        }
        for case in [
            "partial",
            "send-io",
            "receive-io",
            "authentication",
            "cancel",
            "saturation",
        ] {
            let sessions_before_failure = protocol_server
                .session_count()
                .expect("mutation session baseline");
            let association = context
                .egress
                .prepare_udp(
                    Ipv4Addr::LOCALHOST,
                    Some((plan.clone(), first_server)),
                    UdpSocket::bind,
                )
                .await
                .expect("mutation association");
            let pool = Arc::new(Mutex::new(Vec::new()));
            let (session_responses, mut responses) = mpsc::channel(1);
            let mut pooled = PooledDnsUdp {
                idle: Some(IdleDnsUdp {
                    key: DnsUdpPoolKey {
                        first_server,
                        plan: plan.clone(),
                    },
                    association,
                }),
                pool: Arc::clone(&pool),
                reusable: false,
            };
            let mutation_handle = pooled
                .idle
                .as_ref()
                .expect("healthy mutation owner")
                .association
                .handle;
            let payload = vec![0x10];
            let echo = async {
                let mut wire = [0_u8; MAX_UDP_WIRE_LEN];
                let (length, peer) = upstream
                    .recv_from(&mut wire)
                    .await
                    .expect("healthy mutation upstream query");
                upstream
                    .send_to(&wire[..length], peer)
                    .await
                    .expect("healthy mutation upstream response");
            };
            let (reusable, (), ()) = tokio::join!(
                pooled.relay_request(
                    &context.egress,
                    &plan,
                    first_server,
                    destination,
                    payload.clone(),
                    &session_responses,
                ),
                relay_dns_udp_hop_once(
                    &server,
                    &protocol_server,
                    destination,
                    &clock,
                    &random,
                    &mut scratch,
                    false,
                ),
                echo,
            );
            let fully_reusable = reusable.expect("healthy mutation relay");
            let (response, source) = responses.try_recv().expect("healthy mutation response");
            assert_eq!((response, source), (payload, destination), "{case}");
            assert!(fully_reusable, "{case} healthy mutation tainted");
            drop(pooled);
            assert_eq!(pool.lock().expect("healthy mutation pool").len(), 1);
            assert_eq!(
                protocol_server
                    .session_count()
                    .expect("healthy mutation session"),
                sessions_before_failure + 1,
                "{case} healthy mutation session"
            );
            let key = DnsUdpPoolKey {
                first_server,
                plan: plan.clone(),
            };
            let (matched, stale) = take_dns_udp(&pool, &key).expect("mutation exact reuse");
            assert!(stale.is_none(), "{case} healthy exact key was discarded");
            let idle = matched.expect("mutation exact-key association");
            assert_eq!(idle.association.handle, mutation_handle, "{case}");
            let mut pooled = PooledDnsUdp {
                idle: Some(idle),
                pool: Arc::clone(&pool),
                reusable: true,
            };
            match case {
                "partial" => pooled.begin_request(),
                "send-io" | "receive-io" => {
                    let operation = if case == "send-io" {
                        UdpIoOperation::UpstreamSend
                    } else {
                        UdpIoOperation::UpstreamRecv
                    };
                    pooled
                        .idle
                        .as_mut()
                        .expect("mutation owner")
                        .association
                        .io_fault = Some(Arc::new(UdpIoFaultPlan::new(operation, 1)));
                    assert!(
                        pooled
                            .relay_request(
                                &context.egress,
                                &plan,
                                first_server,
                                destination,
                                vec![0x21],
                                &session_responses,
                            )
                            .await
                            .is_err(),
                        "{case}"
                    );
                    if case == "receive-io" {
                        let mut wire = [0_u8; MAX_UDP_WIRE_LEN];
                        tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut wire))
                            .await
                            .expect("receive-io request timeout")
                            .expect("receive-io request");
                    }
                }
                "authentication" => {
                    let echo = async {
                        let mut wire = [0_u8; MAX_UDP_WIRE_LEN];
                        let (length, peer) = upstream
                            .recv_from(&mut wire)
                            .await
                            .expect("authentication upstream query");
                        upstream
                            .send_to(&wire[..length], peer)
                            .await
                            .expect("authentication upstream response");
                    };
                    let payload = vec![0x22];
                    let (result, (), ()) = tokio::join!(
                        pooled.relay_request(
                            &context.egress,
                            &plan,
                            first_server,
                            destination,
                            payload.clone(),
                            &session_responses,
                        ),
                        relay_dns_udp_hop_once(
                            &server,
                            &protocol_server,
                            destination,
                            &clock,
                            &random,
                            &mut scratch,
                            true,
                        ),
                        echo,
                    );
                    let fully_reusable =
                        result.expect("valid response after authentication discard");
                    let (response, source) = responses
                        .try_recv()
                        .expect("valid response after authentication discard");
                    assert_eq!((response, source), (payload, destination));
                    assert!(
                        !fully_reusable,
                        "authentication discard left association reusable"
                    );
                }
                "cancel" => {
                    assert!(
                        tokio::time::timeout(
                            Duration::from_millis(20),
                            pooled.relay_request(
                                &context.egress,
                                &plan,
                                first_server,
                                destination,
                                vec![0x23],
                                &session_responses,
                            ),
                        )
                        .await
                        .is_err(),
                        "cancel"
                    );
                    let mut wire = [0_u8; MAX_UDP_WIRE_LEN];
                    tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut wire))
                        .await
                        .expect("cancel request timeout")
                        .expect("cancel request");
                }
                "saturation" => {
                    pooled.begin_request();
                    assert!(
                        context
                            .egress
                            .prepare_udp(
                                Ipv4Addr::LOCALHOST,
                                Some((plan.clone(), first_server)),
                                UdpSocket::bind,
                            )
                            .await
                            .is_err(),
                        "saturation admitted a second association"
                    );
                }
                _ => unreachable!("closed mutation table"),
            }
            assert!(
                !pooled.reusable,
                "{case} request start retained reusable state"
            );
            drop(pooled);
            assert!(pool.lock().expect("mutation pool").is_empty(), "{case}");

            let sessions_before = protocol_server
                .session_count()
                .expect("healthy session baseline");
            let association = context
                .egress
                .prepare_udp(
                    Ipv4Addr::LOCALHOST,
                    Some((plan.clone(), first_server)),
                    UdpSocket::bind,
                )
                .await
                .expect("following valid association");
            let mut initial = Some(IdleDnsUdp {
                key: DnsUdpPoolKey {
                    first_server,
                    plan: plan.clone(),
                },
                association,
            });
            for valid in 0..2_u8 {
                let (idle, reusable) = match initial.take() {
                    Some(idle) => (idle, false),
                    None => {
                        let key = DnsUdpPoolKey {
                            first_server,
                            plan: plan.clone(),
                        };
                        let (matched, stale) = take_dns_udp(&pool, &key).expect("healthy reuse");
                        assert!(stale.is_none(), "healthy exact key was discarded");
                        (matched.expect("healthy exact-key association"), true)
                    }
                };
                let mut healthy = PooledDnsUdp {
                    idle: Some(idle),
                    pool: Arc::clone(&pool),
                    reusable,
                };
                let payload = vec![0x30 + valid];
                let echo = async {
                    let mut wire = [0_u8; MAX_UDP_WIRE_LEN];
                    let (length, peer) = upstream
                        .recv_from(&mut wire)
                        .await
                        .expect("following valid upstream query");
                    upstream
                        .send_to(&wire[..length], peer)
                        .await
                        .expect("following valid upstream response");
                };
                let (reusable, (), ()) = tokio::join!(
                    healthy.relay_request(
                        &context.egress,
                        &plan,
                        first_server,
                        destination,
                        payload.clone(),
                        &session_responses,
                    ),
                    relay_dns_udp_hop_once(
                        &server,
                        &protocol_server,
                        destination,
                        &clock,
                        &random,
                        &mut scratch,
                        false,
                    ),
                    echo,
                );
                let fully_reusable = reusable.expect("following valid relay");
                let (response, source) = responses.try_recv().expect("following valid response");
                assert_eq!((response, source), (payload, destination), "{case}");
                assert!(fully_reusable, "{case} healthy association tainted");
                drop(healthy);
                assert_eq!(pool.lock().expect("healthy pool").len(), 1, "{case}");
            }
            assert_eq!(
                protocol_server
                    .session_count()
                    .expect("healthy session count"),
                sessions_before + 1,
                "{case} exact-key reuse created another SIP022 session"
            );
            drop(pool.lock().expect("healthy pool").pop());
            assert_eq!(registry.snapshot(), baseline, "{case}");
        }
        drop((context, protocol_server, keys));
        assert_eq!(registry.snapshot(), baseline);
        drop(server);
        drop(upstream);
        drop(
            UdpSocket::bind(first_server)
                .await
                .expect("mutation server rebind"),
        );
        drop(
            UdpSocket::bind(destination)
                .await
                .expect("mutation upstream rebind"),
        );
        std::fs::remove_file(path).expect("remove mutation config");
    }
}
