use std::future::Future;
use std::io;
#[cfg(test)]
use std::net::Ipv4Addr;
use std::net::SocketAddr;
#[cfg(test)]
use std::net::SocketAddrV4;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum2_config::{DnsQueryType, DnsServerConfig, DnsTransport};
use ferrum2_core::TargetAddr;
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_dns::{
    ApplicationResolveBackend, ApplicationResolveFuture, ApplicationResolveRequest,
    BoxedDnsDatagramIo, BoxedDnsTcpIo, DnsDatagramIo, DnsEgress, DnsEgressResourceKind,
    DnsEgressTaskKind, DnsError, DnsIoFuture, DnsProxy, DnsTaskRegistrar, DnsUpstreamSpec,
    DnsUpstreamTransport,
};
use ferrum2_shadowsocks::MAX_UDP_WIRE_LEN;
#[cfg(test)]
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::egress::{ClientEgressEngine, ClientRequestOrigin, ClientUdpAssociation};
use super::tokio_io::TokioFramed;

type Packet = (Vec<u8>, SocketAddr);
type ReserveFuture = Pin<
    Box<dyn Future<Output = Result<mpsc::OwnedPermit<Packet>, mpsc::error::SendError<()>>> + Send>,
>;
type DnsUdpPool = Arc<Mutex<Vec<IdleDnsUdp>>>;

/// Configured application resolver backend bound to the one prepared client
/// DNS proxy graph. Absence or shutdown is terminal and never reaches system
/// DNS.
pub(super) struct ClientConfiguredApplicationBackend {
    proxy: Arc<OnceLock<Arc<DnsProxy>>>,
}

impl ClientConfiguredApplicationBackend {
    pub(super) fn new(proxy: Arc<OnceLock<Arc<DnsProxy>>>) -> Self {
        Self { proxy }
    }
}

impl ApplicationResolveBackend for ClientConfiguredApplicationBackend {
    fn resolve<'a>(
        &'a self,
        request: ApplicationResolveRequest<'a>,
    ) -> ApplicationResolveFuture<'a> {
        Box::pin(async move {
            let proxy = self.proxy.get().ok_or(DnsError::Runtime)?;
            proxy.resolve_application(request).await
        })
    }
}

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

pub(super) fn dns_query_type(code: u16) -> Option<DnsQueryType> {
    [
        DnsQueryType::A,
        DnsQueryType::Aaaa,
        DnsQueryType::Cname,
        DnsQueryType::Mx,
        DnsQueryType::Ns,
        DnsQueryType::Ptr,
        DnsQueryType::Soa,
        DnsQueryType::Srv,
        DnsQueryType::Txt,
        DnsQueryType::Caa,
        DnsQueryType::Svcb,
        DnsQueryType::Https,
        DnsQueryType::Any,
    ]
    .into_iter()
    .find(|qtype| *qtype as u16 == code)
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
    plan: Option<EgressPlanSnapshot>,
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
        plan: Option<&EgressPlanSnapshot>,
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
            .relay(engine, plan, destination, packet)
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
        let engine = Arc::clone(&self.engine);
        Box::pin(async move {
            let target = TargetAddr::ip(target).map_err(|_| invalid_target())?;
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
                        ClientRequestOrigin::Dns,
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
        let engine = Arc::clone(&self.engine);
        let pool = Arc::clone(&self.udp_pool);
        Box::pin(async move {
            let target = TargetAddr::ip(target).map_err(|_| invalid_target())?;
            let key = DnsUdpPoolKey { plan: plan.clone() };
            let (idle, stale) = take_dns_udp(&pool, &key)?;
            let reusable = idle.is_some();
            drop(stale);
            let idle = match idle {
                Some(idle) => idle,
                None => IdleDnsUdp {
                    key,
                    association: engine
                        .prepare_udp(ClientRequestOrigin::Dns, plan.clone(), Some(&target))
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
                            plan.as_ref(),
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

    use tokio::io::AsyncReadExt as _;

    use ferrum2_config::{
        ClientV2Resources, CompiledRuleSetResource, finish_client_v2, prepare_client_v2,
    };
    use ferrum2_core::CanonicalDomain;
    use ferrum2_core::route::{EgressPlanHandle, Network};
    use ferrum2_crypto::{MethodSinglePskProvider, SystemClock, SystemRandom};
    use ferrum2_dns::{ResolverGeneration, TaggedResolver};
    use ferrum2_rule::{
        MatchSetBuilder, SelectorDefinition, TaggedInbound, TaggedOutbound, TaggedPlan,
        TaggedRoute, TaggedStaticBinding, compile_selector_plans,
    };
    use ferrum2_shadowsocks::{MethodKeyAdapter, UdpPacketScratch, UdpServer};

    use crate::run::egress::{UdpIoFaultPlan, UdpIoOperation};
    use crate::run::test_support::*;
    use crate::run::{
        ClientRunResources, dns_egress, run_with_registry_and_metrics,
        run_with_registry_and_metrics_inner,
    };

    #[test]
    fn proxy_qtype_codes_map_to_the_closed_config_vocabulary() {
        for qtype in [
            ferrum2_config::DnsQueryType::A,
            ferrum2_config::DnsQueryType::Aaaa,
            ferrum2_config::DnsQueryType::Cname,
            ferrum2_config::DnsQueryType::Mx,
            ferrum2_config::DnsQueryType::Ns,
            ferrum2_config::DnsQueryType::Ptr,
            ferrum2_config::DnsQueryType::Soa,
            ferrum2_config::DnsQueryType::Srv,
            ferrum2_config::DnsQueryType::Txt,
            ferrum2_config::DnsQueryType::Caa,
            ferrum2_config::DnsQueryType::Svcb,
            ferrum2_config::DnsQueryType::Https,
            ferrum2_config::DnsQueryType::Any,
        ] {
            assert_eq!(dns_query_type(qtype as u16), Some(qtype));
        }
        assert_eq!(dns_query_type(0), None);
    }

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
    }

    async fn answer_policy_a(socket: &UdpSocket, expected: &str, address: Ipv4Addr) {
        let mut wire = [0_u8; 4096];
        let (length, peer) = socket.recv_from(&mut wire).await.expect("DNS query");
        let request = Message::from_vec(&wire[..length]).expect("DNS query decode");
        let [query] = request.queries.as_slice() else {
            panic!("one DNS question");
        };
        assert_eq!(query.name().to_ascii(), expected);
        assert_eq!(query.query_type(), RecordType::A);
        let mut response = Message::response(request.id, OpCode::Query);
        response.metadata.recursion_available = true;
        response.add_query(query.clone());
        response.add_answer(Record::from_rdata(
            query.name().clone(),
            60,
            RData::A(A(address)),
        ));
        socket
            .send_to(&response.to_vec().expect("DNS response encode"), peer)
            .await
            .expect("DNS response send");
    }

    async fn assert_no_policy_udp(socket: &UdpSocket, message: &str) {
        let mut wire = [0_u8; 4096];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), socket.recv_from(&mut wire))
                .await
                .is_err(),
            "{message}"
        );
    }

    #[tokio::test]
    async fn materialized_client_policy_is_shared_by_wire_application_and_cache() {
        let socks = reserve_address();
        let dns_listen = reserve_address();
        let local = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("local DNS upstream");
        let fallback = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("fallback DNS upstream");
        let mut source = format!(
            r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{socks}"

[[outbounds]]
tag = "direct"
type = "direct"

[route]
final = "direct"

[[route.rule_set]]
tag = "ads"
type = "remote"
url = "https://rules.example.invalid/ads.srs"
download_resolver = "system"

[[route.rule_set]]
tag = "cnip"
type = "remote"
url = "https://rules.example.invalid/cnip.srs"
download_resolver = "system"

[dns]
timeout_ms = 200
max_inflight = 8
strategy = "ipv4_only"

[dns.cache]
enabled = true
max_entries = 16

[[dns.inbounds]]
tag = "dns-in"
listen = "{dns_listen}"

[[dns.servers]]
tag = "local"
transport = "udp"
address = "{}"

[[dns.servers]]
tag = "fallback"
transport = "udp"
address = "{}"

[dns.route]
final = "fallback"

[[dns.route.rules]]
inbound = "dns-in"
rule_set = "ads"
action = "reject"

[[dns.route.rules]]
inbound = "proxy"
network = ["tcp", "udp"]
rule_set = "cnip"
action = "route"
server = "local"
strategy = "ipv4_only"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#,
            local.local_addr().unwrap(),
            fallback.local_addr().unwrap(),
        );
        for index in 0..63 {
            source.push_str(&format!(
                "\n[[dns.route.rules]]\nqname = [\"unused-{index}.indexed.invalid\"]\naction = \"reject\"\n"
            ));
        }
        let path = std::env::temp_dir().join(format!(
            "ferrum2-client-policy-composition-{}-{}.toml",
            std::process::id(),
            socks.port()
        ));
        std::fs::write(&path, source).expect("write V2 client config");
        let prepared = prepare_client_v2(&path).expect("prepare V2 client config");
        let mut ads = MatchSetBuilder::new();
        ads.add_exact_domain("ads.example").unwrap();
        let mut cnip = MatchSetBuilder::new();
        cnip.add_ip("203.0.113.7".parse().unwrap()).unwrap();
        let mut config = finish_client_v2(
            prepared,
            ClientV2Resources::new(
                Vec::new(),
                Vec::new(),
                vec![
                    CompiledRuleSetResource::new(0, Arc::new(ads.build().unwrap()), 23),
                    CompiledRuleSetResource::new(1, Arc::new(cnip.build().unwrap()), 23),
                ],
            ),
        )
        .expect("finish V2 client config");
        let _ = std::fs::remove_file(path);
        let metrics = Arc::new(Metrics::new());
        crate::run::publish_rule_program_metadata(&config, &metrics);
        let dns = config.dns.take().expect("materialized DNS graph");
        let runtime = crate::run::ClientDnsProxyRuntime::try_new(
            config.dns_route.as_mut(),
            dns.runtime,
            None,
            &metrics,
        )
        .expect("client proxy runtime");
        assert_eq!(runtime.generation, ResolverGeneration::new(23));
        assert_eq!(runtime.policy.as_ref().unwrap().listener_count, 1);
        assert_eq!(runtime.policy.as_ref().unwrap().ordinary_count, 1);
        assert_eq!(runtime.cache.as_ref().unwrap().capacity().unwrap(), 16);
        let (resolver, mut owner) = TaggedResolver::new(
            dns_runtime_specs(&dns.servers),
            dns.timeout,
            dns.max_inflight,
            Arc::new(ferrum2_dns::SystemDnsEgress),
        )
        .expect("tagged DNS resolver");
        owner.ready().await.expect("tagged DNS ready");
        let proxy = Arc::new(runtime.bind(DnsProxy::new(Arc::new(resolver), |_, _, _, _| Some(1))));

        let name: Name = "ads.example.".parse().unwrap();
        let mut request = Message::new(91, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(name, RecordType::A));
        let response = proxy
            .answer(
                ferrum2_dns::ProxyIngress::Listener(0),
                ferrum2_dns::ProxyTransport::Udp,
                &request.to_vec().unwrap(),
            )
            .await
            .expect("wire reject response");
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(response.metadata.id, 91);
        assert_eq!(response.metadata.response_code, ResponseCode::Refused);
        assert_no_policy_udp(&local, "wire reject reached local upstream").await;
        assert_no_policy_udp(&fallback, "wire reject reached fallback upstream").await;

        let domain = CanonicalDomain::new("hit.example").unwrap();
        let tcp_request = ferrum2_dns::ApplicationResolveRequest::new(
            ferrum2_dns::ApplicationResolveContext::new(0, Network::Tcp),
            &domain,
            std::num::NonZeroU16::new(443).unwrap(),
            crate::run::dns_strategy(dns.runtime.strategy()),
        );
        let hit = proxy.resolve_application(tcp_request);
        let response = answer_policy_a(&local, "hit.example.", Ipv4Addr::new(203, 0, 113, 7));
        let (hit, ()) = tokio::join!(hit, response);
        assert_eq!(
            hit.unwrap(),
            [SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 443))]
        );
        let udp_request = ferrum2_dns::ApplicationResolveRequest::new(
            ferrum2_dns::ApplicationResolveContext::new(0, Network::Udp),
            &domain,
            std::num::NonZeroU16::new(443).unwrap(),
            crate::run::dns_strategy(dns.runtime.strategy()),
        );
        assert_eq!(
            proxy.resolve_application(udp_request).await.unwrap(),
            [SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 443))]
        );
        assert_no_policy_udp(&local, "TCP/UDP shared cache missed").await;

        let miss_domain = CanonicalDomain::new("miss.example").unwrap();
        let miss_request = ferrum2_dns::ApplicationResolveRequest::new(
            ferrum2_dns::ApplicationResolveContext::new(0, Network::Tcp),
            &miss_domain,
            std::num::NonZeroU16::new(443).unwrap(),
            crate::run::dns_strategy(dns.runtime.strategy()),
        );
        let miss = proxy.resolve_application(miss_request);
        let responses = async {
            answer_policy_a(&local, "miss.example.", Ipv4Addr::new(198, 51, 100, 9)).await;
            answer_policy_a(&fallback, "miss.example.", Ipv4Addr::new(192, 0, 2, 9)).await;
        };
        let (miss, ()) = tokio::join!(miss, responses);
        assert_eq!(
            miss.unwrap(),
            [SocketAddr::from((Ipv4Addr::new(192, 0, 2, 9), 443))]
        );
        let encoded = metrics.encode_text().expect("DNS policy metrics");
        for expected in [
            "ferrum2_rule_program_mode{program=\"dns_query\",mode=\"indexed\"} 1",
            "ferrum2_rule_program_mode{program=\"dns_response\",mode=\"indexed\"} 1",
            "ferrum2_rule_program_rules{program=\"dns_query\"} 65",
            "ferrum2_rule_program_rules{program=\"dns_response\"} 1",
            "ferrum2_dns_rule_query_match_total{source=\"rule_set\",type=\"domain\",result=\"matched\"} 1",
            "ferrum2_dns_rule_response_match_total{source=\"rule_set\",type=\"ip_cidr\",result=\"matched\"} 2",
            "ferrum2_dns_rule_response_match_total{source=\"rule_set\",type=\"ip_cidr\",result=\"missed\"} 1",
            "ferrum2_dns_implicit_system_fallback_total 0",
        ] {
            assert!(
                encoded.contains(expected),
                "missing `{expected}`\n{encoded}"
            );
        }
        for identity in [
            "ferrum2_rule_program_candidate_count_sum{program=\"dns_query\"}",
            "ferrum2_rule_program_candidate_count_count{program=\"dns_query\"}",
            "ferrum2_rule_program_match_ns_sum{program=\"dns_query\"}",
            "ferrum2_rule_program_match_ns_count{program=\"dns_query\"}",
            "ferrum2_rule_program_candidate_count_sum{program=\"dns_response\"}",
            "ferrum2_rule_program_candidate_count_count{program=\"dns_response\"}",
            "ferrum2_rule_program_match_ns_sum{program=\"dns_response\"}",
            "ferrum2_rule_program_match_ns_count{program=\"dns_response\"}",
        ] {
            assert!(
                encoded
                    .lines()
                    .any(|line| line.starts_with(identity) && !line.ends_with(" 0")),
                "zero or missing `{identity}`\n{encoded}"
            );
        }
        owner.shutdown().await.expect("tagged DNS shutdown");
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
        let key_cases = [
            (
                "equal snapshot",
                DnsUdpPoolKey {
                    plan: Some(selected.clone()),
                },
                true,
            ),
            ("absent plan", DnsUdpPoolKey { plan: None }, false),
            (
                "different hop order",
                DnsUdpPoolKey {
                    plan: Some(reversed),
                },
                false,
            ),
            (
                "selector switched plan",
                DnsUdpPoolKey { plan: Some(later) },
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
        let (path, mut context) = udp_test_context_for_server(registry.clone(), first_server);
        let outbounds = prepare_client_outbounds(
            (0..3)
                .map(|_| ferrum2_config::ClientOutboundConfig::Shadowsocks {
                    server: first_server.into(),
                    psk: Arc::new(default_test_psk()),
                })
                .collect(),
        )
        .expect("pool outbounds");
        Arc::get_mut(
            &mut Arc::get_mut(&mut context)
                .expect("unique pool context")
                .egress,
        )
        .expect("unique pool egress")
        .outbounds = outbounds;
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
                .prepare_udp_with(selected.clone(), UdpSocket::bind)
                .await
                .expect("key association");
            let pool = Arc::new(Mutex::new(vec![IdleDnsUdp {
                key: DnsUdpPoolKey {
                    plan: Some(selected.clone()),
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
            let mut association = context
                .egress
                .prepare_udp_with(plan.clone(), UdpSocket::bind)
                .await
                .expect("mutation association");
            association
                .activate(&context.egress)
                .expect("mutation activation");
            let pool = Arc::new(Mutex::new(Vec::new()));
            let (session_responses, mut responses) = mpsc::channel(1);
            let mut pooled = PooledDnsUdp {
                idle: Some(IdleDnsUdp {
                    key: DnsUdpPoolKey {
                        plan: Some(plan.clone()),
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
                .handle();
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
                    Some(&plan),
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
                plan: Some(plan.clone()),
            };
            let (matched, stale) = take_dns_udp(&pool, &key).expect("mutation exact reuse");
            assert!(stale.is_none(), "{case} healthy exact key was discarded");
            let idle = matched.expect("mutation exact-key association");
            assert_eq!(idle.association.handle(), mutation_handle, "{case}");
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
                        .set_io_fault(Some(Arc::new(UdpIoFaultPlan::new(operation, 1))));
                    assert!(
                        pooled
                            .relay_request(
                                &context.egress,
                                Some(&plan),
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
                            Some(&plan),
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
                                Some(&plan),
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
                            .prepare_udp_with(plan.clone(), UdpSocket::bind)
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
                .prepare_udp_with(plan.clone(), UdpSocket::bind)
                .await
                .expect("following valid association");
            let mut initial = Some(IdleDnsUdp {
                key: DnsUdpPoolKey {
                    plan: Some(plan.clone()),
                },
                association,
            });
            for valid in 0..2_u8 {
                let (idle, reusable) = match initial.take() {
                    Some(idle) => (idle, false),
                    None => {
                        let key = DnsUdpPoolKey {
                            plan: Some(plan.clone()),
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
                        Some(&plan),
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

    async fn dns_tcp_detour_once(
        listener: TcpListener,
        expected_target: SocketAddr,
        opened: Option<tokio::sync::oneshot::Sender<()>>,
        release: Option<tokio::sync::oneshot::Receiver<()>>,
    ) -> usize {
        let (stream, _) = listener.accept().await.expect("DNS detour accept");
        let stream = ferrum2_runtime::RuntimeTcpStream::from_connected(stream)
            .expect("DNS detour runtime stream");
        let keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(default_test_psk()));
        let clock = SystemClock::new();
        let random = SystemRandom;
        let replay = TcpReplayStore::new(1024).expect("DNS detour replay");
        let ferrum2_core::Session {
            target,
            stream,
            initial_payload,
            ..
        } = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay)
            .accept(TokioTransport::new(stream))
            .await
            .expect("authenticated DNS detour");
        assert_eq!(target.as_socket_addr(), Some(expected_target));
        if let Some(opened) = opened {
            let _ = opened.send(());
        }
        if let Some(release) = release {
            let _ = release.await;
        }
        let mut upstream = tokio::net::TcpStream::connect(expected_target)
            .await
            .expect("DNS detour target");
        upstream
            .write_all(&initial_payload)
            .await
            .expect("DNS detour initial payload");
        let mut stream = TokioFramed::new(stream);
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
        1 + usize::from(
            tokio::time::timeout(Duration::from_millis(250), listener.accept())
                .await
                .is_ok(),
        )
    }

    pub(in crate::run) async fn relay_dns_udp_hop_once(
        socket: &UdpSocket,
        server: &UdpServer,
        upstream_address: SocketAddr,
        clock: &SystemClock,
        random: &SystemRandom,
        scratch: &mut UdpPacketScratch,
        invalid_first: bool,
    ) {
        let mut wire = vec![0_u8; MAX_UDP_WIRE_LEN];
        let mut plain = [0_u8; 4096];
        let (length, peer) = socket
            .recv_from(&mut wire)
            .await
            .expect("encrypted DNS query");
        if invalid_first {
            socket
                .send_to(b"bad", peer)
                .await
                .expect("invalid encrypted DNS response");
        }
        let pending = server
            .prepare_request(clock, &wire[..length], scratch)
            .expect("authenticated DNS query");
        assert_eq!(
            pending.datagram().target().as_socket_addr(),
            Some(upstream_address)
        );
        let request = pending.datagram().payload().to_vec();
        let (_, commit) = pending.into_parts();
        let accepted = server
            .commit_request(commit, peer, clock.monotonic_now(), random)
            .expect("commit DNS query");
        socket
            .send_to(&request, upstream_address)
            .await
            .expect("forward plain DNS query");
        let (length, source) = socket
            .recv_from(&mut plain)
            .await
            .expect("plain DNS response");
        assert_eq!(source, upstream_address);
        let response = server
            .encode_response(
                accepted.capability(),
                clock,
                random,
                &test_datagram(
                    TargetAddr::ip(upstream_address).expect("numeric DNS target"),
                    &plain[..length],
                ),
                0,
                &mut wire,
                scratch,
            )
            .expect("encrypt DNS response");
        socket
            .send_to(&wire[..response.wire_len()], peer)
            .await
            .expect("encrypted DNS response");
    }
    #[tokio::test]
    async fn dns_proxy_selector_snapshot_and_no_fallback() {
        let socks = reserve_address();
        let dns = reserve_address();
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("TCP DNS upstream");
        let upstream_address = upstream.local_addr().expect("TCP DNS upstream address");
        let detours = [
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("outer DNS detour"),
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("inner DNS detour"),
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("later DNS detour"),
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("selected dead detour"),
        ];
        let detour_addresses: [SocketAddrV4; 4] = detours.each_ref().map(|listener| match listener
            .local_addr()
            .expect("detour address")
        {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 DNS detour"),
        });
        let [outer, inner, later, dead] = detours;
        let (path, mut config) = client_test_config(socks, detour_addresses[3]);
        config.outbounds = detour_addresses
            .into_iter()
            .map(|server| ferrum2_config::ClientOutboundConfig::Shadowsocks {
                server: server.into(),
                psk: Arc::new(default_test_psk()),
            })
            .collect();
        let (route, selector, mut dns_roots) = compile_selector_plans_with_roots(
            &[TaggedInbound::new("entry", 0)],
            &[
                TaggedOutbound::new("outer", 0),
                TaggedOutbound::new("inner", 1),
                TaggedOutbound::new("later", 2),
                TaggedOutbound::new("dead", 3),
            ],
            &[TaggedPlan::new("chain", vec![0, 1])],
            &[SelectorDefinition::new(
                "dns-manual",
                vec!["chain", "later", "dead"],
                Some("chain"),
            )],
            TaggedRoute::Static(vec![TaggedStaticBinding::new("entry", "dead")]),
            &["dns-manual"],
        )
        .expect("DNS selector graph");
        config.route = route;
        config.dns = Some(ferrum2_config::DnsConfig {
            inbounds: vec![ferrum2_config::DnsInboundConfig {
                listen: SocketAddr::V4(dns),
            }],
            servers: vec![ferrum2_config::DnsServerConfig {
                transport: ferrum2_config::DnsTransport::Tcp,
                address: upstream_address,
                server_name: None,
                path: None,
                detour: Some(dns_roots.remove(0)),
            }],
            route: ferrum2_rule::ActionTable::new(Vec::new(), 0).expect("selector DNS final"),
            timeout: Duration::from_millis(150),
            max_inflight: std::num::NonZeroU16::new(1).expect("selector DNS admission"),
            runtime: ferrum2_config::DnsRuntimeConfig::default(),
        });

        let upstream_task = tokio::spawn(async move {
            for answer in [
                Ipv4Addr::new(203, 0, 113, 50),
                Ipv4Addr::new(203, 0, 113, 51),
            ] {
                let (mut stream, _) = upstream.accept().await.expect("TCP DNS connection");
                let length = stream.read_u16().await.expect("TCP DNS request length");
                let mut wire = vec![0_u8; usize::from(length)];
                stream.read_exact(&mut wire).await.expect("TCP DNS request");
                let request = Message::from_vec(&wire).expect("typed TCP DNS request");
                let question = request
                    .queries
                    .first()
                    .expect("one TCP DNS question")
                    .clone();
                let mut response = Message::response(request.metadata.id, OpCode::Query);
                response
                    .add_query(question.clone())
                    .add_answer(Record::from_rdata(
                        question.name().clone(),
                        30,
                        RData::A(A(answer)),
                    ));
                let response = response.to_vec().expect("typed TCP DNS response");
                stream
                    .write_u16(u16::try_from(response.len()).expect("bounded TCP DNS response"))
                    .await
                    .expect("TCP DNS response length");
                stream.write_all(&response).await.expect("TCP DNS response");
            }
        });
        let outer_target = SocketAddr::V4(detour_addresses[1]);
        let (opened, opened_inner) = tokio::sync::oneshot::channel();
        let (release_inner, release) = tokio::sync::oneshot::channel();
        let outer_task = tokio::spawn(dns_tcp_detour_once(outer, outer_target, None, None));
        let inner_task = tokio::spawn(dns_tcp_detour_once(
            inner,
            upstream_address,
            Some(opened),
            Some(release),
        ));
        let later_task = tokio::spawn(dns_tcp_detour_once(later, upstream_address, None, None));
        let registry = OwnerRegistry::new();
        let metrics = Arc::new(Metrics::new());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(run_with_registry_and_metrics(
            config,
            registry.clone(),
            async move {
                let _ = stopped.await;
            },
            Arc::clone(&metrics),
        ));
        wait_until_bound(dns).await;
        let mut client = tokio::net::TcpStream::connect(dns)
            .await
            .expect("selector DNS client");
        let query = |id, name: &str| {
            let mut query = Message::new(id, MessageType::Query, OpCode::Query);
            query.add_query(Query::query(
                Name::from_ascii(name).expect("selector query name"),
                RecordType::A,
            ));
            query.to_vec().expect("typed selector query")
        };
        let write_query = async |client: &mut tokio::net::TcpStream, query: &[u8]| {
            client
                .write_u16(u16::try_from(query.len()).expect("bounded selector query"))
                .await
                .expect("selector query length");
            client.write_all(query).await.expect("selector query");
        };
        let read_response = async |client: &mut tokio::net::TcpStream| {
            let length = client.read_u16().await.expect("selector response length");
            let mut wire = vec![0_u8; usize::from(length)];
            client
                .read_exact(&mut wire)
                .await
                .expect("selector response");
            Message::from_vec(&wire).expect("typed selector response")
        };

        write_query(&mut client, &query(0x4401, "held.selector.example.")).await;
        tokio::time::timeout(Duration::from_secs(2), opened_inner)
            .await
            .expect("held chain open timeout")
            .expect("held chain opened");
        selector
            .switch("dns-manual", "later")
            .expect("switch later DNS member");
        release_inner.send(()).expect("release held chain");
        let first = tokio::time::timeout(Duration::from_secs(2), read_response(&mut client))
            .await
            .expect("held selector response timeout");
        assert_eq!(first.metadata.id, 0x4401);
        assert_eq!(
            first.answers.first().map(|record| &record.data),
            Some(&RData::A(A(Ipv4Addr::new(203, 0, 113, 50))))
        );

        write_query(&mut client, &query(0x4402, "later.selector.example.")).await;
        let second = tokio::time::timeout(Duration::from_secs(2), read_response(&mut client))
            .await
            .expect("later selector response timeout");
        assert_eq!(second.metadata.id, 0x4402);
        assert_eq!(
            second.answers.first().map(|record| &record.data),
            Some(&RData::A(A(Ipv4Addr::new(203, 0, 113, 51))))
        );

        selector
            .switch("dns-manual", "dead")
            .expect("switch selected failure");
        write_query(&mut client, &query(0x4403, "dead.selector.example.")).await;
        let failed = tokio::time::timeout(Duration::from_secs(2), read_response(&mut client))
            .await
            .expect("selected failure response timeout");
        assert_eq!(failed.metadata.id, 0x4403);
        assert_eq!(failed.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(outer_task.await.expect("outer detour join"), 1);
        assert_eq!(inner_task.await.expect("inner detour join"), 1);
        assert_eq!(later_task.await.expect("later detour join"), 1);
        let (selected_dead, _) = tokio::time::timeout(Duration::from_secs(1), dead.accept())
            .await
            .expect("selected dead timeout")
            .expect("selected dead connection");
        drop(selected_dead);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), dead.accept())
                .await
                .is_err(),
            "selected failure retried"
        );
        upstream_task.await.expect("TCP DNS upstream join");
        let telemetry = metrics.encode_text().expect("selector metrics");
        let bootstrap_sentinel = upstream_address.to_string();
        for sentinel in [
            "held.selector.example.",
            "later.selector.example.",
            "dead.selector.example.",
            "dns-manual",
            bootstrap_sentinel.as_str(),
        ] {
            assert!(
                !telemetry.contains(sentinel),
                "DNS sentinel leaked: {sentinel}"
            );
        }
        drop(client);
        stop.send(()).expect("stop selector client");
        assert_eq!(task.await.expect("selector client join"), Ok(()));
        drop(dead);
        drop(UdpSocket::bind(dns).await.expect("selector DNS UDP rebind"));
        drop(
            TcpListener::bind(dns)
                .await
                .expect("selector DNS TCP rebind"),
        );
        for address in detour_addresses {
            drop(
                TcpListener::bind(address)
                    .await
                    .expect("selector detour rebind"),
            );
        }
        drop(
            TcpListener::bind(upstream_address)
                .await
                .expect("selector upstream rebind"),
        );
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
        std::fs::remove_file(path).expect("remove selector config");
    }

    #[tokio::test]
    async fn dns_proxy_first_match_direct_and_detoured_transports() {
        let socks = reserve_address();
        let shadowsocks = reserve_address();
        let dns = reserve_address();
        let upstreams = [
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("rule DNS upstream"),
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("ANY DNS upstream"),
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("qtype-less DNS upstream"),
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("final DNS upstream"),
        ];
        let upstream_addresses = upstreams
            .each_ref()
            .map(|upstream| upstream.local_addr().expect("upstream address"));
        let (path, _) = client_test_config(socks, shadowsocks);
        let source = format!(
            "schema_version = 2\n\
             [[inbounds]]\n\
             tag = \"i0\"\n\
             listen = \"{socks}\"\n\
             [[outbounds]]\n\
             tag = \"o0\"\n\
             server = \"{shadowsocks}\"\n\
             [route]\n\
             final = \"o0\"\n\
             [shadowsocks]\n\
             method = \"2022-blake3-aes-128-gcm\"\n\
             psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
             [runtime]\n\
             shutdown_grace_ms = 0\n\
             [dns]\n\
             [[dns.inbounds]]\n\
             tag = \"d0\"\n\
             listen = \"{dns}\"\n\
             [[dns.servers]]\n\
             tag = \"rule\"\n\
             transport = \"udp\"\n\
             address = \"{}\"\n\
             [[dns.servers]]\n\
             tag = \"any\"\n\
             transport = \"udp\"\n\
             address = \"{}\"\n\
             [[dns.servers]]\n\
             tag = \"untyped\"\n\
             transport = \"udp\"\n\
             address = \"{}\"\n\
             [[dns.servers]]\n\
             tag = \"final\"\n\
             transport = \"udp\"\n\
             address = \"{}\"\n\
             [dns.route]\n\
             final = \"final\"\n\
             [[dns.route.rules]]\n\
             inbound = \"d0\"\n\
             network = \"udp\"\n\
             qname_suffix = \"selected.example\"\n\
             qtype = \"A\"\n\
             server = \"rule\"\n\
             [[dns.route.rules]]\n\
             inbound = \"d0\"\n\
             network = \"tcp\"\n\
             qname = \"exact.example\"\n\
             qtype = \"AAAA\"\n\
             server = \"rule\"\n\
             [[dns.route.rules]]\n\
             inbound = \"d0\"\n\
             network = \"udp\"\n\
             qname = \"unknown.policy.example\"\n\
             qtype = \"ANY\"\n\
             server = \"any\"\n\
             [[dns.route.rules]]\n\
             inbound = \"d0\"\n\
             network = \"udp\"\n\
             qname = \"unknown.policy.example\"\n\
             server = \"untyped\"\n",
            upstream_addresses[0],
            upstream_addresses[1],
            upstream_addresses[2],
            upstream_addresses[3],
        );
        std::fs::write(&path, source).expect("write v2 DNS policy config");
        let config = ferrum2_config::load_client(&path).expect("validated v2 DNS policy config");
        let registry = OwnerRegistry::new();
        let (stop, task) = spawn_test_client(config, &registry);
        let upstream_tasks: Vec<_> = upstreams
            .into_iter()
            .zip([
                vec![
                    (
                        Some("selected.example."),
                        RecordType::A,
                        Ipv4Addr::new(192, 0, 2, 44),
                    ),
                    (
                        Some("exact.example."),
                        RecordType::AAAA,
                        Ipv4Addr::new(192, 0, 2, 46),
                    ),
                ],
                vec![(
                    Some("unknown.policy.example."),
                    RecordType::ANY,
                    Ipv4Addr::new(192, 0, 2, 48),
                )],
                vec![(
                    Some("unknown.policy.example."),
                    RecordType::Unknown(65_400),
                    Ipv4Addr::new(192, 0, 2, 49),
                )],
                vec![
                    (
                        Some("selected.example."),
                        RecordType::AAAA,
                        Ipv4Addr::new(192, 0, 2, 45),
                    ),
                    (
                        Some("unmatched.policy.example."),
                        RecordType::Unknown(65_400),
                        Ipv4Addr::new(192, 0, 2, 50),
                    ),
                    (None, RecordType::A, Ipv4Addr::new(192, 0, 2, 47)),
                ],
            ])
            .map(|(upstream, expectations)| {
                tokio::spawn(async move {
                    let mut request = [0_u8; 4096];
                    for (expected_name, expected_type, answer) in expectations {
                        let (length, peer) =
                            upstream.recv_from(&mut request).await.expect("DNS request");
                        let request =
                            Message::from_vec(&request[..length]).expect("typed DNS request");
                        assert_eq!(request.metadata.message_type, MessageType::Query);
                        assert_eq!(request.metadata.op_code, OpCode::Query);
                        let question = request.queries.first().expect("one question").clone();
                        assert_eq!(question.query_type(), expected_type);
                        if let Some(expected_name) = expected_name {
                            assert_eq!(
                                question.name(),
                                &Name::from_ascii(expected_name).expect("expected query name")
                            );
                        }
                        let mut response = Message::response(request.metadata.id, OpCode::Query);
                        response.metadata.recursion_available = true;
                        response
                            .add_query(question.clone())
                            .add_answer(Record::from_rdata(
                                question.name().clone(),
                                30,
                                RData::A(A(answer)),
                            ));
                        upstream
                            .send_to(&response.to_vec().expect("typed DNS response"), peer)
                            .await
                            .expect("DNS response");
                    }
                })
            })
            .collect();
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("DNS client");
        let binary_name = Name::from_labels([
            vec![0x80; 63],
            vec![0x81; 63],
            vec![0x82; 63],
            vec![0x83; 61],
        ])
        .expect("valid maximum wire name");
        assert!(binary_name.to_ascii().len() > 255);
        wait_until_bound(dns).await;
        for (id, name, record_type, expected) in [
            (
                0x1234,
                Name::from_ascii("SeLeCtEd.ExAmPlE.").expect("absolute query name"),
                RecordType::A,
                Ipv4Addr::new(192, 0, 2, 44),
            ),
            (
                0x1235,
                Name::from_ascii("selected.example.").expect("wrong qtype name"),
                RecordType::AAAA,
                Ipv4Addr::new(192, 0, 2, 45),
            ),
            (
                0x1238,
                Name::from_ascii("unknown.policy.example.").expect("unknown qtype name"),
                RecordType::Unknown(65_400),
                Ipv4Addr::new(192, 0, 2, 49),
            ),
            (
                0x1239,
                Name::from_ascii("unmatched.policy.example.").expect("unknown final name"),
                RecordType::Unknown(65_400),
                Ipv4Addr::new(192, 0, 2, 50),
            ),
            (
                0x123a,
                Name::from_ascii("unknown.policy.example.").expect("ANY policy name"),
                RecordType::ANY,
                Ipv4Addr::new(192, 0, 2, 48),
            ),
        ] {
            let mut query = Message::new(id, MessageType::Query, OpCode::Query);
            query.add_query(Query::query(name, record_type));
            let query = query.to_vec().expect("typed query");
            let mut response = [0_u8; 4096];
            client.send_to(&query, dns).await.expect("proxy query");
            let (length, _) =
                tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut response))
                    .await
                    .expect("DNS proxy response timeout")
                    .expect("DNS proxy response");
            let response = Message::from_vec(&response[..length]).expect("typed proxy response");
            assert_eq!(response.metadata.id, id);
            assert_eq!(response.metadata.message_type, MessageType::Response);
            assert_eq!(response.metadata.op_code, OpCode::Query);
            assert_eq!(
                response.metadata.response_code,
                ResponseCode::NoError,
                "query {id:#06x}",
            );
            assert_eq!(response.queries.len(), 1);
            assert_eq!(
                response.answers.first().map(|record| &record.data),
                Some(&RData::A(A(expected)))
            );
        }
        for (id, name, record_type, expected) in [
            (
                0x1236,
                Name::from_ascii("EXACT.EXAMPLE.").expect("exact TCP query name"),
                RecordType::AAAA,
                Ipv4Addr::new(192, 0, 2, 46),
            ),
            (
                0x1237,
                binary_name,
                RecordType::A,
                Ipv4Addr::new(192, 0, 2, 47),
            ),
        ] {
            let mut query = Message::new(id, MessageType::Query, OpCode::Query);
            query.add_query(Query::query(name, record_type));
            let query = query.to_vec().expect("typed TCP query");
            let mut client = tokio::net::TcpStream::connect(dns)
                .await
                .expect("DNS TCP client");
            client
                .write_u16(u16::try_from(query.len()).expect("bounded TCP query"))
                .await
                .expect("DNS TCP query length");
            client.write_all(&query).await.expect("DNS TCP query");
            let length = client.read_u16().await.expect("DNS TCP response length");
            let mut response = vec![0_u8; usize::from(length)];
            client
                .read_exact(&mut response)
                .await
                .expect("DNS TCP response");
            let response = Message::from_vec(&response).expect("typed TCP proxy response");
            assert_eq!(response.metadata.id, id);
            assert_eq!(
                response.answers.first().map(|record| &record.data),
                Some(&RData::A(A(expected)))
            );
        }
        for upstream_task in upstream_tasks {
            upstream_task.await.expect("upstream task");
        }
        stop.send(()).expect("stop client");
        assert_eq!(task.await.expect("client task"), Ok(()));
        drop(client);
        drop(UdpSocket::bind(dns).await.expect("DNS UDP rebind"));
        drop(TcpListener::bind(dns).await.expect("DNS TCP rebind"));
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
        std::fs::remove_file(path).expect("remove config");
    }

    #[tokio::test]
    async fn dns_proxy_detoured_udp_with_public_associate_off() {
        let socks = reserve_address();
        let shadowsocks_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("Shadowsocks UDP hop");
        let shadowsocks = match shadowsocks_socket
            .local_addr()
            .expect("Shadowsocks hop address")
        {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 Shadowsocks hop"),
        };
        let dns = reserve_address();
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("detoured DNS upstream");
        let upstream_address = upstream.local_addr().expect("detoured upstream address");
        let (path, mut config) = client_test_config(socks, shadowsocks);
        config.udp = None;
        config.dns = Some(ferrum2_config::DnsConfig {
            inbounds: vec![ferrum2_config::DnsInboundConfig {
                listen: SocketAddr::V4(dns),
            }],
            servers: vec![ferrum2_config::DnsServerConfig {
                transport: ferrum2_config::DnsTransport::Udp,
                address: upstream_address,
                server_name: None,
                path: None,
                detour: Some(ferrum2_core::route::EgressPlanHandle::direct(0)),
            }],
            route: ferrum2_rule::ActionTable::new(Vec::new(), 0)
                .expect("detoured DNS final action"),
            timeout: Duration::from_secs(1),
            max_inflight: std::num::NonZeroU16::new(1).expect("detoured DNS admission"),
            runtime: ferrum2_config::DnsRuntimeConfig::default(),
        });
        let registry = OwnerRegistry::new();
        let (stop, task) = spawn_test_client(config, &registry);

        let upstream_task = tokio::spawn(async move {
            let mut wire = [0_u8; 4096];
            for answer in [
                Ipv4Addr::new(198, 51, 100, 41),
                Ipv4Addr::new(198, 51, 100, 42),
            ] {
                let (length, peer) = upstream
                    .recv_from(&mut wire)
                    .await
                    .expect("plain DNS query");
                let request = Message::from_vec(&wire[..length]).expect("typed detoured request");
                let question = request.queries.first().expect("detoured question").clone();
                let mut response = Message::response(request.metadata.id, OpCode::Query);
                response
                    .add_query(question.clone())
                    .add_answer(Record::from_rdata(
                        question.name().clone(),
                        30,
                        RData::A(A(answer)),
                    ));
                upstream
                    .send_to(&response.to_vec().expect("typed detoured response"), peer)
                    .await
                    .expect("plain DNS response");
            }
        });

        let hop_task = tokio::spawn(async move {
            let keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(default_test_psk()));
            let server = UdpServer::new(&keys).expect("Shadowsocks UDP server");
            let clock = SystemClock::new();
            let random = SystemRandom;
            let mut scratch = UdpPacketScratch::new();
            for _ in 0..2 {
                relay_dns_udp_hop_once(
                    &shadowsocks_socket,
                    &server,
                    upstream_address,
                    &clock,
                    &random,
                    &mut scratch,
                    false,
                )
                .await;
            }
            assert_eq!(
                server.session_count().expect("DNS UDP session count"),
                1,
                "sequential DNS queries must reuse one SIP022 UDP session"
            );
        });

        wait_until_bound(socks).await;
        wait_until_bound(dns).await;
        let mut rejected = tokio::net::TcpStream::connect(socks)
            .await
            .expect("SOCKS public-off connect");
        rejected
            .write_all(&[5, 1, 0])
            .await
            .expect("SOCKS public-off greeting");
        let mut method = [0_u8; 2];
        rejected
            .read_exact(&mut method)
            .await
            .expect("SOCKS public-off method");
        rejected
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .expect("SOCKS public-off UDP request");
        let mut reply = [0_u8; 10];
        assert!(
            rejected.read_exact(&mut reply).await.is_err() || reply[..2] != [5, 0],
            "internal DNS enabled public UDP"
        );
        drop(rejected);

        let query = |id, name: &str| {
            let mut query = Message::new(id, MessageType::Query, OpCode::Query);
            query.add_query(Query::query(
                Name::from_ascii(name).expect("absolute detoured name"),
                RecordType::A,
            ));
            query.to_vec().expect("typed detoured query")
        };
        let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("detoured UDP client");
        let udp_query = query(0x2201, "udp.detoured.example.");
        let mut response = [0_u8; 4096];
        udp_client
            .send_to(&udp_query, dns)
            .await
            .expect("detoured UDP query");
        let (udp_length, _) =
            tokio::time::timeout(Duration::from_secs(2), udp_client.recv_from(&mut response))
                .await
                .expect("detoured DNS response timeout")
                .expect("detoured DNS response");
        let udp_response =
            Message::from_vec(&response[..udp_length]).expect("detoured UDP response");
        assert_eq!(udp_response.metadata.id, 0x2201);
        assert_eq!(
            udp_response.answers.first().map(|record| &record.data),
            Some(&RData::A(A(Ipv4Addr::new(198, 51, 100, 41))))
        );

        let mut tcp_client = tokio::net::TcpStream::connect(dns)
            .await
            .expect("detoured TCP client");
        let tcp_query = query(0x2202, "tcp.detoured.example.");
        tcp_client
            .write_u16(u16::try_from(tcp_query.len()).expect("bounded TCP query"))
            .await
            .expect("detoured TCP length");
        tcp_client
            .write_all(&tcp_query)
            .await
            .expect("detoured TCP query");
        let length = tcp_client
            .read_u16()
            .await
            .expect("detoured TCP response length");
        let mut response = vec![0_u8; usize::from(length)];
        tcp_client
            .read_exact(&mut response)
            .await
            .expect("detoured TCP response");
        let response = Message::from_vec(&response).expect("typed detoured TCP response");
        assert_eq!(response.metadata.id, 0x2202);
        assert_eq!(
            response.answers.first().map(|record| &record.data),
            Some(&RData::A(A(Ipv4Addr::new(198, 51, 100, 42))))
        );

        upstream_task.await.expect("detoured upstream task");
        hop_task.await.expect("detoured hop task");
        stop.send(()).expect("stop detoured client");
        assert_eq!(task.await.expect("detoured client task"), Ok(()));
        drop((tcp_client, udp_client));
        drop(UdpSocket::bind(dns).await.expect("detoured DNS UDP rebind"));
        drop(
            TcpListener::bind(dns)
                .await
                .expect("detoured DNS TCP rebind"),
        );
        drop(
            UdpSocket::bind(shadowsocks)
                .await
                .expect("Shadowsocks hop rebind"),
        );
        drop(
            UdpSocket::bind(upstream_address)
                .await
                .expect("DNS upstream rebind"),
        );
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
        std::fs::remove_file(path).expect("remove detoured config");
    }

    #[tokio::test]
    async fn dns_proxy_detour_saturation_shutdown_and_exact_rebind() {
        let socks = reserve_address();
        let hop = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("stalled Shadowsocks hop");
        let shadowsocks = match hop.local_addr().expect("stalled Shadowsocks hop address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 stalled Shadowsocks hop"),
        };
        let dns = [reserve_address(), reserve_address()];
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("stalled DNS upstream");
        let upstream_address = upstream.local_addr().expect("stalled upstream address");
        let (seen, mut received) = tokio::sync::oneshot::channel();
        let hop_task = tokio::spawn(async move {
            let mut wire = vec![0_u8; MAX_UDP_WIRE_LEN];
            let _ = hop
                .recv_from(&mut wire)
                .await
                .expect("stalled encrypted query");
            let _ = seen.send(());
            std::future::pending::<()>().await;
        });

        let (path, mut config) = client_udp_test_config(socks, shadowsocks);
        config.dns = Some(ferrum2_config::DnsConfig {
            inbounds: dns
                .into_iter()
                .map(|listen| ferrum2_config::DnsInboundConfig {
                    listen: SocketAddr::V4(listen),
                })
                .collect(),
            servers: vec![ferrum2_config::DnsServerConfig {
                transport: ferrum2_config::DnsTransport::Udp,
                address: upstream_address,
                server_name: None,
                path: None,
                detour: Some(ferrum2_core::route::EgressPlanHandle::direct(0)),
            }],
            route: ferrum2_rule::ActionTable::new(Vec::new(), 0).expect("stalled DNS final action"),
            timeout: Duration::from_secs(5),
            max_inflight: std::num::NonZeroU16::new(1).expect("one DNS admission"),
            runtime: ferrum2_config::DnsRuntimeConfig::default(),
        });
        let registry = OwnerRegistry::new();
        let (observed, resolver) = tokio::sync::oneshot::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let dns_specs = config
            .dns
            .as_ref()
            .map(|dns| dns_egress::dns_runtime_specs(&dns.servers));
        let task = tokio::spawn(run_with_registry_and_metrics_inner(
            config,
            registry.clone(),
            async move {
                let _ = stopped.await;
            },
            Arc::new(Metrics::new()),
            None,
            Some(observed),
            ClientRunResources::legacy(dns_specs),
        ));
        let (context, resolver) = resolver.await.expect("observed DNS resolver");
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("saturation DNS client");
        let query = |id, name: &str| {
            let mut query = Message::new(id, MessageType::Query, OpCode::Query);
            query.add_query(Query::query(
                Name::from_ascii(name).expect("absolute saturation name"),
                RecordType::A,
            ));
            query.to_vec().expect("typed saturation query")
        };
        let first = query(0x3301, "held.detoured.example.");
        wait_until_bound(dns[0]).await;
        client
            .send_to(&first, dns[0])
            .await
            .expect("held detoured query");
        tokio::time::timeout(Duration::from_secs(1), &mut received)
            .await
            .expect("detoured hop receive timeout")
            .expect("detoured hop receive signal");
        let held = active(registry.snapshot());
        assert_eq!(held.udp_sessions, 1);
        assert_eq!(held.udp_buffered_bytes, 3 * MAX_UDP_WIRE_LEN);
        let dns_held = resolver.stats();
        assert_eq!(dns_held.queries, 1);
        assert_eq!(dns_held.udp_sockets, 1);
        assert_eq!(dns_held.bridge_tasks, 1);
        assert_eq!(dns_held.sessions, 1);
        assert_eq!(dns_held.queues, 4);
        assert_eq!(dns_held.buffers, 1);
        assert_eq!(
            context
                .egress
                .udp
                .as_ref()
                .expect("shared DNS/public UDP manager")
                .manager
                .session_count(),
            1
        );
        let (public_control, public_reply) = socks_command(socks, 3).await;
        assert_ne!(public_reply[1], 0, "public UDP used a second manager");
        drop(public_control);
        assert_eq!(active(registry.snapshot()), held);

        let second = query(0x3302, "busy.detoured.example.");
        client
            .send_to(&second, dns[1])
            .await
            .expect("saturated DNS query");
        let mut wire = [0_u8; 4096];
        let (length, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut wire))
            .await
            .expect("saturated response timeout")
            .expect("saturated response");
        let response = Message::from_vec(&wire[..length]).expect("typed saturated response");
        assert_eq!(response.metadata.id, 0x3302);
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(active(registry.snapshot()), held);

        stop.send(()).expect("stop saturated client");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("bounded saturated shutdown")
                .expect("saturated client task"),
            Ok(())
        );
        hop_task.abort();
        assert!(
            hop_task
                .await
                .expect_err("stalled hop cancellation")
                .is_cancelled()
        );
        assert_eq!(resolver.stats(), ferrum2_dns::RuntimeStats::default());
        drop((context, resolver));
        drop((client, upstream));
        for listen in dns {
            drop(
                UdpSocket::bind(listen)
                    .await
                    .expect("saturated DNS UDP rebind"),
            );
            drop(
                TcpListener::bind(listen)
                    .await
                    .expect("saturated DNS TCP rebind"),
            );
        }
        drop(
            UdpSocket::bind(shadowsocks)
                .await
                .expect("stalled hop rebind"),
        );
        drop(
            UdpSocket::bind(upstream_address)
                .await
                .expect("stalled upstream rebind"),
        );
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
        std::fs::remove_file(path).expect("remove saturation config");
    }
}
