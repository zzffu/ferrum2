use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum2_config::{DnsServerConfig, DnsTransport, load_client};
use ferrum2_dns::{
    BoxedDnsDatagramIo, BoxedDnsTcpIo, DnsEgress, DnsError, DnsIoFuture, DnsTaskRegistrar,
    PlanSnapshot, SystemDnsEgress, TaggedResolver,
};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, NS, SOA};
use hickory_proto::rr::{LowerName, Name, RData, Record, RecordType};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_server::Server;
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{AxfrPolicy, Catalog, ZoneType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

#[derive(Clone, Debug, Eq, PartialEq)]
struct EgressCall {
    network: &'static str,
    target: SocketAddr,
    plan: Option<Vec<usize>>,
}

#[derive(Default)]
struct RecordingEgress {
    calls: Mutex<Vec<EgressCall>>,
}

impl RecordingEgress {
    fn calls(&self) -> Vec<EgressCall> {
        self.calls.lock().expect("egress calls poisoned").clone()
    }

    fn record(&self, network: &'static str, target: SocketAddr, plan: &Option<PlanSnapshot>) {
        self.calls
            .lock()
            .expect("egress calls poisoned")
            .push(EgressCall {
                network,
                target,
                plan: plan.as_ref().map(|plan| plan.hops().to_vec()),
            });
    }
}

impl DnsEgress for RecordingEgress {
    fn connect_tcp(
        &self,
        target: SocketAddr,
        plan: Option<PlanSnapshot>,
        timeout: Duration,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo> {
        self.record("tcp", target, &plan);
        SystemDnsEgress.connect_tcp(target, None, timeout, tasks)
    }

    fn bind_udp(
        &self,
        target: SocketAddr,
        plan: Option<PlanSnapshot>,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo> {
        self.record("udp", target, &plan);
        SystemDnsEgress.bind_udp(target, None, tasks)
    }
}

struct PlainFixture {
    address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl PlainFixture {
    async fn start() -> Self {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind fixture UDP");
        let address = udp.local_addr().expect("fixture UDP address");
        let tcp = TcpListener::bind(address).await.expect("bind fixture TCP");

        let origin = Name::from_ascii("resolver.test.").expect("zone origin");
        let mut zone = InMemoryZoneHandler::<TokioRuntimeProvider>::empty(
            origin.clone(),
            ZoneType::Primary,
            AxfrPolicy::Deny,
        );
        let ns = Name::from_ascii("ns.resolver.test.").expect("NS name");
        zone.upsert_mut(
            Record::from_rdata(
                origin.clone(),
                60,
                RData::SOA(SOA::new(
                    ns.clone(),
                    Name::from_ascii("hostmaster.resolver.test.").expect("SOA mailbox"),
                    1,
                    60,
                    60,
                    60,
                    60,
                )),
            ),
            1,
        );
        zone.upsert_mut(Record::from_rdata(origin.clone(), 60, RData::NS(NS(ns))), 1);
        zone.upsert_mut(
            Record::from_rdata(
                Name::from_ascii("answer.resolver.test.").expect("A name"),
                60,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 41))),
            ),
            1,
        );
        zone.upsert_mut(
            Record::from_rdata(
                Name::from_ascii("v6.resolver.test.").expect("AAAA name"),
                60,
                RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 41))),
            ),
            1,
        );
        zone.upsert_mut(
            Record::from_rdata(
                Name::from_ascii("alias.resolver.test.").expect("CNAME owner"),
                60,
                RData::CNAME(CNAME(
                    Name::from_ascii("answer.resolver.test.").expect("CNAME target"),
                )),
            ),
            1,
        );

        let mut catalog = Catalog::new();
        catalog.upsert(LowerName::new(&origin), vec![Arc::new(zone)]);
        let mut server = Server::new(catalog);
        server.register_socket(udp);
        server.register_listener(tcp, Duration::from_secs(2), 4);
        let task = tokio::spawn(async move {
            server
                .block_until_done()
                .await
                .expect("fixture server failed");
        });
        Self { address, task }
    }

    async fn shutdown(self) {
        self.task.abort();
        assert!(
            self.task
                .await
                .expect_err("fixture task should cancel")
                .is_cancelled()
        );
    }
}

fn configured_server(
    address: SocketAddr,
    transport: DnsTransport,
    detoured: bool,
) -> DnsServerConfig {
    let detour = if detoured { "detour = \"o0\"\n" } else { "" };
    let source = format!(
        "schema_version = 1\n\
         [[inbounds]]\n\
         tag = \"i0\"\n\
         listen = \"127.0.0.1:11080\"\n\
         outbound = \"o0\"\n\
         [[outbounds]]\n\
         tag = \"o0\"\n\
         server = \"127.0.0.1:20000\"\n\
         [dns]\n\
         timeout_ms = 1000\n\
         max_inflight = 8\n\
         [[dns.inbounds]]\n\
         tag = \"d0\"\n\
         listen = \"127.0.0.1:15353\"\n\
         [[dns.servers]]\n\
         tag = \"s0\"\n\
         transport = \"{}\"\n\
         address = \"{address}\"\n\
         {detour}\
         [dns.route]\n\
         final = \"s0\"\n\
         [shadowsocks]\n\
         method = \"2022-blake3-aes-128-gcm\"\n\
         psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n",
        match transport {
            DnsTransport::Udp => "udp",
            DnsTransport::Tcp => "tcp",
            DnsTransport::Dot => "dot",
            DnsTransport::Doh => "doh",
        }
    );
    let path = std::env::temp_dir().join(format!(
        "ferrum2-dns-t03-{}-{}-{}-{:?}.toml",
        std::process::id(),
        address.port(),
        if detoured { "detour" } else { "direct" },
        transport,
    ));
    std::fs::write(&path, source).expect("write test config");
    let config = load_client(&path).expect("load test config");
    std::fs::remove_file(path).expect("remove test config");
    config
        .dns
        .expect("validated DNS")
        .servers
        .into_iter()
        .next()
        .expect("validated server")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_tcp_exact_server_plan_and_negative_semantics() {
    let fixture = PlainFixture::start().await;
    let egress = Arc::new(RecordingEgress::default());
    let resolver = TaggedResolver::new(
        vec![
            configured_server(fixture.address, DnsTransport::Udp, true),
            configured_server(fixture.address, DnsTransport::Tcp, false),
        ],
        Duration::from_secs(1),
        NonZeroU16::new(8).expect("nonzero admission"),
        egress.clone(),
    )
    .expect("start resolver");

    for server in [0, 1] {
        let a = resolver
            .lookup(
                server,
                Name::from_ascii("answer.resolver.test.").expect("A query"),
                RecordType::A,
            )
            .await
            .expect("A lookup");
        assert!(
            a.answers()
                .iter()
                .any(|record| record.data == RData::A(A(Ipv4Addr::new(192, 0, 2, 41))))
        );

        let aaaa = resolver
            .lookup(
                server,
                Name::from_ascii("v6.resolver.test.").expect("AAAA query"),
                RecordType::AAAA,
            )
            .await
            .expect("AAAA lookup");
        assert!(
            aaaa.answers()
                .iter()
                .any(|record| matches!(record.data, RData::AAAA(_)))
        );

        let cname = resolver
            .lookup(
                server,
                Name::from_ascii("alias.resolver.test.").expect("CNAME query"),
                RecordType::A,
            )
            .await
            .expect("CNAME lookup");
        assert!(
            cname
                .answers()
                .iter()
                .any(|record| matches!(record.data, RData::CNAME(_)))
        );

        assert_eq!(
            resolver
                .lookup(
                    server,
                    Name::from_ascii("missing.resolver.test.").expect("NX query"),
                    RecordType::A,
                )
                .await,
            Err(DnsError::NxDomain)
        );
        assert_eq!(
            resolver
                .lookup(
                    server,
                    Name::from_ascii("answer.resolver.test.").expect("NODATA query"),
                    RecordType::AAAA,
                )
                .await,
            Err(DnsError::NoData)
        );
    }

    let calls = egress.calls();
    assert!(calls.iter().any(|call| {
        call.network == "udp"
            && call.target == fixture.address
            && call.plan.as_deref() == Some(&[0][..])
    }));
    assert!(calls.iter().any(|call| {
        call.network == "tcp" && call.target == fixture.address && call.plan.is_none()
    }));
    assert!(calls.iter().all(|call| call.target == fixture.address));

    assert_eq!(
        resolver
            .shutdown()
            .await
            .expect("resolver shutdown")
            .runtime_tasks,
        0
    );
    let address = fixture.address;
    fixture.shutdown().await;
    assert!(UdpSocket::bind(address).await.is_ok());
    assert!(TcpListener::bind(address).await.is_ok());
}

fn answer(request: &hickory_proto::op::Message) -> hickory_proto::op::Message {
    use hickory_proto::op::{Message, MessageType, OpCode};

    let query = request.queries.first().expect("one query").clone();
    let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
    response.metadata.recursion_available = true;
    response
        .add_query(query.clone())
        .add_answer(Record::from_rdata(
            query.name().clone(),
            30,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 44))),
        ));
    response
}

async fn tc_fixture() -> (SocketAddr, Vec<tokio::task::JoinHandle<()>>) {
    use hickory_proto::op::Message;

    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("TC UDP bind");
    let address = udp.local_addr().expect("TC address");
    let tcp = TcpListener::bind(address).await.expect("TC TCP bind");
    let udp_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 4096];
        let (length, peer) = udp.recv_from(&mut buffer).await.expect("TC UDP receive");
        let request = Message::from_vec(&buffer[..length]).expect("TC query decode");
        udp.send_to(
            &answer(&request).truncate().to_vec().expect("TC encode"),
            peer,
        )
        .await
        .expect("TC send");
    });
    let tcp_task = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.expect("TC TCP accept");
        let length = stream.read_u16().await.expect("TC length");
        let mut bytes = vec![0; usize::from(length)];
        stream.read_exact(&mut bytes).await.expect("TC request");
        let response = answer(&Message::from_vec(&bytes).expect("TCP query decode"))
            .to_vec()
            .expect("TCP answer encode");
        stream
            .write_u16(response.len() as u16)
            .await
            .expect("answer length");
        stream.write_all(&response).await.expect("answer bytes");
    });
    (address, vec![udp_task, tcp_task])
}

#[derive(Clone, Copy)]
enum UdpFault {
    WrongSource,
    WrongId,
    Malformed,
}

async fn udp_fault(fault: UdpFault) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use hickory_proto::op::Message;

    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("fault UDP bind");
    let address = socket.local_addr().expect("fault UDP address");
    let task = tokio::spawn(async move {
        let mut buffer = [0_u8; 4096];
        let (length, peer) = socket.recv_from(&mut buffer).await.expect("fault receive");
        let request = Message::from_vec(&buffer[..length]).expect("fault query decode");
        match fault {
            UdpFault::WrongSource => {
                let other = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .expect("spoof socket");
                other
                    .send_to(&answer(&request).to_vec().expect("spoof encode"), peer)
                    .await
                    .expect("spoof send");
            }
            UdpFault::WrongId => {
                let mut response = answer(&request);
                response.metadata.id = response.id.wrapping_add(1);
                socket
                    .send_to(&response.to_vec().expect("wrong-ID encode"), peer)
                    .await
                    .expect("wrong-ID send");
            }
            UdpFault::Malformed => {
                socket
                    .send_to(&[0, 1, 2], peer)
                    .await
                    .expect("malformed send");
            }
        }
    });
    (address, task)
}

async fn half_frame() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("half-frame bind");
    let address = listener.local_addr().expect("half-frame address");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("half-frame accept");
        let length = stream.read_u16().await.expect("query length");
        let mut query = vec![0; usize::from(length)];
        stream.read_exact(&mut query).await.expect("query frame");
        stream.write_u16(32).await.expect("partial length");
        stream.write_all(&[0]).await.expect("partial byte");
    });
    (address, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn truncation_and_invalid_wire_inputs_never_change_plan_or_transport() {
    let (address, tasks) = tc_fixture().await;
    let egress = Arc::new(RecordingEgress::default());
    let resolver = TaggedResolver::new(
        vec![configured_server(address, DnsTransport::Udp, true)],
        Duration::from_millis(250),
        NonZeroU16::new(1).expect("nonzero admission"),
        egress.clone(),
    )
    .expect("start TC resolver");
    let tc_result = resolver
        .lookup(
            0,
            Name::from_ascii("tc.resolver.test.").expect("TC name"),
            RecordType::A,
        )
        .await;
    assert!(
        tc_result.as_ref().is_ok_and(|lookup| lookup
            .answers()
            .iter()
            .any(|record| record.data == RData::A(A(Ipv4Addr::new(192, 0, 2, 44))))),
        "TC result {tc_result:?}, calls {:?}",
        egress.calls()
    );
    assert_eq!(
        egress.calls(),
        vec![
            EgressCall {
                network: "udp",
                target: address,
                plan: Some(vec![0])
            },
            EgressCall {
                network: "tcp",
                target: address,
                plan: Some(vec![0])
            },
        ]
    );
    resolver.shutdown().await.expect("TC resolver shutdown");
    for task in tasks {
        task.await.expect("TC fixture join");
    }

    for fault in [
        UdpFault::WrongSource,
        UdpFault::WrongId,
        UdpFault::Malformed,
    ] {
        let (address, task) = udp_fault(fault).await;
        let egress = Arc::new(RecordingEgress::default());
        let resolver = TaggedResolver::new(
            vec![configured_server(address, DnsTransport::Udp, true)],
            Duration::from_millis(50),
            NonZeroU16::new(1).expect("nonzero admission"),
            egress.clone(),
        )
        .expect("start fault resolver");
        assert!(
            resolver
                .lookup(
                    0,
                    Name::from_ascii("fault.resolver.test.").expect("fault name"),
                    RecordType::A,
                )
                .await
                .is_err()
        );
        assert_eq!(
            egress.calls(),
            vec![EgressCall {
                network: "udp",
                target: address,
                plan: Some(vec![0])
            }]
        );
        resolver.shutdown().await.expect("fault resolver shutdown");
        task.await.expect("fault fixture join");
    }

    let (address, task) = half_frame().await;
    let egress = Arc::new(RecordingEgress::default());
    let resolver = TaggedResolver::new(
        vec![configured_server(address, DnsTransport::Tcp, true)],
        Duration::from_millis(100),
        NonZeroU16::new(1).expect("nonzero admission"),
        egress.clone(),
    )
    .expect("start half-frame resolver");
    assert!(
        resolver
            .lookup(
                0,
                Name::from_ascii("half.resolver.test.").expect("half-frame name"),
                RecordType::A,
            )
            .await
            .is_err()
    );
    assert_eq!(
        egress.calls(),
        vec![EgressCall {
            network: "tcp",
            target: address,
            plan: Some(vec![0])
        }]
    );
    resolver
        .shutdown()
        .await
        .expect("half-frame resolver shutdown");
    task.await.expect("half-frame fixture join");
}
