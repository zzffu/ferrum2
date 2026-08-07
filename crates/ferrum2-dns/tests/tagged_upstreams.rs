use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum2_core::route::{EgressPlanHandle, EgressPlanSnapshot};
use ferrum2_dns::{
    BoxedDnsDatagramIo, BoxedDnsTcpIo, DnsEgress, DnsError, DnsIoFuture, DnsTaskRegistrar,
    DnsUpstreamSpec, DnsUpstreamTransport, SystemDnsEgress, TaggedResolver,
};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, NS, SOA};
use hickory_proto::rr::{LowerName, Name, RData, Record, RecordType};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_server::Server;
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{AxfrPolicy, Catalog, ZoneType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

static TEST_NETWORK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static NEXT_TEST_PORT: AtomicU16 = AtomicU16::new(10_000);

async fn bind_paired_sockets() -> (SocketAddr, UdpSocket, TcpListener) {
    loop {
        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        assert!(port < 30_000, "no paired test address available");
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        if let (Ok(tcp), Ok(udp)) = (
            TcpListener::bind(address).await,
            UdpSocket::bind(address).await,
        ) {
            return (address, udp, tcp);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EgressCall {
    network: &'static str,
    target: SocketAddr,
    plan: Option<Vec<usize>>,
}

#[derive(Default)]
struct RecordingEgress {
    calls: Mutex<Vec<EgressCall>>,
    plan_ptrs: Mutex<Vec<usize>>,
}

impl RecordingEgress {
    fn calls(&self) -> Vec<EgressCall> {
        self.calls.lock().expect("egress calls poisoned").clone()
    }

    fn plan_ptrs(&self) -> Vec<usize> {
        self.plan_ptrs
            .lock()
            .expect("plan pointers poisoned")
            .clone()
    }

    fn record(&self, network: &'static str, target: SocketAddr, plan: &Option<EgressPlanSnapshot>) {
        if let Some(plan) = plan {
            self.plan_ptrs
                .lock()
                .expect("plan pointers poisoned")
                .push(plan.hops().as_ptr() as usize);
        }
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
        plan: Option<EgressPlanSnapshot>,
        timeout: Duration,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo> {
        self.record("tcp", target, &plan);
        SystemDnsEgress.connect_tcp(target, None, timeout, tasks)
    }

    fn bind_udp(
        &self,
        target: SocketAddr,
        plan: Option<EgressPlanSnapshot>,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo> {
        self.record("udp", target, &plan);
        SystemDnsEgress.bind_udp(target, None, tasks)
    }
}

struct PlainFixture {
    address: SocketAddr,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl PlainFixture {
    async fn start() -> Self {
        let (address, udp, tcp) = bind_paired_sockets().await;

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
                Name::from_ascii("answer.resolver.test.").expect("AAAA name"),
                60,
                RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 41))),
            ),
            1,
        );
        zone.upsert_mut(
            Record::from_rdata(
                Name::from_ascii("a-only.resolver.test.").expect("A-only name"),
                60,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 42))),
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
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = stopped.await;
            server
                .shutdown_gracefully()
                .await
                .expect("fixture server failed");
        });
        Self {
            address,
            stop,
            task,
        }
    }

    async fn shutdown(self) {
        self.stop.send(()).expect("fixture shutdown signal");
        self.task.await.expect("fixture shutdown task");
    }
}

fn configured_server(
    address: SocketAddr,
    transport: DnsUpstreamTransport,
    detoured: bool,
) -> DnsUpstreamSpec {
    DnsUpstreamSpec {
        transport,
        address,
        detour: detoured.then(|| EgressPlanHandle::direct(0)),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_tcp_exact_server_plan_and_negative_semantics() {
    let _network = TEST_NETWORK.lock().await;
    let fixture = PlainFixture::start().await;
    let egress = Arc::new(RecordingEgress::default());
    let (resolver, mut owner) = TaggedResolver::new(
        vec![
            configured_server(fixture.address, DnsUpstreamTransport::Udp, true),
            configured_server(fixture.address, DnsUpstreamTransport::Tcp, false),
        ],
        Duration::from_secs(1),
        NonZeroU16::new(8).expect("nonzero admission"),
        egress.clone(),
    )
    .expect("start resolver");
    owner.ready().await.expect("resolver ready");

    for server in [0, 1] {
        assert_eq!(
            resolver
                .lookup_ips(
                    server,
                    Name::from_ascii("answer.resolver.test.").expect("address query"),
                )
                .await
                .expect("ordered address lookup"),
            [
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 41)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 41)),
            ]
        );
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
                    Name::from_ascii("a-only.resolver.test.").expect("NODATA query"),
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

    drop(resolver);
    assert_eq!(
        owner
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

    let (address, udp, tcp) = bind_paired_sockets().await;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn address_lookup_shares_one_deadline_admission_plan_and_owner() {
    use hickory_proto::op::{Message, MessageType, OpCode};

    let _network = TEST_NETWORK.lock().await;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("address fixture bind");
    let address = socket.local_addr().expect("address fixture address");
    let (observed, mut observations) = tokio::sync::mpsc::unbounded_channel();
    let (release_a, released_a) = tokio::sync::oneshot::channel();
    let fixture = tokio::spawn(async move {
        let mut buffer = [0_u8; 4096];
        let (length, peer) = socket
            .recv_from(&mut buffer)
            .await
            .expect("address A receive");
        let request = Message::from_vec(&buffer[..length]).expect("address A decode");
        assert_eq!(request.queries[0].query_type(), RecordType::A);
        observed.send(RecordType::A).expect("observe A");
        released_a.await.expect("release A NODATA");
        let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
        response.add_query(request.queries[0].clone());
        socket
            .send_to(&response.to_vec().expect("A NODATA encode"), peer)
            .await
            .expect("A NODATA send");

        let (length, _) = socket
            .recv_from(&mut buffer)
            .await
            .expect("address AAAA receive");
        let request = Message::from_vec(&buffer[..length]).expect("address AAAA decode");
        assert_eq!(request.queries[0].query_type(), RecordType::AAAA);
        observed.send(RecordType::AAAA).expect("observe AAAA");
        std::future::pending::<()>().await;
    });
    let egress = Arc::new(RecordingEgress::default());
    let server = configured_server(address, DnsUpstreamTransport::Udp, true);
    let configured_plan_ptr = server
        .detour
        .as_ref()
        .expect("configured address detour")
        .snapshot_owned()
        .hops()
        .as_ptr() as usize;
    let (resolver, mut owner) = TaggedResolver::new(
        vec![server],
        Duration::from_millis(200),
        NonZeroU16::new(1).expect("one admission"),
        egress.clone(),
    )
    .expect("start address resolver");
    owner.ready().await.expect("address resolver ready");
    let started = tokio::time::Instant::now();
    let lookup = tokio::spawn(resolver.lookup_ips(
        0,
        Name::from_ascii("deadline.resolver.test.").expect("address name"),
    ));
    assert_eq!(observations.recv().await, Some(RecordType::A));
    assert_eq!(resolver.stats().queries, 1);
    assert_eq!(
        resolver
            .lookup_ips(
                0,
                Name::from_ascii("busy.resolver.test.").expect("busy name"),
            )
            .await,
        Err(DnsError::Busy)
    );
    tokio::time::sleep(Duration::from_millis(120)).await;
    release_a.send(()).expect("release delayed A");
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(50), observations.recv())
            .await
            .expect("AAAA followed A"),
        Some(RecordType::AAAA)
    );
    assert_eq!(
        lookup.await.expect("address lookup join"),
        Err(DnsError::Timeout)
    );
    assert!(
        started.elapsed() < Duration::from_millis(280),
        "AAAA received a fresh deadline"
    );
    assert_eq!(resolver.stats(), ferrum2_dns::RuntimeStats::default());
    assert_eq!(
        egress.calls(),
        vec![
            EgressCall {
                network: "udp",
                target: address,
                plan: Some(vec![0]),
            },
            EgressCall {
                network: "udp",
                target: address,
                plan: Some(vec![0]),
            },
        ]
    );
    let plan_ptrs = egress.plan_ptrs();
    assert_eq!(plan_ptrs, vec![configured_plan_ptr; 2]);
    drop(resolver);
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("address resolver shutdown")
            .stats,
        ferrum2_dns::RuntimeStats::default()
    );
    fixture.abort();
    assert!(
        fixture
            .await
            .expect_err("fixture cancellation")
            .is_cancelled()
    );
    assert!(UdpSocket::bind(address).await.is_ok());
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
    let _network = TEST_NETWORK.lock().await;
    let (address, tasks) = tc_fixture().await;
    let egress = Arc::new(RecordingEgress::default());
    let server = configured_server(address, DnsUpstreamTransport::Udp, true);
    let configured_plan_ptr = server
        .detour
        .as_ref()
        .expect("configured TC detour")
        .snapshot_owned()
        .hops()
        .as_ptr() as usize;
    let (resolver, mut owner) = TaggedResolver::new(
        vec![server],
        Duration::from_millis(250),
        NonZeroU16::new(1).expect("nonzero admission"),
        egress.clone(),
    )
    .expect("start TC resolver");
    owner.ready().await.expect("TC resolver ready");
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
    let plan_ptrs = egress.plan_ptrs();
    assert_eq!(plan_ptrs, vec![configured_plan_ptr; 2]);
    drop(resolver);
    owner.shutdown().await.expect("TC resolver shutdown");
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
        let (resolver, mut owner) = TaggedResolver::new(
            vec![configured_server(address, DnsUpstreamTransport::Udp, true)],
            Duration::from_millis(50),
            NonZeroU16::new(1).expect("nonzero admission"),
            egress.clone(),
        )
        .expect("start fault resolver");
        owner.ready().await.expect("fault resolver ready");
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
        drop(resolver);
        owner.shutdown().await.expect("fault resolver shutdown");
        task.await.expect("fault fixture join");
    }

    let (address, task) = half_frame().await;
    let egress = Arc::new(RecordingEgress::default());
    let (resolver, mut owner) = TaggedResolver::new(
        vec![configured_server(address, DnsUpstreamTransport::Tcp, true)],
        Duration::from_millis(100),
        NonZeroU16::new(1).expect("nonzero admission"),
        egress.clone(),
    )
    .expect("start half-frame resolver");
    owner.ready().await.expect("half-frame resolver ready");
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
    drop(resolver);
    owner
        .shutdown()
        .await
        .expect("half-frame resolver shutdown");
    task.await.expect("half-frame fixture join");
}
