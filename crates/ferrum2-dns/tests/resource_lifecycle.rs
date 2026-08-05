use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum2_config::{DnsServerConfig, DnsTransport, load_client};
use ferrum2_dns::{
    BoxedDnsDatagramIo, BoxedDnsTcpIo, DnsDatagramIo, DnsEgress, DnsEgressResourceKind,
    DnsEgressTaskKind, DnsError, DnsIoFuture, DnsTaskRegistrar, PlanSnapshot, RuntimeStats,
    SystemDnsEgress, TaggedResolver,
};
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::copy_bidirectional_with_sizes;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

struct ControlledUdp {
    address: SocketAddr,
    respond: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Default)]
struct GatedEgress {
    blocked: AtomicBool,
    cancelled: Arc<AtomicBool>,
    cancel: Option<Arc<CancelControl>>,
}

struct CancelProbe {
    cancelled: Arc<AtomicBool>,
    cancel: Option<Arc<CancelControl>>,
}

#[derive(Default)]
struct CancelControl {
    state: Mutex<CancelState>,
    changed: Condvar,
}

#[derive(Default)]
struct CancelState {
    entered: bool,
    released: bool,
}

impl CancelControl {
    fn enter(&self) {
        self.state.lock().expect("cancel gate lock").entered = true;
        self.changed.notify_all();
    }

    fn wait_entered(&self) -> bool {
        let state = self.state.lock().expect("cancel gate lock");
        let (state, _) = self
            .changed
            .wait_timeout_while(state, Duration::from_secs(1), |state| !state.entered)
            .expect("cancel entered wait");
        state.entered
    }

    fn wait_release(&self) {
        let state = self.state.lock().expect("cancel gate lock");
        drop(
            self.changed
                .wait_timeout_while(state, Duration::from_secs(1), |state| !state.released)
                .expect("cancel release wait"),
        );
    }

    fn release(&self) {
        self.state.lock().expect("cancel gate lock").released = true;
        self.changed.notify_all();
    }
}

impl Drop for CancelProbe {
    fn drop(&mut self) {
        if let Some(cancel) = &self.cancel {
            cancel.wait_release();
        }
        self.cancelled.store(true, Ordering::Release);
    }
}

impl DnsEgress for GatedEgress {
    fn connect_tcp(
        &self,
        target: SocketAddr,
        plan: Option<PlanSnapshot>,
        timeout: Duration,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo> {
        SystemDnsEgress.connect_tcp(target, plan, timeout, tasks)
    }

    fn bind_udp(
        &self,
        target: SocketAddr,
        plan: Option<PlanSnapshot>,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo> {
        if self.blocked.load(Ordering::Acquire) {
            let cancelled = Arc::clone(&self.cancelled);
            let cancel = self.cancel.clone();
            Box::pin(async move {
                let _probe = CancelProbe {
                    cancelled,
                    cancel: cancel.clone(),
                };
                if let Some(cancel) = cancel {
                    cancel.enter();
                }
                std::future::pending().await
            })
        } else {
            SystemDnsEgress.bind_udp(target, plan, tasks)
        }
    }
}

#[derive(Default)]
struct ScriptedDetour {
    first_hop: Mutex<Option<SocketAddr>>,
    calls: Mutex<Vec<(SocketAddr, Vec<usize>)>>,
    plan_debug: Mutex<Vec<String>>,
}

impl ScriptedDetour {
    fn new(first_hop: SocketAddr) -> Self {
        Self {
            first_hop: Mutex::new(Some(first_hop)),
            calls: Mutex::default(),
            plan_debug: Mutex::default(),
        }
    }
}

impl DnsEgress for ScriptedDetour {
    fn connect_tcp(
        &self,
        target: SocketAddr,
        plan: Option<PlanSnapshot>,
        timeout: Duration,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo> {
        let Some(plan) = plan else {
            return SystemDnsEgress.connect_tcp(target, None, timeout, tasks);
        };
        self.plan_debug
            .lock()
            .expect("plan debug lock")
            .push(format!("{plan:?}"));
        let first_hop = self
            .first_hop
            .lock()
            .expect("first-hop lock")
            .expect("first-hop address");
        self.calls
            .lock()
            .expect("detour calls lock")
            .push((target, plan.hops().to_vec()));
        Box::pin(async move {
            let session = tokio::time::timeout(timeout, TcpStream::connect(first_hop))
                .await
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
            tasks.spawn(DnsEgressTaskKind::Session, async move {
                let _session = session;
                std::future::pending().await
            });
            let upstream = tokio::time::timeout(timeout, TcpStream::connect(target))
                .await
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
            let (client, mut bridge) = tokio::io::duplex(4_096);
            let queue = tasks.own(DnsEgressResourceKind::Queue);
            let buffer = tasks.own(DnsEgressResourceKind::Buffer);
            tasks.spawn(DnsEgressTaskKind::Bridge, async move {
                let (_queue, _buffer) = (queue, buffer);
                let mut upstream = upstream;
                let _ =
                    copy_bidirectional_with_sizes(&mut bridge, &mut upstream, 4_096, 4_096).await;
            });
            Ok(Box::new(client) as BoxedDnsTcpIo)
        })
    }

    fn bind_udp(
        &self,
        target: SocketAddr,
        plan: Option<PlanSnapshot>,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo> {
        let Some(plan) = plan else {
            return SystemDnsEgress.bind_udp(target, None, tasks);
        };
        self.plan_debug
            .lock()
            .expect("plan debug lock")
            .push(format!("{plan:?}"));
        let first_hop = self
            .first_hop
            .lock()
            .expect("first-hop lock")
            .expect("first-hop address");
        self.calls
            .lock()
            .expect("detour calls lock")
            .push((target, plan.hops().to_vec()));
        Box::pin(async move {
            let session = TcpStream::connect(first_hop).await?;
            tasks.spawn(DnsEgressTaskKind::Session, async move {
                let _session = session;
                std::future::pending().await
            });
            let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
            let (outgoing, mut outbound) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1);
            let (inbound, incoming) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1);
            let outbound_queue = tasks.own(DnsEgressResourceKind::Queue);
            let inbound_queue = tasks.own(DnsEgressResourceKind::Queue);
            let buffer = tasks.own(DnsEgressResourceKind::Buffer);
            tasks.spawn(DnsEgressTaskKind::Bridge, async move {
                let (_outbound_queue, _inbound_queue, _buffer) =
                    (outbound_queue, inbound_queue, buffer);
                let mut receive = [0_u8; 4_096];
                while let Some((packet, destination)) = outbound.recv().await {
                    if socket.send_to(&packet, destination).await.is_err() {
                        break;
                    }
                    let Ok((length, source)) = socket.recv_from(&mut receive).await else {
                        break;
                    };
                    if inbound
                        .send((receive[..length].to_vec(), source))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            Ok(Box::new(ScriptedDatagram {
                outgoing,
                incoming: Mutex::new(incoming),
            }) as BoxedDnsDatagramIo)
        })
    }
}

struct ScriptedDatagram {
    outgoing: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    incoming: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
}

impl DnsDatagramIo for ScriptedDatagram {
    fn poll_recv_from(
        &self,
        context: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<std::io::Result<(usize, SocketAddr)>> {
        let mut incoming = self.incoming.lock().expect("scripted UDP receive lock");
        match incoming.poll_recv(context) {
            Poll::Ready(Some((packet, source))) if packet.len() <= buffer.len() => {
                buffer[..packet.len()].copy_from_slice(&packet);
                Poll::Ready(Ok((packet.len(), source)))
            }
            Poll::Ready(Some(_)) => {
                Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::InvalidData)))
            }
            Poll::Ready(None) => {
                Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_send_to(
        &self,
        _context: &mut Context<'_>,
        buffer: &[u8],
        target: SocketAddr,
    ) -> Poll<std::io::Result<usize>> {
        match self.outgoing.try_send((buffer.to_vec(), target)) {
            Ok(()) => Poll::Ready(Ok(buffer.len())),
            Err(mpsc::error::TrySendError::Full(_)) => Poll::Pending,
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))
            }
        }
    }
}

struct TcpStall {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl TcpStall {
    async fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("stall bind");
        let address = listener.local_addr().expect("stall address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let task_accepted = Arc::clone(&accepted);
        let task = tokio::spawn(async move {
            let mut streams = Vec::new();
            loop {
                let (stream, _) = listener.accept().await.expect("stall accept");
                task_accepted.fetch_add(1, Ordering::AcqRel);
                streams.push(stream);
            }
        });
        Self {
            address,
            accepted,
            task,
        }
    }

    async fn shutdown(self) {
        self.task.abort();
        assert!(
            self.task
                .await
                .expect_err("stall cancellation")
                .is_cancelled()
        );
        assert_tcp_rebind(self.address).await;
    }
}

impl ControlledUdp {
    async fn start() -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind controlled UDP");
        let address = socket.local_addr().expect("controlled UDP address");
        let respond = Arc::new(AtomicBool::new(false));
        let task_respond = Arc::clone(&respond);
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 4_096];
            loop {
                let (length, peer) = socket
                    .recv_from(&mut buffer)
                    .await
                    .expect("receive controlled query");
                if !task_respond.load(Ordering::Acquire) {
                    continue;
                }
                let request = Message::from_vec(&buffer[..length]).expect("Hickory request decode");
                let query = request.queries.first().expect("one query").clone();
                let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
                response.metadata.recursion_available = true;
                response
                    .add_query(query.clone())
                    .add_answer(Record::from_rdata(
                        query.name().clone(),
                        30,
                        RData::A(A(Ipv4Addr::new(192, 0, 2, 99))),
                    ));
                socket
                    .send_to(&response.to_vec().expect("Hickory response encode"), peer)
                    .await
                    .expect("send controlled response");
            }
        });
        Self {
            address,
            respond,
            task,
        }
    }

    async fn shutdown(self) {
        self.task.abort();
        assert!(
            self.task
                .await
                .expect_err("controlled task should cancel")
                .is_cancelled()
        );
    }
}

fn direct_udp(address: SocketAddr) -> DnsServerConfig {
    DnsServerConfig {
        transport: DnsTransport::Udp,
        address,
        server_name: None,
        path: None,
        detour: None,
    }
}

fn direct_tcp(address: SocketAddr) -> DnsServerConfig {
    DnsServerConfig {
        transport: DnsTransport::Tcp,
        address,
        server_name: None,
        path: None,
        detour: None,
    }
}

fn detoured_tcp(address: SocketAddr) -> DnsServerConfig {
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
         max_inflight = 2\n\
         [[dns.inbounds]]\n\
         tag = \"d0\"\n\
         listen = \"127.0.0.1:15353\"\n\
         [[dns.servers]]\n\
         tag = \"s0\"\n\
         transport = \"tcp\"\n\
         address = \"{address}\"\n\
         detour = \"o0\"\n\
         [dns.route]\n\
         final = \"s0\"\n\
         [shadowsocks]\n\
         method = \"2022-blake3-aes-128-gcm\"\n\
         psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n"
    );
    let path = std::env::temp_dir().join(format!(
        "ferrum2-dns-t03-lifecycle-{}-{}.toml",
        std::process::id(),
        address.port()
    ));
    std::fs::write(&path, source).expect("write detour config");
    let server = load_client(&path)
        .expect("load detour config")
        .dns
        .expect("validated DNS")
        .servers
        .into_iter()
        .next()
        .expect("validated detour server");
    std::fs::remove_file(path).expect("remove detour config");
    server
}

fn detoured_server(address: SocketAddr, transport: DnsTransport) -> DnsServerConfig {
    let mut server = detoured_tcp(address);
    server.transport = transport;
    match transport {
        DnsTransport::Dot => server.server_name = Some("resolver.test".into()),
        DnsTransport::Doh => {
            server.server_name = Some("resolver.test".into());
            server.path = Some("/dns-query".into());
        }
        DnsTransport::Udp | DnsTransport::Tcp => {}
    }
    server
}

async fn assert_tcp_rebind(address: SocketAddr) {
    for _ in 0..100 {
        if TcpListener::bind(address).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("TCP endpoint did not rebind: {address}");
}

async fn wait_for_nonzero(resolver: &TaggedResolver) {
    for _ in 0..100 {
        if resolver.stats().queries != 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("query never entered the owned runtime");
}

async fn wait_for_zero(resolver: &TaggedResolver) {
    for _ in 0..250 {
        if resolver.stats() == RuntimeStats::default() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("DNS owners did not return to zero: {:?}", resolver.stats());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saturation_timeout_recovery_shutdown_and_rebind_are_bounded() {
    let upstream = ControlledUdp::start().await;
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![direct_udp(upstream.address)],
        Duration::from_millis(250),
        NonZeroU16::new(1).expect("nonzero admission"),
    )
    .expect("start resolver");
    owner.ready().await.expect("resolver ready");
    let resolver = Arc::new(resolver);
    assert_eq!(resolver.stats(), RuntimeStats::default());
    assert_eq!(
        resolver
            .lookup(
                1,
                Name::from_ascii("invalid.resolver.test.").expect("invalid name"),
                RecordType::A,
            )
            .await,
        Err(DnsError::InvalidServer)
    );

    let slow_resolver = Arc::clone(&resolver);
    let slow = tokio::spawn(async move {
        slow_resolver
            .lookup(
                0,
                Name::from_ascii("slow.resolver.test.").expect("slow name"),
                RecordType::A,
            )
            .await
    });
    wait_for_nonzero(&resolver).await;
    assert_eq!(
        resolver
            .lookup(
                0,
                Name::from_ascii("busy.resolver.test.").expect("busy name"),
                RecordType::A,
            )
            .await,
        Err(DnsError::Busy)
    );
    assert_eq!(slow.await.expect("slow task join"), Err(DnsError::Timeout));
    wait_for_zero(&resolver).await;

    upstream.respond.store(true, Ordering::Release);
    let valid = resolver
        .lookup(
            0,
            Name::from_ascii("valid.resolver.test.").expect("valid name"),
            RecordType::A,
        )
        .await
        .expect("valid query after timeout");
    assert!(
        valid
            .answers()
            .iter()
            .any(|record| { record.data == RData::A(A(Ipv4Addr::new(192, 0, 2, 99))) })
    );
    wait_for_zero(&resolver).await;

    let resolver = Arc::try_unwrap(resolver).ok().expect("one resolver owner");
    drop(resolver);
    assert_eq!(owner.shutdown().await.expect("shutdown").runtime_tasks, 0);

    let egress = Arc::new(GatedEgress::default());
    egress.blocked.store(true, Ordering::Release);
    let (resolver, mut owner) = TaggedResolver::new(
        vec![direct_udp(upstream.address)],
        Duration::from_millis(50),
        NonZeroU16::new(1).expect("nonzero admission"),
        egress.clone(),
    )
    .expect("start gated resolver");
    owner.ready().await.expect("gated resolver ready");
    assert_eq!(
        resolver
            .lookup(
                0,
                Name::from_ascii("gated.resolver.test.").expect("gated name"),
                RecordType::A,
            )
            .await,
        Err(DnsError::Timeout)
    );
    wait_for_zero(&resolver).await;
    egress.blocked.store(false, Ordering::Release);
    assert!(
        resolver
            .lookup(
                0,
                Name::from_ascii("recovered.resolver.test.").expect("recovered name"),
                RecordType::A,
            )
            .await
            .is_ok()
    );
    drop(resolver);
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("gated shutdown")
            .runtime_tasks,
        0
    );
    let address = upstream.address;
    upstream.shutdown().await;
    assert!(UdpSocket::bind(address).await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_cancellation_finishes_owned_query_before_readmission() {
    let upstream = ControlledUdp::start().await;
    upstream.respond.store(true, Ordering::Release);
    let egress = Arc::new(GatedEgress::default());
    egress.blocked.store(true, Ordering::Release);
    let (resolver, mut owner) = TaggedResolver::new(
        vec![direct_udp(upstream.address)],
        Duration::from_secs(5),
        NonZeroU16::new(1).expect("nonzero admission"),
        egress.clone(),
    )
    .expect("start cancellation resolver");
    owner.ready().await.expect("cancellation resolver ready");
    let resolver = Arc::new(resolver);
    let active = Arc::clone(&resolver);
    let query = tokio::spawn(async move {
        active
            .lookup(
                0,
                Name::from_ascii("cancel.resolver.test.").expect("cancel name"),
                RecordType::A,
            )
            .await
    });
    wait_for_nonzero(&resolver).await;
    query.abort();
    assert!(query.await.expect_err("caller cancellation").is_cancelled());

    for _ in 0..250 {
        if egress.cancelled.load(Ordering::Acquire) && resolver.stats() == RuntimeStats::default() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(egress.cancelled.load(Ordering::Acquire));
    assert_eq!(resolver.stats(), RuntimeStats::default());

    egress.blocked.store(false, Ordering::Release);
    assert!(
        resolver
            .lookup(
                0,
                Name::from_ascii("after-cancel.resolver.test.").expect("recovery name"),
                RecordType::A,
            )
            .await
            .is_ok()
    );
    let resolver = Arc::try_unwrap(resolver).ok().expect("one resolver owner");
    drop(resolver);
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("cancel shutdown")
            .runtime_tasks,
        0
    );
    upstream.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_drop_is_nonblocking_and_owner_join_is_retryable() {
    for _ in 0..50 {
        assert_resolver_drop_cycle().await;
    }
}

async fn assert_resolver_drop_cycle() {
    let upstream = ControlledUdp::start().await;
    let cancel = Arc::new(CancelControl::default());
    let egress = Arc::new(GatedEgress {
        blocked: AtomicBool::new(true),
        cancelled: Arc::default(),
        cancel: Some(Arc::clone(&cancel)),
    });
    let (resolver, mut owner) = TaggedResolver::new(
        vec![direct_udp(upstream.address)],
        Duration::from_secs(5),
        NonZeroU16::new(1).expect("nonzero admission"),
        egress.clone(),
    )
    .expect("start drop resolver");
    owner.ready().await.expect("resolver owner ready");
    assert_eq!(Arc::strong_count(&egress), 2);
    let lookup = tokio::spawn(resolver.lookup(
        0,
        Name::from_ascii("drop.resolver.test.").expect("drop name"),
        RecordType::A,
    ));
    let entered = Arc::clone(&cancel);
    assert!(
        tokio::task::spawn_blocking(move || entered.wait_entered())
            .await
            .expect("cancel entered join"),
        "active lookup never installed its cancellation guard"
    );
    let drop_started = std::time::Instant::now();
    drop(resolver);
    assert!(drop_started.elapsed() < Duration::from_millis(25));
    {
        let first = owner.shutdown();
        tokio::pin!(first);
        let first_poll =
            std::future::poll_fn(|context| Poll::Ready(first.as_mut().poll(context))).await;
        assert!(
            first_poll.is_pending(),
            "cleanup gate must hold the first owner await"
        );
    }
    cancel.release();
    let report = tokio::time::timeout(Duration::from_millis(250), owner.shutdown())
        .await
        .expect("bounded retried owner await")
        .expect("retried owner shutdown");
    assert_eq!(report.runtime_tasks, 0);
    assert_eq!(report.stats, RuntimeStats::default());
    assert_eq!(
        lookup.await.expect("drop lookup join"),
        Err(DnsError::Shutdown)
    );
    assert_eq!(Arc::strong_count(&egress), 1);
    let address = upstream.address;
    upstream.shutdown().await;
    assert!(UdpSocket::bind(address).await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_shutdown_cancels_an_active_owned_lookup() {
    let upstream = ControlledUdp::start().await;
    let egress = Arc::new(GatedEgress::default());
    egress.blocked.store(true, Ordering::Release);
    let (resolver, mut owner) = TaggedResolver::new(
        vec![direct_udp(upstream.address)],
        Duration::from_secs(5),
        NonZeroU16::new(1).expect("nonzero admission"),
        egress,
    )
    .expect("start active-shutdown resolver");
    owner.ready().await.expect("active resolver ready");
    let lookup = tokio::spawn(resolver.lookup(
        0,
        Name::from_ascii("shutdown.resolver.test.").expect("shutdown name"),
        RecordType::A,
    ));
    wait_for_nonzero(&resolver).await;
    drop(resolver);
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(250), owner.shutdown())
            .await
            .expect("bounded shutdown")
            .expect("active shutdown")
            .runtime_tasks,
        0
    );
    assert_eq!(lookup.await.expect("lookup join"), Err(DnsError::Shutdown));
    upstream.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_joins_direct_and_detour_stream_session_queue_and_buffer_owners() {
    let direct = TcpStall::start().await;
    let first_hop = TcpStall::start().await;
    let final_upstream = TcpStall::start().await;
    let egress = Arc::new(ScriptedDetour::new(first_hop.address));
    let (resolver, mut owner) = TaggedResolver::new(
        vec![
            direct_tcp(direct.address),
            detoured_tcp(final_upstream.address),
        ],
        Duration::from_secs(5),
        NonZeroU16::new(2).expect("nonzero admission"),
        egress.clone(),
    )
    .expect("start detour owner resolver");
    owner.ready().await.expect("detour resolver ready");
    let direct_lookup = tokio::spawn(resolver.lookup(
        0,
        Name::from_ascii("direct.sentinel.resolver.test.").expect("direct sentinel"),
        RecordType::A,
    ));
    let detour_lookup = tokio::spawn(resolver.lookup(
        1,
        Name::from_ascii("detour.sentinel.resolver.test.").expect("detour sentinel"),
        RecordType::A,
    ));
    for _ in 0..250 {
        let stats = resolver.stats();
        if stats.queries == 2
            && stats.tcp_streams == 2
            && stats.bridge_tasks == 1
            && stats.sessions == 1
            && stats.queues == 1
            && stats.buffers == 1
            && direct.accepted.load(Ordering::Acquire) == 1
            && first_hop.accepted.load(Ordering::Acquire) == 1
            && final_upstream.accepted.load(Ordering::Acquire) == 1
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let stats = resolver.stats();
    assert_eq!(stats.queries, 2);
    assert!(stats.tasks <= 2, "bounded Hickory tasks: {stats:?}");
    assert_eq!(stats.tcp_streams, 2);
    assert_eq!(stats.bridge_tasks, 1);
    assert_eq!(stats.sessions, 1);
    assert_eq!(stats.queues, 1);
    assert_eq!(stats.buffers, 1);
    assert_eq!(
        egress.calls.lock().expect("detour calls lock").as_slice(),
        &[(final_upstream.address, vec![0])]
    );
    assert_eq!(
        egress
            .plan_debug
            .lock()
            .expect("plan debug lock")
            .as_slice(),
        &["PlanSnapshot([redacted])"]
    );

    drop(resolver);
    let report = tokio::time::timeout(Duration::from_millis(250), owner.shutdown())
        .await
        .expect("bounded detour shutdown")
        .expect("detour shutdown");
    assert_eq!(report.runtime_tasks, 0);
    assert_eq!(report.stats, RuntimeStats::default());
    assert_eq!(
        direct_lookup.await.expect("direct lookup join"),
        Err(DnsError::Shutdown)
    );
    assert_eq!(
        detour_lookup.await.expect("detour lookup join"),
        Err(DnsError::Shutdown)
    );
    direct.shutdown().await;
    first_hop.shutdown().await;
    final_upstream.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_bounds_slow_detoured_udp_tcp_dot_and_doh_resources() {
    let first_hop = TcpStall::start().await;
    let tcp_upstream = TcpStall::start().await;
    let udp_upstream = ControlledUdp::start().await;
    let egress = Arc::new(ScriptedDetour::new(first_hop.address));
    let (resolver, mut owner) = TaggedResolver::new(
        vec![
            detoured_server(udp_upstream.address, DnsTransport::Udp),
            detoured_server(tcp_upstream.address, DnsTransport::Tcp),
            detoured_server(tcp_upstream.address, DnsTransport::Dot),
            detoured_server(tcp_upstream.address, DnsTransport::Doh),
        ],
        Duration::from_secs(5),
        NonZeroU16::new(4).expect("nonzero admission"),
        egress.clone(),
    )
    .expect("start all-transport detour resolver");
    owner.ready().await.expect("all-transport resolver ready");
    let lookups: Vec<_> = (0..4)
        .map(|server| {
            tokio::spawn(
                resolver.lookup(
                    server,
                    Name::from_ascii(format!("slow-{server}.resolver.test."))
                        .expect("slow transport name"),
                    RecordType::A,
                ),
            )
        })
        .collect();
    for _ in 0..250 {
        let stats = resolver.stats();
        if stats.queries == 4
            && stats.tcp_streams == 3
            && stats.udp_sockets == 1
            && stats.bridge_tasks == 4
            && stats.sessions == 4
            && stats.queues == 5
            && stats.buffers == 4
            && first_hop.accepted.load(Ordering::Acquire) == 4
            && tcp_upstream.accepted.load(Ordering::Acquire) == 3
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let stats = resolver.stats();
    assert_eq!(stats.queries, 4);
    assert!(stats.tasks <= 8, "bounded transport tasks: {stats:?}");
    assert_eq!(stats.tcp_streams, 3);
    assert_eq!(stats.udp_sockets, 1);
    assert_eq!(stats.bridge_tasks, 4);
    assert_eq!(stats.sessions, 4);
    assert_eq!(stats.queues, 5);
    assert_eq!(stats.buffers, 4);
    let mut calls = egress.calls.lock().expect("transport calls lock").clone();
    calls.sort_by_key(|(target, _)| *target);
    assert_eq!(calls.len(), 4);
    assert!(calls.iter().all(|(_, hops)| hops == &[0]));

    drop(resolver);
    let report = tokio::time::timeout(Duration::from_millis(250), owner.shutdown())
        .await
        .expect("bounded all-transport shutdown")
        .expect("all-transport shutdown");
    assert_eq!(report.runtime_tasks, 0);
    assert_eq!(report.stats, RuntimeStats::default());
    for lookup in lookups {
        assert_eq!(
            lookup.await.expect("transport lookup join"),
            Err(DnsError::Shutdown)
        );
    }
    first_hop.shutdown().await;
    tcp_upstream.shutdown().await;
    let udp_address = udp_upstream.address;
    udp_upstream.shutdown().await;
    assert!(UdpSocket::bind(udp_address).await.is_ok());
}

#[test]
fn closed_errors_debug_and_numeric_stats_have_no_peer_value_output_channel() {
    const SENTINEL: &str = "peer-secret-sentinel.resolver.test";
    let errors = [
        DnsError::Busy,
        DnsError::Timeout,
        DnsError::Transport,
        DnsError::Protocol,
        DnsError::NxDomain,
        DnsError::NoData,
        DnsError::Shutdown,
        DnsError::InvalidServer,
        DnsError::Runtime,
    ];
    for error in errors {
        assert!(!error.to_string().contains(SENTINEL));
        assert!(!format!("{error:?}").contains(SENTINEL));
        assert!(std::error::Error::source(&error).is_none());
    }
    assert!(!format!("{:?}", RuntimeStats::default()).contains(SENTINEL));

    for source in [
        include_str!("../src/error.rs"),
        include_str!("../src/resolver.rs"),
        include_str!("../src/runtime_owner.rs"),
        include_str!("../src/runtime_provider.rs"),
    ] {
        let product = source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .expect("product source");
        for output in [
            "println!(",
            "eprintln!(",
            "panic!(",
            "tracing::",
            "log::",
            "metrics::",
        ] {
            assert!(
                !product.contains(output),
                "unexpected output channel: {output}"
            );
        }
    }
}
