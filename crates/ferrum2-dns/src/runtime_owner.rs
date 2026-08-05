use std::num::NonZeroU16;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::thread::JoinHandle as ThreadJoinHandle;
use std::time::Duration;

use ferrum2_config::DnsServerConfig;
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::lookup::Lookup;
use tokio::runtime::Builder;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::error::DnsError;
use crate::resolver::{self, SelectedServer};
use crate::runtime_provider::{
    DnsEgress, FerrumRuntimeProvider, QueryGuard, RuntimeCounters, SystemDnsEgress, TaskSet,
};

/// Current bounded DNS owner counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeStats {
    /// Logical queries admitted and not yet terminal.
    pub queries: usize,
    /// Hickory background tasks registered through its runtime handle.
    pub tasks: usize,
    /// Selected upstream TCP streams currently owned.
    pub tcp_streams: usize,
    /// Selected upstream UDP sockets currently owned.
    pub udp_sockets: usize,
    /// Detour I/O bridges currently owned by admitted queries.
    pub bridge_tasks: usize,
    /// Concrete detour sessions currently owned by admitted queries.
    pub sessions: usize,
    /// Bounded detour queues currently registered to admitted queries.
    pub queues: usize,
    /// Fixed-capacity detour buffers currently registered to admitted queries.
    pub buffers: usize,
}

/// Successful exclusive-runtime shutdown evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ShutdownReport {
    /// Tokio tasks remaining immediately before the exclusive runtime is dropped.
    pub runtime_tasks: usize,
    /// All ferrum-owned DNS resources after cancellation and joining.
    pub stats: RuntimeStats,
}

enum Command {
    Lookup {
        server: usize,
        name: Name,
        record_type: RecordType,
        deadline: Instant,
        reply: oneshot::Sender<Result<Lookup, DnsError>>,
        permit: OwnedSemaphorePermit,
    },
}

struct ShutdownSignal(Mutex<Option<oneshot::Sender<()>>>);

impl ShutdownSignal {
    fn request(&self) {
        if let Some(shutdown) = self.0.lock().expect("DNS shutdown lock poisoned").take() {
            let _ = shutdown.send(());
        }
    }
}

/// Bounded tagged resolver handle backed by one separately awaited runtime owner.
pub struct TaggedResolver {
    sender: Option<mpsc::Sender<Command>>,
    shutdown: Arc<ShutdownSignal>,
    admission: Arc<Semaphore>,
    server_count: usize,
    timeout: Duration,
    counters: Arc<RuntimeCounters>,
}

/// Unique join owner for one tagged resolver's exclusive runtime thread.
#[must_use = "await shutdown() after dropping the TaggedResolver handle"]
pub struct TaggedResolverOwner {
    shutdown: Arc<ShutdownSignal>,
    ready: Option<oneshot::Receiver<Result<(), DnsError>>>,
    ready_result: Option<Result<(), DnsError>>,
    thread: Option<ThreadJoinHandle<Result<ShutdownReport, DnsError>>>,
    join: Option<tokio::task::JoinHandle<Result<ShutdownReport, DnsError>>>,
    report: Option<Result<ShutdownReport, DnsError>>,
}

impl TaggedResolver {
    /// Starts a lazy resolver graph using direct numeric Tokio sockets.
    pub fn direct(
        servers: Vec<DnsServerConfig>,
        timeout: Duration,
        max_inflight: NonZeroU16,
    ) -> Result<(Self, TaggedResolverOwner), DnsError> {
        Self::new(servers, timeout, max_inflight, Arc::new(SystemDnsEgress))
    }

    /// Starts a lazy resolver graph over the supplied direct/detour adapter.
    pub fn new(
        servers: Vec<DnsServerConfig>,
        timeout: Duration,
        max_inflight: NonZeroU16,
        egress: Arc<dyn DnsEgress>,
    ) -> Result<(Self, TaggedResolverOwner), DnsError> {
        Self::start(
            servers
                .into_iter()
                .map(SelectedServer::from_config)
                .collect(),
            timeout,
            max_inflight,
            egress,
        )
    }

    #[cfg(test)]
    pub(crate) fn with_test_tls(
        servers: Vec<(
            DnsServerConfig,
            rustls::ClientConfig,
            Option<crate::runtime_provider::PlanSnapshot>,
        )>,
        timeout: Duration,
        max_inflight: NonZeroU16,
        egress: Arc<dyn DnsEgress>,
    ) -> Result<(Self, TaggedResolverOwner), DnsError> {
        Self::start(
            servers
                .into_iter()
                .map(|(server, tls, plan)| {
                    SelectedServer::from_config(server)
                        .with_tls(tls)
                        .with_plan(plan)
                })
                .collect(),
            timeout,
            max_inflight,
            egress,
        )
    }

    fn start(
        servers: Vec<SelectedServer>,
        timeout: Duration,
        max_inflight: NonZeroU16,
        egress: Arc<dyn DnsEgress>,
    ) -> Result<(Self, TaggedResolverOwner), DnsError> {
        if servers.is_empty() {
            return Err(DnsError::InvalidServer);
        }
        let server_count = servers.len();
        let capacity = usize::from(max_inflight.get());
        let admission = Arc::new(Semaphore::new(capacity));
        let counters = Arc::new(RuntimeCounters::default());
        let (sender, receiver) = mpsc::channel(capacity);
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let shutdown = Arc::new(ShutdownSignal(Mutex::new(Some(shutdown_sender))));
        let (ready_sender, ready_receiver) = oneshot::channel();
        let thread_counters = Arc::clone(&counters);
        let thread = std::thread::Builder::new()
            .name("ferrum2-dns".to_owned())
            .spawn(move || {
                let runtime = match Builder::new_current_thread().enable_all().build() {
                    Ok(runtime) => runtime,
                    Err(_) => {
                        let _ = ready_sender.send(Err(DnsError::Runtime));
                        return Err(DnsError::Runtime);
                    }
                };
                let handle = runtime.handle().clone();
                let servers = Arc::new(servers);
                let _ = ready_sender.send(Ok(()));
                runtime.block_on(run_commands(
                    receiver,
                    shutdown_receiver,
                    servers,
                    egress,
                    thread_counters,
                    handle,
                ))
            })
            .map_err(|_| DnsError::Runtime)?;
        Ok((
            Self {
                sender: Some(sender),
                shutdown: Arc::clone(&shutdown),
                admission,
                server_count,
                timeout,
                counters,
            },
            TaggedResolverOwner {
                shutdown,
                ready: Some(ready_receiver),
                ready_result: None,
                thread: Some(thread),
                join: None,
                report: None,
            },
        ))
    }

    /// Queries one already-selected tagged server under the shared admission and deadline.
    pub fn lookup(
        &self,
        server: usize,
        name: Name,
        record_type: RecordType,
    ) -> impl std::future::Future<Output = Result<Lookup, DnsError>> + Send + 'static {
        let server_count = self.server_count;
        let timeout = self.timeout;
        let admission = Arc::clone(&self.admission);
        let sender = self.sender.clone();
        async move {
            if server >= server_count {
                return Err(DnsError::InvalidServer);
            }
            let deadline = Instant::now() + timeout;
            let permit = admission.try_acquire_owned().map_err(|_| DnsError::Busy)?;
            let (reply, response) = oneshot::channel();
            let command = Command::Lookup {
                server,
                name,
                record_type,
                deadline,
                reply,
                permit,
            };
            tokio::time::timeout_at(deadline, sender.ok_or(DnsError::Shutdown)?.send(command))
                .await
                .map_err(|_| DnsError::Timeout)?
                .map_err(|_| DnsError::Shutdown)?;
            tokio::time::timeout_at(deadline, response)
                .await
                .map_err(|_| DnsError::Timeout)?
                .map_err(|_| DnsError::Shutdown)?
        }
    }

    /// Returns stable, low-cardinality owner counts.
    pub fn stats(&self) -> RuntimeStats {
        runtime_stats(&self.counters)
    }

    fn request_shutdown(&mut self) {
        self.sender.take();
        self.shutdown.request();
    }
}

impl Drop for TaggedResolver {
    fn drop(&mut self) {
        self.request_shutdown();
    }
}

impl TaggedResolverOwner {
    /// Awaits exclusive-runtime initialization without blocking the calling Tokio worker.
    pub async fn ready(&mut self) -> Result<(), DnsError> {
        if let Some(result) = self.ready_result {
            return result;
        }
        let result = match self.ready.as_mut() {
            Some(ready) => ready.await.map_err(|_| DnsError::Runtime)?,
            None => Err(DnsError::Runtime),
        };
        self.ready.take();
        self.ready_result = Some(result);
        result
    }

    /// Signals shutdown and retryably awaits the unique OS-thread join off-worker.
    pub async fn shutdown(&mut self) -> Result<ShutdownReport, DnsError> {
        if let Some(result) = self.report {
            return result;
        }
        self.shutdown.request();
        if self.join.is_none() {
            let thread = self.thread.take().ok_or(DnsError::Shutdown)?;
            self.join = Some(tokio::task::spawn_blocking(move || {
                thread
                    .join()
                    .map_err(|_| DnsError::Runtime)
                    .and_then(|result| result)
            }));
        }
        let result = self
            .join
            .as_mut()
            .expect("DNS join owner present")
            .await
            .map_err(|_| DnsError::Runtime)?;
        self.join.take();
        self.report = Some(result);
        result
    }
}

impl Drop for TaggedResolverOwner {
    fn drop(&mut self) {
        self.shutdown.request();
    }
}

async fn run_commands(
    mut receiver: mpsc::Receiver<Command>,
    mut shutdown: oneshot::Receiver<()>,
    servers: Arc<Vec<SelectedServer>>,
    egress: Arc<dyn DnsEgress>,
    counters: Arc<RuntimeCounters>,
    runtime_handle: tokio::runtime::Handle,
) -> Result<ShutdownReport, DnsError> {
    let mut queries = JoinSet::new();
    let (cancel, cancel_rx) = watch::channel(false);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            completed = queries.join_next(), if !queries.is_empty() => {
                let _ = completed;
            }
            command = receiver.recv() => match command {
                Some(Command::Lookup { server, name, record_type, deadline, mut reply, permit }) => {
                    let plan = servers[server].plan_snapshot();
                    let servers = Arc::clone(&servers);
                    let egress = Arc::clone(&egress);
                    let counters = Arc::clone(&counters);
                    let tasks = TaskSet::default();
                    let query_tasks = tasks.clone();
                    let mut cancelled = cancel_rx.clone();
                    queries.spawn(async move {
                        let _permit = permit;
                        let _guard = QueryGuard::new(Arc::clone(&counters));
                        let provider = FerrumRuntimeProvider::new(
                            egress, plan, deadline, tasks, counters,
                        );
                        let result = tokio::select! {
                            _ = cancelled.changed() => Err(DnsError::Shutdown),
                            _ = reply.closed() => Err(DnsError::Shutdown),
                            result = resolver::lookup(
                                &servers[server],
                                name,
                                record_type,
                                deadline,
                                provider,
                            ) => result,
                        };
                        query_tasks.abort_and_join().await;
                        if !reply.is_closed() {
                            let _ = reply.send(result);
                        }
                    });
                }
                None => break,
            }
        }
    }

    receiver.close();
    let _ = cancel.send(true);
    while let Ok(command) = receiver.try_recv() {
        let Command::Lookup { reply, .. } = command;
        let _ = reply.send(Err(DnsError::Shutdown));
    }
    while queries.join_next().await.is_some() {}

    for _ in 0..256 {
        let stats = runtime_stats(&counters);
        if runtime_handle.metrics().num_alive_tasks() == 0 && stats == RuntimeStats::default() {
            return Ok(ShutdownReport {
                runtime_tasks: 0,
                stats,
            });
        }
        tokio::task::yield_now().await;
    }
    Err(DnsError::Runtime)
}

fn runtime_stats(counters: &RuntimeCounters) -> RuntimeStats {
    RuntimeStats {
        queries: counters.queries.load(Ordering::Acquire),
        tasks: counters.tasks.load(Ordering::Acquire),
        tcp_streams: counters.tcp_streams.load(Ordering::Acquire),
        udp_sockets: counters.udp_sockets.load(Ordering::Acquire),
        bridge_tasks: counters.bridge_tasks.load(Ordering::Acquire),
        sessions: counters.sessions.load(Ordering::Acquire),
        queues: counters.queues.load(Ordering::Acquire),
        buffers: counters.buffers.load(Ordering::Acquire),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    use ferrum2_config::DnsTransport;
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, NS, SOA};
    use hickory_proto::rr::{LowerName, RData, Record};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    use hickory_server::Server;
    use hickory_server::store::in_memory::InMemoryZoneHandler;
    use hickory_server::zone_handler::{AxfrPolicy, Catalog, ZoneType};
    use rustls::client::ClientConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
    use rustls::time_provider::TimeProvider;
    use rustls::{RootCertStore, ServerConfig};
    use tokio::io::copy_bidirectional_with_sizes;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;

    const CERT: &[u8] = include_bytes!("../tests/fixtures/m12-resolver-test.der");
    const KEY: &[u8] = include_bytes!("../tests/fixtures/m12-resolver-test.pk8");
    const ROOT: &[u8] = include_bytes!("../tests/fixtures/m12-test-ca.der");
    const VALID_TIME: u64 = 1_785_974_400;

    #[derive(Debug)]
    struct FixedTime(u64);

    impl TimeProvider for FixedTime {
        fn current_time(&self) -> Option<UnixTime> {
            Some(UnixTime::since_unix_epoch(Duration::from_secs(self.0)))
        }
    }

    struct EncryptedFixture {
        dot: SocketAddr,
        doh: SocketAddr,
        task: tokio::task::JoinHandle<()>,
    }

    impl EncryptedFixture {
        async fn start() -> Self {
            let dot = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind DoT fixture");
            let doh = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind DoH fixture");
            let dot_address = dot.local_addr().expect("DoT address");
            let doh_address = doh.local_addr().expect("DoH address");
            let origin = Name::from_ascii("resolver.test.").expect("zone origin");
            let mut zone = InMemoryZoneHandler::<TokioRuntimeProvider>::empty(
                origin.clone(),
                ZoneType::Primary,
                AxfrPolicy::Deny,
            );
            let ns = Name::from_ascii("ns.resolver.test.").expect("NS name");
            for record in [
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
                Record::from_rdata(origin.clone(), 60, RData::NS(NS(ns))),
                Record::from_rdata(
                    Name::from_ascii("answer.resolver.test.").expect("A name"),
                    60,
                    RData::A(A(Ipv4Addr::new(192, 0, 2, 43))),
                ),
                Record::from_rdata(
                    Name::from_ascii("v6.resolver.test.").expect("AAAA name"),
                    60,
                    RData::AAAA(AAAA("2001:db8::43".parse().expect("AAAA value"))),
                ),
                Record::from_rdata(
                    Name::from_ascii("alias.resolver.test.").expect("CNAME owner"),
                    60,
                    RData::CNAME(CNAME(
                        Name::from_ascii("answer.resolver.test.").expect("CNAME target"),
                    )),
                ),
            ] {
                zone.upsert_mut(record, 1);
            }
            let mut catalog = Catalog::new();
            catalog.upsert(LowerName::new(&origin), vec![Arc::new(zone)]);
            let mut server = Server::new(catalog);
            server
                .register_tls_listener_with_tls_config(
                    dot,
                    Duration::from_secs(2),
                    Arc::new(server_tls(b"dot")),
                )
                .expect("register DoT fixture");
            server
                .register_https_listener_with_tls_config(
                    doh,
                    Duration::from_secs(2),
                    Arc::new(server_tls(b"h2")),
                    Some("resolver.test".to_owned()),
                    "/dns-query".to_owned(),
                )
                .expect("register DoH fixture");
            let task = tokio::spawn(async move {
                server.block_until_done().await.expect("encrypted fixture");
            });
            Self {
                dot: dot_address,
                doh: doh_address,
                task,
            }
        }

        async fn shutdown(self) {
            self.task.abort();
            assert!(
                self.task
                    .await
                    .expect_err("fixture cancellation")
                    .is_cancelled()
            );
        }
    }

    fn server_tls(alpn: &[u8]) -> ServerConfig {
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("server protocol versions")
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(CERT.to_vec())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec())),
                )
                .expect("server certificate");
        config.alpn_protocols = vec![alpn.to_vec()];
        config
    }

    fn client_tls(time: u64, trusted: bool) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        if trusted {
            roots
                .add(CertificateDer::from(ROOT.to_vec()))
                .expect("test root");
        }
        ClientConfig::builder_with_details(
            Arc::new(rustls::crypto::ring::default_provider()),
            Arc::new(FixedTime(time)),
        )
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
    }

    fn encrypted_server(
        transport: DnsTransport,
        address: SocketAddr,
        name: &str,
        path: Option<&str>,
    ) -> DnsServerConfig {
        DnsServerConfig {
            transport,
            address,
            server_name: Some(name.into()),
            path: path.map(Into::into),
            detour: None,
        }
    }

    async fn assert_full_zone(resolver: &TaggedResolver, server: usize) {
        for (name, record_type, expected) in [
            ("answer.resolver.test.", RecordType::A, "192.0.2.43"),
            ("v6.resolver.test.", RecordType::AAAA, "2001:db8::43"),
            (
                "alias.resolver.test.",
                RecordType::A,
                "answer.resolver.test.",
            ),
        ] {
            let lookup = resolver
                .lookup(
                    server,
                    Name::from_ascii(name).expect("query name"),
                    record_type,
                )
                .await
                .expect("encrypted lookup");
            assert!(
                lookup
                    .answers()
                    .iter()
                    .any(|answer| format!("{}", answer.data) == expected),
                "missing {expected} in {lookup:?}"
            );
        }
        assert_eq!(
            resolver
                .lookup(
                    server,
                    Name::from_ascii("missing.resolver.test.").expect("NX name"),
                    RecordType::A,
                )
                .await,
            Err(DnsError::NxDomain)
        );
        assert_eq!(
            resolver
                .lookup(
                    server,
                    Name::from_ascii("answer.resolver.test.").expect("NODATA name"),
                    RecordType::AAAA,
                )
                .await,
            Err(DnsError::NoData)
        );
    }

    async fn assert_tcp_rebind(address: SocketAddr) {
        for _ in 0..100 {
            if TcpListener::bind(address).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("encrypted fixture endpoint did not rebind: {address}");
    }

    #[derive(Clone, Copy)]
    enum DohFault {
        Status,
        ContentType,
        Body,
    }

    async fn doh_fault(fault: DohFault) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("DoH fault bind");
        let address = listener.local_addr().expect("DoH fault address");
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("DoH fault accept");
            let tls = TlsAcceptor::from(Arc::new(server_tls(b"h2")))
                .accept(stream)
                .await
                .expect("DoH fault TLS");
            let mut h2 = h2::server::handshake(tls).await.expect("DoH fault H2");
            let (_, mut respond) = h2
                .accept()
                .await
                .expect("DoH request")
                .expect("valid DoH request");
            let has_body = matches!(fault, DohFault::Body);
            let mut response = hickory_resolver::net::http::response(
                hickory_resolver::net::http::Version::Http2,
                usize::from(has_body) * 3,
            )
            .expect("DoH fault response");
            match fault {
                DohFault::Status => *response.status_mut() = "503".parse().expect("status"),
                DohFault::ContentType => {
                    response
                        .headers_mut()
                        .insert("content-type", "text/plain".parse().expect("content type"));
                }
                DohFault::Body => {
                    response.headers_mut().insert(
                        "content-type",
                        "application/dns-message".parse().expect("DNS content type"),
                    );
                }
            }
            let mut body = respond
                .send_response(response, !has_body)
                .expect("send DoH fault headers");
            if has_body {
                body.send_data(vec![0_u8, 1, 2].into(), true)
                    .expect("send malformed DNS body");
            }
        });
        (address, task)
    }

    #[derive(Default)]
    struct ScriptedTlsDetour {
        attempts: AtomicUsize,
        require_plan: bool,
    }

    impl DnsEgress for ScriptedTlsDetour {
        fn connect_tcp(
            &self,
            target: SocketAddr,
            plan: Option<crate::runtime_provider::PlanSnapshot>,
            timeout: Duration,
            tasks: crate::runtime_provider::DnsTaskRegistrar,
        ) -> crate::runtime_provider::DnsIoFuture<crate::runtime_provider::BoxedDnsTcpIo> {
            if self.require_plan {
                assert_eq!(plan.expect("detour plan").hops(), &[0]);
            } else {
                assert!(plan.is_none(), "unexpected direct plan");
            }
            self.attempts.fetch_add(1, Ordering::AcqRel);
            Box::pin(async move {
                let upstream = tokio::time::timeout(timeout, TcpStream::connect(target))
                    .await
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
                tasks.spawn(
                    crate::runtime_provider::DnsEgressTaskKind::Session,
                    std::future::pending(),
                );
                let queue = tasks.own(crate::runtime_provider::DnsEgressResourceKind::Queue);
                let buffer = tasks.own(crate::runtime_provider::DnsEgressResourceKind::Buffer);
                let (client, mut bridge) = tokio::io::duplex(4_096);
                tasks.spawn(
                    crate::runtime_provider::DnsEgressTaskKind::Bridge,
                    async move {
                        let (_queue, _buffer) = (queue, buffer);
                        let mut upstream = upstream;
                        let _ =
                            copy_bidirectional_with_sizes(&mut bridge, &mut upstream, 4_096, 4_096)
                                .await;
                    },
                );
                Ok(Box::new(client) as crate::runtime_provider::BoxedDnsTcpIo)
            })
        }

        fn bind_udp(
            &self,
            _target: SocketAddr,
            _plan: Option<crate::runtime_provider::PlanSnapshot>,
            _tasks: crate::runtime_provider::DnsTaskRegistrar,
        ) -> crate::runtime_provider::DnsIoFuture<crate::runtime_provider::BoxedDnsDatagramIo>
        {
            Box::pin(async { Err(std::io::Error::from(std::io::ErrorKind::Unsupported)) })
        }
    }

    async fn stalled_doh() -> (SocketAddr, Arc<AtomicBool>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("stalled DoH bind");
        let address = listener.local_addr().expect("stalled DoH address");
        let active = Arc::new(AtomicBool::new(false));
        let task_active = Arc::clone(&active);
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("stalled DoH accept");
            let tls = TlsAcceptor::from(Arc::new(server_tls(b"h2")))
                .accept(stream)
                .await
                .expect("stalled DoH TLS");
            let mut h2 = h2::server::handshake(tls).await.expect("stalled DoH H2");
            let _request = h2
                .accept()
                .await
                .expect("stalled DoH request")
                .expect("valid stalled DoH request");
            task_active.store(true, Ordering::Release);
            std::future::pending::<()>().await;
        });
        (address, active, task)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dot_doh_validate_full_zone_and_tls_policy() {
        let fixture = EncryptedFixture::start().await;
        let valid = client_tls(VALID_TIME, true);
        let servers = vec![
            (
                encrypted_server(DnsTransport::Dot, fixture.dot, "resolver.test", None),
                valid.clone(),
                None,
            ),
            (
                encrypted_server(
                    DnsTransport::Doh,
                    fixture.doh,
                    "resolver.test",
                    Some("/dns-query"),
                ),
                valid.clone(),
                None,
            ),
            (
                encrypted_server(DnsTransport::Dot, fixture.dot, "wrong.test", None),
                valid.clone(),
                None,
            ),
            (
                encrypted_server(DnsTransport::Dot, fixture.dot, "resolver.test", None),
                client_tls(VALID_TIME, false),
                None,
            ),
            (
                encrypted_server(DnsTransport::Dot, fixture.dot, "resolver.test", None),
                client_tls(1_785_915_311, true),
                None,
            ),
            (
                encrypted_server(DnsTransport::Dot, fixture.dot, "resolver.test", None),
                client_tls(2_101_275_313, true),
                None,
            ),
            (
                encrypted_server(
                    DnsTransport::Doh,
                    fixture.doh,
                    "resolver.test",
                    Some("/wrong"),
                ),
                valid,
                None,
            ),
        ];
        let egress = Arc::new(ScriptedTlsDetour::default());
        let (resolver, mut owner) = TaggedResolver::with_test_tls(
            servers,
            Duration::from_secs(1),
            NonZeroU16::new(8).expect("nonzero admission"),
            egress.clone(),
        )
        .expect("start encrypted resolver");
        owner.ready().await.expect("encrypted resolver ready");
        assert_full_zone(&resolver, 0).await;
        assert_full_zone(&resolver, 1).await;
        for server in 2..7 {
            let before = egress.attempts.load(Ordering::Acquire);
            assert!(
                resolver
                    .lookup(
                        server,
                        Name::from_ascii("answer.resolver.test.").expect("negative name"),
                        RecordType::A,
                    )
                    .await
                    .is_err(),
                "encrypted negative server {server} unexpectedly succeeded"
            );
            assert_eq!(egress.attempts.load(Ordering::Acquire), before + 1);
        }
        drop(resolver);
        assert_eq!(
            owner
                .shutdown()
                .await
                .expect("resolver shutdown")
                .runtime_tasks,
            0
        );
        let dot = fixture.dot;
        let doh = fixture.doh;
        fixture.shutdown().await;
        assert_tcp_rebind(dot).await;
        assert_tcp_rebind(doh).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn doh_rejects_status_content_type_and_malformed_body() {
        for fault in [DohFault::Status, DohFault::ContentType, DohFault::Body] {
            let (address, task) = doh_fault(fault).await;
            let egress = Arc::new(ScriptedTlsDetour::default());
            let (resolver, mut owner) = TaggedResolver::with_test_tls(
                vec![(
                    encrypted_server(
                        DnsTransport::Doh,
                        address,
                        "resolver.test",
                        Some("/dns-query"),
                    ),
                    client_tls(VALID_TIME, true),
                    None,
                )],
                Duration::from_secs(1),
                NonZeroU16::new(1).expect("nonzero admission"),
                egress.clone(),
            )
            .expect("start DoH fault resolver");
            owner.ready().await.expect("DoH fault resolver ready");
            assert!(
                resolver
                    .lookup(
                        0,
                        Name::from_ascii("answer.resolver.test.").expect("DoH fault name"),
                        RecordType::A,
                    )
                    .await
                    .is_err()
            );
            assert_eq!(egress.attempts.load(Ordering::Acquire), 1);
            drop(resolver);
            assert_eq!(
                owner
                    .shutdown()
                    .await
                    .expect("DoH fault shutdown")
                    .runtime_tasks,
                0
            );
            task.await.expect("DoH fault join");
            assert_tcp_rebind(address).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_joins_stalled_detoured_doh_h2_and_bridge_owners() {
        let (address, active, fixture) = stalled_doh().await;
        let egress = Arc::new(ScriptedTlsDetour {
            require_plan: true,
            ..ScriptedTlsDetour::default()
        });
        let (resolver, mut owner) = TaggedResolver::with_test_tls(
            vec![(
                encrypted_server(
                    DnsTransport::Doh,
                    address,
                    "resolver.test",
                    Some("/dns-query"),
                ),
                client_tls(VALID_TIME, true),
                Some(crate::runtime_provider::PlanSnapshot::new(&[0])),
            )],
            Duration::from_secs(5),
            NonZeroU16::new(1).expect("nonzero admission"),
            egress.clone(),
        )
        .expect("start stalled DoH resolver");
        owner.ready().await.expect("stalled DoH resolver ready");
        let lookup = tokio::spawn(resolver.lookup(
            0,
            Name::from_ascii("stalled.resolver.test.").expect("stalled DoH name"),
            RecordType::A,
        ));
        for _ in 0..250 {
            let stats = resolver.stats();
            if active.load(Ordering::Acquire)
                && stats.queries == 1
                && stats.tasks != 0
                && stats.tcp_streams == 1
                && stats.bridge_tasks == 1
                && stats.sessions == 1
                && stats.queues == 1
                && stats.buffers == 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let stats = resolver.stats();
        assert!(active.load(Ordering::Acquire), "H2 request not active");
        assert_eq!(stats.queries, 1);
        assert!(stats.tasks <= 2, "bounded Hickory H2 tasks: {stats:?}");
        assert_eq!(stats.tcp_streams, 1);
        assert_eq!(stats.bridge_tasks, 1);
        assert_eq!(stats.sessions, 1);
        assert_eq!(stats.queues, 1);
        assert_eq!(stats.buffers, 1);
        assert_eq!(egress.attempts.load(Ordering::Acquire), 1);

        drop(resolver);
        let report = tokio::time::timeout(Duration::from_millis(250), owner.shutdown())
            .await
            .expect("bounded stalled DoH shutdown")
            .expect("stalled DoH shutdown");
        assert_eq!(report.runtime_tasks, 0);
        assert_eq!(report.stats, RuntimeStats::default());
        assert_eq!(
            lookup.await.expect("stalled lookup join"),
            Err(DnsError::Shutdown)
        );
        fixture.abort();
        assert!(
            fixture
                .await
                .expect_err("stalled fixture cancellation")
                .is_cancelled()
        );
        assert_tcp_rebind(address).await;
    }
}
