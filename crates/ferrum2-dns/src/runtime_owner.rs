use std::num::NonZeroU16;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread::JoinHandle;
use std::time::Duration;

use ferrum2_config::DnsServerConfig;
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::lookup::Lookup;
use tokio::runtime::Builder;
use tokio::sync::{Semaphore, mpsc, oneshot};
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
}

/// Successful exclusive-runtime shutdown evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ShutdownReport {
    /// Tokio tasks remaining immediately before the exclusive runtime is dropped.
    pub runtime_tasks: usize,
}

enum Command {
    Lookup {
        server: usize,
        name: Name,
        record_type: RecordType,
        deadline: Instant,
        reply: oneshot::Sender<Result<Lookup, DnsError>>,
    },
    Shutdown,
}

/// Bounded tagged resolver whose entire Hickory task population lives on one owned OS thread.
#[must_use = "call shutdown() to await the exclusive DNS runtime"]
pub struct TaggedResolver {
    sender: Option<mpsc::Sender<Command>>,
    admission: Arc<Semaphore>,
    server_count: usize,
    timeout: Duration,
    counters: Arc<RuntimeCounters>,
    thread: Option<JoinHandle<Result<ShutdownReport, DnsError>>>,
}

impl TaggedResolver {
    /// Starts a lazy resolver graph using direct numeric Tokio sockets.
    pub fn direct(
        servers: Vec<DnsServerConfig>,
        timeout: Duration,
        max_inflight: NonZeroU16,
    ) -> Result<Self, DnsError> {
        Self::new(servers, timeout, max_inflight, Arc::new(SystemDnsEgress))
    }

    /// Starts a lazy resolver graph over the supplied direct/detour adapter.
    pub fn new(
        servers: Vec<DnsServerConfig>,
        timeout: Duration,
        max_inflight: NonZeroU16,
        egress: Arc<dyn DnsEgress>,
    ) -> Result<Self, DnsError> {
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
        servers: Vec<(DnsServerConfig, rustls::ClientConfig)>,
        timeout: Duration,
        max_inflight: NonZeroU16,
        egress: Arc<dyn DnsEgress>,
    ) -> Result<Self, DnsError> {
        Self::start(
            servers
                .into_iter()
                .map(|(server, tls)| SelectedServer::from_config(server).with_tls(tls))
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
    ) -> Result<Self, DnsError> {
        if servers.is_empty() {
            return Err(DnsError::InvalidServer);
        }
        let server_count = servers.len();
        let capacity = usize::from(max_inflight.get());
        let admission = Arc::new(Semaphore::new(capacity));
        let counters = Arc::new(RuntimeCounters::default());
        let (sender, receiver) = mpsc::channel(capacity);
        let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
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
                let tasks = TaskSet::default();
                let servers = Arc::new(servers);
                let _ = ready_sender.send(Ok(()));
                runtime.block_on(run_commands(
                    receiver,
                    servers,
                    egress,
                    tasks,
                    thread_counters,
                    handle,
                ))
            })
            .map_err(|_| DnsError::Runtime)?;
        ready_receiver.recv().map_err(|_| DnsError::Runtime)??;

        Ok(Self {
            sender: Some(sender),
            admission,
            server_count,
            timeout,
            counters,
            thread: Some(thread),
        })
    }

    /// Queries one already-selected tagged server under the shared admission and deadline.
    pub async fn lookup(
        &self,
        server: usize,
        name: Name,
        record_type: RecordType,
    ) -> Result<Lookup, DnsError> {
        if server >= self.server_count {
            return Err(DnsError::InvalidServer);
        }
        let deadline = Instant::now() + self.timeout;
        let permit = Arc::clone(&self.admission)
            .try_acquire_owned()
            .map_err(|_| DnsError::Busy)?;
        let (reply, response) = oneshot::channel();
        let command = Command::Lookup {
            server,
            name,
            record_type,
            deadline,
            reply,
        };
        tokio::time::timeout_at(
            deadline,
            self.sender
                .as_ref()
                .ok_or(DnsError::Shutdown)?
                .send(command),
        )
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(|_| DnsError::Shutdown)?;
        let result = tokio::time::timeout_at(deadline, response)
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|_| DnsError::Shutdown)?;
        drop(permit);
        result
    }

    /// Returns stable, low-cardinality owner counts.
    pub fn stats(&self) -> RuntimeStats {
        RuntimeStats {
            queries: self.counters.queries.load(Ordering::Acquire),
            tasks: self.counters.tasks.load(Ordering::Acquire),
            tcp_streams: self.counters.tcp_streams.load(Ordering::Acquire),
            udp_sockets: self.counters.udp_sockets.load(Ordering::Acquire),
        }
    }

    /// Closes intake, aborts and joins every DNS task, and joins the owned OS thread off-worker.
    pub async fn shutdown(mut self) -> Result<ShutdownReport, DnsError> {
        if let Some(sender) = self.sender.take() {
            sender
                .send(Command::Shutdown)
                .await
                .map_err(|_| DnsError::Shutdown)?;
        }
        let thread = self.thread.take().ok_or(DnsError::Shutdown)?;
        tokio::task::spawn_blocking(move || thread.join())
            .await
            .map_err(|_| DnsError::Runtime)?
            .map_err(|_| DnsError::Runtime)?
    }
}

impl Drop for TaggedResolver {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.try_send(Command::Shutdown);
        }
    }
}

async fn run_commands(
    mut receiver: mpsc::Receiver<Command>,
    servers: Arc<Vec<SelectedServer>>,
    egress: Arc<dyn DnsEgress>,
    tasks: TaskSet,
    counters: Arc<RuntimeCounters>,
    runtime_handle: tokio::runtime::Handle,
) -> Result<ShutdownReport, DnsError> {
    let mut queries = JoinSet::new();
    loop {
        tokio::select! {
            completed = queries.join_next(), if !queries.is_empty() => {
                let _ = completed;
            }
            command = receiver.recv() => match command {
                Some(Command::Lookup { server, name, record_type, deadline, reply }) => {
                    let plan = servers[server].plan_snapshot();
                    let servers = Arc::clone(&servers);
                    let egress = Arc::clone(&egress);
                    let tasks = tasks.clone();
                    let counters = Arc::clone(&counters);
                    queries.spawn(async move {
                        let _guard = QueryGuard::new(Arc::clone(&counters));
                        let provider = FerrumRuntimeProvider::new(
                            egress, plan, deadline, tasks, counters,
                        );
                        let result = resolver::lookup(
                            &servers[server],
                            name,
                            record_type,
                            deadline,
                            provider,
                        )
                        .await;
                        let _ = reply.send(result);
                    });
                }
                Some(Command::Shutdown) | None => break,
            }
        }
    }

    receiver.close();
    while let Ok(command) = receiver.try_recv() {
        if let Command::Lookup { reply, .. } = command {
            let _ = reply.send(Err(DnsError::Shutdown));
        }
    }
    queries.abort_all();
    while queries.join_next().await.is_some() {}
    tasks.abort_and_join().await;

    for _ in 0..256 {
        if runtime_handle.metrics().num_alive_tasks() == 0 {
            return Ok(ShutdownReport { runtime_tasks: 0 });
        }
        tokio::task::yield_now().await;
    }
    Err(DnsError::Runtime)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, SocketAddr};

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
    use tokio::net::TcpListener;
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dot_doh_validate_full_zone_and_tls_policy() {
        let fixture = EncryptedFixture::start().await;
        let valid = client_tls(VALID_TIME, true);
        let servers = vec![
            (
                encrypted_server(DnsTransport::Dot, fixture.dot, "resolver.test", None),
                valid.clone(),
            ),
            (
                encrypted_server(
                    DnsTransport::Doh,
                    fixture.doh,
                    "resolver.test",
                    Some("/dns-query"),
                ),
                valid.clone(),
            ),
            (
                encrypted_server(DnsTransport::Dot, fixture.dot, "wrong.test", None),
                valid.clone(),
            ),
            (
                encrypted_server(DnsTransport::Dot, fixture.dot, "resolver.test", None),
                client_tls(VALID_TIME, false),
            ),
            (
                encrypted_server(DnsTransport::Dot, fixture.dot, "resolver.test", None),
                client_tls(1_785_915_311, true),
            ),
            (
                encrypted_server(DnsTransport::Dot, fixture.dot, "resolver.test", None),
                client_tls(2_101_275_313, true),
            ),
            (
                encrypted_server(
                    DnsTransport::Doh,
                    fixture.doh,
                    "resolver.test",
                    Some("/wrong"),
                ),
                valid,
            ),
        ];
        let resolver = TaggedResolver::with_test_tls(
            servers,
            Duration::from_secs(1),
            NonZeroU16::new(8).expect("nonzero admission"),
            Arc::new(SystemDnsEgress),
        )
        .expect("start encrypted resolver");
        assert_full_zone(&resolver, 0).await;
        assert_full_zone(&resolver, 1).await;
        for server in 2..7 {
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
        }
        assert_eq!(
            resolver
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
            let resolver = TaggedResolver::with_test_tls(
                vec![(
                    encrypted_server(
                        DnsTransport::Doh,
                        address,
                        "resolver.test",
                        Some("/dns-query"),
                    ),
                    client_tls(VALID_TIME, true),
                )],
                Duration::from_secs(1),
                NonZeroU16::new(1).expect("nonzero admission"),
                Arc::new(SystemDnsEgress),
            )
            .expect("start DoH fault resolver");
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
            assert_eq!(
                resolver
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
}
