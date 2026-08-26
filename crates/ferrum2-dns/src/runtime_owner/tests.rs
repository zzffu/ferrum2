use super::*;

use std::sync::atomic::Ordering;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize};

use ferrum2_core::TargetAddr;
use ferrum2_core::route::{EgressPlanHandle, EgressPlanSnapshot};
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

use crate::resolver::DnsUpstreamTransport;

const CERT: &[u8] = include_bytes!("../../../../tests/fixtures/dns-tls/m12-resolver-test.der");
const KEY: &[u8] = include_bytes!("../../../../tests/fixtures/dns-tls/m12-resolver-test.pk8");
const ROOT: &[u8] = include_bytes!("../../../../tests/fixtures/dns-tls/m12-test-ca.der");
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

fn encrypted_server(address: SocketAddr, name: &str, path: Option<&str>) -> DnsUpstreamSpec {
    let transport = match path {
        Some(path) => DnsUpstreamTransport::Doh {
            server_name: name.into(),
            path: path.into(),
        },
        None => DnsUpstreamTransport::Dot {
            server_name: name.into(),
        },
    };
    DnsUpstreamSpec {
        transport,
        target: TargetAddr::ip(address).expect("non-zero encrypted endpoint"),
        resolved_targets: Box::new([]),
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
        target: TargetAddr,
        plan: Option<EgressPlanSnapshot>,
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
            let target = target
                .as_socket_addr()
                .expect("scripted TLS fixture target is numeric");
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
                    let _ = copy_bidirectional_with_sizes(&mut bridge, &mut upstream, 4_096, 4_096)
                        .await;
                },
            );
            Ok(Box::new(client) as crate::runtime_provider::BoxedDnsTcpIo)
        })
    }

    fn bind_udp(
        &self,
        _target: TargetAddr,
        _plan: Option<EgressPlanSnapshot>,
        _tasks: crate::runtime_provider::DnsTaskRegistrar,
    ) -> crate::runtime_provider::DnsIoFuture<crate::runtime_provider::BoxedDnsDatagramIo> {
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
            encrypted_server(fixture.dot, "resolver.test", None),
            valid.clone(),
        ),
        (
            encrypted_server(fixture.doh, "resolver.test", Some("/dns-query")),
            valid.clone(),
        ),
        (
            encrypted_server(fixture.dot, "wrong.test", None),
            valid.clone(),
        ),
        (
            encrypted_server(fixture.dot, "resolver.test", None),
            client_tls(VALID_TIME, false),
        ),
        (
            encrypted_server(fixture.dot, "resolver.test", None),
            client_tls(1_785_915_311, true),
        ),
        (
            encrypted_server(fixture.dot, "resolver.test", None),
            client_tls(2_101_275_313, true),
        ),
        (
            encrypted_server(fixture.doh, "resolver.test", Some("/wrong")),
            valid,
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
                encrypted_server(address, "resolver.test", Some("/dns-query")),
                client_tls(VALID_TIME, true),
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
    let mut server = encrypted_server(address, "resolver.test", Some("/dns-query"));
    server.detour = Some(EgressPlanHandle::direct(0));
    let (resolver, mut owner) = TaggedResolver::with_test_tls(
        vec![(server, client_tls(VALID_TIME, true))],
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
