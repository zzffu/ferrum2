use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum2_config::DirectDomainResolver;
use ferrum2_core::TargetAddr;
use ferrum2_dns::{DnsCacheQtype, DnsError, DnsUpstreamSpec, DnsUpstreamTransport, TaggedResolver};
use ferrum2_ruleset::{
    RuleSetDialTargets, RuleSetDialer, RuleSetDownloadError, RuleSetDownloadErrorKind,
    RuleSetDownloadFuture, RuleSetDownloadMode, RuleSetDownloadRequest, RuleSetDownloadResolver,
    RuleSetDownloadResponse, RuleSetLoadDisposition, RuleSetLoadErrorKind, RuleSetRefreshOutcome,
};
use hickory_proto::op::{Message, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener as TokioTcpListener, UdpSocket};
use tokio::sync::oneshot;
use tokio::time::Instant;

use super::outcome::classify_rule_set_load_error_kind;
use super::ruleset::{ServerRuleSetDialer, TaggedTransport, refresh_rule_set_result};
use super::*;
use crate::run::dns_egress::ServerPhysicalSocketContext;

const ADS_SRS: &[u8] = include_bytes!("../../../../../tests/fixtures/srs/ads.srs");
static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

#[test]
fn refresh_allocation_and_retained_cache_keep_failure_categories() {
    assert_eq!(
        classify_rule_set_load_error_kind(RuleSetLoadErrorKind::Allocation),
        RunError::RuleAllocation
    );
    assert_eq!(
        refresh_rule_set_result(RuleSetRefreshOutcome::RetainedCache(
            RuleSetLoadDisposition::OfflineCache,
        )),
        RuleSetResult::Failure
    );
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SeenDownload {
    mode: RuleSetDownloadMode,
    detour: Option<Vec<usize>>,
}

struct RecordingDownloader {
    fail_after: Option<usize>,
    calls: AtomicUsize,
    seen: Mutex<Vec<SeenDownload>>,
}

impl RecordingDownloader {
    fn success() -> Self {
        Self {
            fail_after: None,
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn failure() -> Self {
        Self {
            fail_after: Some(0),
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn success_then_failure() -> Self {
        Self {
            fail_after: Some(1),
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn seen(&self) -> Vec<SeenDownload> {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl RuleSetDownloader for RecordingDownloader {
    fn fetch(&self, request: RuleSetDownloadRequest) -> RuleSetDownloadFuture<'_> {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(SeenDownload {
                mode: request.mode(),
                detour: request.detour().map(|plan| plan.hops().to_vec()),
            });
        let call = self.calls.fetch_add(1, Ordering::AcqRel);
        let fail = self.fail_after.is_some_and(|threshold| call >= threshold);
        Box::pin(async move {
            if fail {
                Err(RuleSetDownloadError::new(RuleSetDownloadErrorKind::Connect))
            } else {
                Ok(RuleSetDownloadResponse::downloaded(
                    Box::new(ADS_SRS),
                    None,
                    None,
                ))
            }
        })
    }
}

struct TestConfig {
    path: PathBuf,
    cache_dir: PathBuf,
}

impl TestConfig {
    fn new(source: impl FnOnce(&str) -> String) -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "ferrum2-server-materialize-{}-{id}",
            std::process::id()
        ));
        let path = base.with_extension("toml");
        let cache_dir = base.with_extension("cache");
        let cache = cache_dir.to_string_lossy().replace('\\', "/");
        std::fs::write(&path, source(&cache)).expect("write server materializer config");
        Self { path, cache_dir }
    }
}

impl Drop for TestConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir_all(&self.cache_dir);
    }
}

fn reserve_address() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve address");
    listener.local_addr().expect("reserved address")
}

#[tokio::test]
async fn deferred_ruleset_domain_uses_the_selected_direct_resolver() {
    let listener = TokioTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("deferred RuleSet listener");
    let address = listener.local_addr().expect("deferred RuleSet address");
    let unavailable = super::super::dns_egress::ServerDnsResolver::for_direct(
        DirectDomainResolver::DnsServer {
            server: 0,
            strategy: ferrum2_config::DnsStrategy::Ipv4Only,
        },
        Arc::new(std::sync::OnceLock::new()),
    );
    let system = super::super::dns_egress::ServerDnsResolver::for_direct(
        DirectDomainResolver::System,
        Arc::new(std::sync::OnceLock::new()),
    );
    let dialer = ServerRuleSetDialer::new(
        vec![unavailable, system],
        ServerPhysicalSocketContext::test(2, Arc::new(Metrics::new())),
    );
    let target = RuleSetDialTargets::Domain(
        TargetAddr::domain("localhost", address.port()).expect("deferred RuleSet target"),
    );
    let detour = ferrum2_core::route::EgressPlanHandle::direct(1).snapshot_owned();
    let accepted =
        tokio::spawn(async move { listener.accept().await.expect("deferred RuleSet accept") });

    let stream = dialer
        .connect(
            &target,
            Some(&detour),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect("selected Direct domain dial");
    drop(stream);
    let _ = accepted.await.expect("deferred RuleSet accept join");
}

fn minimal_v2_source(listen: SocketAddr) -> String {
    format!(
        r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{listen}"

[[outbounds]]
tag = "direct"

[route]
final = "direct"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#
    )
}

fn remote_v2_source(listen: SocketAddr, cache: &str, update_interval: bool) -> String {
    let update = if update_interval {
        "update_interval_seconds = 60\n"
    } else {
        ""
    };
    format!(
        r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{listen}"

[[outbounds]]
tag = "direct"

[route]
final = "direct"

[[route.rule_set]]
tag = "ads"
type = "remote"
url = "https://rules.example.invalid/ads.srs"
download_resolver = "system"
download_detour = "direct"
{update}
[[route.rules]]
rule_set = "ads"
action = "reject"

[rule_set_loader]
cache_dir = "{cache}"
download_timeout_ms = 1000
max_redirects = 0

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#
    )
}

#[tokio::test]
async fn minimal_v2_materializes_without_network_or_refresh_owner() {
    let listen = reserve_address();
    let file = TestConfig::new(|_| minimal_v2_source(listen));
    let prepared = ferrum2_config::prepare_server(&file.path).expect("prepare minimal config");
    let downloader = Arc::new(RecordingDownloader::failure());
    let materializer =
        ServerV2Materializer::with_downloader(Arc::new(Metrics::new()), downloader.clone());

    let materialized = materializer
        .materialize(prepared)
        .await
        .expect("materialize minimal config");
    assert!(downloader.seen().is_empty());
    let config = materialized
        .validate_only()
        .expect("validation-only cleanup");
    assert_eq!(SocketAddr::V4(config.inbounds[0].listen), listen);
}

#[tokio::test]
async fn numeric_bootstrap_materializes_domain_dns_upstream_in_dependency_order() {
    let listen = reserve_address();
    let resolved_upstream = reserve_address();
    let bootstrap = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("numeric bootstrap DNS");
    let bootstrap_address = bootstrap.local_addr().expect("bootstrap DNS address");
    let observed = Arc::new(Mutex::new(Vec::new()));
    let worker_observed = Arc::clone(&observed);
    let (stop, mut stopped) = oneshot::channel();
    let worker = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        loop {
            let received = tokio::select! {
                _ = &mut stopped => break,
                received = bootstrap.recv_from(&mut wire) => received,
            };
            let (length, peer) = received.expect("bootstrap DNS receive");
            let request = Message::from_vec(&wire[..length]).expect("bootstrap DNS decode");
            let [query] = request.queries.as_slice() else {
                panic!("one bootstrap DNS question");
            };
            worker_observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((query.name().to_ascii(), query.query_type()));
            let mut response = Message::response(request.id, OpCode::Query);
            response.metadata.recursion_available = true;
            response.add_query(query.clone());
            response.add_answer(Record::from_rdata(
                query.name().clone(),
                60,
                RData::A(A(Ipv4Addr::LOCALHOST)),
            ));
            bootstrap
                .send_to(&response.to_vec().expect("bootstrap DNS encode"), peer)
                .await
                .expect("bootstrap DNS response");
        }
    });
    let file = TestConfig::new(|_| {
        format!(
            r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{listen}"

[[outbounds]]
tag = "direct"

[route]
final = "direct"

[dns]
timeout_ms = 1000
max_inflight = 8
strategy = "ipv4_only"

[[dns.servers]]
tag = "bootstrap"
transport = "udp"
address = "{bootstrap_address}"

[[dns.servers]]
tag = "resolved"
transport = "udp"
address = "upstream.test:{}"
domain_resolver = "bootstrap"
domain_strategy = "ipv4_only"

[dns.route]
final = "resolved"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#,
            resolved_upstream.port()
        )
    });
    let prepared = ferrum2_config::prepare_server(&file.path).expect("prepare domain DNS upstream");
    let order = prepared.materialization_order();
    let bootstrap_position = order
        .iter()
        .position(|node| *node == ferrum2_config::PreparedDependencyNode::DnsServer(0))
        .expect("bootstrap dependency node");
    let resolved_position = order
        .iter()
        .position(|node| *node == ferrum2_config::PreparedDependencyNode::DnsServer(1))
        .expect("resolved dependency node");
    assert!(bootstrap_position < resolved_position);

    let metrics = Arc::new(Metrics::new());
    let materializer = ServerV2Materializer::new(Arc::clone(&metrics));
    let materialized = materializer
        .materialize(prepared)
        .await
        .expect("materialize domain DNS upstream through numeric bootstrap");
    let dns = materialized
        .config()
        .dns
        .as_ref()
        .expect("materialized DNS");
    assert_eq!(
        dns.servers[0].target.as_socket_addr(),
        Some(bootstrap_address)
    );
    assert_eq!(
        dns.servers[1].target.canonical_domain().unwrap().as_str(),
        "upstream.test"
    );
    assert_eq!(
        dns.servers[1].resolved_targets.as_ref(),
        &[SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            resolved_upstream.port()
        )]
    );
    assert_eq!(
        *observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        [("upstream.test.".to_owned(), RecordType::A)],
        "materialization issued anything other than the single bootstrap query"
    );
    let encoded = metrics.encode_text().expect("bootstrap DNS metrics");
    for expected in [
        "ferrum2_dns_resolve_total{resolver=\"configured\",purpose=\"fixed_endpoint\",result=\"success\"} 1",
        "ferrum2_dns_implicit_system_fallback_total 0",
    ] {
        assert!(
            encoded.contains(expected),
            "missing `{expected}`\n{encoded}"
        );
    }
    assert!(
        !encoded.contains("ferrum2_dns_explicit_system_resolve_total{purpose=\"fixed_endpoint\"}")
    );
    materialized
        .validate_only()
        .expect("domain DNS upstream validation-only cleanup");
    let rebound = TcpListener::bind(listen).expect("server inbound remained unbound");
    drop(rebound);
    let _ = stop.send(());
    worker.await.expect("bootstrap DNS worker");
}

#[tokio::test]
async fn production_ruleset_transport_uses_tagged_dns_and_reaps_failed_tls_path() {
    let listen = reserve_address();
    let bootstrap = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("RuleSet tagged DNS");
    let bootstrap_address = bootstrap.local_addr().expect("RuleSet DNS address");
    let observed = Arc::new(Mutex::new(Vec::new()));
    let worker_observed = Arc::clone(&observed);
    let (stop, mut stopped) = oneshot::channel();
    let dns_worker = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        loop {
            let received = tokio::select! {
                _ = &mut stopped => break,
                received = bootstrap.recv_from(&mut wire) => received,
            };
            let (length, peer) = received.expect("RuleSet DNS receive");
            let request = Message::from_vec(&wire[..length]).expect("RuleSet DNS decode");
            let [query] = request.queries.as_slice() else {
                panic!("one RuleSet DNS question");
            };
            worker_observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((query.name().to_ascii(), query.query_type()));
            let mut response = Message::response(request.id, OpCode::Query);
            response.metadata.recursion_available = true;
            response.add_query(query.clone());
            response.add_answer(Record::from_rdata(
                query.name().clone(),
                60,
                RData::A(A(Ipv4Addr::LOCALHOST)),
            ));
            bootstrap
                .send_to(&response.to_vec().expect("RuleSet DNS encode"), peer)
                .await
                .expect("RuleSet DNS response");
        }
    });
    let tls_listener = TokioTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("controlled RuleSet TLS endpoint");
    let tls_address = tls_listener.local_addr().expect("RuleSet TLS address");
    let tls_worker = tokio::spawn(async move {
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), tls_listener.accept())
            .await
            .expect("RuleSet TCP connect timeout")
            .expect("RuleSet TCP connect");
        let mut client_hello = [0_u8; 4096];
        let received = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut client_hello))
            .await
            .expect("RuleSet TLS ClientHello timeout")
            .expect("RuleSet TLS ClientHello read");
        assert!(
            received > 0,
            "production downloader sent no TLS ClientHello"
        );
        stream
            .write_all(&[0, 0, 0, 0, 0])
            .await
            .expect("write controlled invalid TLS record");
        let mut drain = [0_u8; 256];
        loop {
            let length = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut drain))
                .await
                .expect("production RuleSet bridge did not close")
                .expect("read RuleSet bridge shutdown");
            if length == 0 {
                break;
            }
        }
        received
    });
    let file = TestConfig::new(|cache| {
        format!(
            r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{listen}"

[[outbounds]]
tag = "direct"
bind_interface = "test-loopback"

[route]
final = "direct"

[[route.rule_set]]
tag = "private-rule-tag"
type = "remote"
url = "https://rules.test:{}/ads.srs"
download_resolver = "bootstrap"
download_detour = "direct"

[[route.rules]]
rule_set = "private-rule-tag"
action = "reject"

[rule_set_loader]
cache_dir = "{cache}"
download_timeout_ms = 2000
max_redirects = 0

[dns]
timeout_ms = 1000
max_inflight = 8
strategy = "ipv4_only"

[[dns.servers]]
tag = "bootstrap"
transport = "udp"
address = "{bootstrap_address}"

[dns.route]
final = "bootstrap"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#,
            tls_address.port()
        )
    });
    let prepared =
        ferrum2_config::prepare_server(&file.path).expect("prepare production tagged RuleSet V2");
    let order = prepared.materialization_order();
    let resolver_position = order
        .iter()
        .position(|node| *node == ferrum2_config::PreparedDependencyNode::DnsServer(0))
        .expect("RuleSet resolver dependency node");
    let rule_set_position = order
        .iter()
        .position(|node| *node == ferrum2_config::PreparedDependencyNode::RuleSet(0))
        .expect("RuleSet dependency node");
    assert!(resolver_position < rule_set_position);
    let metrics = Arc::new(Metrics::new());
    let materializer = ServerV2Materializer::new(Arc::clone(&metrics));
    let error = match materializer.materialize(prepared).await {
        Ok(_) => panic!("controlled TLS endpoint unexpectedly materialized"),
        Err(error) => error,
    };
    assert_eq!(error, RunError::RuleSetDownload);
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(!rendered.contains("private-rule-tag"));
        assert!(!rendered.contains("rules.test"));
    }
    assert_eq!(
        *observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        [("rules.test.".to_owned(), RecordType::A)],
        "RuleSet resolution escaped its selected tagged resolver"
    );
    let tls_bytes = tls_worker.await.expect("controlled RuleSet TLS worker");
    assert!(tls_bytes > 0);
    let rebound = TcpListener::bind(listen).expect("server inbound remained unbound");
    drop(rebound);
    let encoded = metrics
        .encode_text()
        .expect("production RuleSet DNS metrics");
    for expected in [
        "ferrum2_dns_resolve_total{resolver=\"configured\",purpose=\"ruleset_download\",result=\"success\"} 1",
        "ferrum2_dns_implicit_system_fallback_total 0",
        "ferrum2_outbound_interface_resolution_total{source=\"outbound_explicit\",result=\"success\"} 1",
        "ferrum2_outbound_interface_resolution_total{source=\"system_best_route\",result=\"success\"} 1",
    ] {
        assert!(
            encoded.contains(expected),
            "missing `{expected}`\n{encoded}"
        );
    }
    assert!(
        !encoded
            .contains("ferrum2_dns_explicit_system_resolve_total{purpose=\"ruleset_download\"}")
    );
    let _ = stop.send(());
    dns_worker.await.expect("RuleSet DNS worker");
    let rebound = UdpSocket::bind(bootstrap_address)
        .await
        .expect("test DNS endpoint fully reaped");
    drop(rebound);
}

#[test]
fn validate_only_entrypoint_never_binds_listener() {
    let listen = reserve_address();
    let file = TestConfig::new(|_| minimal_v2_source(listen));
    let prepared = ferrum2_config::prepare_server(&file.path).expect("prepare minimal config");
    super::super::materialize_only(prepared).expect("materialized validation");
    let rebound = TcpListener::bind(listen).expect("validate-only did not bind listener");
    drop(rebound);
}

#[tokio::test]
async fn real_srs_initial_snapshot_finishes_before_listener_bind() {
    let listen = reserve_address();
    let file = TestConfig::new(|cache| remote_v2_source(listen, cache, false));
    let prepared = ferrum2_config::prepare_server(&file.path).expect("prepare remote config");
    let downloader = Arc::new(RecordingDownloader::success());
    let metrics = Arc::new(Metrics::new());
    let materializer =
        ServerV2Materializer::with_downloader(Arc::clone(&metrics), downloader.clone());

    let materialized = materializer
        .materialize(prepared)
        .await
        .expect("materialize real SRS");
    let registry = materialized
        .config()
        .route
        .rule_registry()
        .expect("materialized registry");
    let snapshot = registry.snapshot();
    let rule_set = snapshot.rule_set_id("ads").expect("compiled ads RuleSet");
    let descriptor = snapshot.rule_set(rule_set).expect("ads descriptor");
    assert!(
        snapshot
            .match_set(descriptor.match_set())
            .expect("ads match set")
            .entry_counts()
            .total()
            > 0
    );
    assert_eq!(snapshot.generation(), INITIAL_RULESET_GENERATION);
    assert_eq!(
        downloader.seen(),
        [SeenDownload {
            mode: RuleSetDownloadMode::ClientResolved(RuleSetDownloadResolver::System),
            detour: Some(vec![0]),
        }]
    );
    let rebound = TcpListener::bind(listen).expect("listener was not opened during materialize");
    drop(rebound);
    let encoded = metrics.encode_text().expect("metrics encode");
    assert!(encoded.contains("ferrum2_ruleset_generation 1"));
    materialized.validate_only().expect("drop refresh plan");
}

#[tokio::test]
async fn initial_ruleset_failure_returns_before_listener_bind() {
    let listen = reserve_address();
    let file = TestConfig::new(|cache| remote_v2_source(listen, cache, false));
    let prepared = ferrum2_config::prepare_server(&file.path).expect("prepare remote config");
    let downloader = Arc::new(RecordingDownloader::failure());
    let materializer =
        ServerV2Materializer::with_downloader(Arc::new(Metrics::new()), downloader.clone());

    assert!(matches!(
        materializer.materialize(prepared).await,
        Err(RunError::RuleSetDownload)
    ));
    assert_eq!(downloader.seen().len(), 1);
    let rebound = TcpListener::bind(listen).expect("failed materialize never bound listener");
    drop(rebound);
}

#[tokio::test]
async fn refresh_failure_retains_generation_and_root_cleanup_is_explicit() {
    let listen = reserve_address();
    let file = TestConfig::new(|cache| remote_v2_source(listen, cache, true));
    let prepared = ferrum2_config::prepare_server(&file.path).expect("prepare refresh config");
    let downloader = Arc::new(RecordingDownloader::success_then_failure());
    let materializer =
        ServerV2Materializer::with_downloader(Arc::new(Metrics::new()), downloader.clone());
    let materialized = materializer
        .materialize(prepared)
        .await
        .expect("strict initial snapshot");
    let MaterializedRunParts {
        config,
        materialization_root: root,
        cache: _cache,
    } = materialized
        .into_run_parts()
        .await
        .expect("transfer refresh ownership");
    let registry = config.route.rule_registry().expect("route registry");
    let mut root = root.expect("refresh root");
    let outcome = root.refresh_once(0).await;
    assert!(matches!(
        outcome,
        RuleSetRefreshOutcome::Failed(_) | RuleSetRefreshOutcome::RetainedCache(_)
    ));
    assert_eq!(registry.generation(), INITIAL_RULESET_GENERATION);
    assert_eq!(downloader.seen().len(), 2);
    root.cleanup().await.expect("refresh owner cleanup");
    root.cleanup().await.expect("idempotent cleaned root");
    assert!(root.is_cleaned());
}

#[tokio::test]
async fn tagged_transport_shutdown_joins_resolver_owner() {
    let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("owner probe upstream");
    let upstream_address = upstream.local_addr().expect("probe upstream address");
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![DnsUpstreamSpec {
            transport: DnsUpstreamTransport::Udp,
            target: TargetAddr::ip(upstream_address).expect("numeric upstream"),
            resolved_targets: Box::new([]),
            detour: None,
        }],
        Duration::from_secs(1),
        std::num::NonZeroU16::MIN,
    )
    .expect("owner probe resolver");
    owner.ready().await.expect("owner probe ready");
    let probe = Arc::new(resolver);
    TaggedTransport::Owned {
        resolver: Arc::clone(&probe),
        owner,
    }
    .shutdown()
    .await
    .expect("tagged transport cleanup");
    let domain = ferrum2_core::CanonicalDomain::new("joined.example").expect("probe domain");
    assert!(matches!(
        probe
            .lookup_fixed_endpoint(0, domain, DnsCacheQtype::A)
            .await,
        Err(DnsError::Shutdown)
    ));
}
