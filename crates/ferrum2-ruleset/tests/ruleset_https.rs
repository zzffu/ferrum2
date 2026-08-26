use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use ferrum2_core::route::EgressPlanHandle;
use ferrum2_core::{CanonicalDomain, TargetAddr};
use ferrum2_dns::{DnsServerId, DnsStrategy};
use ferrum2_ruleset::{
    ExplicitRuleSetHostResolver, HttpsRuleSetDownloader, RuleSetCacheName, RuleSetDialTargets,
    RuleSetDialer, RuleSetDownloadError, RuleSetDownloadErrorKind, RuleSetDownloadMode,
    RuleSetDownloadResolver, RuleSetHostResolveOutcome, RuleSetHostResolver,
    RuleSetHostResolverKind, RuleSetLoadDisposition, RuleSetLoader, RuleSetLoaderConfig,
    RuleSetRemoteSource, SystemRuleSetDialer,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;

const ROOT: &[u8] = include_bytes!("../../../tests/fixtures/dns-tls/m12-test-ca.der");
const CERT: &[u8] = include_bytes!("../../../tests/fixtures/dns-tls/m12-resolver-test.der");
const KEY: &[u8] = include_bytes!("../../../tests/fixtures/dns-tls/m12-resolver-test.pk8");
const AI_SRS: &[u8] = include_bytes!("../../../tests/fixtures/srs/ai.srs");

#[derive(Clone)]
struct RecordingResolver {
    endpoint: SocketAddr,
    calls: Arc<Mutex<Vec<(String, RuleSetDownloadResolver)>>>,
}

impl RuleSetHostResolver for RecordingResolver {
    fn resolve(
        &self,
        resolver: RuleSetDownloadResolver,
        host: &CanonicalDomain,
        _port: u16,
        _deadline: Instant,
    ) -> impl Future<Output = Result<Vec<SocketAddr>, RuleSetDownloadError>> + Send {
        let endpoint = self.endpoint;
        lock(&self.calls).push((host.as_str().to_owned(), resolver));
        async move { Ok(vec![endpoint]) }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SeenDial {
    targets: RuleSetDialTargets,
    detour_hops: Option<Vec<usize>>,
    deadline: Instant,
}

#[derive(Clone)]
struct RecordingDialer {
    endpoint: SocketAddr,
    calls: Arc<Mutex<Vec<SeenDial>>>,
}

impl RuleSetDialer for RecordingDialer {
    type Io = TcpStream;

    fn connect(
        &self,
        targets: &RuleSetDialTargets,
        detour: Option<&ferrum2_core::route::EgressPlanSnapshot>,
        deadline: Instant,
    ) -> impl Future<Output = Result<Self::Io, RuleSetDownloadError>> + Send {
        lock(&self.calls).push(SeenDial {
            targets: targets.clone(),
            detour_hops: detour.map(|plan| plan.hops().to_vec()),
            deadline,
        });
        let endpoint = self.endpoint;
        async move {
            tokio::time::timeout_at(deadline, TcpStream::connect(endpoint))
                .await
                .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Timeout))?
                .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Connect))
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn server_tls() -> ServerConfig {
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(CERT.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec())),
        )
        .expect("server certificate")
}

fn client_tls() -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ROOT.to_vec()))
        .expect("test root");
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

async fn fixture_server(
    request_count: usize,
) -> (SocketAddr, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let endpoint = listener.local_addr().expect("local endpoint");
    let acceptor = TlsAcceptor::from(Arc::new(server_tls()));
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for _ in 0..request_count {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut stream = acceptor.accept(stream).await.expect("TLS accept");
            let mut bytes = Vec::new();
            let mut block = [0_u8; 1024];
            loop {
                let read = stream.read(&mut block).await.expect("request read");
                assert_ne!(read, 0, "request header EOF");
                bytes.extend_from_slice(&block[..read]);
                if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(bytes).expect("ASCII request");
            let first_line = request.lines().next().expect("request line").to_owned();
            requests.push(request.clone());
            if first_line.contains(" /redirect?source=one ") {
                stream
                    .write_all(
                        b"HTTP/1.1 302 Found\r\nLocation: /final?target=two\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .expect("redirect");
            } else if request.to_ascii_lowercase().contains("if-none-match:") {
                stream
                    .write_all(
                        b"HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .expect("not modified");
            } else {
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: fixture-v1\r\nLast-Modified: Thu, 20 Aug 2026 00:00:00 GMT\r\nConnection: close\r\n\r\n",
                    AI_SRS.len()
                );
                stream
                    .write_all(header.as_bytes())
                    .await
                    .expect("response header");
                stream.write_all(AI_SRS).await.expect("response body");
            }
            stream.shutdown().await.expect("TLS shutdown");
        }
        requests
    });
    (endpoint, task)
}

#[tokio::test]
async fn https_redirects_and_conditionals_reuse_only_the_explicit_resolver() {
    let (endpoint, server) = fixture_server(4).await;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let dial_calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = RecordingResolver {
        endpoint,
        calls: Arc::clone(&calls),
    };
    let downloader = HttpsRuleSetDownloader::with_tls_config(
        resolver,
        RecordingDialer {
            endpoint,
            calls: Arc::clone(&dial_calls),
        },
        Arc::new(client_tls()),
    );
    let cache = TempDir::new().expect("cache");
    let loader = RuleSetLoader::new(
        RuleSetLoaderConfig::new(cache.path().to_path_buf(), Duration::from_secs(5), 2)
            .expect("config"),
        downloader,
    );
    let source = RuleSetRemoteSource::new(
        RuleSetCacheName::new("ai").expect("cache name"),
        &format!(
            "https://resolver.test:{}/redirect?source=one",
            endpoint.port()
        ),
        RuleSetDownloadMode::ClientResolved(RuleSetDownloadResolver::DnsServer(DnsServerId::new(
            9,
        ))),
        None,
        None,
    )
    .expect("source");

    let first = loader.load(&source, 1).await.expect("download");
    assert_eq!(first.disposition(), RuleSetLoadDisposition::Downloaded);
    let second = loader.load(&source, 2).await.expect("conditional");
    assert_eq!(second.disposition(), RuleSetLoadDisposition::NotModified);

    assert_eq!(
        lock(&calls).as_slice(),
        [
            (
                "resolver.test".to_owned(),
                RuleSetDownloadResolver::DnsServer(DnsServerId::new(9)),
            ),
            (
                "resolver.test".to_owned(),
                RuleSetDownloadResolver::DnsServer(DnsServerId::new(9)),
            ),
            (
                "resolver.test".to_owned(),
                RuleSetDownloadResolver::DnsServer(DnsServerId::new(9)),
            ),
            (
                "resolver.test".to_owned(),
                RuleSetDownloadResolver::DnsServer(DnsServerId::new(9)),
            ),
        ]
    );
    {
        let dial_calls = lock(&dial_calls);
        assert_eq!(dial_calls.len(), 4);
        for call in dial_calls.iter() {
            assert_eq!(
                call.targets,
                RuleSetDialTargets::Resolved(vec![endpoint].into_boxed_slice())
            );
            assert_eq!(call.detour_hops, None);
        }
        assert_eq!(dial_calls[0].deadline, dial_calls[1].deadline);
        assert_eq!(dial_calls[2].deadline, dial_calls[3].deadline);
    }
    let requests = server.await.expect("server join");
    assert_eq!(requests.len(), 4);
    assert!(requests[0].starts_with("GET /redirect?source=one HTTP/1.1"));
    assert!(requests[1].starts_with("GET /final?target=two HTTP/1.1"));
    for request in &requests {
        assert!(
            request
                .to_ascii_lowercase()
                .contains(&format!("host: resolver.test:{}\r\n", endpoint.port()))
        );
    }
    assert!(!requests[1].to_ascii_lowercase().contains("if-none-match:"));
    assert!(requests[3].to_ascii_lowercase().contains("if-none-match:"));
}

#[tokio::test]
async fn deferred_redirects_never_resolve_and_keep_domain_identity_and_detour_snapshot() {
    let (endpoint, server) = fixture_server(2).await;
    let resolver_calls = Arc::new(Mutex::new(Vec::new()));
    let dial_calls = Arc::new(Mutex::new(Vec::new()));
    let downloader = HttpsRuleSetDownloader::with_tls_config(
        RecordingResolver {
            endpoint,
            calls: Arc::clone(&resolver_calls),
        },
        RecordingDialer {
            endpoint,
            calls: Arc::clone(&dial_calls),
        },
        Arc::new(client_tls()),
    );
    let cache = TempDir::new().expect("cache");
    let loader = RuleSetLoader::new(
        RuleSetLoaderConfig::new(cache.path().to_path_buf(), Duration::from_secs(5), 2)
            .expect("config"),
        downloader,
    );
    let source = RuleSetRemoteSource::new(
        RuleSetCacheName::new("deferred").expect("cache name"),
        &format!(
            "https://resolver.test:{}/redirect?source=one",
            endpoint.port()
        ),
        RuleSetDownloadMode::DeferredToDetour,
        Some(EgressPlanHandle::direct(7)),
        None,
    )
    .expect("deferred source");

    let loaded = loader.load(&source, 1).await.expect("deferred download");
    assert_eq!(loaded.disposition(), RuleSetLoadDisposition::Downloaded);
    assert!(lock(&resolver_calls).is_empty());

    let expected_target = TargetAddr::domain("resolver.test", endpoint.port()).expect("target");
    {
        let dial_calls = lock(&dial_calls);
        assert_eq!(dial_calls.len(), 2);
        for call in dial_calls.iter() {
            assert_eq!(
                call.targets,
                RuleSetDialTargets::Domain(expected_target.clone())
            );
            assert_eq!(call.detour_hops.as_deref(), Some([7].as_slice()));
            assert_eq!(call.deadline, dial_calls[0].deadline);
        }
    }

    let requests = server.await.expect("server join");
    assert!(requests[0].starts_with("GET /redirect?source=one HTTP/1.1"));
    assert!(requests[1].starts_with("GET /final?target=two HTTP/1.1"));
    for request in requests {
        assert!(
            request
                .to_ascii_lowercase()
                .contains(&format!("host: resolver.test:{}\r\n", endpoint.port()))
        );
    }
}

#[tokio::test]
async fn system_only_resolver_rejects_tagged_requests_without_lookup() {
    let error = ferrum2_ruleset::SystemRuleSetHostResolver
        .resolve(
            RuleSetDownloadResolver::DnsServer(DnsServerId::new(1)),
            &CanonicalDomain::new("resolver.test").expect("domain"),
            443,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect_err("tagged lookup must fail closed");
    assert_eq!(error.kind(), RuleSetDownloadErrorKind::Resolution);
}

#[tokio::test]
async fn explicit_resolver_never_turns_missing_tagged_state_into_system_lookup() {
    let observations = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&observations);
    let resolver = ExplicitRuleSetHostResolver::new(None, DnsStrategy::PreferIpv4).with_observer(
        Arc::new(move |resolver, outcome| lock(&observed).push((resolver, outcome))),
    );
    let error = resolver
        .resolve(
            RuleSetDownloadResolver::DnsServer(DnsServerId::new(7)),
            &CanonicalDomain::new("not-in-hosts.invalid").expect("domain"),
            443,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect_err("missing tagged graph must fail closed");
    assert_eq!(error.kind(), RuleSetDownloadErrorKind::Resolution);
    assert_eq!(
        lock(&observations).as_slice(),
        [(
            RuleSetHostResolverKind::Configured,
            RuleSetHostResolveOutcome::Failure,
        )]
    );
}

#[tokio::test]
async fn explicit_system_lookup_reports_one_identity_free_success() {
    let observations = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&observations);
    let resolver = ExplicitRuleSetHostResolver::new(None, DnsStrategy::PreferIpv4).with_observer(
        Arc::new(move |resolver, outcome| lock(&observed).push((resolver, outcome))),
    );
    let candidates = resolver
        .resolve(
            RuleSetDownloadResolver::System,
            &CanonicalDomain::new("localhost").expect("domain"),
            443,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect("explicit system lookup");
    assert!(!candidates.is_empty());
    assert_eq!(
        lock(&observations).as_slice(),
        [(
            RuleSetHostResolverKind::System,
            RuleSetHostResolveOutcome::Success,
        )]
    );
}

#[tokio::test]
async fn system_dialer_rejects_a_configured_detour_instead_of_bypassing_it() {
    let detour = EgressPlanHandle::direct(0).snapshot_owned();
    let targets = RuleSetDialTargets::Resolved(
        vec!["127.0.0.1:9".parse().expect("candidate")].into_boxed_slice(),
    );
    let error = SystemRuleSetDialer
        .connect(
            &targets,
            Some(&detour),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect_err("direct dialer must not bypass detour");
    assert_eq!(error.kind(), RuleSetDownloadErrorKind::Connect);
}

#[tokio::test]
async fn system_dialer_rejects_domain_targets_without_implicit_resolution() {
    let targets = RuleSetDialTargets::Domain(
        TargetAddr::domain("must-not-resolve.invalid", 443).expect("domain target"),
    );
    let error = SystemRuleSetDialer
        .connect(&targets, None, Instant::now() + Duration::from_secs(1))
        .await
        .expect_err("system dialer must not resolve a deferred target");
    assert_eq!(error.kind(), RuleSetDownloadErrorKind::Connect);
}
