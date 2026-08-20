use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use ferrum2_core::CanonicalDomain;
use ferrum2_core::route::EgressPlanHandle;
use ferrum2_dns::{DnsServerId, DnsStrategy};
use ferrum2_runtime::{
    ExplicitRuleSetHostResolver, HttpsRuleSetDownloader, RuleSetCacheName, RuleSetDialer,
    RuleSetDownloadError, RuleSetDownloadErrorKind, RuleSetDownloadResolver,
    RuleSetHostResolveOutcome, RuleSetHostResolver, RuleSetHostResolverKind,
    RuleSetLoadDisposition, RuleSetLoader, RuleSetLoaderConfig, RuleSetRemoteSource,
    SystemRuleSetDialer,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;

const ROOT: &[u8] = include_bytes!("../../ferrum2-dns/tests/fixtures/m12-test-ca.der");
const CERT: &[u8] = include_bytes!("../../ferrum2-dns/tests/fixtures/m12-resolver-test.der");
const KEY: &[u8] = include_bytes!("../../ferrum2-dns/tests/fixtures/m12-resolver-test.pk8");
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

async fn fixture_server() -> (SocketAddr, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let endpoint = listener.local_addr().expect("local endpoint");
    let acceptor = TlsAcceptor::from(Arc::new(server_tls()));
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for _ in 0..4 {
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
            if first_line.contains(" /redirect ") {
                stream
                    .write_all(
                        b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
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
    let (endpoint, server) = fixture_server().await;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = RecordingResolver {
        endpoint,
        calls: Arc::clone(&calls),
    };
    let downloader = HttpsRuleSetDownloader::with_tls_config(
        resolver,
        SystemRuleSetDialer,
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
        &format!("https://resolver.test:{}/redirect", endpoint.port()),
        RuleSetDownloadResolver::DnsServer(DnsServerId::new(9)),
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
    let requests = server.await.expect("server join");
    assert_eq!(requests.len(), 4);
    assert!(requests[0].starts_with("GET /redirect HTTP/1.1"));
    assert!(requests[1].starts_with("GET /final HTTP/1.1"));
    assert!(!requests[1].to_ascii_lowercase().contains("if-none-match:"));
    assert!(requests[3].to_ascii_lowercase().contains("if-none-match:"));
}

#[tokio::test]
async fn system_only_resolver_rejects_tagged_requests_without_lookup() {
    let error = ferrum2_runtime::SystemRuleSetHostResolver
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
    let error = SystemRuleSetDialer
        .connect(
            &["127.0.0.1:9".parse().expect("candidate")],
            Some(&detour),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect_err("direct dialer must not bypass detour");
    assert_eq!(error.kind(), RuleSetDownloadErrorKind::Connect);
}
