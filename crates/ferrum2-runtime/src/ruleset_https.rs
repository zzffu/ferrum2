use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{CanonicalDomain, TargetAddr};
use ferrum2_dns::{
    DnsAddressRecords, DnsCache, DnsCacheAnswer, DnsCacheKey, DnsCacheQtype, DnsStrategy,
    FixedEndpointLookup, ResolverGeneration, TaggedResolver,
};
use futures_util::{Stream, TryStreamExt};
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::header::{
    CONNECTION, ETAG, HOST, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LOCATION, USER_AGENT,
};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_util::io::StreamReader;
use url::{Host, Url};

use crate::{
    MAX_RESOLVED_CANDIDATES, RuleSetDownloadError, RuleSetDownloadErrorKind, RuleSetDownloadFuture,
    RuleSetDownloadMode, RuleSetDownloadRequest, RuleSetDownloadResolver, RuleSetDownloadResponse,
    RuleSetDownloader,
};

const HTTPS_PORT: u16 = 443;
const HTTP_USER_AGENT: &str = "ferrum2-ruleset/0.1";

/// Resolves only through the mode supplied by validated configuration. An
/// implementation must never reinterpret a failed tagged lookup as `System`.
pub trait RuleSetHostResolver: Send + Sync {
    fn resolve(
        &self,
        resolver: RuleSetDownloadResolver,
        host: &CanonicalDomain,
        port: u16,
        deadline: Instant,
    ) -> impl Future<Output = Result<Vec<SocketAddr>, RuleSetDownloadError>> + Send;
}

/// Closed resolver mode exposed to identity-free RuleSet download telemetry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSetHostResolverKind {
    System,
    Configured,
}

/// Closed outcome exposed to identity-free RuleSet download telemetry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSetHostResolveOutcome {
    Success,
    Failure,
}

/// Observes one complete RuleSet host lookup without exposing a host or tag.
pub trait RuleSetHostResolveObserver: Send + Sync {
    fn record(&self, resolver: RuleSetHostResolverKind, outcome: RuleSetHostResolveOutcome);
}

impl<F> RuleSetHostResolveObserver for F
where
    F: Fn(RuleSetHostResolverKind, RuleSetHostResolveOutcome) + Send + Sync,
{
    fn record(&self, resolver: RuleSetHostResolverKind, outcome: RuleSetHostResolveOutcome) {
        self(resolver, outcome);
    }
}

/// One closed set of targets selected for a RuleSet HTTPS connection.
#[derive(Clone, Eq, PartialEq)]
pub enum RuleSetDialTargets {
    /// Bounded client-resolved candidates attempted in order under one deadline.
    Resolved(Box<[SocketAddr]>),
    /// A URL domain preserved for resolution by the supplied detour.
    Domain(TargetAddr),
}

impl fmt::Debug for RuleSetDialTargets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolved(_) => formatter.write_str("RuleSetDialTargets::Resolved([redacted])"),
            Self::Domain(_) => formatter.write_str("RuleSetDialTargets::Domain([redacted])"),
        }
    }
}

/// Connects one explicit target set through the supplied immutable detour.
/// Implementations must not reinterpret a domain target as permission to use
/// an unrelated resolver or detour.
pub trait RuleSetDialer: Send + Sync {
    type Io: AsyncRead + AsyncWrite + Send + Unpin + 'static;

    fn connect(
        &self,
        targets: &RuleSetDialTargets,
        detour: Option<&EgressPlanSnapshot>,
        deadline: Instant,
    ) -> impl Future<Output = Result<Self::Io, RuleSetDownloadError>> + Send;
}

/// Explicit system bootstrap implementation. Tagged resolver requests fail
/// closed and must be handled by a DNS-aware binary adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRuleSetHostResolver;

impl RuleSetHostResolver for SystemRuleSetHostResolver {
    fn resolve(
        &self,
        resolver: RuleSetDownloadResolver,
        host: &CanonicalDomain,
        port: u16,
        deadline: Instant,
    ) -> impl Future<Output = Result<Vec<SocketAddr>, RuleSetDownloadError>> + Send {
        let host = host.as_str().to_owned();
        async move {
            if resolver != RuleSetDownloadResolver::System {
                return Err(RuleSetDownloadError::new(
                    RuleSetDownloadErrorKind::Resolution,
                ));
            }
            let resolved = tokio::time::timeout_at(deadline, tokio::net::lookup_host((host, port)))
                .await
                .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Timeout))?
                .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Resolution))?;
            let candidates: Vec<_> = resolved.take(MAX_RESOLVED_CANDIDATES).collect();
            if candidates.is_empty() {
                Err(RuleSetDownloadError::new(
                    RuleSetDownloadErrorKind::Resolution,
                ))
            } else {
                Ok(candidates)
            }
        }
    }
}

/// Explicit system-or-tagged resolver used by materialized binary graphs.
///
/// A tagged request can reach only the supplied [`TaggedResolver`]. Missing or
/// failed tagged state is terminal and is never reinterpreted as a request for
/// [`SystemRuleSetHostResolver`].
#[derive(Clone)]
pub struct ExplicitRuleSetHostResolver {
    tagged: Option<Arc<TaggedResolver>>,
    strategy: DnsStrategy,
    cache: Option<(DnsCache, ResolverGeneration)>,
    observer: Option<Arc<dyn RuleSetHostResolveObserver>>,
}

impl ExplicitRuleSetHostResolver {
    pub const fn new(tagged: Option<Arc<TaggedResolver>>, strategy: DnsStrategy) -> Self {
        Self {
            tagged,
            strategy,
            cache: None,
            observer: None,
        }
    }

    /// Shares the fixed-endpoint DNS cache with RuleSet host lookups.
    pub fn with_cache(mut self, cache: DnsCache, generation: ResolverGeneration) -> Self {
        self.cache = Some((cache, generation));
        self
    }

    pub fn with_observer(mut self, observer: Arc<dyn RuleSetHostResolveObserver>) -> Self {
        self.observer = Some(observer);
        self
    }
}

impl fmt::Debug for ExplicitRuleSetHostResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExplicitRuleSetHostResolver")
            .field("tagged", &self.tagged.is_some())
            .field("strategy", &self.strategy)
            .field("cache", &self.cache.is_some())
            .field("observer", &self.observer.is_some())
            .finish()
    }
}

impl RuleSetHostResolver for ExplicitRuleSetHostResolver {
    fn resolve(
        &self,
        resolver: RuleSetDownloadResolver,
        host: &CanonicalDomain,
        port: u16,
        deadline: Instant,
    ) -> impl Future<Output = Result<Vec<SocketAddr>, RuleSetDownloadError>> + Send {
        let tagged = self.tagged.as_ref().map(Arc::clone);
        let strategy = self.strategy;
        let cache = self.cache.clone();
        let observer = self.observer.as_ref().map(Arc::clone);
        let host = host.clone();
        async move {
            let kind = match resolver {
                RuleSetDownloadResolver::System => RuleSetHostResolverKind::System,
                RuleSetDownloadResolver::DnsServer(_) => RuleSetHostResolverKind::Configured,
            };
            let result =
                resolve_explicit_host(tagged, strategy, cache, resolver, host, port, deadline)
                    .await;
            if let Some(observer) = observer {
                observer.record(
                    kind,
                    if result.is_ok() {
                        RuleSetHostResolveOutcome::Success
                    } else {
                        RuleSetHostResolveOutcome::Failure
                    },
                );
            }
            result
        }
    }
}

async fn resolve_explicit_host(
    tagged: Option<Arc<TaggedResolver>>,
    strategy: DnsStrategy,
    cache: Option<(DnsCache, ResolverGeneration)>,
    resolver: RuleSetDownloadResolver,
    host: CanonicalDomain,
    port: u16,
    deadline: Instant,
) -> Result<Vec<SocketAddr>, RuleSetDownloadError> {
    let port = NonZeroU16::new(port).ok_or_else(resolution_error)?;
    let addresses = match resolver {
        RuleSetDownloadResolver::System => {
            let resolved = tokio::time::timeout_at(
                deadline,
                tokio::net::lookup_host((host.as_str(), port.get())),
            )
            .await
            .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Timeout))?
            .map_err(|_| resolution_error())?;
            resolved.map(|address| address.ip()).collect::<Vec<_>>()
        }
        RuleSetDownloadResolver::DnsServer(server) => {
            let tagged = tagged.ok_or_else(resolution_error)?;
            let qtypes: &[DnsCacheQtype] = match strategy {
                DnsStrategy::Ipv4Only => &[DnsCacheQtype::A],
                DnsStrategy::Ipv6Only => &[DnsCacheQtype::Aaaa],
                DnsStrategy::PreferIpv4 | DnsStrategy::PreferIpv6 => {
                    &[DnsCacheQtype::A, DnsCacheQtype::Aaaa]
                }
            };
            let mut addresses = Vec::new();
            for &qtype in qtypes {
                let key = cache.as_ref().map(|(_, generation)| {
                    DnsCacheKey::new(server, host.clone(), qtype, *generation)
                });
                let cached = match (&cache, &key) {
                    (Some((cache, _)), Some(key)) => cache
                        .get(key, std::time::Instant::now())
                        .map_err(|_| resolution_error())?,
                    _ => None,
                };
                let answer = match cached {
                    Some(answer) => answer,
                    None => {
                        let lookup = tokio::time::timeout_at(
                            deadline,
                            tagged.lookup_fixed_endpoint(
                                server.get() as usize,
                                host.clone(),
                                qtype,
                            ),
                        )
                        .await
                        .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Timeout))?
                        .map_err(|_| resolution_error())?;
                        let now = std::time::Instant::now();
                        match lookup {
                            FixedEndpointLookup::Positive { records, ttl } => {
                                if let (Some((cache, _)), Some(key)) = (&cache, key) {
                                    cache
                                        .insert_positive(key, records.clone(), ttl, now)
                                        .map_err(|_| resolution_error())?;
                                }
                                DnsCacheAnswer::Positive(records)
                            }
                            FixedEndpointLookup::Negative { ttl } => {
                                if let (Some((cache, _)), Some(key)) = (&cache, key) {
                                    cache
                                        .insert_negative(key, ttl, now)
                                        .map_err(|_| resolution_error())?;
                                }
                                DnsCacheAnswer::Negative
                            }
                        }
                    }
                };
                if let DnsCacheAnswer::Positive(records) = answer {
                    match records {
                        DnsAddressRecords::A(records) => {
                            addresses.extend(records.iter().copied().map(std::net::IpAddr::V4));
                        }
                        DnsAddressRecords::Aaaa(records) => {
                            addresses.extend(records.iter().copied().map(std::net::IpAddr::V6));
                        }
                    }
                }
            }
            addresses
        }
    };
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for address in addresses {
        match address {
            std::net::IpAddr::V4(address) if !ipv4.contains(&address) => ipv4.push(address),
            std::net::IpAddr::V6(address) if !ipv6.contains(&address) => ipv6.push(address),
            _ => {}
        }
        if ipv4.len() + ipv6.len() == MAX_RESOLVED_CANDIDATES {
            break;
        }
    }
    let mut candidates = strategy.socket_candidates(port, &ipv4, &ipv6);
    candidates.truncate(MAX_RESOLVED_CANDIDATES);
    if candidates.is_empty() {
        Err(resolution_error())
    } else {
        Ok(candidates)
    }
}

const fn resolution_error() -> RuleSetDownloadError {
    RuleSetDownloadError::new(RuleSetDownloadErrorKind::Resolution)
}

/// Direct TCP implementation for an explicitly detour-free source. Binaries
/// provide their egress-engine dialer when a detour is configured.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRuleSetDialer;

impl RuleSetDialer for SystemRuleSetDialer {
    type Io = TcpStream;

    fn connect(
        &self,
        targets: &RuleSetDialTargets,
        detour: Option<&EgressPlanSnapshot>,
        deadline: Instant,
    ) -> impl Future<Output = Result<Self::Io, RuleSetDownloadError>> + Send {
        let candidates = match targets {
            RuleSetDialTargets::Resolved(candidates) => Some(candidates.clone()),
            RuleSetDialTargets::Domain(_) => None,
        };
        let has_detour = detour.is_some();
        async move {
            let Some(candidates) = candidates else {
                return Err(RuleSetDownloadError::new(RuleSetDownloadErrorKind::Connect));
            };
            if has_detour {
                return Err(RuleSetDownloadError::new(RuleSetDownloadErrorKind::Connect));
            }
            for candidate in candidates {
                match tokio::time::timeout_at(deadline, TcpStream::connect(candidate)).await {
                    Ok(Ok(stream)) => {
                        let _ = stream.set_nodelay(true);
                        return Ok(stream);
                    }
                    Ok(Err(_)) => {}
                    Err(_) => {
                        return Err(RuleSetDownloadError::new(RuleSetDownloadErrorKind::Timeout));
                    }
                }
            }
            Err(RuleSetDownloadError::new(RuleSetDownloadErrorKind::Connect))
        }
    }
}

/// Minimal HTTPS/1.1 client built on explicitly injected resolution and dialing.
/// Redirects apply the same resolution mode to each new hostname while
/// preserving the immutable detour and absolute deadline.
pub struct HttpsRuleSetDownloader<R, D> {
    resolver: R,
    dialer: D,
    tls: TlsConnector,
}

impl<R, D> HttpsRuleSetDownloader<R, D> {
    pub fn new(resolver: R, dialer: D) -> Self {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            resolver,
            dialer,
            tls: TlsConnector::from(Arc::new(config)),
        }
    }

    pub fn with_tls_config(resolver: R, dialer: D, config: Arc<ClientConfig>) -> Self {
        Self {
            resolver,
            dialer,
            tls: TlsConnector::from(config),
        }
    }
}

impl<R, D> fmt::Debug for HttpsRuleSetDownloader<R, D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HttpsRuleSetDownloader([redacted])")
    }
}

impl<R, D> RuleSetDownloader for HttpsRuleSetDownloader<R, D>
where
    R: RuleSetHostResolver,
    D: RuleSetDialer,
{
    fn fetch(&self, request: RuleSetDownloadRequest) -> RuleSetDownloadFuture<'_> {
        Box::pin(async move { self.fetch_inner(request).await })
    }
}

impl<R, D> HttpsRuleSetDownloader<R, D>
where
    R: RuleSetHostResolver,
    D: RuleSetDialer,
{
    async fn fetch_inner(
        &self,
        request: RuleSetDownloadRequest,
    ) -> Result<RuleSetDownloadResponse, RuleSetDownloadError> {
        let mut current = validate_https_url(
            Url::parse(request.url())
                .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Redirect))?,
        )?;
        let mut redirects = 0_u8;
        loop {
            let response = self.request_once(&current, &request).await?;
            if is_redirect(response.response.status()) {
                if redirects >= request.max_redirects() {
                    return Err(RuleSetDownloadError::new(
                        RuleSetDownloadErrorKind::Redirect,
                    ));
                }
                let location = response
                    .response
                    .headers()
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Redirect))?;
                current =
                    validate_https_url(current.join(location).map_err(|_| {
                        RuleSetDownloadError::new(RuleSetDownloadErrorKind::Redirect)
                    })?)?;
                redirects = redirects
                    .checked_add(1)
                    .ok_or_else(|| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Redirect))?;
                continue;
            }
            if response.response.status() == StatusCode::NOT_MODIFIED {
                return Ok(RuleSetDownloadResponse::not_modified());
            }
            if response.response.status() != StatusCode::OK {
                return Err(RuleSetDownloadError::new(RuleSetDownloadErrorKind::Http));
            }
            let etag = header(response.response.headers(), ETAG)?;
            let last_modified = header(response.response.headers(), LAST_MODIFIED)?;
            let body = HyperRuleSetBody::new(response.response.into_body(), response.connection);
            return Ok(RuleSetDownloadResponse::downloaded(
                Box::new(body),
                etag,
                last_modified,
            ));
        }
    }

    async fn request_once(
        &self,
        url: &Url,
        request: &RuleSetDownloadRequest,
    ) -> Result<InternalResponse, RuleSetDownloadError> {
        let host = url
            .host_str()
            .ok_or_else(|| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Redirect))?;
        let canonical = CanonicalDomain::new(host)
            .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Redirect))?;
        let port = url.port_or_known_default().unwrap_or(HTTPS_PORT);
        let targets = match request.mode() {
            RuleSetDownloadMode::ClientResolved(resolver) => {
                let candidates = self
                    .resolver
                    .resolve(resolver, &canonical, port, request.deadline())
                    .await?;
                RuleSetDialTargets::Resolved(candidates.into_boxed_slice())
            }
            RuleSetDownloadMode::DeferredToDetour => RuleSetDialTargets::Domain(
                TargetAddr::domain(host, port)
                    .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Redirect))?,
            ),
        };
        let io = self
            .dialer
            .connect(&targets, request.detour(), request.deadline())
            .await?;
        let server_name = ServerName::try_from(host.to_owned())
            .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Tls))?;
        let tls = tokio::time::timeout_at(request.deadline(), self.tls.connect(server_name, io))
            .await
            .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Timeout))?
            .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Tls))?;
        let (mut sender, connection) =
            tokio::time::timeout_at(request.deadline(), http1::handshake(TokioIo::new(tls)))
                .await
                .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Timeout))?
                .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Http))?;
        let mut connection: ConnectionFuture = Box::pin(async move {
            connection
                .await
                .map_err(|_| io::Error::other("RuleSet HTTP connection failed"))
        });

        let mut builder = Request::builder()
            .method(Method::GET)
            .uri(path_and_query(url))
            .header(HOST, authority(url)?)
            .header(USER_AGENT, HTTP_USER_AGENT)
            .header(CONNECTION, "close");
        if let Some(value) = request.if_none_match() {
            builder = builder.header(IF_NONE_MATCH, value);
        }
        if let Some(value) = request.if_modified_since() {
            builder = builder.header(IF_MODIFIED_SINCE, value);
        }
        let http_request = builder
            .body(Empty::<Bytes>::new())
            .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Http))?;
        let send = tokio::time::timeout_at(request.deadline(), sender.send_request(http_request));
        tokio::pin!(send);
        enum FirstCompletion {
            Response(
                Result<
                    Result<hyper::Response<Incoming>, hyper::Error>,
                    tokio::time::error::Elapsed,
                >,
            ),
            Connection(io::Result<()>),
        }
        let first = tokio::select! {
            biased;
            result = &mut send => FirstCompletion::Response(result),
            result = &mut connection => FirstCompletion::Connection(result),
        };
        let response = match first {
            FirstCompletion::Response(result) => result
                .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Timeout))?
                .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Http))?,
            FirstCompletion::Connection(result) => {
                let response = send
                    .await
                    .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Timeout))?
                    .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Http))?;
                connection = Box::pin(async move { result });
                response
            }
        };
        Ok(InternalResponse {
            response,
            connection,
        })
    }
}

fn validate_https_url(url: Url) -> Result<Url, RuleSetDownloadError> {
    if url.scheme() != "https"
        || !matches!(url.host(), Some(Host::Domain(_)))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        Err(RuleSetDownloadError::new(
            RuleSetDownloadErrorKind::Redirect,
        ))
    } else {
        Ok(url)
    }
}

fn path_and_query(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    }
}

fn authority(url: &Url) -> Result<String, RuleSetDownloadError> {
    let host = url
        .host_str()
        .ok_or_else(|| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Http))?;
    match url.port() {
        Some(port) if port != HTTPS_PORT => Ok(format!("{host}:{port}")),
        _ => Ok(host.to_owned()),
    }
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn header(
    headers: &hyper::HeaderMap,
    name: hyper::header::HeaderName,
) -> Result<Option<Box<str>>, RuleSetDownloadError> {
    headers
        .get(name)
        .map(|value| {
            value
                .to_str()
                .map(|value| value.into())
                .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Http))
        })
        .transpose()
}

type ConnectionFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

struct InternalResponse {
    response: hyper::Response<Incoming>,
    connection: ConnectionFuture,
}

type BodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, io::Error>> + Send>>;

struct HyperRuleSetBody {
    body: StreamReader<BodyStream, Bytes>,
    connection: Option<ConnectionFuture>,
}

impl HyperRuleSetBody {
    fn new(body: Incoming, connection: ConnectionFuture) -> Self {
        let body = body
            .into_data_stream()
            .map_err(|_| io::Error::other("RuleSet HTTP body failed"));
        Self {
            body: StreamReader::new(Box::pin(body)),
            connection: Some(connection),
        }
    }
}

impl AsyncRead for HyperRuleSetBody {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(connection) = self.connection.as_mut()
            && let Poll::Ready(result) = connection.as_mut().poll(context)
        {
            self.connection = None;
            result?;
        }
        Pin::new(&mut self.body).poll_read(context, buffer)
    }
}
