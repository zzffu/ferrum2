use std::fmt;
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU16;
use std::pin::Pin;
use std::sync::Arc;

use ferrum2_core::CanonicalDomain;
use ferrum2_core::route::Network;

use crate::DnsError;

/// Maximum number of ordered socket candidates returned by the system backend.
pub const MAX_APPLICATION_RESOLVED_CANDIDATES: usize = 16;

/// Address-family ordering and filtering for application-target resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsStrategy {
    /// Return IPv4 candidates before IPv6 candidates.
    PreferIpv4,
    /// Return IPv6 candidates before IPv4 candidates.
    PreferIpv6,
    /// Return only IPv4 candidates.
    Ipv4Only,
    /// Return only IPv6 candidates.
    Ipv6Only,
}

impl DnsStrategy {
    /// Returns the stable configuration spelling for this strategy.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreferIpv4 => "prefer_ipv4",
            Self::PreferIpv6 => "prefer_ipv6",
            Self::Ipv4Only => "ipv4_only",
            Self::Ipv6Only => "ipv6_only",
        }
    }

    /// Orders and filters already-resolved address families without changing
    /// the relative order inside either family.
    pub fn socket_candidates(
        self,
        port: NonZeroU16,
        ipv4: &[Ipv4Addr],
        ipv6: &[Ipv6Addr],
    ) -> Vec<SocketAddr> {
        let capacity = match self {
            Self::PreferIpv4 | Self::PreferIpv6 => ipv4.len().saturating_add(ipv6.len()),
            Self::Ipv4Only => ipv4.len(),
            Self::Ipv6Only => ipv6.len(),
        };
        let mut candidates = Vec::with_capacity(capacity);
        let extend_ipv4 = |candidates: &mut Vec<SocketAddr>| {
            candidates.extend(
                ipv4.iter()
                    .copied()
                    .map(|address| SocketAddr::new(address.into(), port.get())),
            );
        };
        let extend_ipv6 = |candidates: &mut Vec<SocketAddr>| {
            candidates.extend(
                ipv6.iter()
                    .copied()
                    .map(|address| SocketAddr::new(address.into(), port.get())),
            );
        };
        match self {
            Self::PreferIpv4 => {
                extend_ipv4(&mut candidates);
                extend_ipv6(&mut candidates);
            }
            Self::PreferIpv6 => {
                extend_ipv6(&mut candidates);
                extend_ipv4(&mut candidates);
            }
            Self::Ipv4Only => extend_ipv4(&mut candidates),
            Self::Ipv6Only => extend_ipv6(&mut candidates),
        }
        candidates
    }
}

impl std::str::FromStr for DnsStrategy {
    type Err = DnsStrategyParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "prefer_ipv4" => Ok(Self::PreferIpv4),
            "prefer_ipv6" => Ok(Self::PreferIpv6),
            "ipv4_only" => Ok(Self::Ipv4Only),
            "ipv6_only" => Ok(Self::Ipv6Only),
            _ => Err(DnsStrategyParseError),
        }
    }
}

/// Closed failure to parse a DNS strategy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsStrategyParseError;

impl fmt::Display for DnsStrategyParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid DNS strategy")
    }
}

impl std::error::Error for DnsStrategyParseError {}

/// Application-target resolution mode selected from the presence of `[dns]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationResolverMode {
    /// The root configuration has no DNS section and explicitly permits the
    /// operating-system resolver for application targets.
    System,
    /// The root configuration has a DNS section and uses only its injected
    /// Ferrum2 resolver backend.
    Configured,
}

/// Closed application-resolution outcome for identity-free telemetry adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationResolveOutcome {
    Success,
    Failure,
}

/// Observer for application resolution. Domains, ports, and ingress identities
/// are intentionally absent from this seam.
pub trait ApplicationResolveObserver: Send + Sync + 'static {
    fn record(&self, mode: ApplicationResolverMode, outcome: ApplicationResolveOutcome);
}

impl<F> ApplicationResolveObserver for F
where
    F: Fn(ApplicationResolverMode, ApplicationResolveOutcome) + Send + Sync + 'static,
{
    fn record(&self, mode: ApplicationResolverMode, outcome: ApplicationResolveOutcome) {
        self(mode, outcome);
    }
}

/// Authenticated routing context for one application-target lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationResolveContext {
    ingress: usize,
    network: Network,
}

impl ApplicationResolveContext {
    /// Creates context for one validated application ingress and transport.
    pub const fn new(ingress: usize, network: Network) -> Self {
        Self { ingress, network }
    }

    /// Returns the validated ordinary ingress identity.
    pub const fn ingress(self) -> usize {
        self.ingress
    }

    /// Returns whether TCP or UDP initiated resolution.
    pub const fn network(self) -> Network {
        self.network
    }
}

/// One normalized application-target resolution request.
#[derive(Clone, Copy)]
pub struct ApplicationResolveRequest<'a> {
    context: ApplicationResolveContext,
    domain: &'a CanonicalDomain,
    port: NonZeroU16,
    strategy: DnsStrategy,
}

impl<'a> ApplicationResolveRequest<'a> {
    /// Creates one request from an already validated domain and non-zero port.
    pub const fn new(
        context: ApplicationResolveContext,
        domain: &'a CanonicalDomain,
        port: NonZeroU16,
        strategy: DnsStrategy,
    ) -> Self {
        Self {
            context,
            domain,
            port,
            strategy,
        }
    }

    /// Returns the authenticated application routing context.
    pub const fn context(self) -> ApplicationResolveContext {
        self.context
    }

    /// Returns the validated application domain.
    pub const fn domain(self) -> &'a CanonicalDomain {
        self.domain
    }

    /// Returns the non-zero application port.
    pub const fn port(self) -> NonZeroU16 {
        self.port
    }

    /// Returns the selected family strategy.
    pub const fn strategy(self) -> DnsStrategy {
        self.strategy
    }
}

impl fmt::Debug for ApplicationResolveRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationResolveRequest")
            .field("context", &self.context)
            .field("domain", &"[redacted]")
            .field("port", &"[redacted]")
            .field("strategy", &self.strategy)
            .finish()
    }
}

/// Owned future returned by an injectable application resolver backend.
pub type ApplicationResolveFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, DnsError>> + Send + 'a>>;

/// Injectable system or configured resolver implementation.
pub trait ApplicationResolveBackend: Send + Sync + 'static {
    /// Resolves one application request into ordered socket candidates.
    fn resolve<'a>(
        &'a self,
        request: ApplicationResolveRequest<'a>,
    ) -> ApplicationResolveFuture<'a>;
}

/// Mode-bound application resolver.
///
/// The selected mode owns exactly one backend. In particular, a configured
/// instance has no system backend to fall back to after a configured failure.
#[derive(Clone)]
pub struct ApplicationResolver {
    mode: ApplicationResolverMode,
    backend: Arc<dyn ApplicationResolveBackend>,
    observer: Option<Arc<dyn ApplicationResolveObserver>>,
}

impl ApplicationResolver {
    /// Creates an explicit system-mode resolver with an injected backend.
    pub fn system(backend: Arc<dyn ApplicationResolveBackend>) -> Self {
        Self {
            mode: ApplicationResolverMode::System,
            backend,
            observer: None,
        }
    }

    /// Creates a configured-mode resolver with an injected Ferrum2 backend.
    pub fn configured(backend: Arc<dyn ApplicationResolveBackend>) -> Self {
        Self {
            mode: ApplicationResolverMode::Configured,
            backend,
            observer: None,
        }
    }

    /// Creates the production operating-system resolver mode.
    pub fn system_default() -> Self {
        Self::system(Arc::new(SystemApplicationResolveBackend))
    }

    /// Installs one identity-free observer shared by every clone.
    pub fn with_observer(mut self, observer: Arc<dyn ApplicationResolveObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Returns the immutable application resolver mode.
    pub const fn mode(&self) -> ApplicationResolverMode {
        self.mode
    }

    /// Resolves through only the backend bound to this mode.
    pub fn resolve<'a>(
        &'a self,
        request: ApplicationResolveRequest<'a>,
    ) -> ApplicationResolveFuture<'a> {
        Box::pin(async move {
            let result = self.backend.resolve(request).await;
            if let Some(observer) = &self.observer {
                observer.record(
                    self.mode,
                    if result.is_ok() {
                        ApplicationResolveOutcome::Success
                    } else {
                        ApplicationResolveOutcome::Failure
                    },
                );
            }
            result
        })
    }
}

impl fmt::Debug for ApplicationResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationResolver")
            .field("mode", &self.mode)
            .field("backend", &"[redacted]")
            .finish()
    }
}

/// Production Tokio operating-system resolver backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemApplicationResolveBackend;

impl ApplicationResolveBackend for SystemApplicationResolveBackend {
    fn resolve<'a>(
        &'a self,
        request: ApplicationResolveRequest<'a>,
    ) -> ApplicationResolveFuture<'a> {
        Box::pin(async move {
            let resolved =
                tokio::net::lookup_host((request.domain().as_str(), request.port().get()))
                    .await
                    .map_err(|_| DnsError::Transport)?;
            let mut ipv4 = Vec::with_capacity(MAX_APPLICATION_RESOLVED_CANDIDATES);
            let mut ipv6 = Vec::with_capacity(MAX_APPLICATION_RESOLVED_CANDIDATES);
            for candidate in resolved {
                match candidate.ip() {
                    std::net::IpAddr::V4(address)
                        if ipv4.len() < MAX_APPLICATION_RESOLVED_CANDIDATES
                            && !ipv4.contains(&address) =>
                    {
                        ipv4.push(address);
                    }
                    std::net::IpAddr::V6(address)
                        if ipv6.len() < MAX_APPLICATION_RESOLVED_CANDIDATES
                            && !ipv6.contains(&address) =>
                    {
                        ipv6.push(address);
                    }
                    _ => {}
                }
                if ipv4.len() == MAX_APPLICATION_RESOLVED_CANDIDATES
                    && ipv6.len() == MAX_APPLICATION_RESOLVED_CANDIDATES
                {
                    break;
                }
            }
            let mut candidates = request
                .strategy()
                .socket_candidates(request.port(), &ipv4, &ipv6);
            candidates.truncate(MAX_APPLICATION_RESOLVED_CANDIDATES);
            if candidates.is_empty() {
                Err(DnsError::NoData)
            } else {
                Ok(candidates)
            }
        })
    }
}
