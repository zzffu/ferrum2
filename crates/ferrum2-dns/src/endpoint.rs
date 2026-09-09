use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU16;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ferrum2_core::CanonicalDomain;

use crate::{
    DnsAddressRecords, DnsCache, DnsCacheAnswer, DnsCacheError, DnsCacheKey, DnsCacheQtype,
    DnsError, DnsServerId, DnsStrategy, MAX_APPLICATION_RESOLVED_CANDIDATES, ResolverGeneration,
};

/// Explicit resolver identity for one fixed domain endpoint.
///
/// `System` is a deliberate bootstrap choice. `DnsServer` is a reference to
/// an earlier DNS-server endpoint in the caller-validated topological order.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResolverRef {
    /// Deliberately use the injected operating-system resolver backend.
    System,
    /// Use only the injected backend for this tagged DNS server.
    DnsServer(DnsServerId),
}

/// Role of one fixed endpoint in the materialization order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedEndpointKind {
    /// A DNS-server endpoint that may satisfy later `DnsServer` references.
    DnsServer(DnsServerId),
    /// A fixed Shadowsocks server endpoint.
    Shadowsocks,
    /// The HTTPS origin endpoint of a remote RuleSet URL.
    RuleSet,
}

#[derive(Clone)]
enum FixedEndpointTarget {
    Ip(SocketAddr),
    Domain {
        domain: CanonicalDomain,
        resolver: ResolverRef,
        strategy: DnsStrategy,
    },
}

/// Validated domain-or-IP fixed endpoint independent of configuration schema.
#[derive(Clone)]
pub struct FixedEndpointSpec {
    target: FixedEndpointTarget,
    port: NonZeroU16,
}

impl FixedEndpointSpec {
    /// Creates a numeric endpoint. Port zero is rejected before materialization.
    pub fn ip(address: SocketAddr) -> Result<Self, FixedEndpointSpecError> {
        let port = NonZeroU16::new(address.port()).ok_or(FixedEndpointSpecError::ZeroPort)?;
        Ok(Self {
            target: FixedEndpointTarget::Ip(address),
            port,
        })
    }

    /// Creates a domain endpoint with an explicit resolver and family strategy.
    pub const fn domain(
        domain: CanonicalDomain,
        port: NonZeroU16,
        resolver: ResolverRef,
        strategy: DnsStrategy,
    ) -> Self {
        Self {
            target: FixedEndpointTarget::Domain {
                domain,
                resolver,
                strategy,
            },
            port,
        }
    }

    /// Returns the original canonical domain retained for TLS SNI and HTTP Host.
    pub const fn domain_name(&self) -> Option<&CanonicalDomain> {
        match &self.target {
            FixedEndpointTarget::Ip(_) => None,
            FixedEndpointTarget::Domain { domain, .. } => Some(domain),
        }
    }

    /// Returns the explicit resolver for a domain endpoint.
    pub const fn resolver(&self) -> Option<ResolverRef> {
        match &self.target {
            FixedEndpointTarget::Ip(_) => None,
            FixedEndpointTarget::Domain { resolver, .. } => Some(*resolver),
        }
    }

    /// Returns the family strategy for a domain endpoint.
    pub const fn strategy(&self) -> Option<DnsStrategy> {
        match &self.target {
            FixedEndpointTarget::Ip(_) => None,
            FixedEndpointTarget::Domain { strategy, .. } => Some(*strategy),
        }
    }

    /// Returns the validated non-zero connection port.
    pub const fn port(&self) -> NonZeroU16 {
        self.port
    }

    /// Returns the complete numeric endpoint without performing a DNS query.
    pub const fn socket_addr(&self) -> Option<SocketAddr> {
        match &self.target {
            FixedEndpointTarget::Ip(address) => Some(*address),
            FixedEndpointTarget::Domain { .. } => None,
        }
    }
}

impl fmt::Debug for FixedEndpointSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("FixedEndpointSpec");
        match &self.target {
            FixedEndpointTarget::Ip(_) => {
                debug.field("target", &"[redacted]");
            }
            FixedEndpointTarget::Domain {
                resolver, strategy, ..
            } => {
                debug
                    .field("domain", &"[redacted]")
                    .field("resolver", resolver)
                    .field("strategy", strategy);
            }
        }
        debug.field("port", &"[redacted]").finish()
    }
}

/// Closed construction error for a fixed endpoint specification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedEndpointSpecError {
    /// Fixed connection endpoints may not use port zero.
    ZeroPort,
}

impl fmt::Display for FixedEndpointSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fixed endpoint port is zero")
    }
}

impl std::error::Error for FixedEndpointSpecError {}

/// One entry in a complete caller-supplied dependency/topological order.
#[derive(Clone, Debug)]
pub struct FixedEndpointPlanEntry {
    kind: FixedEndpointKind,
    spec: FixedEndpointSpec,
}

impl FixedEndpointPlanEntry {
    /// Creates one ordered fixed endpoint entry.
    pub const fn new(kind: FixedEndpointKind, spec: FixedEndpointSpec) -> Self {
        Self { kind, spec }
    }

    /// Returns the endpoint role.
    pub const fn kind(&self) -> FixedEndpointKind {
        self.kind
    }

    /// Returns the validated endpoint specification.
    pub const fn spec(&self) -> &FixedEndpointSpec {
        &self.spec
    }
}

/// One A or AAAA lookup request sent to an injected fixed-endpoint backend.
#[derive(Clone, Copy)]
pub struct FixedEndpointResolveRequest<'a> {
    domain: &'a CanonicalDomain,
    qtype: DnsCacheQtype,
}

impl<'a> FixedEndpointResolveRequest<'a> {
    fn new(domain: &'a CanonicalDomain, qtype: DnsCacheQtype) -> Self {
        Self { domain, qtype }
    }

    /// Returns the canonical query name.
    pub const fn domain(self) -> &'a CanonicalDomain {
        self.domain
    }

    /// Returns the independently queried address family.
    pub const fn qtype(self) -> DnsCacheQtype {
        self.qtype
    }
}

impl fmt::Debug for FixedEndpointResolveRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedEndpointResolveRequest")
            .field("domain", &"[redacted]")
            .field("qtype", &self.qtype)
            .finish()
    }
}

/// Positive or SOA-TTL-backed negative answer from a fixed-endpoint backend.
pub enum FixedEndpointLookup {
    /// Address records and their DNS response TTL.
    Positive {
        /// Typed A or AAAA records.
        records: DnsAddressRecords,
        /// Minimum validated TTL for the returned records.
        ttl: Duration,
    },
    /// NXDOMAIN or NODATA and its validated negative TTL.
    Negative {
        /// SOA-derived negative cache TTL.
        ttl: Duration,
    },
}

impl FixedEndpointLookup {
    /// Creates one positive typed lookup result.
    pub const fn positive(records: DnsAddressRecords, ttl: Duration) -> Self {
        Self::Positive { records, ttl }
    }

    /// Creates one negative lookup result.
    pub const fn negative(ttl: Duration) -> Self {
        Self::Negative { ttl }
    }
}

impl fmt::Debug for FixedEndpointLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Positive { records, ttl } => formatter
                .debug_struct("FixedEndpointLookup::Positive")
                .field("records", records)
                .field("ttl", ttl)
                .finish(),
            Self::Negative { ttl } => formatter
                .debug_struct("FixedEndpointLookup::Negative")
                .field("ttl", ttl)
                .finish(),
        }
    }
}

/// Owned future returned by a fixed-endpoint resolver backend.
pub type FixedEndpointResolveFuture<'a> =
    Pin<Box<dyn Future<Output = Result<FixedEndpointLookup, DnsError>> + Send + 'a>>;

/// Explicitly separated system and tagged-server fixed endpoint resolver seam.
pub trait FixedEndpointResolveBackend: Send + Sync + 'static {
    /// Resolves one family through an explicitly selected system bootstrap.
    fn resolve_system<'a>(
        &'a self,
        request: FixedEndpointResolveRequest<'a>,
    ) -> FixedEndpointResolveFuture<'a>;

    /// Resolves one family through only the selected tagged DNS server.
    ///
    /// `resolver_endpoint` is the already-materialized DNS-server dependency.
    /// An error from this method is terminal; the materializer never invokes
    /// `resolve_system` as a fallback.
    fn resolve_dns_server<'a>(
        &'a self,
        resolver: DnsServerId,
        resolver_endpoint: &'a MaterializedFixedEndpoint,
        request: FixedEndpointResolveRequest<'a>,
    ) -> FixedEndpointResolveFuture<'a>;

    /// Observes each completed entry before the next dependency is resolved.
    ///
    /// Client composition uses this ordered hook to publish a newly concrete
    /// Shadowsocks endpoint into its bootstrap egress graph. A later tagged
    /// DNS server or RuleSet download can therefore use only dependencies that
    /// the already-validated topological plan placed before it.
    fn endpoint_materialized(
        &self,
        _endpoint: &MaterializedFixedEndpoint,
    ) -> Result<(), FixedEndpointMaterializeError> {
        Ok(())
    }
}

/// One materialized fixed endpoint retaining its logical host and candidates.
#[derive(Clone)]
pub struct MaterializedFixedEndpoint {
    kind: FixedEndpointKind,
    spec: FixedEndpointSpec,
    candidates: Arc<[SocketAddr]>,
}

impl MaterializedFixedEndpoint {
    /// Returns the endpoint role supplied by the caller.
    pub const fn kind(&self) -> FixedEndpointKind {
        self.kind
    }

    /// Returns the original logical endpoint, including its domain when any.
    pub const fn spec(&self) -> &FixedEndpointSpec {
        &self.spec
    }

    /// Returns ordered, filtered concrete connection candidates.
    pub fn candidates(&self) -> &[SocketAddr] {
        &self.candidates
    }
}

impl fmt::Debug for MaterializedFixedEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializedFixedEndpoint")
            .field("kind", &self.kind)
            .field("spec", &self.spec)
            .field("candidate_count", &self.candidates.len())
            .field("candidates", &"[redacted]")
            .finish()
    }
}

/// Closed failure while validating or resolving a fixed endpoint plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedEndpointMaterializeError {
    /// Two entries provide the same DNS server identity.
    DuplicateDnsServer,
    /// A tagged resolver reference has no DNS-server endpoint in the full plan.
    MissingResolver,
    /// A dependency is not earlier in the supplied topological order.
    InvalidDependencyOrder,
    /// Bounded output or validation storage could not be reserved.
    Allocation,
    /// The selected backend returned a DNS failure.
    Resolve(DnsError),
    /// The shared cache was unavailable or rejected an entry.
    Cache(DnsCacheError),
    /// A backend returned empty or wrong-family positive records.
    InvalidAnswer,
    /// Resolution completed without an address permitted by the strategy.
    NoCandidates,
}

impl fmt::Display for FixedEndpointMaterializeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DuplicateDnsServer => "fixed endpoint DNS server is duplicated",
            Self::MissingResolver => "fixed endpoint resolver dependency is missing",
            Self::InvalidDependencyOrder => "fixed endpoint dependency order is invalid",
            Self::Allocation => "fixed endpoint materialization allocation failed",
            Self::Resolve(_) => "fixed endpoint DNS resolution failed",
            Self::Cache(_) => "fixed endpoint DNS cache failed",
            Self::InvalidAnswer => "fixed endpoint DNS answer is invalid",
            Self::NoCandidates => "fixed endpoint DNS returned no usable candidates",
        })
    }
}

impl std::error::Error for FixedEndpointMaterializeError {}

/// Validates that every tagged resolver exists exactly once and precedes all
/// of its dependants.
///
/// Configuration code remains responsible for constructing the complete
/// dependency graph and rejecting cycles. This defensive validation enforces
/// the resulting topological-order contract before any backend query occurs.
pub fn validate_fixed_endpoint_order(
    plan: &[FixedEndpointPlanEntry],
) -> Result<(), FixedEndpointMaterializeError> {
    validated_dns_server_positions(plan).map(|_| ())
}

/// Materializes a complete dependency order with the monotonic system clock.
pub async fn materialize_fixed_endpoints<B>(
    plan: &[FixedEndpointPlanEntry],
    backend: &B,
    cache: Option<&DnsCache>,
    generation: ResolverGeneration,
) -> Result<Vec<MaterializedFixedEndpoint>, FixedEndpointMaterializeError>
where
    B: FixedEndpointResolveBackend,
{
    materialize_fixed_endpoints_with_clock(plan, backend, cache, generation, Instant::now).await
}

/// Materializes a complete dependency order with an injected monotonic clock.
///
/// The shared server-scoped cache is used for `DnsServer` references. System
/// bootstrap is structurally separate and is never assigned a tagged-server
/// cache identity.
pub async fn materialize_fixed_endpoints_with_clock<B, N>(
    plan: &[FixedEndpointPlanEntry],
    backend: &B,
    cache: Option<&DnsCache>,
    generation: ResolverGeneration,
    now: N,
) -> Result<Vec<MaterializedFixedEndpoint>, FixedEndpointMaterializeError>
where
    B: FixedEndpointResolveBackend,
    N: Fn() -> Instant + Sync,
{
    let server_positions = validated_dns_server_positions(plan)?;
    let mut materialized = Vec::new();
    materialized
        .try_reserve(plan.len())
        .map_err(|_| FixedEndpointMaterializeError::Allocation)?;

    for entry in plan {
        let candidates: Arc<[SocketAddr]> = match &entry.spec.target {
            FixedEndpointTarget::Ip(address) => Arc::from([*address]),
            FixedEndpointTarget::Domain {
                domain,
                resolver,
                strategy,
            } => {
                let resolver_endpoint = match resolver {
                    ResolverRef::System => None,
                    ResolverRef::DnsServer(server) => {
                        let position = *server_positions
                            .get(server)
                            .ok_or(FixedEndpointMaterializeError::MissingResolver)?;
                        Some(
                            materialized
                                .get(position)
                                .ok_or(FixedEndpointMaterializeError::InvalidDependencyOrder)?,
                        )
                    }
                };
                let mut ipv4 = Vec::<Ipv4Addr>::new();
                let mut ipv6 = Vec::<Ipv6Addr>::new();
                for &qtype in strategy_qtypes(*strategy) {
                    let records = resolve_family(
                        backend,
                        cache,
                        generation,
                        &now,
                        *resolver,
                        resolver_endpoint,
                        domain,
                        qtype,
                    )
                    .await?;
                    match records {
                        Some(DnsAddressRecords::A(records)) => append_ipv4(&mut ipv4, &records),
                        Some(DnsAddressRecords::Aaaa(records)) => append_ipv6(&mut ipv6, &records),
                        None => {}
                    }
                }
                let mut candidates = strategy.socket_candidates(entry.spec.port, &ipv4, &ipv6);
                candidates.truncate(MAX_APPLICATION_RESOLVED_CANDIDATES);
                if candidates.is_empty() {
                    return Err(FixedEndpointMaterializeError::NoCandidates);
                }
                Arc::from(candidates)
            }
        };
        let endpoint = MaterializedFixedEndpoint {
            kind: entry.kind,
            spec: entry.spec.clone(),
            candidates,
        };
        backend.endpoint_materialized(&endpoint)?;
        materialized.push(endpoint);
    }
    Ok(materialized)
}

fn validated_dns_server_positions(
    plan: &[FixedEndpointPlanEntry],
) -> Result<HashMap<DnsServerId, usize>, FixedEndpointMaterializeError> {
    let mut positions = HashMap::new();
    positions
        .try_reserve(plan.len())
        .map_err(|_| FixedEndpointMaterializeError::Allocation)?;
    for (position, entry) in plan.iter().enumerate() {
        if let FixedEndpointKind::DnsServer(server) = entry.kind
            && positions.insert(server, position).is_some()
        {
            return Err(FixedEndpointMaterializeError::DuplicateDnsServer);
        }
    }
    for (position, entry) in plan.iter().enumerate() {
        let Some(ResolverRef::DnsServer(server)) = entry.spec.resolver() else {
            continue;
        };
        let dependency = positions
            .get(&server)
            .ok_or(FixedEndpointMaterializeError::MissingResolver)?;
        if *dependency >= position {
            return Err(FixedEndpointMaterializeError::InvalidDependencyOrder);
        }
    }
    Ok(positions)
}

const fn strategy_qtypes(strategy: DnsStrategy) -> &'static [DnsCacheQtype] {
    match strategy {
        DnsStrategy::PreferIpv4 => &[DnsCacheQtype::A, DnsCacheQtype::Aaaa],
        DnsStrategy::PreferIpv6 => &[DnsCacheQtype::Aaaa, DnsCacheQtype::A],
        DnsStrategy::Ipv4Only => &[DnsCacheQtype::A],
        DnsStrategy::Ipv6Only => &[DnsCacheQtype::Aaaa],
    }
}

fn append_ipv4(output: &mut Vec<Ipv4Addr>, records: &[Ipv4Addr]) {
    for address in records.iter().copied() {
        if output.len() == MAX_APPLICATION_RESOLVED_CANDIDATES {
            break;
        }
        if !output.contains(&address) {
            output.push(address);
        }
    }
}

fn append_ipv6(output: &mut Vec<Ipv6Addr>, records: &[Ipv6Addr]) {
    for address in records.iter().copied() {
        if output.len() == MAX_APPLICATION_RESOLVED_CANDIDATES {
            break;
        }
        if !output.contains(&address) {
            output.push(address);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn resolve_family<B, N>(
    backend: &B,
    cache: Option<&DnsCache>,
    generation: ResolverGeneration,
    now: &N,
    resolver: ResolverRef,
    resolver_endpoint: Option<&MaterializedFixedEndpoint>,
    domain: &CanonicalDomain,
    qtype: DnsCacheQtype,
) -> Result<Option<DnsAddressRecords>, FixedEndpointMaterializeError>
where
    B: FixedEndpointResolveBackend,
    N: Fn() -> Instant + Sync,
{
    let key = match resolver {
        ResolverRef::System => None,
        ResolverRef::DnsServer(server) => {
            Some(DnsCacheKey::new(server, domain.clone(), qtype, generation))
        }
    };
    if let (Some(cache), Some(key)) = (cache, key.as_ref()) {
        match cache
            .get(key, now())
            .map_err(FixedEndpointMaterializeError::Cache)?
        {
            Some(DnsCacheAnswer::Positive(records)) => return Ok(Some(records)),
            Some(DnsCacheAnswer::Negative) => return Ok(None),
            None => {}
        }
    }

    let request = FixedEndpointResolveRequest::new(domain, qtype);
    let lookup = match resolver {
        ResolverRef::System => backend.resolve_system(request).await,
        ResolverRef::DnsServer(server) => {
            let resolver_endpoint =
                resolver_endpoint.ok_or(FixedEndpointMaterializeError::InvalidDependencyOrder)?;
            backend
                .resolve_dns_server(server, resolver_endpoint, request)
                .await
        }
    }
    .map_err(FixedEndpointMaterializeError::Resolve)?;

    match lookup {
        FixedEndpointLookup::Positive { records, ttl } => {
            if records.qtype() != qtype || records.is_empty() {
                return Err(FixedEndpointMaterializeError::InvalidAnswer);
            }
            if let (Some(cache), Some(key)) = (cache, key) {
                cache
                    .insert_positive(key, records.clone(), ttl, now())
                    .map_err(FixedEndpointMaterializeError::Cache)?;
            }
            Ok(Some(records))
        }
        FixedEndpointLookup::Negative { ttl } => {
            if let (Some(cache), Some(key)) = (cache, key) {
                cache
                    .insert_negative(key, ttl, now())
                    .map_err(FixedEndpointMaterializeError::Cache)?;
            }
            Ok(None)
        }
    }
}
