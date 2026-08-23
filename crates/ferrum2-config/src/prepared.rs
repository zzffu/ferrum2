//! Side-effect-free schema-v2 preparation.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use ferrum2_core::{CanonicalDomain, DomainName, TargetAddr, TargetHostRef};
use ferrum2_crypto::{MethodPsk, TcpMethodProfile};
use ferrum2_rule::{
    CompiledMatchSet, DnsPolicyActionDescriptor, DnsPolicyAddressStrategy, DnsPolicyBlueprint,
    DnsPolicyBlueprintError, DnsPolicyMatcherDescriptor, DnsPolicyRouteDescriptor,
    DnsPolicyRuleDescriptor, EgressPlanHandle, MatchSetBuilder, Network, PortRange,
    RuleCompileError, RuleEngineRegistry, RuleEngineSnapshotBuilder, RuleSetId,
};

use crate::dependency::{DependencyGraph, DependencyGraphError, DependencyNode, DependencySource};
use crate::error::{ConfigError, ConfigField};
use crate::load::{parse_v2_toml, read_bounded_utf8};
use crate::model::{
    ClientOutboundConfig, DirectDomainResolver, DnsCacheConfig, DnsEndpointMode, DnsQueryType,
    DnsRuntimeConfig, DnsStrategy, DnsTransport, ResolverRef, RuntimeConfig, UdpConfig,
    ValidatedClientConfig, ValidatedServerConfig,
};
use crate::raw::{
    RawChain, RawClientOutbound, RawClientRoot, RawDns, RawDnsRouteRule, RawRoute, RawRuleSet,
    RawRuleSetLoader, RawSelector, RawServerRoot, ScalarOrList,
};
use crate::validation::{
    finish_client_tun_targets, validate_client_prepared, validate_direct_domain_resolver,
    validate_finished_client_endpoints, validate_route_target, validate_server_prepared,
    validate_tag,
};

const DEFAULT_RULE_SET_CACHE_DIR: &str = "./rule-set-cache";
const DEFAULT_RULE_SET_DOWNLOAD_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_RULE_SET_MAX_REDIRECTS: u8 = 5;
const PLACEHOLDER_ENDPOINT: &str = "192.0.2.254:9";
const PLACEHOLDER_DOMAIN: &str = "prepared.invalid";
const MAX_RESOLVED_DNS_CANDIDATES: usize = 16;

/// Validated fixed endpoint retained without performing DNS I/O.
#[derive(Clone, Eq, PartialEq)]
pub enum DialEndpoint {
    Ip(SocketAddr),
    Domain {
        host: CanonicalDomain,
        port: NonZeroU16,
        resolver: ResolverRef,
        strategy: DnsStrategy,
    },
}

impl DialEndpoint {
    pub const fn resolver(&self) -> Option<ResolverRef> {
        match self {
            Self::Ip(_) => None,
            Self::Domain { resolver, .. } => Some(*resolver),
        }
    }

    pub const fn strategy(&self) -> Option<DnsStrategy> {
        match self {
            Self::Ip(_) => None,
            Self::Domain { strategy, .. } => Some(*strategy),
        }
    }

    pub const fn is_domain(&self) -> bool {
        matches!(self, Self::Domain { .. })
    }
}

impl std::fmt::Debug for DialEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Ip(_) => "DialEndpoint::Ip([redacted])",
            Self::Domain { .. } => "DialEndpoint::Domain([redacted])",
        })
    }
}

/// Closed preparation mode for one DNS upstream target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedDnsEndpointMode {
    Numeric,
    ClientResolved {
        resolver: ResolverRef,
        strategy: DnsStrategy,
    },
    DeferredToDetour,
}

/// Validated DNS upstream target retained without performing DNS I/O.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedDnsEndpoint {
    target: TargetAddr,
    mode: PreparedDnsEndpointMode,
    fixed_endpoint: Option<DialEndpoint>,
}

impl PreparedDnsEndpoint {
    pub fn target(&self) -> &TargetAddr {
        &self.target
    }

    pub const fn mode(&self) -> PreparedDnsEndpointMode {
        self.mode
    }

    pub const fn resolver(&self) -> Option<ResolverRef> {
        match self.mode {
            PreparedDnsEndpointMode::ClientResolved { resolver, .. } => Some(resolver),
            PreparedDnsEndpointMode::Numeric | PreparedDnsEndpointMode::DeferredToDetour => None,
        }
    }

    pub const fn strategy(&self) -> Option<DnsStrategy> {
        match self.mode {
            PreparedDnsEndpointMode::ClientResolved { strategy, .. } => Some(strategy),
            PreparedDnsEndpointMode::Numeric | PreparedDnsEndpointMode::DeferredToDetour => None,
        }
    }

    pub const fn is_domain(&self) -> bool {
        !matches!(self.mode, PreparedDnsEndpointMode::Numeric)
    }

    const fn fixed_endpoint(&self) -> Option<&DialEndpoint> {
        self.fixed_endpoint.as_ref()
    }
}

impl std::fmt::Debug for PreparedDnsEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedDnsEndpoint")
            .field("mode", &self.mode)
            .field("target", &"[redacted]")
            .finish()
    }
}

/// Stable resource identity for an endpoint materialized from a dependency step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedFixedEndpointTarget {
    DnsServer(u32),
    Outbound(u32),
}

/// Redacted, borrowed endpoint declaration for one materialization step.
#[derive(Clone, Copy)]
pub struct PreparedFixedEndpointDescriptor<'a> {
    target: PreparedFixedEndpointTarget,
    endpoint: &'a DialEndpoint,
}

impl<'a> PreparedFixedEndpointDescriptor<'a> {
    const fn new(target: PreparedFixedEndpointTarget, endpoint: &'a DialEndpoint) -> Self {
        Self { target, endpoint }
    }

    pub const fn target(self) -> PreparedFixedEndpointTarget {
        self.target
    }

    pub const fn endpoint(self) -> &'a DialEndpoint {
        self.endpoint
    }
}

impl std::fmt::Debug for PreparedFixedEndpointDescriptor<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedFixedEndpointDescriptor")
            .field("target", &self.target)
            .field("endpoint", &"[redacted]")
            .finish()
    }
}

/// Redacted, borrowed runtime description of one validated DNS upstream.
#[derive(Clone, Copy)]
pub struct PreparedDnsServerDescriptor<'a> {
    index: u32,
    transport: DnsTransport,
    server_name: Option<&'a str>,
    path: Option<&'a str>,
    detour: Option<&'a EgressPlanHandle>,
    endpoint: &'a PreparedDnsEndpoint,
}

impl<'a> PreparedDnsServerDescriptor<'a> {
    pub const fn index(self) -> u32 {
        self.index
    }

    pub const fn transport(self) -> DnsTransport {
        self.transport
    }

    pub const fn server_name(self) -> Option<&'a str> {
        self.server_name
    }

    pub const fn path(self) -> Option<&'a str> {
        self.path
    }

    pub const fn detour(self) -> Option<&'a EgressPlanHandle> {
        self.detour
    }

    pub const fn endpoint(self) -> &'a PreparedDnsEndpoint {
        self.endpoint
    }
}

impl std::fmt::Debug for PreparedDnsServerDescriptor<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedDnsServerDescriptor")
            .field("index", &self.index)
            .field("transport", &self.transport)
            .field("server_name", &self.server_name.map(|_| "[redacted]"))
            .field("path", &self.path.map(|_| "[redacted]"))
            .field("detour", &self.detour.map(|_| "[redacted]"))
            .field("endpoint", &"[redacted]")
            .finish()
    }
}

/// Closed client outbound kind available during bootstrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedClientOutboundKind {
    Direct,
    Shadowsocks,
}

/// Redacted, borrowed bootstrap description of one client outbound.
#[derive(Clone, Copy)]
pub struct PreparedClientOutboundDescriptor<'a> {
    index: u32,
    kind: PreparedClientOutboundKind,
    method: Option<TcpMethodProfile>,
    psk: Option<&'a Arc<MethodPsk>>,
    endpoint: Option<&'a DialEndpoint>,
    domain_resolver: Option<DirectDomainResolver>,
}

impl<'a> PreparedClientOutboundDescriptor<'a> {
    pub const fn index(self) -> u32 {
        self.index
    }

    pub const fn kind(self) -> PreparedClientOutboundKind {
        self.kind
    }

    pub const fn method(self) -> Option<TcpMethodProfile> {
        self.method
    }

    /// Borrows the shared, zeroizing PSK owner for a staged Shadowsocks egress.
    pub const fn psk(self) -> Option<&'a Arc<MethodPsk>> {
        self.psk
    }

    pub const fn endpoint(self) -> Option<&'a DialEndpoint> {
        self.endpoint
    }

    pub const fn domain_resolver(self) -> Option<DirectDomainResolver> {
        self.domain_resolver
    }
}

impl std::fmt::Debug for PreparedClientOutboundDescriptor<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedClientOutboundDescriptor")
            .field("index", &self.index)
            .field("kind", &self.kind)
            .field("method", &self.method)
            .field("psk", &self.psk.map(|_| "[redacted]"))
            .field("endpoint", &self.endpoint.map(|_| "[redacted]"))
            .field("domain_resolver", &self.domain_resolver)
            .finish()
    }
}

/// Redacted bootstrap description of one server Direct outbound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedServerOutboundDescriptor {
    index: u32,
    domain_resolver: DirectDomainResolver,
}

impl PreparedServerOutboundDescriptor {
    pub const fn index(self) -> u32 {
        self.index
    }

    pub const fn domain_resolver(self) -> DirectDomainResolver {
        self.domain_resolver
    }
}

/// Static RuleSet loader settings; no directory is touched during preparation.
#[derive(Clone, Eq, PartialEq)]
pub struct RuleSetLoaderConfig {
    pub cache_dir: PathBuf,
    pub download_timeout: Duration,
    pub max_redirects: u8,
}

impl std::fmt::Debug for RuleSetLoaderConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuleSetLoaderConfig")
            .field("cache_dir", &"[redacted]")
            .field("download_timeout", &self.download_timeout)
            .field("max_redirects", &self.max_redirects)
            .finish()
    }
}

/// Stable egress reference used by a prepared RuleSet download.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedEgressRef {
    Outbound(usize),
    Selector(usize),
    Chain(usize),
}

#[derive(Default)]
struct PreparedEgressCapabilities {
    outbounds: Vec<bool>,
    selectors: Vec<bool>,
    chains: Vec<bool>,
}

impl PreparedEgressCapabilities {
    fn get(&self, egress: PreparedEgressRef) -> Option<bool> {
        match egress {
            PreparedEgressRef::Outbound(index) => self.outbounds.get(index),
            PreparedEgressRef::Selector(index) => self.selectors.get(index),
            PreparedEgressRef::Chain(index) => self.chains.get(index),
        }
        .copied()
    }
}

/// Redacted, stable materialization step returned in dependency-first order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PreparedDependencyNode {
    SystemResolver,
    DnsServer(u32),
    Outbound(u32),
    Selector(u32),
    Chain(u32),
    RuleSet(u32),
}

impl From<DependencyNode> for PreparedDependencyNode {
    fn from(node: DependencyNode) -> Self {
        match node {
            DependencyNode::SystemResolver => Self::SystemResolver,
            DependencyNode::DnsServer(index) => Self::DnsServer(index),
            DependencyNode::Outbound(index) => Self::Outbound(index),
            DependencyNode::Selector(index) => Self::Selector(index),
            DependencyNode::Chain(index) => Self::Chain(index),
            DependencyNode::RuleSet(index) => Self::RuleSet(index),
        }
    }
}

/// One statically validated remote binary RuleSet declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedRuleSetDownloadMode {
    ClientResolved { resolver: ResolverRef },
    DeferredToDetour,
}

/// One statically validated remote binary RuleSet declaration.
pub struct PreparedRuleSet {
    tag: Box<str>,
    url: Box<str>,
    download_mode: PreparedRuleSetDownloadMode,
    download_detour: Option<PreparedEgressRef>,
    update_interval: Option<Duration>,
}

impl PreparedRuleSet {
    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub const fn download_mode(&self) -> PreparedRuleSetDownloadMode {
        self.download_mode
    }

    pub const fn download_resolver(&self) -> Option<ResolverRef> {
        match self.download_mode {
            PreparedRuleSetDownloadMode::ClientResolved { resolver } => Some(resolver),
            PreparedRuleSetDownloadMode::DeferredToDetour => None,
        }
    }

    pub const fn download_detour(&self) -> Option<PreparedEgressRef> {
        self.download_detour
    }

    pub const fn update_interval(&self) -> Option<Duration> {
        self.update_interval
    }
}

impl std::fmt::Debug for PreparedRuleSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedRuleSet([redacted])")
    }
}

/// Stable RuleSet references retained by one ordinary route row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRouteRuleSets {
    pub rule_index: usize,
    pub rule_sets: Vec<usize>,
}

/// Closed DNS action retained until the RuleSet snapshot is materialized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedDnsAction {
    Route { server: usize },
    Reject,
}

#[derive(Clone)]
struct PreparedDnsMatcherDraft {
    query_fields: Vec<Arc<CompiledMatchSet>>,
    inbounds: Vec<usize>,
    networks: Vec<Network>,
    qtypes: Vec<u16>,
    ports: Vec<NonZeroU16>,
    port_ranges: Vec<PortRange>,
    dns_eligible: bool,
}

/// One statically compiled DNS row whose RuleSet matcher is deferred.
#[derive(Clone)]
pub struct PreparedDnsRule {
    pub rule_index: usize,
    pub rule_sets: Vec<usize>,
    pub action: PreparedDnsAction,
    pub strategy: DnsStrategy,
    matcher: PreparedDnsMatcherDraft,
}

impl std::fmt::Debug for PreparedDnsRule {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedDnsRule([redacted])")
    }
}

/// Ordered selected IP endpoints for a prepared domain-valued DNS server.
#[derive(Clone, Eq, PartialEq)]
pub struct ResolvedDnsEndpoint {
    server: u32,
    addresses: Box<[SocketAddr]>,
}

impl ResolvedDnsEndpoint {
    pub fn new(server: u32, address: SocketAddr) -> Self {
        Self {
            server,
            addresses: Box::new([address]),
        }
    }

    pub fn from_candidates(server: u32, addresses: Box<[SocketAddr]>) -> Self {
        Self { server, addresses }
    }

    pub const fn server(&self) -> u32 {
        self.server
    }

    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }

    pub fn address(&self) -> Option<SocketAddr> {
        self.addresses.first().copied()
    }
}

impl std::fmt::Debug for ResolvedDnsEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResolvedDnsEndpoint([redacted])")
    }
}

/// One selected IP endpoint for a prepared domain-valued client outbound.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ResolvedOutboundEndpoint {
    outbound: u32,
    address: SocketAddr,
}

impl ResolvedOutboundEndpoint {
    pub const fn new(outbound: u32, address: SocketAddr) -> Self {
        Self { outbound, address }
    }

    pub const fn outbound(&self) -> u32 {
        self.outbound
    }

    pub const fn address(&self) -> SocketAddr {
        self.address
    }
}

impl std::fmt::Debug for ResolvedOutboundEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResolvedOutboundEndpoint([redacted])")
    }
}

/// One compiled RuleSet resource in declaration order.
pub struct CompiledRuleSetResource {
    rule_set: u32,
    match_set: Arc<CompiledMatchSet>,
    generation: u64,
}

impl CompiledRuleSetResource {
    pub fn new(rule_set: u32, match_set: Arc<CompiledMatchSet>, generation: u64) -> Self {
        Self {
            rule_set,
            match_set,
            generation,
        }
    }

    pub const fn rule_set(&self) -> u32 {
        self.rule_set
    }

    pub fn match_set(&self) -> &Arc<CompiledMatchSet> {
        &self.match_set
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

impl std::fmt::Debug for CompiledRuleSetResource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CompiledRuleSetResource([redacted])")
    }
}

/// Complete, closed resource input for [`finish_client_v2`].
#[derive(Debug, Default)]
pub struct ClientV2Resources {
    dns_endpoints: Vec<ResolvedDnsEndpoint>,
    outbound_endpoints: Vec<ResolvedOutboundEndpoint>,
    rule_sets: Vec<CompiledRuleSetResource>,
}

impl ClientV2Resources {
    pub const fn new(
        dns_endpoints: Vec<ResolvedDnsEndpoint>,
        outbound_endpoints: Vec<ResolvedOutboundEndpoint>,
        rule_sets: Vec<CompiledRuleSetResource>,
    ) -> Self {
        Self {
            dns_endpoints,
            outbound_endpoints,
            rule_sets,
        }
    }
}

/// Complete, closed resource input for [`finish_server_v2`].
#[derive(Debug, Default)]
pub struct ServerV2Resources {
    dns_endpoints: Vec<ResolvedDnsEndpoint>,
    rule_sets: Vec<CompiledRuleSetResource>,
}

impl ServerV2Resources {
    pub const fn new(
        dns_endpoints: Vec<ResolvedDnsEndpoint>,
        rule_sets: Vec<CompiledRuleSetResource>,
    ) -> Self {
        Self {
            dns_endpoints,
            rule_sets,
        }
    }
}

/// Closed future returned by a client V2 resource materializer.
pub type ClientV2MaterializeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ClientV2Resources, ConfigError>> + Send + 'a>>;

/// Injected client V2 resource materializer. The config crate performs no I/O itself.
pub trait ClientV2MaterializeContext: Send + Sync {
    fn materialize_client<'a>(
        &'a self,
        prepared: &'a PreparedClientV2,
    ) -> ClientV2MaterializeFuture<'a>;
}

/// Closed future returned by a server V2 resource materializer.
pub type ServerV2MaterializeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ServerV2Resources, ConfigError>> + Send + 'a>>;

/// Injected server V2 resource materializer. The config crate performs no I/O itself.
pub trait ServerV2MaterializeContext: Send + Sync {
    fn materialize_server<'a>(
        &'a self,
        prepared: &'a PreparedServerV2,
    ) -> ServerV2MaterializeFuture<'a>;
}

/// Side-effect-free client schema-v2 preparation result.
pub struct PreparedClientV2 {
    validated: ValidatedClientConfig,
    physical_first_hops: Vec<usize>,
    direct_detours: Vec<bool>,
    dependency_egress_plans: Vec<EgressPlanHandle>,
    dependency_egress_direct: Vec<bool>,
    rule_set_detour_plans: Vec<Option<usize>>,
    rule_set_loader: RuleSetLoaderConfig,
    rule_sets: Vec<PreparedRuleSet>,
    route_rule_sets: Vec<PreparedRouteRuleSets>,
    dns_rules: Vec<PreparedDnsRule>,
    dns_final_server: Option<usize>,
    dns_strategy: Option<DnsStrategy>,
    dns_cache: Option<DnsCacheConfig>,
    outbound_endpoints: Vec<Option<DialEndpoint>>,
    dns_endpoints: Vec<PreparedDnsEndpoint>,
    egress_domain_capabilities: PreparedEgressCapabilities,
    dependency_order: Vec<PreparedDependencyNode>,
}

/// Side-effect-free server schema-v2 preparation result.
pub struct PreparedServerV2 {
    validated: ValidatedServerConfig,
    dependency_egress_plans: Vec<EgressPlanHandle>,
    dependency_egress_direct: Vec<bool>,
    rule_set_detour_plans: Vec<Option<usize>>,
    rule_set_loader: RuleSetLoaderConfig,
    rule_sets: Vec<PreparedRuleSet>,
    route_rule_sets: Vec<PreparedRouteRuleSets>,
    dns_rules: Vec<PreparedDnsRule>,
    dns_final_server: Option<usize>,
    dns_strategy: Option<DnsStrategy>,
    dns_cache: Option<DnsCacheConfig>,
    dns_endpoints: Vec<PreparedDnsEndpoint>,
    egress_domain_capabilities: PreparedEgressCapabilities,
    dependency_order: Vec<PreparedDependencyNode>,
}

impl std::fmt::Debug for PreparedClientV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedClientV2([redacted])")
    }
}

impl std::fmt::Debug for PreparedServerV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedServerV2([redacted])")
    }
}

macro_rules! prepared_accessors {
    ($type:ty) => {
        impl $type {
            pub const fn rule_set_loader(&self) -> &RuleSetLoaderConfig {
                &self.rule_set_loader
            }

            pub fn rule_sets(&self) -> &[PreparedRuleSet] {
                &self.rule_sets
            }

            pub fn route_rule_sets(&self) -> &[PreparedRouteRuleSets] {
                &self.route_rule_sets
            }

            pub fn dns_rules(&self) -> &[PreparedDnsRule] {
                &self.dns_rules
            }

            pub const fn dns_strategy(&self) -> Option<DnsStrategy> {
                self.dns_strategy
            }

            pub const fn dns_cache(&self) -> Option<DnsCacheConfig> {
                self.dns_cache
            }

            pub fn dns_endpoints(&self) -> &[PreparedDnsEndpoint] {
                &self.dns_endpoints
            }

            /// Reports the statically aggregated domain-target capability.
            pub fn accepts_domain_target(&self, egress: PreparedEgressRef) -> Option<bool> {
                self.egress_domain_capabilities.get(egress)
            }

            pub fn dns_runtime(&self) -> Option<DnsRuntimeConfig> {
                self.validated.dns.as_ref().map(|dns| dns.runtime)
            }

            /// Returns the validated per-query DNS deadline, when DNS is configured.
            pub fn dns_timeout(&self) -> Option<Duration> {
                self.validated.dns.as_ref().map(|dns| dns.timeout)
            }

            /// Returns the validated DNS admission limit, when DNS is configured.
            pub fn dns_max_inflight(&self) -> Option<NonZeroU16> {
                self.validated.dns.as_ref().map(|dns| dns.max_inflight)
            }

            pub const fn runtime(&self) -> RuntimeConfig {
                self.validated.runtime
            }

            pub fn dns_server_count(&self) -> usize {
                self.validated
                    .dns
                    .as_ref()
                    .map_or(0, |dns| dns.servers.len())
            }

            pub fn dns_server(&self, index: u32) -> Option<PreparedDnsServerDescriptor<'_>> {
                let index_usize = usize::try_from(index).ok()?;
                let server = self.validated.dns.as_ref()?.servers.get(index_usize)?;
                let endpoint = self.dns_endpoints.get(index_usize)?;
                Some(PreparedDnsServerDescriptor {
                    index,
                    transport: server.transport,
                    server_name: server.server_name.as_deref(),
                    path: server.path.as_deref(),
                    detour: server.detour.as_ref(),
                    endpoint,
                })
            }

            pub fn dependency_node_count(&self) -> usize {
                self.dependency_order.len()
            }

            pub fn materialization_order(&self) -> &[PreparedDependencyNode] {
                &self.dependency_order
            }

            /// Returns the compiled download detour for one RuleSet declaration.
            ///
            /// The declaration index is stable and no configuration tag is exposed.
            pub fn download_detour_plan(&self, rule_set: usize) -> Option<&EgressPlanHandle> {
                let plan = self
                    .rule_set_detour_plans
                    .get(rule_set)
                    .copied()
                    .flatten()?;
                self.dependency_egress_plans.get(plan)
            }

            /// Reports whether a RuleSet download detour can terminate directly.
            pub fn download_detour_is_direct(&self, rule_set: usize) -> Option<bool> {
                let plan = self
                    .rule_set_detour_plans
                    .get(rule_set)
                    .copied()
                    .flatten()?;
                self.dependency_egress_direct.get(plan).copied()
            }
        }
    };
}

prepared_accessors!(PreparedClientV2);
prepared_accessors!(PreparedServerV2);

impl PreparedClientV2 {
    /// Reports whether a validated TUN is present without exposing its values.
    pub fn has_tun(&self) -> bool {
        self.validated.tun.is_some()
    }

    /// Reports whether the validated TUN requests automatic route installation.
    /// Configurations without a TUN deliberately return `false`.
    pub fn tun_auto_route(&self) -> bool {
        self.validated
            .tun
            .as_ref()
            .is_some_and(|tun| tun.auto_route)
    }

    pub fn outbound_endpoints(&self) -> &[Option<DialEndpoint>] {
        &self.outbound_endpoints
    }

    pub const fn udp(&self) -> Option<UdpConfig> {
        self.validated.udp
    }

    pub fn outbound_count(&self) -> usize {
        self.validated.outbounds.len()
    }

    pub fn outbound(&self, index: u32) -> Option<PreparedClientOutboundDescriptor<'_>> {
        let index_usize = usize::try_from(index).ok()?;
        let outbound = self.validated.outbounds.get(index_usize)?;
        let endpoint = self.outbound_endpoints.get(index_usize)?.as_ref();
        let (kind, psk) = match outbound {
            ClientOutboundConfig::Direct { .. } => (PreparedClientOutboundKind::Direct, None),
            ClientOutboundConfig::Shadowsocks { psk, .. } => {
                (PreparedClientOutboundKind::Shadowsocks, Some(psk))
            }
        };
        Some(PreparedClientOutboundDescriptor {
            index,
            kind,
            method: outbound.method(),
            psk,
            endpoint,
            domain_resolver: outbound.direct_domain_resolver(),
        })
    }

    pub fn fixed_endpoint_for_node(
        &self,
        node: PreparedDependencyNode,
    ) -> Option<PreparedFixedEndpointDescriptor<'_>> {
        match node {
            PreparedDependencyNode::DnsServer(index) => self
                .dns_endpoints
                .get(usize::try_from(index).ok()?)
                .and_then(PreparedDnsEndpoint::fixed_endpoint)
                .map(|endpoint| {
                    PreparedFixedEndpointDescriptor::new(
                        PreparedFixedEndpointTarget::DnsServer(index),
                        endpoint,
                    )
                }),
            PreparedDependencyNode::Outbound(index) => self
                .outbound_endpoints
                .get(usize::try_from(index).ok()?)?
                .as_ref()
                .map(|endpoint| {
                    PreparedFixedEndpointDescriptor::new(
                        PreparedFixedEndpointTarget::Outbound(index),
                        endpoint,
                    )
                }),
            _ => None,
        }
    }
}

impl PreparedServerV2 {
    pub const fn udp(&self) -> UdpConfig {
        self.validated.udp
    }

    pub fn outbound_count(&self) -> usize {
        self.validated.outbounds.len()
    }

    pub fn outbound(&self, index: u32) -> Option<PreparedServerOutboundDescriptor> {
        let outbound = self.validated.outbounds.get(usize::try_from(index).ok()?)?;
        Some(PreparedServerOutboundDescriptor {
            index,
            domain_resolver: outbound.domain_resolver,
        })
    }

    pub fn fixed_endpoint_for_node(
        &self,
        node: PreparedDependencyNode,
    ) -> Option<PreparedFixedEndpointDescriptor<'_>> {
        let PreparedDependencyNode::DnsServer(index) = node else {
            return None;
        };
        self.dns_endpoints
            .get(usize::try_from(index).ok()?)
            .and_then(PreparedDnsEndpoint::fixed_endpoint)
            .map(|endpoint| {
                PreparedFixedEndpointDescriptor::new(
                    PreparedFixedEndpointTarget::DnsServer(index),
                    endpoint,
                )
            })
    }
}

/// Reads and prepares a client schema-v2 config without external I/O.
pub fn prepare_client(path: impl AsRef<Path>) -> Result<PreparedClientV2, ConfigError> {
    let source = read_bounded_utf8(path.as_ref())?;
    let raw: RawClientRoot = parse_v2_toml(&source)?;
    let validation_raw: RawClientRoot = parse_v2_toml(&source)?;
    prepare_client_inner(raw, validation_raw, &source)
}

/// Reads and prepares a server schema-v2 config without external I/O.
pub fn prepare_server(path: impl AsRef<Path>) -> Result<PreparedServerV2, ConfigError> {
    let source = read_bounded_utf8(path.as_ref())?;
    let raw: RawServerRoot = parse_v2_toml(&source)?;
    let validation_raw: RawServerRoot = parse_v2_toml(&source)?;
    prepare_server_inner(raw, validation_raw, &source)
}

/// Reads and prepares a client V2 config without DNS, download, socket, or listener I/O.
pub fn prepare_client_v2(path: impl AsRef<Path>) -> Result<PreparedClientV2, ConfigError> {
    prepare_client(path)
}

/// Reads and prepares a server V2 config without DNS, download, socket, or listener I/O.
pub fn prepare_server_v2(path: impl AsRef<Path>) -> Result<PreparedServerV2, ConfigError> {
    prepare_server(path)
}

/// Materializes client V2 resources through an injected context, then finishes synchronously.
pub async fn materialize_client_v2<C>(
    prepared: PreparedClientV2,
    context: &C,
) -> Result<ValidatedClientConfig, ConfigError>
where
    C: ClientV2MaterializeContext + ?Sized,
{
    let resources = context.materialize_client(&prepared).await?;
    finish_client_v2(prepared, resources)
}

/// Materializes server V2 resources through an injected context, then finishes synchronously.
pub async fn materialize_server_v2<C>(
    prepared: PreparedServerV2,
    context: &C,
) -> Result<ValidatedServerConfig, ConfigError>
where
    C: ServerV2MaterializeContext + ?Sized,
{
    let resources = context.materialize_server(&prepared).await?;
    finish_server_v2(prepared, resources)
}

/// Finishes a prepared client using only already materialized resources.
///
/// This function performs no DNS, filesystem, socket, task, or listener I/O.
pub fn finish_client_v2(
    mut prepared: PreparedClientV2,
    resources: ClientV2Resources,
) -> Result<ValidatedClientConfig, ConfigError> {
    apply_outbound_resources(
        &mut prepared.validated.outbounds,
        &prepared.outbound_endpoints,
        &resources.outbound_endpoints,
    )?;
    apply_dns_resources(
        prepared.validated.dns.as_mut(),
        &prepared.dns_endpoints,
        &resources.dns_endpoints,
    )?;
    validate_finished_client_endpoints(&prepared.validated, &prepared.direct_detours)?;
    let registry = build_rule_registry(&prepared.rule_sets, resources.rule_sets)?;
    attach_rule_registry(&mut prepared.validated, registry.clone())?;
    attach_client_dns_blueprint(
        &mut prepared.validated,
        &prepared.dns_rules,
        prepared.dns_final_server,
        prepared.dns_strategy,
        registry,
    )?;
    finish_client_tun_targets(
        &mut prepared.validated,
        &prepared.physical_first_hops,
        &prepared.direct_detours,
    )?;
    Ok(prepared.validated)
}

/// Finishes a prepared server using only already materialized resources.
///
/// This function performs no DNS, filesystem, socket, task, or listener I/O.
pub fn finish_server_v2(
    mut prepared: PreparedServerV2,
    resources: ServerV2Resources,
) -> Result<ValidatedServerConfig, ConfigError> {
    apply_dns_resources(
        prepared.validated.dns.as_mut(),
        &prepared.dns_endpoints,
        &resources.dns_endpoints,
    )?;
    let registry = build_rule_registry(&prepared.rule_sets, resources.rule_sets)?;
    attach_rule_registry(&mut prepared.validated, registry.clone())?;
    attach_server_dns_blueprint(
        &mut prepared.validated,
        &prepared.dns_rules,
        prepared.dns_final_server,
        prepared.dns_strategy,
        registry,
    )?;
    Ok(prepared.validated)
}

fn attach_client_dns_blueprint(
    validated: &mut ValidatedClientConfig,
    rules: &[PreparedDnsRule],
    final_server: Option<usize>,
    strategy: Option<DnsStrategy>,
    registry: Option<Arc<RuleEngineRegistry>>,
) -> Result<(), ConfigError> {
    let (route, final_server) = match (validated.dns_route.as_mut(), final_server) {
        (None, None) if rules.is_empty() => return Ok(()),
        (Some(route), Some(final_server)) => (route, final_server),
        _ => return Err(ConfigError::semantic(ConfigField::ResourceMaterialization)),
    };
    let registry = registry.map_or_else(empty_rule_registry, Ok)?;
    let blueprint = build_dns_policy_blueprint(
        rules,
        final_server,
        strategy.unwrap_or(DnsStrategy::PreferIpv4),
        &registry,
    )?;
    route.attach_policy_blueprint(blueprint, registry);
    Ok(())
}

fn attach_server_dns_blueprint(
    validated: &mut ValidatedServerConfig,
    rules: &[PreparedDnsRule],
    final_server: Option<usize>,
    strategy: Option<DnsStrategy>,
    registry: Option<Arc<RuleEngineRegistry>>,
) -> Result<(), ConfigError> {
    let (route, final_server) = match (validated.dns_route.as_mut(), final_server) {
        (None, None) if rules.is_empty() => return Ok(()),
        (Some(route), Some(final_server)) => (route, final_server),
        _ => return Err(ConfigError::semantic(ConfigField::ResourceMaterialization)),
    };
    let registry = registry.map_or_else(empty_rule_registry, Ok)?;
    let blueprint = build_dns_policy_blueprint(
        rules,
        final_server,
        strategy.unwrap_or(DnsStrategy::PreferIpv4),
        &registry,
    )?;
    route.attach_policy_blueprint(blueprint, registry);
    Ok(())
}

fn empty_rule_registry() -> Result<Arc<RuleEngineRegistry>, ConfigError> {
    let snapshot = RuleEngineSnapshotBuilder::new(0).build().map_err(|error| {
        ConfigError::from_rule_compile(error, ConfigField::ResourceMaterialization)
    })?;
    Ok(Arc::new(RuleEngineRegistry::new(snapshot)))
}

fn build_dns_policy_blueprint(
    prepared: &[PreparedDnsRule],
    final_server: usize,
    final_strategy: DnsStrategy,
    registry: &Arc<RuleEngineRegistry>,
) -> Result<DnsPolicyBlueprint, ConfigError> {
    let snapshot = registry.snapshot();
    let mut rules = Vec::new();
    rules
        .try_reserve_exact(prepared.len())
        .map_err(|_| ConfigError::rule_allocation(ConfigField::DnsRouteRules))?;
    for prepared in prepared {
        if !prepared.matcher.dns_eligible {
            continue;
        }
        let mut rule_sets = Vec::new();
        rule_sets
            .try_reserve_exact(prepared.rule_sets.len())
            .map_err(|_| ConfigError::rule_allocation(ConfigField::DnsRouteRulesRuleSet))?;
        for &rule_set in &prepared.rule_sets {
            let rule_set = RuleSetId::from_raw(checked_u32(rule_set)?);
            if snapshot.rule_set(rule_set).is_none() {
                return Err(ConfigError::semantic(ConfigField::DnsRouteRulesRuleSet));
            }
            rule_sets.push(rule_set);
        }
        let matcher = DnsPolicyMatcherDescriptor::try_new(
            prepared.matcher.query_fields.clone(),
            rule_sets,
            prepared.matcher.inbounds.clone(),
            prepared.matcher.networks.clone(),
            prepared.matcher.qtypes.clone(),
            prepared.matcher.ports.clone(),
            prepared.matcher.port_ranges.clone(),
        )
        .map_err(map_dns_policy_blueprint_error)?;
        let action = match prepared.action {
            PreparedDnsAction::Route { server } => {
                DnsPolicyActionDescriptor::Route(DnsPolicyRouteDescriptor::new(
                    checked_u32(server)?,
                    dns_policy_strategy(prepared.strategy),
                ))
            }
            PreparedDnsAction::Reject => DnsPolicyActionDescriptor::Reject,
        };
        rules.push(DnsPolicyRuleDescriptor::new(matcher, action));
    }
    let final_route = DnsPolicyRouteDescriptor::new(
        checked_u32(final_server)?,
        dns_policy_strategy(final_strategy),
    );
    DnsPolicyBlueprint::try_new(rules, final_route, &snapshot)
        .map_err(map_dns_policy_blueprint_error)
}

const fn dns_policy_strategy(strategy: DnsStrategy) -> DnsPolicyAddressStrategy {
    match strategy {
        DnsStrategy::PreferIpv4 => DnsPolicyAddressStrategy::PreferIpv4,
        DnsStrategy::PreferIpv6 => DnsPolicyAddressStrategy::PreferIpv6,
        DnsStrategy::Ipv4Only => DnsPolicyAddressStrategy::Ipv4Only,
        DnsStrategy::Ipv6Only => DnsPolicyAddressStrategy::Ipv6Only,
    }
}

fn map_dns_policy_blueprint_error(error: DnsPolicyBlueprintError) -> ConfigError {
    match error {
        DnsPolicyBlueprintError::UnknownRuleSet => {
            ConfigError::semantic(ConfigField::DnsRouteRulesRuleSet)
        }
        DnsPolicyBlueprintError::ResponseDependentReject => {
            ConfigError::semantic(ConfigField::DnsRouteRulesAction)
        }
        DnsPolicyBlueprintError::EmptyRule
        | DnsPolicyBlueprintError::InvalidQueryMatchSet
        | DnsPolicyBlueprintError::DuplicateConstraint => {
            ConfigError::semantic(ConfigField::DnsRouteRules)
        }
        DnsPolicyBlueprintError::IndexOverflow => {
            ConfigError::rule_allocation(ConfigField::DnsRouteRules)
        }
    }
}

fn attach_rule_registry<T: ValidatedRoute>(
    validated: &mut T,
    registry: Option<Arc<RuleEngineRegistry>>,
) -> Result<(), ConfigError> {
    let Some(registry) = registry else {
        return Ok(());
    };
    if let Some(route) = validated.route_program_mut() {
        route.attach_rule_registry(registry);
    }
    Ok(())
}

trait ValidatedRoute {
    fn route_program_mut(&mut self) -> Option<&mut crate::model::CompiledRoute>;
}

impl ValidatedRoute for ValidatedClientConfig {
    fn route_program_mut(&mut self) -> Option<&mut crate::model::CompiledRoute> {
        self.route_program.as_mut()
    }
}

impl ValidatedRoute for ValidatedServerConfig {
    fn route_program_mut(&mut self) -> Option<&mut crate::model::CompiledRoute> {
        self.route_program.as_mut()
    }
}

fn build_rule_registry(
    declarations: &[PreparedRuleSet],
    resources: Vec<CompiledRuleSetResource>,
) -> Result<Option<Arc<RuleEngineRegistry>>, ConfigError> {
    if declarations.len() != resources.len() {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    let Some(generation) = resources.first().map(CompiledRuleSetResource::generation) else {
        return Ok(None);
    };
    let mut builder = RuleEngineSnapshotBuilder::new(generation);
    for (index, (declaration, resource)) in declarations.iter().zip(resources).enumerate() {
        let expected = checked_u32(index)?;
        if resource.rule_set != expected || resource.generation != generation {
            return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
        }
        let match_set = builder
            .add_shared_match_set(resource.match_set)
            .map_err(|error| {
                ConfigError::from_rule_compile(error, ConfigField::ResourceMaterialization)
            })?;
        let rule_set = builder
            .add_rule_set(declaration.tag(), match_set)
            .map_err(|error| {
                ConfigError::from_rule_compile(error, ConfigField::ResourceMaterialization)
            })?;
        if rule_set.raw() != expected {
            return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
        }
    }
    let snapshot = builder.build().map_err(|error| {
        ConfigError::from_rule_compile(error, ConfigField::ResourceMaterialization)
    })?;
    Ok(Some(Arc::new(RuleEngineRegistry::new(snapshot))))
}

fn apply_outbound_resources(
    validated: &mut [ClientOutboundConfig],
    expected: &[Option<DialEndpoint>],
    resources: &[ResolvedOutboundEndpoint],
) -> Result<(), ConfigError> {
    if validated.len() != expected.len()
        || resources.len()
            != expected
                .iter()
                .filter(|endpoint| endpoint.as_ref().is_some_and(DialEndpoint::is_domain))
                .count()
    {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    let mut resources = resources.iter();
    for (index, (validated, expected)) in validated.iter_mut().zip(expected).enumerate() {
        match (validated, expected) {
            (ClientOutboundConfig::Direct { .. }, None) => {}
            (
                ClientOutboundConfig::Shadowsocks { server, .. },
                Some(DialEndpoint::Ip(expected)),
            ) if server == expected => {}
            (
                ClientOutboundConfig::Shadowsocks { server, .. },
                Some(endpoint @ DialEndpoint::Domain { .. }),
            ) => {
                let resource = resources
                    .next()
                    .ok_or_else(|| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
                if resource.outbound != checked_u32(index)? {
                    return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
                }
                validate_selected_endpoint(endpoint, resource.address)?;
                *server = resource.address;
            }
            _ => return Err(ConfigError::semantic(ConfigField::ResourceMaterialization)),
        }
    }
    if resources.next().is_some() {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    Ok(())
}

fn apply_dns_resources(
    validated: Option<&mut crate::model::DnsConfig>,
    expected: &[PreparedDnsEndpoint],
    resources: &[ResolvedDnsEndpoint],
) -> Result<(), ConfigError> {
    let validated = match (validated, expected.is_empty()) {
        (None, true) => {
            if resources.is_empty() {
                return Ok(());
            }
            return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
        }
        (Some(validated), _) => validated,
        (None, false) => {
            return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
        }
    };
    if validated.servers.len() != expected.len()
        || resources.len()
            != expected
                .iter()
                .filter(|endpoint| {
                    matches!(
                        endpoint.mode(),
                        PreparedDnsEndpointMode::ClientResolved { .. }
                    )
                })
                .count()
    {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    let mut resources = resources.iter();
    for (index, (validated, expected)) in validated.servers.iter_mut().zip(expected).enumerate() {
        match expected.mode() {
            PreparedDnsEndpointMode::Numeric if validated.target == *expected.target() => {
                validated.resolved_targets = Box::new([]);
                validated.endpoint_mode = DnsEndpointMode::Numeric;
            }
            PreparedDnsEndpointMode::ClientResolved { .. } => {
                let resource = resources
                    .next()
                    .ok_or_else(|| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
                if resource.server != checked_u32(index)? {
                    return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
                }
                let fixed_endpoint = expected
                    .fixed_endpoint()
                    .ok_or_else(|| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
                if resource.addresses.is_empty()
                    || resource.addresses.len() > MAX_RESOLVED_DNS_CANDIDATES
                {
                    return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
                }
                for &address in &resource.addresses {
                    validate_selected_endpoint(fixed_endpoint, address)?;
                }
                validated.target = expected.target().clone();
                validated.resolved_targets = resource.addresses.clone();
                let PreparedDnsEndpointMode::ClientResolved { resolver, strategy } =
                    expected.mode()
                else {
                    unreachable!("matched client-resolved DNS endpoint")
                };
                validated.endpoint_mode = DnsEndpointMode::ClientResolved { resolver, strategy };
            }
            PreparedDnsEndpointMode::DeferredToDetour => {
                validated.target = expected.target().clone();
                validated.resolved_targets = Box::new([]);
                validated.endpoint_mode = DnsEndpointMode::DeferredToDetour;
            }
            PreparedDnsEndpointMode::Numeric => {
                return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
            }
        }
    }
    if resources.next().is_some() {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    Ok(())
}

fn validate_selected_endpoint(
    expected: &DialEndpoint,
    selected: SocketAddr,
) -> Result<(), ConfigError> {
    let DialEndpoint::Domain { port, strategy, .. } = expected else {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    };
    if selected.port() != port.get()
        || matches!(strategy, DnsStrategy::Ipv4Only) && !selected.is_ipv4()
        || matches!(strategy, DnsStrategy::Ipv6Only) && !selected.is_ipv6()
    {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    Ok(())
}

struct PreparedCommon {
    loader: RuleSetLoaderConfig,
    rule_sets: Vec<PreparedRuleSet>,
    route_rule_sets: Vec<PreparedRouteRuleSets>,
    dns_rules: Vec<PreparedDnsRule>,
    dns_final_server: Option<usize>,
    dns_strategy: Option<DnsStrategy>,
    dns_cache: Option<DnsCacheConfig>,
    dns_endpoints: Vec<PreparedDnsEndpoint>,
    dependency_order: Vec<PreparedDependencyNode>,
}

fn prepared_rule_set_tags(rule_sets: &[PreparedRuleSet]) -> Result<Vec<&str>, ConfigError> {
    let mut tags = Vec::new();
    tags.try_reserve_exact(rule_sets.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    tags.extend(rule_sets.iter().map(PreparedRuleSet::tag));
    Ok(tags)
}

struct PreparedEgressDependencies<'a> {
    tags: Vec<&'a str>,
    rule_set_plans: Vec<Option<usize>>,
}

fn prepared_dependency_egress<'a>(
    rule_sets: &[PreparedRuleSet],
    outbounds: &[&'a str],
    selectors: &'a [RawSelector],
    chains: &'a [RawChain],
) -> Result<PreparedEgressDependencies<'a>, ConfigError> {
    let mut tags = Vec::new();
    tags.try_reserve_exact(rule_sets.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    let mut rule_set_plans = Vec::new();
    rule_set_plans
        .try_reserve_exact(rule_sets.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    for rule_set in rule_sets {
        let Some(detour) = rule_set.download_detour() else {
            rule_set_plans.push(None);
            continue;
        };
        let tag = match detour {
            PreparedEgressRef::Outbound(index) => outbounds.get(index).copied(),
            PreparedEgressRef::Selector(index) => {
                selectors.get(index).map(|selector| selector.tag.as_str())
            }
            PreparedEgressRef::Chain(index) => {
                chains.get(index).and_then(|chain| chain.tag.as_deref())
            }
        }
        .ok_or_else(|| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
        let plan = if let Some(plan) = tags.iter().position(|candidate| *candidate == tag) {
            plan
        } else {
            tags.push(tag);
            tags.len() - 1
        };
        rule_set_plans.push(Some(plan));
    }
    Ok(PreparedEgressDependencies {
        tags,
        rule_set_plans,
    })
}

fn prepared_dependency_dns_servers(
    dns_endpoints: &[PreparedDnsEndpoint],
    outbound_endpoints: &[Option<DialEndpoint>],
    direct_domain_resolvers: &[Option<DirectDomainResolver>],
    rule_sets: &[PreparedRuleSet],
) -> Result<Vec<usize>, ConfigError> {
    let mut servers = Vec::new();
    let candidates = dns_endpoints
        .iter()
        .filter_map(PreparedDnsEndpoint::resolver)
        .chain(
            outbound_endpoints
                .iter()
                .filter_map(Option::as_ref)
                .filter_map(DialEndpoint::resolver),
        )
        .chain(
            direct_domain_resolvers
                .iter()
                .filter_map(|resolver| match resolver {
                    Some(DirectDomainResolver::DnsServer { server, .. }) => {
                        Some(ResolverRef::DnsServer(*server))
                    }
                    Some(DirectDomainResolver::System) | None => None,
                }),
        )
        .chain(
            rule_sets
                .iter()
                .filter_map(PreparedRuleSet::download_resolver),
        );
    for resolver in candidates {
        let ResolverRef::DnsServer(server) = resolver else {
            continue;
        };
        if !servers.contains(&server) {
            servers
                .try_reserve(1)
                .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
            servers.push(server);
        }
    }
    Ok(servers)
}

fn prepare_client_inner(
    raw: RawClientRoot,
    mut validation_raw: RawClientRoot,
    source: &str,
) -> Result<PreparedClientV2, ConfigError> {
    let dns = prepare_dns(raw.dns.as_ref())?;
    let outbound_endpoints = prepare_client_outbounds(
        raw.outbounds.as_deref().unwrap_or(&[]),
        raw.dns.as_ref(),
        dns.strategy,
    )?;
    let outbound_tags = raw
        .outbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|outbound| outbound.tag.as_str())
        .collect::<Vec<_>>();
    let selectors = raw.selectors.as_deref().unwrap_or(&[]);
    let chains = raw.chains.as_deref().unwrap_or(&[]);
    let direct_domain_resolvers = prepare_client_direct_domain_resolvers(
        raw.outbounds.as_deref().unwrap_or(&[]),
        raw.dns.as_ref(),
        dns.strategy,
    )?;
    let egress_domain_capabilities =
        prepare_egress_capabilities(&outbound_tags, selectors, chains)?;
    let mut common = prepare_common(
        raw.rule_set_loader.as_ref(),
        raw.route.as_ref(),
        raw.dns.as_ref(),
        outbound_tags.clone(),
        selectors,
        chains,
        outbound_endpoints.as_slice(),
        &direct_domain_resolvers,
        &egress_domain_capabilities,
        dns,
    )?;
    let ordinary_inbounds = raw
        .inbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|inbound| inbound.tag.as_str())
        .chain(raw.tun.as_ref().map(|tun| tun.tag.as_str()))
        .collect::<Vec<_>>();
    let dns_policy = prepare_dns_rules(
        raw.dns.as_ref(),
        &common.rule_sets,
        common.dns_strategy,
        PreparedDnsRole::Client,
        &ordinary_inbounds,
        source,
    )?;
    common.dns_rules = dns_policy.rules;
    common.dns_final_server = dns_policy.final_server;
    let rule_set_tags = prepared_rule_set_tags(&common.rule_sets)?;
    let dependency_egress =
        prepared_dependency_egress(&common.rule_sets, &outbound_tags, selectors, chains)?;
    let dependency_dns_servers = prepared_dependency_dns_servers(
        &common.dns_endpoints,
        &outbound_endpoints,
        &direct_domain_resolvers,
        &common.rule_sets,
    )?;
    sanitize_client(&mut validation_raw);
    let validation = validate_client_prepared(
        validation_raw,
        source,
        &rule_set_tags,
        &dependency_egress.tags,
        &dependency_dns_servers,
    )?;
    if validation.dependency_egress_plans.len() != dependency_egress.tags.len()
        || validation.dependency_egress_direct.len() != dependency_egress.tags.len()
    {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    Ok(PreparedClientV2 {
        validated: validation.config,
        physical_first_hops: validation.physical_first_hops,
        direct_detours: validation.direct_detours,
        dependency_egress_plans: validation.dependency_egress_plans,
        dependency_egress_direct: validation.dependency_egress_direct,
        rule_set_detour_plans: dependency_egress.rule_set_plans,
        rule_set_loader: common.loader,
        rule_sets: common.rule_sets,
        route_rule_sets: common.route_rule_sets,
        dns_rules: common.dns_rules,
        dns_final_server: common.dns_final_server,
        dns_strategy: common.dns_strategy,
        dns_cache: common.dns_cache,
        outbound_endpoints,
        dns_endpoints: common.dns_endpoints,
        egress_domain_capabilities,
        dependency_order: common.dependency_order,
    })
}

fn prepare_server_inner(
    raw: RawServerRoot,
    mut validation_raw: RawServerRoot,
    source: &str,
) -> Result<PreparedServerV2, ConfigError> {
    let dns = prepare_dns(raw.dns.as_ref())?;
    let outbound_tags = raw
        .outbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|outbound| outbound.tag.as_str())
        .collect::<Vec<_>>();
    let selectors = raw.selectors.as_deref().unwrap_or(&[]);
    let direct_domain_resolvers = prepare_server_direct_domain_resolvers(
        raw.outbounds.as_deref().unwrap_or(&[]),
        raw.dns.as_ref(),
        dns.strategy,
    )?;
    let egress_domain_capabilities = prepare_egress_capabilities(&outbound_tags, selectors, &[])?;
    let mut common = prepare_common(
        raw.rule_set_loader.as_ref(),
        raw.route.as_ref(),
        raw.dns.as_ref(),
        outbound_tags.clone(),
        selectors,
        &[],
        &[],
        &direct_domain_resolvers,
        &egress_domain_capabilities,
        dns,
    )?;
    let ordinary_inbounds = raw
        .inbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|inbound| inbound.tag.as_str())
        .collect::<Vec<_>>();
    let dns_policy = prepare_dns_rules(
        raw.dns.as_ref(),
        &common.rule_sets,
        common.dns_strategy,
        PreparedDnsRole::Server,
        &ordinary_inbounds,
        source,
    )?;
    common.dns_rules = dns_policy.rules;
    common.dns_final_server = dns_policy.final_server;
    let rule_set_tags = prepared_rule_set_tags(&common.rule_sets)?;
    let dependency_egress =
        prepared_dependency_egress(&common.rule_sets, &outbound_tags, selectors, &[])?;
    let dependency_dns_servers = prepared_dependency_dns_servers(
        &common.dns_endpoints,
        &[],
        &direct_domain_resolvers,
        &common.rule_sets,
    )?;
    sanitize_server(&mut validation_raw);
    let validation = validate_server_prepared(
        validation_raw,
        source,
        &rule_set_tags,
        &dependency_egress.tags,
        &dependency_dns_servers,
    )?;
    if validation.dependency_egress_plans.len() != dependency_egress.tags.len()
        || validation.dependency_egress_direct.len() != dependency_egress.tags.len()
    {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    Ok(PreparedServerV2 {
        validated: validation.config,
        dependency_egress_plans: validation.dependency_egress_plans,
        dependency_egress_direct: validation.dependency_egress_direct,
        rule_set_detour_plans: dependency_egress.rule_set_plans,
        rule_set_loader: common.loader,
        rule_sets: common.rule_sets,
        route_rule_sets: common.route_rule_sets,
        dns_rules: common.dns_rules,
        dns_final_server: common.dns_final_server,
        dns_strategy: common.dns_strategy,
        dns_cache: common.dns_cache,
        dns_endpoints: common.dns_endpoints,
        egress_domain_capabilities,
        dependency_order: common.dependency_order,
    })
}

struct PreparedDnsDraft {
    strategy: Option<DnsStrategy>,
    cache: Option<DnsCacheConfig>,
    endpoints: Vec<PreparedDnsEndpoint>,
}

fn prepare_dns(raw: Option<&RawDns>) -> Result<PreparedDnsDraft, ConfigError> {
    let Some(raw) = raw else {
        return Ok(PreparedDnsDraft {
            strategy: None,
            cache: None,
            endpoints: Vec::new(),
        });
    };
    let strategy = parse_strategy(raw.strategy.as_deref(), ConfigField::DnsStrategy)?;
    let cache = raw.cache.as_ref().map_or(
        Ok(DnsCacheConfig {
            enabled: true,
            max_entries: 8_192,
        }),
        |cache| {
            if cache.max_entries == 0 || cache.max_entries > 1_000_000 {
                return Err(ConfigError::semantic(ConfigField::DnsCacheMaxEntries));
            }
            Ok(DnsCacheConfig {
                enabled: cache.enabled,
                max_entries: cache.max_entries,
            })
        },
    )?;
    let servers = raw.servers.as_deref().unwrap_or(&[]);
    for (index, server) in servers.iter().enumerate() {
        validate_tag(&server.tag, ConfigField::DnsServersTag)?;
        if server.tag == "system" {
            return Err(ConfigError::dns_reserved_resolver_name(
                ConfigField::DnsServersTag,
            ));
        }
        if servers[..index].iter().any(|other| other.tag == server.tag) {
            return Err(ConfigError::semantic(ConfigField::DnsServersTag));
        }
    }
    let mut endpoints = Vec::new();
    endpoints
        .try_reserve_exact(servers.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    for server in servers {
        endpoints.push(parse_dns_endpoint(
            &server.address,
            server.domain_resolver.as_deref(),
            server.domain_strategy.as_deref(),
            server.detour.is_some(),
            strategy,
            servers,
        )?);
    }
    Ok(PreparedDnsDraft {
        strategy: Some(strategy),
        cache: Some(cache),
        endpoints,
    })
}

fn prepare_client_outbounds(
    outbounds: &[RawClientOutbound],
    dns: Option<&RawDns>,
    default_strategy: Option<DnsStrategy>,
) -> Result<Vec<Option<DialEndpoint>>, ConfigError> {
    let servers = dns.and_then(|dns| dns.servers.as_deref()).unwrap_or(&[]);
    let strategy = default_strategy.unwrap_or(DnsStrategy::PreferIpv4);
    let mut endpoints = Vec::new();
    endpoints
        .try_reserve_exact(outbounds.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    for outbound in outbounds {
        match outbound.outbound_type.as_deref().unwrap_or("shadowsocks") {
            "direct" => {
                endpoints.push(None);
            }
            "shadowsocks" => {
                let Some(server) = outbound.server.as_deref() else {
                    endpoints.push(None);
                    continue;
                };
                endpoints.push(Some(parse_endpoint(
                    server,
                    outbound.domain_resolver.as_deref(),
                    outbound.domain_strategy.as_deref(),
                    strategy,
                    servers,
                    ConfigField::OutboundsServer,
                    ConfigField::OutboundsDomainResolver,
                    ConfigField::OutboundsDomainStrategy,
                )?));
            }
            _ => endpoints.push(None),
        }
    }
    Ok(endpoints)
}

fn prepare_client_direct_domain_resolvers(
    outbounds: &[RawClientOutbound],
    dns: Option<&RawDns>,
    default_strategy: Option<DnsStrategy>,
) -> Result<Vec<Option<DirectDomainResolver>>, ConfigError> {
    let default_strategy = default_strategy.unwrap_or(DnsStrategy::PreferIpv4);
    outbounds
        .iter()
        .map(|outbound| {
            if outbound.outbound_type.as_deref() != Some("direct") {
                return Ok(None);
            }
            validate_direct_domain_resolver(
                outbound.domain_resolver.as_deref(),
                outbound.domain_strategy.as_deref(),
                dns,
                default_strategy,
            )
            .map(Some)
        })
        .collect()
}

fn prepare_server_direct_domain_resolvers(
    outbounds: &[crate::raw::RawServerOutbound],
    dns: Option<&RawDns>,
    default_strategy: Option<DnsStrategy>,
) -> Result<Vec<Option<DirectDomainResolver>>, ConfigError> {
    let default_strategy = default_strategy.unwrap_or(DnsStrategy::PreferIpv4);
    outbounds
        .iter()
        .map(|outbound| {
            validate_direct_domain_resolver(
                outbound.domain_resolver.as_deref(),
                outbound.domain_strategy.as_deref(),
                dns,
                default_strategy,
            )
            .map(Some)
        })
        .collect()
}

fn parse_dns_endpoint(
    value: &str,
    resolver: Option<&str>,
    strategy: Option<&str>,
    has_detour: bool,
    default_strategy: DnsStrategy,
    dns_servers: &[crate::raw::RawDnsServer],
) -> Result<PreparedDnsEndpoint, ConfigError> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        if address.port() == 0 {
            return Err(ConfigError::semantic(ConfigField::DnsServersAddress));
        }
        if resolver.is_some() {
            return Err(ConfigError::semantic(ConfigField::DnsServersDomainResolver));
        }
        if strategy.is_some() {
            return Err(ConfigError::semantic(ConfigField::DnsServersDomainStrategy));
        }
        return Ok(PreparedDnsEndpoint {
            target: TargetAddr::ip(address)
                .map_err(|_| ConfigError::semantic(ConfigField::DnsServersAddress))?,
            mode: PreparedDnsEndpointMode::Numeric,
            fixed_endpoint: Some(DialEndpoint::Ip(address)),
        });
    }
    let (host, port) = parse_domain_endpoint(value, ConfigField::DnsServersAddress)?;
    let target = TargetAddr::domain(host.as_str(), port.get())
        .map_err(|_| ConfigError::semantic(ConfigField::DnsServersAddress))?;
    let Some(resolver) = resolver else {
        if strategy.is_some() {
            return Err(ConfigError::semantic(ConfigField::DnsServersDomainStrategy));
        }
        if !has_detour {
            return Err(ConfigError::dns_resolver_required(
                ConfigField::DnsServersDomainResolver,
            ));
        }
        return Ok(PreparedDnsEndpoint {
            target,
            mode: PreparedDnsEndpointMode::DeferredToDetour,
            fixed_endpoint: None,
        });
    };
    let resolver = parse_resolver(resolver, dns_servers, ConfigField::DnsServersDomainResolver)?;
    let strategy = strategy.map_or(Ok(default_strategy), |strategy| {
        parse_strategy(Some(strategy), ConfigField::DnsServersDomainStrategy)
    })?;
    Ok(PreparedDnsEndpoint {
        target,
        mode: PreparedDnsEndpointMode::ClientResolved { resolver, strategy },
        fixed_endpoint: Some(DialEndpoint::Domain {
            host,
            port,
            resolver,
            strategy,
        }),
    })
}

fn parse_domain_endpoint(
    value: &str,
    field: ConfigField,
) -> Result<(CanonicalDomain, NonZeroU16), ConfigError> {
    let (host, port) = value
        .rsplit_once(':')
        .filter(|(host, _)| !host.is_empty() && !host.contains(':'))
        .ok_or_else(|| ConfigError::semantic(field))?;
    let port = port
        .parse::<u16>()
        .ok()
        .and_then(NonZeroU16::new)
        .ok_or_else(|| ConfigError::semantic(field))?;
    if host.parse::<IpAddr>().is_ok() || !valid_domain(host) {
        return Err(ConfigError::semantic(field));
    }
    let host = CanonicalDomain::new(host).map_err(|_| ConfigError::semantic(field))?;
    Ok((host, port))
}

#[allow(clippy::too_many_arguments)]
fn parse_endpoint(
    value: &str,
    resolver: Option<&str>,
    strategy: Option<&str>,
    default_strategy: DnsStrategy,
    dns_servers: &[crate::raw::RawDnsServer],
    endpoint_field: ConfigField,
    resolver_field: ConfigField,
    strategy_field: ConfigField,
) -> Result<DialEndpoint, ConfigError> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        if address.port() == 0 {
            return Err(ConfigError::semantic(endpoint_field));
        }
        if resolver.is_some() {
            return Err(ConfigError::semantic(resolver_field));
        }
        if strategy.is_some() {
            return Err(ConfigError::semantic(strategy_field));
        }
        return Ok(DialEndpoint::Ip(address));
    }
    let (host, port) = parse_domain_endpoint(value, endpoint_field)?;
    let resolver = parse_resolver(
        resolver.ok_or_else(|| ConfigError::dns_resolver_required(resolver_field))?,
        dns_servers,
        resolver_field,
    )?;
    let strategy = strategy.map_or(Ok(default_strategy), |strategy| {
        parse_strategy(Some(strategy), strategy_field)
    })?;
    Ok(DialEndpoint::Domain {
        host,
        port,
        resolver,
        strategy,
    })
}

fn parse_resolver(
    value: &str,
    dns_servers: &[crate::raw::RawDnsServer],
    field: ConfigField,
) -> Result<ResolverRef, ConfigError> {
    if value == "system" {
        return Ok(ResolverRef::System);
    }
    validate_tag(value, field)?;
    dns_servers
        .iter()
        .position(|server| server.tag == value)
        .map(ResolverRef::DnsServer)
        .ok_or_else(|| ConfigError::semantic(field))
}

fn parse_strategy(value: Option<&str>, field: ConfigField) -> Result<DnsStrategy, ConfigError> {
    match value.unwrap_or("prefer_ipv4") {
        "prefer_ipv4" => Ok(DnsStrategy::PreferIpv4),
        "prefer_ipv6" => Ok(DnsStrategy::PreferIpv6),
        "ipv4_only" => Ok(DnsStrategy::Ipv4Only),
        "ipv6_only" => Ok(DnsStrategy::Ipv6Only),
        _ => Err(ConfigError::semantic(field)),
    }
}

fn valid_domain(value: &str) -> bool {
    (1..=253).contains(&value.len())
        && value.is_ascii()
        && value
            .strip_suffix('.')
            .unwrap_or(value)
            .split('.')
            .all(|label| {
                (1..=63).contains(&label.len())
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    && label
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && label
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)
            })
}

fn prepare_rule_set_loader(
    raw: Option<&RawRuleSetLoader>,
) -> Result<RuleSetLoaderConfig, ConfigError> {
    let cache_dir = raw
        .and_then(|raw| raw.cache_dir.clone())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_RULE_SET_CACHE_DIR));
    if cache_dir.as_os_str().is_empty() {
        return Err(ConfigError::semantic(ConfigField::RuleSetLoaderCacheDir));
    }
    let timeout_ms = raw
        .and_then(|raw| raw.download_timeout_ms)
        .unwrap_or(DEFAULT_RULE_SET_DOWNLOAD_TIMEOUT_MS);
    if !(100..=300_000).contains(&timeout_ms) {
        return Err(ConfigError::semantic(
            ConfigField::RuleSetLoaderDownloadTimeout,
        ));
    }
    let max_redirects = raw
        .and_then(|raw| raw.max_redirects)
        .unwrap_or(DEFAULT_RULE_SET_MAX_REDIRECTS);
    if max_redirects > 20 {
        return Err(ConfigError::semantic(
            ConfigField::RuleSetLoaderMaxRedirects,
        ));
    }
    Ok(RuleSetLoaderConfig {
        cache_dir,
        download_timeout: Duration::from_millis(timeout_ms),
        max_redirects,
    })
}

#[allow(clippy::too_many_arguments)]
fn prepare_common(
    loader: Option<&RawRuleSetLoader>,
    route: Option<&RawRoute>,
    dns: Option<&RawDns>,
    outbound_tags: Vec<&str>,
    selectors: &[RawSelector],
    chains: &[RawChain],
    outbound_endpoints: &[Option<DialEndpoint>],
    direct_domain_resolvers: &[Option<DirectDomainResolver>],
    egress_domain_capabilities: &PreparedEgressCapabilities,
    dns_draft: PreparedDnsDraft,
) -> Result<PreparedCommon, ConfigError> {
    let loader = prepare_rule_set_loader(loader)?;
    let dns_servers = dns.and_then(|dns| dns.servers.as_deref()).unwrap_or(&[]);
    let raw_rule_sets = route.map(|route| route.rule_set.as_slice()).unwrap_or(&[]);
    validate_deferred_dns_detours(
        dns,
        &dns_draft.endpoints,
        &outbound_tags,
        selectors,
        chains,
        egress_domain_capabilities,
    )?;
    let rule_sets = prepare_rule_sets(
        raw_rule_sets,
        dns_servers,
        &outbound_tags,
        selectors,
        chains,
        egress_domain_capabilities,
    )?;
    let route_rule_sets = prepare_route_rule_sets(route, &rule_sets)?;
    let raw_dependency_order = build_dependency_order(
        dns,
        &dns_draft.endpoints,
        &outbound_tags,
        outbound_endpoints,
        direct_domain_resolvers,
        selectors,
        chains,
        &rule_sets,
    )?;
    let mut dependency_order = Vec::new();
    dependency_order
        .try_reserve_exact(raw_dependency_order.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    dependency_order.extend(
        raw_dependency_order
            .into_iter()
            .map(PreparedDependencyNode::from),
    );
    Ok(PreparedCommon {
        loader,
        rule_sets,
        route_rule_sets,
        dns_rules: Vec::new(),
        dns_final_server: None,
        dns_strategy: dns_draft.strategy,
        dns_cache: dns_draft.cache,
        dns_endpoints: dns_draft.endpoints,
        dependency_order,
    })
}

fn prepare_rule_sets(
    raw_rule_sets: &[RawRuleSet],
    dns_servers: &[crate::raw::RawDnsServer],
    outbound_tags: &[&str],
    selectors: &[RawSelector],
    chains: &[RawChain],
    capabilities: &PreparedEgressCapabilities,
) -> Result<Vec<PreparedRuleSet>, ConfigError> {
    let mut prepared = Vec::new();
    prepared
        .try_reserve_exact(raw_rule_sets.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    for (index, raw) in raw_rule_sets.iter().enumerate() {
        let tag = raw
            .tag
            .as_deref()
            .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRuleSetTag))?;
        validate_tag(tag, ConfigField::RouteRuleSetTag)?;
        if matches!(tag, "." | "..") {
            return Err(ConfigError::semantic(ConfigField::RouteRuleSetTag));
        }
        if raw_rule_sets[..index]
            .iter()
            .any(|other| other.tag.as_deref() == Some(tag))
        {
            return Err(ConfigError::semantic(ConfigField::RouteRuleSetTag));
        }
        if raw.rule_set_type.as_deref() != Some("remote") {
            return Err(ConfigError::semantic(ConfigField::RouteRuleSetType));
        }
        if raw
            .format
            .as_deref()
            .is_some_and(|format| format != "binary")
        {
            return Err(ConfigError::semantic(ConfigField::RouteRuleSetFormat));
        }
        let url = raw
            .url
            .as_deref()
            .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRuleSetUrl))?;
        validate_https_srs_url(url, raw.format.is_none())?;
        let download_detour = raw
            .download_detour
            .as_deref()
            .map(|tag| {
                resolve_egress(
                    tag,
                    outbound_tags,
                    selectors,
                    chains,
                    ConfigField::RouteRuleSetDownloadDetour,
                )
            })
            .transpose()?;
        let download_mode = match raw.download_resolver.as_deref() {
            Some(resolver) => PreparedRuleSetDownloadMode::ClientResolved {
                resolver: parse_resolver(
                    resolver,
                    dns_servers,
                    ConfigField::RouteRuleSetDownloadResolver,
                )?,
            },
            None if download_detour.is_some() => PreparedRuleSetDownloadMode::DeferredToDetour,
            None => {
                return Err(ConfigError::dns_resolver_required(
                    ConfigField::RouteRuleSetDownloadResolver,
                ));
            }
        };
        if download_mode == PreparedRuleSetDownloadMode::DeferredToDetour
            && download_detour.and_then(|detour| capabilities.get(detour)) != Some(true)
        {
            return Err(ConfigError::semantic(
                ConfigField::RouteRuleSetDownloadDetour,
            ));
        }
        let update_interval = raw
            .update_interval_seconds
            .map(|seconds| {
                if seconds == 0 {
                    Err(ConfigError::semantic(
                        ConfigField::RouteRuleSetUpdateInterval,
                    ))
                } else {
                    Ok(Duration::from_secs(seconds))
                }
            })
            .transpose()?;
        prepared.push(PreparedRuleSet {
            tag: tag.into(),
            url: url.into(),
            download_mode,
            download_detour,
            update_interval,
        });
    }
    Ok(prepared)
}

fn validate_https_srs_url(url: &str, infer_format: bool) -> Result<(), ConfigError> {
    if url.len() > 8_192 || url.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(ConfigError::semantic(ConfigField::RouteRuleSetUrl));
    }
    let remainder = url
        .strip_prefix("https://")
        .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRuleSetUrl))?;
    if remainder.contains('#') {
        return Err(ConfigError::semantic(ConfigField::RouteRuleSetUrl));
    }
    let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() || authority.contains('@') || authority.starts_with('[') {
        return Err(ConfigError::semantic(ConfigField::RouteRuleSetUrl));
    }
    let host = if let Some((host, port)) = authority.rsplit_once(':') {
        port.parse::<u16>()
            .ok()
            .and_then(NonZeroU16::new)
            .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRuleSetUrl))?;
        host
    } else {
        authority
    };
    if host.parse::<IpAddr>().is_ok() || !valid_domain(host) {
        return Err(ConfigError::semantic(ConfigField::RouteRuleSetUrl));
    }
    let path = remainder[authority_end..]
        .split_once('?')
        .map_or(&remainder[authority_end..], |(path, _)| path);
    if infer_format && !path.ends_with(".srs") {
        return Err(ConfigError::semantic(ConfigField::RouteRuleSetFormat));
    }
    Ok(())
}

fn resolve_egress(
    tag: &str,
    outbound_tags: &[&str],
    selectors: &[RawSelector],
    chains: &[RawChain],
    field: ConfigField,
) -> Result<PreparedEgressRef, ConfigError> {
    validate_tag(tag, field)?;
    if let Some(index) = outbound_tags.iter().position(|candidate| *candidate == tag) {
        return Ok(PreparedEgressRef::Outbound(index));
    }
    if let Some(index) = selectors.iter().position(|candidate| candidate.tag == tag) {
        return Ok(PreparedEgressRef::Selector(index));
    }
    if let Some(index) = chains
        .iter()
        .position(|candidate| candidate.tag.as_deref() == Some(tag))
    {
        return Ok(PreparedEgressRef::Chain(index));
    }
    Err(ConfigError::semantic(field))
}

fn prepare_egress_capabilities(
    outbound_tags: &[&str],
    selectors: &[RawSelector],
    chains: &[RawChain],
) -> Result<PreparedEgressCapabilities, ConfigError> {
    let mut capabilities = PreparedEgressCapabilities {
        outbounds: vec![true; outbound_tags.len()],
        selectors: vec![false; selectors.len()],
        chains: vec![false; chains.len()],
    };
    let mut selector_state = vec![0_u8; selectors.len()];
    let mut chain_state = vec![0_u8; chains.len()];
    let mut stack = Vec::new();
    for index in 0..selectors.len() {
        evaluate_egress_capability(
            PreparedEgressRef::Selector(index),
            outbound_tags,
            selectors,
            chains,
            &mut capabilities,
            &mut selector_state,
            &mut chain_state,
            &mut stack,
        )?;
        debug_assert!(stack.is_empty());
    }
    for index in 0..chains.len() {
        evaluate_egress_capability(
            PreparedEgressRef::Chain(index),
            outbound_tags,
            selectors,
            chains,
            &mut capabilities,
            &mut selector_state,
            &mut chain_state,
            &mut stack,
        )?;
        debug_assert!(stack.is_empty());
    }
    Ok(capabilities)
}

#[allow(clippy::too_many_arguments)]
fn evaluate_egress_capability(
    egress: PreparedEgressRef,
    outbound_tags: &[&str],
    selectors: &[RawSelector],
    chains: &[RawChain],
    capabilities: &mut PreparedEgressCapabilities,
    selector_state: &mut [u8],
    chain_state: &mut [u8],
    stack: &mut Vec<PreparedEgressRef>,
) -> Result<bool, ConfigError> {
    match egress {
        PreparedEgressRef::Outbound(index) => capabilities
            .outbounds
            .get(index)
            .copied()
            .ok_or_else(|| ConfigError::semantic(ConfigField::ResourceMaterialization)),
        PreparedEgressRef::Selector(index) => {
            match selector_state.get(index).copied() {
                Some(2) => return Ok(capabilities.selectors[index]),
                Some(1) => {
                    return Err(capability_cycle_error(stack, egress)?);
                }
                Some(0) => {}
                _ => {
                    return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
                }
            }
            selector_state[index] = 1;
            stack
                .try_reserve(1)
                .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
            stack.push(egress);
            let members = &selectors[index].outbounds;
            if members.is_empty() {
                return Err(ConfigError::semantic(ConfigField::SelectorsOutbounds));
            }
            let mut accepts_domain_target = true;
            for member in members {
                let member = resolve_egress(
                    member,
                    outbound_tags,
                    selectors,
                    chains,
                    ConfigField::SelectorsOutbounds,
                )?;
                accepts_domain_target &= evaluate_egress_capability(
                    member,
                    outbound_tags,
                    selectors,
                    chains,
                    capabilities,
                    selector_state,
                    chain_state,
                    stack,
                )?;
            }
            if stack.pop() != Some(egress) {
                return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
            }
            capabilities.selectors[index] = accepts_domain_target;
            selector_state[index] = 2;
            Ok(accepts_domain_target)
        }
        PreparedEgressRef::Chain(index) => {
            match chain_state.get(index).copied() {
                Some(2) => return Ok(capabilities.chains[index]),
                Some(1) => {
                    return Err(capability_cycle_error(stack, egress)?);
                }
                Some(0) => {}
                _ => {
                    return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
                }
            }
            chain_state[index] = 1;
            stack
                .try_reserve(1)
                .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
            stack.push(egress);
            let terminal = chains[index]
                .hops
                .as_deref()
                .and_then(<[String]>::last)
                .ok_or_else(|| ConfigError::semantic(ConfigField::ChainsHops))?;
            let terminal = resolve_egress(
                terminal,
                outbound_tags,
                selectors,
                chains,
                ConfigField::ChainsHops,
            )?;
            let accepts_domain_target = evaluate_egress_capability(
                terminal,
                outbound_tags,
                selectors,
                chains,
                capabilities,
                selector_state,
                chain_state,
                stack,
            )?;
            if stack.pop() != Some(egress) {
                return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
            }
            capabilities.chains[index] = accepts_domain_target;
            chain_state[index] = 2;
            Ok(accepts_domain_target)
        }
    }
}

fn capability_cycle_error(
    stack: &[PreparedEgressRef],
    repeated: PreparedEgressRef,
) -> Result<ConfigError, ConfigError> {
    let start = stack
        .iter()
        .position(|candidate| *candidate == repeated)
        .ok_or_else(|| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    let cycle_len = stack
        .len()
        .checked_sub(start)
        .and_then(|length| length.checked_add(1))
        .ok_or_else(|| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    let mut path = Vec::new();
    path.try_reserve_exact(cycle_len)
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    for egress in &stack[start..] {
        path.push(egress_node(*egress)?);
    }
    path.push(egress_node(repeated)?);
    Ok(ConfigError::dependency_cycle(path))
}

fn validate_deferred_dns_detours(
    dns: Option<&RawDns>,
    endpoints: &[PreparedDnsEndpoint],
    outbound_tags: &[&str],
    selectors: &[RawSelector],
    chains: &[RawChain],
    capabilities: &PreparedEgressCapabilities,
) -> Result<(), ConfigError> {
    let servers = dns.and_then(|dns| dns.servers.as_deref()).unwrap_or(&[]);
    if servers.len() != endpoints.len() {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    for (server, endpoint) in servers.iter().zip(endpoints) {
        if endpoint.mode() != PreparedDnsEndpointMode::DeferredToDetour {
            continue;
        }
        let detour = resolve_egress(
            server
                .detour
                .as_deref()
                .ok_or_else(|| ConfigError::semantic(ConfigField::DnsServersDetour))?,
            outbound_tags,
            selectors,
            chains,
            ConfigField::DnsServersDetour,
        )?;
        if capabilities.get(detour) != Some(true) {
            return Err(ConfigError::semantic(ConfigField::DnsServersDetour));
        }
    }
    Ok(())
}

fn prepare_route_rule_sets(
    route: Option<&RawRoute>,
    rule_sets: &[PreparedRuleSet],
) -> Result<Vec<PreparedRouteRuleSets>, ConfigError> {
    let Some(route) = route else {
        return Ok(Vec::new());
    };
    let mut prepared = Vec::new();
    for (rule_index, rule) in route.rules.iter().enumerate() {
        let Some(raw_refs) = rule.rule_set.as_ref() else {
            continue;
        };
        if matches!(rule.action.as_deref(), Some("sniff" | "hijack-dns")) {
            return Err(ConfigError::semantic(ConfigField::RouteRulesRuleSet));
        }
        prepared
            .try_reserve(1)
            .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
        prepared.push(PreparedRouteRuleSets {
            rule_index,
            rule_sets: resolve_rule_set_refs(raw_refs, rule_sets, ConfigField::RouteRulesRuleSet)?,
        });
    }
    Ok(prepared)
}

#[derive(Clone, Copy)]
enum PreparedDnsRole {
    Client,
    Server,
}

struct PreparedDnsPolicyDraft {
    rules: Vec<PreparedDnsRule>,
    final_server: Option<usize>,
}

fn prepare_dns_rules(
    dns: Option<&RawDns>,
    rule_sets: &[PreparedRuleSet],
    strategy: Option<DnsStrategy>,
    role: PreparedDnsRole,
    ordinary_inbounds: &[&str],
    source: &str,
) -> Result<PreparedDnsPolicyDraft, ConfigError> {
    let Some(dns) = dns else {
        return Ok(PreparedDnsPolicyDraft {
            rules: Vec::new(),
            final_server: None,
        });
    };
    let servers = dns.servers.as_deref().unwrap_or(&[]);
    let route = dns
        .route
        .as_ref()
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRoute))?;
    let final_server = route
        .final_server
        .as_deref()
        .and_then(|tag| servers.iter().position(|server| server.tag == tag))
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteFinal))?;
    let default_strategy = strategy.unwrap_or(DnsStrategy::PreferIpv4);
    let mut prepared = Vec::new();
    prepared
        .try_reserve_exact(route.rules.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    for (rule_index, rule) in route.rules.iter().enumerate() {
        if !dns_matcher_present(rule) {
            return Err(ConfigError::semantic(ConfigField::DnsRouteRules));
        }
        let matcher = prepare_dns_matcher(rule, dns, role, ordinary_inbounds, source)?;
        let rule_sets = rule
            .rule_set
            .as_ref()
            .map(|raw| resolve_rule_set_refs(raw, rule_sets, ConfigField::DnsRouteRulesRuleSet))
            .transpose()?
            .unwrap_or_default();
        let action = match rule.action.as_deref().unwrap_or("route") {
            "route" => {
                if rule.outbound.is_some() {
                    return Err(ConfigError::semantic(ConfigField::DnsRouteRulesServer));
                }
                let server = rule
                    .server
                    .as_deref()
                    .and_then(|tag| servers.iter().position(|server| server.tag == tag))
                    .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesServer))?;
                PreparedDnsAction::Route { server }
            }
            "reject" => {
                if rule.server.is_some() || rule.outbound.is_some() {
                    return Err(ConfigError::semantic(ConfigField::DnsRouteRulesServer));
                }
                if rule.strategy.is_some() {
                    return Err(ConfigError::semantic(ConfigField::DnsRouteRulesStrategy));
                }
                PreparedDnsAction::Reject
            }
            _ => return Err(ConfigError::semantic(ConfigField::DnsRouteRulesAction)),
        };
        let strategy = match action {
            PreparedDnsAction::Reject => default_strategy,
            PreparedDnsAction::Route { .. } => rule
                .strategy
                .as_deref()
                .map_or(Ok(default_strategy), |value| {
                    parse_strategy(Some(value), ConfigField::DnsRouteRulesStrategy)
                })?,
        };
        prepared.push(PreparedDnsRule {
            rule_index,
            rule_sets,
            action,
            strategy,
            matcher,
        });
    }
    Ok(PreparedDnsPolicyDraft {
        rules: prepared,
        final_server: Some(final_server),
    })
}

fn prepare_dns_matcher(
    rule: &RawDnsRouteRule,
    dns: &RawDns,
    role: PreparedDnsRole,
    ordinary_inbounds: &[&str],
    source: &str,
) -> Result<PreparedDnsMatcherDraft, ConfigError> {
    match role {
        PreparedDnsRole::Client => {
            if rule.domain.is_some() {
                return Err(ConfigError::semantic(ConfigField::DnsRouteRulesDomain));
            }
            if rule.domain_suffix.is_some() {
                return Err(ConfigError::semantic(
                    ConfigField::DnsRouteRulesDomainSuffix,
                ));
            }
            if rule.port.is_some() {
                return Err(ConfigError::semantic(ConfigField::DnsRouteRulesPort));
            }
            if rule.port_range.is_some() {
                return Err(ConfigError::semantic(ConfigField::DnsRouteRulesPortRange));
            }
            if rule.target.is_some()
                && (rule.qname.is_some()
                    || rule.qname_suffix.is_some()
                    || rule.domain_keyword.is_some()
                    || rule.qtype.is_some())
            {
                return Err(ConfigError::semantic(ConfigField::DnsRouteRulesTarget));
            }
        }
        PreparedDnsRole::Server => {
            if rule.qname.is_some() {
                return Err(ConfigError::semantic(ConfigField::DnsRouteRulesQname));
            }
            if rule.qname_suffix.is_some() {
                return Err(ConfigError::semantic(ConfigField::DnsRouteRulesQnameSuffix));
            }
            if rule.qtype.is_some() {
                return Err(ConfigError::semantic(ConfigField::DnsRouteRulesQtype));
            }
            if rule.target.is_some()
                && (rule.domain.is_some()
                    || rule.domain_suffix.is_some()
                    || rule.domain_keyword.is_some()
                    || rule.port.is_some()
                    || rule.port_range.is_some())
            {
                return Err(ConfigError::semantic(ConfigField::DnsRouteRulesTarget));
            }
        }
    }

    let mut query_fields = Vec::new();
    query_fields
        .try_reserve_exact(4)
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    let (exact, suffix) = match role {
        PreparedDnsRole::Client => (
            (rule.qname.as_ref(), ConfigField::DnsRouteRulesQname),
            (
                rule.qname_suffix.as_ref(),
                ConfigField::DnsRouteRulesQnameSuffix,
            ),
        ),
        PreparedDnsRole::Server => (
            (rule.domain.as_ref(), ConfigField::DnsRouteRulesDomain),
            (
                rule.domain_suffix.as_ref(),
                ConfigField::DnsRouteRulesDomainSuffix,
            ),
        ),
    };
    push_prepared_dns_domain_field(
        &mut query_fields,
        exact.0,
        exact.1,
        PreparedDomainField::Exact,
    )?;
    push_prepared_dns_domain_field(
        &mut query_fields,
        suffix.0,
        suffix.1,
        PreparedDomainField::Suffix,
    )?;
    push_prepared_dns_domain_field(
        &mut query_fields,
        rule.domain_keyword.as_ref(),
        ConfigField::DnsRouteRulesDomainKeyword,
        PreparedDomainField::Keyword,
    )?;

    let listeners = dns.inbounds.as_deref().unwrap_or(&[]);
    let inbounds = rule
        .inbound
        .as_ref()
        .map(|values| {
            prepare_dns_values(
                values,
                ConfigField::DnsRouteRulesInbound,
                |tag| match role {
                    PreparedDnsRole::Client => listeners
                        .iter()
                        .position(|candidate| candidate.tag == *tag)
                        .or_else(|| {
                            ordinary_inbounds
                                .iter()
                                .position(|candidate| *candidate == tag)
                                .map(|index| listeners.len() + index)
                        })
                        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesInbound)),
                    PreparedDnsRole::Server => ordinary_inbounds
                        .iter()
                        .position(|candidate| *candidate == tag)
                        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesInbound)),
                },
            )
        })
        .transpose()?
        .unwrap_or_default();
    let networks = rule
        .network
        .as_ref()
        .map(|values| {
            prepare_dns_values(
                values,
                ConfigField::DnsRouteRulesNetwork,
                |value| match value.as_str() {
                    "tcp" => Ok(Network::Tcp),
                    "udp" => Ok(Network::Udp),
                    _ => Err(ConfigError::semantic(ConfigField::DnsRouteRulesNetwork)),
                },
            )
        })
        .transpose()?
        .unwrap_or_default();
    let qtypes = rule
        .qtype
        .as_ref()
        .map(|values| {
            prepare_dns_values(values, ConfigField::DnsRouteRulesQtype, |value| {
                parse_dns_record_type(value)
            })
        })
        .transpose()?
        .unwrap_or_default();
    let mut ports = rule
        .port
        .as_ref()
        .map(|values| {
            prepare_dns_values(values, ConfigField::DnsRouteRulesPort, |value| {
                u16::try_from(*value)
                    .ok()
                    .and_then(NonZeroU16::new)
                    .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesPort))
            })
        })
        .transpose()?
        .unwrap_or_default();
    let port_ranges = rule
        .port_range
        .as_ref()
        .map(|values| {
            prepare_dns_values(values, ConfigField::DnsRouteRulesPortRange, |value| {
                parse_dns_port_range(value)
            })
        })
        .transpose()?
        .unwrap_or_default();

    let mut dns_eligible = true;
    if let Some(target) = &rule.target {
        let target = validate_route_target(target, source, ConfigField::DnsRouteRulesTarget)?;
        match target.host() {
            TargetHostRef::Ip(_) => dns_eligible = false,
            TargetHostRef::Domain(domain) => {
                if matches!(role, PreparedDnsRole::Client) && target.port().get() != 53 {
                    dns_eligible = false;
                } else {
                    push_prepared_dns_domain_field(
                        &mut query_fields,
                        Some(&ScalarOrList::Scalar(domain.to_owned())),
                        ConfigField::DnsRouteRulesTarget,
                        PreparedDomainField::Exact,
                    )?;
                    if matches!(role, PreparedDnsRole::Server) {
                        ports.push(target.port());
                    }
                }
            }
        }
    }

    Ok(PreparedDnsMatcherDraft {
        query_fields,
        inbounds,
        networks,
        qtypes,
        ports,
        port_ranges,
        dns_eligible,
    })
}

#[derive(Clone, Copy)]
enum PreparedDomainField {
    Exact,
    Suffix,
    Keyword,
}

fn push_prepared_dns_domain_field(
    fields: &mut Vec<Arc<CompiledMatchSet>>,
    raw: Option<&ScalarOrList<String>>,
    field: ConfigField,
    kind: PreparedDomainField,
) -> Result<(), ConfigError> {
    let Some(raw) = raw else {
        return Ok(());
    };
    if raw.len() == 0 {
        return Err(ConfigError::semantic(field));
    }
    let mut builder = MatchSetBuilder::new();
    for value in raw.iter() {
        let domain = DomainName::new(value).map_err(|_| ConfigError::semantic(field))?;
        let result = match kind {
            PreparedDomainField::Exact => builder.add_domain(&domain),
            PreparedDomainField::Suffix => builder.add_domain_suffix_name(&domain),
            PreparedDomainField::Keyword => builder.add_domain_keyword(value),
        };
        result.map_err(|error| map_match_set_error(error, field))?;
    }
    let compiled = builder
        .build()
        .map_err(|error| map_match_set_error(error, field))?;
    fields
        .try_reserve(1)
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    fields.push(Arc::new(compiled));
    Ok(())
}

fn map_match_set_error(error: RuleCompileError, field: ConfigField) -> ConfigError {
    ConfigError::from_rule_compile(error, field)
}

fn prepare_dns_values<T, U: Eq>(
    raw: &ScalarOrList<T>,
    field: ConfigField,
    mut parse: impl FnMut(&T) -> Result<U, ConfigError>,
) -> Result<Vec<U>, ConfigError> {
    if raw.len() == 0 {
        return Err(ConfigError::semantic(field));
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(raw.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    for raw in raw.iter() {
        let value = parse(raw)?;
        if values.contains(&value) {
            return Err(ConfigError::semantic(field));
        }
        values.push(value);
    }
    Ok(values)
}

fn parse_dns_port_range(value: &str) -> Result<PortRange, ConfigError> {
    let (first, last) = value
        .split_once(':')
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesPortRange))?;
    let first = first
        .parse::<u16>()
        .map_err(|_| ConfigError::semantic(ConfigField::DnsRouteRulesPortRange))?;
    let last = last
        .parse::<u16>()
        .map_err(|_| ConfigError::semantic(ConfigField::DnsRouteRulesPortRange))?;
    PortRange::try_new(first, last)
        .map_err(|_| ConfigError::semantic(ConfigField::DnsRouteRulesPortRange))
}

fn parse_dns_record_type(value: &str) -> Result<u16, ConfigError> {
    match value.to_ascii_uppercase().as_str() {
        "A" => Ok(DnsQueryType::A as u16),
        "AAAA" => Ok(DnsQueryType::Aaaa as u16),
        "CNAME" => Ok(DnsQueryType::Cname as u16),
        "MX" => Ok(DnsQueryType::Mx as u16),
        "NS" => Ok(DnsQueryType::Ns as u16),
        "PTR" => Ok(DnsQueryType::Ptr as u16),
        "SOA" => Ok(DnsQueryType::Soa as u16),
        "SRV" => Ok(DnsQueryType::Srv as u16),
        "TXT" => Ok(DnsQueryType::Txt as u16),
        "CAA" => Ok(DnsQueryType::Caa as u16),
        "SVCB" => Ok(DnsQueryType::Svcb as u16),
        "HTTPS" => Ok(DnsQueryType::Https as u16),
        "ANY" => Ok(DnsQueryType::Any as u16),
        _ => Err(ConfigError::semantic(ConfigField::DnsRouteRulesQtype)),
    }
}

fn resolve_rule_set_refs(
    raw: &ScalarOrList<String>,
    rule_sets: &[PreparedRuleSet],
    field: ConfigField,
) -> Result<Vec<usize>, ConfigError> {
    if raw.len() == 0 {
        return Err(ConfigError::semantic(field));
    }
    let mut resolved = Vec::new();
    resolved
        .try_reserve_exact(raw.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    for tag in raw.iter() {
        validate_tag(tag, field)?;
        let index = rule_sets
            .iter()
            .position(|rule_set| rule_set.tag() == tag)
            .ok_or_else(|| ConfigError::semantic(field))?;
        if resolved.contains(&index) {
            return Err(ConfigError::semantic(field));
        }
        resolved.push(index);
    }
    Ok(resolved)
}

fn dns_matcher_present(rule: &RawDnsRouteRule) -> bool {
    rule.inbound.is_some()
        || rule.network.is_some()
        || rule.target.is_some()
        || rule.qname.is_some()
        || rule.qname_suffix.is_some()
        || rule.qtype.is_some()
        || rule.domain.is_some()
        || rule.domain_suffix.is_some()
        || rule.domain_keyword.is_some()
        || rule.rule_set.is_some()
        || rule.port.is_some()
        || rule.port_range.is_some()
}

#[allow(clippy::too_many_arguments)]
fn build_dependency_order(
    dns: Option<&RawDns>,
    dns_endpoints: &[PreparedDnsEndpoint],
    outbound_tags: &[&str],
    outbound_endpoints: &[Option<DialEndpoint>],
    direct_domain_resolvers: &[Option<DirectDomainResolver>],
    selectors: &[RawSelector],
    chains: &[RawChain],
    rule_sets: &[PreparedRuleSet],
) -> Result<Vec<DependencyNode>, ConfigError> {
    let mut graph = DependencyGraph::new();
    graph
        .try_add_node(DependencyNode::system_resolver())
        .map_err(map_dependency_error)?;
    for index in 0..dns_endpoints.len() {
        graph
            .try_add_node(dns_node(index)?)
            .map_err(map_dependency_error)?;
    }
    for index in 0..outbound_tags.len() {
        graph
            .try_add_node(outbound_node(index)?)
            .map_err(map_dependency_error)?;
    }
    for index in 0..selectors.len() {
        graph
            .try_add_node(selector_node(index)?)
            .map_err(map_dependency_error)?;
    }
    for index in 0..chains.len() {
        graph
            .try_add_node(chain_node(index)?)
            .map_err(map_dependency_error)?;
    }
    for index in 0..rule_sets.len() {
        graph
            .try_add_node(rule_set_node(index)?)
            .map_err(map_dependency_error)?;
    }

    let raw_dns_servers = dns.and_then(|dns| dns.servers.as_deref()).unwrap_or(&[]);
    for (index, endpoint) in dns_endpoints.iter().enumerate() {
        let from = dns_node(index)?;
        if let Some(resolver) = endpoint.resolver() {
            graph
                .try_add_edge(
                    from,
                    resolver_node(resolver)?,
                    DependencySource::DnsServerDomainResolver {
                        server: checked_u32(index)?,
                    },
                )
                .map_err(map_dependency_error)?;
        }
        if let Some(detour) = raw_dns_servers
            .get(index)
            .and_then(|server| server.detour.as_deref())
        {
            let detour = resolve_egress(
                detour,
                outbound_tags,
                selectors,
                chains,
                ConfigField::DnsServersDetour,
            )?;
            graph
                .try_add_edge(
                    from,
                    egress_node(detour)?,
                    DependencySource::DnsServerDetour {
                        server: checked_u32(index)?,
                    },
                )
                .map_err(map_dependency_error)?;
        }
    }
    for (index, endpoint) in outbound_endpoints.iter().enumerate() {
        if let Some(resolver) = endpoint.as_ref().and_then(DialEndpoint::resolver) {
            graph
                .try_add_edge(
                    outbound_node(index)?,
                    resolver_node(resolver)?,
                    DependencySource::OutboundDomainResolver {
                        outbound: checked_u32(index)?,
                    },
                )
                .map_err(map_dependency_error)?;
        }
    }
    for (index, resolver) in direct_domain_resolvers.iter().enumerate() {
        let Some(DirectDomainResolver::DnsServer { server, .. }) = resolver else {
            continue;
        };
        graph
            .try_add_edge(
                outbound_node(index)?,
                dns_node(*server)?,
                DependencySource::OutboundDomainResolver {
                    outbound: checked_u32(index)?,
                },
            )
            .map_err(map_dependency_error)?;
    }
    for (index, selector) in selectors.iter().enumerate() {
        let mut members = Vec::new();
        members
            .try_reserve_exact(selector.outbounds.len())
            .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
        for member in &selector.outbounds {
            members.push(egress_node(resolve_egress(
                member,
                outbound_tags,
                selectors,
                chains,
                ConfigField::SelectorsOutbounds,
            )?)?);
        }
        graph
            .try_add_selector_members(checked_u64(index)?, members)
            .map_err(map_dependency_error)?;
    }
    for (index, chain) in chains.iter().enumerate() {
        let Some(hops) = chain.hops.as_deref() else {
            continue;
        };
        let mut targets = Vec::new();
        targets
            .try_reserve_exact(hops.len())
            .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
        for hop in hops {
            targets.push(egress_node(resolve_egress(
                hop,
                outbound_tags,
                selectors,
                chains,
                ConfigField::ChainsHops,
            )?)?);
        }
        graph
            .try_add_chain_hops(checked_u64(index)?, targets)
            .map_err(map_dependency_error)?;
    }
    for (index, rule_set) in rule_sets.iter().enumerate() {
        let from = rule_set_node(index)?;
        if let Some(resolver) = rule_set.download_resolver() {
            graph
                .try_add_edge(
                    from,
                    resolver_node(resolver)?,
                    DependencySource::RuleSetDownloadResolver {
                        rule_set: checked_u32(index)?,
                    },
                )
                .map_err(map_dependency_error)?;
        }
        if let Some(detour) = rule_set.download_detour() {
            graph
                .try_add_edge(
                    from,
                    egress_node(detour)?,
                    DependencySource::RuleSetDownloadDetour {
                        rule_set: checked_u32(index)?,
                    },
                )
                .map_err(map_dependency_error)?;
        }
    }
    graph.topological_order().map_err(map_dependency_error)
}

fn map_dependency_error(error: DependencyGraphError) -> ConfigError {
    match error {
        DependencyGraphError::Cycle(cycle) => ConfigError::dependency_cycle(cycle.into_path()),
        _ => ConfigError::semantic(ConfigField::ResourceMaterialization),
    }
}

fn resolver_node(resolver: ResolverRef) -> Result<DependencyNode, ConfigError> {
    match resolver {
        ResolverRef::System => Ok(DependencyNode::system_resolver()),
        ResolverRef::DnsServer(index) => dns_node(index),
    }
}

fn egress_node(egress: PreparedEgressRef) -> Result<DependencyNode, ConfigError> {
    match egress {
        PreparedEgressRef::Outbound(index) => outbound_node(index),
        PreparedEgressRef::Selector(index) => selector_node(index),
        PreparedEgressRef::Chain(index) => chain_node(index),
    }
}

fn dns_node(index: usize) -> Result<DependencyNode, ConfigError> {
    DependencyNode::try_dns_server(checked_u64(index)?).map_err(map_dependency_error)
}

fn outbound_node(index: usize) -> Result<DependencyNode, ConfigError> {
    DependencyNode::try_outbound(checked_u64(index)?).map_err(map_dependency_error)
}

fn selector_node(index: usize) -> Result<DependencyNode, ConfigError> {
    DependencyNode::try_selector(checked_u64(index)?).map_err(map_dependency_error)
}

fn chain_node(index: usize) -> Result<DependencyNode, ConfigError> {
    DependencyNode::try_chain(checked_u64(index)?).map_err(map_dependency_error)
}

fn rule_set_node(index: usize) -> Result<DependencyNode, ConfigError> {
    DependencyNode::try_rule_set(checked_u64(index)?).map_err(map_dependency_error)
}

fn checked_u64(index: usize) -> Result<u64, ConfigError> {
    u64::try_from(index).map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))
}

fn checked_u32(index: usize) -> Result<u32, ConfigError> {
    u32::try_from(index).map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))
}

fn sanitize_client(raw: &mut RawClientRoot) {
    if let Some(outbounds) = &mut raw.outbounds {
        for outbound in outbounds {
            if outbound
                .server
                .as_deref()
                .is_some_and(|server| server.parse::<SocketAddr>().is_err())
            {
                outbound.server = Some(PLACEHOLDER_ENDPOINT.to_owned());
            }
        }
    }
    sanitize_route(raw.route.as_mut());
    sanitize_dns(raw.dns.as_mut());
}

fn sanitize_server(raw: &mut RawServerRoot) {
    sanitize_route(raw.route.as_mut());
    sanitize_dns(raw.dns.as_mut());
}

fn sanitize_route(route: Option<&mut RawRoute>) {
    let Some(route) = route else {
        return;
    };
    route.rule_set.clear();
}

fn sanitize_dns(dns: Option<&mut RawDns>) {
    let Some(dns) = dns else {
        return;
    };
    if let Some(servers) = &mut dns.servers {
        for server in servers {
            if server.address.parse::<SocketAddr>().is_err() {
                server.address = PLACEHOLDER_ENDPOINT.to_owned();
            }
        }
    }
    let Some(route) = &mut dns.route else {
        return;
    };
    let final_server = route.final_server.clone();
    for rule in &mut route.rules {
        rule.rule_set = None;
        if !dns_matcher_present(rule) {
            rule.domain_keyword = Some(ScalarOrList::Scalar(PLACEHOLDER_DOMAIN.to_owned()));
        }
        if rule.action.as_deref() == Some("reject") {
            rule.server = final_server.clone();
        }
        rule.action = None;
        rule.strategy = None;
    }
}
