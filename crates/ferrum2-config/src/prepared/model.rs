use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ferrum2_core::route::EgressPlanHandle;
use ferrum2_core::{CanonicalDomain, TargetAddr};
use ferrum2_crypto::{MethodProfile, MethodPsk};
use ferrum2_rule::{CompiledMatchSet, Network, PortRange};

use crate::dependency::DependencyNode;
use crate::model::{
    DirectDomainResolver, DnsCacheConfig, DnsRuntimeConfig, DnsStrategy, DnsTransport,
    OutboundDialOptions, ResolverRef, RouteNetworkConfig, RuntimeConfig, ValidatedClientConfig,
    ValidatedServerConfig,
};

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
    pub(super) target: TargetAddr,
    pub(super) mode: PreparedDnsEndpointMode,
    pub(super) fixed_endpoint: Option<DialEndpoint>,
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

    pub(super) const fn fixed_endpoint(&self) -> Option<&DialEndpoint> {
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
    pub(super) target: PreparedFixedEndpointTarget,
    pub(super) endpoint: &'a DialEndpoint,
}

impl<'a> PreparedFixedEndpointDescriptor<'a> {
    pub(super) const fn new(
        target: PreparedFixedEndpointTarget,
        endpoint: &'a DialEndpoint,
    ) -> Self {
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
    pub(super) index: u32,
    pub(super) transport: DnsTransport,
    pub(super) server_name: Option<&'a str>,
    pub(super) path: Option<&'a str>,
    pub(super) detour: Option<&'a EgressPlanHandle>,
    pub(super) endpoint: &'a PreparedDnsEndpoint,
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
    pub(super) index: u32,
    pub(super) kind: PreparedClientOutboundKind,
    pub(super) method: Option<MethodProfile>,
    pub(super) psk: Option<&'a Arc<MethodPsk>>,
    pub(super) endpoint: Option<&'a DialEndpoint>,
    pub(super) domain_resolver: Option<DirectDomainResolver>,
    pub(super) dial_options: &'a OutboundDialOptions,
}

impl<'a> PreparedClientOutboundDescriptor<'a> {
    pub const fn index(self) -> u32 {
        self.index
    }

    pub const fn kind(self) -> PreparedClientOutboundKind {
        self.kind
    }

    pub const fn method(self) -> Option<MethodProfile> {
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

    pub const fn dial_options(self) -> &'a OutboundDialOptions {
        self.dial_options
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
            .field("dial_options", &"[redacted]")
            .finish()
    }
}

/// Redacted bootstrap description of one server Direct outbound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedServerOutboundDescriptor<'a> {
    pub(super) index: u32,
    pub(super) domain_resolver: DirectDomainResolver,
    pub(super) dial_options: &'a OutboundDialOptions,
}

impl<'a> PreparedServerOutboundDescriptor<'a> {
    pub const fn index(self) -> u32 {
        self.index
    }

    pub const fn domain_resolver(self) -> DirectDomainResolver {
        self.domain_resolver
    }

    pub const fn dial_options(self) -> &'a OutboundDialOptions {
        self.dial_options
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
pub(super) struct PreparedEgressCapabilities {
    pub(super) outbounds: Vec<bool>,
    pub(super) selectors: Vec<bool>,
    pub(super) chains: Vec<bool>,
}

impl PreparedEgressCapabilities {
    pub(super) fn get(&self, egress: PreparedEgressRef) -> Option<bool> {
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
    pub(super) tag: Box<str>,
    pub(super) url: Box<str>,
    pub(super) download_mode: PreparedRuleSetDownloadMode,
    pub(super) download_detour: Option<PreparedEgressRef>,
    pub(super) update_interval: Option<Duration>,
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
pub(super) struct PreparedDnsMatcherDraft {
    pub(super) query_fields: Vec<Arc<CompiledMatchSet>>,
    pub(super) inbounds: Vec<usize>,
    pub(super) networks: Vec<Network>,
    pub(super) qtypes: Vec<u16>,
    pub(super) ports: Vec<NonZeroU16>,
    pub(super) port_ranges: Vec<PortRange>,
}

/// One statically compiled DNS row whose RuleSet matcher is deferred.
#[derive(Clone)]
pub struct PreparedDnsRule {
    pub rule_index: usize,
    pub rule_sets: Vec<usize>,
    pub action: PreparedDnsAction,
    pub strategy: DnsStrategy,
    pub(super) matcher: PreparedDnsMatcherDraft,
}

impl std::fmt::Debug for PreparedDnsRule {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedDnsRule([redacted])")
    }
}

/// Side-effect-free client schema-v2 preparation result.
pub struct PreparedClientV2 {
    pub(super) validated: ValidatedClientConfig,
    pub(super) physical_first_hops: Vec<usize>,
    pub(super) direct_detours: Vec<bool>,
    pub(super) dependency_egress_plans: Vec<EgressPlanHandle>,
    pub(super) dependency_egress_direct: Vec<bool>,
    pub(super) rule_set_detour_plans: Vec<Option<usize>>,
    pub(super) rule_set_loader: RuleSetLoaderConfig,
    pub(super) rule_sets: Vec<PreparedRuleSet>,
    pub(super) route_rule_sets: Vec<PreparedRouteRuleSets>,
    pub(super) dns_rules: Vec<PreparedDnsRule>,
    pub(super) dns_final_server: Option<usize>,
    pub(super) dns_strategy: Option<DnsStrategy>,
    pub(super) dns_cache: Option<DnsCacheConfig>,
    pub(super) outbound_endpoints: Vec<Option<DialEndpoint>>,
    pub(super) dns_endpoints: Vec<PreparedDnsEndpoint>,
    pub(super) egress_domain_capabilities: PreparedEgressCapabilities,
    pub(super) dependency_order: Vec<PreparedDependencyNode>,
}

/// Side-effect-free server schema-v2 preparation result.
pub struct PreparedServerV2 {
    pub(super) validated: ValidatedServerConfig,
    pub(super) dependency_egress_plans: Vec<EgressPlanHandle>,
    pub(super) dependency_egress_direct: Vec<bool>,
    pub(super) rule_set_detour_plans: Vec<Option<usize>>,
    pub(super) rule_set_loader: RuleSetLoaderConfig,
    pub(super) rule_sets: Vec<PreparedRuleSet>,
    pub(super) route_rule_sets: Vec<PreparedRouteRuleSets>,
    pub(super) dns_rules: Vec<PreparedDnsRule>,
    pub(super) dns_final_server: Option<usize>,
    pub(super) dns_strategy: Option<DnsStrategy>,
    pub(super) dns_cache: Option<DnsCacheConfig>,
    pub(super) dns_endpoints: Vec<PreparedDnsEndpoint>,
    pub(super) egress_domain_capabilities: PreparedEgressCapabilities,
    pub(super) dependency_order: Vec<PreparedDependencyNode>,
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

            /// Returns the retained route-level interface-selection contract.
            pub const fn route_network(&self) -> &RouteNetworkConfig {
                &self.validated.route_network
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
