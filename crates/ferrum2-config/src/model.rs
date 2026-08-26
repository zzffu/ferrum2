use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;

use ferrum2_core::TargetAddr;
use ferrum2_crypto::{MethodProfile, MethodPsk};
use ferrum2_rule::{
    DnsPolicyBlueprint, EgressPlanHandle, Network, OrderedRouteProgram,
    RouteProgramEvaluationWithScratch, RuleCompileError, RuleEvaluationScratch,
};
use ferrum2_rule::{RuleEngineRegistry, SelectorControl};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// A validated client configuration with no retained source text.
pub struct ValidatedClientConfig {
    pub schema_version: SchemaVersion,
    pub inbounds: Vec<ClientInboundConfig>,
    pub outbounds: Vec<ClientOutboundConfig>,
    pub route: CompiledRoute,
    pub route_network: RouteNetworkConfig,
    pub tun: Option<TunConfig>,
    pub dns: Option<DnsConfig>,
    pub dns_route: Option<ClientDnsRoute>,
    pub runtime: RuntimeConfig,
    pub udp: Option<UdpConfig>,
    pub logging: LoggingConfig,
    pub metrics: Option<MetricsConfig>,
}

/// Validated family-neutral Windows TUN configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunConfig {
    pub adapter_name: Box<str>,
    pub ipv4_address: Option<Ipv4Net>,
    pub ipv6_address: Option<Ipv6Net>,
    pub auto_route: bool,
    /// The source-level strict-route request, retained even when automatic routing is disabled.
    pub strict_route: bool,
    pub capture_routes: Vec<IpNet>,
    pub auto_dns: bool,
    pub ipv4_dns_address: Option<Ipv4Addr>,
    pub ipv6_dns_address: Option<Ipv6Addr>,
    pub physical_endpoints: Vec<SocketAddr>,
    pub mtu: u16,
    pub ring_capacity: u32,
    pub ready_timeout: Duration,
    pub max_tcp_flows: usize,
    pub tcp_buffer_bytes: usize,
    pub max_udp_mappings: usize,
    pub udp_filtering: UdpFiltering,
}

impl TunConfig {
    /// Reports the source-level strict-route request without applying its `auto_route` gate.
    pub const fn strict_route_requested(&self) -> bool {
        self.strict_route
    }

    /// Reports whether strict routing is effective under the closed configuration contract.
    pub const fn strict_route_effective(&self) -> bool {
        self.auto_route && self.strict_route
    }
}

/// Source-address filtering applied to one endpoint-independent UDP association.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UdpFiltering {
    AddressDependent,
    #[default]
    EndpointIndependent,
}

/// One validated SOCKS5 listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientInboundConfig {
    pub listen: SocketAddrV4,
}

/// One validated client egress identity.
pub enum ClientOutboundConfig {
    Shadowsocks {
        server: SocketAddr,
        psk: Arc<MethodPsk>,
        dial_options: OutboundDialOptions,
    },
    Direct {
        domain_resolver: DirectDomainResolver,
        dial_options: OutboundDialOptions,
    },
}

impl ClientOutboundConfig {
    pub const fn server(&self) -> Option<SocketAddr> {
        match self {
            Self::Shadowsocks { server, .. } => Some(*server),
            Self::Direct { .. } => None,
        }
    }

    pub fn method(&self) -> Option<MethodProfile> {
        match self {
            Self::Shadowsocks { psk, .. } => Some(psk.profile()),
            Self::Direct { .. } => None,
        }
    }

    /// Returns the fixed resolver identity captured by one Direct outbound.
    pub const fn direct_domain_resolver(&self) -> Option<DirectDomainResolver> {
        match self {
            Self::Direct {
                domain_resolver, ..
            } => Some(*domain_resolver),
            Self::Shadowsocks { .. } => None,
        }
    }

    /// Returns the interface and source-address constraints for this socket owner.
    pub const fn dial_options(&self) -> &OutboundDialOptions {
        match self {
            Self::Shadowsocks { dial_options, .. } | Self::Direct { dial_options, .. } => {
                dial_options
            }
        }
    }
}

impl std::fmt::Debug for ClientOutboundConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Shadowsocks { .. } => "ClientOutboundConfig::Shadowsocks([redacted])",
            Self::Direct { .. } => "ClientOutboundConfig::Direct([redacted])",
        })
    }
}

impl ValidatedClientConfig {
    /// Returns a control handle sharing the route table's selector state.
    pub fn selector_control(&self) -> SelectorControl {
        self.route.selector_control()
    }
}

/// Validated route-level network-interface selection contract.
///
/// Runtime consumers must prefer an automatically detected interface over
/// `default_interface` when both values are configured.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteNetworkConfig {
    pub auto_detect_interface: bool,
    pub default_interface: Option<Box<str>>,
}

/// Validated interface and family-specific source-address constraints for one socket owner.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct OutboundDialOptions {
    pub bind_interface: Option<Box<str>>,
    pub inet4_bind_address: Option<Ipv4Addr>,
    pub inet6_bind_address: Option<Ipv6Addr>,
}

impl std::fmt::Debug for OutboundDialOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OutboundDialOptions")
            .field(
                "bind_interface",
                &self.bind_interface.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "inet4_bind_address",
                &self.inet4_bind_address.map(|_| "[redacted]"),
            )
            .field(
                "inet6_bind_address",
                &self.inet6_bind_address.map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl OutboundDialOptions {
    pub fn bind_interface(&self) -> Option<&str> {
        self.bind_interface.as_deref()
    }

    pub const fn inet4_bind_address(&self) -> Option<Ipv4Addr> {
        self.inet4_bind_address
    }

    pub const fn inet6_bind_address(&self) -> Option<Ipv6Addr> {
        self.inet6_bind_address
    }
}

impl RouteNetworkConfig {
    pub fn default_interface(&self) -> Option<&str> {
        self.default_interface.as_deref()
    }
}

/// A validated server configuration with no retained source text.
pub struct ValidatedServerConfig {
    pub schema_version: SchemaVersion,
    pub inbounds: Vec<ServerInboundConfig>,
    pub outbounds: Vec<ServerOutboundConfig>,
    pub route: CompiledRoute,
    pub route_network: RouteNetworkConfig,
    pub dns: Option<DnsConfig>,
    pub dns_route: Option<ServerDnsRoute>,
    pub psk: MethodPsk,
    pub runtime: RuntimeConfig,
    pub replay: ReplayConfig,
    pub udp: UdpConfig,
    pub logging: LoggingConfig,
    pub metrics: Option<MetricsConfig>,
}

/// One validated Shadowsocks listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerInboundConfig {
    pub listen: SocketAddrV4,
}

/// One validated direct server outbound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerOutboundConfig {
    pub domain_resolver: DirectDomainResolver,
    pub dial_options: OutboundDialOptions,
}

impl ServerOutboundConfig {
    pub const fn dial_options(&self) -> &OutboundDialOptions {
        &self.dial_options
    }
}

/// Explicit fixed-endpoint resolver; `System` is never an implicit fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolverRef {
    System,
    DnsServer(usize),
}

/// Resolver mode captured by one Direct outbound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectDomainResolver {
    System,
    DnsServer {
        server: usize,
        strategy: DnsStrategy,
    },
}

/// Explicit supported configuration versions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaVersion {
    V2,
}

/// Closed protocols recognized by ordinary route sniffing.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RouteProtocol {
    Dns,
    Tls,
    Http,
}

/// Validated sniffer selection for one non-terminal action.
#[derive(Debug, Eq, PartialEq)]
pub enum Sniffers {
    Default,
    Explicit(Vec<RouteProtocol>),
}

/// Closed ordinary route action set.
pub enum RouteAction {
    Route(EgressPlanHandle),
    Sniff(Sniffers),
    HijackDns,
    Reject,
}

impl std::fmt::Debug for RouteAction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Route(_) => "RouteAction::Route([redacted])",
            Self::Sniff(_) => "RouteAction::Sniff([redacted])",
            Self::HijackDns => "RouteAction::HijackDns",
            Self::Reject => "RouteAction::Reject",
        })
    }
}

/// Validated bounded TCP sniff resources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteSniffConfig {
    pub timeout: Duration,
    pub max_bytes: usize,
    pub max_aggregate_bytes: usize,
}

/// One compiled ordinary program and its shared sniff budget.
pub struct CompiledRoute {
    pub(super) program: OrderedRouteProgram<RouteProtocol, RouteAction>,
    pub(super) registry: Option<Arc<RuleEngineRegistry>>,
    pub(super) selector: SelectorControl,
    pub sniff: RouteSniffConfig,
}

impl CompiledRoute {
    /// Allocates one scratch owner that callers may reuse across route evaluations.
    pub fn evaluation_scratch(&self) -> Result<RuleEvaluationScratch, RuleCompileError> {
        self.program.evaluation_scratch()
    }

    /// Returns the current ruleset registry generation used for route snapshots.
    /// Registry-free route programs are immutable generation zero.
    pub fn rule_engine_generation(&self) -> u64 {
        self.registry
            .as_ref()
            .map_or(0, |registry| registry.generation())
    }

    pub const fn program_mode(&self) -> ferrum2_rule::RuleProgramMode {
        self.program.mode()
    }

    pub const fn rule_count(&self) -> usize {
        self.program.len()
    }

    /// Starts an allocation-free evaluation using caller-owned reusable scratch.
    pub fn evaluate_with_scratch<'program, 'target, 'scratch>(
        &'program self,
        inbound: usize,
        network: Network,
        original: &'target TargetAddr,
        scratch: &'scratch mut RuleEvaluationScratch,
    ) -> RouteProgramEvaluationWithScratch<'program, 'target, 'scratch, RouteProtocol, RouteAction>
    {
        match &self.registry {
            Some(registry) => self
                .program
                .evaluate_with_registry_and_scratch(inbound, network, original, registry, scratch),
            None => self
                .program
                .evaluate_with_scratch(inbound, network, original, scratch),
        }
    }

    /// Returns the live RuleSet registry captured by new-V2 evaluations.
    pub fn rule_registry(&self) -> Option<Arc<RuleEngineRegistry>> {
        self.registry.as_ref().map(Arc::clone)
    }

    /// Returns a control handle sharing this route program's selector state.
    pub fn selector_control(&self) -> SelectorControl {
        self.selector.clone()
    }

    pub(super) fn attach_rule_registry(&mut self, registry: Arc<RuleEngineRegistry>) {
        self.registry = Some(registry);
    }
}

/// Collision-free client DNS policy ingress identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsIngressId {
    Listener(usize),
    Ordinary(usize),
}

/// Stable closed DNS query types accepted by schema version 2.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum DnsQueryType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Ptr = 12,
    Mx = 15,
    Txt = 16,
    Aaaa = 28,
    Srv = 33,
    Svcb = 64,
    Https = 65,
    Any = 255,
    Caa = 257,
}

/// Compiled client query policy with distinct listener and ordinary identities.
pub struct ClientDnsRoute {
    pub(super) listener_count: usize,
    pub(super) ordinary_count: usize,
    pub(super) rule_count: usize,
    pub(super) policy_blueprint: Option<DnsPolicyBlueprintBinding>,
}

impl ClientDnsRoute {
    pub const fn listener_count(&self) -> usize {
        self.listener_count
    }

    pub const fn ordinary_count(&self) -> usize {
        self.ordinary_count
    }

    pub fn program_mode(&self) -> ferrum2_rule::RuleProgramMode {
        ferrum2_rule::RuleProgramMode::for_rule_count(self.rule_count)
    }

    pub const fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Returns the runtime-neutral materialized DNS policy blueprint.
    pub const fn policy_blueprint(&self) -> Option<&DnsPolicyBlueprintBinding> {
        self.policy_blueprint.as_ref()
    }

    /// Removes the blueprint so exactly one DNS execution program can consume it.
    pub fn take_policy_blueprint(&mut self) -> Option<DnsPolicyBlueprintBinding> {
        self.policy_blueprint.take()
    }

    pub(super) fn attach_policy_blueprint(
        &mut self,
        blueprint: DnsPolicyBlueprint,
        registry: Arc<RuleEngineRegistry>,
    ) {
        debug_assert_eq!(blueprint.len(), self.rule_count);
        self.policy_blueprint = Some(DnsPolicyBlueprintBinding::new(
            blueprint,
            registry,
            self.listener_count,
            self.ordinary_count,
        ));
    }
}

/// Compiled server application-domain resolution policy.
pub struct ServerDnsRoute {
    pub(super) ordinary_count: usize,
    pub(super) rule_count: usize,
    pub(super) policy_blueprint: Option<DnsPolicyBlueprintBinding>,
}

impl ServerDnsRoute {
    pub const fn ordinary_count(&self) -> usize {
        self.ordinary_count
    }

    pub fn program_mode(&self) -> ferrum2_rule::RuleProgramMode {
        ferrum2_rule::RuleProgramMode::for_rule_count(self.rule_count)
    }

    pub const fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Returns the runtime-neutral materialized DNS policy blueprint.
    pub const fn policy_blueprint(&self) -> Option<&DnsPolicyBlueprintBinding> {
        self.policy_blueprint.as_ref()
    }

    /// Removes the blueprint so exactly one DNS execution program can consume it.
    pub fn take_policy_blueprint(&mut self) -> Option<DnsPolicyBlueprintBinding> {
        self.policy_blueprint.take()
    }

    pub(super) fn attach_policy_blueprint(
        &mut self,
        blueprint: DnsPolicyBlueprint,
        registry: Arc<RuleEngineRegistry>,
    ) {
        debug_assert_eq!(blueprint.len(), self.rule_count);
        self.policy_blueprint = Some(DnsPolicyBlueprintBinding::new(
            blueprint,
            registry,
            0,
            self.ordinary_count,
        ));
    }
}

/// Read-only binding between a runtime-neutral policy, registry, and ingress namespace.
pub struct DnsPolicyBlueprintBinding {
    blueprint: DnsPolicyBlueprint,
    registry: Arc<RuleEngineRegistry>,
    listener_count: usize,
    ordinary_count: usize,
}

impl DnsPolicyBlueprintBinding {
    pub(super) const fn new(
        blueprint: DnsPolicyBlueprint,
        registry: Arc<RuleEngineRegistry>,
        listener_count: usize,
        ordinary_count: usize,
    ) -> Self {
        Self {
            blueprint,
            registry,
            listener_count,
            ordinary_count,
        }
    }

    pub const fn blueprint(&self) -> &DnsPolicyBlueprint {
        &self.blueprint
    }

    /// Clones the live registry shared with ordinary Route evaluation.
    pub fn registry(&self) -> Arc<RuleEngineRegistry> {
        Arc::clone(&self.registry)
    }

    pub const fn listener_count(&self) -> usize {
        self.listener_count
    }

    pub const fn ordinary_count(&self) -> usize {
        self.ordinary_count
    }

    /// Transfers the closed blueprint and shared registry to the DNS adapter.
    pub fn into_parts(self) -> (DnsPolicyBlueprint, Arc<RuleEngineRegistry>, usize, usize) {
        (
            self.blueprint,
            self.registry,
            self.listener_count,
            self.ordinary_count,
        )
    }

    /// Resolves a client ingress identity without allowing namespace aliasing.
    pub const fn resolve_ingress(&self, ingress: DnsIngressId) -> Option<usize> {
        match ingress {
            DnsIngressId::Listener(index) if index < self.listener_count => Some(index),
            DnsIngressId::Ordinary(index) if index < self.ordinary_count => {
                Some(self.listener_count + index)
            }
            _ => None,
        }
    }
}

impl std::fmt::Debug for DnsPolicyBlueprintBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DnsPolicyBlueprintBinding([redacted])")
    }
}

/// Validated role-specific DNS graph.
pub struct DnsConfig {
    pub inbounds: Vec<DnsInboundConfig>,
    pub servers: Vec<DnsServerConfig>,
    pub timeout: Duration,
    pub max_inflight: NonZeroU16,
    pub runtime: DnsRuntimeConfig,
}

/// Closed address-family policy used by DNS and fixed-endpoint materialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsStrategy {
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

impl DnsStrategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreferIpv4 => "prefer_ipv4",
            Self::PreferIpv6 => "prefer_ipv6",
            Self::Ipv4Only => "ipv4_only",
            Self::Ipv6Only => "ipv6_only",
        }
    }
}

/// Validated bounded DNS cache policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsCacheConfig {
    pub enabled: bool,
    pub max_entries: usize,
}

/// Production DNS resolver policy retained by every validated DNS graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsRuntimeConfig {
    strategy: DnsStrategy,
    cache: DnsCacheConfig,
}

impl DnsRuntimeConfig {
    pub(super) const fn new(strategy: DnsStrategy, cache: DnsCacheConfig) -> Self {
        Self { strategy, cache }
    }

    pub const fn strategy(self) -> DnsStrategy {
        self.strategy
    }

    pub const fn cache(self) -> DnsCacheConfig {
        self.cache
    }
}

impl Default for DnsRuntimeConfig {
    fn default() -> Self {
        Self::new(
            DnsStrategy::PreferIpv4,
            DnsCacheConfig {
                enabled: true,
                max_entries: 8_192,
            },
        )
    }
}

/// One validated client DNS UDP/TCP listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsInboundConfig {
    pub listen: SocketAddr,
}

/// One validated tagged DNS upstream.
pub struct DnsServerConfig {
    pub transport: DnsTransport,
    pub target: TargetAddr,
    /// Ordered sockets produced by explicit bootstrap resolution.
    /// Empty for numeric and deferred-domain endpoints.
    pub resolved_targets: Box<[SocketAddr]>,
    pub endpoint_mode: DnsEndpointMode,
    pub server_name: Option<Box<str>>,
    pub path: Option<Box<str>>,
    pub detour: Option<EgressPlanHandle>,
}

/// Closed resolution mode retained after a DNS upstream is materialized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsEndpointMode {
    Numeric,
    ClientResolved {
        resolver: ResolverRef,
        strategy: DnsStrategy,
    },
    DeferredToDetour,
}

/// Closed DNS upstream transports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsTransport {
    Udp,
    Tcp,
    Dot,
    Doh,
}

/// Validated bounded UDP server settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpConfig {
    pub enabled: bool,
    pub max_sessions: usize,
    pub max_buffered_bytes: usize,
    pub idle_timeout: Duration,
}

impl ValidatedServerConfig {
    /// Returns the immutable TCP method bound to the validated PSK.
    pub const fn method(&self) -> MethodProfile {
        self.psk.profile()
    }

    /// Returns a control handle sharing the route table's selector state.
    pub fn selector_control(&self) -> SelectorControl {
        self.route.selector_control()
    }
}

/// Validated bounded runtime settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
    pub max_connections: NonZeroU16,
    pub listen_backlog: NonZeroU16,
    pub handshake_timeout: Duration,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub shutdown_grace: Duration,
}

/// Validated exact replay capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayConfig {
    pub capacity: usize,
}

/// Validated closed logging settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoggingConfig {
    pub level: LoggingLevel,
}

/// Closed logging levels accepted by schema version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoggingLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// Validated optional loopback metrics endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricsConfig {
    pub listen: SocketAddrV4,
}
