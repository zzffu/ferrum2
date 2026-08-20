use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;

use ferrum2_core::TargetAddr;
use ferrum2_crypto::{MethodPsk, TcpMethodProfile};
use ferrum2_rule::{
    ActionTable, DnsPolicyBlueprint, EgressPlanHandle, Network, OrderedRouteProgram, RouteMetadata,
    RouteProgramAction, RouteProgramEvaluation, RouteProgramEvaluationWithScratch, RouteTable,
    RuleCompileError, RuleEvaluationScratch,
};
use ferrum2_rule::{RuleEngineRegistry, SelectorControl};
use ipnet::{Ipv4Net, Ipv6Net};

/// A validated client configuration with no retained source text.
pub struct ValidatedClientConfig {
    pub schema_version: SchemaVersion,
    pub listen: SocketAddrV4,
    pub inbounds: Vec<ClientInboundConfig>,
    pub outbounds: Vec<ClientOutboundConfig>,
    pub route: RouteTable,
    pub route_program: Option<CompiledRoute>,
    pub tun: Option<TunConfig>,
    pub dns: Option<DnsConfig>,
    pub dns_route: Option<ClientDnsRoute>,
    pub runtime: RuntimeConfig,
    pub udp: Option<UdpConfig>,
    pub logging: LoggingConfig,
    pub metrics: Option<MetricsConfig>,
}

/// Validated Windows TUN configuration and its complete owned-buffer plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunConfig {
    pub adapter_name: Box<str>,
    pub ipv4_address: Ipv4Net,
    pub ipv6_address: Ipv6Net,
    pub auto_route: bool,
    pub capture_routes: Vec<Ipv4Net>,
    pub auto_dns: bool,
    pub ipv4_dns_address: Option<Ipv4Addr>,
    pub physical_endpoints: Vec<SocketAddrV4>,
    pub mtu: u16,
    pub ring_capacity: u32,
    pub ready_timeout: Duration,
    pub max_tcp_flows: usize,
    pub tcp_buffer_bytes: usize,
    pub max_udp_mappings: usize,
    pub max_udp_buffered_bytes: usize,
    pub owned_buffer_bytes: u64,
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
    },
    Direct,
}

impl ClientOutboundConfig {
    pub const fn server(&self) -> Option<SocketAddr> {
        match self {
            Self::Shadowsocks { server, .. } => Some(*server),
            Self::Direct => None,
        }
    }

    pub fn method(&self) -> Option<TcpMethodProfile> {
        match self {
            Self::Shadowsocks { psk, .. } => Some(psk.profile()),
            Self::Direct => None,
        }
    }
}

impl std::fmt::Debug for ClientOutboundConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Shadowsocks { .. } => "ClientOutboundConfig::Shadowsocks([redacted])",
            Self::Direct => "ClientOutboundConfig::Direct",
        })
    }
}

impl ValidatedClientConfig {
    /// Returns a control handle sharing the route table's selector state.
    pub fn selector_control(&self) -> SelectorControl {
        self.route.selector_control()
    }
}

/// A validated server configuration with no retained source text.
pub struct ValidatedServerConfig {
    pub schema_version: SchemaVersion,
    pub listen: SocketAddrV4,
    pub inbounds: Vec<ServerInboundConfig>,
    pub outbounds: Vec<ServerOutboundConfig>,
    pub route: RouteTable,
    pub route_program: Option<CompiledRoute>,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerOutboundConfig;

/// Explicit supported configuration versions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaVersion {
    V1,
    V2,
}

impl SchemaVersion {
    /// Returns whether this model requires the M14 composition path.
    pub const fn is_v2(self) -> bool {
        matches!(self, Self::V2)
    }
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
    pub sniff: RouteSniffConfig,
}

impl CompiledRoute {
    /// Allocates one scratch owner that callers may reuse across route evaluations.
    pub fn evaluation_scratch(&self) -> Result<RuleEvaluationScratch, RuleCompileError> {
        self.program.evaluation_scratch()
    }

    pub const fn program_mode(&self) -> ferrum2_rule::RuleProgramMode {
        self.program.mode()
    }

    pub const fn rule_count(&self) -> usize {
        self.program.len()
    }

    /// Starts one private-cursor ordered evaluation with newly allocated scratch.
    /// Production hot paths should use [`Self::evaluate_with_scratch`].
    pub fn evaluate<'program, 'target>(
        &'program self,
        inbound: usize,
        network: Network,
        original: &'target TargetAddr,
    ) -> RouteProgramEvaluation<'program, 'target, RouteProtocol, RouteAction> {
        match &self.registry {
            Some(registry) => self
                .program
                .evaluate_with_registry(inbound, network, original, registry),
            None => self.program.evaluate(inbound, network, original),
        }
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
    pub(super) compatibility_program: Option<OrderedRouteProgram<DnsQueryType, usize>>,
    pub(super) listener_count: usize,
    pub(super) ordinary_count: usize,
    pub(super) policy_blueprint: Option<DnsPolicyBlueprintBinding>,
}

impl ClientDnsRoute {
    /// Reports whether this value retains the synchronous compatibility program.
    /// Materialized V2 policies own only their [`DnsPolicyBlueprintBinding`].
    pub const fn has_compatibility_program(&self) -> bool {
        self.compatibility_program.is_some()
    }

    /// Allocates one scratch owner for repeated compatibility selections.
    pub fn evaluation_scratch(&self) -> Result<RuleEvaluationScratch, RuleCompileError> {
        self.compatibility_program
            .as_ref()
            .ok_or(RuleCompileError::Internal)?
            .evaluation_scratch()
    }

    pub fn program_mode(&self) -> ferrum2_rule::RuleProgramMode {
        self.policy_blueprint.as_ref().map_or_else(
            || {
                self.compatibility_program
                    .as_ref()
                    .map_or(ferrum2_rule::RuleProgramMode::SmallLinear, |program| {
                        program.mode()
                    })
            },
            |binding| ferrum2_rule::RuleProgramMode::for_rule_count(binding.blueprint().len()),
        )
    }

    pub fn rule_count(&self) -> usize {
        self.policy_blueprint.as_ref().map_or_else(
            || {
                self.compatibility_program
                    .as_ref()
                    .map_or(0, |program| program.len())
            },
            |binding| binding.blueprint().len(),
        )
    }

    /// Selects one DNS server with newly allocated compatibility scratch.
    ///
    /// An absent query type represents a wire type outside the closed policy vocabulary.
    pub fn select(
        &self,
        ingress: DnsIngressId,
        network: Network,
        target: &TargetAddr,
        qtype: Option<DnsQueryType>,
    ) -> Option<usize> {
        let mut scratch = self.evaluation_scratch().ok()?;
        self.select_with_scratch(ingress, network, target, qtype, &mut scratch)
    }

    /// Selects with caller-owned scratch and performs no hot-path allocation.
    pub fn select_with_scratch(
        &self,
        ingress: DnsIngressId,
        network: Network,
        target: &TargetAddr,
        qtype: Option<DnsQueryType>,
        scratch: &mut RuleEvaluationScratch,
    ) -> Option<usize> {
        let inbound = match ingress {
            DnsIngressId::Listener(index) if index < self.listener_count => index,
            DnsIngressId::Ordinary(index) if index < self.ordinary_count => {
                self.listener_count + index
            }
            _ => return None,
        };
        let mut evaluation = self
            .compatibility_program
            .as_ref()?
            .evaluate_with_scratch(inbound, network, target, scratch);
        match evaluation.next(RouteMetadata::new(qtype, None))? {
            RouteProgramAction::Terminal(server) | RouteProgramAction::Final(server) => {
                Some(*server)
            }
            RouteProgramAction::Continue(_) => unreachable!("DNS actions are terminal"),
        }
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
        self.compatibility_program = None;
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
    pub(super) compatibility_program: Option<OrderedRouteProgram<(), usize>>,
    pub(super) ordinary_count: usize,
    pub(super) policy_blueprint: Option<DnsPolicyBlueprintBinding>,
}

impl ServerDnsRoute {
    /// Reports whether this value retains the synchronous compatibility program.
    /// Materialized V2 policies own only their [`DnsPolicyBlueprintBinding`].
    pub const fn has_compatibility_program(&self) -> bool {
        self.compatibility_program.is_some()
    }

    /// Allocates one scratch owner for repeated compatibility selections.
    pub fn evaluation_scratch(&self) -> Result<RuleEvaluationScratch, RuleCompileError> {
        self.compatibility_program
            .as_ref()
            .ok_or(RuleCompileError::Internal)?
            .evaluation_scratch()
    }

    pub fn program_mode(&self) -> ferrum2_rule::RuleProgramMode {
        self.policy_blueprint.as_ref().map_or_else(
            || {
                self.compatibility_program
                    .as_ref()
                    .map_or(ferrum2_rule::RuleProgramMode::SmallLinear, |program| {
                        program.mode()
                    })
            },
            |binding| ferrum2_rule::RuleProgramMode::for_rule_count(binding.blueprint().len()),
        )
    }

    pub fn rule_count(&self) -> usize {
        self.policy_blueprint.as_ref().map_or_else(
            || {
                self.compatibility_program
                    .as_ref()
                    .map_or(0, |program| program.len())
            },
            |binding| binding.blueprint().len(),
        )
    }

    /// Selects one DNS server with newly allocated compatibility scratch.
    pub fn select(&self, inbound: usize, network: Network, target: &TargetAddr) -> usize {
        let mut scratch = self
            .evaluation_scratch()
            .expect("validated server DNS route scratch allocation failed");
        self.select_with_scratch(inbound, network, target, &mut scratch)
    }

    /// Selects with caller-owned scratch and performs no hot-path allocation.
    pub fn select_with_scratch(
        &self,
        inbound: usize,
        network: Network,
        target: &TargetAddr,
        scratch: &mut RuleEvaluationScratch,
    ) -> usize {
        let mut evaluation = self
            .compatibility_program
            .as_ref()
            .expect("compatibility DNS program is unavailable after policy materialization")
            .evaluate_with_scratch(inbound, network, target, scratch);
        match evaluation
            .next(RouteMetadata::new(None, None))
            .expect("DNS program has a mandatory final")
        {
            RouteProgramAction::Terminal(server) | RouteProgramAction::Final(server) => *server,
            RouteProgramAction::Continue(_) => unreachable!("DNS actions are terminal"),
        }
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
        self.compatibility_program = None;
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
    pub route: ActionTable<usize>,
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
    pub address: SocketAddr,
    pub server_name: Option<Box<str>>,
    pub path: Option<Box<str>>,
    pub detour: Option<EgressPlanHandle>,
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
    pub const fn method(&self) -> TcpMethodProfile {
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
