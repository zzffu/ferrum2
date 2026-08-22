use std::error::Error;
use std::fmt;

use crate::dependency::DependencyNode;

/// Stable operator-facing configuration error category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigErrorKind {
    Io,
    TooLarge,
    Syntax,
    Semantic,
    RuleCompile,
    RuleAllocation,
    DnsResolverRequired,
    DnsReservedResolverName,
    DnsDependencyCycle,
    ResourceMaterialization,
}

impl ConfigErrorKind {
    /// Returns the stable error code consumed by the binary composition layer.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Io => "config.io",
            Self::TooLarge => "config.too_large",
            Self::Syntax => "config.syntax",
            Self::Semantic => "config.semantic",
            Self::RuleCompile => "rule.compile",
            Self::RuleAllocation => "rule.allocation",
            Self::DnsResolverRequired => "dns.resolver_required",
            Self::DnsReservedResolverName => "dns.reserved_resolver_name",
            Self::DnsDependencyCycle => "config.dependency_cycle",
            Self::ResourceMaterialization => "config.resource_materialization",
        }
    }
}

/// Closed, non-secret location associated with a configuration error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigField {
    Config,
    SchemaVersion,
    ClientListen,
    ClientServer,
    ServerListen,
    ShadowsocksMethod,
    ShadowsocksPsk,
    RuntimeMaxConnections,
    RuntimeListenBacklog,
    RuntimeHandshakeTimeout,
    RuntimeConnectTimeout,
    RuntimeIdleTimeout,
    RuntimeShutdownGrace,
    ReplayCapacity,
    UdpMaxSessions,
    UdpMaxBufferedBytes,
    UdpIdleTimeout,
    LoggingLevel,
    MetricsListen,
    Tun,
    TunTag,
    TunAdapterName,
    TunIpv4Address,
    TunIpv6Address,
    TunOutbound,
    TunAutoRoute,
    TunRouteAddress,
    TunRouteExcludeAddress,
    TunAutoDns,
    TunIpv4DnsAddress,
    TunIpv6DnsAddress,
    TunMtu,
    TunRingCapacity,
    TunReadyTimeout,
    TunMaxTcpFlows,
    TunTcpBufferBytes,
    TunMaxUdpMappings,
    TunUdpFiltering,
    Inbounds,
    Outbounds,
    InboundsTag,
    InboundsListen,
    InboundsOutbound,
    OutboundsTag,
    OutboundsType,
    OutboundsServer,
    OutboundsMethod,
    OutboundsPsk,
    OutboundsDomainResolver,
    OutboundsDomainStrategy,
    Chains,
    ChainsTag,
    ChainsHops,
    Selectors,
    SelectorsTag,
    SelectorsOutbounds,
    SelectorsDefault,
    Route,
    RouteRules,
    RouteRulesInbound,
    RouteRulesNetwork,
    RouteRulesTarget,
    RouteRulesProtocol,
    RouteRulesDomain,
    RouteRulesDomainSuffix,
    RouteRulesDomainKeyword,
    RouteRulesRuleSet,
    RouteRulesIp,
    RouteRulesIpCidr,
    RouteRulesPort,
    RouteRulesPortRange,
    RouteRulesAction,
    RouteRulesSniffers,
    RouteRulesOutbound,
    RouteFinal,
    RouteSniff,
    RouteSniffTimeout,
    RouteSniffMaxBytes,
    RouteRuleSet,
    RouteRuleSetTag,
    RouteRuleSetType,
    RouteRuleSetFormat,
    RouteRuleSetUrl,
    RouteRuleSetDownloadResolver,
    RouteRuleSetDownloadDetour,
    RouteRuleSetUpdateInterval,
    RuleSetLoader,
    RuleSetLoaderCacheDir,
    RuleSetLoaderDownloadTimeout,
    RuleSetLoaderMaxRedirects,
    Dns,
    DnsTimeout,
    DnsMaxInflight,
    DnsStrategy,
    DnsCache,
    DnsCacheEnabled,
    DnsCacheMaxEntries,
    DnsInbounds,
    DnsInboundsTag,
    DnsInboundsListen,
    DnsServers,
    DnsServersTag,
    DnsServersTransport,
    DnsServersAddress,
    DnsServersServerName,
    DnsServersPath,
    DnsServersDetour,
    DnsServersDomainResolver,
    DnsServersDomainStrategy,
    DnsRoute,
    DnsRouteRules,
    DnsRouteRulesInbound,
    DnsRouteRulesNetwork,
    DnsRouteRulesTarget,
    DnsRouteRulesQname,
    DnsRouteRulesQnameSuffix,
    DnsRouteRulesQtype,
    DnsRouteRulesDomain,
    DnsRouteRulesDomainSuffix,
    DnsRouteRulesDomainKeyword,
    DnsRouteRulesRuleSet,
    DnsRouteRulesPort,
    DnsRouteRulesPortRange,
    DnsRouteRulesServer,
    DnsRouteRulesAction,
    DnsRouteRulesStrategy,
    DnsRouteFinal,
    DnsDependencyCycle,
    ResourceMaterialization,
}

impl ConfigField {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::SchemaVersion => "schema_version",
            Self::ClientListen => "client.listen",
            Self::ClientServer => "client.server",
            Self::ServerListen => "server.listen",
            Self::ShadowsocksMethod => "shadowsocks.method",
            Self::ShadowsocksPsk => "shadowsocks.psk",
            Self::RuntimeMaxConnections => "runtime.max_connections",
            Self::RuntimeListenBacklog => "runtime.listen_backlog",
            Self::RuntimeHandshakeTimeout => "runtime.handshake_timeout_ms",
            Self::RuntimeConnectTimeout => "runtime.connect_timeout_ms",
            Self::RuntimeIdleTimeout => "runtime.idle_timeout_ms",
            Self::RuntimeShutdownGrace => "runtime.shutdown_grace_ms",
            Self::ReplayCapacity => "replay.capacity",
            Self::UdpMaxSessions => "udp.max_sessions",
            Self::UdpMaxBufferedBytes => "udp.max_buffered_bytes",
            Self::UdpIdleTimeout => "udp.idle_timeout_ms",
            Self::LoggingLevel => "logging.level",
            Self::MetricsListen => "metrics.listen",
            Self::Tun => "tun",
            Self::TunTag => "tun.tag",
            Self::TunAdapterName => "tun.adapter_name",
            Self::TunIpv4Address => "tun.ipv4_address",
            Self::TunIpv6Address => "tun.ipv6_address",
            Self::TunOutbound => "tun.outbound",
            Self::TunAutoRoute => "tun.auto_route",
            Self::TunRouteAddress => "tun.route_address",
            Self::TunRouteExcludeAddress => "tun.route_exclude_address",
            Self::TunAutoDns => "tun.auto_dns",
            Self::TunIpv4DnsAddress => "tun.ipv4_dns_address",
            Self::TunIpv6DnsAddress => "tun.ipv6_dns_address",
            Self::TunMtu => "tun.mtu",
            Self::TunRingCapacity => "tun.ring_capacity",
            Self::TunReadyTimeout => "tun.ready_timeout_ms",
            Self::TunMaxTcpFlows => "tun.max_tcp_flows",
            Self::TunTcpBufferBytes => "tun.tcp_buffer_bytes",
            Self::TunMaxUdpMappings => "tun.max_udp_mappings",
            Self::TunUdpFiltering => "tun.udp_filtering",
            Self::Inbounds => "inbounds",
            Self::Outbounds => "outbounds",
            Self::InboundsTag => "inbounds.tag",
            Self::InboundsListen => "inbounds.listen",
            Self::InboundsOutbound => "inbounds.outbound",
            Self::OutboundsTag => "outbounds.tag",
            Self::OutboundsType => "outbounds.type",
            Self::OutboundsServer => "outbounds.server",
            Self::OutboundsMethod => "outbounds.method",
            Self::OutboundsPsk => "outbounds.psk",
            Self::OutboundsDomainResolver => "outbounds.domain_resolver",
            Self::OutboundsDomainStrategy => "outbounds.domain_strategy",
            Self::Chains => "chains",
            Self::ChainsTag => "chains.tag",
            Self::ChainsHops => "chains.hops",
            Self::Selectors => "selectors",
            Self::SelectorsTag => "selectors.tag",
            Self::SelectorsOutbounds => "selectors.outbounds",
            Self::SelectorsDefault => "selectors.default",
            Self::Route => "route",
            Self::RouteRules => "route.rules",
            Self::RouteRulesInbound => "route.rules.inbound",
            Self::RouteRulesNetwork => "route.rules.network",
            Self::RouteRulesTarget => "route.rules.target",
            Self::RouteRulesProtocol => "route.rules.protocol",
            Self::RouteRulesDomain => "route.rules.domain",
            Self::RouteRulesDomainSuffix => "route.rules.domain_suffix",
            Self::RouteRulesDomainKeyword => "route.rules.domain_keyword",
            Self::RouteRulesRuleSet => "route.rules.rule_set",
            Self::RouteRulesIp => "route.rules.ip",
            Self::RouteRulesIpCidr => "route.rules.ip_cidr",
            Self::RouteRulesPort => "route.rules.port",
            Self::RouteRulesPortRange => "route.rules.port_range",
            Self::RouteRulesAction => "route.rules.action",
            Self::RouteRulesSniffers => "route.rules.sniffers",
            Self::RouteRulesOutbound => "route.rules.outbound",
            Self::RouteFinal => "route.final",
            Self::RouteSniff => "route.sniff",
            Self::RouteSniffTimeout => "route.sniff.timeout_ms",
            Self::RouteSniffMaxBytes => "route.sniff.max_bytes",
            Self::RouteRuleSet => "route.rule_set",
            Self::RouteRuleSetTag => "route.rule_set.tag",
            Self::RouteRuleSetType => "route.rule_set.type",
            Self::RouteRuleSetFormat => "route.rule_set.format",
            Self::RouteRuleSetUrl => "route.rule_set.url",
            Self::RouteRuleSetDownloadResolver => "route.rule_set.download_resolver",
            Self::RouteRuleSetDownloadDetour => "route.rule_set.download_detour",
            Self::RouteRuleSetUpdateInterval => "route.rule_set.update_interval_seconds",
            Self::RuleSetLoader => "rule_set_loader",
            Self::RuleSetLoaderCacheDir => "rule_set_loader.cache_dir",
            Self::RuleSetLoaderDownloadTimeout => "rule_set_loader.download_timeout_ms",
            Self::RuleSetLoaderMaxRedirects => "rule_set_loader.max_redirects",
            Self::Dns => "dns",
            Self::DnsTimeout => "dns.timeout_ms",
            Self::DnsMaxInflight => "dns.max_inflight",
            Self::DnsStrategy => "dns.strategy",
            Self::DnsCache => "dns.cache",
            Self::DnsCacheEnabled => "dns.cache.enabled",
            Self::DnsCacheMaxEntries => "dns.cache.max_entries",
            Self::DnsInbounds => "dns.inbounds",
            Self::DnsInboundsTag => "dns.inbounds.tag",
            Self::DnsInboundsListen => "dns.inbounds.listen",
            Self::DnsServers => "dns.servers",
            Self::DnsServersTag => "dns.servers.tag",
            Self::DnsServersTransport => "dns.servers.transport",
            Self::DnsServersAddress => "dns.servers.address",
            Self::DnsServersServerName => "dns.servers.server_name",
            Self::DnsServersPath => "dns.servers.path",
            Self::DnsServersDetour => "dns.servers.detour",
            Self::DnsServersDomainResolver => "dns.servers.domain_resolver",
            Self::DnsServersDomainStrategy => "dns.servers.domain_strategy",
            Self::DnsRoute => "dns.route",
            Self::DnsRouteRules => "dns.route.rules",
            Self::DnsRouteRulesInbound => "dns.route.rules.inbound",
            Self::DnsRouteRulesNetwork => "dns.route.rules.network",
            Self::DnsRouteRulesTarget => "dns.route.rules.target",
            Self::DnsRouteRulesQname => "dns.route.rules.qname",
            Self::DnsRouteRulesQnameSuffix => "dns.route.rules.qname_suffix",
            Self::DnsRouteRulesQtype => "dns.route.rules.qtype",
            Self::DnsRouteRulesDomain => "dns.route.rules.domain",
            Self::DnsRouteRulesDomainSuffix => "dns.route.rules.domain_suffix",
            Self::DnsRouteRulesDomainKeyword => "dns.route.rules.domain_keyword",
            Self::DnsRouteRulesRuleSet => "dns.route.rules.rule_set",
            Self::DnsRouteRulesPort => "dns.route.rules.port",
            Self::DnsRouteRulesPortRange => "dns.route.rules.port_range",
            Self::DnsRouteRulesServer => "dns.route.rules.server",
            Self::DnsRouteRulesAction => "dns.route.rules.action",
            Self::DnsRouteRulesStrategy => "dns.route.rules.strategy",
            Self::DnsRouteFinal => "dns.route.final",
            Self::DnsDependencyCycle => "config.dependency_cycle",
            Self::ResourceMaterialization => "config.resource_materialization",
        }
    }
}

/// A redacted configuration error that never retains a parser or I/O source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigError {
    kind: ConfigErrorKind,
    field: ConfigField,
    dependency_cycle: Option<Vec<DependencyNode>>,
}

impl ConfigError {
    pub const fn kind(&self) -> ConfigErrorKind {
        self.kind
    }

    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }

    pub const fn field(&self) -> ConfigField {
        self.field
    }

    /// Creates the single redacted error exposed to injected resource materializers.
    pub const fn resource_materialization() -> Self {
        Self::new(
            ConfigErrorKind::ResourceMaterialization,
            ConfigField::ResourceMaterialization,
        )
    }

    pub(super) const fn new(kind: ConfigErrorKind, field: ConfigField) -> Self {
        Self {
            kind,
            field,
            dependency_cycle: None,
        }
    }

    /// Retains only the closed resource categories and stable list indices from
    /// one complete dependency cycle. Configuration tags, endpoints, URLs, and
    /// resolver names never enter this diagnostic.
    pub(crate) fn dependency_cycle(path: Vec<DependencyNode>) -> Self {
        debug_assert!(path.len() >= 2);
        debug_assert_eq!(path.first(), path.last());
        Self {
            kind: ConfigErrorKind::DnsDependencyCycle,
            field: ConfigField::DnsDependencyCycle,
            dependency_cycle: Some(path),
        }
    }

    pub(super) const fn semantic(field: ConfigField) -> Self {
        match field {
            ConfigField::DnsDependencyCycle => {
                Self::new(ConfigErrorKind::DnsDependencyCycle, field)
            }
            ConfigField::ResourceMaterialization => {
                Self::new(ConfigErrorKind::ResourceMaterialization, field)
            }
            _ => Self::new(ConfigErrorKind::Semantic, field),
        }
    }

    /// Preserves closed compiler failures without retaining a matcher value.
    pub(super) const fn from_rule_compile(
        error: ferrum2_rule::RuleCompileError,
        field: ConfigField,
    ) -> Self {
        use ferrum2_rule::RuleCompileError;

        match error {
            RuleCompileError::Allocation | RuleCompileError::IndexOverflow => {
                Self::new(ConfigErrorKind::RuleAllocation, field)
            }
            RuleCompileError::InvalidId
            | RuleCompileError::InvalidGeneration
            | RuleCompileError::Internal => Self::new(ConfigErrorKind::RuleCompile, field),
            RuleCompileError::EmptyMatcher
            | RuleCompileError::EmptyField
            | RuleCompileError::DuplicateField
            | RuleCompileError::DuplicateValue
            | RuleCompileError::ConflictingFields
            | RuleCompileError::InvalidDomain
            | RuleCompileError::NonCanonicalCidr
            | RuleCompileError::InvalidTag
            | RuleCompileError::DuplicateRuleSet => Self::semantic(field),
        }
    }

    pub(super) const fn rule_allocation(field: ConfigField) -> Self {
        Self::new(ConfigErrorKind::RuleAllocation, field)
    }

    pub(super) const fn rule_compile(field: ConfigField) -> Self {
        Self::new(ConfigErrorKind::RuleCompile, field)
    }

    pub(super) const fn dns_resolver_required(field: ConfigField) -> Self {
        Self::new(ConfigErrorKind::DnsResolverRequired, field)
    }

    pub(super) const fn dns_reserved_resolver_name(field: ConfigField) -> Self {
        Self::new(ConfigErrorKind::DnsReservedResolverName, field)
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            ConfigErrorKind::Io => "unable to read configuration",
            ConfigErrorKind::TooLarge => "configuration exceeds 1048576 bytes",
            ConfigErrorKind::Syntax => "configuration is not valid TOML",
            ConfigErrorKind::Semantic => "configuration value is invalid",
            ConfigErrorKind::RuleCompile => "rule compilation failed",
            ConfigErrorKind::RuleAllocation => "rule allocation failed",
            ConfigErrorKind::DnsResolverRequired => "an explicit resolver is required",
            ConfigErrorKind::DnsReservedResolverName => "the resolver name is reserved",
            ConfigErrorKind::DnsDependencyCycle => {
                "the configuration dependency graph contains a cycle"
            }
            ConfigErrorKind::ResourceMaterialization => "supplied resources are invalid",
        };
        write!(
            formatter,
            "error[{}] {}: {message}",
            self.kind.code(),
            self.field.as_str()
        )?;
        if let Some(path) = &self.dependency_cycle {
            formatter.write_str(": ")?;
            for (index, node) in path.iter().enumerate() {
                if index != 0 {
                    formatter.write_str(" -> ")?;
                }
                node.fmt(formatter)?;
            }
        }
        Ok(())
    }
}

impl Error for ConfigError {}

#[cfg(test)]
mod tests {
    use ferrum2_rule::RuleCompileError;

    use crate::dependency::DependencyNode;

    use super::{ConfigError, ConfigErrorKind, ConfigField};

    #[test]
    fn rule_compiler_categories_are_closed_and_value_free() {
        let compile =
            ConfigError::from_rule_compile(RuleCompileError::Internal, ConfigField::RouteRules);
        assert_eq!(compile.kind(), ConfigErrorKind::RuleCompile);
        assert_eq!(compile.code(), "rule.compile");
        assert_eq!(
            compile.to_string(),
            "error[rule.compile] route.rules: rule compilation failed"
        );

        let allocation = ConfigError::from_rule_compile(
            RuleCompileError::IndexOverflow,
            ConfigField::DnsRouteRules,
        );
        assert_eq!(allocation.kind(), ConfigErrorKind::RuleAllocation);
        assert_eq!(allocation.code(), "rule.allocation");
        assert_eq!(
            allocation.to_string(),
            "error[rule.allocation] dns.route.rules: rule allocation failed"
        );
        let blueprint_allocation = ConfigError::rule_allocation(ConfigField::DnsRouteRulesRuleSet);
        assert_eq!(blueprint_allocation.kind(), ConfigErrorKind::RuleAllocation);
        assert_eq!(
            blueprint_allocation.field(),
            ConfigField::DnsRouteRulesRuleSet
        );

        let input = ConfigError::from_rule_compile(
            RuleCompileError::NonCanonicalCidr,
            ConfigField::RouteRulesIpCidr,
        );
        assert_eq!(input.kind(), ConfigErrorKind::Semantic);

        let required = ConfigError::dns_resolver_required(ConfigField::OutboundsDomainResolver);
        assert_eq!(required.code(), "dns.resolver_required");
        assert_eq!(
            required.to_string(),
            "error[dns.resolver_required] outbounds.domain_resolver: an explicit resolver is required"
        );

        let reserved = ConfigError::dns_reserved_resolver_name(ConfigField::DnsServersTag);
        assert_eq!(reserved.code(), "dns.reserved_resolver_name");
        assert_eq!(
            ConfigError::semantic(ConfigField::DnsDependencyCycle).code(),
            "config.dependency_cycle"
        );
        assert_eq!(
            ConfigError::resource_materialization().code(),
            "config.resource_materialization"
        );
    }

    #[test]
    fn dependency_cycle_display_retains_only_closed_resource_nodes() {
        let error = ConfigError::dependency_cycle(vec![
            DependencyNode::DnsServer(0),
            DependencyNode::RuleSet(1),
            DependencyNode::Selector(2),
            DependencyNode::Chain(3),
            DependencyNode::Outbound(4),
            DependencyNode::DnsServer(0),
        ]);

        assert_eq!(
            error.to_string(),
            concat!(
                "error[config.dependency_cycle] config.dependency_cycle: ",
                "the configuration dependency graph contains a cycle: ",
                "dns-server[0] -> rule-set[1] -> selector[2] -> chain[3] -> ",
                "outbound[4] -> dns-server[0]"
            )
        );
        assert_eq!(error.clone(), error);
    }
}
