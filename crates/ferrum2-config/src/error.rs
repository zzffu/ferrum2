use std::error::Error;
use std::fmt;

/// Stable operator-facing configuration error category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigErrorKind {
    Io,
    TooLarge,
    Syntax,
    Semantic,
}

impl ConfigErrorKind {
    /// Returns the stable error code consumed by the binary composition layer.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Io => "config.io",
            Self::TooLarge => "config.too_large",
            Self::Syntax => "config.syntax",
            Self::Semantic => "config.semantic",
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
    TunMaxUdpBufferedBytes,
    TunMemory,
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
    Dns,
    DnsTimeout,
    DnsMaxInflight,
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
    DnsRouteRulesPort,
    DnsRouteRulesPortRange,
    DnsRouteRulesServer,
    DnsRouteFinal,
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
            Self::TunMaxUdpBufferedBytes => "tun.max_udp_buffered_bytes",
            Self::TunMemory => "tun.memory",
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
            Self::Dns => "dns",
            Self::DnsTimeout => "dns.timeout_ms",
            Self::DnsMaxInflight => "dns.max_inflight",
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
            Self::DnsRouteRulesPort => "dns.route.rules.port",
            Self::DnsRouteRulesPortRange => "dns.route.rules.port_range",
            Self::DnsRouteRulesServer => "dns.route.rules.server",
            Self::DnsRouteFinal => "dns.route.final",
        }
    }
}

/// A redacted configuration error that never retains a parser or I/O source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigError {
    kind: ConfigErrorKind,
    field: ConfigField,
}

impl ConfigError {
    pub const fn kind(self) -> ConfigErrorKind {
        self.kind
    }

    pub const fn code(self) -> &'static str {
        self.kind.code()
    }

    pub const fn field(self) -> ConfigField {
        self.field
    }

    pub(super) const fn new(kind: ConfigErrorKind, field: ConfigField) -> Self {
        Self { kind, field }
    }

    pub(super) const fn semantic(field: ConfigField) -> Self {
        Self::new(ConfigErrorKind::Semantic, field)
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            ConfigErrorKind::Io => "unable to read configuration",
            ConfigErrorKind::TooLarge => "configuration exceeds 1048576 bytes",
            ConfigErrorKind::Syntax => "configuration is not valid TOML",
            ConfigErrorKind::Semantic => "configuration value is invalid",
        };
        write!(
            formatter,
            "error[{}] {}: {message}",
            self.kind.code(),
            self.field.as_str()
        )
    }
}

impl Error for ConfigError {}
