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
    Inbounds,
    Outbounds,
    InboundsTag,
    InboundsListen,
    InboundsOutbound,
    OutboundsTag,
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
    RouteRulesOutbound,
    RouteFinal,
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
            Self::Inbounds => "inbounds",
            Self::Outbounds => "outbounds",
            Self::InboundsTag => "inbounds.tag",
            Self::InboundsListen => "inbounds.listen",
            Self::InboundsOutbound => "inbounds.outbound",
            Self::OutboundsTag => "outbounds.tag",
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
            Self::RouteRulesOutbound => "route.rules.outbound",
            Self::RouteFinal => "route.final",
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
            ConfigErrorKind::Syntax => "configuration is not valid schema version 1 TOML",
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
