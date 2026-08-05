#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU16;
use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ferrum2_core::TargetAddr;
use ferrum2_core::route::{
    ActionRule, ActionTable, EgressPlanHandle, MAX_ROUTE_RULES, Network, RouteRule, RouteTable,
    compile_selector_plans_with_roots,
};
use ferrum2_core::selector::{
    SelectorCompileError, SelectorControl, SelectorDefinition, TaggedInbound, TaggedOutbound,
    TaggedPlan, TaggedRoute, TaggedRouteRule, TaggedStaticBinding,
};
use ferrum2_crypto::{MethodPsk, TcpMethodProfile};
use serde::Deserialize;
use serde::de::{Deserializer, Visitor};
use zeroize::{Zeroize, Zeroizing};

/// Maximum accepted configuration size in bytes.
pub const MAX_CONFIG_BYTES: usize = 1_048_576;

const DEFAULT_MAX_CONNECTIONS: u32 = 4096;
const DEFAULT_LISTEN_BACKLOG: u32 = 1024;
const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 300_000;
const DEFAULT_SHUTDOWN_GRACE_MS: u64 = 30_000;
const DEFAULT_REPLAY_CAPACITY: usize = 65_536;
const DEFAULT_UDP_MAX_SESSIONS: usize = 4_096;
const DEFAULT_UDP_MAX_BUFFERED_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_UDP_IDLE_TIMEOUT_MS: u64 = 300_000;
const DEFAULT_DNS_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_DNS_MAX_INFLIGHT: u32 = 256;

/// A validated client configuration with no retained source text.
pub struct ValidatedClientConfig {
    pub listen: SocketAddrV4,
    pub server: SocketAddrV4,
    pub inbounds: Vec<ClientInboundConfig>,
    pub outbounds: Vec<ClientOutboundConfig>,
    pub route: RouteTable,
    pub dns: Option<DnsConfig>,
    pub psk: MethodPsk,
    pub outbound_psks: Vec<MethodPsk>,
    pub runtime: RuntimeConfig,
    pub udp: Option<UdpConfig>,
    pub logging: LoggingConfig,
    pub metrics: Option<MetricsConfig>,
}

/// One validated SOCKS5 listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientInboundConfig {
    pub listen: SocketAddrV4,
}

/// One validated Shadowsocks client destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientOutboundConfig {
    pub server: SocketAddrV4,
}

impl ValidatedClientConfig {
    /// Returns the immutable TCP method bound to the validated PSK.
    pub const fn method(&self) -> TcpMethodProfile {
        self.psk.profile()
    }

    /// Returns a control handle sharing the route table's selector state.
    pub fn selector_control(&self) -> SelectorControl {
        self.route.selector_control()
    }
}

/// A validated server configuration with no retained source text.
pub struct ValidatedServerConfig {
    pub listen: SocketAddrV4,
    pub inbounds: Vec<ServerInboundConfig>,
    pub outbounds: Vec<ServerOutboundConfig>,
    pub route: RouteTable,
    pub dns: Option<DnsConfig>,
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

/// Validated role-specific DNS graph.
pub struct DnsConfig {
    pub inbounds: Vec<DnsInboundConfig>,
    pub servers: Vec<DnsServerConfig>,
    pub route: ActionTable<usize>,
    pub timeout: Duration,
    pub max_inflight: NonZeroU16,
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

    const fn new(kind: ConfigErrorKind, field: ConfigField) -> Self {
        Self { kind, field }
    }

    const fn semantic(field: ConfigField) -> Self {
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

/// Reads and fully validates a client configuration without creating runtime resources.
pub fn load_client(path: impl AsRef<Path>) -> Result<ValidatedClientConfig, ConfigError> {
    let source = read_bounded_utf8(path.as_ref())?;
    let raw: RawClientRoot = parse_toml(&source)?;
    validate_client(raw, &source)
}

/// Reads and fully validates a server configuration without creating runtime resources.
pub fn load_server(path: impl AsRef<Path>) -> Result<ValidatedServerConfig, ConfigError> {
    let source = read_bounded_utf8(path.as_ref())?;
    let raw: RawServerRoot = parse_toml(&source)?;
    validate_server(raw, &source)
}

fn read_bounded_utf8(path: &Path) -> Result<Zeroizing<String>, ConfigError> {
    let file =
        File::open(path).map_err(|_| ConfigError::new(ConfigErrorKind::Io, ConfigField::Config))?;
    let metadata = file
        .metadata()
        .map_err(|_| ConfigError::new(ConfigErrorKind::Io, ConfigField::Config))?;
    if metadata.len() > MAX_CONFIG_BYTES as u64 {
        return Err(ConfigError::new(
            ConfigErrorKind::TooLarge,
            ConfigField::Config,
        ));
    }

    let mut source = Zeroizing::new(String::new());
    let mut bounded = file.take((MAX_CONFIG_BYTES + 1) as u64);
    match bounded.read_to_string(&mut source) {
        Ok(_) if source.len() > MAX_CONFIG_BYTES => Err(ConfigError::new(
            ConfigErrorKind::TooLarge,
            ConfigField::Config,
        )),
        Ok(_) => Ok(source),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => Err(ConfigError::new(
            ConfigErrorKind::Syntax,
            ConfigField::Config,
        )),
        Err(_) => Err(ConfigError::new(ConfigErrorKind::Io, ConfigField::Config)),
    }
}

fn parse_toml<'a, T: Deserialize<'a>>(source: &'a str) -> Result<T, ConfigError> {
    toml::from_str(source)
        .map_err(|_| ConfigError::new(ConfigErrorKind::Syntax, ConfigField::Config))
}

fn client_global_tags(raw: &RawClientRoot) -> Vec<String> {
    raw.inbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|item| item.tag.clone())
        .chain(
            raw.outbounds
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|item| item.tag.clone()),
        )
        .chain(
            raw.chains
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .filter_map(|item| item.tag.clone()),
        )
        .chain(
            raw.selectors
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|item| item.tag.clone()),
        )
        .collect()
}

fn server_global_tags(raw: &RawServerRoot) -> Vec<String> {
    raw.inbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|item| item.tag.clone())
        .chain(
            raw.outbounds
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|item| item.tag.clone()),
        )
        .chain(
            raw.selectors
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|item| item.tag.clone()),
        )
        .collect()
}

fn dns_detour_tags(raw: &RawDns) -> Vec<&str> {
    raw.servers
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter_map(|server| server.detour.as_deref())
        .collect()
}

#[derive(Clone, Copy)]
enum DnsRole {
    Client,
    Server,
}

struct DnsValidationContext<'a> {
    role: DnsRole,
    global_tags: &'a [String],
    context_inbounds: &'a [String],
    ordinary_listens: &'a [SocketAddr],
    outbound_servers: &'a [SocketAddr],
}

struct GraphValidation<'a> {
    detour_tags: &'a [&'a str],
    source: &'a str,
}

fn validate_dns(
    raw: Option<RawDns>,
    context: DnsValidationContext<'_>,
    detours: Vec<EgressPlanHandle>,
    source: &str,
) -> Result<Option<DnsConfig>, ConfigError> {
    let Some(raw) = raw else {
        debug_assert!(detours.is_empty());
        return Ok(None);
    };
    let timeout = bounded_duration(raw.timeout_ms, 100, 30_000, ConfigField::DnsTimeout)?;
    let max_inflight = bounded_nonzero_u16(raw.max_inflight, ConfigField::DnsMaxInflight)?;
    if max_inflight.get() > 4_096 {
        return Err(ConfigError::semantic(ConfigField::DnsMaxInflight));
    }

    let raw_inbounds = match (context.role, raw.inbounds) {
        (DnsRole::Client, Some(inbounds)) => {
            validate_count(inbounds.len(), ConfigField::DnsInbounds)?;
            inbounds
        }
        (DnsRole::Client, None) => return Err(ConfigError::semantic(ConfigField::DnsInbounds)),
        (DnsRole::Server, None) => Vec::new(),
        (DnsRole::Server, Some(_)) => {
            return Err(ConfigError::semantic(ConfigField::DnsInbounds));
        }
    };
    let mut inbounds = Vec::with_capacity(raw_inbounds.len());
    for (index, inbound) in raw_inbounds.iter().enumerate() {
        validate_tag(&inbound.tag, ConfigField::DnsInboundsTag)?;
        if context.global_tags.contains(&inbound.tag)
            || raw_inbounds[..index]
                .iter()
                .any(|other| other.tag == inbound.tag)
        {
            return Err(ConfigError::semantic(ConfigField::DnsInboundsTag));
        }
        let listen = parse_socket(&inbound.listen, ConfigField::DnsInboundsListen)?;
        if context
            .ordinary_listens
            .iter()
            .chain(inbounds.iter().map(|item: &DnsInboundConfig| &item.listen))
            .any(|other| sockets_alias(*other, listen))
            || context
                .outbound_servers
                .iter()
                .any(|server| sockets_alias(*server, listen))
        {
            return Err(ConfigError::semantic(ConfigField::DnsInboundsListen));
        }
        inbounds.push(DnsInboundConfig { listen });
    }

    let raw_servers = raw
        .servers
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsServers))?;
    validate_count(raw_servers.len(), ConfigField::DnsServers)?;
    let mut servers = Vec::with_capacity(raw_servers.len());
    let mut detours = detours.into_iter();
    for (index, server) in raw_servers.iter().enumerate() {
        validate_tag(&server.tag, ConfigField::DnsServersTag)?;
        if raw_servers[..index]
            .iter()
            .any(|other| other.tag == server.tag)
        {
            return Err(ConfigError::semantic(ConfigField::DnsServersTag));
        }
        let transport = match server.transport.as_str() {
            "udp" => DnsTransport::Udp,
            "tcp" => DnsTransport::Tcp,
            "dot" => DnsTransport::Dot,
            "doh" => DnsTransport::Doh,
            _ => return Err(ConfigError::semantic(ConfigField::DnsServersTransport)),
        };
        let address = parse_socket(&server.address, ConfigField::DnsServersAddress)?;
        if server.detour.is_none()
            && inbounds
                .iter()
                .any(|inbound| sockets_alias(inbound.listen, address))
        {
            return Err(ConfigError::semantic(ConfigField::DnsServersAddress));
        }
        let server_name = match transport {
            DnsTransport::Udp | DnsTransport::Tcp if server.server_name.is_some() => {
                return Err(ConfigError::semantic(ConfigField::DnsServersServerName));
            }
            DnsTransport::Dot | DnsTransport::Doh => {
                let name = server
                    .server_name
                    .as_deref()
                    .filter(|name| valid_tls_name(name))
                    .ok_or_else(|| ConfigError::semantic(ConfigField::DnsServersServerName))?;
                Some(Box::from(name))
            }
            _ => None,
        };
        let path = match transport {
            DnsTransport::Doh => {
                let path = server.path.as_deref().unwrap_or("/dns-query");
                if !valid_doh_path(path) {
                    return Err(ConfigError::semantic(ConfigField::DnsServersPath));
                }
                Some(Box::from(path))
            }
            _ if server.path.is_some() => {
                return Err(ConfigError::semantic(ConfigField::DnsServersPath));
            }
            _ => None,
        };
        let detour = server.detour.as_ref().map(|_| {
            detours
                .next()
                .expect("validated detour roots preserve server order")
        });
        servers.push(DnsServerConfig {
            transport,
            address,
            server_name,
            path,
            detour,
        });
    }
    debug_assert!(detours.next().is_none());

    let route = raw
        .route
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRoute))?;
    if route.rules.len() > MAX_ROUTE_RULES {
        return Err(ConfigError::semantic(ConfigField::DnsRouteRules));
    }
    let final_tag = route
        .final_server
        .as_deref()
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteFinal))?;
    validate_tag(final_tag, ConfigField::DnsRouteFinal)?;
    let final_server = raw_servers
        .iter()
        .position(|server| server.tag == final_tag)
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteFinal))?;
    let mut reached = vec![false; servers.len()];
    reached[final_server] = true;
    let mut rules = Vec::with_capacity(route.rules.len());
    for rule in route.rules {
        if rule.outbound.is_some() {
            return Err(ConfigError::semantic(ConfigField::DnsRouteRulesServer));
        }
        let inbound = rule
            .inbound
            .as_deref()
            .map(|tag| {
                validate_tag(tag, ConfigField::DnsRouteRulesInbound)?;
                match context.role {
                    DnsRole::Client => raw_inbounds.iter().position(|item| item.tag == tag),
                    DnsRole::Server => context.context_inbounds.iter().position(|item| item == tag),
                }
                .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesInbound))
            })
            .transpose()?;
        let network = validate_network(rule.network.as_deref(), ConfigField::DnsRouteRulesNetwork)?;
        let target = rule
            .target
            .as_ref()
            .map(|target| validate_route_target(target, source, ConfigField::DnsRouteRulesTarget))
            .transpose()?;
        let server_tag = rule
            .server
            .as_deref()
            .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesServer))?;
        validate_tag(server_tag, ConfigField::DnsRouteRulesServer)?;
        let server = raw_servers
            .iter()
            .position(|candidate| candidate.tag == server_tag)
            .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesServer))?;
        reached[server] = true;
        rules.push(ActionRule::new(inbound, network, target, server));
    }
    if reached.contains(&false) {
        return Err(ConfigError::semantic(ConfigField::DnsRouteRulesServer));
    }
    let route = ActionTable::new(rules, final_server)
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRules))?;
    Ok(Some(DnsConfig {
        inbounds,
        servers,
        route,
        timeout,
        max_inflight,
    }))
}

fn validate_network(
    value: Option<&str>,
    field: ConfigField,
) -> Result<Option<Network>, ConfigError> {
    value
        .map(|network| match network {
            "tcp" => Ok(Network::Tcp),
            "udp" => Ok(Network::Udp),
            _ => Err(ConfigError::semantic(field)),
        })
        .transpose()
}

fn parse_socket(value: &str, field: ConfigField) -> Result<SocketAddr, ConfigError> {
    let address: SocketAddr = value.parse().map_err(|_| ConfigError::semantic(field))?;
    if address.port() == 0 {
        Err(ConfigError::semantic(field))
    } else {
        Ok(address)
    }
}

fn sockets_alias(left: SocketAddr, right: SocketAddr) -> bool {
    left.port() == right.port()
        && left.is_ipv4() == right.is_ipv4()
        && (left.ip() == right.ip() || left.ip().is_unspecified() || right.ip().is_unspecified())
}

fn valid_tls_name(name: &str) -> bool {
    (1..=253).contains(&name.len())
        && name.is_ascii()
        && name.split('.').all(|label| {
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

fn valid_doh_path(path: &str) -> bool {
    (1..=1_024).contains(&path.len())
        && path.is_ascii()
        && path.starts_with('/')
        && !path.starts_with("//")
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'?' | b'#'))
}

fn validate_client(
    mut raw: RawClientRoot,
    source: &str,
) -> Result<ValidatedClientConfig, ConfigError> {
    validate_schema(raw.schema_version)?;
    let global_tags = client_global_tags(&raw);
    let outbound_credentials = raw.outbounds.as_mut().map(|outbounds| {
        outbounds
            .iter_mut()
            .map(|outbound| (outbound.method.take(), outbound.psk.take()))
            .collect::<Vec<_>>()
    });
    let detour_tags = raw.dns.as_ref().map(dns_detour_tags).unwrap_or_default();
    let (listen, server, inbounds, outbounds, route, detours) = validate_client_graph(
        raw.client,
        raw.inbounds,
        raw.outbounds,
        raw.chains,
        raw.selectors,
        raw.route,
        GraphValidation {
            detour_tags: &detour_tags,
            source,
        },
    )?;
    let ordinary_listens = inbounds
        .iter()
        .map(|inbound| SocketAddr::V4(inbound.listen))
        .collect::<Vec<_>>();
    let outbound_servers = outbounds
        .iter()
        .map(|outbound| SocketAddr::V4(outbound.server))
        .collect::<Vec<_>>();
    let dns = validate_dns(
        raw.dns,
        DnsValidationContext {
            role: DnsRole::Client,
            global_tags: &global_tags,
            context_inbounds: &[],
            ordinary_listens: &ordinary_listens,
            outbound_servers: &outbound_servers,
        },
        detours,
        source,
    )?;
    let method = parse_method(&raw.shadowsocks.method, ConfigField::ShadowsocksMethod)?;
    let psk = parse_psk(method, &raw.shadowsocks.psk, ConfigField::ShadowsocksPsk)?;
    let outbound_psks =
        validate_client_credentials(outbound_credentials, &raw.shadowsocks, outbounds.len())?;
    let runtime = validate_runtime(raw.runtime)?;
    let udp = raw.udp.map(validate_udp).transpose()?;
    let logging = validate_logging(raw.logging)?;
    let mut listens: Vec<_> = inbounds.iter().map(|inbound| inbound.listen).collect();
    if let Some(dns) = &dns {
        listens.extend(
            dns.inbounds
                .iter()
                .filter_map(|inbound| match inbound.listen {
                    SocketAddr::V4(listen) => Some(listen),
                    SocketAddr::V6(_) => None,
                }),
        );
    }
    let metrics = validate_metrics(raw.metrics, &listens)?;
    Ok(ValidatedClientConfig {
        listen,
        server,
        inbounds,
        outbounds,
        route,
        dns,
        psk,
        outbound_psks,
        runtime,
        udp,
        logging,
        metrics,
    })
}

fn validate_server(raw: RawServerRoot, source: &str) -> Result<ValidatedServerConfig, ConfigError> {
    validate_schema(raw.schema_version)?;
    let global_tags = server_global_tags(&raw);
    let context_inbounds = raw
        .inbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|inbound| inbound.tag.clone())
        .collect::<Vec<_>>();
    if raw.chains.is_some() {
        return Err(ConfigError::semantic(ConfigField::Chains));
    }
    let detour_tags = raw.dns.as_ref().map(dns_detour_tags).unwrap_or_default();
    let (listen, inbounds, outbounds, route, detours) = validate_server_graph(
        raw.server,
        raw.inbounds,
        raw.outbounds,
        raw.selectors,
        raw.route,
        GraphValidation {
            detour_tags: &detour_tags,
            source,
        },
    )?;
    let dns = validate_dns(
        raw.dns,
        DnsValidationContext {
            role: DnsRole::Server,
            global_tags: &global_tags,
            context_inbounds: &context_inbounds,
            ordinary_listens: &[],
            outbound_servers: &[],
        },
        detours,
        source,
    )?;
    let method = parse_method(&raw.shadowsocks.method, ConfigField::ShadowsocksMethod)?;
    let psk = parse_psk(method, &raw.shadowsocks.psk, ConfigField::ShadowsocksPsk)?;
    let runtime = validate_runtime(raw.runtime)?;
    let replay = validate_replay(raw.replay)?;
    let udp = validate_udp(raw.udp)?;
    let logging = validate_logging(raw.logging)?;
    let listens: Vec<_> = inbounds.iter().map(|inbound| inbound.listen).collect();
    let metrics = validate_metrics(raw.metrics, &listens)?;
    Ok(ValidatedServerConfig {
        listen,
        inbounds,
        outbounds,
        route,
        dns,
        psk,
        runtime,
        replay,
        udp,
        logging,
        metrics,
    })
}

type ValidatedClientGraph = (
    SocketAddrV4,
    SocketAddrV4,
    Vec<ClientInboundConfig>,
    Vec<ClientOutboundConfig>,
    RouteTable,
    Vec<EgressPlanHandle>,
);

fn validate_client_graph(
    legacy: Option<RawClient>,
    tagged_inbounds: Option<Vec<RawClientInbound>>,
    tagged_outbounds: Option<Vec<RawClientOutbound>>,
    chains: Option<Vec<RawChain>>,
    selectors: Option<Vec<RawSelector>>,
    route: Option<RawRoute>,
    validation: GraphValidation<'_>,
) -> Result<ValidatedClientGraph, ConfigError> {
    let GraphValidation {
        detour_tags,
        source,
    } = validation;
    if chains.is_some()
        && (legacy.is_some() || tagged_inbounds.is_none() || tagged_outbounds.is_none())
    {
        return Err(ConfigError::semantic(ConfigField::Chains));
    }
    if selectors.is_some()
        && (legacy.is_some() || tagged_inbounds.is_none() || tagged_outbounds.is_none())
    {
        return Err(ConfigError::semantic(ConfigField::Selectors));
    }
    if route.is_some()
        && (legacy.is_some() || tagged_inbounds.is_none() || tagged_outbounds.is_none())
    {
        return Err(ConfigError::semantic(ConfigField::Route));
    }
    match (legacy, tagged_inbounds, tagged_outbounds) {
        (Some(legacy), None, None) => {
            let listen = parse_endpoint(&legacy.listen, ConfigField::ClientListen)?;
            let server = parse_endpoint(&legacy.server, ConfigField::ClientServer)?;
            if listen == server {
                return Err(ConfigError::semantic(ConfigField::ClientServer));
            }
            Ok((
                listen,
                server,
                vec![ClientInboundConfig { listen }],
                vec![ClientOutboundConfig { server }],
                RouteTable::static_bindings(vec![0])
                    .ok_or_else(|| ConfigError::semantic(ConfigField::Inbounds))?,
                if detour_tags.is_empty() {
                    Vec::new()
                } else {
                    return Err(ConfigError::semantic(ConfigField::DnsServersDetour));
                },
            ))
        }
        (None, Some(inbounds), Some(outbounds)) => {
            validate_count(inbounds.len(), ConfigField::Inbounds)?;
            validate_count(outbounds.len(), ConfigField::Outbounds)?;

            let mut listens = Vec::with_capacity(inbounds.len());
            for (index, inbound) in inbounds.iter().enumerate() {
                validate_tag(&inbound.tag, ConfigField::InboundsTag)?;
                if inbounds[..index]
                    .iter()
                    .any(|other| other.tag == inbound.tag)
                {
                    return Err(ConfigError::semantic(ConfigField::InboundsTag));
                }
                let listen = parse_endpoint(&inbound.listen, ConfigField::InboundsListen)?;
                if listens.contains(&listen) {
                    return Err(ConfigError::semantic(ConfigField::InboundsListen));
                }
                listens.push(listen);
            }

            let mut validated_outbounds = Vec::with_capacity(outbounds.len());
            for (index, outbound) in outbounds.iter().enumerate() {
                validate_tag(&outbound.tag, ConfigField::OutboundsTag)?;
                if inbounds.iter().any(|inbound| inbound.tag == outbound.tag)
                    || outbounds[..index]
                        .iter()
                        .any(|other| other.tag == outbound.tag)
                {
                    return Err(ConfigError::semantic(ConfigField::OutboundsTag));
                }
                let server = parse_endpoint(&outbound.server, ConfigField::OutboundsServer)?;
                if listens.contains(&server) {
                    return Err(ConfigError::semantic(ConfigField::OutboundsServer));
                }
                validated_outbounds.push(ClientOutboundConfig { server });
            }

            let plans = validate_chains(
                chains.as_deref(),
                &inbounds,
                &outbounds,
                selectors.as_deref(),
            )?;
            if detour_tags.iter().any(|tag| {
                !outbounds.iter().any(|outbound| outbound.tag == **tag)
                    && !chains.as_deref().is_some_and(|chains| {
                        chains
                            .iter()
                            .any(|chain| chain.tag.as_deref() == Some(*tag))
                    })
                    && !selectors.as_deref().is_some_and(|selectors| {
                        selectors.iter().any(|selector| selector.tag == **tag)
                    })
            }) {
                return Err(ConfigError::semantic(ConfigField::DnsServersDetour));
            }
            let (route, detours) = validate_route(
                route,
                inbounds
                    .iter()
                    .map(|inbound| (inbound.tag.as_str(), inbound.outbound.as_deref()))
                    .collect(),
                outbounds
                    .iter()
                    .map(|outbound| outbound.tag.as_str())
                    .collect(),
                selectors.as_deref(),
                &plans,
                detour_tags,
                source,
            )?;
            let validated_inbounds = listens
                .into_iter()
                .map(|listen| ClientInboundConfig { listen })
                .collect::<Vec<_>>();
            Ok((
                validated_inbounds[0].listen,
                validated_outbounds[route.final_outbound()].server,
                validated_inbounds,
                validated_outbounds,
                route,
                detours,
            ))
        }
        (None, None, None) => Err(ConfigError::new(
            ConfigErrorKind::Syntax,
            ConfigField::Config,
        )),
        (Some(_), Some(_), _) | (None, None, Some(_)) => {
            Err(ConfigError::semantic(ConfigField::Inbounds))
        }
        (Some(_), None, Some(_)) | (None, Some(_), None) => {
            Err(ConfigError::semantic(ConfigField::Outbounds))
        }
    }
}

fn validate_client_credentials(
    credentials: Option<Vec<(Option<String>, Option<SecretString>)>>,
    global: &RawShadowsocks,
    outbound_count: usize,
) -> Result<Vec<MethodPsk>, ConfigError> {
    let credentials = credentials.unwrap_or_else(|| vec![(None, None)]);
    debug_assert_eq!(credentials.len(), outbound_count);
    credentials
        .into_iter()
        .map(|(method, psk)| match (method, psk) {
            (None, None) => {
                let method = parse_method(&global.method, ConfigField::ShadowsocksMethod)?;
                parse_psk(method, &global.psk, ConfigField::ShadowsocksPsk)
            }
            (Some(_), None) => Err(ConfigError::semantic(ConfigField::OutboundsPsk)),
            (None, Some(_)) => Err(ConfigError::semantic(ConfigField::OutboundsMethod)),
            (Some(method), Some(psk)) => {
                let method = parse_method(&method, ConfigField::OutboundsMethod)?;
                parse_psk(method, &psk, ConfigField::OutboundsPsk)
            }
        })
        .collect()
}

fn validate_chains<'a>(
    chains: Option<&'a [RawChain]>,
    inbounds: &[RawClientInbound],
    outbounds: &[RawClientOutbound],
    selectors: Option<&[RawSelector]>,
) -> Result<Vec<TaggedPlan<'a>>, ConfigError> {
    let Some(chains) = chains else {
        return Ok(Vec::new());
    };
    validate_count(chains.len(), ConfigField::Chains)?;
    let mut plans = Vec::with_capacity(chains.len());
    for (index, chain) in chains.iter().enumerate() {
        let tag = chain
            .tag
            .as_deref()
            .ok_or_else(|| ConfigError::semantic(ConfigField::Chains))?;
        let chain_hops = chain
            .hops
            .as_deref()
            .ok_or_else(|| ConfigError::semantic(ConfigField::Chains))?;
        validate_tag(tag, ConfigField::ChainsTag)?;
        if inbounds.iter().any(|inbound| inbound.tag == tag)
            || outbounds.iter().any(|outbound| outbound.tag == tag)
            || chains[..index]
                .iter()
                .any(|other| other.tag.as_deref() == Some(tag))
            || selectors
                .is_some_and(|selectors| selectors.iter().any(|selector| selector.tag == tag))
        {
            return Err(ConfigError::semantic(ConfigField::ChainsTag));
        }
        if !(2..=8).contains(&chain_hops.len()) {
            return Err(ConfigError::semantic(ConfigField::ChainsHops));
        }
        let mut hops = Vec::with_capacity(chain_hops.len());
        for (hop, outbound_tag) in chain_hops.iter().enumerate() {
            validate_tag(outbound_tag, ConfigField::ChainsHops)?;
            if chain_hops[..hop].contains(outbound_tag) {
                return Err(ConfigError::semantic(ConfigField::ChainsHops));
            }
            hops.push(
                outbounds
                    .iter()
                    .position(|outbound| outbound.tag == *outbound_tag)
                    .ok_or_else(|| ConfigError::semantic(ConfigField::ChainsHops))?,
            );
        }
        plans.push(TaggedPlan::new(tag, hops));
    }
    Ok(plans)
}

type ValidatedServerGraph = (
    SocketAddrV4,
    Vec<ServerInboundConfig>,
    Vec<ServerOutboundConfig>,
    RouteTable,
    Vec<EgressPlanHandle>,
);

fn validate_server_graph(
    legacy: Option<RawServer>,
    tagged_inbounds: Option<Vec<RawServerInbound>>,
    tagged_outbounds: Option<Vec<RawServerOutbound>>,
    selectors: Option<Vec<RawSelector>>,
    route: Option<RawRoute>,
    validation: GraphValidation<'_>,
) -> Result<ValidatedServerGraph, ConfigError> {
    let GraphValidation {
        detour_tags,
        source,
    } = validation;
    if selectors.is_some()
        && (legacy.is_some() || tagged_inbounds.is_none() || tagged_outbounds.is_none())
    {
        return Err(ConfigError::semantic(ConfigField::Selectors));
    }
    if route.is_some()
        && (legacy.is_some() || tagged_inbounds.is_none() || tagged_outbounds.is_none())
    {
        return Err(ConfigError::semantic(ConfigField::Route));
    }
    match (legacy, tagged_inbounds, tagged_outbounds) {
        (Some(legacy), None, None) => {
            let listen = parse_endpoint(&legacy.listen, ConfigField::ServerListen)?;
            Ok((
                listen,
                vec![ServerInboundConfig { listen }],
                vec![ServerOutboundConfig],
                RouteTable::static_bindings(vec![0])
                    .ok_or_else(|| ConfigError::semantic(ConfigField::Inbounds))?,
                if detour_tags.is_empty() {
                    Vec::new()
                } else {
                    return Err(ConfigError::semantic(ConfigField::DnsServersDetour));
                },
            ))
        }
        (None, Some(inbounds), Some(outbounds)) => {
            validate_count(inbounds.len(), ConfigField::Inbounds)?;
            validate_count(outbounds.len(), ConfigField::Outbounds)?;

            let mut listens = Vec::with_capacity(inbounds.len());
            for (index, inbound) in inbounds.iter().enumerate() {
                validate_tag(&inbound.tag, ConfigField::InboundsTag)?;
                if inbounds[..index]
                    .iter()
                    .any(|other| other.tag == inbound.tag)
                {
                    return Err(ConfigError::semantic(ConfigField::InboundsTag));
                }
                let listen = parse_endpoint(&inbound.listen, ConfigField::InboundsListen)?;
                if listens.contains(&listen) {
                    return Err(ConfigError::semantic(ConfigField::InboundsListen));
                }
                listens.push(listen);
            }
            for (index, outbound) in outbounds.iter().enumerate() {
                validate_tag(&outbound.tag, ConfigField::OutboundsTag)?;
                if inbounds.iter().any(|inbound| inbound.tag == outbound.tag)
                    || outbounds[..index]
                        .iter()
                        .any(|other| other.tag == outbound.tag)
                {
                    return Err(ConfigError::semantic(ConfigField::OutboundsTag));
                }
            }

            if detour_tags
                .iter()
                .any(|tag| !outbounds.iter().any(|outbound| outbound.tag == **tag))
            {
                return Err(ConfigError::semantic(ConfigField::DnsServersDetour));
            }
            let (route, detours) = validate_route(
                route,
                inbounds
                    .iter()
                    .map(|inbound| (inbound.tag.as_str(), inbound.outbound.as_deref()))
                    .collect(),
                outbounds
                    .iter()
                    .map(|outbound| outbound.tag.as_str())
                    .collect(),
                selectors.as_deref(),
                &[],
                detour_tags,
                source,
            )?;
            let validated_inbounds = listens
                .into_iter()
                .map(|listen| ServerInboundConfig { listen })
                .collect::<Vec<_>>();
            Ok((
                validated_inbounds[0].listen,
                validated_inbounds,
                vec![ServerOutboundConfig; outbounds.len()],
                route,
                detours,
            ))
        }
        (None, None, None) => Err(ConfigError::new(
            ConfigErrorKind::Syntax,
            ConfigField::Config,
        )),
        (Some(_), Some(_), _) | (None, None, Some(_)) => {
            Err(ConfigError::semantic(ConfigField::Inbounds))
        }
        (Some(_), None, Some(_)) | (None, Some(_), None) => {
            Err(ConfigError::semantic(ConfigField::Outbounds))
        }
    }
}

fn validate_route(
    route: Option<RawRoute>,
    inbounds: Vec<(&str, Option<&str>)>,
    outbounds: Vec<&str>,
    selectors: Option<&[RawSelector]>,
    plans: &[TaggedPlan<'_>],
    extra_roots: &[&str],
    source: &str,
) -> Result<(RouteTable, Vec<EgressPlanHandle>), ConfigError> {
    if selectors.is_some_and(<[RawSelector]>::is_empty) {
        return Err(ConfigError::semantic(ConfigField::Selectors));
    }
    if selectors.is_some() || !plans.is_empty() {
        return validate_selector_route(
            route,
            &inbounds,
            &outbounds,
            selectors.unwrap_or(&[]),
            plans,
            extra_roots,
            source,
        );
    }
    let Some(route) = route else {
        let mut referenced = vec![false; outbounds.len()];
        let mut bindings = Vec::with_capacity(inbounds.len());
        for (_, outbound) in inbounds {
            let outbound =
                outbound.ok_or_else(|| ConfigError::semantic(ConfigField::InboundsOutbound))?;
            validate_tag(outbound, ConfigField::InboundsOutbound)?;
            let index = outbounds
                .iter()
                .position(|tag| *tag == outbound)
                .ok_or_else(|| ConfigError::semantic(ConfigField::InboundsOutbound))?;
            referenced[index] = true;
            bindings.push(index);
        }
        if referenced.contains(&false) {
            for tag in extra_roots {
                let index = outbounds
                    .iter()
                    .position(|outbound| outbound == tag)
                    .ok_or_else(|| ConfigError::semantic(ConfigField::DnsServersDetour))?;
                referenced[index] = true;
            }
        }
        if referenced.contains(&false) {
            return Err(ConfigError::semantic(ConfigField::OutboundsTag));
        }
        let route = RouteTable::static_bindings(bindings)
            .ok_or_else(|| ConfigError::semantic(ConfigField::Inbounds))?;
        let detours = extra_roots
            .iter()
            .map(|tag| {
                let outbound = outbounds
                    .iter()
                    .position(|candidate| candidate == tag)
                    .expect("validated direct detour");
                EgressPlanHandle::direct(outbound)
            })
            .collect();
        return Ok((route, detours));
    };

    if inbounds.iter().any(|(_, outbound)| outbound.is_some()) {
        return Err(ConfigError::semantic(ConfigField::Route));
    }
    if route.rules.len() > MAX_ROUTE_RULES {
        return Err(ConfigError::semantic(ConfigField::RouteRules));
    }

    let final_tag = route
        .final_outbound
        .as_deref()
        .ok_or_else(|| ConfigError::semantic(ConfigField::RouteFinal))?;
    validate_tag(final_tag, ConfigField::RouteFinal)?;
    let final_outbound = outbounds
        .iter()
        .position(|tag| *tag == final_tag)
        .ok_or_else(|| ConfigError::semantic(ConfigField::RouteFinal))?;
    let mut referenced = vec![false; outbounds.len()];
    referenced[final_outbound] = true;
    let mut rules = Vec::with_capacity(route.rules.len());
    for rule in route.rules {
        if rule.server.is_some() {
            return Err(ConfigError::semantic(ConfigField::RouteRulesOutbound));
        }
        if rule.inbound.is_none() && rule.network.is_none() && rule.target.is_none() {
            return Err(ConfigError::semantic(ConfigField::RouteRules));
        }
        let inbound = rule
            .inbound
            .as_deref()
            .map(|tag| {
                validate_tag(tag, ConfigField::RouteRulesInbound)?;
                inbounds
                    .iter()
                    .position(|(inbound, _)| *inbound == tag)
                    .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRulesInbound))
            })
            .transpose()?;
        let network = validate_network(rule.network.as_deref(), ConfigField::RouteRulesNetwork)?;
        let target = rule
            .target
            .as_ref()
            .map(|target| validate_route_target(target, source, ConfigField::RouteRulesTarget))
            .transpose()?;
        let outbound_tag = rule
            .outbound
            .as_deref()
            .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRulesOutbound))?;
        validate_tag(outbound_tag, ConfigField::RouteRulesOutbound)?;
        let outbound = outbounds
            .iter()
            .position(|tag| *tag == outbound_tag)
            .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRulesOutbound))?;
        referenced[outbound] = true;
        rules.push(RouteRule::new(inbound, network, target, outbound));
    }
    if referenced.contains(&false) {
        for tag in extra_roots {
            let index = outbounds
                .iter()
                .position(|outbound| outbound == tag)
                .ok_or_else(|| ConfigError::semantic(ConfigField::DnsServersDetour))?;
            referenced[index] = true;
        }
    }
    if referenced.contains(&false) {
        return Err(ConfigError::semantic(ConfigField::RouteRulesOutbound));
    }
    let route = RouteTable::routed(rules, final_outbound)
        .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRules))?;
    let detours = extra_roots
        .iter()
        .map(|tag| {
            let outbound = outbounds
                .iter()
                .position(|candidate| candidate == tag)
                .expect("validated direct detour");
            EgressPlanHandle::direct(outbound)
        })
        .collect();
    Ok((route, detours))
}

fn validate_selector_route(
    route: Option<RawRoute>,
    inbounds: &[(&str, Option<&str>)],
    outbounds: &[&str],
    selectors: &[RawSelector],
    plans: &[TaggedPlan<'_>],
    extra_roots: &[&str],
    source: &str,
) -> Result<(RouteTable, Vec<EgressPlanHandle>), ConfigError> {
    let tagged_inbounds = inbounds
        .iter()
        .enumerate()
        .map(|(index, (tag, _))| TaggedInbound::new(tag, index))
        .collect::<Vec<_>>();
    let tagged_outbounds = outbounds
        .iter()
        .enumerate()
        .map(|(index, tag)| TaggedOutbound::new(tag, index))
        .collect::<Vec<_>>();
    let definitions = selectors
        .iter()
        .map(|selector| {
            SelectorDefinition::new(
                &selector.tag,
                selector.outbounds.iter().map(String::as_str).collect(),
                selector.default.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    let (tagged_route, routed) = match route.as_ref() {
        None => {
            let bindings = inbounds
                .iter()
                .map(|(inbound, outbound)| {
                    outbound
                        .map(|outbound| TaggedStaticBinding::new(inbound, outbound))
                        .ok_or_else(|| ConfigError::semantic(ConfigField::InboundsOutbound))
                })
                .collect::<Result<Vec<_>, _>>()?;
            (TaggedRoute::Static(bindings), false)
        }
        Some(route) => {
            if inbounds.iter().any(|(_, outbound)| outbound.is_some()) {
                return Err(ConfigError::semantic(ConfigField::Route));
            }
            if route.rules.len() > MAX_ROUTE_RULES {
                return Err(ConfigError::semantic(ConfigField::RouteRules));
            }
            let mut rules = Vec::with_capacity(route.rules.len());
            for rule in &route.rules {
                if rule.server.is_some() {
                    return Err(ConfigError::semantic(ConfigField::RouteRulesOutbound));
                }
                let network =
                    validate_network(rule.network.as_deref(), ConfigField::RouteRulesNetwork)?;
                let target = rule
                    .target
                    .as_ref()
                    .map(|target| {
                        validate_route_target(target, source, ConfigField::RouteRulesTarget)
                    })
                    .transpose()?;
                rules.push(TaggedRouteRule::new(
                    rule.inbound.as_deref(),
                    network,
                    target,
                    rule.outbound.as_deref(),
                ));
            }
            (
                TaggedRoute::Routed {
                    rules,
                    final_outbound: route.final_outbound.as_deref(),
                },
                true,
            )
        }
    };

    compile_selector_plans_with_roots(
        &tagged_inbounds,
        &tagged_outbounds,
        plans,
        &definitions,
        tagged_route,
        extra_roots,
    )
    .map(|(route, _, roots)| (route, roots))
    .map_err(|error| {
        if matches!(error, SelectorCompileError::ExtraRoot) {
            ConfigError::semantic(ConfigField::DnsServersDetour)
        } else {
            ConfigError::semantic(selector_error_field(error, routed))
        }
    })
}

const fn selector_error_field(error: SelectorCompileError, routed: bool) -> ConfigField {
    match error {
        SelectorCompileError::Inbounds => ConfigField::InboundsTag,
        SelectorCompileError::Outbounds => ConfigField::OutboundsTag,
        SelectorCompileError::Plans => ConfigField::Chains,
        SelectorCompileError::PlanTag | SelectorCompileError::UnreachablePlan => {
            ConfigField::ChainsTag
        }
        SelectorCompileError::PlanHops => ConfigField::ChainsHops,
        SelectorCompileError::Selectors => ConfigField::Selectors,
        SelectorCompileError::SelectorTag | SelectorCompileError::UnreachableSelector => {
            ConfigField::SelectorsTag
        }
        SelectorCompileError::SelectorOutbounds => ConfigField::SelectorsOutbounds,
        SelectorCompileError::SelectorDefault => ConfigField::SelectorsDefault,
        SelectorCompileError::StaticBinding => ConfigField::InboundsOutbound,
        SelectorCompileError::RouteRules => ConfigField::RouteRules,
        SelectorCompileError::RouteRuleInbound => ConfigField::RouteRulesInbound,
        SelectorCompileError::RouteRuleOutbound => ConfigField::RouteRulesOutbound,
        SelectorCompileError::ExtraRoot => ConfigField::RouteRulesOutbound,
        SelectorCompileError::RouteFinal => ConfigField::RouteFinal,
        SelectorCompileError::UnreachableOutbound if routed => ConfigField::RouteRulesOutbound,
        SelectorCompileError::UnreachableOutbound => ConfigField::OutboundsTag,
    }
}

fn validate_route_target(
    raw: &toml::Spanned<RawRouteTarget>,
    source: &str,
    field: ConfigField,
) -> Result<TargetAddr, ConfigError> {
    if !source
        .get(raw.span())
        .is_some_and(|value| value.trim_start().starts_with('{'))
    {
        return Err(ConfigError::semantic(field));
    }
    let raw = raw.get_ref();
    let host = raw
        .host
        .as_deref()
        .ok_or_else(|| ConfigError::semantic(field))?;
    let port = raw
        .port
        .and_then(|port| u16::try_from(port).ok())
        .ok_or_else(|| ConfigError::semantic(field))?;
    match host.parse::<IpAddr>() {
        Ok(ip) => TargetAddr::ip(SocketAddr::new(ip, port)),
        Err(_) => TargetAddr::domain(host, port),
    }
    .map_err(|_| ConfigError::semantic(field))
}

fn validate_count(count: usize, field: ConfigField) -> Result<(), ConfigError> {
    if (1..=64).contains(&count) {
        Ok(())
    } else {
        Err(ConfigError::semantic(field))
    }
}

fn validate_tag(tag: &str, field: ConfigField) -> Result<(), ConfigError> {
    if (1..=64).contains(&tag.len())
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        Ok(())
    } else {
        Err(ConfigError::semantic(field))
    }
}

fn validate_schema(version: u32) -> Result<(), ConfigError> {
    if version == 1 {
        Ok(())
    } else {
        Err(ConfigError::semantic(ConfigField::SchemaVersion))
    }
}

fn parse_endpoint(value: &str, field: ConfigField) -> Result<SocketAddrV4, ConfigError> {
    let endpoint: SocketAddrV4 = value.parse().map_err(|_| ConfigError::semantic(field))?;
    if endpoint.port() == 0 {
        return Err(ConfigError::semantic(field));
    }
    Ok(endpoint)
}

fn parse_method(value: &str, field: ConfigField) -> Result<TcpMethodProfile, ConfigError> {
    match value {
        "2022-blake3-aes-128-gcm" => Ok(TcpMethodProfile::Blake3Aes128Gcm2022),
        "2022-blake3-aes-256-gcm" => Ok(TcpMethodProfile::Blake3Aes256Gcm2022),
        "2022-blake3-chacha20-poly1305" => Ok(TcpMethodProfile::Blake3ChaCha20Poly13052022),
        _ => Err(ConfigError::semantic(field)),
    }
}

fn parse_psk(
    method: TcpMethodProfile,
    value: &SecretString,
    field: ConfigField,
) -> Result<MethodPsk, ConfigError> {
    let token = value.as_str();
    let expected_bytes = method.key_bytes();
    let expected_encoded_bytes = expected_bytes.div_ceil(3) * 4;
    if token.len() != expected_encoded_bytes {
        return Err(ConfigError::semantic(field));
    }

    let mut decoded = Zeroizing::new([0_u8; 32]);
    let decoded_len = STANDARD
        .decode_slice(token.as_bytes(), decoded.as_mut())
        .map_err(|_| ConfigError::semantic(field))?;
    if decoded_len != expected_bytes {
        return Err(ConfigError::semantic(field));
    }

    let mut canonical = Zeroizing::new([0_u8; 44]);
    let encoded_len = STANDARD
        .encode_slice(&decoded[..decoded_len], canonical.as_mut())
        .map_err(|_| ConfigError::semantic(field))?;
    if encoded_len != token.len() || &canonical[..encoded_len] != token.as_bytes() {
        return Err(ConfigError::semantic(field));
    }

    let psk = MethodPsk::try_from_slice(method, &decoded[..decoded_len])
        .map_err(|_| ConfigError::semantic(field))?;
    decoded.zeroize();
    canonical.zeroize();
    Ok(psk)
}

fn validate_runtime(raw: RawRuntime) -> Result<RuntimeConfig, ConfigError> {
    let max_connections =
        bounded_nonzero_u16(raw.max_connections, ConfigField::RuntimeMaxConnections)?;
    let listen_backlog =
        bounded_nonzero_u16(raw.listen_backlog, ConfigField::RuntimeListenBacklog)?;
    let handshake_timeout = bounded_duration(
        raw.handshake_timeout_ms,
        100,
        60_000,
        ConfigField::RuntimeHandshakeTimeout,
    )?;
    let connect_timeout = bounded_duration(
        raw.connect_timeout_ms,
        100,
        120_000,
        ConfigField::RuntimeConnectTimeout,
    )?;
    let idle_timeout = bounded_duration(
        raw.idle_timeout_ms,
        1_000,
        86_400_000,
        ConfigField::RuntimeIdleTimeout,
    )?;
    let shutdown_grace = bounded_duration(
        raw.shutdown_grace_ms,
        0,
        300_000,
        ConfigField::RuntimeShutdownGrace,
    )?;
    Ok(RuntimeConfig {
        max_connections,
        listen_backlog,
        handshake_timeout,
        connect_timeout,
        idle_timeout,
        shutdown_grace,
    })
}

fn bounded_nonzero_u16(value: u32, field: ConfigField) -> Result<NonZeroU16, ConfigError> {
    let value = u16::try_from(value).map_err(|_| ConfigError::semantic(field))?;
    NonZeroU16::new(value).ok_or_else(|| ConfigError::semantic(field))
}

fn bounded_duration(
    value: u64,
    minimum: u64,
    maximum: u64,
    field: ConfigField,
) -> Result<Duration, ConfigError> {
    if (minimum..=maximum).contains(&value) {
        Ok(Duration::from_millis(value))
    } else {
        Err(ConfigError::semantic(field))
    }
}

fn validate_replay(raw: RawReplay) -> Result<ReplayConfig, ConfigError> {
    if (1_024..=1_048_576).contains(&raw.capacity) {
        Ok(ReplayConfig {
            capacity: raw.capacity,
        })
    } else {
        Err(ConfigError::semantic(ConfigField::ReplayCapacity))
    }
}

fn validate_udp(raw: RawUdp) -> Result<UdpConfig, ConfigError> {
    if !(1..=65_535).contains(&raw.max_sessions) {
        return Err(ConfigError::semantic(ConfigField::UdpMaxSessions));
    }
    if !((1024 * 1024)..=(256 * 1024 * 1024)).contains(&raw.max_buffered_bytes) {
        return Err(ConfigError::semantic(ConfigField::UdpMaxBufferedBytes));
    }
    let idle_timeout = bounded_duration(
        raw.idle_timeout_ms,
        60_000,
        86_400_000,
        ConfigField::UdpIdleTimeout,
    )?;
    Ok(UdpConfig {
        enabled: raw.enabled,
        max_sessions: raw.max_sessions,
        max_buffered_bytes: raw.max_buffered_bytes,
        idle_timeout,
    })
}

fn validate_logging(raw: RawLogging) -> Result<LoggingConfig, ConfigError> {
    let level = match raw.level.as_str() {
        "error" => LoggingLevel::Error,
        "warn" => LoggingLevel::Warn,
        "info" => LoggingLevel::Info,
        "debug" => LoggingLevel::Debug,
        "trace" => LoggingLevel::Trace,
        _ => return Err(ConfigError::semantic(ConfigField::LoggingLevel)),
    };
    Ok(LoggingConfig { level })
}

fn validate_metrics(
    raw: Option<RawMetrics>,
    proxy_listens: &[SocketAddrV4],
) -> Result<Option<MetricsConfig>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let listen = parse_endpoint(&raw.listen, ConfigField::MetricsListen)?;
    if !listen.ip().is_loopback() || proxy_listens.contains(&listen) {
        return Err(ConfigError::semantic(ConfigField::MetricsListen));
    }
    Ok(Some(MetricsConfig { listen }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClientRoot {
    schema_version: u32,
    client: Option<RawClient>,
    inbounds: Option<Vec<RawClientInbound>>,
    outbounds: Option<Vec<RawClientOutbound>>,
    chains: Option<Vec<RawChain>>,
    selectors: Option<Vec<RawSelector>>,
    route: Option<RawRoute>,
    dns: Option<RawDns>,
    shadowsocks: RawShadowsocks,
    #[serde(default)]
    runtime: RawRuntime,
    udp: Option<RawUdp>,
    #[serde(default)]
    logging: RawLogging,
    metrics: Option<RawMetrics>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServerRoot {
    schema_version: u32,
    server: Option<RawServer>,
    inbounds: Option<Vec<RawServerInbound>>,
    outbounds: Option<Vec<RawServerOutbound>>,
    chains: Option<Vec<RawChain>>,
    selectors: Option<Vec<RawSelector>>,
    route: Option<RawRoute>,
    dns: Option<RawDns>,
    shadowsocks: RawShadowsocks,
    #[serde(default)]
    runtime: RawRuntime,
    #[serde(default)]
    replay: RawReplay,
    #[serde(default)]
    udp: RawUdp,
    #[serde(default)]
    logging: RawLogging,
    metrics: Option<RawMetrics>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUdp {
    #[serde(default = "default_udp_enabled")]
    enabled: bool,
    #[serde(default = "default_udp_max_sessions")]
    max_sessions: usize,
    #[serde(default = "default_udp_max_buffered_bytes")]
    max_buffered_bytes: usize,
    #[serde(default = "default_udp_idle_timeout_ms")]
    idle_timeout_ms: u64,
}

impl Default for RawUdp {
    fn default() -> Self {
        Self {
            enabled: default_udp_enabled(),
            max_sessions: default_udp_max_sessions(),
            max_buffered_bytes: default_udp_max_buffered_bytes(),
            idle_timeout_ms: default_udp_idle_timeout_ms(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClient {
    listen: String,
    server: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    listen: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClientInbound {
    tag: String,
    listen: String,
    outbound: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClientOutbound {
    tag: String,
    server: String,
    method: Option<String>,
    psk: Option<SecretString>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawChain {
    tag: Option<String>,
    hops: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServerInbound {
    tag: String,
    listen: String,
    outbound: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServerOutbound {
    tag: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSelector {
    tag: String,
    #[serde(default)]
    outbounds: Vec<String>,
    default: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoute {
    #[serde(rename = "final")]
    final_outbound: Option<String>,
    #[serde(default)]
    rules: Vec<RawRouteRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouteRule {
    inbound: Option<String>,
    network: Option<String>,
    target: Option<toml::Spanned<RawRouteTarget>>,
    outbound: Option<String>,
    server: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDns {
    #[serde(default = "default_dns_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_dns_max_inflight")]
    max_inflight: u32,
    inbounds: Option<Vec<RawDnsInbound>>,
    servers: Option<Vec<RawDnsServer>>,
    route: Option<RawDnsRoute>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDnsInbound {
    tag: String,
    listen: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDnsServer {
    tag: String,
    transport: String,
    address: String,
    server_name: Option<String>,
    path: Option<String>,
    detour: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDnsRoute {
    #[serde(rename = "final")]
    final_server: Option<String>,
    #[serde(default)]
    rules: Vec<RawDnsRouteRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDnsRouteRule {
    inbound: Option<String>,
    network: Option<String>,
    target: Option<toml::Spanned<RawRouteTarget>>,
    server: Option<String>,
    outbound: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouteTarget {
    host: Option<String>,
    port: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawShadowsocks {
    method: String,
    psk: SecretString,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntime {
    #[serde(default = "default_max_connections")]
    max_connections: u32,
    #[serde(default = "default_listen_backlog")]
    listen_backlog: u32,
    #[serde(default = "default_handshake_timeout_ms")]
    handshake_timeout_ms: u64,
    #[serde(default = "default_connect_timeout_ms")]
    connect_timeout_ms: u64,
    #[serde(default = "default_idle_timeout_ms")]
    idle_timeout_ms: u64,
    #[serde(default = "default_shutdown_grace_ms")]
    shutdown_grace_ms: u64,
}

impl Default for RawRuntime {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            listen_backlog: default_listen_backlog(),
            handshake_timeout_ms: default_handshake_timeout_ms(),
            connect_timeout_ms: default_connect_timeout_ms(),
            idle_timeout_ms: default_idle_timeout_ms(),
            shutdown_grace_ms: default_shutdown_grace_ms(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReplay {
    #[serde(default = "default_replay_capacity")]
    capacity: usize,
}

impl Default for RawReplay {
    fn default() -> Self {
        Self {
            capacity: default_replay_capacity(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLogging {
    #[serde(default = "default_logging_level")]
    level: String,
}

impl Default for RawLogging {
    fn default() -> Self {
        Self {
            level: default_logging_level(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMetrics {
    listen: String,
}

struct SecretString(Zeroizing<String>);

impl SecretString {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SecretVisitor;

        impl Visitor<'_> for SecretVisitor {
            type Value = SecretString;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a base64 secret string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SecretString(Zeroizing::new(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SecretString(Zeroizing::new(value)))
            }
        }

        deserializer.deserialize_string(SecretVisitor)
    }
}

const fn default_max_connections() -> u32 {
    DEFAULT_MAX_CONNECTIONS
}

const fn default_listen_backlog() -> u32 {
    DEFAULT_LISTEN_BACKLOG
}

const fn default_handshake_timeout_ms() -> u64 {
    DEFAULT_HANDSHAKE_TIMEOUT_MS
}

const fn default_connect_timeout_ms() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_MS
}

const fn default_idle_timeout_ms() -> u64 {
    DEFAULT_IDLE_TIMEOUT_MS
}

const fn default_shutdown_grace_ms() -> u64 {
    DEFAULT_SHUTDOWN_GRACE_MS
}

const fn default_replay_capacity() -> usize {
    DEFAULT_REPLAY_CAPACITY
}

const fn default_udp_enabled() -> bool {
    true
}

const fn default_udp_max_sessions() -> usize {
    DEFAULT_UDP_MAX_SESSIONS
}

const fn default_udp_max_buffered_bytes() -> usize {
    DEFAULT_UDP_MAX_BUFFERED_BYTES
}

const fn default_udp_idle_timeout_ms() -> u64 {
    DEFAULT_UDP_IDLE_TIMEOUT_MS
}

const fn default_dns_timeout_ms() -> u64 {
    DEFAULT_DNS_TIMEOUT_MS
}

const fn default_dns_max_inflight() -> u32 {
    DEFAULT_DNS_MAX_INFLIGHT
}

fn default_logging_level() -> String {
    "info".to_owned()
}
