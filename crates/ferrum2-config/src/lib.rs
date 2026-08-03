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
use ferrum2_core::route::{MAX_ROUTE_RULES, Network, RouteRule, RouteTable};
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

/// A validated client configuration with no retained source text.
pub struct ValidatedClientConfig {
    pub listen: SocketAddrV4,
    pub server: SocketAddrV4,
    pub inbounds: Vec<ClientInboundConfig>,
    pub outbounds: Vec<ClientOutboundConfig>,
    pub route: RouteTable,
    pub psk: MethodPsk,
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
}

/// A validated server configuration with no retained source text.
pub struct ValidatedServerConfig {
    pub listen: SocketAddrV4,
    pub inbounds: Vec<ServerInboundConfig>,
    pub outbounds: Vec<ServerOutboundConfig>,
    pub route: RouteTable,
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
    Route,
    RouteRules,
    RouteRulesInbound,
    RouteRulesNetwork,
    RouteRulesTarget,
    RouteRulesOutbound,
    RouteFinal,
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
            Self::Route => "route",
            Self::RouteRules => "route.rules",
            Self::RouteRulesInbound => "route.rules.inbound",
            Self::RouteRulesNetwork => "route.rules.network",
            Self::RouteRulesTarget => "route.rules.target",
            Self::RouteRulesOutbound => "route.rules.outbound",
            Self::RouteFinal => "route.final",
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
    validate_client(raw)
}

/// Reads and fully validates a server configuration without creating runtime resources.
pub fn load_server(path: impl AsRef<Path>) -> Result<ValidatedServerConfig, ConfigError> {
    let source = read_bounded_utf8(path.as_ref())?;
    let raw: RawServerRoot = parse_toml(&source)?;
    validate_server(raw)
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

fn validate_client(raw: RawClientRoot) -> Result<ValidatedClientConfig, ConfigError> {
    validate_schema(raw.schema_version)?;
    let (listen, server, inbounds, outbounds, route) =
        validate_client_graph(raw.client, raw.inbounds, raw.outbounds, raw.route)?;
    let method = parse_method(&raw.shadowsocks.method)?;
    let psk = parse_psk(method, &raw.shadowsocks.psk)?;
    let runtime = validate_runtime(raw.runtime)?;
    let udp = raw.udp.map(validate_udp).transpose()?;
    let logging = validate_logging(raw.logging)?;
    let listens: Vec<_> = inbounds.iter().map(|inbound| inbound.listen).collect();
    let metrics = validate_metrics(raw.metrics, &listens)?;
    Ok(ValidatedClientConfig {
        listen,
        server,
        inbounds,
        outbounds,
        route,
        psk,
        runtime,
        udp,
        logging,
        metrics,
    })
}

fn validate_server(raw: RawServerRoot) -> Result<ValidatedServerConfig, ConfigError> {
    validate_schema(raw.schema_version)?;
    let (listen, inbounds, outbounds, route) =
        validate_server_graph(raw.server, raw.inbounds, raw.outbounds, raw.route)?;
    let method = parse_method(&raw.shadowsocks.method)?;
    let psk = parse_psk(method, &raw.shadowsocks.psk)?;
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
);

fn validate_client_graph(
    legacy: Option<RawClient>,
    tagged_inbounds: Option<Vec<RawClientInbound>>,
    tagged_outbounds: Option<Vec<RawClientOutbound>>,
    route: Option<RawRoute>,
) -> Result<ValidatedClientGraph, ConfigError> {
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

            let route = validate_route(
                route,
                inbounds
                    .iter()
                    .map(|inbound| (inbound.tag.as_str(), inbound.outbound.as_deref()))
                    .collect(),
                outbounds
                    .iter()
                    .map(|outbound| outbound.tag.as_str())
                    .collect(),
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

fn validate_server_graph(
    legacy: Option<RawServer>,
    tagged_inbounds: Option<Vec<RawServerInbound>>,
    tagged_outbounds: Option<Vec<RawServerOutbound>>,
    route: Option<RawRoute>,
) -> Result<
    (
        SocketAddrV4,
        Vec<ServerInboundConfig>,
        Vec<ServerOutboundConfig>,
        RouteTable,
    ),
    ConfigError,
> {
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

            let route = validate_route(
                route,
                inbounds
                    .iter()
                    .map(|inbound| (inbound.tag.as_str(), inbound.outbound.as_deref()))
                    .collect(),
                outbounds
                    .iter()
                    .map(|outbound| outbound.tag.as_str())
                    .collect(),
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
) -> Result<RouteTable, ConfigError> {
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
            return Err(ConfigError::semantic(ConfigField::OutboundsTag));
        }
        return RouteTable::static_bindings(bindings)
            .ok_or_else(|| ConfigError::semantic(ConfigField::Inbounds));
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
        let network = rule
            .network
            .as_deref()
            .map(|network| match network {
                "tcp" => Ok(Network::Tcp),
                "udp" => Ok(Network::Udp),
                _ => Err(ConfigError::semantic(ConfigField::RouteRulesNetwork)),
            })
            .transpose()?;
        let target = rule.target.map(validate_route_target).transpose()?;
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
        return Err(ConfigError::semantic(ConfigField::RouteRulesOutbound));
    }
    RouteTable::routed(rules, final_outbound)
        .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRules))
}

fn validate_route_target(raw: RawRouteTarget) -> Result<TargetAddr, ConfigError> {
    let host = raw
        .host
        .as_deref()
        .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRulesTarget))?;
    let port = raw
        .port
        .and_then(|port| u16::try_from(port).ok())
        .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRulesTarget))?;
    match host.parse::<IpAddr>() {
        Ok(ip) => TargetAddr::ip(SocketAddr::new(ip, port)),
        Err(_) => TargetAddr::domain(host, port),
    }
    .map_err(|_| ConfigError::semantic(ConfigField::RouteRulesTarget))
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

fn parse_method(value: &str) -> Result<TcpMethodProfile, ConfigError> {
    match value {
        "2022-blake3-aes-128-gcm" => Ok(TcpMethodProfile::Blake3Aes128Gcm2022),
        "2022-blake3-aes-256-gcm" => Ok(TcpMethodProfile::Blake3Aes256Gcm2022),
        "2022-blake3-chacha20-poly1305" => Ok(TcpMethodProfile::Blake3ChaCha20Poly13052022),
        _ => Err(ConfigError::semantic(ConfigField::ShadowsocksMethod)),
    }
}

fn parse_psk(method: TcpMethodProfile, value: &SecretString) -> Result<MethodPsk, ConfigError> {
    let token = value.as_str();
    let expected_bytes = method.key_bytes();
    let expected_encoded_bytes = expected_bytes.div_ceil(3) * 4;
    if token.len() != expected_encoded_bytes {
        return Err(ConfigError::semantic(ConfigField::ShadowsocksPsk));
    }

    let mut decoded = Zeroizing::new([0_u8; 32]);
    let decoded_len = STANDARD
        .decode_slice(token.as_bytes(), decoded.as_mut())
        .map_err(|_| ConfigError::semantic(ConfigField::ShadowsocksPsk))?;
    if decoded_len != expected_bytes {
        return Err(ConfigError::semantic(ConfigField::ShadowsocksPsk));
    }

    let mut canonical = Zeroizing::new([0_u8; 44]);
    let encoded_len = STANDARD
        .encode_slice(&decoded[..decoded_len], canonical.as_mut())
        .map_err(|_| ConfigError::semantic(ConfigField::ShadowsocksPsk))?;
    if encoded_len != token.len() || &canonical[..encoded_len] != token.as_bytes() {
        return Err(ConfigError::semantic(ConfigField::ShadowsocksPsk));
    }

    let psk = MethodPsk::try_from_slice(method, &decoded[..decoded_len])
        .map_err(|_| ConfigError::semantic(ConfigField::ShadowsocksPsk))?;
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
    route: Option<RawRoute>,
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
    route: Option<RawRoute>,
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
    target: Option<RawRouteTarget>,
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

fn default_logging_level() -> String {
    "info".to_owned()
}
