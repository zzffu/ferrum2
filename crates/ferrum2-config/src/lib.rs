#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddrV4;
use std::num::NonZeroU16;
use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
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

/// A validated client configuration with no retained source text.
pub struct ValidatedClientConfig {
    pub listen: SocketAddrV4,
    pub server: SocketAddrV4,
    pub psk: MethodPsk,
    pub runtime: RuntimeConfig,
    pub logging: LoggingConfig,
    pub metrics: Option<MetricsConfig>,
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
    pub psk: MethodPsk,
    pub runtime: RuntimeConfig,
    pub replay: ReplayConfig,
    pub logging: LoggingConfig,
    pub metrics: Option<MetricsConfig>,
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
    LoggingLevel,
    MetricsListen,
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
            Self::LoggingLevel => "logging.level",
            Self::MetricsListen => "metrics.listen",
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
    let listen = parse_endpoint(&raw.client.listen, ConfigField::ClientListen)?;
    let server = parse_endpoint(&raw.client.server, ConfigField::ClientServer)?;
    if listen == server {
        return Err(ConfigError::semantic(ConfigField::ClientServer));
    }
    let method = parse_method(&raw.shadowsocks.method)?;
    let psk = parse_psk(method, &raw.shadowsocks.psk)?;
    let runtime = validate_runtime(raw.runtime)?;
    let logging = validate_logging(raw.logging)?;
    let metrics = validate_metrics(raw.metrics, listen)?;
    Ok(ValidatedClientConfig {
        listen,
        server,
        psk,
        runtime,
        logging,
        metrics,
    })
}

fn validate_server(raw: RawServerRoot) -> Result<ValidatedServerConfig, ConfigError> {
    validate_schema(raw.schema_version)?;
    let listen = parse_endpoint(&raw.server.listen, ConfigField::ServerListen)?;
    let method = parse_method(&raw.shadowsocks.method)?;
    let psk = parse_psk(method, &raw.shadowsocks.psk)?;
    let runtime = validate_runtime(raw.runtime)?;
    let replay = validate_replay(raw.replay)?;
    let logging = validate_logging(raw.logging)?;
    let metrics = validate_metrics(raw.metrics, listen)?;
    Ok(ValidatedServerConfig {
        listen,
        psk,
        runtime,
        replay,
        logging,
        metrics,
    })
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
    proxy_listen: SocketAddrV4,
) -> Result<Option<MetricsConfig>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let listen = parse_endpoint(&raw.listen, ConfigField::MetricsListen)?;
    if !listen.ip().is_loopback() || listen == proxy_listen {
        return Err(ConfigError::semantic(ConfigField::MetricsListen));
    }
    Ok(Some(MetricsConfig { listen }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClientRoot {
    schema_version: u32,
    client: RawClient,
    shadowsocks: RawShadowsocks,
    #[serde(default)]
    runtime: RawRuntime,
    #[serde(default)]
    logging: RawLogging,
    metrics: Option<RawMetrics>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServerRoot {
    schema_version: u32,
    server: RawServer,
    shadowsocks: RawShadowsocks,
    #[serde(default)]
    runtime: RawRuntime,
    #[serde(default)]
    replay: RawReplay,
    #[serde(default)]
    logging: RawLogging,
    metrics: Option<RawMetrics>,
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

fn default_logging_level() -> String {
    "info".to_owned()
}
