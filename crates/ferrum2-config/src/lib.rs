#![forbid(unsafe_code)]

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
const DEFAULT_ROUTE_SNIFF_TIMEOUT_MS: u64 = 300;
const DEFAULT_ROUTE_SNIFF_MAX_BYTES: usize = 8_192;

mod error;
mod load;
mod model;
mod raw;
mod validation;

pub use error::{ConfigError, ConfigErrorKind, ConfigField};
pub use load::{load_client, load_server};
pub use model::{
    ClientDnsRoute, ClientInboundConfig, ClientOutboundConfig, CompiledRoute, DnsConfig,
    DnsInboundConfig, DnsIngressId, DnsQueryType, DnsServerConfig, DnsTransport, LoggingConfig,
    LoggingLevel, MetricsConfig, ReplayConfig, RouteAction, RouteProtocol, RouteSniffConfig,
    RuntimeConfig, SchemaVersion, ServerDnsRoute, ServerInboundConfig, ServerOutboundConfig,
    Sniffers, UdpConfig, ValidatedClientConfig, ValidatedServerConfig,
};
