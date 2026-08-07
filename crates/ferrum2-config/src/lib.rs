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

mod error;
mod load;
mod model;
mod raw;
mod validation;

pub use error::{ConfigError, ConfigErrorKind, ConfigField};
pub use load::{load_client, load_server};
pub use model::{
    ClientInboundConfig, ClientOutboundConfig, DnsConfig, DnsInboundConfig, DnsServerConfig,
    DnsTransport, LoggingConfig, LoggingLevel, MetricsConfig, ReplayConfig, RuntimeConfig,
    ServerInboundConfig, ServerOutboundConfig, UdpConfig, ValidatedClientConfig,
    ValidatedServerConfig,
};
