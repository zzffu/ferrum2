use std::net::{SocketAddr, SocketAddrV4};
use std::num::NonZeroU16;
use std::time::Duration;

use ferrum2_core::route::{ActionTable, EgressPlanHandle, RouteTable};
use ferrum2_core::selector::SelectorControl;
use ferrum2_crypto::{MethodPsk, TcpMethodProfile};

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
