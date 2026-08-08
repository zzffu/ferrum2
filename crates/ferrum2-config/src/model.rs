use std::net::{SocketAddr, SocketAddrV4};
use std::num::NonZeroU16;
use std::time::Duration;

use ferrum2_core::TargetAddr;
use ferrum2_core::route::{
    ActionTable, EgressPlanHandle, Network, OrderedRouteProgram, RouteMetadata, RouteProgramAction,
    RouteProgramEvaluation, RouteTable,
};
use ferrum2_core::selector::SelectorControl;
use ferrum2_crypto::{MethodPsk, TcpMethodProfile};

/// A validated client configuration with no retained source text.
pub struct ValidatedClientConfig {
    pub schema_version: SchemaVersion,
    pub listen: SocketAddrV4,
    pub server: SocketAddrV4,
    pub inbounds: Vec<ClientInboundConfig>,
    pub outbounds: Vec<ClientOutboundConfig>,
    pub route: RouteTable,
    pub route_program: Option<CompiledRoute>,
    pub dns: Option<DnsConfig>,
    pub dns_route: Option<ClientDnsRoute>,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    pub sniff: RouteSniffConfig,
}

impl CompiledRoute {
    /// Starts one private-cursor ordered evaluation.
    pub fn evaluate<'program, 'target>(
        &'program self,
        inbound: usize,
        network: Network,
        original: &'target TargetAddr,
    ) -> RouteProgramEvaluation<'program, 'target, RouteProtocol, RouteAction> {
        self.program.evaluate(inbound, network, original)
    }
}

/// Collision-free client DNS policy ingress identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsIngressId {
    Listener(usize),
    Ordinary(usize),
}

/// Stable closed DNS query types accepted by schema version 2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    pub(super) program: OrderedRouteProgram<DnsQueryType, usize>,
    pub(super) listener_count: usize,
    pub(super) ordinary_count: usize,
}

impl ClientDnsRoute {
    /// Selects one DNS server for a validated client query context.
    ///
    /// An absent query type represents a wire type outside the closed policy vocabulary.
    pub fn select(
        &self,
        ingress: DnsIngressId,
        network: Network,
        target: &TargetAddr,
        qtype: Option<DnsQueryType>,
    ) -> Option<usize> {
        let inbound = match ingress {
            DnsIngressId::Listener(index) if index < self.listener_count => index,
            DnsIngressId::Ordinary(index) if index < self.ordinary_count => {
                self.listener_count + index
            }
            _ => return None,
        };
        let mut evaluation = self.program.evaluate(inbound, network, target);
        match evaluation.next(RouteMetadata::new(qtype, None))? {
            RouteProgramAction::Terminal(server) | RouteProgramAction::Final(server) => {
                Some(*server)
            }
            RouteProgramAction::Continue(_) => unreachable!("DNS actions are terminal"),
        }
    }
}

/// Compiled server application-domain resolution policy.
pub struct ServerDnsRoute {
    pub(super) program: OrderedRouteProgram<(), usize>,
}

impl ServerDnsRoute {
    /// Selects one DNS server for a validated application target.
    pub fn select(&self, inbound: usize, network: Network, target: &TargetAddr) -> usize {
        let mut evaluation = self.program.evaluate(inbound, network, target);
        match evaluation
            .next(RouteMetadata::new(None, None))
            .expect("DNS program has a mandatory final")
        {
            RouteProgramAction::Terminal(server) | RouteProgramAction::Final(server) => *server,
            RouteProgramAction::Continue(_) => unreachable!("DNS actions are terminal"),
        }
    }
}

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
