use std::fmt;

use tracing::Level;

/// Closed severity levels accepted by the tracing boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub(super) fn enables(self, level: &Level) -> bool {
        match self {
            Self::Error => *level == Level::ERROR,
            Self::Warn => matches!(*level, Level::ERROR | Level::WARN),
            Self::Info => matches!(*level, Level::ERROR | Level::WARN | Level::INFO),
            Self::Debug => {
                matches!(
                    *level,
                    Level::ERROR | Level::WARN | Level::INFO | Level::DEBUG
                )
            }
            Self::Trace => true,
        }
    }
}

/// Process role used by tracing and metrics.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

/// Closed transport categories used by tracing.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Closed tracing stages.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Stage {
    Config,
    Listen,
    Socks5,
    Shadowsocks,
    Sniff,
    Direct,
    Relay,
    Metrics,
    Shutdown,
    Tun,
}

impl Stage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Listen => "listen",
            Self::Socks5 => "socks5",
            Self::Shadowsocks => "shadowsocks",
            Self::Sniff => "sniff",
            Self::Direct => "direct",
            Self::Relay => "relay",
            Self::Metrics => "metrics",
            Self::Shutdown => "shutdown",
            Self::Tun => "tun",
        }
    }
}

/// Closed tracing outcomes.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Outcome {
    Accepted,
    Completed,
    Rejected,
    Failed,
    Cancelled,
    Timeout,
    Dropped,
}

impl Outcome {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Completed => "completed",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
            Self::Dropped => "dropped",
        }
    }
}

/// Closed outcomes produced by one authenticated sniff attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SniffOutcome {
    Matched,
    Unknown,
    Timeout,
    Limit,
    Invalid,
    Unavailable,
}

impl SniffOutcome {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Unknown => "unknown",
            Self::Timeout => "timeout",
            Self::Limit => "limit",
            Self::Invalid => "invalid",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Closed protocols observable from authenticated, bounded sniffing.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SniffProtocol {
    Dns,
    Tls,
    Http,
    None,
}

impl SniffProtocol {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Tls => "tls",
            Self::Http => "http",
            Self::None => "none",
        }
    }
}

/// Closed event names; callers cannot inject a free-form message.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    Config,
    Connection,
    Failure,
    BytesForwarded,
    Replay,
    Lifecycle,
    ForcedShutdown,
    Sniff,
    Tun,
}

impl Event {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Connection => "connection",
            Self::Failure => "failure",
            Self::BytesForwarded => "bytes_forwarded",
            Self::Replay => "replay",
            Self::Lifecycle => "lifecycle",
            Self::ForcedShutdown => "forced_shutdown",
            Self::Sniff => "sniff",
            Self::Tun => "tun",
        }
    }
}

/// Closed address-family label for TUN diagnostics.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TunIpFamily {
    Ipv4,
    Ipv6,
}

impl TunIpFamily {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

/// Closed reasons for TUN events which require a structured diagnostic log.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TunDiagnosticReason {
    WintunRingFull,
}

impl TunDiagnosticReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::WintunRingFull => "wintun_ring_full",
        }
    }

    pub(super) const fn outcome(self) -> Outcome {
        match self {
            Self::WintunRingFull => Outcome::Dropped,
        }
    }
}

/// Closed failure reasons shared by tracing and failure metrics.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Reason {
    ConfigIo,
    ConfigTooLarge,
    ConfigSyntax,
    ConfigSemantic,
    SocksProtocol,
    SocksUnsupported,
    Authentication,
    InvalidType,
    TimestampSkew,
    Replay,
    ReplayCapacity,
    FrameBounds,
    AddressBounds,
    ResponseBinding,
    NonceExhausted,
    RandomUnavailable,
    ClockUnavailable,
    HandshakeTimeout,
    ConnectTimeout,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    RelayIo,
    IdleTimeout,
    Cancelled,
    Shutdown,
    ListenerFailure,
    Bounds,
    Type,
    Timestamp,
    Address,
    Padding,
    Binding,
    Duplicate,
    TooOld,
    SessionLimit,
    BufferLimit,
    QueueFull,
    Clock,
    Random,
    Key,
    Counter,
    Resolve,
    Send,
    Receive,
    Idle,
}

impl Reason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ConfigIo => "config_io",
            Self::ConfigTooLarge => "config_too_large",
            Self::ConfigSyntax => "config_syntax",
            Self::ConfigSemantic => "config_semantic",
            Self::SocksProtocol => "socks_protocol",
            Self::SocksUnsupported => "socks_unsupported",
            Self::Authentication => "authentication",
            Self::InvalidType => "invalid_type",
            Self::TimestampSkew => "timestamp_skew",
            Self::Replay => "replay",
            Self::ReplayCapacity => "replay_capacity",
            Self::FrameBounds => "frame_bounds",
            Self::AddressBounds => "address_bounds",
            Self::ResponseBinding => "response_binding",
            Self::NonceExhausted => "nonce_exhausted",
            Self::RandomUnavailable => "random_unavailable",
            Self::ClockUnavailable => "clock_unavailable",
            Self::HandshakeTimeout => "handshake_timeout",
            Self::ConnectTimeout => "connect_timeout",
            Self::NetworkUnreachable => "network_unreachable",
            Self::HostUnreachable => "host_unreachable",
            Self::ConnectionRefused => "connection_refused",
            Self::RelayIo => "relay_io",
            Self::IdleTimeout => "idle_timeout",
            Self::Cancelled => "cancelled",
            Self::Shutdown => "shutdown",
            Self::ListenerFailure => "listener_failure",
            Self::Bounds => "bounds",
            Self::Type => "type",
            Self::Timestamp => "timestamp",
            Self::Address => "address",
            Self::Padding => "padding",
            Self::Binding => "binding",
            Self::Duplicate => "duplicate",
            Self::TooOld => "too_old",
            Self::SessionLimit => "session_limit",
            Self::BufferLimit => "buffer_limit",
            Self::QueueFull => "queue_full",
            Self::Clock => "clock",
            Self::Random => "random",
            Self::Key => "key",
            Self::Counter => "counter",
            Self::Resolve => "resolve",
            Self::Send => "send",
            Self::Receive => "receive",
            Self::Idle => "idle",
        }
    }
}

/// Closed reasons for rejecting a packet at the TUN boundary.
///
/// The enum deliberately carries no packet, address, port, adapter, or route
/// identity, keeping the corresponding metric family bounded.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TunPacketRejectReason {
    InvalidIpVersion,
    FamilyDisabled,
    InvalidIpLength,
    InvalidIpChecksum,
    InvalidExtensionHeader,
    UnsupportedIpProtocol,
    IcmpEchoUnsupported,
    FragmentMalformed,
    FragmentOverlap,
    FragmentTimeout,
    FragmentLimit,
    InvalidTransportLength,
    InvalidTransportChecksum,
    InvalidSource,
    InvalidDestination,
    IngressFull,
    TcpFlowLimit,
    UdpAssociationLimit,
    UdpCandidateTimeout,
    UdpQueueFull,
    UdpResponseFiltered,
    UdpResponseClosed,
    StaleGeneration,
    WintunRingFull,
}

impl TunPacketRejectReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidIpVersion => "invalid_ip_version",
            Self::FamilyDisabled => "family_disabled",
            Self::InvalidIpLength => "invalid_ip_length",
            Self::InvalidIpChecksum => "invalid_ip_checksum",
            Self::InvalidExtensionHeader => "invalid_extension_header",
            Self::UnsupportedIpProtocol => "unsupported_ip_protocol",
            Self::IcmpEchoUnsupported => "icmp_echo_unsupported",
            Self::FragmentMalformed => "fragment_malformed",
            Self::FragmentOverlap => "fragment_overlap",
            Self::FragmentTimeout => "fragment_timeout",
            Self::FragmentLimit => "fragment_limit",
            Self::InvalidTransportLength => "invalid_transport_length",
            Self::InvalidTransportChecksum => "invalid_transport_checksum",
            Self::InvalidSource => "invalid_source",
            Self::InvalidDestination => "invalid_destination",
            Self::IngressFull => "ingress_full",
            Self::TcpFlowLimit => "tcp_flow_limit",
            Self::UdpAssociationLimit => "udp_association_limit",
            Self::UdpCandidateTimeout => "udp_candidate_timeout",
            Self::UdpQueueFull => "udp_queue_full",
            Self::UdpResponseFiltered => "udp_response_filtered",
            Self::UdpResponseClosed => "udp_response_closed",
            Self::StaleGeneration => "stale_generation",
            Self::WintunRingFull => "wintun_ring_full",
        }
    }
}

/// Closed reasons why one TUN UDP response became terminal before injection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TunUdpResponseDropReason {
    StaleGeneration,
    AssociationClosed,
    QueueFull,
    MalformedResponse,
    Filtered,
    InjectionRejected,
    SessionReset,
    Shutdown,
    OwnerFatal,
}

impl TunUdpResponseDropReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::StaleGeneration => "stale_generation",
            Self::AssociationClosed => "association_closed",
            Self::QueueFull => "queue_full",
            Self::MalformedResponse => "malformed_response",
            Self::Filtered => "filtered",
            Self::InjectionRejected => "injection_rejected",
            Self::SessionReset => "session_reset",
            Self::Shutdown => "shutdown",
            Self::OwnerFatal => "owner_fatal",
        }
    }
}

macro_rules! impl_closed_display {
    ($type:ty) => {
        impl fmt::Display for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

impl_closed_display!(Role);
impl_closed_display!(Transport);
impl_closed_display!(Stage);
impl_closed_display!(Outcome);
impl_closed_display!(Event);
impl_closed_display!(Reason);
impl_closed_display!(SniffOutcome);
impl_closed_display!(SniffProtocol);
impl_closed_display!(TunPacketRejectReason);
impl_closed_display!(TunIpFamily);
impl_closed_display!(TunDiagnosticReason);

/// One structured event containing only approved closed fields and numeric values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceRecord {
    pub(super) level: LogLevel,
    pub(super) event: Event,
    pub(super) role: Role,
    pub(super) transport: Transport,
    pub(super) stage: Stage,
    pub(super) outcome: Outcome,
    pub(super) reason: Option<Reason>,
    pub(super) session_id: Option<u64>,
    pub(super) duration_ms: Option<u64>,
    pub(super) bytes: Option<u64>,
}

impl TraceRecord {
    pub const fn new(
        level: LogLevel,
        event: Event,
        role: Role,
        stage: Stage,
        outcome: Outcome,
    ) -> Self {
        Self {
            level,
            event,
            role,
            transport: Transport::Tcp,
            stage,
            outcome,
            reason: None,
            session_id: None,
            duration_ms: None,
            bytes: None,
        }
    }

    pub const fn with_reason(mut self, reason: Reason) -> Self {
        self.reason = Some(reason);
        self
    }

    /// Selects the UDP transport without admitting a free-form field.
    pub const fn udp(mut self) -> Self {
        self.transport = Transport::Udp;
        self
    }

    pub const fn with_session_id(mut self, session_id: u64) -> Self {
        self.session_id = Some(session_id);
        self
    }

    pub const fn with_duration_ms(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    pub const fn with_bytes(mut self, bytes: u64) -> Self {
        self.bytes = Some(bytes);
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NetworkLifecycleOperation {
    ResetNetwork,
    FullRebuild,
}

impl NetworkLifecycleOperation {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ResetNetwork => "reset_network",
            Self::FullRebuild => "full_rebuild",
        }
    }
}

/// Closed results for a lightweight reset or managed-plane rebuild attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NetworkLifecycleResult {
    Started,
    Succeeded,
    Failed,
}

impl NetworkLifecycleResult {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

/// Closed reasons for replacing generation-bound runtime state while preserving the managed plane.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NetworkResetReason {
    NetworkChange,
    Retry,
}

impl NetworkResetReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NetworkChange => "network_change",
            Self::Retry => "retry",
        }
    }
}

/// Closed reasons which permit rebuilding Ferrum2-owned managed network state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NetworkFullRebuildReason {
    AdapterDamage,
    SessionDamage,
    AddressDamage,
    RouteDamage,
    DnsDamage,
    StrictRouteDamage,
    OwnershipLedgerDamage,
}

impl NetworkFullRebuildReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AdapterDamage => "adapter_damage",
            Self::SessionDamage => "session_damage",
            Self::AddressDamage => "address_damage",
            Self::RouteDamage => "route_damage",
            Self::DnsDamage => "dns_damage",
            Self::StrictRouteDamage => "strict_route_damage",
            Self::OwnershipLedgerDamage => "ownership_ledger_damage",
        }
    }
}

/// Closed outcomes for installing the effective Windows strict-route filter set.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StrictRouteFilterInstallResult {
    Success,
    Failure,
}

impl StrictRouteFilterInstallResult {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

/// Closed startup/runtime strict-route states safe for diagnostic traces.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StrictRouteDiagnosticStatus {
    NotRequested,
    RequestedIneffective,
    Installed,
    InstallFailed,
}

impl StrictRouteDiagnosticStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NotRequested => "not_requested",
            Self::RequestedIneffective => "requested_ineffective",
            Self::Installed => "installed",
            Self::InstallFailed => "install_failed",
        }
    }

    pub(super) const fn requested(self) -> bool {
        !matches!(self, Self::NotRequested)
    }

    pub(super) const fn effective(self) -> bool {
        matches!(self, Self::Installed | Self::InstallFailed)
    }
}

/// Closed source selected by the shared outbound interface resolver.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InterfaceResolutionSource {
    OutboundExplicit,
    AutoDetected,
    RouteDefault,
    SystemBestRoute,
}

impl InterfaceResolutionSource {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::OutboundExplicit => "outbound_explicit",
            Self::AutoDetected => "auto_detected",
            Self::RouteDefault => "route_default",
            Self::SystemBestRoute => "system_best_route",
        }
    }
}

/// Closed result of one shared outbound interface resolution.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InterfaceResolutionResult {
    Success,
    Failure,
}

impl InterfaceResolutionResult {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

/// Closed result of the single route evaluation for a TUN UDP association.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TunUdpAssociationRouteResult {
    Success,
    Rejected,
    Failure,
    StaleGeneration,
}

impl TunUdpAssociationRouteResult {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Rejected => "rejected",
            Self::Failure => "failure",
            Self::StaleGeneration => "stale_generation",
        }
    }
}

impl_closed_display!(TunUdpResponseDropReason);
impl_closed_display!(NetworkLifecycleOperation);
impl_closed_display!(NetworkLifecycleResult);
impl_closed_display!(NetworkResetReason);
impl_closed_display!(NetworkFullRebuildReason);
impl_closed_display!(StrictRouteFilterInstallResult);
impl_closed_display!(StrictRouteDiagnosticStatus);
impl_closed_display!(InterfaceResolutionSource);
impl_closed_display!(InterfaceResolutionResult);
impl_closed_display!(TunUdpAssociationRouteResult);
