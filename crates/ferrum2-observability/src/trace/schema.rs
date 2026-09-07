use crate::dimension::closed_dimension;

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

closed_dimension! {
    /// Process role used by tracing and metrics.
    pub enum Role {
        Client => "client",
        Server => "server",
    }
}

closed_dimension! {
    /// Closed transport categories used by tracing.
    pub enum Transport {
        Tcp => "tcp",
        Udp => "udp",
    }
}

closed_dimension! {
    /// Closed tracing stages.
    pub enum Stage {
        Config => "config",
        Listen => "listen",
        Socks5 => "socks5",
        Shadowsocks => "shadowsocks",
        Sniff => "sniff",
        Direct => "direct",
        Relay => "relay",
        Metrics => "metrics",
        Shutdown => "shutdown",
        Tun => "tun",
    }
}

closed_dimension! {
    /// Closed tracing outcomes.
    pub enum Outcome {
        Accepted => "accepted",
        Completed => "completed",
        Rejected => "rejected",
        Failed => "failed",
        Cancelled => "cancelled",
        Timeout => "timeout",
        Dropped => "dropped",
    }
}

closed_dimension! {
    /// Closed outcomes produced by one authenticated sniff attempt.
    pub enum SniffOutcome {
        Matched => "matched",
        Unknown => "unknown",
        Timeout => "timeout",
        Limit => "limit",
        Invalid => "invalid",
        Unavailable => "unavailable",
    }
}

closed_dimension! {
    /// Closed protocols observable from authenticated, bounded sniffing.
    pub enum SniffProtocol {
        Dns => "dns",
        Tls => "tls",
        Http => "http",
        None => "none",
    }
}

/// Closed event names; callers cannot inject a free-form message.
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

closed_dimension! {
    /// Closed failure reasons shared by tracing and failure metrics.
    pub enum Reason {
        ConfigIo => "config_io",
        ConfigTooLarge => "config_too_large",
        ConfigSyntax => "config_syntax",
        ConfigSemantic => "config_semantic",
        SocksProtocol => "socks_protocol",
        SocksUnsupported => "socks_unsupported",
        Authentication => "authentication",
        InvalidType => "invalid_type",
        TimestampSkew => "timestamp_skew",
        Replay => "replay",
        ReplayCapacity => "replay_capacity",
        FrameBounds => "frame_bounds",
        AddressBounds => "address_bounds",
        ResponseBinding => "response_binding",
        NonceExhausted => "nonce_exhausted",
        RandomUnavailable => "random_unavailable",
        ClockUnavailable => "clock_unavailable",
        HandshakeTimeout => "handshake_timeout",
        ConnectTimeout => "connect_timeout",
        NetworkUnreachable => "network_unreachable",
        HostUnreachable => "host_unreachable",
        ConnectionRefused => "connection_refused",
        RelayIo => "relay_io",
        IdleTimeout => "idle_timeout",
        Cancelled => "cancelled",
        Shutdown => "shutdown",
        ListenerFailure => "listener_failure",
        Bounds => "bounds",
        Type => "type",
        Timestamp => "timestamp",
        Address => "address",
        Padding => "padding",
        Binding => "binding",
        Duplicate => "duplicate",
        TooOld => "too_old",
        SessionLimit => "session_limit",
        BufferLimit => "buffer_limit",
        QueueFull => "queue_full",
        Clock => "clock",
        Random => "random",
        Key => "key",
        Counter => "counter",
        Resolve => "resolve",
        Send => "send",
        Receive => "receive",
        Idle => "idle",
    }
}

closed_dimension! {
    /// Closed reasons for rejecting a packet at the TUN boundary.
    ///
    /// The enum deliberately carries no packet, address, port, adapter, or route
    /// identity, keeping the corresponding metric family bounded.
    pub enum TunPacketRejectReason {
        InvalidIpVersion => "invalid_ip_version",
        FamilyDisabled => "family_disabled",
        InvalidIpLength => "invalid_ip_length",
        InvalidIpChecksum => "invalid_ip_checksum",
        InvalidExtensionHeader => "invalid_extension_header",
        UnsupportedIpProtocol => "unsupported_ip_protocol",
        IcmpEchoUnsupported => "icmp_echo_unsupported",
        FragmentMalformed => "fragment_malformed",
        FragmentOverlap => "fragment_overlap",
        FragmentTimeout => "fragment_timeout",
        FragmentLimit => "fragment_limit",
        InvalidTransportLength => "invalid_transport_length",
        InvalidTransportChecksum => "invalid_transport_checksum",
        InvalidSource => "invalid_source",
        InvalidDestination => "invalid_destination",
        IngressFull => "ingress_full",
        TcpFlowLimit => "tcp_flow_limit",
        UdpAssociationLimit => "udp_association_limit",
        UdpCandidateTimeout => "udp_candidate_timeout",
        UdpQueueFull => "udp_queue_full",
        UdpResponseFiltered => "udp_response_filtered",
        UdpResponseClosed => "udp_response_closed",
        StaleGeneration => "stale_generation",
        WintunRingFull => "wintun_ring_full",
    }
}

closed_dimension! {
    /// Closed reasons why one TUN UDP response became terminal before injection.
    pub enum TunUdpResponseDropReason {
        StaleGeneration => "stale_generation",
        AssociationClosed => "association_closed",
        QueueFull => "queue_full",
        MalformedResponse => "malformed_response",
        Filtered => "filtered",
        InjectionRejected => "injection_rejected",
        SessionReset => "session_reset",
        Shutdown => "shutdown",
        OwnerFatal => "owner_fatal",
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

closed_dimension! {
    pub enum NetworkLifecycleOperation {
        ResetNetwork => "reset_network",
        FullRebuild => "full_rebuild",
    }
}

closed_dimension! {
    /// Closed results for a lightweight reset or managed-plane rebuild attempt.
    pub enum NetworkLifecycleResult {
        Started => "started",
        Succeeded => "succeeded",
        Failed => "failed",
    }
}

closed_dimension! {
    /// Closed reasons for replacing generation-bound runtime state while preserving the managed plane.
    pub enum NetworkResetReason {
        NetworkChange => "network_change",
        Retry => "retry",
    }
}

closed_dimension! {
    /// Closed reasons which permit rebuilding Ferrum2-owned managed network state.
    pub enum NetworkFullRebuildReason {
        AdapterDamage => "adapter_damage",
        SessionDamage => "session_damage",
        AddressDamage => "address_damage",
        RouteDamage => "route_damage",
        DnsDamage => "dns_damage",
        MtuDamage => "mtu_damage",
        StrictRouteDamage => "strict_route_damage",
        OwnershipLedgerDamage => "ownership_ledger_damage",
    }
}

closed_dimension! {
    /// Closed outcomes for installing the effective Windows strict-route filter set.
    pub enum StrictRouteFilterInstallResult {
        Success => "success",
        Failure => "failure",
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

closed_dimension! {
    /// Closed source selected by the shared outbound interface resolver.
    pub enum InterfaceResolutionSource {
        OutboundExplicit => "outbound_explicit",
        AutoDetected => "auto_detected",
        RouteDefault => "route_default",
        SystemBestRoute => "system_best_route",
    }
}

closed_dimension! {
    /// Closed result of one shared outbound interface resolution.
    pub enum InterfaceResolutionResult {
        Success => "success",
        Failure => "failure",
    }
}

closed_dimension! {
    /// Closed result of the single route evaluation for a TUN UDP association.
    pub enum TunUdpAssociationRouteResult {
        Success => "success",
        Rejected => "rejected",
        Failure => "failure",
        StaleGeneration => "stale_generation",
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
