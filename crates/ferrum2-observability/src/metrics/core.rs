use std::fmt;
use std::fmt::Write as _;

use prometheus_client::encoding::{EncodeLabelValue, LabelValueEncoder};
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

use super::Metrics;
use super::family::{
    CachedCounter, CachedGauge, SharedClosedFamily, pair_index, pair_labels, quadruple_index,
    quadruple_labels, single_labels, triple_index, triple_labels,
};
use crate::trace::{
    Outcome, Reason, Role, SniffOutcome, SniffProtocol, Stage, Transport, emit_sniff,
};

/// Closed inbound protocol labels.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Inbound {
    Socks5,
    Shadowsocks,
}

impl Inbound {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::Shadowsocks => "shadowsocks",
        }
    }
}

/// Closed byte-flow directions.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Direction {
    InboundToOutbound,
    OutboundToInbound,
    ClientToTarget,
    TargetToClient,
}

impl Direction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InboundToOutbound => "inbound_to_outbound",
            Self::OutboundToInbound => "outbound_to_inbound",
            Self::ClientToTarget => "client_to_target",
            Self::TargetToClient => "target_to_client",
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

macro_rules! impl_label_value {
    ($type:ty) => {
        impl EncodeLabelValue for $type {
            fn encode(&self, encoder: &mut LabelValueEncoder) -> fmt::Result {
                encoder.write_str(self.as_str())
            }
        }
    };
}

impl_closed_display!(Inbound);
impl_closed_display!(Direction);
impl_label_value!(Role);
impl_label_value!(Transport);
impl_label_value!(Inbound);
impl_label_value!(Outcome);
impl_label_value!(Stage);
impl_label_value!(Reason);
impl_label_value!(Direction);
impl_label_value!(SniffOutcome);
impl_label_value!(SniffProtocol);

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct ConnectionLabels {
    role: Role,
    inbound: Inbound,
    outcome: Outcome,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct ActiveLabels {
    role: Role,
    inbound: Inbound,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct FailureLabels {
    role: Role,
    stage: Stage,
    reason: Reason,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct ByteLabels {
    role: Role,
    direction: Direction,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct ReplayRejectionLabels {
    reason: Reason,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct ForcedShutdownLabels {
    role: Role,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct UdpRoleLabels {
    role: Role,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct UdpDatagramLabels {
    role: Role,
    direction: Direction,
    outcome: Outcome,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct UdpReplayLabels {
    role: Role,
    direction: Direction,
    reason: Reason,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct SniffLabels {
    role: Role,
    transport: Transport,
    stage: Stage,
    outcome: SniffOutcome,
    protocol: SniffProtocol,
}

const ROLES: &[Role] = &[Role::Client, Role::Server];
pub(super) const TRANSPORTS: &[Transport] = &[Transport::Tcp, Transport::Udp];
const INBOUNDS: &[Inbound] = &[Inbound::Socks5, Inbound::Shadowsocks];
const OUTCOMES: &[Outcome] = &[
    Outcome::Accepted,
    Outcome::Completed,
    Outcome::Rejected,
    Outcome::Failed,
    Outcome::Cancelled,
    Outcome::Timeout,
];
const STAGES: &[Stage] = &[
    Stage::Config,
    Stage::Listen,
    Stage::Socks5,
    Stage::Shadowsocks,
    Stage::Sniff,
    Stage::Direct,
    Stage::Relay,
    Stage::Metrics,
    Stage::Shutdown,
];
const REASONS: &[Reason] = &[
    Reason::ConfigIo,
    Reason::ConfigTooLarge,
    Reason::ConfigSyntax,
    Reason::ConfigSemantic,
    Reason::SocksProtocol,
    Reason::SocksUnsupported,
    Reason::Authentication,
    Reason::InvalidType,
    Reason::TimestampSkew,
    Reason::Replay,
    Reason::ReplayCapacity,
    Reason::FrameBounds,
    Reason::AddressBounds,
    Reason::ResponseBinding,
    Reason::NonceExhausted,
    Reason::RandomUnavailable,
    Reason::ClockUnavailable,
    Reason::HandshakeTimeout,
    Reason::ConnectTimeout,
    Reason::NetworkUnreachable,
    Reason::HostUnreachable,
    Reason::ConnectionRefused,
    Reason::RelayIo,
    Reason::IdleTimeout,
    Reason::Cancelled,
    Reason::Shutdown,
    Reason::ListenerFailure,
    Reason::Bounds,
    Reason::Type,
    Reason::Timestamp,
    Reason::Address,
    Reason::Padding,
    Reason::Binding,
    Reason::Duplicate,
    Reason::TooOld,
    Reason::SessionLimit,
    Reason::BufferLimit,
    Reason::QueueFull,
    Reason::Clock,
    Reason::Random,
    Reason::Key,
    Reason::Counter,
    Reason::Resolve,
    Reason::Send,
    Reason::Receive,
    Reason::Idle,
];
const DIRECTIONS: &[Direction] = &[
    Direction::InboundToOutbound,
    Direction::OutboundToInbound,
    Direction::ClientToTarget,
    Direction::TargetToClient,
];
const SNIFF_OUTCOMES: &[SniffOutcome] = &[
    SniffOutcome::Matched,
    SniffOutcome::Unknown,
    SniffOutcome::Timeout,
    SniffOutcome::Limit,
    SniffOutcome::Invalid,
    SniffOutcome::Unavailable,
];
const SNIFF_PROTOCOLS: &[SniffProtocol] = &[
    SniffProtocol::Dns,
    SniffProtocol::Tls,
    SniffProtocol::Http,
    SniffProtocol::None,
];

const CONNECTION_SERIES: usize = ROLES.len() * INBOUNDS.len() * OUTCOMES.len();
const ACTIVE_SERIES: usize = ROLES.len() * INBOUNDS.len();
const FAILURE_SERIES: usize = ROLES.len() * STAGES.len() * REASONS.len();
const BYTE_SERIES: usize = ROLES.len() * DIRECTIONS.len();
const REPLAY_REJECTION_SERIES: usize = REASONS.len();
const FORCED_SHUTDOWN_SERIES: usize = ROLES.len();
const UDP_ROLE_SERIES: usize = ROLES.len();
const UDP_DATAGRAM_SERIES: usize = ROLES.len() * DIRECTIONS.len() * OUTCOMES.len();
const UDP_REPLAY_SERIES: usize = ROLES.len() * DIRECTIONS.len() * REASONS.len();
const SNIFF_SERIES: usize =
    ROLES.len() * TRANSPORTS.len() * SNIFF_OUTCOMES.len() * SNIFF_PROTOCOLS.len();

type ConnectionFamily = SharedClosedFamily<ConnectionLabels, CachedCounter, CONNECTION_SERIES>;
type ActiveFamily = SharedClosedFamily<ActiveLabels, CachedGauge, ACTIVE_SERIES>;
type FailureFamily = SharedClosedFamily<FailureLabels, CachedCounter, FAILURE_SERIES>;
type ByteFamily = SharedClosedFamily<ByteLabels, CachedCounter, BYTE_SERIES>;
type ReplayRejectionFamily =
    SharedClosedFamily<ReplayRejectionLabels, CachedCounter, REPLAY_REJECTION_SERIES>;
type ForcedShutdownFamily =
    SharedClosedFamily<ForcedShutdownLabels, CachedCounter, FORCED_SHUTDOWN_SERIES>;
type UdpRoleGaugeFamily = SharedClosedFamily<UdpRoleLabels, CachedGauge, UDP_ROLE_SERIES>;
type UdpRoleCounterFamily = SharedClosedFamily<UdpRoleLabels, CachedCounter, UDP_ROLE_SERIES>;
type UdpDatagramFamily = SharedClosedFamily<UdpDatagramLabels, CachedCounter, UDP_DATAGRAM_SERIES>;
type UdpReplayFamily = SharedClosedFamily<UdpReplayLabels, CachedCounter, UDP_REPLAY_SERIES>;
type SniffFamily = SharedClosedFamily<SniffLabels, CachedCounter, SNIFF_SERIES>;

pub(super) struct CoreMetrics {
    connections: ConnectionFamily,
    active: ActiveFamily,
    failures: FailureFamily,
    bytes: ByteFamily,
    replay_entries: Gauge,
    replay_rejections: ReplayRejectionFamily,
    forced_shutdowns: ForcedShutdownFamily,
    udp_sessions_active: UdpRoleGaugeFamily,
    udp_datagrams: UdpDatagramFamily,
    udp_failures: FailureFamily,
    udp_bytes: ByteFamily,
    udp_buffered_bytes: UdpRoleGaugeFamily,
    udp_replay_rejections: UdpReplayFamily,
    udp_forced_shutdown: UdpRoleCounterFamily,
    sniff: SniffFamily,
}

impl CoreMetrics {
    pub(super) fn register(registry: &mut Registry) -> Self {
        let connections = ConnectionFamily::new(triple_labels(
            ROLES,
            INBOUNDS,
            OUTCOMES,
            |role, inbound, outcome| ConnectionLabels {
                role,
                inbound,
                outcome,
            },
        ));
        let active = ActiveFamily::new(pair_labels(ROLES, INBOUNDS, |role, inbound| {
            ActiveLabels { role, inbound }
        }));
        let failures = FailureFamily::new(triple_labels(
            ROLES,
            STAGES,
            REASONS,
            |role, stage, reason| FailureLabels {
                role,
                stage,
                reason,
            },
        ));
        let bytes = ByteFamily::new(pair_labels(ROLES, DIRECTIONS, |role, direction| {
            ByteLabels { role, direction }
        }));
        let replay_entries = Gauge::default();
        let replay_rejections = ReplayRejectionFamily::new(single_labels(REASONS, |reason| {
            ReplayRejectionLabels { reason }
        }));
        let forced_shutdowns =
            ForcedShutdownFamily::new(single_labels(ROLES, |role| ForcedShutdownLabels { role }));
        let udp_sessions_active =
            UdpRoleGaugeFamily::new(single_labels(ROLES, |role| UdpRoleLabels { role }));
        let udp_datagrams = UdpDatagramFamily::new(triple_labels(
            ROLES,
            DIRECTIONS,
            OUTCOMES,
            |role, direction, outcome| UdpDatagramLabels {
                role,
                direction,
                outcome,
            },
        ));
        let udp_failures = FailureFamily::new(triple_labels(
            ROLES,
            STAGES,
            REASONS,
            |role, stage, reason| FailureLabels {
                role,
                stage,
                reason,
            },
        ));
        let udp_bytes = ByteFamily::new(pair_labels(ROLES, DIRECTIONS, |role, direction| {
            ByteLabels { role, direction }
        }));
        let udp_buffered_bytes =
            UdpRoleGaugeFamily::new(single_labels(ROLES, |role| UdpRoleLabels { role }));
        let udp_replay_rejections = UdpReplayFamily::new(triple_labels(
            ROLES,
            DIRECTIONS,
            REASONS,
            |role, direction, reason| UdpReplayLabels {
                role,
                direction,
                reason,
            },
        ));
        let udp_forced_shutdown =
            UdpRoleCounterFamily::new(single_labels(ROLES, |role| UdpRoleLabels { role }));
        let sniff = SniffFamily::new(quadruple_labels(
            ROLES,
            TRANSPORTS,
            SNIFF_OUTCOMES,
            SNIFF_PROTOCOLS,
            |role, transport, outcome, protocol| SniffLabels {
                role,
                transport,
                stage: Stage::Sniff,
                outcome,
                protocol,
            },
        ));
        registry.register(
            "ferrum2_tcp_connections",
            "TCP connection outcomes",
            connections.clone(),
        );
        registry.register(
            "ferrum2_tcp_connections_active",
            "Active TCP connections",
            active.clone(),
        );
        registry.register(
            "ferrum2_tcp_failures",
            "Closed TCP failure categories",
            failures.clone(),
        );
        registry.register(
            "ferrum2_tcp_bytes",
            "Authenticated application bytes forwarded",
            bytes.clone(),
        );
        registry.register(
            "ferrum2_tcp_replay_entries",
            "Current exact TCP replay entries",
            replay_entries.clone(),
        );
        registry.register(
            "ferrum2_tcp_replay_rejections",
            "TCP replay-related rejections",
            replay_rejections.clone(),
        );
        registry.register(
            "ferrum2_tcp_forced_shutdown",
            "TCP flows terminated at shutdown deadline",
            forced_shutdowns.clone(),
        );
        registry.register(
            "ferrum2_udp_sessions_active",
            "Active bounded UDP sessions",
            udp_sessions_active.clone(),
        );
        registry.register(
            "ferrum2_udp_datagrams",
            "UDP datagram outcomes",
            udp_datagrams.clone(),
        );
        registry.register(
            "ferrum2_udp_failures",
            "Closed UDP failure categories",
            udp_failures.clone(),
        );
        registry.register(
            "ferrum2_udp_bytes",
            "Authenticated UDP application bytes forwarded",
            udp_bytes.clone(),
        );
        registry.register(
            "ferrum2_udp_buffered_bytes",
            "Allocated user-space UDP bytes",
            udp_buffered_bytes.clone(),
        );
        registry.register(
            "ferrum2_udp_replay_rejections",
            "UDP replay-related rejections",
            udp_replay_rejections.clone(),
        );
        registry.register(
            "ferrum2_udp_forced_shutdown",
            "UDP sessions terminated at shutdown deadline",
            udp_forced_shutdown.clone(),
        );
        registry.register(
            "ferrum2_sniff",
            "Authenticated bounded sniff outcomes",
            sniff.clone(),
        );
        Self {
            connections,
            active,
            failures,
            bytes,
            replay_entries,
            replay_rejections,
            forced_shutdowns,
            udp_sessions_active,
            udp_datagrams,
            udp_failures,
            udp_bytes,
            udp_buffered_bytes,
            udp_replay_rejections,
            udp_forced_shutdown,
            sniff,
        }
    }
}

impl Metrics {
    pub fn connection(&self, role: Role, inbound: Inbound, outcome: Outcome) {
        self.core
            .connections
            .metric(triple_index(
                role as usize,
                inbound as usize,
                outcome as usize,
                INBOUNDS.len(),
                OUTCOMES.len(),
            ))
            .inc();
    }

    pub fn active_connections_inc(&self, role: Role, inbound: Inbound) {
        self.core
            .active
            .metric(pair_index(role as usize, inbound as usize, INBOUNDS.len()))
            .inc();
    }

    pub fn active_connections_dec(&self, role: Role, inbound: Inbound) {
        self.core
            .active
            .metric(pair_index(role as usize, inbound as usize, INBOUNDS.len()))
            .dec();
    }

    pub fn failure(&self, role: Role, stage: Stage, reason: Reason) {
        self.core
            .failures
            .metric(triple_index(
                role as usize,
                stage as usize,
                reason as usize,
                STAGES.len(),
                REASONS.len(),
            ))
            .inc();
    }

    pub fn add_bytes(&self, role: Role, direction: Direction, bytes: u64) {
        self.core
            .bytes
            .metric(pair_index(
                role as usize,
                direction as usize,
                DIRECTIONS.len(),
            ))
            .inc_by(bytes);
    }

    pub fn set_replay_entries(&self, entries: u32) {
        self.core.replay_entries.set(i64::from(entries));
    }

    pub fn replay_rejection(&self, reason: Reason) {
        self.core.replay_rejections.metric(reason as usize).inc();
    }

    pub fn forced_shutdown(&self, role: Role) {
        self.core.forced_shutdowns.metric(role as usize).inc();
    }

    pub fn udp_sessions_active_inc(&self, role: Role) {
        self.core.udp_sessions_active.metric(role as usize).inc();
    }

    pub fn udp_sessions_active_dec(&self, role: Role) {
        self.core.udp_sessions_active.metric(role as usize).dec();
    }

    pub fn set_udp_sessions_active(&self, role: Role, sessions: usize) {
        let value = i64::try_from(sessions).unwrap_or(i64::MAX);
        self.core
            .udp_sessions_active
            .metric(role as usize)
            .set(value);
    }

    pub fn udp_datagram(&self, role: Role, direction: Direction, outcome: Outcome) {
        self.core
            .udp_datagrams
            .metric(triple_index(
                role as usize,
                direction as usize,
                outcome as usize,
                DIRECTIONS.len(),
                OUTCOMES.len(),
            ))
            .inc();
    }

    pub fn udp_failure(&self, role: Role, stage: Stage, reason: Reason) {
        self.core
            .udp_failures
            .metric(triple_index(
                role as usize,
                stage as usize,
                reason as usize,
                STAGES.len(),
                REASONS.len(),
            ))
            .inc();
    }

    pub fn add_udp_bytes(&self, role: Role, direction: Direction, bytes: u64) {
        self.core
            .udp_bytes
            .metric(pair_index(
                role as usize,
                direction as usize,
                DIRECTIONS.len(),
            ))
            .inc_by(bytes);
    }

    pub fn set_udp_buffered_bytes(&self, role: Role, bytes: usize) {
        let value = i64::try_from(bytes).unwrap_or(i64::MAX);
        self.core
            .udp_buffered_bytes
            .metric(role as usize)
            .set(value);
    }

    pub fn udp_replay_rejection(&self, role: Role, direction: Direction, reason: Reason) {
        self.core
            .udp_replay_rejections
            .metric(triple_index(
                role as usize,
                direction as usize,
                reason as usize,
                DIRECTIONS.len(),
                REASONS.len(),
            ))
            .inc();
    }

    pub fn udp_forced_shutdown(&self, role: Role) {
        self.core.udp_forced_shutdown.metric(role as usize).inc();
    }

    /// Records and traces exactly one closed tuple for an authenticated sniff.
    pub fn sniff(
        &self,
        role: Role,
        transport: Transport,
        outcome: SniffOutcome,
        protocol: SniffProtocol,
    ) {
        self.core
            .sniff
            .metric(quadruple_index(
                role as usize,
                transport as usize,
                outcome as usize,
                protocol as usize,
                TRANSPORTS.len(),
                SNIFF_OUTCOMES.len(),
                SNIFF_PROTOCOLS.len(),
            ))
            .inc();
        emit_sniff(role, transport, outcome, protocol);
    }
}
