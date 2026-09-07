use crate::dimension::closed_dimension;

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

closed_dimension! {
    /// Closed inbound protocol labels.
    pub enum Inbound {
        Socks5 => "socks5",
        Shadowsocks => "shadowsocks",
    }
}

closed_dimension! {
    /// Closed byte-flow directions.
    pub enum Direction {
        InboundToOutbound => "inbound_to_outbound",
        OutboundToInbound => "outbound_to_inbound",
        ClientToTarget => "client_to_target",
        TargetToClient => "target_to_client",
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

const CONNECTION_SERIES: usize = Role::ALL.len() * Inbound::ALL.len() * Outcome::ALL.len();
const ACTIVE_SERIES: usize = Role::ALL.len() * Inbound::ALL.len();
const FAILURE_SERIES: usize = Role::ALL.len() * Stage::ALL.len() * Reason::ALL.len();
const BYTE_SERIES: usize = Role::ALL.len() * Direction::ALL.len();
const REPLAY_REJECTION_SERIES: usize = Reason::ALL.len();
const FORCED_SHUTDOWN_SERIES: usize = Role::ALL.len();
const UDP_ROLE_SERIES: usize = Role::ALL.len();
const UDP_DATAGRAM_SERIES: usize = Role::ALL.len() * Direction::ALL.len() * Outcome::ALL.len();
const UDP_REPLAY_SERIES: usize = Role::ALL.len() * Direction::ALL.len() * Reason::ALL.len();
const SNIFF_SERIES: usize =
    Role::ALL.len() * Transport::ALL.len() * SniffOutcome::ALL.len() * SniffProtocol::ALL.len();

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
            Role::ALL,
            Inbound::ALL,
            Outcome::ALL,
            |role, inbound, outcome| ConnectionLabels {
                role,
                inbound,
                outcome,
            },
        ));
        let active = ActiveFamily::new(pair_labels(Role::ALL, Inbound::ALL, |role, inbound| {
            ActiveLabels { role, inbound }
        }));
        let failures = FailureFamily::new(triple_labels(
            Role::ALL,
            Stage::ALL,
            Reason::ALL,
            |role, stage, reason| FailureLabels {
                role,
                stage,
                reason,
            },
        ));
        let bytes = ByteFamily::new(pair_labels(Role::ALL, Direction::ALL, |role, direction| {
            ByteLabels { role, direction }
        }));
        let replay_entries = Gauge::default();
        let replay_rejections = ReplayRejectionFamily::new(single_labels(Reason::ALL, |reason| {
            ReplayRejectionLabels { reason }
        }));
        let forced_shutdowns = ForcedShutdownFamily::new(single_labels(Role::ALL, |role| {
            ForcedShutdownLabels { role }
        }));
        let udp_sessions_active =
            UdpRoleGaugeFamily::new(single_labels(Role::ALL, |role| UdpRoleLabels { role }));
        let udp_datagrams = UdpDatagramFamily::new(triple_labels(
            Role::ALL,
            Direction::ALL,
            Outcome::ALL,
            |role, direction, outcome| UdpDatagramLabels {
                role,
                direction,
                outcome,
            },
        ));
        let udp_failures = FailureFamily::new(triple_labels(
            Role::ALL,
            Stage::ALL,
            Reason::ALL,
            |role, stage, reason| FailureLabels {
                role,
                stage,
                reason,
            },
        ));
        let udp_bytes =
            ByteFamily::new(pair_labels(Role::ALL, Direction::ALL, |role, direction| {
                ByteLabels { role, direction }
            }));
        let udp_buffered_bytes =
            UdpRoleGaugeFamily::new(single_labels(Role::ALL, |role| UdpRoleLabels { role }));
        let udp_replay_rejections = UdpReplayFamily::new(triple_labels(
            Role::ALL,
            Direction::ALL,
            Reason::ALL,
            |role, direction, reason| UdpReplayLabels {
                role,
                direction,
                reason,
            },
        ));
        let udp_forced_shutdown =
            UdpRoleCounterFamily::new(single_labels(Role::ALL, |role| UdpRoleLabels { role }));
        let sniff = SniffFamily::new(quadruple_labels(
            Role::ALL,
            Transport::ALL,
            SniffOutcome::ALL,
            SniffProtocol::ALL,
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
                role.index(),
                inbound.index(),
                outcome.index(),
                Inbound::ALL.len(),
                Outcome::ALL.len(),
            ))
            .inc();
    }

    pub fn active_connections_inc(&self, role: Role, inbound: Inbound) {
        self.core
            .active
            .metric(pair_index(
                role.index(),
                inbound.index(),
                Inbound::ALL.len(),
            ))
            .inc();
    }

    pub fn active_connections_dec(&self, role: Role, inbound: Inbound) {
        self.core
            .active
            .metric(pair_index(
                role.index(),
                inbound.index(),
                Inbound::ALL.len(),
            ))
            .dec();
    }

    pub fn failure(&self, role: Role, stage: Stage, reason: Reason) {
        self.core
            .failures
            .metric(triple_index(
                role.index(),
                stage.index(),
                reason.index(),
                Stage::ALL.len(),
                Reason::ALL.len(),
            ))
            .inc();
    }

    pub fn add_bytes(&self, role: Role, direction: Direction, bytes: u64) {
        self.core
            .bytes
            .metric(pair_index(
                role.index(),
                direction.index(),
                Direction::ALL.len(),
            ))
            .inc_by(bytes);
    }

    pub fn set_replay_entries(&self, entries: u32) {
        self.core.replay_entries.set(i64::from(entries));
    }

    pub fn replay_rejection(&self, reason: Reason) {
        self.core.replay_rejections.metric(reason.index()).inc();
    }

    pub fn forced_shutdown(&self, role: Role) {
        self.core.forced_shutdowns.metric(role.index()).inc();
    }

    pub fn udp_sessions_active_inc(&self, role: Role) {
        self.core.udp_sessions_active.metric(role.index()).inc();
    }

    pub fn udp_sessions_active_dec(&self, role: Role) {
        self.core.udp_sessions_active.metric(role.index()).dec();
    }

    pub fn set_udp_sessions_active(&self, role: Role, sessions: usize) {
        let value = i64::try_from(sessions).unwrap_or(i64::MAX);
        self.core
            .udp_sessions_active
            .metric(role.index())
            .set(value);
    }

    pub fn udp_datagram(&self, role: Role, direction: Direction, outcome: Outcome) {
        self.core
            .udp_datagrams
            .metric(triple_index(
                role.index(),
                direction.index(),
                outcome.index(),
                Direction::ALL.len(),
                Outcome::ALL.len(),
            ))
            .inc();
    }

    pub fn udp_failure(&self, role: Role, stage: Stage, reason: Reason) {
        self.core
            .udp_failures
            .metric(triple_index(
                role.index(),
                stage.index(),
                reason.index(),
                Stage::ALL.len(),
                Reason::ALL.len(),
            ))
            .inc();
    }

    pub fn add_udp_bytes(&self, role: Role, direction: Direction, bytes: u64) {
        self.core
            .udp_bytes
            .metric(pair_index(
                role.index(),
                direction.index(),
                Direction::ALL.len(),
            ))
            .inc_by(bytes);
    }

    pub fn set_udp_buffered_bytes(&self, role: Role, bytes: usize) {
        let value = i64::try_from(bytes).unwrap_or(i64::MAX);
        self.core.udp_buffered_bytes.metric(role.index()).set(value);
    }

    pub fn udp_replay_rejection(&self, role: Role, direction: Direction, reason: Reason) {
        self.core
            .udp_replay_rejections
            .metric(triple_index(
                role.index(),
                direction.index(),
                reason.index(),
                Direction::ALL.len(),
                Reason::ALL.len(),
            ))
            .inc();
    }

    pub fn udp_forced_shutdown(&self, role: Role) {
        self.core.udp_forced_shutdown.metric(role.index()).inc();
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
                role.index(),
                transport.index(),
                outcome.index(),
                protocol.index(),
                Transport::ALL.len(),
                SniffOutcome::ALL.len(),
                SniffProtocol::ALL.len(),
            ))
            .inc();
        emit_sniff(role, transport, outcome, protocol);
    }
}
