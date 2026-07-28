#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::fmt::Write as _;

use prometheus_client::encoding::{EncodeLabelValue, LabelValueEncoder, text};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use tracing::{Level, Metadata};
use tracing_subscriber::Layer as _;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt as _;

const CLOSED_TRACE_TARGET: &str = "ferrum2_observability::closed";
const CLOSED_TRACE_MODULE: &str = module_path!();
const TRACE_FIELDS: &[&str] = &[
    "event",
    "role",
    "transport",
    "stage",
    "outcome",
    "session_id",
    "duration_ms",
    "bytes",
];
const TRACE_FIELDS_WITH_REASON: &[&str] = &[
    "event",
    "role",
    "transport",
    "stage",
    "outcome",
    "reason",
    "session_id",
    "duration_ms",
    "bytes",
];

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
    fn enables(self, level: &Level) -> bool {
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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

/// The only M0 transport.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Closed tracing stages.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Stage {
    Config,
    Listen,
    Socks5,
    Shadowsocks,
    Direct,
    Relay,
    Metrics,
    Shutdown,
}

impl Stage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Listen => "listen",
            Self::Socks5 => "socks5",
            Self::Shadowsocks => "shadowsocks",
            Self::Direct => "direct",
            Self::Relay => "relay",
            Self::Metrics => "metrics",
            Self::Shutdown => "shutdown",
        }
    }
}

/// Closed tracing outcomes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Outcome {
    Accepted,
    Completed,
    Rejected,
    Failed,
    Cancelled,
    Timeout,
}

impl Outcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Completed => "completed",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
        }
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
}

impl Event {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Connection => "connection",
            Self::Failure => "failure",
            Self::BytesForwarded => "bytes_forwarded",
            Self::Replay => "replay",
            Self::Lifecycle => "lifecycle",
            Self::ForcedShutdown => "forced_shutdown",
        }
    }
}

/// Closed failure reasons shared by tracing and failure metrics.
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
    const fn as_str(self) -> &'static str {
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

/// One structured event containing only approved closed fields and numeric values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceRecord {
    level: LogLevel,
    event: Event,
    role: Role,
    transport: Transport,
    stage: Stage,
    outcome: Outcome,
    reason: Option<Reason>,
    session_id: Option<u64>,
    duration_ms: Option<u64>,
    bytes: Option<u64>,
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

/// Builds a caller-owned newline JSON subscriber without installing it globally.
pub fn json_subscriber<W>(writer: W, max_level: LogLevel) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let filter = filter_fn(move |metadata| approved_trace_metadata(metadata, max_level));
    let format = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(writer)
        .with_ansi(false)
        .with_target(false)
        .with_file(false)
        .with_line_number(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_filter(filter);
    tracing_subscriber::registry().with(format)
}

fn approved_trace_metadata(metadata: &Metadata<'_>, max_level: LogLevel) -> bool {
    metadata.is_event()
        && metadata.target() == CLOSED_TRACE_TARGET
        && metadata.module_path() == Some(CLOSED_TRACE_MODULE)
        && max_level.enables(metadata.level())
        && (has_exact_fields(metadata, TRACE_FIELDS)
            || has_exact_fields(metadata, TRACE_FIELDS_WITH_REASON))
}

fn has_exact_fields(metadata: &Metadata<'_>, expected: &[&str]) -> bool {
    let fields = metadata.fields();
    fields.len() == expected.len() && expected.iter().all(|name| fields.field(name).is_some())
}

macro_rules! emit_at {
    ($level:expr, $record:ident) => {
        if let Some(reason) = $record.reason {
            tracing::event!(
                target: CLOSED_TRACE_TARGET,
                $level,
                event = %$record.event,
                role = %$record.role,
                transport = %$record.transport,
                stage = %$record.stage,
                outcome = %$record.outcome,
                reason = %reason,
                session_id = $record.session_id,
                duration_ms = $record.duration_ms,
                bytes = $record.bytes,
            );
        } else {
            tracing::event!(
                target: CLOSED_TRACE_TARGET,
                $level,
                event = %$record.event,
                role = %$record.role,
                transport = %$record.transport,
                stage = %$record.stage,
                outcome = %$record.outcome,
                session_id = $record.session_id,
                duration_ms = $record.duration_ms,
                bytes = $record.bytes,
            );
        }
    };
}

/// Emits one approved trace record through the current caller-selected dispatcher.
pub fn emit(record: TraceRecord) {
    match record.level {
        LogLevel::Error => emit_at!(Level::ERROR, record),
        LogLevel::Warn => emit_at!(Level::WARN, record),
        LogLevel::Info => emit_at!(Level::INFO, record),
        LogLevel::Debug => emit_at!(Level::DEBUG, record),
        LogLevel::Trace => emit_at!(Level::TRACE, record),
    }
}

/// Closed inbound protocol labels.
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

impl_closed_display!(Inbound);
impl_closed_display!(Direction);

macro_rules! impl_label_value {
    ($type:ty) => {
        impl EncodeLabelValue for $type {
            fn encode(&self, encoder: &mut LabelValueEncoder) -> fmt::Result {
                encoder.write_str(self.as_str())
            }
        }
    };
}

impl_label_value!(Role);
impl_label_value!(Inbound);
impl_label_value!(Outcome);
impl_label_value!(Stage);
impl_label_value!(Reason);
impl_label_value!(Direction);

#[derive(Clone, Debug, Eq, Hash, PartialEq, prometheus_client::encoding::EncodeLabelSet)]
struct ConnectionLabels {
    role: Role,
    inbound: Inbound,
    outcome: Outcome,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, prometheus_client::encoding::EncodeLabelSet)]
struct ActiveLabels {
    role: Role,
    inbound: Inbound,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, prometheus_client::encoding::EncodeLabelSet)]
struct FailureLabels {
    role: Role,
    stage: Stage,
    reason: Reason,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, prometheus_client::encoding::EncodeLabelSet)]
struct ByteLabels {
    role: Role,
    direction: Direction,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, prometheus_client::encoding::EncodeLabelSet)]
struct ReplayRejectionLabels {
    reason: Reason,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, prometheus_client::encoding::EncodeLabelSet)]
struct ForcedShutdownLabels {
    role: Role,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, prometheus_client::encoding::EncodeLabelSet)]
struct UdpRoleLabels {
    role: Role,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, prometheus_client::encoding::EncodeLabelSet)]
struct UdpDatagramLabels {
    role: Role,
    direction: Direction,
    outcome: Outcome,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, prometheus_client::encoding::EncodeLabelSet)]
struct UdpReplayLabels {
    role: Role,
    direction: Direction,
    reason: Reason,
}

type ConnectionFamily = Family<ConnectionLabels, Counter>;
type ActiveFamily = Family<ActiveLabels, Gauge>;
type FailureFamily = Family<FailureLabels, Counter>;
type ByteFamily = Family<ByteLabels, Counter>;
type ReplayRejectionFamily = Family<ReplayRejectionLabels, Counter>;
type ForcedShutdownFamily = Family<ForcedShutdownLabels, Counter>;
type UdpRoleGaugeFamily = Family<UdpRoleLabels, Gauge>;
type UdpRoleCounterFamily = Family<UdpRoleLabels, Counter>;
type UdpDatagramFamily = Family<UdpDatagramLabels, Counter>;
type UdpReplayFamily = Family<UdpReplayLabels, Counter>;

/// Explicit owner of the seven stable TCP and seven stable UDP metric families.
///
/// This type installs no global recorder and starts no listener or task.
pub struct Metrics {
    registry: Registry,
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
}

impl Metrics {
    /// Creates an isolated registry containing exactly the fourteen approved families.
    pub fn new() -> Self {
        let connections = ConnectionFamily::default();
        let active = ActiveFamily::default();
        let failures = FailureFamily::default();
        let bytes = ByteFamily::default();
        let replay_entries = Gauge::default();
        let replay_rejections = ReplayRejectionFamily::default();
        let forced_shutdowns = ForcedShutdownFamily::default();
        let udp_sessions_active = UdpRoleGaugeFamily::default();
        let udp_datagrams = UdpDatagramFamily::default();
        let udp_failures = FailureFamily::default();
        let udp_bytes = ByteFamily::default();
        let udp_buffered_bytes = UdpRoleGaugeFamily::default();
        let udp_replay_rejections = UdpReplayFamily::default();
        let udp_forced_shutdown = UdpRoleCounterFamily::default();

        let mut registry = Registry::default();
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

        Self {
            registry,
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
        }
    }

    pub fn connection(&self, role: Role, inbound: Inbound, outcome: Outcome) {
        self.connections
            .get_or_create(&ConnectionLabels {
                role,
                inbound,
                outcome,
            })
            .inc();
    }

    pub fn active_connections_inc(&self, role: Role, inbound: Inbound) {
        self.active
            .get_or_create(&ActiveLabels { role, inbound })
            .inc();
    }

    pub fn active_connections_dec(&self, role: Role, inbound: Inbound) {
        self.active
            .get_or_create(&ActiveLabels { role, inbound })
            .dec();
    }

    pub fn failure(&self, role: Role, stage: Stage, reason: Reason) {
        self.failures
            .get_or_create(&FailureLabels {
                role,
                stage,
                reason,
            })
            .inc();
    }

    pub fn add_bytes(&self, role: Role, direction: Direction, bytes: u64) {
        self.bytes
            .get_or_create(&ByteLabels { role, direction })
            .inc_by(bytes);
    }

    pub fn set_replay_entries(&self, entries: u32) {
        self.replay_entries.set(i64::from(entries));
    }

    pub fn replay_rejection(&self, reason: Reason) {
        self.replay_rejections
            .get_or_create(&ReplayRejectionLabels { reason })
            .inc();
    }

    pub fn forced_shutdown(&self, role: Role) {
        self.forced_shutdowns
            .get_or_create(&ForcedShutdownLabels { role })
            .inc();
    }

    pub fn udp_sessions_active_inc(&self, role: Role) {
        self.udp_sessions_active
            .get_or_create(&UdpRoleLabels { role })
            .inc();
    }

    pub fn udp_sessions_active_dec(&self, role: Role) {
        self.udp_sessions_active
            .get_or_create(&UdpRoleLabels { role })
            .dec();
    }

    pub fn set_udp_sessions_active(&self, role: Role, sessions: usize) {
        let value = i64::try_from(sessions).unwrap_or(i64::MAX);
        self.udp_sessions_active
            .get_or_create(&UdpRoleLabels { role })
            .set(value);
    }

    pub fn udp_datagram(&self, role: Role, direction: Direction, outcome: Outcome) {
        self.udp_datagrams
            .get_or_create(&UdpDatagramLabels {
                role,
                direction,
                outcome,
            })
            .inc();
    }

    pub fn udp_failure(&self, role: Role, stage: Stage, reason: Reason) {
        self.udp_failures
            .get_or_create(&FailureLabels {
                role,
                stage,
                reason,
            })
            .inc();
    }

    pub fn add_udp_bytes(&self, role: Role, direction: Direction, bytes: u64) {
        self.udp_bytes
            .get_or_create(&ByteLabels { role, direction })
            .inc_by(bytes);
    }

    pub fn set_udp_buffered_bytes(&self, role: Role, bytes: usize) {
        let value = i64::try_from(bytes).unwrap_or(i64::MAX);
        self.udp_buffered_bytes
            .get_or_create(&UdpRoleLabels { role })
            .set(value);
    }

    pub fn udp_replay_rejection(&self, role: Role, direction: Direction, reason: Reason) {
        self.udp_replay_rejections
            .get_or_create(&UdpReplayLabels {
                role,
                direction,
                reason,
            })
            .inc();
    }

    pub fn udp_forced_shutdown(&self, role: Role) {
        self.udp_forced_shutdown
            .get_or_create(&UdpRoleLabels { role })
            .inc();
    }

    /// Encodes a stable OpenMetrics text representation.
    ///
    /// Family blocks and samples are sorted so output does not inherit hash-map
    /// iteration or update order.
    pub fn encode_text(&self) -> Result<String, MetricsEncodeError> {
        let mut encoded = String::new();
        text::encode(&mut encoded, &self.registry).map_err(|_| MetricsEncodeError)?;
        Ok(canonicalize_text(&encoded))
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Closed text-encoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricsEncodeError;

impl fmt::Display for MetricsEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("metrics encoding failed")
    }
}

impl Error for MetricsEncodeError {}

fn canonicalize_text(encoded: &str) -> String {
    let mut blocks: Vec<Vec<&str>> = Vec::new();
    let mut current = Vec::new();
    for line in encoded.lines() {
        if line == "# EOF" {
            continue;
        }
        if line.starts_with("# HELP ") && !current.is_empty() {
            blocks.push(current);
            current = Vec::new();
        }
        current.push(line);
    }
    if !current.is_empty() {
        blocks.push(current);
    }

    for block in &mut blocks {
        let sample_start = block
            .iter()
            .position(|line| !line.starts_with('#'))
            .unwrap_or(block.len());
        block[sample_start..].sort_unstable();
    }
    blocks.sort_unstable_by(|left, right| left.first().cmp(&right.first()));

    let mut canonical = String::new();
    for block in blocks {
        for line in block {
            canonical.push_str(line);
            canonical.push('\n');
        }
    }
    canonical.push_str("# EOF\n");
    canonical
}
