#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

use prometheus_client::encoding::{
    EncodeLabelSet, EncodeLabelValue, EncodeMetric, LabelValueEncoder, MetricEncoder, NoLabelSet,
    text,
};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::metrics::{MetricType, TypedMetric};
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
const SNIFF_TRACE_FIELDS: &[&str] = &["event", "role", "transport", "stage", "outcome", "protocol"];
const TUN_TRACE_FIELDS: &[&str] = &["event", "role", "stage", "outcome", "reason", "family"];

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
#[non_exhaustive]
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

/// Closed transport categories used by tracing.
#[non_exhaustive]
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
    const fn as_str(self) -> &'static str {
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
    const fn as_str(self) -> &'static str {
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
    const fn as_str(self) -> &'static str {
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
    const fn as_str(self) -> &'static str {
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
    const fn as_str(self) -> &'static str {
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
    const fn as_str(self) -> &'static str {
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
    const fn as_str(self) -> &'static str {
        match self {
            Self::WintunRingFull => "wintun_ring_full",
        }
    }

    const fn outcome(self) -> Outcome {
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
    const fn as_str(self) -> &'static str {
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
    const fn as_str(self) -> &'static str {
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
            || has_exact_fields(metadata, TRACE_FIELDS_WITH_REASON)
            || has_exact_fields(metadata, SNIFF_TRACE_FIELDS)
            || has_exact_fields(metadata, TUN_TRACE_FIELDS))
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

/// Emits one redacted TUN diagnostic with only fixed low-cardinality fields.
pub fn emit_tun_diagnostic(role: Role, reason: TunDiagnosticReason, family: TunIpFamily) {
    tracing::event!(
        target: CLOSED_TRACE_TARGET,
        Level::WARN,
        event = %Event::Tun,
        role = %role,
        stage = %Stage::Tun,
        outcome = %reason.outcome(),
        reason = %reason,
        family = %family,
    );
}

fn emit_sniff(role: Role, transport: Transport, outcome: SniffOutcome, protocol: SniffProtocol) {
    tracing::event!(
        target: CLOSED_TRACE_TARGET,
        Level::INFO,
        event = %Event::Sniff,
        role = %role,
        transport = %transport,
        stage = %Stage::Sniff,
        outcome = %outcome,
        protocol = %protocol,
    );
}

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

/// Closed outcomes for loading or refreshing a RuleSet.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuleSetResult {
    Success,
    Failure,
    Unchanged,
}

impl RuleSetResult {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Unchanged => "unchanged",
        }
    }
}

/// Closed matcher categories used by compiled RuleSet entry gauges.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CompiledMatchType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    IpCidr,
}

impl CompiledMatchType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::DomainSuffix => "domain_suffix",
            Self::DomainKeyword => "domain_keyword",
            Self::IpCidr => "ip_cidr",
        }
    }
}

/// Closed rule programs which share the matching engine.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuleProgram {
    Route,
    DnsQuery,
    DnsResponse,
}

impl RuleProgram {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Route => "route",
            Self::DnsQuery => "dns_query",
            Self::DnsResponse => "dns_response",
        }
    }
}

/// Closed implementations available to a compiled rule program.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuleProgramMode {
    SmallLinear,
    Indexed,
}

impl RuleProgramMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SmallLinear => "small_linear",
            Self::Indexed => "indexed",
        }
    }
}

/// Closed origins for route and DNS rule matchers.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuleSource {
    Inline,
    RuleSet,
}

impl RuleSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::RuleSet => "rule_set",
        }
    }
}

/// Closed rule matcher categories. No concrete value is accepted as a label.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuleMatchType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    IpCidr,
    Scalar,
}

impl RuleMatchType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::DomainSuffix => "domain_suffix",
            Self::DomainKeyword => "domain_keyword",
            Self::IpCidr => "ip_cidr",
            Self::Scalar => "scalar",
        }
    }
}

/// Closed results for one rule-matching source and category.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuleMatchResult {
    Matched,
    Missed,
}

impl RuleMatchResult {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Missed => "missed",
        }
    }
}

/// Closed resolver classes. Configured resolver tags are deliberately excluded.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DnsResolverKind {
    System,
    Configured,
}

impl DnsResolverKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Configured => "configured",
        }
    }
}

/// Closed purposes for DNS resolution.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DnsResolvePurpose {
    Application,
    FixedEndpoint,
    RuleSetDownload,
}

impl DnsResolvePurpose {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::FixedEndpoint => "fixed_endpoint",
            Self::RuleSetDownload => "ruleset_download",
        }
    }
}

/// Closed DNS resolution results.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DnsResolveResult {
    Success,
    Failure,
}

impl DnsResolveResult {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

/// Closed DNS query types used by the shared cache metrics.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DnsQueryType {
    A,
    Aaaa,
    Other,
}

impl DnsQueryType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::Aaaa => "aaaa",
            Self::Other => "other",
        }
    }
}

/// Closed components whose dial targets may be resolved in different places.
/// Concrete DNS server, RuleSet, domain, and URL identities are excluded.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TargetResolutionComponent {
    DnsUpstream,
    RuleSetDownload,
}

impl TargetResolutionComponent {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DnsUpstream => "dns_upstream",
            Self::RuleSetDownload => "ruleset_download",
        }
    }
}

/// Closed locations at which a DNS upstream or RuleSet target is resolved.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TargetResolutionMode {
    Numeric,
    ClientResolvedSystem,
    ClientResolvedConfigured,
    DeferredToDetour,
}

impl TargetResolutionMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Numeric => "numeric",
            Self::ClientResolvedSystem => "client_resolved_system",
            Self::ClientResolvedConfigured => "client_resolved_configured",
            Self::DeferredToDetour => "deferred_to_detour",
        }
    }
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
impl_closed_display!(RuleSetResult);
impl_closed_display!(CompiledMatchType);
impl_closed_display!(RuleProgram);
impl_closed_display!(RuleProgramMode);
impl_closed_display!(RuleSource);
impl_closed_display!(RuleMatchType);
impl_closed_display!(RuleMatchResult);
impl_closed_display!(DnsResolverKind);
impl_closed_display!(DnsResolvePurpose);
impl_closed_display!(DnsResolveResult);
impl_closed_display!(DnsQueryType);
impl_closed_display!(TargetResolutionComponent);
impl_closed_display!(TargetResolutionMode);
impl_closed_display!(TunUdpResponseDropReason);

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
impl_label_value!(Transport);
impl_label_value!(Inbound);
impl_label_value!(Outcome);
impl_label_value!(Stage);
impl_label_value!(Reason);
impl_label_value!(Direction);
impl_label_value!(SniffOutcome);
impl_label_value!(SniffProtocol);
impl_label_value!(RuleSetResult);
impl_label_value!(CompiledMatchType);
impl_label_value!(RuleProgram);
impl_label_value!(RuleProgramMode);
impl_label_value!(RuleSource);
impl_label_value!(RuleMatchType);
impl_label_value!(RuleMatchResult);
impl_label_value!(DnsResolverKind);
impl_label_value!(DnsResolvePurpose);
impl_label_value!(DnsResolveResult);
impl_label_value!(DnsQueryType);
impl_label_value!(TargetResolutionComponent);
impl_label_value!(TargetResolutionMode);
impl_label_value!(TunPacketRejectReason);
impl_label_value!(TunUdpResponseDropReason);

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

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct RuleSetResultLabels {
    result: RuleSetResult,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct CompiledMatchLabels {
    r#type: CompiledMatchType,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct RuleProgramLabels {
    program: RuleProgram,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct RuleProgramModeLabels {
    program: RuleProgram,
    mode: RuleProgramMode,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct RuleMatchLabels {
    source: RuleSource,
    r#type: RuleMatchType,
    result: RuleMatchResult,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct DnsResolveLabels {
    resolver: DnsResolverKind,
    purpose: DnsResolvePurpose,
    result: DnsResolveResult,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct DnsQueryTypeLabels {
    qtype: DnsQueryType,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct DnsResolvePurposeLabels {
    purpose: DnsResolvePurpose,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct TargetResolutionLabels {
    component: TargetResolutionComponent,
    mode: TargetResolutionMode,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct TunPacketRejectLabels {
    reason: TunPacketRejectReason,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct TunUdpResponseDropLabels {
    reason: TunUdpResponseDropReason,
}

const ROLES: &[Role] = &[Role::Client, Role::Server];
const TRANSPORTS: &[Transport] = &[Transport::Tcp, Transport::Udp];
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
const RULESET_RESULTS: &[RuleSetResult] = &[
    RuleSetResult::Success,
    RuleSetResult::Failure,
    RuleSetResult::Unchanged,
];
const COMPILED_MATCH_TYPES: &[CompiledMatchType] = &[
    CompiledMatchType::Domain,
    CompiledMatchType::DomainSuffix,
    CompiledMatchType::DomainKeyword,
    CompiledMatchType::IpCidr,
];
const RULE_PROGRAMS: &[RuleProgram] = &[
    RuleProgram::Route,
    RuleProgram::DnsQuery,
    RuleProgram::DnsResponse,
];
const RULE_PROGRAM_MODES: &[RuleProgramMode] =
    &[RuleProgramMode::SmallLinear, RuleProgramMode::Indexed];
const RULE_SOURCES: &[RuleSource] = &[RuleSource::Inline, RuleSource::RuleSet];
const RULE_MATCH_TYPES: &[RuleMatchType] = &[
    RuleMatchType::Domain,
    RuleMatchType::DomainSuffix,
    RuleMatchType::DomainKeyword,
    RuleMatchType::IpCidr,
    RuleMatchType::Scalar,
];
const RULE_MATCH_RESULTS: &[RuleMatchResult] = &[RuleMatchResult::Matched, RuleMatchResult::Missed];
const DNS_RESOLVER_KINDS: &[DnsResolverKind] =
    &[DnsResolverKind::System, DnsResolverKind::Configured];
const DNS_RESOLVE_PURPOSES: &[DnsResolvePurpose] = &[
    DnsResolvePurpose::Application,
    DnsResolvePurpose::FixedEndpoint,
    DnsResolvePurpose::RuleSetDownload,
];
const DNS_RESOLVE_RESULTS: &[DnsResolveResult] =
    &[DnsResolveResult::Success, DnsResolveResult::Failure];
const DNS_QUERY_TYPES: &[DnsQueryType] =
    &[DnsQueryType::A, DnsQueryType::Aaaa, DnsQueryType::Other];
const TARGET_RESOLUTION_COMPONENTS: &[TargetResolutionComponent] = &[
    TargetResolutionComponent::DnsUpstream,
    TargetResolutionComponent::RuleSetDownload,
];
const TARGET_RESOLUTION_MODES: &[TargetResolutionMode] = &[
    TargetResolutionMode::Numeric,
    TargetResolutionMode::ClientResolvedSystem,
    TargetResolutionMode::ClientResolvedConfigured,
    TargetResolutionMode::DeferredToDetour,
];
const TUN_PACKET_REJECT_REASONS: &[TunPacketRejectReason] = &[
    TunPacketRejectReason::InvalidIpVersion,
    TunPacketRejectReason::FamilyDisabled,
    TunPacketRejectReason::InvalidIpLength,
    TunPacketRejectReason::InvalidIpChecksum,
    TunPacketRejectReason::InvalidExtensionHeader,
    TunPacketRejectReason::UnsupportedIpProtocol,
    TunPacketRejectReason::IcmpEchoUnsupported,
    TunPacketRejectReason::FragmentMalformed,
    TunPacketRejectReason::FragmentOverlap,
    TunPacketRejectReason::FragmentTimeout,
    TunPacketRejectReason::FragmentLimit,
    TunPacketRejectReason::InvalidTransportLength,
    TunPacketRejectReason::InvalidTransportChecksum,
    TunPacketRejectReason::InvalidSource,
    TunPacketRejectReason::InvalidDestination,
    TunPacketRejectReason::IngressFull,
    TunPacketRejectReason::TcpFlowLimit,
    TunPacketRejectReason::UdpAssociationLimit,
    TunPacketRejectReason::UdpCandidateTimeout,
    TunPacketRejectReason::UdpQueueFull,
    TunPacketRejectReason::UdpResponseFiltered,
    TunPacketRejectReason::UdpResponseClosed,
    TunPacketRejectReason::StaleGeneration,
    TunPacketRejectReason::WintunRingFull,
];
const TUN_UDP_RESPONSE_DROP_REASONS: &[TunUdpResponseDropReason] = &[
    TunUdpResponseDropReason::StaleGeneration,
    TunUdpResponseDropReason::AssociationClosed,
    TunUdpResponseDropReason::QueueFull,
    TunUdpResponseDropReason::MalformedResponse,
    TunUdpResponseDropReason::Filtered,
    TunUdpResponseDropReason::InjectionRejected,
    TunUdpResponseDropReason::SessionReset,
    TunUdpResponseDropReason::Shutdown,
    TunUdpResponseDropReason::OwnerFatal,
];
const RULE_PROGRAM_CANDIDATE_BUCKETS: &[f64] = &[
    0.0, 1.0, 4.0, 16.0, 64.0, 256.0, 1_024.0, 4_096.0, 16_384.0, 65_536.0,
];
const RULE_PROGRAM_MATCH_NS_BUCKETS: &[f64] = &[
    100.0,
    500.0,
    1_000.0,
    5_000.0,
    10_000.0,
    50_000.0,
    100_000.0,
    500_000.0,
    1_000_000.0,
    5_000_000.0,
    10_000_000.0,
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
const RULESET_RESULT_SERIES: usize = RULESET_RESULTS.len();
const COMPILED_MATCH_SERIES: usize = COMPILED_MATCH_TYPES.len();
const RULE_PROGRAM_SERIES: usize = RULE_PROGRAMS.len();
const RULE_PROGRAM_MODE_SERIES: usize = RULE_PROGRAMS.len() * RULE_PROGRAM_MODES.len();
const RULE_MATCH_SERIES: usize =
    RULE_SOURCES.len() * RULE_MATCH_TYPES.len() * RULE_MATCH_RESULTS.len();
const DNS_RESOLVE_SERIES: usize =
    DNS_RESOLVER_KINDS.len() * DNS_RESOLVE_PURPOSES.len() * DNS_RESOLVE_RESULTS.len();
const DNS_QUERY_TYPE_SERIES: usize = DNS_QUERY_TYPES.len();
const DNS_RESOLVE_PURPOSE_SERIES: usize = DNS_RESOLVE_PURPOSES.len();
const TARGET_RESOLUTION_SERIES: usize =
    TARGET_RESOLUTION_COMPONENTS.len() * TARGET_RESOLUTION_MODES.len();
const TUN_PACKET_REJECT_SERIES: usize = TUN_PACKET_REJECT_REASONS.len();
const TUN_UDP_RESPONSE_DROP_SERIES: usize = TUN_UDP_RESPONSE_DROP_REASONS.len();

#[derive(Debug, Default)]
struct CachedCounter {
    value: AtomicU64,
    touched: AtomicBool,
}

impl CachedCounter {
    fn inc(&self) {
        self.touched.store(true, Ordering::Relaxed);
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_by(&self, value: u64) {
        self.touched.store(true, Ordering::Relaxed);
        self.value.fetch_add(value, Ordering::Relaxed);
    }
}

impl TypedMetric for CachedCounter {
    const TYPE: MetricType = MetricType::Counter;
}

impl EncodeMetric for CachedCounter {
    fn encode(&self, mut encoder: MetricEncoder) -> fmt::Result {
        encoder.encode_counter::<NoLabelSet, _, u64>(&self.value.load(Ordering::Relaxed), None)
    }

    fn metric_type(&self) -> MetricType {
        Self::TYPE
    }

    fn is_empty(&self) -> bool {
        !self.touched.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Default)]
struct CachedGauge {
    value: AtomicI64,
    touched: AtomicBool,
}

impl CachedGauge {
    fn inc(&self) {
        self.touched.store(true, Ordering::Relaxed);
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    fn dec(&self) {
        self.touched.store(true, Ordering::Relaxed);
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    fn set(&self, value: i64) {
        self.touched.store(true, Ordering::Relaxed);
        self.value.store(value, Ordering::Relaxed);
    }
}

impl TypedMetric for CachedGauge {
    const TYPE: MetricType = MetricType::Gauge;
}

impl EncodeMetric for CachedGauge {
    fn encode(&self, mut encoder: MetricEncoder) -> fmt::Result {
        encoder.encode_gauge(&self.value.load(Ordering::Relaxed))
    }

    fn metric_type(&self) -> MetricType {
        Self::TYPE
    }

    fn is_empty(&self) -> bool {
        !self.touched.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
struct CachedHistogram {
    histogram: Histogram,
    touched: AtomicBool,
}

impl CachedHistogram {
    fn new(buckets: impl IntoIterator<Item = f64>) -> Self {
        Self {
            histogram: Histogram::new(buckets),
            touched: AtomicBool::new(false),
        }
    }

    fn observe(&self, value: f64) {
        self.histogram.observe(value);
        self.touched.store(true, Ordering::Relaxed);
    }
}

impl TypedMetric for CachedHistogram {
    const TYPE: MetricType = MetricType::Histogram;
}

impl EncodeMetric for CachedHistogram {
    fn encode(&self, encoder: MetricEncoder) -> fmt::Result {
        self.histogram.encode(encoder)
    }

    fn metric_type(&self) -> MetricType {
        Self::TYPE
    }

    fn is_empty(&self) -> bool {
        !self.touched.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
struct ClosedFamily<S, M, const N: usize> {
    entries: [(S, M); N],
}

#[derive(Debug)]
struct SharedClosedFamily<S, M, const N: usize> {
    inner: Arc<ClosedFamily<S, M, N>>,
}

impl<S, M, const N: usize> Clone for SharedClosedFamily<S, M, N> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<S, M: Default, const N: usize> SharedClosedFamily<S, M, N> {
    fn new(labels: [S; N]) -> Self {
        Self {
            inner: Arc::new(ClosedFamily {
                entries: labels.map(|labels| (labels, M::default())),
            }),
        }
    }
}

impl<S, M, const N: usize> SharedClosedFamily<S, M, N> {
    fn new_with(labels: [S; N], make_metric: impl Fn() -> M) -> Self {
        let mut labels = labels.into_iter();
        Self {
            inner: Arc::new(ClosedFamily {
                entries: std::array::from_fn(|_| {
                    (
                        labels.next().expect("label count matches family size"),
                        make_metric(),
                    )
                }),
            }),
        }
    }

    fn metric(&self, index: usize) -> &M {
        &self.inner.entries[index].1
    }
}

impl<S, M, const N: usize> EncodeMetric for SharedClosedFamily<S, M, N>
where
    S: EncodeLabelSet,
    M: EncodeMetric + TypedMetric,
{
    fn encode(&self, mut encoder: MetricEncoder) -> fmt::Result {
        for (labels, metric) in &self.inner.entries {
            if !metric.is_empty() {
                metric.encode(encoder.encode_family(labels)?)?;
            }
        }
        Ok(())
    }

    fn metric_type(&self) -> MetricType {
        M::TYPE
    }

    fn is_empty(&self) -> bool {
        self.inner
            .entries
            .iter()
            .all(|(_, metric)| metric.is_empty())
    }
}

fn single_labels<A: Copy, S, const N: usize>(values: &[A], make: impl Fn(A) -> S) -> [S; N] {
    assert_eq!(values.len(), N);
    std::array::from_fn(|index| make(values[index]))
}

fn pair_labels<A: Copy, B: Copy, S, const N: usize>(
    first: &[A],
    second: &[B],
    make: impl Fn(A, B) -> S,
) -> [S; N] {
    assert_eq!(first.len() * second.len(), N);
    std::array::from_fn(|index| {
        let second_index = index % second.len();
        let first_index = index / second.len();
        make(first[first_index], second[second_index])
    })
}

fn triple_labels<A: Copy, B: Copy, C: Copy, S, const N: usize>(
    first: &[A],
    second: &[B],
    third: &[C],
    make: impl Fn(A, B, C) -> S,
) -> [S; N] {
    assert_eq!(first.len() * second.len() * third.len(), N);
    std::array::from_fn(|index| {
        let third_index = index % third.len();
        let remaining = index / third.len();
        let second_index = remaining % second.len();
        let first_index = remaining / second.len();
        make(first[first_index], second[second_index], third[third_index])
    })
}

fn quadruple_labels<A: Copy, B: Copy, C: Copy, D: Copy, S, const N: usize>(
    first: &[A],
    second: &[B],
    third: &[C],
    fourth: &[D],
    make: impl Fn(A, B, C, D) -> S,
) -> [S; N] {
    assert_eq!(first.len() * second.len() * third.len() * fourth.len(), N);
    std::array::from_fn(|index| {
        let fourth_index = index % fourth.len();
        let remaining = index / fourth.len();
        let third_index = remaining % third.len();
        let remaining = remaining / third.len();
        let second_index = remaining % second.len();
        let first_index = remaining / second.len();
        make(
            first[first_index],
            second[second_index],
            third[third_index],
            fourth[fourth_index],
        )
    })
}

const fn pair_index(first: usize, second: usize, second_count: usize) -> usize {
    first * second_count + second
}

const fn triple_index(
    first: usize,
    second: usize,
    third: usize,
    second_count: usize,
    third_count: usize,
) -> usize {
    pair_index(first, second, second_count) * third_count + third
}

const fn quadruple_index(
    first: usize,
    second: usize,
    third: usize,
    fourth: usize,
    second_count: usize,
    third_count: usize,
    fourth_count: usize,
) -> usize {
    triple_index(first, second, third, second_count, third_count) * fourth_count + fourth
}

fn u64_gauge(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn usize_gauge(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

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
type RuleSetResultFamily =
    SharedClosedFamily<RuleSetResultLabels, CachedCounter, RULESET_RESULT_SERIES>;
type CompiledMatchFamily =
    SharedClosedFamily<CompiledMatchLabels, CachedGauge, COMPILED_MATCH_SERIES>;
type RuleProgramGaugeFamily =
    SharedClosedFamily<RuleProgramLabels, CachedGauge, RULE_PROGRAM_SERIES>;
type RuleProgramHistogramFamily =
    SharedClosedFamily<RuleProgramLabels, CachedHistogram, RULE_PROGRAM_SERIES>;
type RuleProgramModeFamily =
    SharedClosedFamily<RuleProgramModeLabels, CachedGauge, RULE_PROGRAM_MODE_SERIES>;
type RuleMatchFamily = SharedClosedFamily<RuleMatchLabels, CachedCounter, RULE_MATCH_SERIES>;
type DnsResolveFamily = SharedClosedFamily<DnsResolveLabels, CachedCounter, DNS_RESOLVE_SERIES>;
type DnsQueryTypeFamily =
    SharedClosedFamily<DnsQueryTypeLabels, CachedCounter, DNS_QUERY_TYPE_SERIES>;
type DnsResolvePurposeFamily =
    SharedClosedFamily<DnsResolvePurposeLabels, CachedCounter, DNS_RESOLVE_PURPOSE_SERIES>;
type TargetResolutionFamily =
    SharedClosedFamily<TargetResolutionLabels, CachedCounter, TARGET_RESOLUTION_SERIES>;
type TunPacketRejectFamily =
    SharedClosedFamily<TunPacketRejectLabels, CachedCounter, TUN_PACKET_REJECT_SERIES>;
type TunUdpResponseDropFamily =
    SharedClosedFamily<TunUdpResponseDropLabels, CachedCounter, TUN_UDP_RESPONSE_DROP_SERIES>;
fn record_rule_match(
    family: &RuleMatchFamily,
    source: RuleSource,
    r#type: RuleMatchType,
    result: RuleMatchResult,
) {
    record_rule_matches(family, source, r#type, result, 1);
}

fn record_rule_matches(
    family: &RuleMatchFamily,
    source: RuleSource,
    r#type: RuleMatchType,
    result: RuleMatchResult,
    count: u64,
) {
    if count == 0 {
        return;
    }
    family
        .metric(triple_index(
            source as usize,
            r#type as usize,
            result as usize,
            RULE_MATCH_TYPES.len(),
            RULE_MATCH_RESULTS.len(),
        ))
        .inc_by(count);
}

/// Explicit owner of the stable networking, rules, and DNS metric families.
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
    sniff: SniffFamily,
    tun_packets_accepted: Counter,
    tun_packets_foundation_dropped: Counter,
    tun_session_started: Counter,
    tun_session_restart_started: Counter,
    tun_session_restart_succeeded: Counter,
    tun_session_restart_failed: Counter,
    tun_session_generation: Gauge,
    tun_session_active: Gauge,
    tun_packets_ingress: Counter,
    tun_packets_egress: Counter,
    tun_packets_rejected: TunPacketRejectFamily,
    tun_internal_egress_backpressured: Counter,
    tun_pending_udp_responses: Gauge,
    tun_udp_response_dropped: TunUdpResponseDropFamily,
    tun_wintun_ring_full_dropped: Counter,
    tun_tcp_flows_active: Gauge,
    tun_tcp_flows_rejected_limit: Counter,
    tun_tcp_flows_reset_restart: Counter,
    tun_tcp_bridge_blocked: Counter,
    tun_udp_associations_active: Gauge,
    tun_udp_candidates_active: Gauge,
    tun_udp_association_created: Counter,
    tun_udp_association_rejected_limit: Counter,
    tun_udp_datagram_queue_full: Counter,
    tun_udp_response_queue_full: Counter,
    tun_udp_response_filtered: Counter,
    tun_udp_stale_generation: Counter,
    tun_reassembly_entries_active: Gauge,
    tun_reassembly_started: Counter,
    tun_reassembly_completed: Counter,
    tun_reassembly_dropped_overlap: Counter,
    tun_reassembly_dropped_timeout: Counter,
    tun_reassembly_dropped_limit: Counter,
    tun_reassembly_dropped_malformed: Counter,
    tun_network_change: Counter,
    tun_underlay_bind_stale: Counter,
    ruleset_loads: RuleSetResultFamily,
    ruleset_refreshes: RuleSetResultFamily,
    ruleset_generation: Gauge,
    ruleset_compiled_entries: CompiledMatchFamily,
    ruleset_last_success_timestamp: Gauge,
    rule_program_mode: RuleProgramModeFamily,
    rule_program_rules: RuleProgramGaugeFamily,
    rule_program_candidate_count: RuleProgramHistogramFamily,
    rule_program_match_ns: RuleProgramHistogramFamily,
    route_matches: RuleMatchFamily,
    dns_rule_query_matches: RuleMatchFamily,
    dns_rule_response_matches: RuleMatchFamily,
    dns_resolves: DnsResolveFamily,
    dns_cache_hits: DnsQueryTypeFamily,
    dns_cache_misses: DnsQueryTypeFamily,
    dns_explicit_system_resolves: DnsResolvePurposeFamily,
    dns_implicit_system_fallbacks: Counter,
    target_resolutions: TargetResolutionFamily,
}

impl Metrics {
    /// Creates an isolated registry containing the stable metric families.
    ///
    /// Later releases may add families without removing or repurposing these.
    pub fn new() -> Self {
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
        let tun_packets_accepted = Counter::default();
        let tun_packets_foundation_dropped = Counter::default();
        let tun_session_started = Counter::default();
        let tun_session_restart_started = Counter::default();
        let tun_session_restart_succeeded = Counter::default();
        let tun_session_restart_failed = Counter::default();
        let tun_session_generation = Gauge::default();
        let tun_session_active = Gauge::default();
        let tun_packets_ingress = Counter::default();
        let tun_packets_egress = Counter::default();
        let tun_packets_rejected =
            TunPacketRejectFamily::new(single_labels(TUN_PACKET_REJECT_REASONS, |reason| {
                TunPacketRejectLabels { reason }
            }));
        let tun_internal_egress_backpressured = Counter::default();
        let tun_pending_udp_responses = Gauge::default();
        let tun_udp_response_dropped =
            TunUdpResponseDropFamily::new(single_labels(TUN_UDP_RESPONSE_DROP_REASONS, |reason| {
                TunUdpResponseDropLabels { reason }
            }));
        let tun_wintun_ring_full_dropped = Counter::default();
        let tun_tcp_flows_active = Gauge::default();
        let tun_tcp_flows_rejected_limit = Counter::default();
        let tun_tcp_flows_reset_restart = Counter::default();
        let tun_tcp_bridge_blocked = Counter::default();
        let tun_udp_associations_active = Gauge::default();
        let tun_udp_candidates_active = Gauge::default();
        let tun_udp_association_created = Counter::default();
        let tun_udp_association_rejected_limit = Counter::default();
        let tun_udp_datagram_queue_full = Counter::default();
        let tun_udp_response_queue_full = Counter::default();
        let tun_udp_response_filtered = Counter::default();
        let tun_udp_stale_generation = Counter::default();
        let tun_reassembly_entries_active = Gauge::default();
        let tun_reassembly_started = Counter::default();
        let tun_reassembly_completed = Counter::default();
        let tun_reassembly_dropped_overlap = Counter::default();
        let tun_reassembly_dropped_timeout = Counter::default();
        let tun_reassembly_dropped_limit = Counter::default();
        let tun_reassembly_dropped_malformed = Counter::default();
        let tun_network_change = Counter::default();
        let tun_underlay_bind_stale = Counter::default();
        let ruleset_loads = RuleSetResultFamily::new(single_labels(RULESET_RESULTS, |result| {
            RuleSetResultLabels { result }
        }));
        let ruleset_refreshes =
            RuleSetResultFamily::new(single_labels(RULESET_RESULTS, |result| {
                RuleSetResultLabels { result }
            }));
        let ruleset_generation = Gauge::default();
        let ruleset_compiled_entries =
            CompiledMatchFamily::new(single_labels(COMPILED_MATCH_TYPES, |r#type| {
                CompiledMatchLabels { r#type }
            }));
        let ruleset_last_success_timestamp = Gauge::default();
        let rule_program_mode = RuleProgramModeFamily::new(pair_labels(
            RULE_PROGRAMS,
            RULE_PROGRAM_MODES,
            |program, mode| RuleProgramModeLabels { program, mode },
        ));
        let rule_program_rules =
            RuleProgramGaugeFamily::new(single_labels(RULE_PROGRAMS, |program| {
                RuleProgramLabels { program }
            }));
        let rule_program_candidate_count = RuleProgramHistogramFamily::new_with(
            single_labels(RULE_PROGRAMS, |program| RuleProgramLabels { program }),
            || CachedHistogram::new(RULE_PROGRAM_CANDIDATE_BUCKETS.iter().copied()),
        );
        let rule_program_match_ns = RuleProgramHistogramFamily::new_with(
            single_labels(RULE_PROGRAMS, |program| RuleProgramLabels { program }),
            || CachedHistogram::new(RULE_PROGRAM_MATCH_NS_BUCKETS.iter().copied()),
        );
        let make_rule_match_labels = || {
            triple_labels(
                RULE_SOURCES,
                RULE_MATCH_TYPES,
                RULE_MATCH_RESULTS,
                |source, r#type, result| RuleMatchLabels {
                    source,
                    r#type,
                    result,
                },
            )
        };
        let route_matches = RuleMatchFamily::new(make_rule_match_labels());
        let dns_rule_query_matches = RuleMatchFamily::new(make_rule_match_labels());
        let dns_rule_response_matches = RuleMatchFamily::new(make_rule_match_labels());
        let dns_resolves = DnsResolveFamily::new(triple_labels(
            DNS_RESOLVER_KINDS,
            DNS_RESOLVE_PURPOSES,
            DNS_RESOLVE_RESULTS,
            |resolver, purpose, result| DnsResolveLabels {
                resolver,
                purpose,
                result,
            },
        ));
        let dns_cache_hits = DnsQueryTypeFamily::new(single_labels(DNS_QUERY_TYPES, |qtype| {
            DnsQueryTypeLabels { qtype }
        }));
        let dns_cache_misses = DnsQueryTypeFamily::new(single_labels(DNS_QUERY_TYPES, |qtype| {
            DnsQueryTypeLabels { qtype }
        }));
        let dns_explicit_system_resolves =
            DnsResolvePurposeFamily::new(single_labels(DNS_RESOLVE_PURPOSES, |purpose| {
                DnsResolvePurposeLabels { purpose }
            }));
        let dns_implicit_system_fallbacks = Counter::default();
        let target_resolutions = TargetResolutionFamily::new(pair_labels(
            TARGET_RESOLUTION_COMPONENTS,
            TARGET_RESOLUTION_MODES,
            |component, mode| TargetResolutionLabels { component, mode },
        ));

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
        registry.register(
            "ferrum2_sniff",
            "Authenticated bounded sniff outcomes",
            sniff.clone(),
        );
        registry.register(
            "ferrum2_tun_packets_accepted",
            "Validated TUN packets accepted by the foundation stack",
            tun_packets_accepted.clone(),
        );
        registry.register(
            "ferrum2_tun_packets_foundation_dropped",
            "TUN packets deterministically dropped before policy composition",
            tun_packets_foundation_dropped.clone(),
        );
        registry.register(
            "ferrum2_tun_session_started",
            "TUN sessions that reached their initial start",
            tun_session_started.clone(),
        );
        registry.register(
            "ferrum2_tun_session_restart_started",
            "TUN session restart attempts started",
            tun_session_restart_started.clone(),
        );
        registry.register(
            "ferrum2_tun_session_restart_succeeded",
            "TUN session restart attempts completed successfully",
            tun_session_restart_succeeded.clone(),
        );
        registry.register(
            "ferrum2_tun_session_restart_failed",
            "TUN session restart attempts that failed",
            tun_session_restart_failed.clone(),
        );
        registry.register(
            "ferrum2_tun_session_generation",
            "Current TUN session generation",
            tun_session_generation.clone(),
        );
        registry.register(
            "ferrum2_tun_session_active",
            "Whether a TUN session is active",
            tun_session_active.clone(),
        );
        registry.register(
            "ferrum2_tun_packets_ingress",
            "Packets received from Wintun by the TUN owner",
            tun_packets_ingress.clone(),
        );
        registry.register(
            "ferrum2_tun_packets_egress",
            "Packets sent successfully to Wintun by the TUN owner",
            tun_packets_egress.clone(),
        );
        registry.register(
            "ferrum2_tun_packets_rejected",
            "TUN packets rejected by a closed low-cardinality reason",
            tun_packets_rejected.clone(),
        );
        registry.register(
            "ferrum2_tun_internal_egress_backpressured",
            "TUN internal egress backpressure observations; packets are retained for retry",
            tun_internal_egress_backpressured.clone(),
        );
        registry.register(
            "ferrum2_tun_pending_udp_responses",
            "TUN UDP responses retained for owner-thread injection",
            tun_pending_udp_responses.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_response_dropped",
            "Terminal TUN UDP response drops by a closed low-cardinality reason",
            tun_udp_response_dropped.clone(),
        );
        registry.register(
            "ferrum2_tun_wintun_ring_full_dropped",
            "TUN packets dropped because the Wintun send ring was full",
            tun_wintun_ring_full_dropped.clone(),
        );
        registry.register(
            "ferrum2_tun_tcp_flows_active",
            "Active TUN TCP flows",
            tun_tcp_flows_active.clone(),
        );
        registry.register(
            "ferrum2_tun_tcp_flows_rejected_limit",
            "TUN TCP flows rejected by the configured flow limit",
            tun_tcp_flows_rejected_limit.clone(),
        );
        registry.register(
            "ferrum2_tun_tcp_flows_reset_restart",
            "TUN TCP flows reset during session restart",
            tun_tcp_flows_reset_restart.clone(),
        );
        registry.register(
            "ferrum2_tun_tcp_bridge_blocked",
            "TUN TCP bridge operations that observed bounded backpressure",
            tun_tcp_bridge_blocked.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_associations_active",
            "Active TUN UDP associations",
            tun_udp_associations_active.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_candidates_active",
            "Active uncommitted TUN UDP association candidates",
            tun_udp_candidates_active.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_association_created",
            "TUN UDP associations created",
            tun_udp_association_created.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_association_rejected_limit",
            "TUN UDP associations rejected by the configured limit",
            tun_udp_association_rejected_limit.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_datagram_queue_full",
            "TUN UDP datagrams dropped because an association queue was full",
            tun_udp_datagram_queue_full.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_response_queue_full",
            "TUN UDP responses dropped because the response queue was full",
            tun_udp_response_queue_full.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_response_filtered",
            "TUN UDP responses rejected by endpoint filtering",
            tun_udp_response_filtered.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_stale_generation",
            "TUN UDP work rejected after its session generation became stale",
            tun_udp_stale_generation.clone(),
        );
        registry.register(
            "ferrum2_tun_reassembly_entries_active",
            "Active bounded TUN fragment reassembly entries",
            tun_reassembly_entries_active.clone(),
        );
        registry.register(
            "ferrum2_tun_reassembly_started",
            "TUN fragment reassemblies started",
            tun_reassembly_started.clone(),
        );
        registry.register(
            "ferrum2_tun_reassembly_completed",
            "TUN fragment reassemblies completed",
            tun_reassembly_completed.clone(),
        );
        registry.register(
            "ferrum2_tun_reassembly_dropped_overlap",
            "TUN fragment reassemblies dropped for overlap",
            tun_reassembly_dropped_overlap.clone(),
        );
        registry.register(
            "ferrum2_tun_reassembly_dropped_timeout",
            "TUN fragment reassemblies dropped after timeout",
            tun_reassembly_dropped_timeout.clone(),
        );
        registry.register(
            "ferrum2_tun_reassembly_dropped_limit",
            "TUN fragment reassemblies dropped by a bounded limit",
            tun_reassembly_dropped_limit.clone(),
        );
        registry.register(
            "ferrum2_tun_reassembly_dropped_malformed",
            "Malformed TUN fragment reassemblies dropped",
            tun_reassembly_dropped_malformed.clone(),
        );
        registry.register(
            "ferrum2_tun_network_change",
            "Semantic network changes observed by the TUN session",
            tun_network_change.clone(),
        );
        registry.register(
            "ferrum2_tun_underlay_bind_stale",
            "TUN underlay binds rejected because their generation was stale",
            tun_underlay_bind_stale.clone(),
        );
        registry.register(
            "ferrum2_ruleset_load",
            "RuleSet initial load outcomes aggregated without RuleSet identity",
            ruleset_loads.clone(),
        );
        registry.register(
            "ferrum2_ruleset_refresh",
            "RuleSet refresh outcomes aggregated without RuleSet identity",
            ruleset_refreshes.clone(),
        );
        registry.register(
            "ferrum2_ruleset_generation",
            "Current atomically published RuleSet snapshot generation",
            ruleset_generation.clone(),
        );
        registry.register(
            "ferrum2_ruleset_compiled_entries",
            "Compiled RuleSet entries aggregated by closed matcher type",
            ruleset_compiled_entries.clone(),
        );
        registry.register(
            "ferrum2_ruleset_last_success_timestamp",
            "Unix timestamp of the latest successful RuleSet load or refresh",
            ruleset_last_success_timestamp.clone(),
        );
        registry.register(
            "ferrum2_rule_program_mode",
            "One-hot selected implementation mode for each closed rule program",
            rule_program_mode.clone(),
        );
        registry.register(
            "ferrum2_rule_program_rules",
            "Compiled rule count for each closed rule program",
            rule_program_rules.clone(),
        );
        registry.register(
            "ferrum2_rule_program_candidate_count",
            "Candidate rule count per evaluation for each closed rule program",
            rule_program_candidate_count.clone(),
        );
        registry.register(
            "ferrum2_rule_program_match_ns",
            "Rule matching duration in nanoseconds for each closed rule program",
            rule_program_match_ns.clone(),
        );
        registry.register(
            "ferrum2_route_match",
            "Route matcher outcomes by closed source and matcher type",
            route_matches.clone(),
        );
        registry.register(
            "ferrum2_dns_rule_query_match",
            "DNS query rule matcher outcomes by closed source and matcher type",
            dns_rule_query_matches.clone(),
        );
        registry.register(
            "ferrum2_dns_rule_response_match",
            "DNS response rule matcher outcomes by closed source and matcher type",
            dns_rule_response_matches.clone(),
        );
        registry.register(
            "ferrum2_dns_resolve",
            "DNS resolution outcomes by closed resolver class and purpose",
            dns_resolves.clone(),
        );
        registry.register(
            "ferrum2_dns_cache_hit",
            "Shared DNS cache hits aggregated across configured server identities",
            dns_cache_hits.clone(),
        );
        registry.register(
            "ferrum2_dns_cache_miss",
            "Shared DNS cache misses aggregated across configured server identities",
            dns_cache_misses.clone(),
        );
        registry.register(
            "ferrum2_dns_explicit_system_resolve",
            "Explicitly authorized system DNS resolutions by closed purpose",
            dns_explicit_system_resolves.clone(),
        );
        registry.register(
            "ferrum2_dns_implicit_system_fallback",
            "Invariant violations that attempted an implicit system DNS fallback",
            dns_implicit_system_fallbacks.clone(),
        );
        registry.register(
            "ferrum2_target_resolution",
            "Target resolution locations by closed component and mode",
            target_resolutions.clone(),
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
            sniff,
            tun_packets_accepted,
            tun_packets_foundation_dropped,
            tun_session_started,
            tun_session_restart_started,
            tun_session_restart_succeeded,
            tun_session_restart_failed,
            tun_session_generation,
            tun_session_active,
            tun_packets_ingress,
            tun_packets_egress,
            tun_packets_rejected,
            tun_internal_egress_backpressured,
            tun_pending_udp_responses,
            tun_udp_response_dropped,
            tun_wintun_ring_full_dropped,
            tun_tcp_flows_active,
            tun_tcp_flows_rejected_limit,
            tun_tcp_flows_reset_restart,
            tun_tcp_bridge_blocked,
            tun_udp_associations_active,
            tun_udp_candidates_active,
            tun_udp_association_created,
            tun_udp_association_rejected_limit,
            tun_udp_datagram_queue_full,
            tun_udp_response_queue_full,
            tun_udp_response_filtered,
            tun_udp_stale_generation,
            tun_reassembly_entries_active,
            tun_reassembly_started,
            tun_reassembly_completed,
            tun_reassembly_dropped_overlap,
            tun_reassembly_dropped_timeout,
            tun_reassembly_dropped_limit,
            tun_reassembly_dropped_malformed,
            tun_network_change,
            tun_underlay_bind_stale,
            ruleset_loads,
            ruleset_refreshes,
            ruleset_generation,
            ruleset_compiled_entries,
            ruleset_last_success_timestamp,
            rule_program_mode,
            rule_program_rules,
            rule_program_candidate_count,
            rule_program_match_ns,
            route_matches,
            dns_rule_query_matches,
            dns_rule_response_matches,
            dns_resolves,
            dns_cache_hits,
            dns_cache_misses,
            dns_explicit_system_resolves,
            dns_implicit_system_fallbacks,
            target_resolutions,
        }
    }

    /// Records an initial RuleSet load without exposing its tag or source URL.
    pub fn ruleset_load(&self, result: RuleSetResult) {
        self.ruleset_loads.metric(result as usize).inc();
    }

    /// Records a RuleSet refresh without exposing its tag or source URL.
    pub fn ruleset_refresh(&self, result: RuleSetResult) {
        self.ruleset_refreshes.metric(result as usize).inc();
    }

    /// Sets the current fully published RuleSet snapshot generation.
    pub fn set_ruleset_generation(&self, generation: u64) {
        self.ruleset_generation.set(u64_gauge(generation));
    }

    /// Sets the aggregate compiled entry count for one closed matcher type.
    pub fn set_ruleset_compiled_entries(&self, r#type: CompiledMatchType, entries: usize) {
        self.ruleset_compiled_entries
            .metric(r#type as usize)
            .set(usize_gauge(entries));
    }

    /// Sets the Unix timestamp of the latest successful RuleSet publication.
    pub fn set_ruleset_last_success_timestamp(&self, unix_seconds: u64) {
        self.ruleset_last_success_timestamp
            .set(u64_gauge(unix_seconds));
    }

    /// Selects one implementation mode for a closed rule program.
    ///
    /// Both mode series are updated as a one-hot pair, so a later mode change
    /// cannot leave the prior mode reporting `1`.
    pub fn set_rule_program_mode(&self, program: RuleProgram, selected: RuleProgramMode) {
        for mode in RULE_PROGRAM_MODES {
            self.rule_program_mode
                .metric(pair_index(
                    program as usize,
                    *mode as usize,
                    RULE_PROGRAM_MODES.len(),
                ))
                .set(i64::from(*mode == selected));
        }
    }

    /// Sets the compiled rule count for a closed rule program.
    pub fn set_rule_program_rules(&self, program: RuleProgram, rules: usize) {
        self.rule_program_rules
            .metric(program as usize)
            .set(usize_gauge(rules));
    }

    /// Observes the number of candidates considered by one program evaluation.
    pub fn observe_rule_program_candidate_count(&self, program: RuleProgram, candidates: usize) {
        self.rule_program_candidate_count
            .metric(program as usize)
            .observe(candidates as f64);
    }

    /// Observes the matching duration of one program evaluation in nanoseconds.
    pub fn observe_rule_program_match_ns(&self, program: RuleProgram, match_ns: u64) {
        self.rule_program_match_ns
            .metric(program as usize)
            .observe(match_ns as f64);
    }

    /// Records one route matcher result using closed, identity-free labels.
    pub fn route_match(&self, source: RuleSource, r#type: RuleMatchType, result: RuleMatchResult) {
        record_rule_match(&self.route_matches, source, r#type, result);
    }

    /// Records one DNS query-rule matcher result using closed labels.
    pub fn dns_rule_query_match(
        &self,
        source: RuleSource,
        r#type: RuleMatchType,
        result: RuleMatchResult,
    ) {
        record_rule_match(&self.dns_rule_query_matches, source, r#type, result);
    }

    /// Records a fixed aggregate of DNS query-rule matcher results.
    pub fn dns_rule_query_matches(
        &self,
        source: RuleSource,
        r#type: RuleMatchType,
        result: RuleMatchResult,
        count: u64,
    ) {
        record_rule_matches(&self.dns_rule_query_matches, source, r#type, result, count);
    }

    /// Records one DNS response-rule matcher result using closed labels.
    pub fn dns_rule_response_match(
        &self,
        source: RuleSource,
        r#type: RuleMatchType,
        result: RuleMatchResult,
    ) {
        record_rule_match(&self.dns_rule_response_matches, source, r#type, result);
    }

    /// Records a fixed aggregate of DNS response-rule matcher results.
    pub fn dns_rule_response_matches(
        &self,
        source: RuleSource,
        r#type: RuleMatchType,
        result: RuleMatchResult,
        count: u64,
    ) {
        record_rule_matches(
            &self.dns_rule_response_matches,
            source,
            r#type,
            result,
            count,
        );
    }

    /// Records one DNS resolution without accepting a configured resolver tag.
    pub fn dns_resolve(
        &self,
        resolver: DnsResolverKind,
        purpose: DnsResolvePurpose,
        result: DnsResolveResult,
    ) {
        self.dns_resolves
            .metric(triple_index(
                resolver as usize,
                purpose as usize,
                result as usize,
                DNS_RESOLVE_PURPOSES.len(),
                DNS_RESOLVE_RESULTS.len(),
            ))
            .inc();
    }

    /// Records a shared DNS cache hit without accepting a server identity.
    pub fn dns_cache_hit(&self, qtype: DnsQueryType) {
        self.dns_cache_hits.metric(qtype as usize).inc();
    }

    /// Records a shared DNS cache miss without accepting a server identity.
    pub fn dns_cache_miss(&self, qtype: DnsQueryType) {
        self.dns_cache_misses.metric(qtype as usize).inc();
    }

    /// Records an authorized use of the system resolver.
    ///
    /// Callers must use this only for system application mode or an explicit
    /// `domain_resolver`/`download_resolver = "system"` configuration.
    pub fn dns_explicit_system_resolve(&self, purpose: DnsResolvePurpose) {
        self.dns_explicit_system_resolves
            .metric(purpose as usize)
            .inc();
    }

    /// Records an invariant violation that attempted an implicit system fallback.
    ///
    /// This is intentionally the only API which can increment the fallback
    /// counter. Normal resolution and explicit-system APIs leave it at zero.
    pub fn record_dns_implicit_system_fallback_violation(&self) {
        self.dns_implicit_system_fallbacks.inc();
    }

    /// Records where a DNS upstream or RuleSet dial target is resolved.
    ///
    /// The closed component and mode enums prevent target, resolver, detour,
    /// domain, URL, or configured-tag identities from becoming labels.
    pub fn target_resolution(
        &self,
        component: TargetResolutionComponent,
        mode: TargetResolutionMode,
    ) {
        self.target_resolutions
            .metric(pair_index(
                component as usize,
                mode as usize,
                TARGET_RESOLUTION_MODES.len(),
            ))
            .inc();
    }

    /// Records one packet that passed the shared TUN ingress validator.
    pub fn tun_packet_accepted(&self) {
        self.tun_packets_accepted.inc();
    }

    /// Records one accepted packet consumed by the foundation stack before policy.
    pub fn tun_packet_foundation_dropped(&self) {
        self.tun_packets_foundation_dropped.inc();
    }

    /// Records the first successful start of a TUN session.
    pub fn tun_session_started(&self) {
        self.tun_session_started.inc();
    }

    /// Records the beginning of one TUN session restart attempt.
    pub fn tun_session_restart_started(&self) {
        self.tun_session_restart_started.inc();
    }

    /// Records one successful TUN session restart attempt.
    pub fn tun_session_restart_succeeded(&self) {
        self.tun_session_restart_succeeded.inc();
    }

    /// Records one failed TUN session restart attempt.
    pub fn tun_session_restart_failed(&self) {
        self.tun_session_restart_failed.inc();
    }

    /// Sets the currently published TUN session generation.
    pub fn set_tun_session_generation(&self, generation: u64) {
        self.tun_session_generation.set(u64_gauge(generation));
    }

    /// Marks one TUN session active.
    pub fn tun_session_active_inc(&self) {
        self.tun_session_active.inc();
    }

    /// Marks one TUN session inactive after a matching increment.
    pub fn tun_session_active_dec(&self) {
        self.tun_session_active.dec();
    }

    /// Sets whether the single owned TUN session is active.
    pub fn set_tun_session_active(&self, active: bool) {
        self.tun_session_active.set(i64::from(active));
    }

    /// Records one packet received from Wintun by the TUN owner.
    pub fn tun_packet_ingress(&self) {
        self.tun_packets_ingress.inc();
    }

    /// Records one packet sent successfully to Wintun by the TUN owner.
    pub fn tun_packet_egress(&self) {
        self.tun_packets_egress.inc();
    }

    /// Records one TUN packet rejection using only a closed reason code.
    pub fn tun_packet_rejected(&self, reason: TunPacketRejectReason) {
        self.tun_packets_rejected.metric(reason as usize).inc();
    }

    /// Records one observation of bounded internal egress backpressure.
    pub fn tun_internal_egress_backpressured(&self) {
        self.tun_internal_egress_backpressured.inc();
    }

    /// Sets whether one TUN UDP response is retained for owner-thread injection.
    pub fn set_tun_pending_udp_responses(&self, responses: usize) {
        debug_assert!(responses <= 1);
        self.tun_pending_udp_responses.set(usize_gauge(responses));
    }

    /// Records one terminal TUN UDP response drop.
    pub fn tun_udp_response_dropped(&self, reason: TunUdpResponseDropReason) {
        self.tun_udp_response_dropped.metric(reason as usize).inc();
    }

    /// Records one expected packet drop caused by a full Wintun send ring.
    pub fn tun_wintun_ring_full_dropped(&self) {
        self.tun_wintun_ring_full_dropped.inc();
    }

    /// Increments the active TUN TCP flow gauge.
    pub fn tun_tcp_flows_active_inc(&self) {
        self.tun_tcp_flows_active.inc();
    }

    /// Decrements the active TUN TCP flow gauge after a matching increment.
    pub fn tun_tcp_flows_active_dec(&self) {
        self.tun_tcp_flows_active.dec();
    }

    /// Sets the exact active TUN TCP flow count.
    pub fn set_tun_tcp_flows_active(&self, flows: usize) {
        self.tun_tcp_flows_active.set(usize_gauge(flows));
    }

    /// Records one TUN TCP flow rejected by the configured flow limit.
    pub fn tun_tcp_flow_rejected_limit(&self) {
        self.tun_tcp_flows_rejected_limit.inc();
    }

    /// Records one TUN TCP flow reset during session restart.
    pub fn tun_tcp_flow_reset_restart(&self) {
        self.tun_tcp_flows_reset_restart.inc();
    }

    /// Records one bounded wait caused by TUN TCP bridge backpressure.
    pub fn tun_tcp_bridge_blocked(&self) {
        self.tun_tcp_bridge_blocked.inc();
    }

    /// Increments the active TUN UDP association gauge.
    pub fn tun_udp_associations_active_inc(&self) {
        self.tun_udp_associations_active.inc();
    }

    /// Decrements the active TUN UDP association gauge after a matching increment.
    pub fn tun_udp_associations_active_dec(&self) {
        self.tun_udp_associations_active.dec();
    }

    /// Sets the exact active TUN UDP association count.
    pub fn set_tun_udp_associations_active(&self, associations: usize) {
        self.tun_udp_associations_active
            .set(usize_gauge(associations));
    }

    /// Increments the active uncommitted TUN UDP candidate gauge.
    pub fn tun_udp_candidates_active_inc(&self) {
        self.tun_udp_candidates_active.inc();
    }

    /// Decrements the active TUN UDP candidate gauge after a matching increment.
    pub fn tun_udp_candidates_active_dec(&self) {
        self.tun_udp_candidates_active.dec();
    }

    /// Sets the exact active uncommitted TUN UDP candidate count.
    pub fn set_tun_udp_candidates_active(&self, candidates: usize) {
        self.tun_udp_candidates_active.set(usize_gauge(candidates));
    }

    /// Records one committed TUN UDP association.
    pub fn tun_udp_association_created(&self) {
        self.tun_udp_association_created.inc();
    }

    /// Records one TUN UDP association rejected by the configured limit.
    pub fn tun_udp_association_rejected_limit(&self) {
        self.tun_udp_association_rejected_limit.inc();
    }

    /// Records one TUN UDP datagram dropped because its queue was full.
    pub fn tun_udp_datagram_queue_full(&self) {
        self.tun_udp_datagram_queue_full.inc();
    }

    /// Records one TUN UDP response dropped because the owner queue was full.
    pub fn tun_udp_response_queue_full(&self) {
        self.tun_udp_response_queue_full.inc();
    }

    /// Records one TUN UDP response rejected by endpoint filtering.
    pub fn tun_udp_response_filtered(&self) {
        self.tun_udp_response_filtered.inc();
    }

    /// Records TUN UDP work rejected after its session generation became stale.
    pub fn tun_udp_stale_generation(&self) {
        self.tun_udp_stale_generation.inc();
    }

    /// Increments the active TUN fragment reassembly entry gauge.
    pub fn tun_reassembly_entries_active_inc(&self) {
        self.tun_reassembly_entries_active.inc();
    }

    /// Decrements the reassembly entry gauge after a matching increment.
    pub fn tun_reassembly_entries_active_dec(&self) {
        self.tun_reassembly_entries_active.dec();
    }

    /// Sets the exact active TUN fragment reassembly entry count.
    pub fn set_tun_reassembly_entries_active(&self, entries: usize) {
        self.tun_reassembly_entries_active.set(usize_gauge(entries));
    }

    /// Records one newly allocated TUN fragment reassembly entry.
    pub fn tun_reassembly_started(&self) {
        self.tun_reassembly_started.inc();
    }

    /// Records one completed TUN fragment reassembly.
    pub fn tun_reassembly_completed(&self) {
        self.tun_reassembly_completed.inc();
    }

    /// Records one TUN fragment reassembly dropped for overlap.
    pub fn tun_reassembly_dropped_overlap(&self) {
        self.tun_reassembly_dropped_overlap.inc();
    }

    /// Records one TUN fragment reassembly dropped after timeout.
    pub fn tun_reassembly_dropped_timeout(&self) {
        self.tun_reassembly_dropped_timeout.inc();
    }

    /// Records one TUN fragment reassembly dropped by a bounded limit.
    pub fn tun_reassembly_dropped_limit(&self) {
        self.tun_reassembly_dropped_limit.inc();
    }

    /// Records one malformed TUN fragment reassembly drop.
    pub fn tun_reassembly_dropped_malformed(&self) {
        self.tun_reassembly_dropped_malformed.inc();
    }

    /// Records one semantic network change delivered to the TUN session.
    pub fn tun_network_change(&self) {
        self.tun_network_change.inc();
    }

    /// Records one underlay bind rejected because its generation was stale.
    pub fn tun_underlay_bind_stale(&self) {
        self.tun_underlay_bind_stale.inc();
    }

    pub fn connection(&self, role: Role, inbound: Inbound, outcome: Outcome) {
        self.connections
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
        self.active
            .metric(pair_index(role as usize, inbound as usize, INBOUNDS.len()))
            .inc();
    }

    pub fn active_connections_dec(&self, role: Role, inbound: Inbound) {
        self.active
            .metric(pair_index(role as usize, inbound as usize, INBOUNDS.len()))
            .dec();
    }

    pub fn failure(&self, role: Role, stage: Stage, reason: Reason) {
        self.failures
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
        self.bytes
            .metric(pair_index(
                role as usize,
                direction as usize,
                DIRECTIONS.len(),
            ))
            .inc_by(bytes);
    }

    pub fn set_replay_entries(&self, entries: u32) {
        self.replay_entries.set(i64::from(entries));
    }

    pub fn replay_rejection(&self, reason: Reason) {
        self.replay_rejections.metric(reason as usize).inc();
    }

    pub fn forced_shutdown(&self, role: Role) {
        self.forced_shutdowns.metric(role as usize).inc();
    }

    pub fn udp_sessions_active_inc(&self, role: Role) {
        self.udp_sessions_active.metric(role as usize).inc();
    }

    pub fn udp_sessions_active_dec(&self, role: Role) {
        self.udp_sessions_active.metric(role as usize).dec();
    }

    pub fn set_udp_sessions_active(&self, role: Role, sessions: usize) {
        let value = i64::try_from(sessions).unwrap_or(i64::MAX);
        self.udp_sessions_active.metric(role as usize).set(value);
    }

    pub fn udp_datagram(&self, role: Role, direction: Direction, outcome: Outcome) {
        self.udp_datagrams
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
        self.udp_failures
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
        self.udp_bytes
            .metric(pair_index(
                role as usize,
                direction as usize,
                DIRECTIONS.len(),
            ))
            .inc_by(bytes);
    }

    pub fn set_udp_buffered_bytes(&self, role: Role, bytes: usize) {
        let value = i64::try_from(bytes).unwrap_or(i64::MAX);
        self.udp_buffered_bytes.metric(role as usize).set(value);
    }

    pub fn udp_replay_rejection(&self, role: Role, direction: Direction, reason: Reason) {
        self.udp_replay_rejections
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
        self.udp_forced_shutdown.metric(role as usize).inc();
    }

    /// Records and traces exactly one closed tuple for an authenticated sniff.
    pub fn sniff(
        &self,
        role: Role,
        transport: Transport,
        outcome: SniffOutcome,
        protocol: SniffProtocol,
    ) {
        self.sniff
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
