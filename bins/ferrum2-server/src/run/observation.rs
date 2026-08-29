#[cfg(feature = "structural-metrics")]
use std::fmt::Write as _;
use std::sync::Arc;

use ferrum2_config::LoggingLevel;
use ferrum2_core::ConnectErrorKind;
use ferrum2_observability::{
    Direction, Event, Inbound, LogLevel, Metrics, Outcome, Reason, Role, SniffOutcome,
    SniffProtocol, Stage, TraceRecord, Transport, emit,
};
use ferrum2_runtime::{
    MetricsEndpoint, MetricsEndpointError, OwnerRegistry, PreparedProcessRoot, ProcessCancellation,
    ProcessFuture, RelayFailure, RelayRunError, SniffPrefixOutcome, SupervisorError,
    UdpRuntimeError,
};
use ferrum2_shadowsocks::{
    DetectionReason, FlowTerminal, PlainDuplex, ProtocolReason, ShadowsocksError, UdpPacketError,
};
use ferrum2_sniff::{Metadata as SniffMetadata, Progress as SniffProgress};
#[cfg(feature = "structural-metrics")]
use ferrum2_structural::{StructuralHub, StructuralSnapshot, StructuralUnit};
use tokio::net::TcpListener;

use super::RunError;
use super::tcp::ServerContext;
use ferrum2_shadowsocks::tokio::TokioFramed;

pub(super) struct ServerMetricsRoot {
    pub(super) listener: Option<TcpListener>,
    pub(super) metrics: Arc<Metrics>,
    pub(super) registry: OwnerRegistry,
    #[cfg(feature = "structural-metrics")]
    pub(super) structural: StructuralHub,
}

impl PreparedProcessRoot<RunError> for ServerMetricsRoot {
    fn activate(&mut self) -> Result<(), RunError> {
        Ok(())
    }

    fn run(
        mut self: Box<Self>,
        mut cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        let listener = self.listener.take().expect("prepared metrics root");
        let metrics = Arc::clone(&self.metrics);
        let registry = self.registry.clone();
        #[cfg(feature = "structural-metrics")]
        let structural = self.structural.clone();
        let endpoint = MetricsEndpoint::new(
            listener,
            move || {
                render_server_metrics(
                    &metrics,
                    &registry,
                    #[cfg(feature = "structural-metrics")]
                    &structural,
                )
            },
            self.registry.clone(),
        );
        Box::pin(async move {
            endpoint
                .run_until(cancellation.cancelled())
                .await
                .map_err(run_error_for_metrics)
        })
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async { Ok(()) })
    }
}

fn render_server_metrics(
    metrics: &Metrics,
    registry: &OwnerRegistry,
    #[cfg(feature = "structural-metrics")] structural: &StructuralHub,
) -> String {
    update_udp_resource_metrics(metrics, registry);
    let output = metrics.encode_text().unwrap_or_default();
    #[cfg(feature = "structural-metrics")]
    let output = {
        let mut output = output;
        if output.ends_with("# EOF\n") {
            output.truncate(output.len() - "# EOF\n".len());
        }
        append_structural_metrics(&mut output, &structural.snapshot());
        output.push_str("# EOF\n");
        output
    };
    output
}

#[cfg(feature = "structural-metrics")]
fn append_structural_metrics(output: &mut String, snapshot: &StructuralSnapshot) {
    for (counter, value) in snapshot.iter() {
        let unit = match counter.unit() {
            StructuralUnit::Count => "events",
            StructuralUnit::Bytes => "bytes",
            StructuralUnit::Nanoseconds => "nanoseconds",
        };
        write!(
            output,
            concat!(
                "# HELP ferrum2_structural_{} Closed structural performance evidence measured in {}.\n",
                "# TYPE ferrum2_structural_{} counter\n",
                "ferrum2_structural_{}_total {}\n",
            ),
            counter.name(),
            unit,
            counter.name(),
            counter.name(),
            value,
        )
        .expect("writing structural metrics to a String cannot fail");
    }
    write!(
        output,
        concat!(
            "# HELP ferrum2_structural_overflow Whether a structural counter saturated.\n",
            "# TYPE ferrum2_structural_overflow gauge\n",
            "ferrum2_structural_overflow {}\n",
        ),
        u8::from(snapshot.overflowed()),
    )
    .expect("writing structural overflow to a String cannot fail");
}

pub(super) fn run_error_for_supervisor(error: SupervisorError) -> RunError {
    match error {
        SupervisorError::ListenerFailure => RunError::RuntimeListener,
        SupervisorError::ChildFailure => RunError::RuntimeChild,
    }
}

fn run_error_for_metrics(error: MetricsEndpointError) -> RunError {
    match error {
        MetricsEndpointError::ListenerFailure => RunError::RuntimeListener,
        MetricsEndpointError::ChildFailure => RunError::RuntimeChild,
    }
}

pub(super) fn record_udp_request_accepted(metrics: &Metrics, wire_len: usize) {
    metrics.udp_datagram(Role::Server, Direction::ClientToTarget, Outcome::Accepted);
    metrics.add_udp_bytes(Role::Server, Direction::ClientToTarget, wire_len as u64);
}

pub(super) fn record_sniff(
    metrics: &Metrics,
    transport: Transport,
    progress: SniffProgress,
    collector: Option<SniffPrefixOutcome>,
) {
    let (outcome, protocol) = sniff_observation(progress, collector);
    metrics.sniff(Role::Server, transport, outcome, protocol);
}

fn sniff_observation(
    progress: SniffProgress,
    collector: Option<SniffPrefixOutcome>,
) -> (SniffOutcome, SniffProtocol) {
    match collector {
        Some(SniffPrefixOutcome::Timeout) => return (SniffOutcome::Timeout, SniffProtocol::None),
        Some(SniffPrefixOutcome::Limit) => return (SniffOutcome::Limit, SniffProtocol::None),
        Some(
            SniffPrefixOutcome::Cancelled
            | SniffPrefixOutcome::ReadError
            | SniffPrefixOutcome::Unavailable,
        ) => return (SniffOutcome::Unavailable, SniffProtocol::None),
        Some(SniffPrefixOutcome::Complete) | None => {}
    }
    match progress {
        SniffProgress::Matched(SniffMetadata::Dns { .. }) => {
            (SniffOutcome::Matched, SniffProtocol::Dns)
        }
        SniffProgress::Matched(SniffMetadata::Tls { .. }) => {
            (SniffOutcome::Matched, SniffProtocol::Tls)
        }
        SniffProgress::Matched(SniffMetadata::Http { .. }) => {
            (SniffOutcome::Matched, SniffProtocol::Http)
        }
        SniffProgress::NoMatch | SniffProgress::NeedMore => {
            (SniffOutcome::Unknown, SniffProtocol::None)
        }
        SniffProgress::Invalid => (SniffOutcome::Invalid, SniffProtocol::None),
    }
}

pub(super) fn update_udp_resource_metrics(metrics: &Metrics, registry: &OwnerRegistry) {
    let snapshot = registry.snapshot();
    metrics.set_udp_sessions_active(Role::Server, snapshot.udp_sessions);
    metrics.set_udp_buffered_bytes(Role::Server, snapshot.udp_buffered_bytes);
}

pub(super) fn record_udp_protocol_failure(metrics: &Metrics, error: UdpPacketError) {
    let reason = match error {
        UdpPacketError::Bounds => Reason::Bounds,
        UdpPacketError::Authentication => Reason::Authentication,
        UdpPacketError::Type => Reason::Type,
        UdpPacketError::Clock => Reason::Clock,
        UdpPacketError::Timestamp => Reason::Timestamp,
        UdpPacketError::Address => Reason::Address,
        UdpPacketError::Padding => Reason::Padding,
        UdpPacketError::Binding => Reason::Binding,
        UdpPacketError::Duplicate => Reason::Duplicate,
        UdpPacketError::TooOld => Reason::TooOld,
        UdpPacketError::AssociationLimit | UdpPacketError::Generation => Reason::SessionLimit,
        UdpPacketError::Key => Reason::Key,
        UdpPacketError::Random => Reason::Random,
        UdpPacketError::Counter => Reason::Counter,
        UdpPacketError::StateUnavailable => Reason::Cancelled,
    };
    let outcome = match error {
        UdpPacketError::Authentication
        | UdpPacketError::Type
        | UdpPacketError::Timestamp
        | UdpPacketError::Address
        | UdpPacketError::Padding
        | UdpPacketError::Binding
        | UdpPacketError::Duplicate
        | UdpPacketError::TooOld => Outcome::Rejected,
        _ => Outcome::Failed,
    };
    if matches!(error, UdpPacketError::Duplicate | UdpPacketError::TooOld) {
        metrics.udp_replay_rejection(Role::Server, Direction::ClientToTarget, reason);
    }
    record_udp_failure(metrics, Stage::Shadowsocks, reason, outcome);
}

pub(super) fn record_udp_runtime_failure(metrics: &Metrics, error: UdpRuntimeError) {
    let reason = match error {
        UdpRuntimeError::Bounds => Reason::Bounds,
        UdpRuntimeError::SessionLimit => Reason::SessionLimit,
        UdpRuntimeError::BufferLimit => Reason::BufferLimit,
        UdpRuntimeError::QueueFull => Reason::QueueFull,
        UdpRuntimeError::Counter => Reason::Counter,
        UdpRuntimeError::Resolve => Reason::Resolve,
        UdpRuntimeError::Send => Reason::Send,
        UdpRuntimeError::Receive => Reason::Receive,
        UdpRuntimeError::Idle => Reason::Idle,
        UdpRuntimeError::Cancelled => Reason::Cancelled,
    };
    let stage = match error {
        UdpRuntimeError::Resolve | UdpRuntimeError::Send | UdpRuntimeError::Receive => {
            Stage::Direct
        }
        UdpRuntimeError::Idle | UdpRuntimeError::Cancelled => Stage::Shutdown,
        _ => Stage::Relay,
    };
    record_udp_failure(metrics, stage, reason, Outcome::Failed);
}

pub(super) fn record_udp_failure(
    metrics: &Metrics,
    stage: Stage,
    reason: Reason,
    outcome: Outcome,
) {
    metrics.udp_failure(Role::Server, stage, reason);
    emit(
        TraceRecord::new(LogLevel::Warn, Event::Failure, Role::Server, stage, outcome)
            .udp()
            .with_reason(reason),
    );
}

pub(super) fn update_replay_metric(context: &ServerContext) {
    if let Ok(entries) = context.replay.entry_count()
        && let Ok(entries) = u32::try_from(entries)
    {
        context.metrics.set_replay_entries(entries);
    }
}

pub(super) fn finish_relay(
    context: &ServerContext,
    framed: &TokioFramed<impl PlainDuplex>,
    initial_payload_bytes: u64,
    result: Result<ferrum2_runtime::RelayStats, RelayFailure>,
) {
    let stats = match result {
        Ok(stats) => stats,
        Err(failure) => failure.stats,
    };
    context.metrics.add_bytes(
        Role::Server,
        Direction::InboundToOutbound,
        initial_payload_bytes + stats.inbound_to_outbound,
    );
    context.metrics.add_bytes(
        Role::Server,
        Direction::OutboundToInbound,
        stats.outbound_to_inbound,
    );
    match result {
        Ok(_) => {
            context
                .metrics
                .connection(Role::Server, Inbound::Shadowsocks, Outcome::Completed);
            let (stage, outcome, reason) = framed
                .terminal()
                .map(observation_for_terminal)
                .unwrap_or((Stage::Relay, Outcome::Completed, None));
            emit_observation(Role::Server, stage, outcome, reason);
        }
        Err(RelayFailure {
            kind: RelayRunError::Cancelled,
            ..
        }) => {
            record_failure(context, Stage::Relay, Reason::Cancelled, Outcome::Cancelled);
        }
        Err(RelayFailure {
            kind: RelayRunError::IdleTimeout,
            ..
        }) => {
            record_failure(context, Stage::Relay, Reason::IdleTimeout, Outcome::Timeout);
        }
        Err(RelayFailure {
            kind: RelayRunError::Io,
            ..
        }) => {
            if let Some(terminal) = framed.terminal() {
                let (stage, outcome, reason) = observation_for_terminal(terminal);
                emit_observation(Role::Server, stage, outcome, reason);
                if let Some(reason) = reason {
                    context.metrics.failure(Role::Server, stage, reason);
                }
            } else {
                record_failure(context, Stage::Relay, Reason::RelayIo, Outcome::Failed);
            }
        }
    }
}

pub(super) fn record_failure(
    context: &ServerContext,
    stage: Stage,
    reason: Reason,
    outcome: Outcome,
) {
    context.metrics.failure(Role::Server, stage, reason);
    if matches!(reason, Reason::Replay | Reason::ReplayCapacity) {
        context.metrics.replay_rejection(reason);
    }
    emit_observation(Role::Server, stage, outcome, Some(reason));
}

fn emit_observation(role: Role, stage: Stage, outcome: Outcome, reason: Option<Reason>) {
    let record = TraceRecord::new(LogLevel::Warn, Event::Failure, role, stage, outcome);
    emit(match reason {
        Some(reason) => record.with_reason(reason),
        None => record,
    });
}

pub(super) fn log_level(level: LoggingLevel) -> LogLevel {
    match level {
        LoggingLevel::Error => LogLevel::Error,
        LoggingLevel::Warn => LogLevel::Warn,
        LoggingLevel::Info => LogLevel::Info,
        LoggingLevel::Debug => LogLevel::Debug,
        LoggingLevel::Trace => LogLevel::Trace,
    }
}

pub(super) fn observation_for_error(error: ShadowsocksError) -> (Stage, Outcome, Reason) {
    match error {
        ShadowsocksError::Connect(kind) => (
            Stage::Shadowsocks,
            Outcome::Failed,
            reason_for_connect(kind),
        ),
        ShadowsocksError::Detection(reason) => (
            Stage::Shadowsocks,
            Outcome::Rejected,
            reason_for_detection(reason),
        ),
        ShadowsocksError::Protocol(reason) => (
            Stage::Shadowsocks,
            Outcome::Rejected,
            reason_for_protocol(reason),
        ),
        ShadowsocksError::Transport(_) => (Stage::Relay, Outcome::Failed, Reason::RelayIo),
    }
}

pub(super) fn observation_for_direct_connect(kind: ConnectErrorKind) -> (Stage, Outcome, Reason) {
    (Stage::Direct, Outcome::Failed, reason_for_connect(kind))
}

fn observation_for_terminal(terminal: FlowTerminal) -> (Stage, Outcome, Option<Reason>) {
    match terminal {
        FlowTerminal::Normal => (Stage::Relay, Outcome::Completed, None),
        FlowTerminal::Detection(reason) => (
            Stage::Shadowsocks,
            Outcome::Rejected,
            Some(reason_for_detection(reason)),
        ),
        FlowTerminal::Protocol(reason) => (
            Stage::Shadowsocks,
            Outcome::Rejected,
            Some(reason_for_protocol(reason)),
        ),
        FlowTerminal::Transport(_) => (Stage::Relay, Outcome::Failed, Some(Reason::RelayIo)),
    }
}

fn reason_for_detection(reason: DetectionReason) -> Reason {
    match reason {
        DetectionReason::ShortRead
        | DetectionReason::ShortWrite
        | DetectionReason::Authentication
        | DetectionReason::KeyUnavailable => Reason::Authentication,
        DetectionReason::InvalidType => Reason::InvalidType,
        DetectionReason::TimestampSkew => Reason::TimestampSkew,
        DetectionReason::FrameBounds
        | DetectionReason::PaddingBounds
        | DetectionReason::EmptyRequest => Reason::FrameBounds,
        DetectionReason::AddressBounds => Reason::AddressBounds,
        DetectionReason::ResponseBinding => Reason::ResponseBinding,
        DetectionReason::ClockUnavailable => Reason::ClockUnavailable,
        DetectionReason::RandomUnavailable => Reason::RandomUnavailable,
        DetectionReason::Replay => Reason::Replay,
        DetectionReason::ReplayCapacity => Reason::ReplayCapacity,
        DetectionReason::ReplayUnavailable
        | DetectionReason::ReadFailed
        | DetectionReason::WriteFailed => Reason::RelayIo,
    }
}

fn reason_for_protocol(reason: ProtocolReason) -> Reason {
    match reason {
        ProtocolReason::Authentication => Reason::Authentication,
        ProtocolReason::FrameBounds => Reason::FrameBounds,
        ProtocolReason::NonceExhausted => Reason::NonceExhausted,
    }
}

fn reason_for_connect(kind: ConnectErrorKind) -> Reason {
    match kind {
        ConnectErrorKind::NetworkUnreachable => Reason::NetworkUnreachable,
        ConnectErrorKind::HostUnreachable => Reason::HostUnreachable,
        ConnectErrorKind::ConnectionRefused => Reason::ConnectionRefused,
        ConnectErrorKind::PolicyDenied => Reason::RelayIo,
        ConnectErrorKind::Timeout => Reason::ConnectTimeout,
        ConnectErrorKind::Other => Reason::RelayIo,
    }
}

#[cfg(test)]
mod tests {
    use ferrum2_observability::{SniffOutcome, SniffProtocol};
    use ferrum2_runtime::SniffPrefixOutcome;
    use ferrum2_shadowsocks::TransportPhase;
    use ferrum2_sniff::{Metadata as SniffMetadata, Progress as SniffProgress};
    #[cfg(feature = "structural-metrics")]
    use ferrum2_structural::StructuralCounter;

    use super::*;

    #[cfg(not(feature = "structural-metrics"))]
    #[test]
    fn default_metrics_render_has_no_structural_families() {
        let output = render_server_metrics(&Metrics::new(), &OwnerRegistry::new());
        assert!(!output.contains("ferrum2_structural_"));
    }

    #[cfg(feature = "structural-metrics")]
    #[test]
    fn structural_metrics_render_exact_fixed_unlabelled_values() {
        let structural = StructuralHub::new();
        let local = structural.local();
        local.add(StructuralCounter::FtbrBorrowedDownloadFrames, 7);
        local.add(StructuralCounter::AdmissionLockWaitNanoseconds, 19);

        let output = render_server_metrics(&Metrics::new(), &OwnerRegistry::new(), &structural);
        assert!(output.contains(concat!(
            "# HELP ferrum2_structural_tcp_fused_borrowed_download_frames Closed structural performance evidence measured in events.\n",
            "# TYPE ferrum2_structural_tcp_fused_borrowed_download_frames counter\n",
            "ferrum2_structural_tcp_fused_borrowed_download_frames_total 7\n",
        )));
        assert!(output.contains("ferrum2_structural_admission_lock_wait_nanoseconds_total 19\n"));
        assert!(output.contains("ferrum2_structural_overflow 0\n"));
        assert_eq!(
            output.matches("# TYPE ferrum2_structural_").count(),
            StructuralCounter::COUNT + 1
        );
        assert_eq!(output.matches("# EOF").count(), 1);
        for line in output
            .lines()
            .filter(|line| line.starts_with("ferrum2_structural_"))
        {
            assert!(!line.contains('{'), "structural samples have no labels");
            assert!(!line.contains("structural-private-peer.example"));
        }
    }

    #[test]
    fn adapter_contract_observability_mapping_is_exhaustive_and_call_site_specific() {
        for (kind, expected) in [
            (
                ConnectErrorKind::NetworkUnreachable,
                Reason::NetworkUnreachable,
            ),
            (ConnectErrorKind::HostUnreachable, Reason::HostUnreachable),
            (
                ConnectErrorKind::ConnectionRefused,
                Reason::ConnectionRefused,
            ),
            (ConnectErrorKind::PolicyDenied, Reason::RelayIo),
            (ConnectErrorKind::Timeout, Reason::ConnectTimeout),
            (ConnectErrorKind::Other, Reason::RelayIo),
        ] {
            assert_eq!(reason_for_connect(kind), expected);
            assert_eq!(
                observation_for_direct_connect(kind),
                (Stage::Direct, Outcome::Failed, expected)
            );
        }
        for (reason, expected) in detection_cases() {
            assert_eq!(reason_for_detection(reason), expected);
            assert_eq!(
                observation_for_error(ShadowsocksError::Detection(reason)),
                (Stage::Shadowsocks, Outcome::Rejected, expected)
            );
        }
        for (reason, expected) in [
            (ProtocolReason::Authentication, Reason::Authentication),
            (ProtocolReason::FrameBounds, Reason::FrameBounds),
            (ProtocolReason::NonceExhausted, Reason::NonceExhausted),
        ] {
            assert_eq!(reason_for_protocol(reason), expected);
            assert_eq!(
                observation_for_terminal(FlowTerminal::Protocol(reason)),
                (Stage::Shadowsocks, Outcome::Rejected, Some(expected))
            );
        }
        for phase in [
            TransportPhase::Read,
            TransportPhase::Write,
            TransportPhase::WriteZero,
            TransportPhase::Flush,
            TransportPhase::Shutdown,
        ] {
            assert_eq!(
                observation_for_terminal(FlowTerminal::Transport(phase)),
                (Stage::Relay, Outcome::Failed, Some(Reason::RelayIo))
            );
        }
        assert_eq!(
            observation_for_terminal(FlowTerminal::Normal),
            (Stage::Relay, Outcome::Completed, None)
        );
    }

    #[test]
    fn sniff_observation_mapping_keeps_parser_and_collector_outcomes_closed() {
        for (progress, collector, expected) in [
            (
                SniffProgress::Matched(SniffMetadata::Dns {
                    domain: "secret.example".to_owned(),
                }),
                None,
                (SniffOutcome::Matched, SniffProtocol::Dns),
            ),
            (
                SniffProgress::Matched(SniffMetadata::Tls {
                    domain: Some("outer.example".to_owned()),
                }),
                Some(SniffPrefixOutcome::Complete),
                (SniffOutcome::Matched, SniffProtocol::Tls),
            ),
            (
                SniffProgress::Matched(SniffMetadata::Http {
                    domain: Some("host.example".to_owned()),
                }),
                None,
                (SniffOutcome::Matched, SniffProtocol::Http),
            ),
            (
                SniffProgress::NoMatch,
                None,
                (SniffOutcome::Unknown, SniffProtocol::None),
            ),
            (
                SniffProgress::Invalid,
                None,
                (SniffOutcome::Invalid, SniffProtocol::None),
            ),
            (
                SniffProgress::NeedMore,
                Some(SniffPrefixOutcome::Timeout),
                (SniffOutcome::Timeout, SniffProtocol::None),
            ),
            (
                SniffProgress::NeedMore,
                Some(SniffPrefixOutcome::Limit),
                (SniffOutcome::Limit, SniffProtocol::None),
            ),
            (
                SniffProgress::NeedMore,
                Some(SniffPrefixOutcome::ReadError),
                (SniffOutcome::Unavailable, SniffProtocol::None),
            ),
            (
                SniffProgress::NeedMore,
                Some(SniffPrefixOutcome::Cancelled),
                (SniffOutcome::Unavailable, SniffProtocol::None),
            ),
            (
                SniffProgress::NeedMore,
                Some(SniffPrefixOutcome::Unavailable),
                (SniffOutcome::Unavailable, SniffProtocol::None),
            ),
        ] {
            assert_eq!(sniff_observation(progress, collector), expected);
        }
    }

    fn detection_cases() -> [(DetectionReason, Reason); 18] {
        [
            (DetectionReason::ShortRead, Reason::Authentication),
            (DetectionReason::ShortWrite, Reason::Authentication),
            (DetectionReason::Authentication, Reason::Authentication),
            (DetectionReason::InvalidType, Reason::InvalidType),
            (DetectionReason::TimestampSkew, Reason::TimestampSkew),
            (DetectionReason::FrameBounds, Reason::FrameBounds),
            (DetectionReason::AddressBounds, Reason::AddressBounds),
            (DetectionReason::PaddingBounds, Reason::FrameBounds),
            (DetectionReason::EmptyRequest, Reason::FrameBounds),
            (DetectionReason::ResponseBinding, Reason::ResponseBinding),
            (DetectionReason::KeyUnavailable, Reason::Authentication),
            (DetectionReason::ClockUnavailable, Reason::ClockUnavailable),
            (
                DetectionReason::RandomUnavailable,
                Reason::RandomUnavailable,
            ),
            (DetectionReason::Replay, Reason::Replay),
            (DetectionReason::ReplayCapacity, Reason::ReplayCapacity),
            (DetectionReason::ReplayUnavailable, Reason::RelayIo),
            (DetectionReason::ReadFailed, Reason::RelayIo),
            (DetectionReason::WriteFailed, Reason::RelayIo),
        ]
    }
}
