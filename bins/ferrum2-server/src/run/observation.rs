use std::sync::Arc;

use ferrum2_config::LoggingLevel;
use ferrum2_core::ConnectErrorKind;
use ferrum2_observability::{
    Direction, Event, Inbound, LogLevel, Metrics, Outcome, Reason, Role, Stage, TraceRecord, emit,
};
use ferrum2_runtime::{
    MetricsEndpoint, MetricsEndpointError, OwnerRegistry, PreparedProcessRoot, ProcessCancellation,
    ProcessFuture, RelayFailure, RelayRunError, SupervisorError, UdpRuntimeError,
};
use ferrum2_shadowsocks::{
    DetectionReason, FlowTerminal, PlainDuplex, ProtocolReason, ShadowsocksError, UdpPacketError,
};
use tokio::net::TcpListener;

use super::RunError;
use super::tcp::ServerContext;
use super::tokio_io::TokioFramed;

pub(super) struct ServerMetricsRoot {
    pub(super) listener: Option<TcpListener>,
    pub(super) metrics: Arc<Metrics>,
    pub(super) registry: OwnerRegistry,
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
        let endpoint = MetricsEndpoint::new(
            listener,
            move || {
                update_udp_resource_metrics(&metrics, &registry);
                metrics.encode_text().unwrap_or_default()
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
        ConnectErrorKind::Timeout => Reason::ConnectTimeout,
        ConnectErrorKind::Other => Reason::RelayIo,
    }
}

#[cfg(test)]
mod tests {
    use ferrum2_shadowsocks::TransportPhase;

    use super::*;

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
