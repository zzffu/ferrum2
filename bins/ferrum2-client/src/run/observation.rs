use std::fmt::Write as _;
use std::sync::Arc;

use ferrum2_config::{LoggingLevel, ValidatedClientConfig};
use ferrum2_core::ConnectErrorKind;
use ferrum2_dns::{
    DnsPolicyMatchResult, DnsPolicyMatchSource, DnsPolicyMatchType, DnsPolicyObservation,
    DnsPolicyObserver, DnsPolicyStage,
};
use ferrum2_observability::{
    Direction, Event, Inbound, LogLevel, Metrics, Outcome, Reason, Role, RuleMatchResult,
    RuleMatchType, RuleProgram, RuleProgramMode, RuleSource, SniffOutcome, SniffProtocol, Stage,
    TraceRecord, Transport, emit,
};
use ferrum2_runtime::{
    MetricsEndpoint, MetricsEndpointError, OwnerRegistry, PreparedProcessRoot, ProcessCancellation,
    ProcessFuture, RelayFailure, RelayRunError, SupervisorError, UdpRuntimeError,
};
use ferrum2_shadowsocks::{
    DetectionReason, FlowTerminal, PlainDuplex, ProtocolReason, ShadowsocksError, UdpPacketError,
};
use ferrum2_sniff::{Metadata as SniffMetadata, Progress as SniffProgress};
use tokio::net::TcpListener;

use super::RunError;
use super::context::ClientContext;
use ferrum2_shadowsocks::tokio::TokioFramed;

pub(super) fn record_forced_udp_sessions(context: &ClientContext) {
    for _ in 0..context.registry.snapshot().udp_sessions {
        context.metrics.udp_forced_shutdown(Role::Client);
    }
}

pub(super) fn record_sniff(metrics: &Metrics, progress: SniffProgress, limited: bool) {
    let (outcome, protocol) = if limited {
        (SniffOutcome::Limit, SniffProtocol::None)
    } else {
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
    };
    metrics.sniff(Role::Client, Transport::Udp, outcome, protocol);
}

pub(super) struct ClientMetricsRoot {
    pub(super) listener: Option<TcpListener>,
    pub(super) metrics: Arc<Metrics>,
    pub(super) registry: OwnerRegistry,
}

impl PreparedProcessRoot<RunError> for ClientMetricsRoot {
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
            move || render_client_metrics(&metrics, &registry),
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

fn render_client_metrics(metrics: &Metrics, registry: &OwnerRegistry) -> String {
    let snapshot = registry.snapshot();
    metrics.set_udp_sessions_active(Role::Client, snapshot.udp_sessions);
    metrics.set_udp_buffered_bytes(Role::Client, snapshot.udp_buffered_bytes);
    let mut output = metrics.encode_text().unwrap_or_default();
    if output.ends_with("# EOF\n") {
        output.truncate(output.len() - "# EOF\n".len());
    }
    write!(
        output,
        concat!(
            "# HELP ferrum2_process_roots_active Process roots currently owned by the client supervisor.\n",
            "# TYPE ferrum2_process_roots_active gauge\n",
            "ferrum2_process_roots_active{{role=\"client\"}} {}\n",
            "# HELP ferrum2_process_roots_forced Process roots forced after a shutdown grace deadline.\n",
            "# TYPE ferrum2_process_roots_forced counter\n",
            "ferrum2_process_roots_forced_total{{role=\"client\"}} {}\n",
            "# HELP ferrum2_tun_handler_tasks_active Handler tasks currently owned by the TUN process root.\n",
            "# TYPE ferrum2_tun_handler_tasks_active gauge\n",
            "ferrum2_tun_handler_tasks_active{{role=\"client\"}} {}\n",
            "# HELP ferrum2_tun_tcp_flows_active TCP flows currently owned by the TUN foundation stack.\n",
            "# TYPE ferrum2_tun_tcp_flows_active gauge\n",
            "ferrum2_tun_tcp_flows_active{{role=\"client\"}} {}\n",
            "# EOF\n",
        ),
        snapshot.active_process_roots,
        snapshot.process_forced_roots,
        snapshot.active_tun_handler_tasks,
        snapshot.active_tun_tcp_flows,
    )
    .expect("writing owner metrics to a String cannot fail");
    output
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

pub(super) fn record_udp_drop(
    context: &ClientContext,
    direction: Direction,
    stage: Stage,
    reason: Reason,
) {
    context
        .metrics
        .udp_datagram(Role::Client, direction, Outcome::Rejected);
    context.metrics.udp_failure(Role::Client, stage, reason);
}

pub(super) fn record_udp_terminal(
    context: &ClientContext,
    stage: Stage,
    reason: Reason,
    outcome: Outcome,
) {
    context.metrics.udp_failure(Role::Client, stage, reason);
    emit_observation(Role::Client, stage, outcome, Some(reason));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UdpPacketPhase {
    RequestEncode,
    ResponsePrepare,
    #[cfg(test)]
    ResponseCommit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UdpPacketPolicy {
    pub(super) reason: Reason,
    pub(super) terminal: bool,
    pub(super) replay: bool,
}

fn udp_packet_policy(phase: UdpPacketPhase, error: UdpPacketError) -> UdpPacketPolicy {
    let (reason, terminal, replay) = match (phase, error) {
        (
            _,
            UdpPacketError::Bounds
            | UdpPacketError::Authentication
            | UdpPacketError::Type
            | UdpPacketError::Timestamp
            | UdpPacketError::Address
            | UdpPacketError::Padding
            | UdpPacketError::Binding,
        ) => (
            match error {
                UdpPacketError::Bounds => Reason::Bounds,
                UdpPacketError::Authentication => Reason::Authentication,
                UdpPacketError::Type => Reason::Type,
                UdpPacketError::Timestamp => Reason::Timestamp,
                UdpPacketError::Address => Reason::Address,
                UdpPacketError::Padding => Reason::Padding,
                UdpPacketError::Binding => Reason::Binding,
                UdpPacketError::Clock
                | UdpPacketError::Duplicate
                | UdpPacketError::TooOld
                | UdpPacketError::AssociationLimit
                | UdpPacketError::Generation
                | UdpPacketError::Key
                | UdpPacketError::Random
                | UdpPacketError::Counter
                | UdpPacketError::StateUnavailable => unreachable!("outer pattern is closed"),
            },
            false,
            false,
        ),
        (_, UdpPacketError::Duplicate) => (Reason::Duplicate, false, true),
        (_, UdpPacketError::TooOld) => (Reason::TooOld, false, true),
        (_, UdpPacketError::AssociationLimit) => (Reason::SessionLimit, false, false),
        (_, UdpPacketError::Clock) => (Reason::Clock, true, false),
        (_, UdpPacketError::Key) => (Reason::Key, true, false),
        (_, UdpPacketError::Random) => (Reason::Random, true, false),
        (_, UdpPacketError::Counter) => (Reason::Counter, true, false),
        (_, UdpPacketError::Generation | UdpPacketError::StateUnavailable) => {
            (Reason::RelayIo, true, false)
        }
    };
    UdpPacketPolicy {
        reason,
        terminal,
        replay,
    }
}

pub(super) fn record_udp_packet_error(
    context: &ClientContext,
    direction: Direction,
    phase: UdpPacketPhase,
    error: UdpPacketError,
) -> bool {
    let policy = udp_packet_policy(phase, error);
    record_udp_packet_metrics(&context.metrics, direction, policy);
    if policy.terminal {
        emit_observation(
            Role::Client,
            Stage::Shadowsocks,
            Outcome::Failed,
            Some(policy.reason),
        );
    } else {
        emit_observation(
            Role::Client,
            Stage::Shadowsocks,
            Outcome::Rejected,
            Some(policy.reason),
        );
    }
    !policy.terminal
}

fn record_udp_packet_metrics(metrics: &Metrics, direction: Direction, policy: UdpPacketPolicy) {
    metrics.udp_failure(Role::Client, Stage::Shadowsocks, policy.reason);
    if !policy.terminal {
        metrics.udp_datagram(Role::Client, direction, Outcome::Rejected);
    }
    if policy.replay {
        metrics.udp_replay_rejection(Role::Client, direction, policy.reason);
    }
}

pub(super) fn record_udp_runtime_error(
    context: &ClientContext,
    direction: Direction,
    error: UdpRuntimeError,
) -> bool {
    let (reason, terminal) = match error {
        UdpRuntimeError::Bounds => (Reason::Bounds, false),
        UdpRuntimeError::SessionLimit => (Reason::SessionLimit, false),
        UdpRuntimeError::BufferLimit => (Reason::BufferLimit, false),
        UdpRuntimeError::QueueFull => (Reason::QueueFull, false),
        UdpRuntimeError::Counter => (Reason::Counter, true),
        UdpRuntimeError::Resolve => (Reason::Resolve, true),
        UdpRuntimeError::Send => (Reason::Send, true),
        UdpRuntimeError::Receive => (Reason::Receive, true),
        UdpRuntimeError::Idle => (Reason::Idle, true),
        UdpRuntimeError::Cancelled => (Reason::Cancelled, true),
    };
    if terminal {
        record_udp_terminal(context, Stage::Relay, reason, Outcome::Failed);
    } else {
        record_udp_drop(context, direction, Stage::Relay, reason);
    }
    !terminal
}

pub(super) fn finish_relay(
    context: &ClientContext,
    framed: &TokioFramed<impl PlainDuplex>,
    result: Result<ferrum2_runtime::RelayStats, RelayFailure>,
) {
    let stats = match result {
        Ok(stats) => stats,
        Err(failure) => failure.stats,
    };
    context.metrics.add_bytes(
        Role::Client,
        Direction::InboundToOutbound,
        stats.inbound_to_outbound,
    );
    context.metrics.add_bytes(
        Role::Client,
        Direction::OutboundToInbound,
        stats.outbound_to_inbound,
    );
    match result {
        Ok(_) => {
            context
                .metrics
                .connection(Role::Client, Inbound::Socks5, Outcome::Completed);
            let (stage, outcome, reason) = framed
                .terminal()
                .map(observation_for_terminal)
                .unwrap_or((Stage::Relay, Outcome::Completed, None));
            emit_observation(Role::Client, stage, outcome, reason);
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
                emit_observation(Role::Client, stage, outcome, reason);
                if let Some(reason) = reason {
                    context.metrics.failure(Role::Client, stage, reason);
                }
            } else {
                record_failure(context, Stage::Relay, Reason::RelayIo, Outcome::Failed);
            }
        }
    }
}

pub(super) fn record_failure(
    context: &ClientContext,
    stage: Stage,
    reason: Reason,
    outcome: Outcome,
) {
    context.metrics.failure(Role::Client, stage, reason);
    emit_observation(Role::Client, stage, outcome, Some(reason));
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

pub(super) fn publish_rule_program_metadata(config: &ValidatedClientConfig, metrics: &Metrics) {
    metrics.set_rule_program_mode(
        RuleProgram::Route,
        rule_program_mode(config.route.program_mode()),
    );
    metrics.set_rule_program_rules(RuleProgram::Route, config.route.rule_count());
    let Some(dns) = config.dns_route.as_ref() else {
        return;
    };
    if let Some(binding) = dns.policy_blueprint() {
        let blueprint = binding.blueprint();
        metrics.set_rule_program_mode(RuleProgram::DnsQuery, rule_program_mode(dns.program_mode()));
        metrics.set_rule_program_rules(RuleProgram::DnsQuery, blueprint.len());
        metrics.set_rule_program_mode(
            RuleProgram::DnsResponse,
            rule_program_mode(dns.program_mode()),
        );
        metrics.set_rule_program_rules(RuleProgram::DnsResponse, blueprint.response_rule_count());
    } else {
        metrics.set_rule_program_mode(RuleProgram::DnsQuery, rule_program_mode(dns.program_mode()));
        metrics.set_rule_program_rules(RuleProgram::DnsQuery, dns.rule_count());
        metrics.set_rule_program_mode(RuleProgram::DnsResponse, RuleProgramMode::SmallLinear);
        metrics.set_rule_program_rules(RuleProgram::DnsResponse, 0);
    }
}

const fn rule_program_mode(mode: ferrum2_rule::RuleProgramMode) -> RuleProgramMode {
    match mode {
        ferrum2_rule::RuleProgramMode::SmallLinear => RuleProgramMode::SmallLinear,
        ferrum2_rule::RuleProgramMode::Indexed => RuleProgramMode::Indexed,
    }
}

pub(super) fn dns_policy_observer(metrics: &Arc<Metrics>) -> Arc<dyn DnsPolicyObserver> {
    let metrics = Arc::clone(metrics);
    Arc::new(move |observation| observe_dns_policy(&metrics, observation))
}

fn observe_dns_policy(metrics: &Metrics, observation: DnsPolicyObservation) {
    if observation.query_evaluated() {
        metrics.observe_rule_program_candidate_count(
            RuleProgram::DnsQuery,
            observation.query_candidates(),
        );
        metrics.observe_rule_program_match_ns(RuleProgram::DnsQuery, observation.query_match_ns());
    }
    if observation.response_evaluated() {
        metrics.observe_rule_program_candidate_count(
            RuleProgram::DnsResponse,
            observation.response_candidates(),
        );
        metrics.observe_rule_program_match_ns(
            RuleProgram::DnsResponse,
            observation.response_match_ns(),
        );
    }
    for stage in DnsPolicyStage::ALL {
        for source in DnsPolicyMatchSource::ALL {
            for r#type in DnsPolicyMatchType::ALL {
                for result in DnsPolicyMatchResult::ALL {
                    let count = observation.match_count(stage, source, r#type, result);
                    if count == 0 {
                        continue;
                    }
                    let source = match source {
                        DnsPolicyMatchSource::Inline => RuleSource::Inline,
                        DnsPolicyMatchSource::RuleSet => RuleSource::RuleSet,
                    };
                    let r#type = match r#type {
                        DnsPolicyMatchType::Domain => RuleMatchType::Domain,
                        DnsPolicyMatchType::DomainSuffix => RuleMatchType::DomainSuffix,
                        DnsPolicyMatchType::DomainKeyword => RuleMatchType::DomainKeyword,
                        DnsPolicyMatchType::IpCidr => RuleMatchType::IpCidr,
                        DnsPolicyMatchType::Scalar => RuleMatchType::Scalar,
                    };
                    let result = match result {
                        DnsPolicyMatchResult::Matched => RuleMatchResult::Matched,
                        DnsPolicyMatchResult::Missed => RuleMatchResult::Missed,
                    };
                    match stage {
                        DnsPolicyStage::Query => {
                            metrics.dns_rule_query_matches(source, r#type, result, count);
                        }
                        DnsPolicyStage::Response => {
                            metrics.dns_rule_response_matches(source, r#type, result, count);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ferrum2_shadowsocks::{TransportPhase, UDP_REPLAY_LAG, UdpReplayWindow};

    use super::*;
    use crate::run::test_support::*;

    #[test]
    fn udp_packet_error_policy_is_closed_for_every_phase_and_variant() {
        let rows = [
            (UdpPacketError::Bounds, Reason::Bounds, false, false),
            (
                UdpPacketError::Authentication,
                Reason::Authentication,
                false,
                false,
            ),
            (UdpPacketError::Type, Reason::Type, false, false),
            (UdpPacketError::Clock, Reason::Clock, true, false),
            (UdpPacketError::Timestamp, Reason::Timestamp, false, false),
            (UdpPacketError::Address, Reason::Address, false, false),
            (UdpPacketError::Padding, Reason::Padding, false, false),
            (UdpPacketError::Binding, Reason::Binding, false, false),
            (UdpPacketError::Duplicate, Reason::Duplicate, false, true),
            (UdpPacketError::TooOld, Reason::TooOld, false, true),
            (
                UdpPacketError::AssociationLimit,
                Reason::SessionLimit,
                false,
                false,
            ),
            (UdpPacketError::Generation, Reason::RelayIo, true, false),
            (UdpPacketError::Key, Reason::Key, true, false),
            (UdpPacketError::Random, Reason::Random, true, false),
            (UdpPacketError::Counter, Reason::Counter, true, false),
            (
                UdpPacketError::StateUnavailable,
                Reason::RelayIo,
                true,
                false,
            ),
        ];
        for phase in [
            UdpPacketPhase::RequestEncode,
            UdpPacketPhase::ResponsePrepare,
            UdpPacketPhase::ResponseCommit,
        ] {
            for (error, reason, terminal, replay) in rows {
                assert_eq!(
                    udp_packet_policy(phase, error),
                    UdpPacketPolicy {
                        reason,
                        terminal,
                        replay,
                    },
                    "{phase:?}/{error:?}"
                );
            }
        }
    }

    #[test]
    fn real_duplicate_and_too_old_errors_update_the_closed_replay_family() {
        let mut replay = UdpReplayWindow::new();
        replay.commit(UDP_REPLAY_LAG + 1).expect("highest");
        let too_old = replay.commit(0).expect_err("too old");
        replay.commit(UDP_REPLAY_LAG).expect("fresh lower packet");
        let duplicate = replay.commit(UDP_REPLAY_LAG).expect_err("duplicate packet");
        assert_eq!(too_old, UdpPacketError::TooOld);
        assert_eq!(duplicate, UdpPacketError::Duplicate);

        let metrics = Metrics::new();
        for error in [duplicate, too_old] {
            record_udp_packet_metrics(
                &metrics,
                Direction::TargetToClient,
                udp_packet_policy(UdpPacketPhase::ResponseCommit, error),
            );
        }
        let text = metrics.encode_text().expect("metrics");
        for reason in ["duplicate", "too_old"] {
            assert!(text.contains(&format!(
                "ferrum2_udp_replay_rejections_total{{role=\"client\",direction=\"target_to_client\",reason=\"{reason}\"}} 1"
            )));
        }
    }

    #[test]
    fn metrics_render_tracks_provisional_temporary_rollback_and_closed_owners() {
        let registry = OwnerRegistry::new();
        let manager = UdpSessionManager::new(
            UdpRuntimeLimits::new(
                1,
                ferrum2_runtime::MIN_UDP_MAX_BUFFERED_BYTES,
                ferrum2_runtime::MIN_UDP_IDLE_TIMEOUT,
            )
            .expect("limits"),
            registry.clone(),
        );
        let metrics = Metrics::new();
        let provisional = manager.reserve_session(Instant::now()).expect("session");
        let temporary = provisional
            .reserve_datagram(UdpDirection::ToTarget, 777)
            .expect("temporary reservation");
        let live = render_client_metrics(&metrics, &registry);
        assert!(live.contains("ferrum2_udp_sessions_active{role=\"client\"} 1"));
        assert!(live.contains("ferrum2_udp_buffered_bytes{role=\"client\"} 777"));
        assert_eq!(registry.snapshot().udp_queued_datagrams, 0);
        drop(temporary);
        let rolled_back = render_client_metrics(&metrics, &registry);
        assert!(rolled_back.contains("ferrum2_udp_sessions_active{role=\"client\"} 1"));
        assert!(rolled_back.contains("ferrum2_udp_buffered_bytes{role=\"client\"} 0"));
        drop(provisional);
        let closed = render_client_metrics(&metrics, &registry);
        assert!(closed.contains("ferrum2_udp_sessions_active{role=\"client\"} 0"));
        assert!(closed.contains("ferrum2_udp_buffered_bytes{role=\"client\"} 0"));
    }

    #[test]
    fn metrics_render_exposes_live_tun_and_process_owner_counts() {
        let registry = OwnerRegistry::new();
        let metrics = Metrics::new();
        let flow = registry.track_tun_tcp_flow();
        let handler = registry.track_tun_handler_task();

        let live = render_client_metrics(&metrics, &registry);
        assert!(live.contains("ferrum2_process_roots_active{role=\"client\"} 0"));
        assert!(live.contains("ferrum2_process_roots_forced_total{role=\"client\"} 0"));
        assert!(live.contains("ferrum2_tun_handler_tasks_active{role=\"client\"} 1"));
        assert!(live.contains("ferrum2_tun_tcp_flows_active{role=\"client\"} 1"));
        assert_eq!(live.matches("# EOF").count(), 1);

        drop(handler);
        drop(flow);
        let closed = render_client_metrics(&metrics, &registry);
        assert!(closed.contains("ferrum2_tun_handler_tasks_active{role=\"client\"} 0"));
        assert!(closed.contains("ferrum2_tun_tcp_flows_active{role=\"client\"} 0"));
    }

    #[test]
    fn adapter_contract_observability_mapping_is_closed_and_call_site_specific() {
        let connect_cases = [
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
        ];
        for (kind, expected) in connect_cases {
            let oracle = (
                observation_for_error(ShadowsocksError::Connect(kind)),
                (Stage::Shadowsocks, Outcome::Failed, expected),
            );
            assert_eq!(oracle.0, oracle.1);
        }
        let oracle = (
            observation_for_terminal(FlowTerminal::Normal),
            (Stage::Relay, Outcome::Completed, None),
        );
        assert_eq!(oracle.0, oracle.1);
        for (reason, expected) in detection_cases() {
            assert_eq!(reason_for_detection(reason), expected);
            let oracle = (
                observation_for_terminal(FlowTerminal::Detection(reason)),
                (Stage::Shadowsocks, Outcome::Rejected, Some(expected)),
            );
            assert_eq!(oracle.0, oracle.1);
        }
        for (reason, expected) in [
            (ProtocolReason::Authentication, Reason::Authentication),
            (ProtocolReason::FrameBounds, Reason::FrameBounds),
            (ProtocolReason::NonceExhausted, Reason::NonceExhausted),
        ] {
            assert_eq!(reason_for_protocol(reason), expected);
            let oracle = (
                observation_for_terminal(FlowTerminal::Protocol(reason)),
                (Stage::Shadowsocks, Outcome::Rejected, Some(expected)),
            );
            assert_eq!(oracle.0, oracle.1);
        }
        for phase in [
            TransportPhase::Read,
            TransportPhase::Write,
            TransportPhase::WriteZero,
            TransportPhase::Flush,
            TransportPhase::Shutdown,
        ] {
            let oracle = (
                observation_for_terminal(FlowTerminal::Transport(phase)),
                (Stage::Relay, Outcome::Failed, Some(Reason::RelayIo)),
            );
            assert_eq!(oracle.0, oracle.1);
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
