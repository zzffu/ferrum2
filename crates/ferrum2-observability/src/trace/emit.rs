use tracing::Level;

use super::CLOSED_TRACE_TARGET;
use super::schema::{
    Event, InterfaceResolutionResult, InterfaceResolutionSource, LogLevel,
    NetworkFullRebuildReason, NetworkLifecycleOperation, NetworkLifecycleResult,
    NetworkResetReason, Role, SniffOutcome, SniffProtocol, Stage, StrictRouteDiagnosticStatus,
    TraceRecord, Transport, TunDiagnosticReason, TunIpFamily,
};

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

macro_rules! emit_network_lifecycle_at {
    ($level:expr, $role:expr, $operation:expr, $reason:expr, $result:expr, $generation:expr, $tcp:expr, $udp:expr) => {
        tracing::event!(
            target: CLOSED_TRACE_TARGET,
            $level,
            event = %Event::Lifecycle,
            role = %$role,
            stage = %Stage::Tun,
            operation = %$operation,
            reason = %$reason,
            result = %$result,
            generation = $generation,
            tcp_associations = $tcp,
            udp_associations = $udp,
        );
    };
}

/// Emits a debug-level reset transition with its actual published generation.
/// No association counts are accepted when the caller has not measured a cohort.
pub fn emit_network_reset_diagnostic(
    role: Role,
    reason: NetworkResetReason,
    result: NetworkLifecycleResult,
    generation: u64,
) {
    tracing::event!(
        target: CLOSED_TRACE_TARGET,
        Level::DEBUG,
        event = %Event::Lifecycle,
        role = %role,
        stage = %Stage::Tun,
        operation = %NetworkLifecycleOperation::ResetNetwork,
        reason = %reason,
        result = %result,
        generation,
    );
}

/// Emits one redacted managed-plane full-rebuild diagnostic.
pub fn emit_network_full_rebuild_diagnostic(
    role: Role,
    reason: NetworkFullRebuildReason,
    result: NetworkLifecycleResult,
    generation: u64,
    tcp_associations: usize,
    udp_associations: usize,
) {
    match result {
        NetworkLifecycleResult::Started | NetworkLifecycleResult::Succeeded => {
            emit_network_lifecycle_at!(
                Level::INFO,
                role,
                NetworkLifecycleOperation::FullRebuild,
                reason,
                result,
                generation,
                tcp_associations,
                udp_associations
            );
        }
        NetworkLifecycleResult::Failed => {
            emit_network_lifecycle_at!(
                Level::ERROR,
                role,
                NetworkLifecycleOperation::FullRebuild,
                reason,
                result,
                generation,
                tcp_associations,
                udp_associations
            );
        }
    }
}

/// Emits one redacted strict-route startup or filter-install diagnostic.
pub fn emit_strict_route_diagnostic(role: Role, status: StrictRouteDiagnosticStatus) {
    macro_rules! emit_at {
        ($level:expr) => {
            tracing::event!(
                target: CLOSED_TRACE_TARGET,
                $level,
                event = %Event::Lifecycle,
                role = %role,
                stage = %Stage::Tun,
                requested = status.requested(),
                effective = status.effective(),
                status = %status,
            );
        };
    }

    match status {
        StrictRouteDiagnosticStatus::NotRequested | StrictRouteDiagnosticStatus::Installed => {
            emit_at!(Level::INFO);
        }
        StrictRouteDiagnosticStatus::RequestedIneffective => {
            emit_at!(Level::WARN);
        }
        StrictRouteDiagnosticStatus::InstallFailed => {
            emit_at!(Level::ERROR);
        }
    }
}

/// Emits one debug-level interface-resolution diagnostic without identities.
pub fn emit_interface_resolution_diagnostic(
    role: Role,
    source: InterfaceResolutionSource,
    result: InterfaceResolutionResult,
    cache: super::schema::InterfaceResolutionCache,
) {
    tracing::event!(
        target: CLOSED_TRACE_TARGET,
        Level::DEBUG,
        event = %Event::Lifecycle,
        role = %role,
        stage = %Stage::Tun,
        source = %source,
        result = %result,
        cache = %cache,
    );
}

pub(crate) fn emit_sniff(
    role: Role,
    transport: Transport,
    outcome: SniffOutcome,
    protocol: SniffProtocol,
) {
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
