#![forbid(unsafe_code)]

mod metrics;
mod trace;

pub use metrics::{
    CompiledMatchType, Direction, DnsQueryType, DnsResolvePurpose, DnsResolveResult,
    DnsResolverKind, Inbound, Metrics, MetricsEncodeError, RuleMatchResult, RuleMatchType,
    RuleProgram, RuleProgramMode, RuleSetResult, RuleSource, TargetResolutionComponent,
    TargetResolutionMode,
};
pub use trace::{
    Event, InterfaceResolutionResult, InterfaceResolutionSource, LogLevel,
    NetworkFullRebuildReason, NetworkLifecycleOperation, NetworkLifecycleResult,
    NetworkResetReason, Outcome, Reason, Role, SniffOutcome, SniffProtocol, Stage,
    StrictRouteDiagnosticStatus, StrictRouteFilterInstallResult, TraceRecord, Transport,
    TunDiagnosticReason, TunIpFamily, TunPacketRejectReason, TunUdpAssociationRouteResult,
    TunUdpResponseDropReason, emit, emit_interface_resolution_diagnostic,
    emit_network_full_rebuild_diagnostic, emit_network_reset_diagnostic,
    emit_strict_route_diagnostic, emit_tun_diagnostic, json_subscriber,
};
