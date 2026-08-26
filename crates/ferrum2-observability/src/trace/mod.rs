mod emit;
mod schema;
mod subscriber;

pub(crate) use emit::emit_sniff;
pub use emit::{
    emit, emit_interface_resolution_diagnostic, emit_network_full_rebuild_diagnostic,
    emit_network_reset_diagnostic, emit_strict_route_diagnostic, emit_tun_diagnostic,
};
pub use schema::{
    Event, InterfaceResolutionResult, InterfaceResolutionSource, LogLevel,
    NetworkFullRebuildReason, NetworkLifecycleOperation, NetworkLifecycleResult,
    NetworkResetReason, Outcome, Reason, Role, SniffOutcome, SniffProtocol, Stage,
    StrictRouteDiagnosticStatus, StrictRouteFilterInstallResult, TraceRecord, Transport,
    TunDiagnosticReason, TunIpFamily, TunPacketRejectReason, TunUdpAssociationRouteResult,
    TunUdpResponseDropReason,
};
pub use subscriber::json_subscriber;

pub(super) const CLOSED_TRACE_TARGET: &str = "ferrum2_observability::closed";
