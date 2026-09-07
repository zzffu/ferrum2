use ferrum2_observability::{Metrics, Outcome, Reason, Stage};
use ferrum2_runtime::{
    DirectUdpCompletion, DirectUdpShutdownReport, DirectUdpTerminal, UdpRuntimeError,
};
use ferrum2_shadowsocks::UdpPacketError;

use super::identity::UdpMappings;
use super::listener::UdpAdapterError;
use crate::run::observation::{
    record_udp_failure, record_udp_protocol_failure, record_udp_runtime_failure,
};

pub(super) fn observe_completion(
    metrics: &Metrics,
    mappings: &UdpMappings,
    completion: &DirectUdpCompletion<UdpAdapterError>,
) -> bool {
    mappings.invalidate_handle(completion.session());
    match completion.terminal() {
        DirectUdpTerminal::Completed => {}
        DirectUdpTerminal::Idle => record_udp_runtime_failure(metrics, UdpRuntimeError::Idle),
        DirectUdpTerminal::Cancelled => {
            record_udp_runtime_failure(metrics, UdpRuntimeError::Cancelled)
        }
        DirectUdpTerminal::ResolveFailed => {
            record_udp_runtime_failure(metrics, UdpRuntimeError::Resolve)
        }
        DirectUdpTerminal::SendFailed => record_udp_runtime_failure(metrics, UdpRuntimeError::Send),
        DirectUdpTerminal::ReceiveFailed => {
            record_udp_runtime_failure(metrics, UdpRuntimeError::Receive)
        }
        DirectUdpTerminal::RuntimeFailed(error) => record_udp_runtime_failure(metrics, *error),
        DirectUdpTerminal::HandlerFailed(error) => match error {
            UdpAdapterError::Mapping => {
                record_udp_protocol_failure(metrics, UdpPacketError::Generation)
            }
            UdpAdapterError::Protocol(error) => record_udp_protocol_failure(metrics, *error),
            UdpAdapterError::Runtime(error) => record_udp_runtime_failure(metrics, *error),
            UdpAdapterError::Send => record_udp_runtime_failure(metrics, UdpRuntimeError::Send),
        },
        DirectUdpTerminal::Panicked => {
            record_udp_failure(metrics, Stage::Direct, Reason::RelayIo, Outcome::Failed)
        }
        DirectUdpTerminal::Aborted => {
            record_udp_failure(metrics, Stage::Shutdown, Reason::Cancelled, Outcome::Failed)
        }
    }
    completion.unexpected_failure()
        || matches!(
            completion.terminal(),
            DirectUdpTerminal::HandlerFailed(UdpAdapterError::Protocol(
                UdpPacketError::StateUnavailable
            )) | DirectUdpTerminal::HandlerFailed(UdpAdapterError::Runtime(
                UdpRuntimeError::ProtocolPanicked | UdpRuntimeError::StateUnavailable
            ))
        )
}

pub(super) fn observe_shutdown(
    metrics: &Metrics,
    mappings: &UdpMappings,
    report: &DirectUdpShutdownReport<UdpAdapterError>,
) -> bool {
    let mut failed = report.cleanup_failed();
    for completion in report.completions() {
        failed |= observe_completion(metrics, mappings, completion);
    }
    for _ in 0..report.forced() {
        metrics.udp_forced_shutdown(ferrum2_observability::Role::Server);
    }
    failed
}
