use crate::stack::Stack;
use crate::stack::{OutputFlushOutcome, OutputSendOutcome};
use crate::{TunEvent, TunEventSink, TunRejectReason};
use std::time::{Duration, Instant};

/// The old kernel sockets have been fenced, but their abort RST packets still
/// traverse Wintun. Normal FIN history does not replace reset delivery.
/// Keep the exact listener guard and tuple maps until reset delivery.
/// A bounded failure never advertises a completed reset; it still proceeds to
/// the caller's ordinary exact cleanup. Ring-full packets are not retried.
pub(super) fn drain_fenced(
    stack: &mut Stack,
    adapter: &mut ferrum2_platform_windows::Adapter,
    origin: Instant,
    events: &TunEventSink,
) -> Result<(), ()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let mut worked = false;
        for _ in 0..64 {
            let output = stack.flush_fenced_tcp(|packet| match adapter.send(packet) {
                Ok(ferrum2_platform_windows::SendOutcome::Sent) => {
                    events.emit(TunEvent::PacketEgress);
                    OutputSendOutcome::Sent
                }
                Ok(ferrum2_platform_windows::SendOutcome::DroppedRingFull) => {
                    events.emit(TunEvent::WintunRingFullDropped);
                    events.emit(TunEvent::PacketRejected(TunRejectReason::WintunRingFull));
                    OutputSendOutcome::DroppedRingFull
                }
                Err(_) => OutputSendOutcome::Fatal,
            });
            match output {
                OutputFlushOutcome::Sent => worked = true,
                OutputFlushOutcome::Empty => {}
                OutputFlushOutcome::DroppedRingFull | OutputFlushOutcome::Fatal => return Err(()),
            }
            worked |= stack.process_one_tcp_packet();
            if stack.ingress_available() != 0
                && let Some(packet) = adapter.receive().map_err(|_| ())?
            {
                events.emit(TunEvent::PacketIngress);
                let now = i64::try_from(origin.elapsed().as_millis()).unwrap_or(i64::MAX);
                if stack.enqueue_fenced_tcp(&packet, now) {
                    events.emit(TunEvent::PacketAccepted);
                }
                worked = true;
            }
            if stack.pending_tcp_close_notifications() == 0 && !stack.tcp_teardown_output_pending()
            {
                return Ok(());
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(());
        }
        if !worked {
            match adapter
                .wait(remaining.min(Duration::from_millis(10)))
                .map_err(|_| ())?
            {
                ferrum2_platform_windows::WaitOutcome::Stop => return Err(()),
                ferrum2_platform_windows::WaitOutcome::Work
                | ferrum2_platform_windows::WaitOutcome::Readable
                | ferrum2_platform_windows::WaitOutcome::Timeout
                | ferrum2_platform_windows::WaitOutcome::NetworkChanged => {}
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TcpEpochError {
    Runtime,
    Cleanup,
}

pub(super) fn start(
    stack: &mut Stack,
    adapter: &mut ferrum2_platform_windows::Adapter,
    runtime: &tokio::runtime::Handle,
) -> Result<(), TcpEpochError> {
    let endpoints = match stack.start_tcp(runtime) {
        Ok(endpoints) => endpoints,
        Err(_) => {
            return if stop(stack, adapter).is_err() {
                Err(TcpEpochError::Cleanup)
            } else {
                Err(TcpEpochError::Runtime)
            };
        }
    };
    let setup = endpoints
        .iter()
        .try_for_each(|endpoint| adapter.verify_tcp_peer_route(endpoint.peer()))
        .and_then(|()| adapter.install_tcp_ingress(&endpoints))
        .and_then(|()| adapter.verify_tcp_ingress());
    if setup.is_ok() && !stack.tcp_failed() {
        return Ok(());
    }
    let cleanup_error =
        setup.is_err_and(|error| error.kind() == ferrum2_platform_windows::ErrorKind::Cleanup);
    let stop_failed = stop(stack, adapter).is_err();
    if cleanup_error || stop_failed {
        Err(TcpEpochError::Cleanup)
    } else {
        Err(TcpEpochError::Runtime)
    }
}

pub(super) fn stop(
    stack: &mut Stack,
    adapter: &mut ferrum2_platform_windows::Adapter,
) -> Result<(), ()> {
    let stopped = stack.stop_tcp_and_join();
    let cleared = adapter.clear_tcp_ingress();
    if stopped.is_err() || cleared.is_err() {
        Err(())
    } else {
        Ok(())
    }
}
