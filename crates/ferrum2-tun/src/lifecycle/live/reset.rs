use std::sync::atomic::Ordering;
use std::time::Duration;

pub(crate) use super::super::reset::{
    NetworkChangeErrorDisposition, NetworkChangeTransition, NetworkResetHealthDisposition,
    bounded_network_wait, classify_network_change, classify_network_change_error,
    classify_network_reset_health, classify_network_reset_refresh_error, owner_wait_after_budget,
};
use super::prepare::wait_owner_delay;
use super::rebuild::adapter_underlay_is_current;
use crate::supervisor::runtime::RestartBackoff;
use crate::{
    AdapterErrorDisposition, OwnerControl, TunEvent, TunEventSink, TunIpFamily,
    TunNetworkFullRebuildReason, TunNetworkResetReason,
};

pub(crate) fn packet_ip_family(packet: &[u8]) -> Option<TunIpFamily> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => Some(TunIpFamily::Ipv4),
        Some(6) => Some(TunIpFamily::Ipv6),
        _ => None,
    }
}

pub(crate) const MANAGED_DNS_AUDIT_MILLIS: i64 = 5_000;
const TRANSIENT_UNDERLAY_SETTLE: Duration = Duration::from_secs(5);

pub(crate) fn semantic_network_change_transition(
    adapter: &mut ferrum2_platform_windows::Adapter,
    events: &TunEventSink,
) -> Result<NetworkChangeTransition, AdapterErrorDisposition> {
    match adapter.revalidate_network_change() {
        Ok(outcome) => {
            let transition = classify_network_change(outcome);
            if transition != NetworkChangeTransition::Unchanged {
                events.emit(TunEvent::NetworkChange);
            }
            Ok(transition)
        }
        Err(error) => {
            events.emit(TunEvent::NetworkChange);
            match classify_network_change_error(error) {
                NetworkChangeErrorDisposition::ResetNetwork { settle_underlay } => {
                    Ok(NetworkChangeTransition::ResetNetwork { settle_underlay })
                }
                NetworkChangeErrorDisposition::RuntimeFailed => {
                    Err(AdapterErrorDisposition::RuntimeFailed)
                }
                NetworkChangeErrorDisposition::CleanupFailed => {
                    Err(AdapterErrorDisposition::CleanupFailed)
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkResetRefreshOutcome {
    Refreshed(TunNetworkResetReason),
    FullRebuild(TunNetworkFullRebuildReason),
    RuntimeFailed,
    CleanupFailed,
    Stopped,
}

pub(crate) fn refresh_network_runtime(
    adapter: &mut ferrum2_platform_windows::Adapter,
    control: &OwnerControl,
    backoff: &mut RestartBackoff,
    events: &TunEventSink,
    reason: TunNetworkResetReason,
    settle_underlay: bool,
) -> NetworkResetRefreshOutcome {
    let mut settle_pending = settle_underlay;
    loop {
        if control.stop.load(Ordering::Acquire) || control.shutdown.load(Ordering::Acquire) {
            events.emit(TunEvent::NetworkResetFailed(reason));
            return NetworkResetRefreshOutcome::Stopped;
        }
        match classify_network_reset_health(adapter.managed_health()) {
            NetworkResetHealthDisposition::Healthy => {}
            NetworkResetHealthDisposition::FullRebuild(damage) => {
                events.emit(TunEvent::NetworkResetFailed(reason));
                return NetworkResetRefreshOutcome::FullRebuild(damage);
            }
            NetworkResetHealthDisposition::RuntimeFailed => {
                events.emit(TunEvent::NetworkResetFailed(reason));
                return NetworkResetRefreshOutcome::RuntimeFailed;
            }
            NetworkResetHealthDisposition::CleanupFailed => {
                events.emit(TunEvent::NetworkResetFailed(reason));
                return NetworkResetRefreshOutcome::CleanupFailed;
            }
            NetworkResetHealthDisposition::Retry => {
                // A transient managed-state readback belongs to the same logical reset. Keep its
                // metric attempt and initiating reason open while the platform state settles.
                settle_pending = true;
                if !wait_owner_delay(control, backoff.next_delay()) {
                    events.emit(TunEvent::NetworkResetFailed(reason));
                    return NetworkResetRefreshOutcome::Stopped;
                }
                continue;
            }
        }
        match adapter.refresh_underlay() {
            Ok(_) if !adapter_underlay_is_current(adapter) => {
                settle_pending = true;
            }
            Ok(notification_span) if notification_span > 1 => {
                // One refresh consumed a burst that continued after semantic revalidation. Keep
                // the initiating reset open until a second capture sees the settled Windows state.
                if !wait_owner_delay(control, TRANSIENT_UNDERLAY_SETTLE) {
                    events.emit(TunEvent::NetworkResetFailed(reason));
                    return NetworkResetRefreshOutcome::Stopped;
                }
                settle_pending = false;
            }
            Ok(_) if settle_pending => {
                // Windows can publish the remaining address and route notifications after the
                // interface first becomes readable. Keep them inside this logical reset, then
                // capture the final generation before reopening admission.
                if !wait_owner_delay(control, TRANSIENT_UNDERLAY_SETTLE) {
                    events.emit(TunEvent::NetworkResetFailed(reason));
                    return NetworkResetRefreshOutcome::Stopped;
                }
                settle_pending = false;
            }
            Ok(_) => return NetworkResetRefreshOutcome::Refreshed(reason),
            Err(error) => match classify_network_reset_refresh_error(error) {
                NetworkResetHealthDisposition::RuntimeFailed => {
                    events.emit(TunEvent::NetworkResetFailed(reason));
                    return NetworkResetRefreshOutcome::RuntimeFailed;
                }
                NetworkResetHealthDisposition::CleanupFailed => {
                    events.emit(TunEvent::NetworkResetFailed(reason));
                    return NetworkResetRefreshOutcome::CleanupFailed;
                }
                NetworkResetHealthDisposition::Retry => {
                    // A temporarily unavailable underlay is still the same ordinary network
                    // change. Keep admission closed and the logical reset attempt open while the
                    // interface settles; only a terminal abort records a failed reset.
                    settle_pending = true;
                    if !wait_owner_delay(control, backoff.next_delay()) {
                        events.emit(TunEvent::NetworkResetFailed(reason));
                        return NetworkResetRefreshOutcome::Stopped;
                    }
                }
                NetworkResetHealthDisposition::Healthy
                | NetworkResetHealthDisposition::FullRebuild(_) => {
                    unreachable!("refresh errors have an exact retry or terminal disposition")
                }
            },
        }
    }
}
