use std::sync::atomic::Ordering;
use std::time::Duration;

use super::prepare::wait_owner_delay;
use super::rebuild::adapter_underlay_is_current;
use crate::scheduler::BudgetOutcome;
use crate::supervisor::RestartBackoff;
use crate::{
    AdapterErrorDisposition, OwnerControl, TunEvent, TunEventSink, TunIpFamily,
    TunNetworkFullRebuildReason, TunNetworkResetReason,
};

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) fn packet_ip_family(packet: &[u8]) -> Option<TunIpFamily> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => Some(TunIpFamily::Ipv4),
        Some(6) => Some(TunIpFamily::Ipv6),
        _ => None,
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) const MANAGED_DNS_AUDIT_MILLIS: i64 = 5_000;

#[cfg(all(windows, target_arch = "x86_64"))]
const TRANSIENT_UNDERLAY_SETTLE: Duration = Duration::from_secs(5);

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkChangeTransition {
    Unchanged,
    ResetNetwork { settle_underlay: bool },
    FullRebuild(TunNetworkFullRebuildReason),
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkResetHealthDisposition {
    Healthy,
    Retry,
    FullRebuild(TunNetworkFullRebuildReason),
    RuntimeFailed,
    CleanupFailed,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkChangeErrorDisposition {
    ResetNetwork { settle_underlay: bool },
    RuntimeFailed,
    CleanupFailed,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(crate) const fn classify_network_reset_health(
    health: Result<ferrum2_platform_windows::ManagedTunHealth, ferrum2_platform_windows::Error>,
) -> NetworkResetHealthDisposition {
    match health {
        Ok(ferrum2_platform_windows::ManagedTunHealth::Healthy) => {
            NetworkResetHealthDisposition::Healthy
        }
        Ok(ferrum2_platform_windows::ManagedTunHealth::Damaged(damage)) => {
            NetworkResetHealthDisposition::FullRebuild(map_managed_state_damage(damage))
        }
        Err(error) => match error.kind() {
            ferrum2_platform_windows::ErrorKind::RecoverableSession => {
                NetworkResetHealthDisposition::Retry
            }
            ferrum2_platform_windows::ErrorKind::InvalidInput
            | ferrum2_platform_windows::ErrorKind::UnrecoverableCorruption => {
                NetworkResetHealthDisposition::RuntimeFailed
            }
            ferrum2_platform_windows::ErrorKind::Cleanup => {
                NetworkResetHealthDisposition::CleanupFailed
            }
        },
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(crate) const fn classify_network_reset_refresh_error(
    error: ferrum2_platform_windows::Error,
) -> NetworkResetHealthDisposition {
    match error.kind() {
        ferrum2_platform_windows::ErrorKind::RecoverableSession => {
            NetworkResetHealthDisposition::Retry
        }
        ferrum2_platform_windows::ErrorKind::InvalidInput
        | ferrum2_platform_windows::ErrorKind::UnrecoverableCorruption => {
            NetworkResetHealthDisposition::RuntimeFailed
        }
        ferrum2_platform_windows::ErrorKind::Cleanup => {
            NetworkResetHealthDisposition::CleanupFailed
        }
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(crate) const fn classify_network_change_error(
    error: ferrum2_platform_windows::Error,
) -> NetworkChangeErrorDisposition {
    match error.kind() {
        ferrum2_platform_windows::ErrorKind::RecoverableSession => {
            NetworkChangeErrorDisposition::ResetNetwork {
                settle_underlay: true,
            }
        }
        ferrum2_platform_windows::ErrorKind::InvalidInput
        | ferrum2_platform_windows::ErrorKind::UnrecoverableCorruption => {
            NetworkChangeErrorDisposition::RuntimeFailed
        }
        ferrum2_platform_windows::ErrorKind::Cleanup => {
            NetworkChangeErrorDisposition::CleanupFailed
        }
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(crate) const fn classify_network_change(
    outcome: ferrum2_platform_windows::NetworkChangeOutcome,
) -> NetworkChangeTransition {
    match outcome {
        ferrum2_platform_windows::NetworkChangeOutcome::Unchanged => {
            NetworkChangeTransition::Unchanged
        }
        ferrum2_platform_windows::NetworkChangeOutcome::Changed => {
            NetworkChangeTransition::ResetNetwork {
                settle_underlay: false,
            }
        }
        ferrum2_platform_windows::NetworkChangeOutcome::ManagedStateDamaged(damage) => {
            NetworkChangeTransition::FullRebuild(map_managed_state_damage(damage))
        }
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(crate) const fn map_managed_state_damage(
    damage: ferrum2_platform_windows::ManagedStateDamage,
) -> TunNetworkFullRebuildReason {
    match damage {
        ferrum2_platform_windows::ManagedStateDamage::Adapter => {
            TunNetworkFullRebuildReason::AdapterDamage
        }
        ferrum2_platform_windows::ManagedStateDamage::Session => {
            TunNetworkFullRebuildReason::SessionDamage
        }
        ferrum2_platform_windows::ManagedStateDamage::Address => {
            TunNetworkFullRebuildReason::AddressDamage
        }
        ferrum2_platform_windows::ManagedStateDamage::Route => {
            TunNetworkFullRebuildReason::RouteDamage
        }
        ferrum2_platform_windows::ManagedStateDamage::Dns => TunNetworkFullRebuildReason::DnsDamage,
        ferrum2_platform_windows::ManagedStateDamage::StrictRoute => {
            TunNetworkFullRebuildReason::StrictRouteDamage
        }
        ferrum2_platform_windows::ManagedStateDamage::OwnershipLedger => {
            TunNetworkFullRebuildReason::OwnershipLedgerDamage
        }
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(crate) fn bounded_network_wait(
    base: Duration,
    now_millis: i64,
    debounce_deadline: Option<i64>,
    audit_deadline: Option<i64>,
) -> Duration {
    let deadline = [debounce_deadline, audit_deadline]
        .into_iter()
        .flatten()
        .min();
    let Some(deadline) = deadline else {
        return base;
    };
    let millis = u64::try_from(deadline.saturating_sub(now_millis).max(0)).unwrap_or(u64::MAX);
    base.min(Duration::from_millis(millis))
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(crate) fn owner_wait_after_budget(budget: BudgetOutcome, bounded_wait: Duration) -> Duration {
    if budget.budget_exhausted {
        Duration::ZERO
    } else {
        bounded_wait
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
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

#[cfg(all(windows, target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkResetRefreshOutcome {
    Refreshed(TunNetworkResetReason),
    FullRebuild(TunNetworkFullRebuildReason),
    RuntimeFailed,
    CleanupFailed,
    Stopped,
}

#[cfg(all(windows, target_arch = "x86_64"))]
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
