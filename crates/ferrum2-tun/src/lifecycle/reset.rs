use std::time::Duration;

use crate::TunNetworkFullRebuildReason;
use crate::scheduler::BudgetOutcome;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkChangeTransition {
    Unchanged,
    ResetNetwork { settle_underlay: bool },
    FullRebuild(TunNetworkFullRebuildReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkResetHealthDisposition {
    Healthy,
    Retry,
    FullRebuild(TunNetworkFullRebuildReason),
    RuntimeFailed,
    CleanupFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkChangeErrorDisposition {
    ResetNetwork { settle_underlay: bool },
    RuntimeFailed,
    CleanupFailed,
}

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

pub(crate) fn owner_wait_after_budget(budget: BudgetOutcome, bounded_wait: Duration) -> Duration {
    if budget.budget_exhausted {
        Duration::ZERO
    } else {
        bounded_wait
    }
}
