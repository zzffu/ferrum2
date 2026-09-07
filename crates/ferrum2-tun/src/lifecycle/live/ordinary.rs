use std::sync::Arc;

use ferrum2_net::NetworkSnapshot;

use super::prepare::wait_owner_delay;
use super::rebuild::adapter_underlay_is_current;
use super::reset::{NetworkResetRefreshOutcome, refresh_network_runtime};
use crate::supervisor::runtime::RestartBackoff;
use crate::{
    LifecycleLink, NetworkResetBridgeOutcome, OwnerControl, TunEvent, TunEventSink,
    TunNetworkFullRebuildReason, TunNetworkLifecycle, TunNetworkResetReason,
};

pub(super) struct OrdinaryResetRequest<'a> {
    pub(super) adapter: &'a mut ferrum2_platform_windows::Adapter,
    pub(super) control: &'a OwnerControl,
    pub(super) backoff: &'a mut RestartBackoff,
    pub(super) events: &'a TunEventSink,
    pub(super) link: &'a LifecycleLink,
    pub(super) current_generation: u64,
    pub(super) reason: TunNetworkResetReason,
    pub(super) settle_underlay: bool,
    pub(super) completed: Option<&'a Arc<NetworkSnapshot>>,
}

pub(super) enum OrdinaryResetOutcome {
    Completed(Arc<NetworkSnapshot>),
    FullRebuild(TunNetworkFullRebuildReason),
    RuntimeFailed,
    CleanupFailed,
    Stopped,
}

/// The caller keeps its old fenced stack alive until this transaction completes.
/// A completed snapshot survives replacement-stack construction failure. Only a
/// subsequent observed underlay change starts a newer generation.
pub(super) fn complete_ordinary_reset(request: OrdinaryResetRequest<'_>) -> OrdinaryResetOutcome {
    let OrdinaryResetRequest {
        adapter,
        control,
        backoff,
        events,
        link,
        current_generation,
        reason,
        settle_underlay,
        completed,
    } = request;
    if let Some(snapshot) = completed
        && adapter_underlay_is_current(adapter)
    {
        return OrdinaryResetOutcome::Completed(Arc::clone(snapshot));
    }
    let current_generation = completed.map_or(current_generation, |snapshot| snapshot.generation());
    let Some(generation) = current_generation.checked_add(1) else {
        return OrdinaryResetOutcome::RuntimeFailed;
    };
    let mut settle = settle_underlay;
    let snapshot = loop {
        match refresh_network_runtime(adapter, control, backoff, events, reason, settle) {
            NetworkResetRefreshOutcome::Refreshed(_) => {}
            NetworkResetRefreshOutcome::FullRebuild(damage) => {
                return OrdinaryResetOutcome::FullRebuild(damage);
            }
            NetworkResetRefreshOutcome::RuntimeFailed => {
                return OrdinaryResetOutcome::RuntimeFailed;
            }
            NetworkResetRefreshOutcome::CleanupFailed => {
                return OrdinaryResetOutcome::CleanupFailed;
            }
            NetworkResetRefreshOutcome::Stopped => return OrdinaryResetOutcome::Stopped,
        }
        match NetworkSnapshot::capture(generation, &adapter.network_interface_catalog()) {
            Ok(snapshot) if adapter_underlay_is_current(adapter) => break Arc::new(snapshot),
            Ok(_) | Err(_) => {
                if !wait_owner_delay(control, backoff.next_delay()) {
                    return OrdinaryResetOutcome::Stopped;
                }
                settle = true;
            }
        }
    };
    loop {
        match link.request(
            Arc::clone(&snapshot),
            TunNetworkLifecycle::ResetNetwork(reason),
        ) {
            NetworkResetBridgeOutcome::Completed => {
                return OrdinaryResetOutcome::Completed(snapshot);
            }
            NetworkResetBridgeOutcome::Stopped => return OrdinaryResetOutcome::Stopped,
            NetworkResetBridgeOutcome::Retry => {
                // Keep the same immutable snapshot even when publication already happened.
                events.emit(TunEvent::NetworkResetFailed(reason));
                if !wait_owner_delay(control, backoff.next_delay()) {
                    return OrdinaryResetOutcome::Stopped;
                }
                events.emit(TunEvent::NetworkResetStarted(reason));
            }
        }
    }
}
