use std::sync::Arc;

use ferrum2_net::NetworkSnapshot;

use super::prepare::wait_owner_delay;
use crate::supervisor::runtime::RestartBackoff;
use crate::{
    NetworkResetBridgeOutcome, NetworkResetRequest, OwnerControl, OwnerExit, TunEvent,
    TunEventSink, TunNetworkFullRebuildReason, TunNetworkLifecycle, TunNetworkResetReason,
};

pub(crate) fn adapter_underlay_is_current(adapter: &ferrum2_platform_windows::Adapter) -> bool {
    adapter
        .underlay_policy()
        .is_none_or(|policy| policy.generation_is_current())
}

pub(crate) fn request_client_network_lifecycle(
    output: &tokio::sync::mpsc::Sender<NetworkResetRequest>,
    snapshot: Arc<NetworkSnapshot>,
    lifecycle: TunNetworkLifecycle,
) -> NetworkResetBridgeOutcome {
    let (completion, completed) = tokio::sync::oneshot::channel();
    if output
        .blocking_send(NetworkResetRequest {
            snapshot,
            lifecycle,
            completion,
        })
        .is_err()
    {
        return NetworkResetBridgeOutcome::Stopped;
    }
    completed
        .blocking_recv()
        .unwrap_or(NetworkResetBridgeOutcome::Stopped)
}

#[derive(Clone, Copy)]
pub(crate) struct PendingFullRebuild {
    pub(crate) reason: TunNetworkFullRebuildReason,
    pub(crate) generation: u64,
    pub(crate) tcp_associations: usize,
    pub(crate) udp_associations: usize,
}

impl PendingFullRebuild {
    pub(crate) fn new(
        reason: TunNetworkFullRebuildReason,
        current_generation: u64,
        tcp_associations: usize,
        udp_associations: usize,
    ) -> Option<Self> {
        Some(Self {
            reason,
            generation: current_generation.checked_add(1)?,
            tcp_associations,
            udp_associations,
        })
    }

    pub(crate) fn placeholder_snapshot(self) -> Arc<NetworkSnapshot> {
        Arc::new(
            NetworkSnapshot::new(self.generation, None, None)
                .expect("an empty full-rebuild intent snapshot is valid"),
        )
    }

    pub(crate) fn emit_started(self, events: &TunEventSink) {
        events.emit(TunEvent::NetworkFullRebuildStarted {
            reason: self.reason,
            generation: self.generation,
            tcp_associations: self.tcp_associations,
            udp_associations: self.udp_associations,
        });
    }

    pub(crate) fn emit_succeeded(self, events: &TunEventSink) {
        events.emit(TunEvent::NetworkFullRebuildSucceeded {
            reason: self.reason,
            generation: self.generation,
            tcp_associations: self.tcp_associations,
            udp_associations: self.udp_associations,
        });
    }

    pub(crate) fn emit_failed(self, events: &TunEventSink) {
        events.emit(TunEvent::NetworkFullRebuildFailed {
            reason: self.reason,
            generation: self.generation,
            tcp_associations: self.tcp_associations,
            udp_associations: self.udp_associations,
        });
    }
}

pub(crate) enum OwnerAttempt {
    Starting,
    Reset {
        adapter: ferrum2_platform_windows::Adapter,
        reason: TunNetworkResetReason,
        start_pending: bool,
    },
    Rebuild {
        pending: PendingFullRebuild,
        adapter: Option<ferrum2_platform_windows::Adapter>,
    },
}

impl OwnerAttempt {
    pub(crate) fn reset(
        adapter: ferrum2_platform_windows::Adapter,
        reason: TunNetworkResetReason,
        start_pending: bool,
    ) -> Self {
        Self::Reset {
            adapter,
            reason,
            start_pending,
        }
    }

    pub(crate) const fn rebuild(
        pending: PendingFullRebuild,
        adapter: Option<ferrum2_platform_windows::Adapter>,
    ) -> Self {
        Self::Rebuild { pending, adapter }
    }

    pub(crate) fn into_transition(
        self,
    ) -> (AttemptMode, Option<ferrum2_platform_windows::Adapter>) {
        match self {
            Self::Starting => (AttemptMode::Starting, None),
            Self::Reset {
                adapter,
                reason,
                start_pending,
            } => (
                AttemptMode::Reset {
                    reason,
                    start_pending,
                },
                Some(adapter),
            ),
            Self::Rebuild { pending, adapter } => (AttemptMode::Rebuild(pending), adapter),
        }
    }

    pub(crate) fn cleanup(self, events: &TunEventSink) -> bool {
        match self {
            Self::Starting => false,
            Self::Reset {
                adapter,
                reason,
                start_pending,
            } => {
                if !start_pending {
                    events.emit(TunEvent::NetworkResetFailed(reason));
                }
                adapter.cleanup().is_err()
            }
            Self::Rebuild { pending, adapter } => {
                pending.emit_failed(events);
                adapter.is_some_and(|adapter| adapter.cleanup().is_err())
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum AttemptMode {
    Starting,
    Reset {
        reason: TunNetworkResetReason,
        start_pending: bool,
    },
    Rebuild(PendingFullRebuild),
}

impl AttemptMode {
    pub(crate) const fn is_starting(self) -> bool {
        matches!(self, Self::Starting)
    }

    pub(crate) const fn is_rebuilding(self) -> bool {
        matches!(self, Self::Rebuild(_))
    }

    pub(crate) const fn reset_reason(&self) -> Option<TunNetworkResetReason> {
        match self {
            Self::Reset { reason, .. } => Some(*reason),
            Self::Starting | Self::Rebuild(_) => None,
        }
    }

    pub(crate) const fn reset_start_pending(&self) -> Option<TunNetworkResetReason> {
        match self {
            Self::Reset {
                reason,
                start_pending: true,
                ..
            } => Some(*reason),
            Self::Starting | Self::Reset { .. } | Self::Rebuild(_) => None,
        }
    }

    pub(crate) const fn pending_rebuild(self) -> Option<PendingFullRebuild> {
        match self {
            Self::Rebuild(pending) => Some(pending),
            Self::Starting | Self::Reset { .. } => None,
        }
    }

    pub(crate) fn resume_with(
        self,
        adapter: Option<ferrum2_platform_windows::Adapter>,
    ) -> OwnerAttempt {
        match self {
            Self::Starting => {
                debug_assert!(adapter.is_none());
                OwnerAttempt::Starting
            }
            Self::Reset {
                reason,
                start_pending,
            } => OwnerAttempt::reset(
                adapter.expect("reset transition retains its adapter"),
                reason,
                start_pending,
            ),
            Self::Rebuild(pending) => OwnerAttempt::rebuild(pending, adapter),
        }
    }

    pub(crate) fn emit_rebuild_failed(self, events: &TunEventSink) {
        if let Self::Rebuild(pending) = self {
            pending.emit_failed(events);
        }
    }

    pub(crate) fn emit_rebuild_succeeded(self, events: &TunEventSink) {
        if let Self::Rebuild(pending) = self {
            pending.emit_succeeded(events);
        }
    }
}

pub(crate) fn request_full_rebuild_transition(
    output: &tokio::sync::mpsc::Sender<NetworkResetRequest>,
    snapshot: Arc<NetworkSnapshot>,
    lifecycle: TunNetworkLifecycle,
    control: &OwnerControl,
    backoff: &mut RestartBackoff,
) -> NetworkResetBridgeOutcome {
    loop {
        let outcome = request_client_network_lifecycle(output, Arc::clone(&snapshot), lifecycle);
        if outcome != NetworkResetBridgeOutcome::Retry {
            return outcome;
        }
        if !wait_owner_delay(control, backoff.next_delay()) {
            return NetworkResetBridgeOutcome::Stopped;
        }
    }
}

pub(crate) fn start_full_rebuild(
    rebuild: Result<PendingFullRebuild, OwnerExit>,
    output: &tokio::sync::mpsc::Sender<NetworkResetRequest>,
    control: &OwnerControl,
    backoff: &mut RestartBackoff,
    events: &TunEventSink,
) -> Result<PendingFullRebuild, OwnerExit> {
    let rebuild = rebuild?;
    rebuild.emit_started(events);
    let outcome = request_full_rebuild_transition(
        output,
        rebuild.placeholder_snapshot(),
        TunNetworkLifecycle::FullRebuildStarted(rebuild.reason),
        control,
        backoff,
    );
    if outcome == NetworkResetBridgeOutcome::Completed {
        Ok(rebuild)
    } else {
        rebuild.emit_failed(events);
        Err(if outcome == NetworkResetBridgeOutcome::Stopped {
            OwnerExit::Stopped
        } else {
            OwnerExit::RuntimeFailed
        })
    }
}
