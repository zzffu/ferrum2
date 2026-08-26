use super::{ManagedNetworkDamage, NetworkResetHookStage};

/// Public coordinator phase. The coordinator begins after managed-plane startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkResetState {
    Active,
    ResetPending,
    Resetting,
    RetryReset,
    ManagedDamaged,
}

/// Read-only, redacted state of one coordinator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkResetStatus {
    pub(super) state: NetworkResetState,
    pub(super) admission_open: bool,
    pub(super) published_generation: u64,
    pub(super) active_generation: Option<u64>,
    pub(super) pending_generation: Option<u64>,
    pub(super) registered_hooks: usize,
    pub(super) registered_runtime_owners: usize,
}

impl NetworkResetStatus {
    pub const fn state(self) -> NetworkResetState {
        self.state
    }

    pub const fn admission_open(self) -> bool {
        self.admission_open
    }

    pub const fn published_generation(self) -> u64 {
        self.published_generation
    }

    pub const fn active_generation(self) -> Option<u64> {
        self.active_generation
    }

    pub const fn pending_generation(self) -> Option<u64> {
        self.pending_generation
    }

    pub const fn registered_hooks(self) -> usize {
        self.registered_hooks
    }

    pub const fn registered_runtime_owners(self) -> usize {
        self.registered_runtime_owners
    }
}

/// Closed reset result classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkResetOutcome {
    Noop,
    ResetCompleted,
    FullRebuildRequired(ManagedNetworkDamage),
    FullRebuildAcknowledged,
}

/// Result of placing one notification into the coordinator's single pending slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkResetRequestDisposition {
    /// The same snapshot is already active and no reset is required.
    Noop,
    /// The notification created the pending reset slot.
    Queued,
    /// The notification was absorbed by active, pending, or full-rebuild work.
    Coalesced,
}

/// Bounded summary of work completed by one serialized driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkResetReport {
    pub(super) outcome: NetworkResetOutcome,
    pub(super) published_generation: u64,
    pub(super) completed_resets: usize,
    pub(super) cancelled_runtime_owners: usize,
}

impl NetworkResetReport {
    pub const fn outcome(self) -> NetworkResetOutcome {
        self.outcome
    }

    pub const fn published_generation(self) -> u64 {
        self.published_generation
    }

    pub const fn completed_resets(self) -> usize {
        self.completed_resets
    }

    pub const fn cancelled_runtime_owners(self) -> usize {
        self.cancelled_runtime_owners
    }
}

/// Closed reset coordination failure. No injected hook or platform error is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkResetCoordinatorError {
    StaleRequestGeneration,
    ConflictingGenerationSnapshot,
    HookFailed(NetworkResetHookStage),
    HookPanicked(NetworkResetHookStage),
    SnapshotPublicationStale,
    SnapshotPublicationNonMonotonic,
    FullRebuildNotPending,
    FullRebuildGenerationTooOld,
    FullRebuildOwnersRemain,
}

/// Closed reset-hook registration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkResetHookRegistrationError {
    AdmissionClosed,
    CapacityExhausted,
    IdentifierExhausted,
}

/// Closed generation-bound owner admission failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkRuntimeOwnerRegistrationError {
    AdmissionClosed,
    StaleGeneration,
    CapacityExhausted,
    IdentifierExhausted,
}
