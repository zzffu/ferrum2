use std::fmt;
use std::sync::Weak;

use ferrum2_net::{InterfaceResolutionError, InterfaceSelectionSource, ResolvedInterface};
use tokio::sync::watch;

use crate::owner::OwnerGuard;

use super::transition::{CoordinatorInner, lock_unpoisoned};
use super::{
    NetworkResetHookStage, NetworkResetIntent, NetworkRuntimeOwnerKind,
    NetworkRuntimeOwnerRegistrationError,
};

/// One prepared resource admitted under an exact network generation.
#[must_use = "the runtime owner must be retained for the admitted resource lifetime"]
pub struct AdmittedNetworkRuntimeResource<T> {
    pub(super) resource: T,
    pub(super) resolved_interface: ResolvedInterface,
    pub(super) owner: NetworkRuntimeOwner,
}

impl<T> AdmittedNetworkRuntimeResource<T> {
    /// Returns the prepared resource.
    pub const fn resource(&self) -> &T {
        &self.resource
    }

    /// Returns mutable access to the prepared resource.
    pub const fn resource_mut(&mut self) -> &mut T {
        &mut self.resource
    }

    /// Returns the interface decision used while preparing the resource.
    pub const fn resolved_interface(&self) -> &ResolvedInterface {
        &self.resolved_interface
    }

    /// Returns the generation owner that must remain alive with the resource.
    pub const fn owner(&self) -> &NetworkRuntimeOwner {
        &self.owner
    }

    /// Returns mutable access to the owner for cancellation waits.
    pub const fn owner_mut(&mut self) -> &mut NetworkRuntimeOwner {
        &mut self.owner
    }

    /// Splits the admitted value into its resource, interface decision, and exclusive owner.
    pub fn into_parts(self) -> (T, ResolvedInterface, NetworkRuntimeOwner) {
        (self.resource, self.resolved_interface, self.owner)
    }
}

impl<T> fmt::Debug for AdmittedNetworkRuntimeResource<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmittedNetworkRuntimeResource")
            .field("resource", &"[closed]")
            .field("resolved_interface", &self.resolved_interface)
            .field("owner", &self.owner)
            .finish()
    }
}

/// Closed failure from preparing and admitting one generation-bound runtime resource.
#[derive(Eq, PartialEq)]
pub enum NetworkRuntimeResourceAdmissionError<E> {
    InterfaceResolution(InterfaceResolutionError),
    Preparation {
        attempted_source: InterfaceSelectionSource,
        error: E,
    },
    NetworkGenerationChanged {
        attempted_source: InterfaceSelectionSource,
    },
    RuntimeOwnerRegistration {
        attempted_source: InterfaceSelectionSource,
        error: NetworkRuntimeOwnerRegistrationError,
    },
}

impl<E> fmt::Debug for NetworkRuntimeResourceAdmissionError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InterfaceResolution(error) => formatter
                .debug_tuple("InterfaceResolution")
                .field(error)
                .finish(),
            Self::Preparation {
                attempted_source, ..
            } => formatter
                .debug_struct("Preparation")
                .field("attempted_source", attempted_source)
                .field("error", &"[closed]")
                .finish(),
            Self::NetworkGenerationChanged { attempted_source } => formatter
                .debug_struct("NetworkGenerationChanged")
                .field("attempted_source", attempted_source)
                .finish(),
            Self::RuntimeOwnerRegistration {
                attempted_source,
                error,
            } => formatter
                .debug_struct("RuntimeOwnerRegistration")
                .field("attempted_source", attempted_source)
                .field("error", error)
                .finish(),
        }
    }
}

impl<E> NetworkRuntimeResourceAdmissionError<E> {
    /// Returns the low-cardinality interface source attempted by the failed operation.
    pub const fn attempted_source(&self) -> InterfaceSelectionSource {
        match self {
            Self::InterfaceResolution(error) => error.attempted_source(),
            Self::Preparation {
                attempted_source, ..
            }
            | Self::NetworkGenerationChanged { attempted_source }
            | Self::RuntimeOwnerRegistration {
                attempted_source, ..
            } => *attempted_source,
        }
    }
}

/// Cancellation delivered to one generation-bound owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkResetSignal {
    pub(super) target_generation: u64,
    pub(super) intent: NetworkResetIntent,
}

impl NetworkResetSignal {
    pub const fn target_generation(self) -> u64 {
        self.target_generation
    }

    pub const fn intent(self) -> NetworkResetIntent {
        self.intent
    }
}

/// Terminal result from waiting for a runtime-owner cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkRuntimeOwnerCancellation {
    Reset(NetworkResetSignal),
    CoordinatorDropped,
}

/// Cloneable reset-cancellation observer that does not acknowledge owner completion.
///
/// The exclusive [`NetworkRuntimeOwner`] must still be retained until its resource is closed.
#[derive(Clone)]
pub struct NetworkRuntimeCancellation {
    pub(super) cancellation: watch::Receiver<Option<NetworkResetSignal>>,
}

impl NetworkRuntimeCancellation {
    /// Returns an already-delivered reset without registering an async waiter.
    pub fn cancellation_now(&self) -> Option<NetworkResetSignal> {
        *self.cancellation.borrow()
    }

    /// Returns an already-observable terminal state without registering an async waiter.
    pub fn terminal_now(&self) -> Option<NetworkRuntimeOwnerCancellation> {
        if let Some(signal) = self.cancellation_now() {
            Some(NetworkRuntimeOwnerCancellation::Reset(signal))
        } else if self.cancellation.has_changed().is_err() {
            Some(NetworkRuntimeOwnerCancellation::CoordinatorDropped)
        } else {
            None
        }
    }

    /// Waits for reset cancellation or coordinator destruction without acknowledging it.
    pub async fn cancelled(&mut self) -> NetworkRuntimeOwnerCancellation {
        wait_for_runtime_owner_cancellation(&mut self.cancellation).await
    }
}

impl fmt::Debug for NetworkRuntimeCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkRuntimeCancellation")
            .field("cancelled", &self.cancellation_now().is_some())
            .finish()
    }
}

/// RAII registration for one reset hook.
#[must_use = "dropping the registration removes the reset hook"]
pub struct NetworkResetHookRegistration {
    pub(super) coordinator: Weak<CoordinatorInner>,
    pub(super) id: u64,
    pub(super) stage: NetworkResetHookStage,
    pub(super) _owner: OwnerGuard,
}

impl NetworkResetHookRegistration {
    pub const fn stage(&self) -> NetworkResetHookStage {
        self.stage
    }
}

impl fmt::Debug for NetworkResetHookRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkResetHookRegistration")
            .field("stage", &self.stage)
            .finish_non_exhaustive()
    }
}

impl Drop for NetworkResetHookRegistration {
    fn drop(&mut self) {
        let Some(coordinator) = self.coordinator.upgrade() else {
            return;
        };
        lock_unpoisoned(&coordinator.state).hooks.remove(&self.id);
    }
}

/// Exclusive acknowledgement owner for one generation-bound task or connection.
#[must_use = "dropping the owner acknowledges completion to the reset coordinator"]
pub struct NetworkRuntimeOwner {
    pub(super) coordinator: Weak<CoordinatorInner>,
    pub(super) id: u64,
    pub(super) generation: u64,
    pub(super) kind: NetworkRuntimeOwnerKind,
    pub(super) cancellation: watch::Receiver<Option<NetworkResetSignal>>,
    pub(super) _owner: OwnerGuard,
}

impl NetworkRuntimeOwner {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn kind(&self) -> NetworkRuntimeOwnerKind {
        self.kind
    }

    /// Returns an already-delivered reset without registering an async waiter.
    pub fn cancellation_now(&self) -> Option<NetworkResetSignal> {
        *self.cancellation.borrow()
    }

    /// Returns a cloneable cancellation observer without transferring acknowledgement ownership.
    pub fn cancellation(&self) -> NetworkRuntimeCancellation {
        NetworkRuntimeCancellation {
            cancellation: self.cancellation.clone(),
        }
    }

    /// Returns an already-observable terminal state without registering an async waiter.
    pub fn cancellation_status_now(&self) -> Option<NetworkRuntimeOwnerCancellation> {
        self.cancellation().terminal_now()
    }

    /// Waits for reset cancellation or coordinator destruction.
    pub async fn cancelled(&mut self) -> NetworkRuntimeOwnerCancellation {
        wait_for_runtime_owner_cancellation(&mut self.cancellation).await
    }
}

pub(super) async fn wait_for_runtime_owner_cancellation(
    cancellation: &mut watch::Receiver<Option<NetworkResetSignal>>,
) -> NetworkRuntimeOwnerCancellation {
    loop {
        if let Some(signal) = *cancellation.borrow_and_update() {
            return NetworkRuntimeOwnerCancellation::Reset(signal);
        }
        if cancellation.changed().await.is_err() {
            return NetworkRuntimeOwnerCancellation::CoordinatorDropped;
        }
    }
}

impl fmt::Debug for NetworkRuntimeOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkRuntimeOwner")
            .field("generation", &self.generation)
            .field("kind", &self.kind)
            .field("cancelled", &self.cancellation_now().is_some())
            .finish()
    }
}

impl Drop for NetworkRuntimeOwner {
    fn drop(&mut self) {
        let Some(coordinator) = self.coordinator.upgrade() else {
            return;
        };
        let removed = lock_unpoisoned(&coordinator.state)
            .runtime_owners
            .remove(&self.id)
            .is_some();
        if removed {
            coordinator
                .owner_changes
                .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
        }
    }
}
