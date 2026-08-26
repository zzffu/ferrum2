use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use ferrum2_net::NetworkSnapshot;

/// Atomically publishes immutable network generations to all runtime users.
#[derive(Clone)]
pub struct NetworkSnapshotPublisher {
    current: Arc<RwLock<Arc<NetworkSnapshot>>>,
}

impl NetworkSnapshotPublisher {
    /// Creates a publisher with one already-validated initial generation.
    pub fn new(initial: Arc<NetworkSnapshot>) -> Self {
        Self {
            current: Arc::new(RwLock::new(initial)),
        }
    }

    /// Returns one immutable snapshot of the current generation.
    pub fn snapshot(&self) -> Arc<NetworkSnapshot> {
        Arc::clone(&read_unpoisoned(&self.current))
    }

    /// Returns the currently published generation.
    pub fn generation(&self) -> u64 {
        read_unpoisoned(&self.current).generation()
    }

    /// Returns whether an operation prepared against `generation` may still publish resources.
    pub fn is_current(&self, generation: u64) -> bool {
        self.generation() == generation
    }

    /// Publishes a newer snapshot only if the expected generation is still current.
    pub fn publish_if_current(
        &self,
        expected_generation: u64,
        next: Arc<NetworkSnapshot>,
    ) -> Result<Arc<NetworkSnapshot>, NetworkSnapshotPublishError> {
        let mut current = write_unpoisoned(&self.current);
        if current.generation() != expected_generation {
            return Err(NetworkSnapshotPublishError::StaleExpectedGeneration);
        }
        if next.generation() <= expected_generation {
            return Err(NetworkSnapshotPublishError::NonMonotonicGeneration);
        }
        Ok(std::mem::replace(&mut *current, next))
    }
}

fn read_unpoisoned<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_unpoisoned<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Closed failure from atomically publishing a network snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkSnapshotPublishError {
    StaleExpectedGeneration,
    NonMonotonicGeneration,
}

/// Closed reset-hook failure safe for runtime boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkResetError;

/// Boxed future returned by an object-safe network reset hook.
pub type NetworkResetFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), NetworkResetError>> + Send + 'a>>;

/// Generation-aware hook implemented by network-dependent runtime components.
pub trait ResetNetwork: Send + Sync {
    /// Replaces all generation-bound state without tearing down managed device state.
    fn reset_network(&self, snapshot: Arc<NetworkSnapshot>) -> NetworkResetFuture<'_>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_publication_is_atomic_and_monotonic() {
        let initial = Arc::new(NetworkSnapshot::new(4, None, None).unwrap());
        let publisher = NetworkSnapshotPublisher::new(Arc::clone(&initial));
        let next = Arc::new(NetworkSnapshot::new(5, None, None).unwrap());

        assert!(publisher.is_current(4));
        assert_eq!(
            publisher.publish_if_current(4, Arc::clone(&next)).unwrap(),
            initial
        );
        assert!(publisher.is_current(5));
        assert_eq!(publisher.snapshot(), next);
        assert_eq!(
            publisher
                .publish_if_current(4, Arc::new(NetworkSnapshot::new(6, None, None).unwrap()))
                .unwrap_err(),
            NetworkSnapshotPublishError::StaleExpectedGeneration
        );
        assert_eq!(
            publisher
                .publish_if_current(5, Arc::new(NetworkSnapshot::new(5, None, None).unwrap()))
                .unwrap_err(),
            NetworkSnapshotPublishError::NonMonotonicGeneration
        );
        assert_eq!(publisher.snapshot(), next);
    }
}
