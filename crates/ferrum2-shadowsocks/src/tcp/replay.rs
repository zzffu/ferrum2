use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use ferrum2_crypto::{MethodTcpSalt, MonotonicInstant};
use thiserror::Error;

use super::error::{DetectionReason, ShadowsocksError};

const REPLAY_RETENTION: Duration = Duration::from_secs(60);
const DEFAULT_REPLAY_CAPACITY: usize = 65_536;
pub(super) const MIN_REPLAY_CAPACITY: usize = 1_024;
const MAX_REPLAY_CAPACITY: usize = 1_048_576;

/// Exact, bounded TCP replay state shared by server handshakes.
pub struct TcpReplayStore {
    capacity: usize,
    pub(super) state: Mutex<ReplayState>,
}

pub(super) struct ReplayState {
    entries: HashMap<MethodTcpSalt, MonotonicInstant>,
    insertion_order: VecDeque<MethodTcpSalt>,
}

/// Invalid replay capacity.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("replay capacity is outside the approved range")]
pub struct ReplayCapacityError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReplayInsertError {
    Duplicate,
    Capacity,
    Unavailable,
}

impl TcpReplayStore {
    /// Creates exact replay state with the approved default capacity.
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_REPLAY_CAPACITY).expect("the approved default is in range")
    }

    /// Creates exact replay state with a validated capacity.
    pub fn new(capacity: usize) -> Result<Self, ReplayCapacityError> {
        if !(MIN_REPLAY_CAPACITY..=MAX_REPLAY_CAPACITY).contains(&capacity) {
            return Err(ReplayCapacityError);
        }
        Ok(Self {
            capacity,
            state: Mutex::new(ReplayState {
                entries: HashMap::with_capacity(capacity),
                insertion_order: VecDeque::with_capacity(capacity),
            }),
        })
    }

    /// Returns the exact number of live or not-yet-purged entries.
    pub fn entry_count(&self) -> Result<usize, ShadowsocksError> {
        self.state
            .lock()
            .map(|state| state.entries.len())
            .map_err(|_| ShadowsocksError::Detection(DetectionReason::ReplayUnavailable))
    }

    pub(super) fn check_and_insert(
        &self,
        salt: &MethodTcpSalt,
        now: MonotonicInstant,
    ) -> Result<(), ReplayInsertError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ReplayInsertError::Unavailable)?;
        purge_expired(&mut state, now);
        if state.entries.contains_key(salt) {
            return Err(ReplayInsertError::Duplicate);
        }
        if state.entries.len() == self.capacity {
            return Err(ReplayInsertError::Capacity);
        }
        state.entries.insert(salt.clone(), now);
        state.insertion_order.push_back(salt.clone());
        Ok(())
    }
}

impl Default for TcpReplayStore {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

fn purge_expired(state: &mut ReplayState, now: MonotonicInstant) {
    while let Some(oldest) = state.insertion_order.front() {
        let Some(inserted) = state.entries.get(oldest).copied() else {
            state.insertion_order.pop_front();
            continue;
        };
        if !now
            .duration_since(inserted)
            .is_some_and(|elapsed| elapsed >= REPLAY_RETENTION)
        {
            break;
        }
        let salt = state
            .insertion_order
            .pop_front()
            .expect("front was observed");
        state.entries.remove(&salt);
    }
}
