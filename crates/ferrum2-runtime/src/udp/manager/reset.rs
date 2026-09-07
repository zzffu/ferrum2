use super::{UdpRuntimeError, UdpSessionManager, lock_state, publish_removal, remove_entry};

#[derive(Clone, Copy)]
pub(super) struct NetworkFence {
    generation: u64,
    pub(super) cutoff: u64,
    retired: bool,
}

impl UdpSessionManager {
    /// Closes admission and invalidates existing capabilities without cancelling or clearing them.
    ///
    /// Network generations are positive and monotonic, independent of session generations.
    /// Retrying the same fence keeps its original cutoff. A newer fence is rejected until
    /// retirement and reopening complete; callers must serialize the whole reset transaction.
    pub fn fence_network_generation(&self, generation: u64) -> Result<(), UdpRuntimeError> {
        let mut state = lock_state(&self.inner);
        if state.shutting_down || generation == 0 || generation < state.completed_network_generation
        {
            return Err(UdpRuntimeError::Cancelled);
        }
        if let Some(fence) = state.network_fence {
            return if fence.generation == generation {
                Ok(())
            } else {
                Err(UdpRuntimeError::Cancelled)
            };
        }
        if generation == state.completed_network_generation {
            return Ok(());
        }
        state.network_fence = Some(NetworkFence {
            generation,
            cutoff: state.next_generation,
            retired: false,
        });
        Ok(())
    }

    /// Removes only the fenced cohort after external owners have acknowledged cancellation.
    ///
    /// Exact-owner drops may already have removed entries; each remaining entry is counted once.
    /// Permanent shutdown still permits retirement, but can never be undone by reopening.
    pub fn retire_network_generation(&self, generation: u64) -> Result<usize, UdpRuntimeError> {
        let mut state = lock_state(&self.inner);
        let Some(fence) = state.network_fence else {
            return if generation != 0 && generation == state.completed_network_generation {
                Ok(0)
            } else {
                Err(UdpRuntimeError::Cancelled)
            };
        };
        if fence.generation != generation {
            return Err(UdpRuntimeError::Cancelled);
        }
        if fence.retired {
            return Ok(0);
        }
        let slots: Vec<_> = state
            .entries
            .iter()
            .filter_map(|(slot, entry)| (entry.generation <= fence.cutoff).then_some(*slot))
            .collect();
        let removed: Vec<_> = slots
            .into_iter()
            .filter_map(|slot| remove_entry(&mut state, slot))
            .collect();
        state
            .network_fence
            .as_mut()
            .expect("retained fence")
            .retired = true;
        drop(state);
        let count = removed.len();
        for handle in removed {
            publish_removal(&self.inner, handle);
        }
        Ok(count)
    }

    /// Reopens only the completed fenced generation; shutdown always remains terminal.
    pub fn reopen_network_generation(&self, generation: u64) -> Result<(), UdpRuntimeError> {
        let mut state = lock_state(&self.inner);
        if state.shutting_down {
            return Err(UdpRuntimeError::Cancelled);
        }
        match state.network_fence {
            Some(fence) if fence.generation == generation && fence.retired => {
                state.completed_network_generation = generation;
                state.network_fence = None;
                Ok(())
            }
            None if generation != 0 && generation == state.completed_network_generation => Ok(()),
            Some(_) | None => Err(UdpRuntimeError::Cancelled),
        }
    }
}
