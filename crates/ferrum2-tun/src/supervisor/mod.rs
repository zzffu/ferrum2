use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

/// Cancellation token scoped to exactly one TUN session generation.
///
/// Process cancellation remains owned by the composition root. This token is
/// cancelled on every in-process network rebuild so old handlers cannot
/// mutate, authorize, or inject into a replacement session.
#[derive(Clone)]
pub struct SessionCancellation {
    generation: u64,
    shared: Arc<SessionCancellationState>,
}

impl SessionCancellation {
    /// Generation to which this token is permanently bound.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn is_cancelled(&self) -> bool {
        self.shared.cancelled.load(Ordering::Acquire)
    }

    /// Waits until the bound session begins quiescing.
    pub async fn cancelled(&self) {
        loop {
            let notified = self.shared.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

pub(super) struct SessionCancellationState {
    pub(super) cancelled: AtomicBool,
    pub(super) notify: Notify,
}

#[cfg(any(all(windows, target_arch = "x86_64", feature = "live-backend"), test))]
pub(crate) mod runtime;
