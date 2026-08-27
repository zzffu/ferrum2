use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::{SessionCancellation, SessionCancellationState};
use crate::OwnerWake;

const RESTART_BACKOFF_MILLIS: [u64; 5] = [250, 500, 1_000, 2_000, 5_000];
pub(crate) const NETWORK_DEBOUNCE: Duration = Duration::from_millis(350);

pub(crate) struct SessionCancelHandle {
    generation: u64,
    shared: Arc<SessionCancellationState>,
    owner_wake: OwnerWake,
}

impl SessionCancelHandle {
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    /// Cancels once and wakes both async handlers and the blocking owner wait.
    pub(crate) fn cancel(&self) -> bool {
        if self.shared.cancelled.swap(true, Ordering::AcqRel) {
            return false;
        }
        self.shared.notify.notify_waiters();
        self.owner_wake.signal();
        true
    }
}

impl Drop for SessionCancelHandle {
    fn drop(&mut self) {
        self.cancel();
    }
}

pub(crate) fn session_cancellation(
    generation: u64,
    owner_wake: OwnerWake,
) -> (SessionCancelHandle, SessionCancellation) {
    let shared = Arc::new(SessionCancellationState {
        cancelled: AtomicBool::new(false),
        notify: tokio::sync::Notify::new(),
    });
    (
        SessionCancelHandle {
            generation,
            shared: Arc::clone(&shared),
            owner_wake,
        },
        SessionCancellation { generation, shared },
    )
}

/// Bounded exponential retry schedule used only after an initial session has
/// reached Active. Startup remains bounded by `ready_timeout`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RestartBackoff {
    attempt: usize,
}

impl RestartBackoff {
    pub(crate) fn next_delay(&mut self) -> Duration {
        let index = self.attempt.min(RESTART_BACKOFF_MILLIS.len() - 1);
        self.attempt = self.attempt.saturating_add(1);
        Duration::from_millis(RESTART_BACKOFF_MILLIS[index])
    }

    pub(crate) fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// Debounces a burst of raw Windows notifications while retaining the newest
/// observed platform generation. Time is supplied by the owner for
/// deterministic tests and a single clock domain.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct NetworkDebounce {
    generation: Option<u64>,
    deadline_millis: Option<i64>,
}

impl NetworkDebounce {
    pub(crate) fn observe(&mut self, generation: u64, now_millis: i64) {
        self.generation = Some(generation);
        self.deadline_millis = Some(
            now_millis
                .saturating_add(i64::try_from(NETWORK_DEBOUNCE.as_millis()).unwrap_or(i64::MAX)),
        );
    }

    pub(crate) const fn deadline_millis(&self) -> Option<i64> {
        self.deadline_millis
    }

    pub(crate) fn take_ready(&mut self, now_millis: i64) -> Option<u64> {
        if self
            .deadline_millis
            .is_none_or(|deadline| now_millis < deadline)
        {
            return None;
        }
        self.deadline_millis = None;
        self.generation.take()
    }

    pub(crate) fn clear(&mut self) {
        self.generation = None;
        self.deadline_millis = None;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[tokio::test]
    async fn session_cancel_is_generation_bound_idempotent_and_wakes_waiters() {
        let wake_count = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&wake_count);
        let wake = OwnerWake::new(move || {
            observed.fetch_add(1, Ordering::SeqCst);
        });
        let (handle, token) = session_cancellation(41, wake);
        let waiter = tokio::spawn({
            let token = token.clone();
            async move { token.cancelled().await }
        });

        assert_eq!(handle.generation(), 41);
        assert_eq!(token.generation(), 41);
        assert!(!token.is_cancelled());
        assert!(handle.cancel());
        assert!(!handle.cancel());
        waiter.await.expect("session cancellation waiter");
        assert!(token.is_cancelled());
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn restart_backoff_is_bounded_and_resets_after_a_stable_session() {
        let mut backoff = RestartBackoff::default();
        let observed = (0..8).map(|_| backoff.next_delay()).collect::<Vec<_>>();
        assert_eq!(
            observed,
            [250, 500, 1_000, 2_000, 5_000, 5_000, 5_000, 5_000].map(Duration::from_millis)
        );
        backoff.reset();
        assert_eq!(backoff.next_delay(), Duration::from_millis(250));
    }

    #[test]
    fn notification_burst_keeps_only_latest_generation_and_extends_debounce() {
        let mut debounce = NetworkDebounce::default();
        debounce.observe(7, 1_000);
        assert_eq!(debounce.deadline_millis(), Some(1_350));
        debounce.observe(8, 1_200);
        assert_eq!(debounce.deadline_millis(), Some(1_550));
        assert_eq!(debounce.take_ready(1_549), None);
        assert_eq!(debounce.take_ready(1_550), Some(8));
        assert_eq!(debounce.take_ready(i64::MAX), None);

        debounce.observe(9, i64::MAX - 1);
        assert_eq!(debounce.deadline_millis(), Some(i64::MAX));
        debounce.clear();
        assert_eq!(debounce, NetworkDebounce::default());
    }
}
