use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

/// A one-shot subscription that completes after its captured generation changes.
///
/// The subscription is runtime-neutral and may be awaited by any executor. Dropping
/// it unregisters any stored waker.
#[must_use = "generation changes are observed by awaiting this subscription"]
pub struct GenerationChange {
    signal: GenerationSignal,
    baseline: u64,
    subscriber: Option<u64>,
    completed: Option<u64>,
}

impl GenerationChange {
    /// Returns the generation captured when this subscription was created.
    pub const fn baseline(&self) -> u64 {
        self.baseline
    }
}

impl Future for GenerationChange {
    type Output = u64;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Some(generation) = this.completed {
            return Poll::Ready(generation);
        }

        let mut state = this
            .signal
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generation != this.baseline {
            if let Some(subscriber) = this.subscriber.take() {
                state.subscribers.remove(&subscriber);
            }
            let generation = state.generation;
            drop(state);
            this.completed = Some(generation);
            return Poll::Ready(generation);
        }

        if let Some(subscriber) = this.subscriber {
            match state.subscribers.get_mut(&subscriber) {
                Some(waker) if !waker.will_wake(context.waker()) => {
                    waker.clone_from(context.waker());
                }
                Some(_) => {}
                None => {
                    state
                        .subscribers
                        .insert(subscriber, context.waker().clone());
                }
            }
        } else {
            let subscriber = state.next_subscriber();
            state
                .subscribers
                .insert(subscriber, context.waker().clone());
            this.subscriber = Some(subscriber);
        }
        Poll::Pending
    }
}

impl Drop for GenerationChange {
    fn drop(&mut self) {
        let Some(subscriber) = self.subscriber.take() else {
            return;
        };
        let mut state = self
            .signal
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.subscribers.remove(&subscriber);
    }
}

impl fmt::Debug for GenerationChange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenerationChange([redacted])")
    }
}

/// Runtime-neutral publisher for generation-change subscriptions.
///
/// This is public so runtime-neutral registries in downstream crates can share
/// the same watcher implementation. Application code normally obtains a
/// [`GenerationChange`] from the owning control or registry instead.
#[doc(hidden)]
#[derive(Clone)]
pub struct GenerationSignal {
    state: Arc<Mutex<GenerationState>>,
}

impl GenerationSignal {
    /// Starts a signal at one complete source generation.
    pub fn new(generation: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(GenerationState {
                generation,
                next_subscriber: 0,
                subscribers: BTreeMap::new(),
            })),
        }
    }

    /// Captures the current generation and creates an independent subscription.
    pub fn watch(&self) -> GenerationChange {
        let baseline = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .generation;
        self.watch_from(baseline)
    }

    /// Creates an independent subscription from a source generation captured
    /// by the caller's atomic operation.
    pub fn watch_from(&self, baseline: u64) -> GenerationChange {
        GenerationChange {
            signal: self.clone(),
            baseline,
            subscriber: None,
            completed: None,
        }
    }

    /// Records a completed generation and detaches all subscribers waiting on
    /// the previous generation.
    ///
    /// The caller must record this while its source publication remains
    /// serialized, then release the source lock before calling
    /// [`GenerationNotification::wake`].
    pub fn prepare_notification(&self, generation: u64) -> GenerationNotification {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generation == generation {
            return GenerationNotification::default();
        }
        state.generation = generation;
        GenerationNotification {
            wakers: std::mem::take(&mut state.subscribers)
                .into_values()
                .collect(),
        }
    }
}

impl Default for GenerationSignal {
    fn default() -> Self {
        Self::new(0)
    }
}

impl fmt::Debug for GenerationSignal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenerationSignal([redacted])")
    }
}

/// Detached wake operations for one completed generation publication.
#[doc(hidden)]
#[derive(Default)]
#[must_use = "release the source publication lock, then wake this notification"]
pub struct GenerationNotification {
    wakers: Vec<Waker>,
}

impl GenerationNotification {
    /// Wakes every subscriber that was pending when the generation changed.
    pub fn wake(self) {
        for waker in self.wakers {
            waker.wake();
        }
    }
}

struct GenerationState {
    generation: u64,
    next_subscriber: u64,
    subscribers: BTreeMap<u64, Waker>,
}

impl GenerationState {
    fn next_subscriber(&mut self) -> u64 {
        loop {
            let subscriber = self.next_subscriber;
            self.next_subscriber = self.next_subscriber.wrapping_add(1);
            if !self.subscribers.contains_key(&subscriber) {
                return subscriber;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::task::{Wake, Waker};
    use std::thread;

    use super::*;

    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn poll(change: &mut GenerationChange, waker: &Waker) -> Poll<u64> {
        Future::poll(Pin::new(change), &mut Context::from_waker(waker))
    }

    #[test]
    fn publication_wakes_every_independent_subscriber() {
        let signal = GenerationSignal::new(7);
        let first_wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let second_wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let first_waker = Waker::from(Arc::clone(&first_wakes));
        let second_waker = Waker::from(Arc::clone(&second_wakes));
        let mut first = signal.watch();
        let mut second = signal.watch();
        assert_eq!(first.baseline(), 7);
        assert_eq!(poll(&mut first, &first_waker), Poll::Pending);
        assert_eq!(poll(&mut second, &second_waker), Poll::Pending);

        signal.prepare_notification(9).wake();

        assert_eq!(first_wakes.0.load(Ordering::SeqCst), 1);
        assert_eq!(second_wakes.0.load(Ordering::SeqCst), 1);
        assert_eq!(poll(&mut first, &first_waker), Poll::Ready(9));
        assert_eq!(poll(&mut second, &second_waker), Poll::Ready(9));
    }

    #[test]
    fn publication_before_first_poll_is_not_lost() {
        let signal = GenerationSignal::new(11);
        let mut change = signal.watch();
        signal.prepare_notification(12).wake();
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));

        assert_eq!(poll(&mut change, &waker), Poll::Ready(12));
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn dropping_pending_subscription_releases_its_waker() {
        let signal = GenerationSignal::new(1);
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        let mut change = signal.watch();
        assert_eq!(poll(&mut change, &waker), Poll::Pending);
        drop(waker);
        assert_eq!(Arc::strong_count(&wakes), 2);

        drop(change);

        assert_eq!(Arc::strong_count(&wakes), 1);
        signal.prepare_notification(2).wake();
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn repoll_replaces_an_obsolete_waker_without_retaining_it() {
        let signal = GenerationSignal::new(3);
        let first_wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let second_wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let first_waker = Waker::from(Arc::clone(&first_wakes));
        let second_waker = Waker::from(Arc::clone(&second_wakes));
        let mut change = signal.watch();
        assert_eq!(poll(&mut change, &first_waker), Poll::Pending);
        assert_eq!(poll(&mut change, &second_waker), Poll::Pending);

        signal.prepare_notification(4).wake();

        assert_eq!(first_wakes.0.load(Ordering::SeqCst), 0);
        assert_eq!(second_wakes.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn concurrent_registration_and_publication_never_lose_a_change() {
        let signal = GenerationSignal::new(0);
        for generation in 1..=128 {
            let mut change = signal.watch();
            let barrier = Arc::new(Barrier::new(2));
            let publisher_barrier = Arc::clone(&barrier);
            let publisher_signal = signal.clone();
            let publisher = thread::spawn(move || {
                publisher_barrier.wait();
                publisher_signal.prepare_notification(generation).wake();
            });
            let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
            let waker = Waker::from(Arc::clone(&wakes));

            barrier.wait();
            let first_poll = poll(&mut change, &waker);
            publisher.join().expect("publisher");

            assert_eq!(poll(&mut change, &waker), Poll::Ready(generation));
            match first_poll {
                Poll::Pending => assert_eq!(wakes.0.load(Ordering::SeqCst), 1),
                Poll::Ready(observed) => {
                    assert_eq!(observed, generation);
                    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
                }
            }
        }
    }
}
