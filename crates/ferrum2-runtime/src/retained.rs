use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Closed retained-work failure; underlying monitor errors are never exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedMonitorError {
    Wait,
    Cleanup,
}

/// Retained blocking-work seam. Implementors must retain resources and stop handles
/// through wait, make signal interrupt that wait, and close resources only after
/// wait returns. Closing consumes the sole monitor. Errors remain opaque to callers.
pub trait RetainedMonitor: Send + 'static {
    type Outcome: Send + 'static;
    type Error: Send + 'static;
    type Stop: Clone + Send + Sync;
    fn stop(&self) -> Self::Stop;
    fn signal(stop: &Self::Stop) -> Result<(), Self::Error>;
    fn wait(&mut self, timeout: Duration) -> Result<Self::Outcome, Self::Error>;
    fn close(self) -> Result<(), Self::Error>;
}

type MonitorCompletion<M> = (
    M,
    Result<<M as RetainedMonitor>::Outcome, <M as RetainedMonitor>::Error>,
);

enum Phase<M: RetainedMonitor> {
    Idle(M),
    Waiting(tokio::task::JoinHandle<MonitorCompletion<M>>),
    Closed,
}
struct State<M: RetainedMonitor> {
    phase: Phase<M>,
    failed: bool,
}

/// Unique external cleanup owner, retained beyond cancellation/abort of process roots.
///
/// Call `shutdown` before dropping this owner. Dropping a waiter or cancelling its
/// future is safe, but cannot replace joining and closing the real blocking work.
#[must_use = "retained monitors must be shut down to join and close their work"]
pub struct RetainedMonitorOwner<M: RetainedMonitor> {
    state: Arc<Mutex<State<M>>>,
    stop: M::Stop,
    completed: Option<Result<(), RetainedMonitorError>>,
    signal_failed: bool,
}
/// A waiter borrows retained work; dropping its future never drops the native join.
pub struct RetainedMonitorWait<M: RetainedMonitor> {
    state: Arc<Mutex<State<M>>>,
}
impl<M: RetainedMonitor> Clone for RetainedMonitorWait<M> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}
impl<M: RetainedMonitor> RetainedMonitorOwner<M> {
    pub fn new(monitor: M) -> (Self, RetainedMonitorWait<M>) {
        let stop = monitor.stop();
        let state = Arc::new(Mutex::new(State {
            phase: Phase::Idle(monitor),
            failed: false,
        }));
        (
            Self {
                state: Arc::clone(&state),
                stop,
                completed: None,
                signal_failed: false,
            },
            RetainedMonitorWait { state },
        )
    }
    pub async fn shutdown(&mut self) -> Result<(), RetainedMonitorError> {
        if let Some(result) = self.completed {
            return result;
        }
        // Signal before taking the state lock: an active waiter may hold that lock
        // while awaiting the retained native operation.
        self.signal_failed |= M::signal(&self.stop).is_err();
        let mut state = self.state.lock().await;
        state.failed |= self.signal_failed;
        if let Phase::Waiting(join) = &mut state.phase {
            match join.await {
                Ok((monitor, outcome)) => {
                    state.failed |= outcome.is_err();
                    state.phase = Phase::Idle(monitor);
                }
                Err(_) => {
                    state.failed = true;
                    state.phase = Phase::Closed;
                }
            }
        }
        if let Phase::Idle(monitor) = std::mem::replace(&mut state.phase, Phase::Closed) {
            state.failed |= monitor.close().is_err();
        }
        let result = if state.failed {
            Err(RetainedMonitorError::Cleanup)
        } else {
            Ok(())
        };
        self.completed = Some(result);
        result
    }
}
impl<M: RetainedMonitor> RetainedMonitorWait<M> {
    pub async fn wait(&self, timeout: Duration) -> Result<M::Outcome, RetainedMonitorError> {
        let mut state = self.state.lock().await;
        if matches!(state.phase, Phase::Idle(_)) {
            let Phase::Idle(mut monitor) = std::mem::replace(&mut state.phase, Phase::Closed)
            else {
                unreachable!()
            };
            // No await between spawn and retained handle publication.
            state.phase = Phase::Waiting(tokio::task::spawn_blocking(move || {
                let outcome = monitor.wait(timeout);
                (monitor, outcome)
            }));
        }
        let Phase::Waiting(join) = &mut state.phase else {
            return Err(RetainedMonitorError::Wait);
        };
        match join.await {
            Ok((monitor, outcome)) => {
                state.failed |= outcome.is_err();
                state.phase = Phase::Idle(monitor);
                outcome.map_err(|_| RetainedMonitorError::Wait)
            }
            Err(_) => {
                state.failed = true;
                state.phase = Phase::Closed;
                Err(RetainedMonitorError::Wait)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Fake {
        stopped: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
        entered: Arc<tokio::sync::Notify>,
        closed: Arc<AtomicUsize>,
        completion: Option<Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>>,
        close_failure: bool,
    }
    impl RetainedMonitor for Fake {
        type Outcome = ();
        type Error = ();
        type Stop = Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>;
        fn stop(&self) -> Self::Stop {
            Arc::clone(&self.stopped)
        }
        fn signal(stop: &Self::Stop) -> Result<(), ()> {
            *stop.0.lock().unwrap() = true;
            stop.1.notify_all();
            Ok(())
        }
        fn wait(&mut self, _: Duration) -> Result<(), ()> {
            self.entered.notify_one();
            let stopped = self.stopped.0.lock().unwrap();
            let (stopped, timeout) = self
                .stopped
                .1
                .wait_timeout_while(stopped, Duration::from_secs(5), |stopped| !*stopped)
                .unwrap();
            if timeout.timed_out() || !*stopped {
                return Err(());
            }
            if let Some(completion) = &self.completion {
                let released = completion.0.lock().unwrap();
                let (_released, timeout) = completion
                    .1
                    .wait_timeout_while(released, Duration::from_secs(5), |released| !*released)
                    .unwrap();
                if timeout.timed_out() {
                    return Err(());
                }
            }
            Ok(())
        }
        fn close(self) -> Result<(), ()> {
            self.closed.fetch_add(1, Ordering::AcqRel);
            if self.close_failure { Err(()) } else { Ok(()) }
        }
    }
    #[tokio::test]
    async fn dropped_waiter_leaves_native_join_for_external_cleanup() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let closed = Arc::new(AtomicUsize::new(0));
        let (mut owner, waiter) = RetainedMonitorOwner::new(Fake {
            stopped: Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new())),
            entered: Arc::clone(&entered),
            closed: Arc::clone(&closed),
            completion: None,
            close_failure: false,
        });
        let task = tokio::spawn(async move { waiter.wait(Duration::from_secs(1)).await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(closed.load(Ordering::Acquire), 0);
        tokio::time::timeout(Duration::from_secs(2), owner.shutdown())
            .await
            .unwrap()
            .unwrap();
        owner.shutdown().await.unwrap();
        assert_eq!(closed.load(Ordering::Acquire), 1);
    }
    #[tokio::test]
    async fn cancelled_cleanup_resumes_the_same_native_join_and_keeps_close_errors() {
        for close_failure in [false, true] {
            let entered = Arc::new(tokio::sync::Notify::new());
            let closed = Arc::new(AtomicUsize::new(0));
            let completion = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
            let (mut owner, waiter) = RetainedMonitorOwner::new(Fake {
                stopped: Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new())),
                entered: Arc::clone(&entered),
                closed: Arc::clone(&closed),
                completion: Some(Arc::clone(&completion)),
                close_failure,
            });
            let task = tokio::spawn(async move { waiter.wait(Duration::from_secs(1)).await });
            tokio::time::timeout(Duration::from_secs(2), entered.notified())
                .await
                .unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert!(
                tokio::time::timeout(Duration::from_millis(20), owner.shutdown())
                    .await
                    .is_err()
            );
            assert_eq!(closed.load(Ordering::Acquire), 0);
            *completion.0.lock().unwrap() = true;
            completion.1.notify_all();
            let expected = if close_failure {
                Err(RetainedMonitorError::Cleanup)
            } else {
                Ok(())
            };
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), owner.shutdown())
                    .await
                    .unwrap(),
                expected
            );
            assert_eq!(owner.shutdown().await, expected);
            assert_eq!(closed.load(Ordering::Acquire), 1);
        }
    }

    #[tokio::test]
    async fn repeated_waits_reuse_monitor_and_shutdown_closes_waiter_clones() {
        struct Counting {
            count: usize,
            closed: Arc<AtomicUsize>,
        }
        impl RetainedMonitor for Counting {
            type Outcome = usize;
            type Error = ();
            type Stop = ();
            fn stop(&self) {}
            fn signal(_: &()) -> Result<(), ()> {
                Ok(())
            }
            fn wait(&mut self, _: Duration) -> Result<usize, ()> {
                self.count += 1;
                Ok(self.count)
            }
            fn close(self) -> Result<(), ()> {
                self.closed.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }
        }
        let closed = Arc::new(AtomicUsize::new(0));
        let (mut owner, waiter) = RetainedMonitorOwner::new(Counting {
            count: 0,
            closed: Arc::clone(&closed),
        });
        let other = waiter.clone();
        assert_eq!(waiter.wait(Duration::ZERO).await, Ok(1));
        drop(waiter);
        assert_eq!(other.wait(Duration::ZERO).await, Ok(2));
        owner.shutdown().await.unwrap();
        assert_eq!(
            other.wait(Duration::ZERO).await,
            Err(RetainedMonitorError::Wait)
        );
        owner.shutdown().await.unwrap();
        assert_eq!(closed.load(Ordering::Acquire), 1);
    }
}
