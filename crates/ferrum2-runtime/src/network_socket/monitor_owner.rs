use std::collections::BTreeMap;
use std::future::Future;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use futures_util::FutureExt;
use tokio::sync::{Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch};

use crate::OwnerRegistry;
use crate::owner::OwnerGuard;

/// Closed network-work admission and cleanup outcomes; no native details escape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkSocketOwnerError {
    Busy,
    Closed,
    Capture,
    WorkerFailed,
}

/// Unique lifetime authority for socket monitors and the single native capture.
/// Cancellation of an await retains all task handles for a later join retry.
#[must_use = "retain and await shutdown to confirm network work joined"]
pub struct NetworkSocketOwner {
    pub(super) shared: Arc<Shared>,
}

#[derive(Clone)]
pub(super) struct Registrar {
    shared: Weak<Shared>,
}

pub(super) struct Shared {
    pub(super) state: Mutex<State>,
    slots: Arc<Semaphore>,
    capacity: usize,
    pub(super) owners: OwnerRegistry,
    changed: Arc<Notify>,
    stop: watch::Sender<bool>,
    completed: mpsc::Sender<u64>,
    pub(super) failure: Arc<AtomicBool>,
}

pub(super) struct State {
    pub(super) accepting: bool,
    retired: Option<u64>,
    monitors: BTreeMap<u64, MonitorRecord>,
    next_monitor: u64,
    completed: mpsc::Receiver<u64>,
    deferred_completion: Option<u64>,
    pub(super) capture: Option<Arc<TrackedTask>>,
}

struct MonitorRecord {
    generation: u64,
    task: Arc<TrackedTask>,
}

/// Constructed before spawn, so abort before the first poll still notifies the
/// parent. The bounded channel contains at most one ID per admitted monitor.
struct MonitorCompletion {
    id: u64,
    sender: mpsc::Sender<u64>,
    failure: Arc<AtomicBool>,
}
impl Drop for MonitorCompletion {
    fn drop(&mut self) {
        if let Err(mpsc::error::TrySendError::Full(_)) = self.sender.try_send(self.id) {
            // Admission drains notifications before allocating a new slot, so
            // this is an invariant failure, never a reason to detach a join.
            self.failure.store(true, Ordering::Release);
        }
    }
}

pub(super) struct Accounting {
    _guard: Option<OwnerGuard>,
    _permit: Option<OwnedSemaphorePermit>,
    changed: Arc<Notify>,
}
impl Drop for Accounting {
    fn drop(&mut self) {
        drop(self._permit.take());
        drop(self._guard.take());
        self.changed.notify_one();
    }
}

pub(super) struct TrackedTask {
    task: AsyncMutex<Option<PendingTask>>,
    stop: watch::Sender<bool>,
    failure: Arc<AtomicBool>,
}

struct PendingTask {
    join: tokio::task::JoinHandle<Result<(), NetworkSocketOwnerError>>,
    _accounting: Accounting,
}

impl TrackedTask {
    pub(super) fn new(
        task: tokio::task::JoinHandle<Result<(), NetworkSocketOwnerError>>,
        accounting: Accounting,
        stop: watch::Sender<bool>,
        failure: Arc<AtomicBool>,
    ) -> Self {
        Self {
            task: AsyncMutex::new(Some(PendingTask {
                join: task,
                _accounting: accounting,
            })),
            stop,
            failure,
        }
    }

    fn observe(&self, result: Result<Result<(), NetworkSocketOwnerError>, tokio::task::JoinError>) {
        if !matches!(result, Ok(Ok(()))) {
            self.failure.store(true, Ordering::Release);
        }
    }

    pub(super) fn reap_ready(&self) -> bool {
        let Ok(mut task) = self.task.try_lock() else {
            return false;
        };
        let Some(PendingTask { join, .. }) = task.as_mut() else {
            return true;
        };
        if !join.is_finished() {
            return false;
        }
        if let Some(result) = (&mut *join).now_or_never() {
            self.observe(result);
            *task = None;
            true
        } else {
            false
        }
    }

    pub(super) async fn join(&self) {
        let mut task = self.task.lock().await;
        if let Some(PendingTask { join, .. }) = task.as_mut() {
            self.observe(join.await);
            *task = None;
        }
    }
    fn cancel(&self) {
        self.stop.send_replace(true);
    }
}

/// A bounded reservation precedes any physical resource preparation.
pub(super) struct MonitorReservation {
    shared: Weak<Shared>,
    accounting: Accounting,
    stop: watch::Sender<bool>,
    global_stop: MonitorStop,
}

#[derive(Clone)]
pub(super) struct MonitorStop(watch::Receiver<bool>);
impl MonitorStop {
    pub(super) async fn stopped(&mut self) {
        loop {
            if *self.0.borrow_and_update() {
                return;
            }
            if self.0.changed().await.is_err() {
                return;
            }
        }
    }
}

impl MonitorReservation {
    pub(super) fn stop(&self) -> MonitorStop {
        MonitorStop(self.stop.subscribe())
    }
    pub(super) async fn stopped(&mut self) {
        self.global_stop.stopped().await;
    }
    pub(super) fn spawn(
        self,
        generation: u64,
        future: impl Future<Output = Result<(), NetworkSocketOwnerError>> + Send + 'static,
    ) -> Result<(), NetworkSocketOwnerError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(NetworkSocketOwnerError::Closed)?;
        let mut state = lock(&shared.state);
        if !state.accepting || state.retired.is_some_and(|retired| generation <= retired) {
            return Err(NetworkSocketOwnerError::Closed);
        }
        let id = state.next_monitor;
        state.next_monitor = id.checked_add(1).ok_or(NetworkSocketOwnerError::Closed)?;
        let completion = MonitorCompletion {
            id,
            sender: shared.completed.clone(),
            failure: Arc::clone(&shared.failure),
        };
        let task = tokio::spawn(async move {
            let _completion = completion;
            future.await
        });
        // No await between physical-owner transfer, spawn, and parent registration.
        state.monitors.insert(
            id,
            MonitorRecord {
                generation,
                task: Arc::new(TrackedTask::new(
                    task,
                    self.accounting,
                    self.stop,
                    Arc::clone(&shared.failure),
                )),
            },
        );
        Ok(())
    }
}

impl Registrar {
    pub(super) fn reserve(&self) -> Result<MonitorReservation, NetworkSocketOwnerError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(NetworkSocketOwnerError::Closed)?;
        let mut state = lock(&shared.state);
        if !state.accepting {
            return Err(NetworkSocketOwnerError::Closed);
        }
        reap_completed(&mut state)?;
        if shared.failure.load(Ordering::Acquire) {
            return Err(NetworkSocketOwnerError::WorkerFailed);
        }
        let permit = Arc::clone(&shared.slots)
            .try_acquire_owned()
            .map_err(|_| NetworkSocketOwnerError::Busy)?;
        let (stop, _) = watch::channel(false);
        Ok(MonitorReservation {
            shared: Arc::downgrade(&shared),
            accounting: Accounting {
                _guard: Some(shared.owners.track_network_socket_monitor()),
                _permit: Some(permit),
                changed: Arc::clone(&shared.changed),
            },
            stop,
            global_stop: MonitorStop(shared.stop.subscribe()),
        })
    }
    pub(super) fn shared(&self) -> Result<Arc<Shared>, NetworkSocketOwnerError> {
        self.shared.upgrade().ok_or(NetworkSocketOwnerError::Closed)
    }
}

impl NetworkSocketOwner {
    pub(super) fn new(capacity: NonZeroUsize, owners: OwnerRegistry) -> (Registrar, Self) {
        let (stop, _) = watch::channel(false);
        let (completed, completions) = mpsc::channel(capacity.get());
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                accepting: true,
                retired: None,
                monitors: BTreeMap::new(),
                next_monitor: 0,
                completed: completions,
                deferred_completion: None,
                capture: None,
            }),
            slots: Arc::new(Semaphore::new(capacity.get())),
            capacity: capacity.get(),
            owners,
            changed: Arc::new(Notify::new()),
            stop,
            completed,
            failure: Arc::new(AtomicBool::new(false)),
        });
        (
            Registrar {
                shared: Arc::downgrade(&shared),
            },
            Self { shared },
        )
    }

    /// Closes monitor admission through the retired generation and joins that
    /// fence only. Newer-generation monitors cannot prolong this barrier.
    /// Call after the coordinator has closed retired-generation physical admission
    /// and drained its in-flight connect owners; this fence covers socket monitors.
    pub async fn retire_generation(
        &mut self,
        generation: u64,
    ) -> Result<(), NetworkSocketOwnerError> {
        {
            let mut state = lock(&self.shared.state);
            state.retired = Some(state.retired.map_or(generation, |old| old.max(generation)));
            for record in state.monitors.values() {
                if record.generation <= generation {
                    record.task.cancel();
                }
            }
        }
        self.join_monitors(Some(generation)).await;
        self.result()
    }

    async fn join_monitors(&self, through: Option<u64>) {
        let mut after = std::ops::Bound::Unbounded;
        loop {
            let task = lock(&self.shared.state)
                .monitors
                .range((after, std::ops::Bound::Unbounded))
                .find(|(_, record)| through.is_none_or(|end| record.generation <= end))
                .map(|(id, record)| (*id, Arc::clone(&record.task)));
            let Some((id, task)) = task else {
                return;
            };
            after = std::ops::Bound::Excluded(id);
            task.join().await;
            lock(&self.shared.state).monitors.remove(&id);
        }
    }

    /// Closes admission, stops physical monitors and joins every retained task.
    /// Native capture is not forcibly interruptible; pending cleanup stays owned.
    pub async fn shutdown(&mut self) -> Result<(), NetworkSocketOwnerError> {
        self.close();
        let capture = lock(&self.shared.state).capture.clone();
        if let Some(capture) = capture {
            capture.join().await;
            lock(&self.shared.state).capture = None;
        }
        self.join_monitors(None).await;
        loop {
            let changed = self.shared.changed.notified();
            if self.shared.slots.available_permits() == self.shared.capacity {
                break;
            }
            changed.await;
        }
        self.result()
    }
    fn close(&self) {
        let mut state = lock(&self.shared.state);
        state.accepting = false;
        self.shared.stop.send_replace(true);
        for record in state.monitors.values() {
            record.task.cancel();
        }
        if let Some(capture) = &state.capture {
            capture.cancel();
        }
    }
    fn result(&self) -> Result<(), NetworkSocketOwnerError> {
        if self.shared.failure.load(Ordering::Acquire) {
            Err(NetworkSocketOwnerError::WorkerFailed)
        } else {
            Ok(())
        }
    }
}
impl Drop for NetworkSocketOwner {
    fn drop(&mut self) {
        self.close();
    }
}

/// Only completed IDs are visited on admission; active monitors are never scanned.
/// A drop notification may beat Tokio's final JoinHandle readiness by a few
/// instructions. Keep that ID and reject this admission until its join is ready.
fn reap_completed(state: &mut State) -> Result<(), NetworkSocketOwnerError> {
    loop {
        let Some(id) = state
            .deferred_completion
            .take()
            .or_else(|| state.completed.try_recv().ok())
        else {
            return Ok(());
        };
        let Some(record) = state.monitors.get(&id) else {
            continue;
        };
        if !record.task.reap_ready() {
            state.deferred_completion = Some(id);
            return Err(NetworkSocketOwnerError::Busy);
        }
        state.monitors.remove(&id);
    }
}

pub(super) fn capture_accounting(shared: &Shared) -> Accounting {
    Accounting {
        _guard: Some(shared.owners.track_network_snapshot_capture()),
        _permit: None,
        changed: Arc::clone(&shared.changed),
    }
}
pub(super) fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests;
