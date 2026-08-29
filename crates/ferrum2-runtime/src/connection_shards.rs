use std::{
    fmt,
    marker::PhantomData,
    num::NonZeroUsize,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc as std_mpsc,
    },
    thread::{self, JoinHandle},
};

use thiserror::Error;
use tokio::{runtime::Handle, sync::oneshot};

#[cfg(target_os = "linux")]
use rustix::thread::{CpuSet, sched_getaffinity, sched_setaffinity};

/// An opaque failure to start every requested connection runtime shard.
///
/// The underlying thread or Tokio runtime error is deliberately not retained.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("connection runtime pool startup failed")]
pub struct ConnectionRuntimePoolStartupError;

/// Owns a fixed set of current-thread Tokio runtimes for whole connections.
///
/// Each shard runs on one dedicated OS thread. A [`BoundedSupervisor`](crate::BoundedSupervisor)
/// can use [`Self::dispatcher`] to place each accepted connection on one shard while retaining
/// exact ownership of the task in its own `JoinSet`. The pool must outlive every supervisor using
/// its dispatcher and should be dropped only after those supervisors have completed.
pub struct ConnectionRuntimePool {
    dispatcher: ConnectionRuntimeDispatcher,
    workers: Vec<ShardWorker>,
    // The owner joins every worker synchronously on drop. Keeping it on its
    // constructing thread makes moving it into one of those workers impossible;
    // only the dispatcher is intended to cross thread boundaries.
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl ConnectionRuntimePool {
    /// Starts up to `max_shards` dedicated current-thread Tokio runtimes.
    ///
    /// On Linux, the pool discovers the constructing thread's allowed CPU mask
    /// and starts at most one shard per allowed CPU. Each shard sets and reads
    /// back a singleton affinity mask before building its Tokio runtime. This
    /// returns only after every shard has completed those steps. Any discovery,
    /// affinity, thread, or runtime failure tears down the whole partial pool.
    pub fn new(max_shards: NonZeroUsize) -> Result<Self, ConnectionRuntimePoolStartupError> {
        let shard_cpu_ids = shard_cpu_ids(max_shards)?;
        let mut shards = Vec::with_capacity(shard_cpu_ids.len());
        let mut workers = Vec::with_capacity(shard_cpu_ids.len());

        for (shard_index, cpu_id) in shard_cpu_ids.into_iter().enumerate() {
            match start_shard(shard_index, cpu_id) {
                Ok((handle, worker)) => {
                    shards.push(ShardHandle { cpu_id, handle });
                    workers.push(worker);
                }
                Err(error) => {
                    shutdown_workers(&mut workers);
                    return Err(error);
                }
            }
        }

        Ok(Self {
            dispatcher: ConnectionRuntimeDispatcher {
                inner: Arc::new(DispatcherInner {
                    next_shard: AtomicUsize::new(0),
                    shards,
                }),
            },
            workers,
            _not_send_or_sync: PhantomData,
        })
    }

    /// Returns an opaque cloneable dispatcher sharing this pool's round-robin sequence.
    #[must_use]
    pub fn dispatcher(&self) -> ConnectionRuntimeDispatcher {
        self.dispatcher.clone()
    }
}

impl Drop for ConnectionRuntimePool {
    fn drop(&mut self) {
        shutdown_workers(&mut self.workers);
    }
}

/// Opaque connection-runtime selection state shared by bounded supervisors.
///
/// The supervisor remains the sole owner of every connection task. This value
/// selects only the Tokio runtime on which its `JoinSet` spawns that task.
#[derive(Clone)]
pub struct ConnectionRuntimeDispatcher {
    inner: Arc<DispatcherInner>,
}

impl ConnectionRuntimeDispatcher {
    pub(crate) fn handle_for_cpu_or_next(&self, cpu_hint: Option<usize>) -> &Handle {
        if let Some(cpu_id) = cpu_hint
            && let Some(shard) = self
                .inner
                .shards
                .iter()
                .find(|shard| shard.cpu_id == Some(cpu_id))
        {
            return &shard.handle;
        }

        let shard_index =
            self.inner.next_shard.fetch_add(1, Ordering::Relaxed) % self.inner.shards.len();
        &self.inner.shards[shard_index].handle
    }
}

impl fmt::Debug for ConnectionRuntimeDispatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionRuntimeDispatcher")
            .field("shard_count", &self.inner.shards.len())
            .finish_non_exhaustive()
    }
}

struct DispatcherInner {
    next_shard: AtomicUsize,
    shards: Vec<ShardHandle>,
}

struct ShardHandle {
    cpu_id: Option<usize>,
    handle: Handle,
}

struct ShardWorker {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

fn start_shard(
    shard_index: usize,
    cpu_id: Option<usize>,
) -> Result<(Handle, ShardWorker), ConnectionRuntimePoolStartupError> {
    let (stop_sender, stop_receiver) = oneshot::channel();
    let (started_sender, started_receiver) = std_mpsc::sync_channel(0);

    let worker_thread = thread::Builder::new()
        .name(format!("ferrum2-connection-{shard_index}"))
        .spawn(move || {
            if pin_current_thread(cpu_id).is_err() {
                return;
            }
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };

            if started_sender.send(runtime.handle().clone()).is_err() {
                return;
            }
            runtime.block_on(async move {
                let _closed = stop_receiver.await;
            });
        })
        .map_err(|_closed| ConnectionRuntimePoolStartupError)?;

    let handle = match started_receiver.recv() {
        Ok(handle) => handle,
        Err(_closed) => {
            let _closed = stop_sender.send(());
            let _closed = worker_thread.join();
            return Err(ConnectionRuntimePoolStartupError);
        }
    };

    Ok((
        handle,
        ShardWorker {
            stop: Some(stop_sender),
            thread: Some(worker_thread),
        },
    ))
}

#[cfg(target_os = "linux")]
fn shard_cpu_ids(
    max_shards: NonZeroUsize,
) -> Result<Vec<Option<usize>>, ConnectionRuntimePoolStartupError> {
    let allowed = sched_getaffinity(None).map_err(|_| ConnectionRuntimePoolStartupError)?;
    let cpu_ids = (0..CpuSet::MAX_CPU)
        .filter(|cpu_id| allowed.is_set(*cpu_id))
        .take(max_shards.get())
        .map(Some)
        .collect::<Vec<_>>();
    if cpu_ids.is_empty() {
        return Err(ConnectionRuntimePoolStartupError);
    }
    Ok(cpu_ids)
}

#[cfg(not(target_os = "linux"))]
fn shard_cpu_ids(
    max_shards: NonZeroUsize,
) -> Result<Vec<Option<usize>>, ConnectionRuntimePoolStartupError> {
    Ok((0..max_shards.get()).map(|_| None).collect())
}

#[cfg(target_os = "linux")]
fn pin_current_thread(cpu_id: Option<usize>) -> Result<(), ConnectionRuntimePoolStartupError> {
    let cpu_id = cpu_id.ok_or(ConnectionRuntimePoolStartupError)?;
    let mut singleton = CpuSet::new();
    singleton.set(cpu_id);
    sched_setaffinity(None, &singleton).map_err(|_| ConnectionRuntimePoolStartupError)?;
    let observed = sched_getaffinity(None).map_err(|_| ConnectionRuntimePoolStartupError)?;
    if observed != singleton {
        return Err(ConnectionRuntimePoolStartupError);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn pin_current_thread(cpu_id: Option<usize>) -> Result<(), ConnectionRuntimePoolStartupError> {
    if cpu_id.is_some() {
        return Err(ConnectionRuntimePoolStartupError);
    }
    Ok(())
}

fn shutdown_workers(workers: &mut [ShardWorker]) {
    for worker in workers.iter_mut() {
        if let Some(stop) = worker.stop.take() {
            let _closed = stop.send(());
        }
    }
    for worker in workers.iter_mut() {
        if let Some(worker_thread) = worker.thread.take() {
            let _closed = worker_thread.join();
        }
    }
}
