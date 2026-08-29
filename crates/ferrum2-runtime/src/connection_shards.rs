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
    /// Starts `shard_count` dedicated current-thread Tokio runtimes.
    ///
    /// This returns only after every shard has built its runtime. Startup fails
    /// closed and tears down any shards that were already started.
    pub fn new(shard_count: NonZeroUsize) -> Result<Self, ConnectionRuntimePoolStartupError> {
        let mut handles = Vec::with_capacity(shard_count.get());
        let mut workers = Vec::with_capacity(shard_count.get());

        for shard_index in 0..shard_count.get() {
            match start_shard(shard_index) {
                Ok((handle, worker)) => {
                    handles.push(handle);
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
                    handles,
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
    pub(crate) fn next_handle(&self) -> &Handle {
        let shard_index =
            self.inner.next_shard.fetch_add(1, Ordering::Relaxed) % self.inner.handles.len();
        &self.inner.handles[shard_index]
    }
}

impl fmt::Debug for ConnectionRuntimeDispatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionRuntimeDispatcher")
            .field("shard_count", &self.inner.handles.len())
            .finish_non_exhaustive()
    }
}

struct DispatcherInner {
    next_shard: AtomicUsize,
    handles: Vec<Handle>,
}

struct ShardWorker {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

fn start_shard(
    shard_index: usize,
) -> Result<(Handle, ShardWorker), ConnectionRuntimePoolStartupError> {
    let (stop_sender, stop_receiver) = oneshot::channel();
    let (started_sender, started_receiver) = std_mpsc::sync_channel(0);

    let worker_thread = thread::Builder::new()
        .name(format!("ferrum2-connection-{shard_index}"))
        .spawn(move || {
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
