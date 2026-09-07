//! Actual native lookup work remains charged until its join is observed.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::{Id, JoinHandle, JoinSet};
use tokio::time::Instant;

mod adapters;
mod native;
use native::{Candidates, NativeLookup, SystemLookup};

/// Closed, peer-redacting failure from the bounded system resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemResolutionError {
    InvalidLimits,
    Busy,
    Timeout,
    Shutdown,
    Resolution,
    WorkerFailed,
}

impl fmt::Display for SystemResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLimits => "invalid system resolution limits",
            Self::Busy => "system resolution capacity exhausted",
            Self::Timeout => "system resolution deadline elapsed",
            Self::Shutdown => "system resolution closed",
            Self::Resolution => "system resolution failed",
            Self::WorkerFailed => "system resolution worker failed",
        })
    }
}
impl std::error::Error for SystemResolutionError {}

/// Successful shutdown proves every accepted operation and dispatcher was joined.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SystemResolutionReport {
    pub outstanding_operations: usize,
}

struct Shared {
    slots: Arc<Semaphore>,
    stop: Notify,
    timeout: Duration,
}

impl Shared {
    fn close(&self) {
        self.slots.close();
        self.stop.notify_one();
    }
}

/// Starts one process-owned native resolver, separately budgeted from tagged DNS.
pub struct SystemResolution;

impl SystemResolution {
    /// Uses the validated DNS inflight limit as a separate native-work budget.
    /// Requires a Tokio runtime; no native call is started by construction.
    pub fn start(
        max_system_operations: NonZeroU16,
        query_timeout: Duration,
    ) -> Result<(SystemResolver, SystemResolverOwner), SystemResolutionError> {
        if max_system_operations.get() > 4096
            || query_timeout.is_zero()
            || Instant::now().checked_add(query_timeout).is_none()
        {
            return Err(SystemResolutionError::InvalidLimits);
        }
        Ok(start(
            max_system_operations,
            query_timeout,
            Arc::new(SystemLookup),
        ))
    }
}

fn start(
    limit: NonZeroU16,
    timeout: Duration,
    native: Arc<dyn NativeLookup>,
) -> (SystemResolver, SystemResolverOwner) {
    let shared = Arc::new(Shared {
        slots: Arc::new(Semaphore::new(usize::from(limit.get()))),
        stop: Notify::new(),
        timeout,
    });
    let (send, receive) = mpsc::channel(usize::from(limit.get()));
    let join = tokio::spawn(dispatch(receive, shared.clone(), native));
    (
        SystemResolver {
            send,
            shared: shared.clone(),
        },
        SystemResolverOwner {
            shared,
            join: Some(join),
            result: None,
        },
    )
}

/// Cloneable admission handle; a logical wait never owns a native task join.
#[derive(Clone)]
pub struct SystemResolver {
    send: mpsc::Sender<Command>,
    shared: Arc<Shared>,
}

impl fmt::Debug for SystemResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SystemResolver([redacted])")
    }
}

impl SystemResolver {
    /// Resolves bounded candidates in original OS order, preserving duplicates.
    pub async fn resolve(
        &self,
        host: &str,
        port: u16,
        deadline: Instant,
    ) -> Result<Vec<SocketAddr>, SystemResolutionError> {
        Ok(self.query(host, port, deadline).await?.ordered)
    }

    /// Address-only lookup, retaining at most sixteen unique addresses per family.
    pub async fn resolve_addresses(
        &self,
        host: &str,
        deadline: Instant,
    ) -> Result<Vec<IpAddr>, SystemResolutionError> {
        Ok(self.query(host, 0, deadline).await?.families)
    }

    async fn query(
        &self,
        host: &str,
        port: u16,
        deadline: Instant,
    ) -> Result<Candidates, SystemResolutionError> {
        if self.shared.slots.is_closed() {
            return Err(SystemResolutionError::Shutdown);
        }
        if Instant::now() >= deadline {
            return Err(SystemResolutionError::Timeout);
        }
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok(Candidates::collect([SocketAddr::new(address, port)]));
        }
        if host.is_empty() || host.len() > 253 || !host.is_ascii() || host.contains('\0') {
            return Err(SystemResolutionError::Resolution);
        }
        let permit =
            self.shared
                .slots
                .clone()
                .try_acquire_owned()
                .map_err(|error| match error {
                    tokio::sync::TryAcquireError::Closed => SystemResolutionError::Shutdown,
                    tokio::sync::TryAcquireError::NoPermits => SystemResolutionError::Busy,
                })?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel = Cancel(cancelled.clone());
        let (reply, receive) = oneshot::channel();
        self.send
            .try_send(Command {
                host: host.to_owned(),
                port,
                deadline,
                work: Work {
                    permit,
                    reply,
                    cancelled,
                },
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => SystemResolutionError::Busy,
                mpsc::error::TrySendError::Closed(_) => SystemResolutionError::Shutdown,
            })?;
        tokio::time::timeout_at(deadline, receive)
            .await
            .map_err(|_| SystemResolutionError::Timeout)?
            .map_err(|_| SystemResolutionError::WorkerFailed)?
    }
}

struct Cancel(Arc<AtomicBool>);
impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

struct Command {
    host: String,
    port: u16,
    deadline: Instant,
    work: Work,
}
struct Work {
    permit: OwnedSemaphorePermit,
    reply: oneshot::Sender<Result<Candidates, SystemResolutionError>>,
    cancelled: Arc<AtomicBool>,
}

/// Unique join authority. Retain this owner through shutdown retries and only
/// release it after shutdown completes; native calls cannot be forcibly cancelled.
#[must_use = "retain the unique owner and explicitly await shutdown"]
pub struct SystemResolverOwner {
    shared: Arc<Shared>,
    join: Option<JoinHandle<Result<SystemResolutionReport, SystemResolutionError>>>,
    result: Option<Result<SystemResolutionReport, SystemResolutionError>>,
}

impl SystemResolverOwner {
    /// Closes admission and joins actual work. Cancelling this await retains joins.
    pub async fn shutdown(&mut self) -> Result<SystemResolutionReport, SystemResolutionError> {
        self.shared.close();
        if let Some(result) = self.result {
            return result;
        }
        let result = self
            .join
            .as_mut()
            .expect("live system resolver owner")
            .await
            .unwrap_or(Err(SystemResolutionError::WorkerFailed));
        self.join.take();
        self.result = Some(result);
        result
    }
}

async fn dispatch(
    mut receive: mpsc::Receiver<Command>,
    shared: Arc<Shared>,
    native: Arc<dyn NativeLookup>,
) -> Result<SystemResolutionReport, SystemResolutionError> {
    let mut tasks = JoinSet::new();
    let mut records = HashMap::new();
    let mut failed = false;
    loop {
        tokio::select! {
            biased;
            _ = shared.stop.notified() => break,
            joined = tasks.join_next_with_id(), if !tasks.is_empty() => {
                finish(joined.expect("nonempty native tasks"), &mut records, &mut failed);
            }
            command = receive.recv() => {
                let Some(command) = command else { break };
                if shared.slots.is_closed() { reject(command.work); continue; }
                let Command { host, port, deadline, work } = command;
                let cancelled = work.cancelled.clone();
                let native = native.clone();
                let native_shared = shared.clone();
                // There is no await between spawning and publishing parent-owned work.
                let task = tasks.spawn_blocking(move || {
                    if cancelled.load(Ordering::Acquire) || native_shared.slots.is_closed() { return Err(SystemResolutionError::Shutdown); }
                    if Instant::now() >= deadline { return Err(SystemResolutionError::Timeout); }
                    native.resolve(&host, port)
                });
                records.insert(task.id(), work);
            }
        }
    }
    shared.slots.close();
    receive.close();
    while let Ok(command) = receive.try_recv() {
        reject(command.work);
    }
    for work in records.values() {
        work.cancelled.store(true, Ordering::Release);
    }
    while let Some(joined) = tasks.join_next_with_id().await {
        finish(joined, &mut records, &mut failed);
    }
    if failed {
        Err(SystemResolutionError::WorkerFailed)
    } else {
        Ok(SystemResolutionReport::default())
    }
}

fn reject(work: Work) {
    let Work {
        permit,
        reply,
        cancelled,
    } = work;
    cancelled.store(true, Ordering::Release);
    drop(permit);
    let _ = reply.send(Err(SystemResolutionError::Shutdown));
}

fn finish(
    joined: Result<(Id, Result<Candidates, SystemResolutionError>), tokio::task::JoinError>,
    records: &mut HashMap<Id, Work>,
    failed: &mut bool,
) {
    let (id, result) = match joined {
        Ok(joined) => joined,
        Err(error) => {
            *failed = true;
            (error.id(), Err(SystemResolutionError::WorkerFailed))
        }
    };
    let Work {
        permit,
        reply,
        cancelled,
    } = records.remove(&id).expect("registered native work");
    // A completed native call still consumes its slot until this join observation.
    drop(permit);
    let result = if cancelled.load(Ordering::Acquire)
        && !matches!(result, Err(SystemResolutionError::WorkerFailed))
    {
        Err(SystemResolutionError::Shutdown)
    } else {
        result
    };
    let _ = reply.send(result);
}

#[cfg(test)]
mod tests;
