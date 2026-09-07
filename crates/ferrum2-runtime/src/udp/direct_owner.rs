use std::collections::HashMap;
use std::fmt;
use std::future::poll_fn;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::sync::OwnedSemaphorePermit;
use tokio::task::{Id, JoinError, JoinSet};
use tokio::time::Instant;

use crate::owner::OwnerGuard;
use crate::{OwnerRegistry, ProcessCancellation};

use super::manager::UdpRuntimeOwner;
use super::{UdpRuntimeError, UdpSessionHandle, UdpSessionManager};

/// Joined task terminal data. Handler errors are retained without being formatted.
pub enum DirectUdpTerminal<E> {
    Completed,
    Idle,
    Cancelled,
    ResolveFailed,
    SendFailed,
    ReceiveFailed,
    HandlerFailed(E),
    RuntimeFailed(UdpRuntimeError),
    Panicked,
    Aborted,
}

impl<E> fmt::Debug for DirectUdpTerminal<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Completed => "Completed",
            Self::Idle => "Idle",
            Self::Cancelled => "Cancelled",
            Self::ResolveFailed => "ResolveFailed",
            Self::SendFailed => "SendFailed",
            Self::ReceiveFailed => "ReceiveFailed",
            Self::HandlerFailed(_) => "HandlerFailed([closed])",
            Self::RuntimeFailed(_) => "RuntimeFailed([closed])",
            Self::Panicked => "Panicked",
            Self::Aborted => "Aborted",
        })
    }
}

/// One exact-generation completion, returned only after its task was joined.
#[derive(Debug)]
pub struct DirectUdpCompletion<E> {
    session: UdpSessionHandle,
    terminal: DirectUdpTerminal<E>,
    unexpected_failure: bool,
}

impl<E> DirectUdpCompletion<E> {
    pub const fn unexpected_failure(&self) -> bool {
        self.unexpected_failure
    }
    pub const fn session(&self) -> UdpSessionHandle {
        self.session
    }
    pub const fn terminal(&self) -> &DirectUdpTerminal<E> {
        &self.terminal
    }
}

/// Fixed-size cumulative terminal counts; no completed-event queue is retained.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectUdpTerminalCounts {
    pub completed: usize,
    pub idle: usize,
    pub cancelled: usize,
    pub resolve_failed: usize,
    pub send_failed: usize,
    pub receive_failed: usize,
    pub handler_failed: usize,
    pub runtime_failed: usize,
    pub panicked: usize,
    pub aborted: usize,
}

impl DirectUdpTerminalCounts {
    fn record<E>(&mut self, terminal: &DirectUdpTerminal<E>) {
        let count = match terminal {
            DirectUdpTerminal::Completed => &mut self.completed,
            DirectUdpTerminal::Idle => &mut self.idle,
            DirectUdpTerminal::Cancelled => &mut self.cancelled,
            DirectUdpTerminal::ResolveFailed => &mut self.resolve_failed,
            DirectUdpTerminal::SendFailed => &mut self.send_failed,
            DirectUdpTerminal::ReceiveFailed => &mut self.receive_failed,
            DirectUdpTerminal::HandlerFailed(_) => &mut self.handler_failed,
            DirectUdpTerminal::RuntimeFailed(_) => &mut self.runtime_failed,
            DirectUdpTerminal::Panicked => &mut self.panicked,
            DirectUdpTerminal::Aborted => &mut self.aborted,
        };
        *count = count.saturating_add(1);
    }
}

/// Joined shutdown evidence, including only the bounded tasks drained by this call.
#[derive(Debug)]
pub struct DirectUdpShutdownReport<E> {
    forced: usize,
    terminals: DirectUdpTerminalCounts,
    cleanup_failed: bool,
    completions: Vec<DirectUdpCompletion<E>>,
}

impl<E> DirectUdpShutdownReport<E> {
    pub const fn forced(&self) -> usize {
        self.forced
    }
    pub const fn terminals(&self) -> DirectUdpTerminalCounts {
        self.terminals
    }
    pub const fn cleanup_failed(&self) -> bool {
        self.cleanup_failed
    }
    pub fn completions(&self) -> &[DirectUdpCompletion<E>] {
        &self.completions
    }
}

pub(super) enum DirectTaskFailure<E> {
    Runtime(UdpRuntimeError),
    Handler(E),
}
impl<E> From<UdpRuntimeError> for DirectTaskFailure<E> {
    fn from(error: UdpRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

pub(super) struct DirectTaskRecord {
    pub(super) session: UdpSessionHandle,
    pub(super) _task_guard: OwnerGuard,
    pub(super) _owner_slot: OwnedSemaphorePermit,
    forced: bool,
}
impl DirectTaskRecord {
    pub(super) fn new(
        session: UdpSessionHandle,
        task_guard: OwnerGuard,
        owner_slot: OwnedSemaphorePermit,
    ) -> Self {
        Self {
            session,
            _task_guard: task_guard,
            _owner_slot: owner_slot,
            forced: false,
        }
    }
}

pub(super) struct DirectTaskOwner<E: Send + 'static> {
    pub(super) tasks: JoinSet<Result<(), DirectTaskFailure<E>>>,
    pub(super) records: HashMap<Id, DirectTaskRecord>,
    manager: UdpSessionManager,
    registry: OwnerRegistry,
    runtime_owner: UdpRuntimeOwner,
    terminals: DirectUdpTerminalCounts,
    cleanup_failed: bool,
    forced: usize,
    forced_started: bool,
    deadline: Option<Instant>,
    shutdown_completions: Vec<DirectUdpCompletion<E>>,
}

impl<E: Send + 'static> DirectTaskOwner<E> {
    pub(super) fn new(manager: UdpSessionManager, registry: OwnerRegistry) -> Self {
        Self {
            runtime_owner: manager.runtime_owner(),
            manager,
            registry,
            tasks: JoinSet::new(),
            records: HashMap::new(),
            terminals: DirectUdpTerminalCounts::default(),
            cleanup_failed: false,
            forced: 0,
            forced_started: false,
            deadline: None,
            shutdown_completions: Vec::new(),
        }
    }

    fn reap(
        &mut self,
        joined: Result<(Id, Result<(), DirectTaskFailure<E>>), JoinError>,
    ) -> DirectUdpCompletion<E> {
        let (id, terminal) = match joined {
            Ok((id, Ok(()))) => (id, DirectUdpTerminal::Completed),
            Ok((id, Err(DirectTaskFailure::Handler(error)))) => {
                (id, DirectUdpTerminal::HandlerFailed(error))
            }
            Ok((id, Err(DirectTaskFailure::Runtime(error)))) => (
                id,
                match error {
                    UdpRuntimeError::Idle => DirectUdpTerminal::Idle,
                    UdpRuntimeError::Cancelled => DirectUdpTerminal::Cancelled,
                    UdpRuntimeError::Resolve => DirectUdpTerminal::ResolveFailed,
                    UdpRuntimeError::Send => DirectUdpTerminal::SendFailed,
                    UdpRuntimeError::Receive => DirectUdpTerminal::ReceiveFailed,
                    UdpRuntimeError::Bounds
                    | UdpRuntimeError::SessionLimit
                    | UdpRuntimeError::BufferLimit
                    | UdpRuntimeError::QueueFull
                    | UdpRuntimeError::Counter
                    | UdpRuntimeError::ProtocolPanicked
                    | UdpRuntimeError::StateUnavailable => DirectUdpTerminal::RuntimeFailed(error),
                },
            ),
            Err(error) => (
                error.id(),
                if error.is_cancelled() {
                    DirectUdpTerminal::Aborted
                } else {
                    DirectUdpTerminal::Panicked
                },
            ),
        };
        // Registration is synchronous with spawn and only this owner removes records.
        let record = self
            .records
            .remove(&id)
            .expect("joined Direct task has parent record");
        let unexpected_failure = matches!(
            terminal,
            DirectUdpTerminal::Panicked
                | DirectUdpTerminal::RuntimeFailed(
                    UdpRuntimeError::ProtocolPanicked | UdpRuntimeError::StateUnavailable
                )
        ) || matches!(terminal, DirectUdpTerminal::Aborted)
            && !record.forced;
        self.cleanup_failed |= unexpected_failure;
        self.terminals.record(&terminal);
        DirectUdpCompletion {
            session: record.session,
            terminal,
            unexpected_failure,
        }
        // record releases the admitted-but-unjoined permit and task guard here.
    }

    pub(super) fn accepting(&self) -> bool {
        !self.runtime_owner.shutdown_started
    }

    pub(super) fn poll_completion(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<DirectUdpCompletion<E>>> {
        match self.tasks.poll_join_next_with_id(cx) {
            Poll::Ready(Some(joined)) => Poll::Ready(Some(self.reap(joined))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    pub(super) fn try_completion(&mut self) -> Option<DirectUdpCompletion<E>> {
        self.tasks
            .try_join_next_with_id()
            .map(|joined| self.reap(joined))
    }

    fn force(&mut self) {
        if !self.forced_started {
            self.forced_started = true;
            self.forced = self.tasks.len();
            for record in self.records.values_mut() {
                record.forced = true;
            }
            self.registry.record_udp_forced_shutdowns(self.forced);
            self.tasks.abort_all();
        }
    }
}

pub(super) type SharedDirectTasks<E> = Arc<Mutex<DirectTaskOwner<E>>>;

/// Unique external join custody, retained outside a cancellable run future.
///
/// Obtain before starting the root. Shutdown is retryable: cancelling an await
/// leaves all joins and admitted task permits in this owner. It must outlive the
/// run future and be shut down after that future exits or is aborted.
pub struct DirectUdpCleanup<E: Send + 'static> {
    pub(super) tasks: SharedDirectTasks<E>,
}

impl<E: Send + 'static> DirectUdpCleanup<E> {
    pub async fn shutdown(&mut self, grace: Duration) -> DirectUdpShutdownReport<E> {
        shutdown(
            &self.tasks,
            ShutdownControl::Relative(Instant::now() + grace),
        )
        .await
    }
}

pub(super) async fn next_completion<E: Send + 'static>(
    tasks: &SharedDirectTasks<E>,
) -> Option<DirectUdpCompletion<E>> {
    poll_fn(|cx| {
        tasks
            .lock()
            .expect("Direct task owner lock")
            .poll_completion(cx)
    })
    .await
}

pub(super) enum ShutdownControl {
    Relative(Instant),
    Process(ProcessCancellation),
}

pub(super) async fn shutdown<E: Send + 'static>(
    tasks: &SharedDirectTasks<E>,
    mut control: ShutdownControl,
) -> DirectUdpShutdownReport<E> {
    {
        let mut owner = tasks.lock().expect("Direct task owner lock");
        owner.runtime_owner.begin_shutdown();
        if let ShutdownControl::Relative(requested) = control {
            let deadline = owner.deadline.get_or_insert(requested);
            *deadline = (*deadline).min(requested);
            control = ShutdownControl::Relative(*deadline);
        }
    }
    loop {
        if tasks
            .lock()
            .expect("Direct task owner lock")
            .tasks
            .is_empty()
        {
            break;
        }
        tokio::select! {
            biased;
            completion = next_completion(tasks) => {
                if let Some(completion) = completion { tasks.lock().expect("Direct task owner lock").shutdown_completions.push(completion); }
            }
            () = async {
                match &mut control {
                    ShutdownControl::Relative(deadline) => tokio::time::sleep_until(*deadline).await,
                    ShutdownControl::Process(cancellation) => cancellation.forced().await,
                }
            } => {
                tasks.lock().expect("Direct task owner lock").force();
                while let Some(completion) = next_completion(tasks).await { tasks.lock().expect("Direct task owner lock").shutdown_completions.push(completion); }
                break;
            }
        }
    }
    let mut owner = tasks.lock().expect("Direct task owner lock");
    DirectUdpShutdownReport {
        forced: std::mem::take(&mut owner.forced),
        terminals: owner.terminals,
        cleanup_failed: owner.cleanup_failed || owner.manager.cleanup_failed(),
        completions: std::mem::take(&mut owner.shutdown_completions),
    }
}
