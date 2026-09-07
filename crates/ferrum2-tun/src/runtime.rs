mod prepare;
mod thread;
#[cfg(all(windows, target_arch = "x86_64", feature = "live-backend", not(test)))]
pub(crate) use prepare::PreparationFailure;
pub(crate) use thread::NativeLifecycleOwner;
mod link;
pub(crate) use link::{LifecycleEvent, LifecycleLink, NetworkResetRequest};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ferrum2_runtime::{OwnerRegistry, PreparedProcessRoot, ProcessCancellation, ProcessFuture};

use crate::process::{NetworkLifecycleHandler, TcpHandler, UdpHandler};
use crate::{
    SessionCancellation, TcpFlow, TunNetworkFullRebuildReason, TunNetworkResetError, UdpCandidate,
};

// Unsupported roots type-check bridge callbacks but never own a packet loop.
#[cfg(test)]
pub(crate) const PACKET_QUANTUM: usize = 8;
pub(crate) const INGRESS_SLOTS: usize = 16;
pub(crate) const TCP_REAP_QUANTUM: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerExit {
    Stopped,
    RuntimeFailed,
    CleanupFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdapterErrorDisposition {
    FullRebuild(TunNetworkFullRebuildReason),
    RuntimeFailed,
    CleanupFailed,
}

pub(crate) const fn classify_adapter_error(
    error: ferrum2_platform_windows::Error,
) -> AdapterErrorDisposition {
    match error.kind() {
        ferrum2_platform_windows::ErrorKind::RecoverableSession => {
            AdapterErrorDisposition::FullRebuild(TunNetworkFullRebuildReason::SessionDamage)
        }
        ferrum2_platform_windows::ErrorKind::Cleanup => AdapterErrorDisposition::CleanupFailed,
        ferrum2_platform_windows::ErrorKind::InvalidInput
        | ferrum2_platform_windows::ErrorKind::UnrecoverableCorruption => {
            AdapterErrorDisposition::RuntimeFailed
        }
    }
}

#[derive(Clone)]
pub(crate) struct OwnerControl {
    pub(crate) stop: Arc<AtomicBool>,
    pub(crate) shutdown: Arc<AtomicBool>,
    pub(crate) active: Arc<AtomicBool>,
    pub(crate) admitting: Arc<AtomicBool>,
    pub(crate) flow_count: Arc<AtomicUsize>,
    pub(crate) association_count: Arc<AtomicUsize>,
}

impl OwnerControl {
    pub(crate) fn new() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicBool::new(false)),
            admitting: Arc::new(AtomicBool::new(false)),
            flow_count: Arc::new(AtomicUsize::new(0)),
            association_count: Arc::new(AtomicUsize::new(0)),
        }
    }
}

pub(crate) struct TunRoot<E> {
    pub(crate) owner: NativeLifecycleOwner,
    pub(crate) done: tokio::sync::oneshot::Receiver<OwnerExit>,
    pub(crate) runtime: Option<E>,
    pub(crate) cleanup: Option<E>,
    pub(crate) flows: tokio::sync::mpsc::Receiver<SessionItem<TcpFlow>>,
    pub(crate) datagrams: tokio::sync::mpsc::Receiver<SessionItem<UdpCandidate>>,
    pub(crate) flow_count: Arc<AtomicUsize>,
    pub(crate) association_count: Arc<AtomicUsize>,
    pub(crate) registry: OwnerRegistry,
    pub(crate) handle_tcp: TcpHandler,
    pub(crate) handle_udp: UdpHandler,
    pub(crate) handle_network_lifecycle: NetworkLifecycleHandler,
}

pub(crate) struct SessionItem<T> {
    pub(crate) value: T,
    pub(crate) cancellation: SessionCancellation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkResetBridgeOutcome {
    Completed,
    Retry,
    Stopped,
}

impl<E> PreparedProcessRoot<E> for TunRoot<E>
where
    E: Send + 'static,
{
    fn activate(&mut self) -> Result<(), E> {
        self.owner.control.admitting.store(true, Ordering::Release);
        self.owner.control.active.store(true, Ordering::Release);
        self.owner.work.signal();
        Ok(())
    }

    fn run(
        mut self: Box<Self>,
        mut cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), E>> {
        Box::pin(async move {
            let mut tasks = tokio::task::JoinSet::new();
            let mut forced = cancellation.clone();
            let mut network_resets_open = true;
            let reported = 'required: loop {
                if cancellation.is_cancelled() {
                    self.owner.link.close();
                    self.owner.control.shutdown.store(true, Ordering::Release);
                    self.owner.control.admitting.store(false, Ordering::Release);
                    self.owner.work.signal();
                }
                if cancellation.is_forced() {
                    break OwnerExit::Stopped;
                }
                if cancellation.is_cancelled()
                    && tasks.is_empty()
                    && self.flow_count.load(Ordering::Acquire) == 0
                    && self.association_count.load(Ordering::Acquire) == 0
                {
                    break OwnerExit::Stopped;
                }
                tokio::select! {
                    result = &mut self.done => break reported_owner_exit(result),
                    item = self.flows.recv() => {
                        if let Some(SessionItem { value: flow, cancellation: session }) = item {
                            self.owner.work.signal();
                            if session.is_cancelled() {
                                continue;
                            }
                            while let Some(result) = tasks.try_join_next() {
                                if result.is_err() {
                                    break 'required OwnerExit::RuntimeFailed;
                                }
                            }
                            let owner = self.registry.track_tun_handler_task();
                            let task_session = session.clone();
                            let handler = (self.handle_tcp)(flow, cancellation.clone(), session);
                            tasks.spawn(async move {
                                let _owner = owner;
                                tokio::select! {
                                    biased;
                                    () = task_session.cancelled() => {}
                                    () = handler => {}
                                }
                            });
                        }
                    }
                    item = self.datagrams.recv() => {
                        if let Some(SessionItem { value: candidate, cancellation: session }) = item {
                            self.owner.work.signal();
                            if session.is_cancelled() {
                                continue;
                            }
                            while let Some(result) = tasks.try_join_next() {
                                if result.is_err() {
                                    break 'required OwnerExit::RuntimeFailed;
                                }
                            }
                            let owner = self.registry.track_tun_handler_task();
                            let task_session = session.clone();
                            let handler = (self.handle_udp)(candidate, cancellation.clone(), session);
                            tasks.spawn(async move {
                                let _owner = owner;
                                tokio::select! {
                                    biased;
                                    () = task_session.cancelled() => {}
                                    () = handler => {}
                                }
                            });
                        }
                    }
                    request = self.owner.link.receive(), if network_resets_open => {
                        let Some(LifecycleEvent::Request(NetworkResetRequest { snapshot, lifecycle, completion })) = request else {
                            network_resets_open = false;
                            continue;
                        };
                        let mut reset_cancellation = cancellation.clone();
                        let mut reset_forced = forced.clone();
                        let reset = (self.handle_network_lifecycle)(snapshot, lifecycle);
                        let outcome = tokio::select! {
                            biased;
                            () = reset_forced.forced() => NetworkResetBridgeOutcome::Stopped,
                            () = reset_cancellation.cancelled() => NetworkResetBridgeOutcome::Stopped,
                            result = reset => match result {
                                Ok(()) => NetworkResetBridgeOutcome::Completed,
                                Err(TunNetworkResetError) => NetworkResetBridgeOutcome::Retry,
                            },
                        };
                        completion.complete(outcome);
                    }
                    result = tasks.join_next(), if !tasks.is_empty() => {
                        if result.is_some_and(|result| result.is_err()) {
                            break OwnerExit::RuntimeFailed;
                        }
                    }
                    () = cancellation.cancelled(), if !cancellation.is_cancelled() => {
                        self.owner.link.close();
                    self.owner.control.shutdown.store(true, Ordering::Release);
                        self.owner.control.admitting.store(false, Ordering::Release);
                        self.owner.work.signal();
                    }
                    () = forced.forced(), if cancellation.is_cancelled() => {}
                }
            };
            self.owner.signal();
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            let reaped = self.owner.reap().await;
            let exit = reconcile_owner_exit(reported, reaped);
            match exit {
                OwnerExit::Stopped => Ok(()),
                OwnerExit::RuntimeFailed => {
                    Err(self.runtime.take().expect("runtime error retained"))
                }
                OwnerExit::CleanupFailed => {
                    Err(self.cleanup.take().expect("cleanup error retained"))
                }
            }
        })
    }

    fn rollback(mut self: Box<Self>) -> ProcessFuture<Result<(), E>> {
        Box::pin(async move {
            match self.owner.reap().await {
                OwnerExit::Stopped => Ok(()),
                OwnerExit::RuntimeFailed => {
                    Err(self.runtime.take().expect("runtime error retained"))
                }
                OwnerExit::CleanupFailed => {
                    Err(self.cleanup.take().expect("cleanup error retained"))
                }
            }
        })
    }
}

pub(crate) fn reported_owner_exit(
    result: Result<OwnerExit, tokio::sync::oneshot::error::RecvError>,
) -> OwnerExit {
    result.unwrap_or(OwnerExit::CleanupFailed)
}

pub(crate) fn reconcile_owner_exit(reported: OwnerExit, reaped: OwnerExit) -> OwnerExit {
    if reaped == OwnerExit::CleanupFailed || reported == OwnerExit::Stopped {
        reaped
    } else {
        reported
    }
}

#[cfg(test)]
pub(crate) fn map_owner_spawn<T, E>(spawned: std::io::Result<T>, startup: E) -> Result<T, E> {
    spawned.map_err(|_| startup)
}

#[cfg(test)]
pub(crate) fn finish_stack_setup<T, A, C>(
    stack: Result<T, ()>,
    adapter: A,
    cleanup: impl FnOnce(A) -> Result<(), C>,
) -> Result<(T, A), OwnerExit> {
    match stack {
        Ok(stack) => Ok((stack, adapter)),
        Err(()) => Err(match cleanup(adapter) {
            Ok(()) => OwnerExit::RuntimeFailed,
            Err(_) => OwnerExit::CleanupFailed,
        }),
    }
}

#[cfg(all(windows, target_arch = "x86_64", feature = "live-backend", not(test)))]
mod live;
#[cfg(all(windows, target_arch = "x86_64", feature = "live-backend", not(test)))]
pub(crate) use live::{OWNER_WORK_BUDGET, OwnerSessionServices};
