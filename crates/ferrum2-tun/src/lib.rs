#![forbid(unsafe_code)]

#[cfg(feature = "fuzzing")]
mod fuzzing;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
mod lifecycle;
mod model;
mod network;
#[cfg(test)]
mod owner_harness_tests;
#[cfg(any(all(windows, target_arch = "x86_64"), test, feature = "fuzzing"))]
mod packet;
mod process;
#[cfg(any(all(windows, target_arch = "x86_64"), test, feature = "fuzzing"))]
mod reassembly;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
mod scheduler;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
mod stack;
mod supervisor;
mod tcp;
mod udp;
mod wake;

#[cfg(feature = "fuzzing")]
pub use fuzzing::{
    MAX_FUZZ_INPUT_BYTES, MAX_UDP_RESET_FUZZ_INPUT_BYTES, fuzz_packet_reassembly,
    fuzz_udp_reset_races,
};
pub(crate) use model::TunEventSink;
pub use model::{
    Config, TunDiagnosticReason, TunEvent, TunIpFamily, TunNetworkFullRebuildReason,
    TunNetworkLifecycle, TunNetworkResetError, TunNetworkResetReason, TunRejectReason,
    UdpResponseDropReason,
};
pub use network::UnderlayPublisher;
#[cfg(test)]
pub(crate) use process::map_packet_reject;
pub use process::process_root;
pub use supervisor::SessionCancellation;
pub use tcp::TcpFlow;
#[cfg(test)]
use udp::GenerationTable;
#[cfg(test)]
use udp::{Admission as UdpAdmission, InjectOutcome as UdpInjectOutcome, UdpDatagramEndpoints};
pub use udp::{
    UdpAssociation, UdpCandidate, UdpCommitError, UdpDatagram, UdpFiltering, UdpPeerAuthorization,
    UdpPeerPolicyHandle, UdpPeerReservation, UdpPeerReservationOutcome, UdpResponseSendOutcome,
    UdpResponseSink,
};
pub use wake::OwnerWake;

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use ferrum2_net::NetworkSnapshot;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use ferrum2_runtime::{OwnerRegistry, PreparedProcessRoot, ProcessCancellation, ProcessFuture};
#[cfg(test)]
use packet::{Families, PacketParser, ParsedPacket};
#[cfg(test)]
use scheduler::{FairScheduler, WorkStage};
#[cfg(test)]
use stack::{
    MemoryDevice, MemoryTx, OutputFlushOutcome, OutputSendOutcome, OutputSlot, PacketValidator,
    Stack, TcpTuple, udp_datagram,
};
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use std::sync::Arc;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// Unsupported roots type-check bridge callbacks but never own a packet loop.
#[cfg(test)]
const PACKET_QUANTUM: usize = 8;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
const INGRESS_SLOTS: usize = 16;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
const TCP_REAP_QUANTUM: usize = 16;
#[cfg(all(windows, target_arch = "x86_64"))]
const OWNER_WORK_BUDGET: usize = 64;

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnerExit {
    Stopped,
    RuntimeFailed,
    CleanupFailed,
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdapterErrorDisposition {
    FullRebuild(TunNetworkFullRebuildReason),
    RuntimeFailed,
    CleanupFailed,
}

#[cfg(all(windows, target_arch = "x86_64"))]
const fn classify_adapter_error(error: ferrum2_platform_windows::Error) -> AdapterErrorDisposition {
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

#[cfg(all(windows, target_arch = "x86_64"))]
enum OwnerReady {
    Ready {
        work: OwnerWake,
        snapshot: Arc<NetworkSnapshot>,
        initialization: std::sync::mpsc::SyncSender<NetworkResetBridgeOutcome>,
    },
    Failed,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[derive(Clone)]
struct OwnerControl {
    stop: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
    admitting: Arc<AtomicBool>,
    #[cfg(all(windows, target_arch = "x86_64"))]
    flow_count: Arc<AtomicUsize>,
    #[cfg(all(windows, target_arch = "x86_64"))]
    association_count: Arc<AtomicUsize>,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl OwnerControl {
    fn new() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicBool::new(false)),
            admitting: Arc::new(AtomicBool::new(false)),
            #[cfg(all(windows, target_arch = "x86_64"))]
            flow_count: Arc::new(AtomicUsize::new(0)),
            #[cfg(all(windows, target_arch = "x86_64"))]
            association_count: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
struct OwnerThread {
    control: OwnerControl,
    work: OwnerWake,
    thread: Option<std::thread::JoinHandle<OwnerExit>>,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl OwnerThread {
    fn signal(&self) {
        self.control.stop.store(true, Ordering::Release);
        self.work.signal();
    }

    async fn reap(mut self) -> OwnerExit {
        self.signal();
        let Some(thread) = self.thread.take() else {
            return OwnerExit::CleanupFailed;
        };
        match tokio::task::spawn_blocking(move || thread.join()).await {
            Ok(Ok(exit)) => exit,
            _ => OwnerExit::CleanupFailed,
        }
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl Drop for OwnerThread {
    fn drop(&mut self) {
        self.signal();
        if let Some(thread) = self.thread.take() {
            if tokio::runtime::Handle::try_current().is_ok_and(|handle| {
                handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
            }) {
                tokio::task::block_in_place(move || {
                    tokio::runtime::Handle::current().block_on(async move {
                        let _ = tokio::task::spawn_blocking(move || thread.join()).await;
                    });
                });
            } else {
                // Outside the product's multi-thread runtime there is no Tokio worker to block.
                let _ = thread.join();
            }
        }
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
struct TunRoot<E> {
    owner: OwnerThread,
    done: tokio::sync::oneshot::Receiver<OwnerExit>,
    runtime: Option<E>,
    cleanup: Option<E>,
    flows: tokio::sync::mpsc::Receiver<SessionItem<TcpFlow>>,
    datagrams: tokio::sync::mpsc::Receiver<SessionItem<UdpCandidate>>,
    network_resets: tokio::sync::mpsc::Receiver<NetworkResetRequest>,
    flow_count: Arc<AtomicUsize>,
    association_count: Arc<AtomicUsize>,
    registry: OwnerRegistry,
    handle_tcp: TcpHandler,
    handle_udp: UdpHandler,
    handle_network_lifecycle: NetworkLifecycleHandler,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
struct SessionItem<T> {
    value: T,
    cancellation: SessionCancellation,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
type TcpHandler = Arc<
    dyn Fn(TcpFlow, ProcessCancellation, SessionCancellation) -> ProcessFuture<()>
        + Send
        + Sync
        + 'static,
>;

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
type UdpHandler = Arc<
    dyn Fn(UdpCandidate, ProcessCancellation, SessionCancellation) -> ProcessFuture<()>
        + Send
        + Sync
        + 'static,
>;

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
type NetworkLifecycleHandler = Arc<
    dyn Fn(
            Arc<NetworkSnapshot>,
            TunNetworkLifecycle,
        ) -> ProcessFuture<Result<(), TunNetworkResetError>>
        + Send
        + Sync
        + 'static,
>;

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
struct NetworkResetRequest {
    snapshot: Arc<NetworkSnapshot>,
    lifecycle: TunNetworkLifecycle,
    completion: tokio::sync::oneshot::Sender<NetworkResetBridgeOutcome>,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NetworkResetBridgeOutcome {
    Completed,
    Retry,
    Stopped,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
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
                    self.owner.control.shutdown.store(true, Ordering::Release);
                    self.owner.control.admitting.store(false, Ordering::Release);
                    self.owner.work.signal();
                }
                if cancellation.is_forced() {
                    tasks.abort_all();
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
                    request = self.network_resets.recv(), if network_resets_open => {
                        let Some(NetworkResetRequest { snapshot, lifecycle, completion }) = request else {
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
                        let _ = completion.send(outcome);
                    }
                    result = tasks.join_next(), if !tasks.is_empty() => {
                        if result.is_some_and(|result| result.is_err()) {
                            break OwnerExit::RuntimeFailed;
                        }
                    }
                    () = cancellation.cancelled(), if !cancellation.is_cancelled() => {
                        self.owner.control.shutdown.store(true, Ordering::Release);
                        self.owner.control.admitting.store(false, Ordering::Release);
                        self.owner.work.signal();
                    }
                    () = forced.forced(), if cancellation.is_cancelled() => {}
                }
            };
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

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
fn reported_owner_exit(
    result: Result<OwnerExit, tokio::sync::oneshot::error::RecvError>,
) -> OwnerExit {
    result.unwrap_or(OwnerExit::CleanupFailed)
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
fn reconcile_owner_exit(reported: OwnerExit, reaped: OwnerExit) -> OwnerExit {
    if reaped == OwnerExit::CleanupFailed || reported == OwnerExit::Stopped {
        reaped
    } else {
        reported
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
fn map_owner_spawn<T, E>(spawned: std::io::Result<T>, startup: E) -> Result<T, E> {
    spawned.map_err(|_| startup)
}

#[cfg(test)]
fn finish_stack_setup<T, A, C>(
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

#[cfg(all(windows, target_arch = "x86_64"))]
struct OwnerSessionServices {
    ready: std::sync::mpsc::SyncSender<OwnerReady>,
    registry: OwnerRegistry,
    network_catalog: ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
    events: TunEventSink,
    underlay: UnderlayPublisher,
    flow_output: tokio::sync::mpsc::Sender<SessionItem<TcpFlow>>,
    datagram_output: tokio::sync::mpsc::Sender<SessionItem<UdpCandidate>>,
    network_lifecycle_output: tokio::sync::mpsc::Sender<NetworkResetRequest>,
    max_udp_associations: usize,
}

#[cfg(test)]
mod tests;
