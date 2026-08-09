#![forbid(unsafe_code)]

mod tcp;

pub use tcp::TcpFlow;

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use std::net::IpAddr;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use std::net::SocketAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use std::sync::Arc;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use ferrum2_runtime::{PreparedProcessRoot, ProcessCancellation, ProcessFuture, ProcessRoot};
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use smoltcp::iface::{
    Config as InterfaceConfig, Interface, PollIngressSingleResult, Route, SocketHandle, SocketSet,
};
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use smoltcp::socket::tcp::{
    Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
};
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use smoltcp::time::Instant;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address, TcpControl,
    TcpPacket, TcpRepr,
};

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
const PACKET_QUANTUM: usize = 8;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
const INGRESS_SLOTS: usize = PACKET_QUANTUM - 1;

/// Complete, already-validated construction input for the private TUN owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub adapter_name: Box<str>,
    pub ipv4: Ipv4Addr,
    pub ipv4_prefix: u8,
    pub ipv6: Ipv6Addr,
    pub ipv6_prefix: u8,
    pub mtu: u16,
    pub ring_capacity: u32,
    pub ready_timeout: Duration,
    pub max_tcp_flows: usize,
    pub tcp_buffer_bytes: usize,
    pub tcp_timeout: Duration,
    pub max_udp_mappings: usize,
    pub max_udp_buffered_bytes: usize,
    pub owned_buffer_bytes: u64,
}

/// Builds one required process root around the private owner-thread implementation.
///
/// Error values are supplied by the binary so this deep module does not depend on
/// configuration, policy, DNS, protocol, or observability crates.
#[cfg(all(windows, target_arch = "x86_64"))]
pub fn process_root<E, H, A, D>(
    config: Config,
    startup: E,
    runtime: E,
    cleanup: E,
    handle_tcp: H,
    accepted: A,
    foundation_dropped: D,
) -> ProcessRoot<E>
where
    E: Copy + Send + 'static,
    H: Fn(TcpFlow, ProcessCancellation) -> ProcessFuture<()> + Send + Sync + 'static,
    A: Fn() + Send + Sync + 'static,
    D: Fn() + Send + Sync + 'static,
{
    ProcessRoot::new_cancellable(move |cancellation| async move {
        if !config_is_exact(&config) {
            return Err(startup);
        }
        prepare(
            config,
            RootErrors {
                startup,
                runtime,
                cleanup,
            },
            cancellation,
            Arc::new(handle_tcp),
            PacketMetrics {
                accepted: Box::new(accepted),
                foundation_dropped: Box::new(foundation_dropped),
            },
        )
        .await
    })
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
/// Builds a required root that fails during preparation on unsupported targets.
pub fn process_root<E, H, A, D>(
    _config: Config,
    startup: E,
    _runtime: E,
    _cleanup: E,
    _handle_tcp: H,
    _accepted: A,
    _foundation_dropped: D,
) -> ProcessRoot<E>
where
    E: Copy + Send + 'static,
    H: Fn(TcpFlow, ProcessCancellation) -> ProcessFuture<()> + Send + Sync + 'static,
    A: Fn() + Send + Sync + 'static,
    D: Fn() + Send + Sync + 'static,
{
    ProcessRoot::new(move || async move { Err::<UnsupportedTargetRoot, _>(startup) })
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
struct UnsupportedTargetRoot;

#[cfg(not(all(windows, target_arch = "x86_64")))]
impl<E> PreparedProcessRoot<E> for UnsupportedTargetRoot
where
    E: Send + 'static,
{
    fn activate(&mut self) -> Result<(), E> {
        unreachable!("unsupported TUN target cannot prepare")
    }

    fn run(self: Box<Self>, _cancellation: ProcessCancellation) -> ProcessFuture<Result<(), E>> {
        unreachable!("unsupported TUN target cannot run")
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), E>> {
        unreachable!("unsupported TUN target cannot roll back")
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[derive(Clone, Copy)]
struct RootErrors<E> {
    startup: E,
    runtime: E,
    cleanup: E,
}

#[cfg(all(windows, target_arch = "x86_64"))]
struct PacketMetrics {
    accepted: Box<dyn Fn() + Send + Sync>,
    foundation_dropped: Box<dyn Fn() + Send + Sync>,
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn config_is_exact(config: &Config) -> bool {
    let mtu = u64::from(config.mtu);
    let ring = u64::from(config.ring_capacity);
    let Ok(tcp_flows) = u64::try_from(config.max_tcp_flows) else {
        return false;
    };
    let Ok(tcp_buffer) = u64::try_from(config.tcp_buffer_bytes) else {
        return false;
    };
    let Ok(udp_mappings) = u64::try_from(config.max_udp_mappings) else {
        return false;
    };
    let Ok(udp_buffer) = u64::try_from(config.max_udp_buffered_bytes) else {
        return false;
    };
    if !(1280..=1500).contains(&config.mtu)
        || !(131_072..=67_108_864).contains(&config.ring_capacity)
        || !config.ring_capacity.is_power_of_two()
        || !(Duration::from_secs(1)..=Duration::from_secs(60)).contains(&config.ready_timeout)
        || !(1..=4096).contains(&config.max_tcp_flows)
        || !(4096..=262_144).contains(&config.tcp_buffer_bytes)
        || !(Duration::from_secs(1)..=Duration::from_secs(86_400)).contains(&config.tcp_timeout)
        || !(1..=8192).contains(&config.max_udp_mappings)
        || !(65_536..=134_217_728).contains(&config.max_udp_buffered_bytes)
    {
        return false;
    }
    let Some(tcp_staging) = mtu.checked_add(1024) else {
        return false;
    };
    let Some(udp_staging) = mtu.checked_add(512) else {
        return false;
    };
    let terms = [
        ring.checked_mul(2),
        tcp_flows
            .checked_mul(tcp_buffer)
            .and_then(|value| value.checked_mul(2)),
        Some(udp_buffer),
        tcp_flows.checked_mul(tcp_staging),
        udp_mappings.checked_mul(udp_staging),
        mtu.checked_mul(8),
        Some(1_048_576),
    ];
    let computed = terms
        .into_iter()
        .try_fold(0_u64, |total, term| total.checked_add(term?));
    computed == Some(config.owned_buffer_bytes) && config.owned_buffer_bytes <= 268_435_456
}

#[cfg(all(windows, target_arch = "x86_64"))]
async fn prepare<E>(
    config: Config,
    errors: RootErrors<E>,
    mut cancellation: ProcessCancellation,
    handle_tcp: TcpHandler,
    metrics: PacketMetrics,
) -> Result<Option<TunRoot<E>>, E>
where
    E: Copy + Send + 'static,
{
    let timeout = config.ready_timeout;
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(std::time::Instant::now);
    let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
    let (done_sender, _done_receiver) = tokio::sync::oneshot::channel();
    let control = OwnerControl::new();
    let owner_control = control.clone();
    let thread = map_owner_spawn(
        std::thread::Builder::new()
            .name("ferrum2-tun-owner".into())
            .spawn(move || {
                let result = owner_main(config, owner_control, ready_sender, deadline, metrics);
                let _ = done_sender.send(result);
                result
            }),
        errors.startup,
    )?;
    let guard = OwnerThread {
        control: control.clone(),
        #[cfg(all(windows, target_arch = "x86_64"))]
        wake: None,
        thread: Some(thread),
    };
    #[cfg(all(windows, target_arch = "x86_64"))]
    let mut guard = guard;
    loop {
        if cancellation.is_cancelled() {
            return cancel_prepare(guard, errors.cleanup).await;
        }
        if std::time::Instant::now() >= deadline {
            return Err(prepare_failure(guard, errors.startup, errors.cleanup).await);
        }
        match ready_receiver.try_recv() {
            #[cfg(all(windows, target_arch = "x86_64"))]
            Ok(OwnerReady::Ready { wake, flows }) => {
                if std::time::Instant::now() >= deadline {
                    return Err(prepare_failure(guard, errors.startup, errors.cleanup).await);
                }
                guard.wake = Some(wake);
                return Ok(Some(TunRoot {
                    owner: guard,
                    done: _done_receiver,
                    runtime: Some(errors.runtime),
                    cleanup: Some(errors.cleanup),
                    flows,
                    flow_count: control.flow_count,
                    handle_tcp,
                }));
            }
            Ok(OwnerReady::Failed) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err(prepare_failure(guard, errors.startup, errors.cleanup).await);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return cancel_prepare(guard, errors.cleanup).await;
            }
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
async fn cancel_prepare<E>(guard: OwnerThread, cleanup: E) -> Result<Option<TunRoot<E>>, E>
where
    E: Copy + Send + 'static,
{
    if guard.reap().await == OwnerExit::CleanupFailed {
        Err(cleanup)
    } else {
        Ok(None)
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
async fn prepare_failure<E>(guard: OwnerThread, startup: E, cleanup: E) -> E
where
    E: Copy + Send + 'static,
{
    if guard.reap().await == OwnerExit::CleanupFailed {
        cleanup
    } else {
        startup
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnerExit {
    Stopped,
    RuntimeFailed,
    CleanupFailed,
}

#[cfg(all(windows, target_arch = "x86_64"))]
enum OwnerReady {
    Ready {
        wake: ferrum2_wintun::StopSignal,
        flows: tokio::sync::mpsc::Receiver<TcpFlow>,
    },
    Failed,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[derive(Clone)]
struct OwnerControl {
    stop: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
    admitting: Arc<AtomicBool>,
    #[cfg(all(windows, target_arch = "x86_64"))]
    flow_count: Arc<AtomicUsize>,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl OwnerControl {
    fn new() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicBool::new(false)),
            admitting: Arc::new(AtomicBool::new(false)),
            #[cfg(all(windows, target_arch = "x86_64"))]
            flow_count: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
struct OwnerThread {
    control: OwnerControl,
    #[cfg(all(windows, target_arch = "x86_64"))]
    wake: Option<ferrum2_wintun::StopSignal>,
    thread: Option<std::thread::JoinHandle<OwnerExit>>,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl OwnerThread {
    fn signal(&self) {
        self.control.stop.store(true, Ordering::Release);
        #[cfg(all(windows, target_arch = "x86_64"))]
        if let Some(wake) = &self.wake {
            let _ = wake.signal();
        }
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
    flows: tokio::sync::mpsc::Receiver<TcpFlow>,
    flow_count: Arc<AtomicUsize>,
    handle_tcp: TcpHandler,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
type TcpHandler =
    Arc<dyn Fn(TcpFlow, ProcessCancellation) -> ProcessFuture<()> + Send + Sync + 'static>;

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl<E> PreparedProcessRoot<E> for TunRoot<E>
where
    E: Send + 'static,
{
    fn activate(&mut self) -> Result<(), E> {
        self.owner.control.admitting.store(true, Ordering::Release);
        self.owner.control.active.store(true, Ordering::Release);
        Ok(())
    }

    fn run(
        mut self: Box<Self>,
        mut cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), E>> {
        Box::pin(async move {
            let mut tasks = tokio::task::JoinSet::new();
            let mut forced = cancellation.clone();
            let reported = 'required: loop {
                if cancellation.is_cancelled() {
                    self.owner.control.admitting.store(false, Ordering::Release);
                }
                if cancellation.is_forced() {
                    tasks.abort_all();
                    break OwnerExit::Stopped;
                }
                if cancellation.is_cancelled()
                    && tasks.is_empty()
                    && self.flow_count.load(Ordering::Acquire) == 0
                {
                    break OwnerExit::Stopped;
                }
                tokio::select! {
                    result = &mut self.done => break reported_owner_exit(result),
                    flow = self.flows.recv() => {
                        if let Some(flow) = flow {
                            while let Some(result) = tasks.try_join_next() {
                                if result.is_err() {
                                    break 'required OwnerExit::RuntimeFailed;
                                }
                            }
                            tasks.spawn((self.handle_tcp)(flow, cancellation.clone()));
                        }
                    }
                    result = tasks.join_next(), if !tasks.is_empty() => {
                        if result.is_some_and(|result| result.is_err()) {
                            break OwnerExit::RuntimeFailed;
                        }
                    }
                    () = cancellation.cancelled(), if !cancellation.is_cancelled() => {
                        self.owner.control.admitting.store(false, Ordering::Release);
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

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
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
fn owner_main(
    config: Config,
    control: OwnerControl,
    ready: std::sync::mpsc::SyncSender<OwnerReady>,
    deadline: std::time::Instant,
    metrics: PacketMetrics,
) -> OwnerExit {
    let adapter_config = match ferrum2_wintun::AdapterConfig::new(
        config.adapter_name,
        config.ipv4,
        config.ipv4_prefix,
        config.ipv6,
        config.ipv6_prefix,
        config.mtu,
        config.ring_capacity,
        config.ready_timeout,
    ) {
        Ok(config) => config,
        Err(_) => {
            let _ = ready.send(OwnerReady::Failed);
            return OwnerExit::RuntimeFailed;
        }
    };
    let adapter = match ferrum2_wintun::Adapter::create(adapter_config, deadline, &control.stop) {
        Ok(adapter) => adapter,
        Err(error) => {
            let _ = ready.send(OwnerReady::Failed);
            return if error.is_cleanup_failure() {
                OwnerExit::CleanupFailed
            } else {
                OwnerExit::RuntimeFailed
            };
        }
    };
    let wake = adapter.stop_signal();
    let stack = Stack::new(
        (
            config.ipv4,
            config.ipv4_prefix,
            config.ipv6,
            config.ipv6_prefix,
        ),
        usize::from(config.mtu),
        config.max_tcp_flows,
        config.tcp_buffer_bytes,
        config.tcp_timeout,
        Arc::clone(&control.flow_count),
    );
    let ((mut stack, flows), mut adapter) =
        match finish_stack_setup(stack, adapter, |adapter| adapter.cleanup()) {
            Ok(stack) => stack,
            Err(exit) => {
                let _ = ready.send(OwnerReady::Failed);
                return exit;
            }
        };
    let _mapping_generations = GenerationTable::new(config.max_udp_mappings);
    if std::time::Instant::now() >= deadline {
        let _ = ready.send(OwnerReady::Failed);
        return match adapter.cleanup() {
            Ok(()) => OwnerExit::RuntimeFailed,
            Err(_) => OwnerExit::CleanupFailed,
        };
    }
    if ready.send(OwnerReady::Ready { wake, flows }).is_err() {
        control.stop.store(true, Ordering::Release);
    }

    let mut fatal = false;
    let clock_origin = std::time::Instant::now();
    while !control.stop.load(Ordering::Acquire) {
        if !control.active.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }
        for _ in 0..PACKET_QUANTUM {
            let received = match adapter.receive() {
                Ok(Some(packet)) => packet,
                Ok(None) => break,
                Err(_) => {
                    fatal = true;
                    break;
                }
            };
            if stack.enqueue(&received, control.admitting.load(Ordering::Acquire)) {
                (metrics.accepted)();
            }
        }
        let elapsed = i64::try_from(clock_origin.elapsed().as_millis()).unwrap_or(i64::MAX);
        for _ in 0..PACKET_QUANTUM {
            for _ in 0..stack.poll_quantum(Instant::from_millis(elapsed)) {
                (metrics.foundation_dropped)();
            }
            match stack.take_output(|packet| adapter.send(packet).is_ok()) {
                OutputResult::Sent => {}
                OutputResult::Empty => break,
                OutputResult::Failed => {
                    fatal = true;
                    break;
                }
            }
        }
        if fatal {
            break;
        }
        let wait = if stack.live_tcp_flows() == 0 { 50 } else { 1 };
        match adapter.wait(Duration::from_millis(wait)) {
            Ok(_) => {}
            Err(_) => {
                fatal = true;
                break;
            }
        }
    }
    match adapter.cleanup() {
        Err(_) => OwnerExit::CleanupFailed,
        Ok(()) if fatal => OwnerExit::RuntimeFailed,
        Ok(()) => OwnerExit::Stopped,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[allow(dead_code)] // Reserved IDs are allocated now; T04/T05 are the first admission users.
struct GenerationId {
    slot: usize,
    generation: u32,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
struct GenerationTable {
    slots: Box<[u32]>,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl GenerationTable {
    fn new(capacity: usize) -> Self {
        Self {
            slots: vec![0; capacity].into_boxed_slice(),
        }
    }

    #[allow(dead_code)] // Exercised by the generation mutation test before flow admission exists.
    fn current(&self, slot: usize) -> Option<GenerationId> {
        self.slots
            .get(slot)
            .copied()
            .filter(|generation| *generation != u32::MAX)
            .map(|generation| GenerationId { slot, generation })
    }

    #[allow(dead_code)] // Exercised by the generation mutation test before flow admission exists.
    fn recycle(&mut self, id: GenerationId) -> bool {
        let Some(generation) = self.slots.get_mut(id.slot) else {
            return false;
        };
        if *generation != id.generation {
            return false;
        }
        let Some(next) = generation.checked_add(1) else {
            return false;
        };
        *generation = next;
        true
    }
}

#[derive(Clone, Copy)]
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
struct PacketValidator {
    mtu: usize,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl PacketValidator {
    const fn new(mtu: usize) -> Self {
        Self { mtu }
    }

    fn accepts(self, packet: &[u8]) -> bool {
        if packet.is_empty() || packet.len() > self.mtu {
            return false;
        }
        match packet[0] >> 4 {
            4 => self.accepts_ipv4(packet),
            6 => self.accepts_ipv6(packet),
            _ => false,
        }
    }

    fn accepts_ipv4(self, packet: &[u8]) -> bool {
        if packet.len() < 20
            || packet[0] & 0x0f != 5
            || usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len()
            || checksum(&[&packet[..20]]) != 0
        {
            return false;
        }
        let fragment = u16::from_be_bytes([packet[6], packet[7]]);
        if fragment & 0x8000 != 0 || fragment & 0x2000 != 0 || fragment & 0x1fff != 0 {
            return false;
        }
        let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        if !ipv4_unicast(source) || !ipv4_unicast(destination) {
            return false;
        }
        self.accepts_transport(
            packet[9],
            &packet[20..],
            &[&packet[12..16], &packet[16..20]],
            false,
        )
    }

    fn accepts_ipv6(self, packet: &[u8]) -> bool {
        if packet.len() < 40
            || 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]])) != packet.len()
        {
            return false;
        }
        let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).expect("fixed slice"));
        let destination =
            Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).expect("fixed slice"));
        if source.is_unspecified()
            || source.is_multicast()
            || destination.is_unspecified()
            || destination.is_multicast()
        {
            return false;
        }
        self.accepts_transport(
            packet[6],
            &packet[40..],
            &[&packet[8..24], &packet[24..40]],
            true,
        )
    }

    fn accepts_transport(
        self,
        protocol: u8,
        transport: &[u8],
        addresses: &[&[u8]],
        ipv6: bool,
    ) -> bool {
        if transport.len() > u16::MAX as usize
            || transport.len() < 8
            || transport[..2] == [0, 0]
            || transport[2..4] == [0, 0]
        {
            return false;
        }
        let checksum_offset = match protocol {
            6 if transport.len() >= 20 => {
                let header_len = usize::from(transport[12] >> 4) * 4;
                if header_len < 20 || header_len > transport.len() {
                    return false;
                }
                16
            }
            17 if usize::from(u16::from_be_bytes([transport[4], transport[5]]))
                == transport.len() =>
            {
                6
            }
            _ => return false,
        };
        if protocol == 17 && !ipv6 && transport[checksum_offset..checksum_offset + 2] == [0, 0] {
            return true;
        }
        if transport[checksum_offset..checksum_offset + 2] == [0, 0] {
            return false;
        }
        let length = transport.len() as u32;
        let length_bytes = length.to_be_bytes();
        let next = [0_u8, 0, 0, protocol];
        if ipv6 {
            checksum(&[
                addresses[0],
                addresses[1],
                length_bytes.as_slice(),
                next.as_slice(),
                transport,
            ]) == 0
        } else {
            checksum(&[
                addresses[0],
                addresses[1],
                &next[2..],
                &length_bytes[2..],
                transport,
            ]) == 0
        }
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
fn ipv4_unicast(address: Ipv4Addr) -> bool {
    !address.is_unspecified() && !address.is_multicast() && !address.is_broadcast()
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0_u32;
    for part in parts {
        let mut chunks = part.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        if let Some(byte) = chunks.remainder().first() {
            sum += u32::from(*byte) << 8;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
struct MemoryDevice {
    ingress: [PacketSlot; INGRESS_SLOTS],
    ingress_head: usize,
    ingress_len: usize,
    output: Box<[u8]>,
    output_len: usize,
    validator: PacketValidator,
    discarded_output: usize,
    rejected_output: usize,
    foundation_input: usize,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl MemoryDevice {
    fn new(mtu: usize) -> Self {
        Self {
            ingress: std::array::from_fn(|_| PacketSlot {
                len: 0,
                foundation: false,
                bytes: vec![0_u8; mtu].into_boxed_slice(),
            }),
            ingress_head: 0,
            ingress_len: 0,
            output: vec![0_u8; mtu].into_boxed_slice(),
            output_len: 0,
            validator: PacketValidator::new(mtu),
            discarded_output: 0,
            rejected_output: 0,
            foundation_input: 0,
        }
    }

    fn enqueue(&mut self, packet: &[u8]) -> bool {
        if self.ingress_len == INGRESS_SLOTS || !self.validator.accepts(packet) {
            return false;
        }
        let tail = (self.ingress_head + self.ingress_len) % INGRESS_SLOTS;
        self.ingress[tail].bytes[..packet.len()].copy_from_slice(packet);
        self.ingress[tail].len = packet.len();
        self.ingress[tail].foundation = match packet[0] >> 4 {
            4 => packet[9] == 17,
            6 => packet[6] == 17,
            _ => false,
        };
        self.ingress_len += 1;
        true
    }

    fn dequeue_index(&mut self) -> Option<usize> {
        if self.ingress_len == 0 || self.output_len != 0 {
            return None;
        }
        let index = self.ingress_head;
        self.foundation_input += usize::from(self.ingress[index].foundation);
        self.ingress_head = (self.ingress_head + 1) % INGRESS_SLOTS;
        self.ingress_len -= 1;
        Some(index)
    }

    fn take_output(&mut self, send: impl FnOnce(&[u8]) -> bool) -> OutputResult {
        if self.output_len == 0 {
            return OutputResult::Empty;
        }
        if !send(&self.output[..self.output_len]) {
            return OutputResult::Failed;
        }
        self.output_len = 0;
        OutputResult::Sent
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputResult {
    Empty,
    Sent,
    Failed,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
struct PacketSlot {
    len: usize,
    foundation: bool,
    bytes: Box<[u8]>,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
struct MemoryRx<'a>(&'a PacketSlot);

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl RxToken for MemoryRx<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0.bytes[..self.0.len])
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
struct MemoryTx<'a> {
    validator: PacketValidator,
    discarded_output: &'a mut usize,
    rejected_output: &'a mut usize,
    output: &'a mut [u8],
    output_len: &'a mut usize,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl TxToken for MemoryTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        assert!(len <= self.output.len(), "stack exceeded validated MTU");
        self.output[..len].fill(0);
        let result = f(&mut self.output[..len]);
        if self.validator.accepts(&self.output[..len]) {
            *self.discarded_output += 1;
            *self.output_len = len;
        } else {
            *self.rejected_output += 1;
        }
        result
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl Device for MemoryDevice {
    type RxToken<'a> = MemoryRx<'a>;
    type TxToken<'a> = MemoryTx<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let index = self.dequeue_index()?;
        Some((
            MemoryRx(&self.ingress[index]),
            MemoryTx {
                validator: self.validator,
                discarded_output: &mut self.discarded_output,
                rejected_output: &mut self.rejected_output,
                output: &mut self.output,
                output_len: &mut self.output_len,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        (self.output_len == 0).then_some(MemoryTx {
            validator: self.validator,
            discarded_output: &mut self.discarded_output,
            rejected_output: &mut self.rejected_output,
            output: &mut self.output,
            output_len: &mut self.output_len,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.validator.mtu;
        capabilities
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
struct Stack {
    interface: Interface,
    sockets: SocketSet<'static>,
    device: MemoryDevice,
    foundation_dropped: usize,
    flows: Box<[Option<TcpFlowEntry>]>,
    generations: GenerationTable,
    tcp_buffer_bytes: usize,
    tcp_timeout_millis: u64,
    bridge_capacity: usize,
    flow_sender: tokio::sync::mpsc::Sender<TcpFlow>,
    flow_count: Arc<AtomicUsize>,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TcpTuple {
    source: SocketAddr,
    target: SocketAddr,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
struct TcpFlowEntry {
    tuple: TcpTuple,
    generation: GenerationId,
    socket: SocketHandle,
    owner: tcp::FlowOwner,
    pending: Option<TcpFlow>,
    published: bool,
    remote_closed: bool,
    fin_started: bool,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl Stack {
    fn new(
        addresses: (Ipv4Addr, u8, Ipv6Addr, u8),
        mtu: usize,
        max_tcp_flows: usize,
        tcp_buffer_bytes: usize,
        tcp_timeout: Duration,
        flow_count: Arc<AtomicUsize>,
    ) -> Result<(Self, tokio::sync::mpsc::Receiver<TcpFlow>), ()> {
        let (ipv4, ipv4_prefix, ipv6, ipv6_prefix) = addresses;
        let mut device = MemoryDevice::new(mtu);
        let mut interface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            Instant::ZERO,
        );
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::from(IpAddr::V4(ipv4)), ipv4_prefix))
                .expect("two-address feature");
            addresses
                .push(IpCidr::new(IpAddress::from(IpAddr::V6(ipv6)), ipv6_prefix))
                .expect("two-address feature");
        });
        interface.set_any_ip(true);
        interface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::from(ipv4.octets()))
            .map_err(|_| ())?;
        interface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::from(ipv6.octets()))
            .map_err(|_| ())?;
        let mut third_rejected = false;
        interface.routes_mut().update(|routes| {
            third_rejected = routes.push(Route::new_ipv4_gateway(ipv4)).is_err();
        });
        if !third_rejected {
            return Err(());
        }
        let (flow_sender, flow_receiver) = tokio::sync::mpsc::channel(max_tcp_flows);
        let tcp_timeout_millis = u64::try_from(tcp_timeout.as_millis()).map_err(|_| ())?;
        Ok((
            Self {
                interface,
                sockets: SocketSet::new(Vec::with_capacity(max_tcp_flows)),
                device,
                foundation_dropped: 0,
                flows: std::iter::repeat_with(|| None)
                    .take(max_tcp_flows)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                generations: GenerationTable::new(max_tcp_flows),
                tcp_buffer_bytes,
                tcp_timeout_millis,
                bridge_capacity: mtu / 2,
                flow_sender,
                flow_count,
            },
            flow_receiver,
        ))
    }

    fn enqueue(&mut self, packet: &[u8], admitting: bool) -> bool {
        if self.device.ingress_len == INGRESS_SLOTS || !self.device.validator.accepts(packet) {
            return false;
        }
        match initial_tcp_tuple(packet) {
            Ok(Some(tuple)) if !self.admit_tcp(tuple, admitting) => return false,
            Err(()) => return false,
            Ok(Some(_)) | Ok(None) => {}
        }
        self.device.enqueue(packet)
    }

    fn admit_tcp(&mut self, tuple: TcpTuple, admitting: bool) -> bool {
        if self.flows.iter().flatten().any(|flow| flow.tuple == tuple) {
            return true;
        }
        if !admitting {
            return false;
        }
        let Some(slot) = self.flows.iter().position(Option::is_none) else {
            return false;
        };
        let Some(generation) = self.generations.current(slot) else {
            return false;
        };
        let mut socket = TcpSocket::new(
            TcpSocketBuffer::new(vec![0; self.tcp_buffer_bytes]),
            TcpSocketBuffer::new(vec![0; self.tcp_buffer_bytes]),
        );
        socket.set_timeout(Some(smoltcp::time::Duration::from_millis(
            self.tcp_timeout_millis,
        )));
        socket.set_nagle_enabled(false);
        let endpoint = IpEndpoint::new(ip_address(tuple.target.ip()), tuple.target.port());
        if socket.listen(endpoint).is_err() {
            return false;
        }
        let socket = self.sockets.add(socket);
        let (flow, owner) = tcp::tcp_flow_pair(tuple.target, self.bridge_capacity);
        self.flows[slot] = Some(TcpFlowEntry {
            tuple,
            generation,
            socket,
            owner,
            pending: Some(flow),
            published: false,
            remote_closed: false,
            fin_started: false,
        });
        self.flow_count.fetch_add(1, Ordering::AcqRel);
        true
    }

    fn live_tcp_flows(&self) -> usize {
        self.flows.iter().flatten().count()
    }

    fn poll_quantum(&mut self, now: Instant) -> usize {
        let mut processed = 0;
        let foundation_before = self.device.foundation_input;
        while processed < PACKET_QUANTUM {
            if matches!(
                self.interface
                    .poll_ingress_single(now, &mut self.device, &mut self.sockets,),
                PollIngressSingleResult::None
            ) {
                break;
            }
            processed += 1;
        }
        let foundation = self.device.foundation_input - foundation_before;
        self.foundation_dropped += foundation;
        self.drive_tcp();
        let _ = self
            .interface
            .poll_egress(now, &mut self.device, &mut self.sockets);
        self.reap_tcp();
        foundation
    }

    fn drive_tcp(&mut self) {
        for entry in self.flows.iter_mut().flatten() {
            let socket = self.sockets.get_mut::<TcpSocket>(entry.socket);

            if socket.state() == TcpState::Established
                && let Some(flow) = entry.pending.take()
            {
                match self.flow_sender.try_send(flow) {
                    Ok(()) => entry.published = true,
                    Err(tokio::sync::mpsc::error::TrySendError::Full(flow)) => {
                        entry.pending = Some(flow);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => socket.abort(),
                }
            }

            if entry.owner.is_aborted() {
                socket.abort();
            } else {
                if entry.owner.application_capacity() != 0 && socket.can_recv() {
                    let _ = socket.recv(|bytes| {
                        let copied = entry.owner.write_from_stack(bytes);
                        (copied, ())
                    });
                }
                if entry.owner.stack_buffered() != 0 && socket.may_send() {
                    entry
                        .owner
                        .drain_to_stack(|bytes| socket.send_slice(bytes).unwrap_or(0));
                }
                if !entry.remote_closed && !socket.may_recv() && entry.published {
                    entry.owner.mark_remote_closed();
                    entry.remote_closed = true;
                }
                if entry.owner.shutdown_requested()
                    && entry.owner.stack_buffered() == 0
                    && !entry.fin_started
                    && socket.may_send()
                {
                    socket.close();
                    entry.fin_started = true;
                    entry.owner.mark_fin_sent();
                }
            }

            if socket.state() == TcpState::Closed && !entry.remote_closed {
                entry.owner.mark_reset();
            }
        }
    }

    fn reap_tcp(&mut self) {
        for index in 0..self.flows.len() {
            let remove = self.flows[index].as_ref().is_some_and(|entry| {
                let state = self.sockets.get::<TcpSocket>(entry.socket).state();
                state == TcpState::Closed || (state == TcpState::TimeWait && entry.remote_closed)
            });
            if remove && let Some(entry) = self.flows[index].take() {
                self.sockets.remove(entry.socket);
                let _ = self.generations.recycle(entry.generation);
                self.flow_count.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }

    fn take_output(&mut self, send: impl FnOnce(&[u8]) -> bool) -> OutputResult {
        self.device.take_output(send)
    }

    #[cfg(test)]
    fn pending(&self) -> usize {
        self.device.ingress_len
    }

    #[cfg(test)]
    fn discarded_packets(&self) -> usize {
        self.foundation_dropped
    }

    #[cfg(test)]
    fn validated_egress_packets(&self) -> usize {
        self.device.discarded_output
    }

    #[cfg(test)]
    fn rejected_egress_packets(&self) -> usize {
        self.device.rejected_output
    }

    #[cfg(test)]
    fn has_exact_routes(&self) -> bool {
        self.interface.routes().get_default_ipv4_route().is_some()
            && self.interface.routes().get_default_ipv6_route().is_some()
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
fn initial_tcp_tuple(packet: &[u8]) -> Result<Option<TcpTuple>, ()> {
    let (source, target, offset) = match packet[0] >> 4 {
        4 if packet.get(9) == Some(&6) => (
            std::net::IpAddr::V4(Ipv4Addr::new(
                packet[12], packet[13], packet[14], packet[15],
            )),
            std::net::IpAddr::V4(Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            )),
            20,
        ),
        6 if packet.get(6) == Some(&6) => (
            std::net::IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&packet[8..24]).map_err(|_| ())?,
            )),
            std::net::IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&packet[24..40]).map_err(|_| ())?,
            )),
            40,
        ),
        _ => return Ok(None),
    };
    if packet[offset + 13] & 0x02 == 0 {
        return Ok(None);
    }
    let segment = TcpPacket::new_checked(&packet[offset..]).map_err(|_| ())?;
    let repr = TcpRepr::parse(
        &segment,
        &ip_address(source),
        &ip_address(target),
        &ChecksumCapabilities::default(),
    )
    .map_err(|_| ())?;
    if repr.control != TcpControl::Syn || repr.ack_number.is_some() {
        return Err(());
    }
    Ok(Some(TcpTuple {
        source: SocketAddr::new(source, repr.src_port),
        target: SocketAddr::new(target, repr.dst_port),
    }))
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
fn ip_address(address: std::net::IpAddr) -> IpAddress {
    match address {
        std::net::IpAddr::V4(address) => IpAddress::Ipv4(Ipv4Address::from(address.octets())),
        std::net::IpAddr::V6(address) => IpAddress::Ipv6(Ipv6Address::from(address.octets())),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use smoltcp::phy::{Device, TxToken};
    use smoltcp::time::Instant;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::tcp::tcp_flow_pair;
    use super::{
        GenerationTable, MemoryTx, OutputResult, OwnerControl, OwnerExit, OwnerThread,
        PacketValidator, Stack, TunRoot, finish_stack_setup, map_owner_spawn, reconcile_owner_exit,
        reported_owner_exit,
    };

    #[tokio::test]
    async fn tcp_flow_queue_backpressure_partial_writes_fin_and_reset_are_lossless() {
        let target: SocketAddr = "192.0.2.10:443".parse().expect("target");
        let (mut flow, mut owner) = tcp_flow_pair(target, 4);
        assert_eq!(flow.target(), target);

        assert_eq!(flow.write(b"abcdef").await.expect("bounded write"), 4);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), flow.write(b"x"))
                .await
                .is_err(),
            "a full Tokio-to-stack queue applies backpressure"
        );
        let mut bytes = [0; 8];
        assert_eq!(owner.read_to_stack(&mut bytes[..2]), 2);
        assert_eq!(&bytes[..2], b"ab");
        assert_eq!(flow.write(b"ef").await.expect("released write"), 2);
        assert_eq!(owner.read_to_stack(&mut bytes), 4);
        assert_eq!(&bytes[..4], b"cdef");

        assert_eq!(owner.write_from_stack(b"abcdef"), 4);
        flow.read_exact(&mut bytes[..2])
            .await
            .expect("partial read");
        assert_eq!(&bytes[..2], b"ab");
        assert_eq!(owner.write_from_stack(b"ef"), 2);
        flow.read_exact(&mut bytes[..4])
            .await
            .expect("retained read");
        assert_eq!(&bytes[..4], b"cdef");

        flow.write_all(b"xy").await.expect("write before FIN");
        assert!(
            tokio::time::timeout(Duration::from_millis(10), flow.shutdown())
                .await
                .is_err(),
            "FIN waits behind accepted bytes"
        );
        assert_eq!(owner.read_to_stack(&mut bytes), 2);
        assert_eq!(&bytes[..2], b"xy");
        assert!(owner.shutdown_requested());
        owner.mark_fin_sent();
        flow.shutdown().await.expect("ordered FIN");
        owner.mark_remote_closed();
        assert_eq!(flow.read(&mut bytes).await.expect("remote FIN"), 0);

        let (mut reset_flow, mut reset_owner) = tcp_flow_pair(target, 4);
        reset_owner.mark_reset();
        assert_eq!(
            reset_flow
                .write(b"closed")
                .await
                .expect_err("reset is terminal")
                .kind(),
            std::io::ErrorKind::ConnectionReset
        );

        let (dropped, owner) = tcp_flow_pair(target, 4);
        drop(dropped);
        assert!(owner.is_aborted(), "dropping a live flow requests reset");
    }

    fn checksum(parts: &[&[u8]]) -> u16 {
        let mut sum = 0_u32;
        for part in parts {
            let mut chunks = part.chunks_exact(2);
            for chunk in &mut chunks {
                sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
            }
            if let Some(byte) = chunks.remainder().first() {
                sum += u32::from(*byte) << 8;
            }
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn ipv4_udp_with_payload(payload: usize) -> Vec<u8> {
        let len = 28 + payload;
        let mut packet = vec![0_u8; len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[198, 18, 0, 1]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
        packet[20..22].copy_from_slice(&10_000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53_u16.to_be_bytes());
        packet[24..26].copy_from_slice(&((8 + payload) as u16).to_be_bytes());
        for (index, byte) in packet[28..].iter_mut().enumerate() {
            *byte = index as u8;
        }
        let header = checksum(&[&packet[..20]]);
        packet[10..12].copy_from_slice(&header.to_be_bytes());
        let pseudo = [0_u8, 17];
        let length = ((8 + payload) as u16).to_be_bytes();
        let udp = checksum(&[
            &packet[12..16],
            &packet[16..20],
            &pseudo,
            &length,
            &packet[20..],
        ]);
        packet[26..28].copy_from_slice(&udp.to_be_bytes());
        packet
    }

    fn ipv4_udp() -> Vec<u8> {
        ipv4_udp_with_payload(4)
    }

    fn ipv4_tcp() -> Vec<u8> {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[198, 18, 0, 1]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
        packet[20..22].copy_from_slice(&10_000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x02;
        packet[34..36].copy_from_slice(&8192_u16.to_be_bytes());
        let pseudo = [0_u8, 6];
        let length = 20_u16.to_be_bytes();
        let tcp = checksum(&[
            &packet[12..16],
            &packet[16..20],
            &pseudo,
            &length,
            &packet[20..],
        ]);
        packet[36..38].copy_from_slice(&tcp.to_be_bytes());
        let header = checksum(&[&packet[..20]]);
        packet[10..12].copy_from_slice(&header.to_be_bytes());
        packet
    }

    fn ipv6_udp() -> Vec<u8> {
        let mut packet = vec![0_u8; 52];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&12_u16.to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[23] = 2;
        packet[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        packet[40..42].copy_from_slice(&10_000_u16.to_be_bytes());
        packet[42..44].copy_from_slice(&53_u16.to_be_bytes());
        packet[44..46].copy_from_slice(&12_u16.to_be_bytes());
        packet[48..].copy_from_slice(b"test");
        let length = 12_u32.to_be_bytes();
        let next = [0_u8, 0, 0, 17];
        let udp = checksum(&[
            &packet[8..24],
            &packet[24..40],
            &length,
            &next,
            &packet[40..],
        ]);
        packet[46..48].copy_from_slice(&udp.to_be_bytes());
        packet
    }

    fn ipv6_tcp() -> Vec<u8> {
        let mut packet = vec![0_u8; 60];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&20_u16.to_be_bytes());
        packet[6] = 6;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2).octets());
        packet[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        packet[40..42].copy_from_slice(&10_000_u16.to_be_bytes());
        packet[42..44].copy_from_slice(&443_u16.to_be_bytes());
        packet[52] = 0x50;
        packet[53] = 0x02;
        let length = 20_u32.to_be_bytes();
        let next = [0_u8, 0, 0, 6];
        let tcp = checksum(&[
            &packet[8..24],
            &packet[24..40],
            &length,
            &next,
            &packet[40..],
        ]);
        packet[56..58].copy_from_slice(&tcp.to_be_bytes());
        packet
    }

    fn repair_ipv4_header(packet: &mut [u8]) {
        packet[10..12].fill(0);
        let header = checksum(&[&packet[..20]]);
        packet[10..12].copy_from_slice(&header.to_be_bytes());
    }

    fn repair_ipv4_tcp_checksum(packet: &mut [u8]) {
        packet[36..38].fill(0);
        let pseudo = [0_u8, 6];
        let length = ((packet.len() - 20) as u16).to_be_bytes();
        let tcp = checksum(&[
            &packet[12..16],
            &packet[16..20],
            &pseudo,
            &length,
            &packet[20..],
        ]);
        packet[36..38].copy_from_slice(&tcp.to_be_bytes());
    }

    fn ipv4_tcp_after_syn(syn_ack: &[u8], flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = ipv4_tcp();
        packet.resize(40 + payload.len(), 0);
        let packet_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[24..28].copy_from_slice(&1_u32.to_be_bytes());
        let server_sequence = u32::from_be_bytes(syn_ack[24..28].try_into().expect("SYN-ACK seq"));
        packet[28..32].copy_from_slice(&server_sequence.wrapping_add(1).to_be_bytes());
        packet[33] = flags;
        packet[40..].copy_from_slice(payload);
        repair_ipv4_header(&mut packet);
        repair_ipv4_tcp_checksum(&mut packet);
        packet
    }

    fn assert_ingress_and_egress(name: &str, packet: &[u8], mtu: usize, expected: bool) {
        let validator = PacketValidator::new(mtu);
        assert_eq!(validator.accepts(packet), expected, "ingress {name}");

        let mut accepted = 0;
        let mut rejected = 0;
        let mut output_len = 0;
        let mut output = vec![0_u8; packet.len().max(1)];
        MemoryTx {
            validator,
            discarded_output: &mut accepted,
            rejected_output: &mut rejected,
            output: &mut output,
            output_len: &mut output_len,
        }
        .consume(packet.len(), |bytes| bytes.copy_from_slice(packet));
        assert_eq!(accepted, usize::from(expected), "egress accept {name}");
        assert_eq!(rejected, usize::from(!expected), "egress reject {name}");
    }

    #[test]
    fn packet_filter_accepts_only_complete_direct_tcp_or_udp() {
        let valid_v4 = ipv4_udp();
        let valid_v6 = ipv6_udp();
        let valid_v4_tcp = ipv4_tcp();
        let valid_v6_tcp = ipv6_tcp();
        for (name, packet) in [
            ("IPv4 UDP", valid_v4.as_slice()),
            ("IPv4 TCP", valid_v4_tcp.as_slice()),
            ("IPv6 UDP", valid_v6.as_slice()),
            ("IPv6 TCP", valid_v6_tcp.as_slice()),
        ] {
            assert_ingress_and_egress(name, packet, 1420, true);
        }
        let mut zero_v4_udp = valid_v4.clone();
        zero_v4_udp[26..28].fill(0);
        assert_ingress_and_egress("IPv4 UDP zero checksum", &zero_v4_udp, 1420, true);

        let mut df = valid_v4.clone();
        df[6] = 0x40;
        repair_ipv4_header(&mut df);
        assert_ingress_and_egress("IPv4 DF", &df, 1420, true);

        let minimum_udp = ipv4_udp_with_payload(0);
        assert_ingress_and_egress("IPv4 UDP minimum", &minimum_udp, 1420, true);
        let mtu_packet = ipv4_udp_with_payload(1420 - 28);
        assert_ingress_and_egress("MTU exact", &mtu_packet, 1420, true);
        assert_ingress_and_egress("MTU plus one", &mtu_packet, 1419, false);

        let mut mutations = vec![
            ("empty", Vec::new()),
            ("IPv4 header minimum minus one", valid_v4[..19].to_vec()),
            ("IPv4 transport minimum minus one", valid_v4[..27].to_vec()),
            ("IPv4 version", {
                let mut p = valid_v4.clone();
                p[0] = 0x55;
                repair_ipv4_header(&mut p);
                p
            }),
            ("IPv4 IHL 4", {
                let mut p = valid_v4.clone();
                p[0] = 0x44;
                repair_ipv4_header(&mut p);
                p
            }),
            ("IPv4 option", {
                let mut p = valid_v4.clone();
                p[0] = 0x46;
                repair_ipv4_header(&mut p);
                p
            }),
            ("IPv4 declared length minimum minus one", {
                let mut p = valid_v4.clone();
                p[2..4].copy_from_slice(&31_u16.to_be_bytes());
                repair_ipv4_header(&mut p);
                p
            }),
            ("IPv4 declared length plus one", {
                let mut p = valid_v4.clone();
                p[2..4].copy_from_slice(&33_u16.to_be_bytes());
                repair_ipv4_header(&mut p);
                p
            }),
            ("IPv4 reserved", {
                let mut p = valid_v4.clone();
                p[6] = 0x80;
                repair_ipv4_header(&mut p);
                p
            }),
            ("IPv4 MF", {
                let mut p = valid_v4.clone();
                p[6] = 0x20;
                repair_ipv4_header(&mut p);
                p
            }),
            ("IPv4 fragment offset", {
                let mut p = valid_v4.clone();
                p[7] = 1;
                repair_ipv4_header(&mut p);
                p
            }),
            ("IPv4 trailing", {
                let mut p = valid_v4.clone();
                p.push(0);
                p
            }),
            ("IPv4 checksum", {
                let mut p = valid_v4.clone();
                p[10] ^= 1;
                p
            }),
            ("IPv4 ICMP", {
                let mut p = valid_v4.clone();
                p[9] = 1;
                repair_ipv4_header(&mut p);
                p
            }),
            ("IPv4 unknown protocol", {
                let mut p = valid_v4.clone();
                p[9] = 99;
                repair_ipv4_header(&mut p);
                p
            }),
            ("IPv4 zero port", {
                let mut p = valid_v4.clone();
                p[20..22].fill(0);
                p
            }),
            ("IPv4 UDP destination zero", {
                let mut p = valid_v4.clone();
                p[22..24].fill(0);
                p
            }),
            ("IPv4 UDP length minimum minus one", {
                let mut p = valid_v4.clone();
                p[24..26].copy_from_slice(&7_u16.to_be_bytes());
                p
            }),
            ("IPv4 UDP length short", {
                let mut p = valid_v4.clone();
                p[24..26].copy_from_slice(&11_u16.to_be_bytes());
                p
            }),
            ("IPv4 UDP length long", {
                let mut p = valid_v4.clone();
                p[24..26].copy_from_slice(&13_u16.to_be_bytes());
                p
            }),
            ("IPv4 UDP checksum", {
                let mut p = valid_v4.clone();
                p[28] ^= 1;
                p
            }),
            ("TCP data offset", {
                let mut p = valid_v4_tcp.clone();
                p[32] = 0x40;
                p
            }),
            ("TCP data offset beyond payload", {
                let mut p = valid_v4_tcp.clone();
                p[32] = 0x60;
                p
            }),
            ("TCP source zero", {
                let mut p = valid_v4_tcp.clone();
                p[20..22].fill(0);
                p
            }),
            ("TCP destination zero", {
                let mut p = valid_v4_tcp.clone();
                p[22..24].fill(0);
                p
            }),
            ("TCP checksum", {
                let mut p = valid_v4_tcp.clone();
                p[36] ^= 1;
                p
            }),
            ("IPv6 header minimum minus one", valid_v6[..39].to_vec()),
            ("IPv6 payload length short", {
                let mut p = valid_v6.clone();
                p[4..6].copy_from_slice(&11_u16.to_be_bytes());
                p
            }),
            ("IPv6 payload length long", {
                let mut p = valid_v6.clone();
                p[4..6].copy_from_slice(&13_u16.to_be_bytes());
                p
            }),
            ("IPv6 UDP source zero", {
                let mut p = valid_v6.clone();
                p[40..42].fill(0);
                p
            }),
            ("IPv6 UDP destination zero", {
                let mut p = valid_v6.clone();
                p[42..44].fill(0);
                p
            }),
            ("IPv6 UDP length minimum minus one", {
                let mut p = valid_v6.clone();
                p[44..46].copy_from_slice(&7_u16.to_be_bytes());
                p
            }),
            ("IPv6 UDP length mismatch", {
                let mut p = valid_v6.clone();
                p[44..46].copy_from_slice(&11_u16.to_be_bytes());
                p
            }),
            ("IPv6 zero checksum", {
                let mut p = valid_v6.clone();
                p[46..48].fill(0);
                p
            }),
            ("IPv6 UDP nonzero bad checksum", {
                let mut p = valid_v6.clone();
                p[46] ^= 1;
                p
            }),
            ("IPv6 trailing", {
                let mut p = valid_v6.clone();
                p.push(0);
                p
            }),
            ("IPv6 TCP data offset minimum minus one", {
                let mut p = valid_v6_tcp.clone();
                p[52] = 0x40;
                p
            }),
            ("IPv6 TCP data offset beyond payload", {
                let mut p = valid_v6_tcp.clone();
                p[52] = 0x60;
                p
            }),
            ("IPv6 TCP checksum", {
                let mut p = valid_v6_tcp.clone();
                p[56] ^= 1;
                p
            }),
            ("IPv6 TCP source zero", {
                let mut p = valid_v6_tcp.clone();
                p[40..42].fill(0);
                p
            }),
            ("IPv6 TCP destination zero", {
                let mut p = valid_v6_tcp.clone();
                p[42..44].fill(0);
                p
            }),
        ];

        for (name, range, bytes) in [
            ("IPv4 source unspecified", 12..16, [0, 0, 0, 0]),
            ("IPv4 source multicast", 12..16, [224, 0, 0, 1]),
            ("IPv4 destination unspecified", 16..20, [0, 0, 0, 0]),
            ("IPv4 destination multicast", 16..20, [224, 0, 0, 1]),
            ("IPv4 destination broadcast", 16..20, [255, 255, 255, 255]),
        ] {
            let mut packet = valid_v4.clone();
            packet[range].copy_from_slice(&bytes);
            repair_ipv4_header(&mut packet);
            mutations.push((name, packet));
        }

        for (name, range, bytes) in [
            (
                "IPv6 source unspecified",
                8..24,
                Ipv6Addr::UNSPECIFIED.octets(),
            ),
            (
                "IPv6 source multicast",
                8..24,
                Ipv6Addr::LOCALHOST.octets().map(|_| 0),
            ),
            (
                "IPv6 destination unspecified",
                24..40,
                Ipv6Addr::UNSPECIFIED.octets(),
            ),
            (
                "IPv6 destination multicast",
                24..40,
                Ipv6Addr::LOCALHOST.octets().map(|_| 0),
            ),
        ] {
            let mut packet = valid_v6.clone();
            let mut address = bytes;
            if name.contains("multicast") {
                address[0] = 0xff;
                address[1] = 0x02;
                address[15] = 1;
            }
            packet[range].copy_from_slice(&address);
            mutations.push((name, packet));
        }

        for (name, packet) in mutations {
            assert_ingress_and_egress(name, &packet, 1420, false);
        }

        for next_header in [0, 43, 44, 50, 51, 59, 60, 135, 139, 140, 253, 254] {
            for (shape, mut packet) in [
                ("absent", valid_v6[..40].to_vec()),
                ("truncated", valid_v6[..41].to_vec()),
                ("well-formed/chained", valid_v6.clone()),
            ] {
                packet[6] = next_header;
                let payload = packet.len() - 40;
                packet[4..6].copy_from_slice(&(payload as u16).to_be_bytes());
                if payload > 0 {
                    packet[40] = 17;
                }
                assert_ingress_and_egress(
                    &format!("IPv6 next header {next_header} {shape}"),
                    &packet,
                    1420,
                    false,
                );
            }
        }
    }

    #[test]
    fn tcp_five_tuple_admission_is_bounded_before_socket_or_buffer_creation() {
        let flow_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (mut stack, _flows) = Stack::new(
            (
                Ipv4Addr::new(198, 18, 0, 2),
                30,
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                126,
            ),
            1420,
            1,
            4096,
            Duration::from_secs(60),
            Arc::clone(&flow_count),
        )
        .expect("bounded stack");
        for (name, mut packet, flags) in [
            ("SYN+FIN", ipv4_tcp(), 0x03),
            ("SYN+RST", ipv4_tcp(), 0x06),
            ("SYN+ACK", ipv4_tcp(), 0x12),
        ] {
            packet[33] = flags;
            repair_ipv4_tcp_checksum(&mut packet);
            assert!(
                !stack.enqueue(&packet, true),
                "{name} is not an initial SYN"
            );
            assert_eq!(stack.live_tcp_flows(), 0, "{name} leaked a flow slot");
        }
        let mut malformed_option = ipv4_tcp();
        malformed_option.resize(44, 0);
        malformed_option[2..4].copy_from_slice(&44_u16.to_be_bytes());
        malformed_option[32] = 0x60;
        malformed_option[40..44].copy_from_slice(&[2, 1, 0, 0]);
        repair_ipv4_header(&mut malformed_option);
        repair_ipv4_tcp_checksum(&mut malformed_option);
        assert!(
            !stack.enqueue(&malformed_option, true),
            "malformed TCP options fail before admission"
        );
        assert_eq!(stack.live_tcp_flows(), 0, "malformed options leaked a slot");

        let first = ipv4_tcp();
        assert!(stack.enqueue(&first, true));
        assert_eq!(stack.live_tcp_flows(), 1);
        assert_eq!(flow_count.load(Ordering::Acquire), 1);

        assert!(
            stack.enqueue(&first, true),
            "duplicate SYN reuses its tuple"
        );
        assert_eq!(stack.live_tcp_flows(), 1);

        let mut second = first.clone();
        second[20..22].copy_from_slice(&10_001_u16.to_be_bytes());
        repair_ipv4_tcp_checksum(&mut second);
        assert!(!stack.enqueue(&second, true), "flow ceiling is exact");
        assert_eq!(stack.live_tcp_flows(), 1);

        let mut closed = Stack::new(
            (
                Ipv4Addr::new(198, 18, 0, 2),
                30,
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                126,
            ),
            1420,
            1,
            4096,
            Duration::from_secs(60),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        )
        .expect("closed stack")
        .0;
        assert!(!closed.enqueue(&first, false), "quiesce rejects new SYN");
        assert_eq!(closed.live_tcp_flows(), 0);

        let (mut ipv6_stack, _) = Stack::new(
            (
                Ipv4Addr::new(198, 18, 0, 2),
                30,
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                126,
            ),
            1420,
            1,
            4096,
            Duration::from_secs(60),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        )
        .expect("IPv6 stack");
        assert!(ipv6_stack.enqueue(&ipv6_tcp(), true));
        assert_eq!(ipv6_stack.live_tcp_flows(), 1, "IPv6 has the same ceiling");
    }

    #[tokio::test]
    async fn tcp_handshake_publishes_once_and_preserves_both_byte_directions() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut stack, mut flows) = Stack::new(
            (
                Ipv4Addr::new(198, 18, 0, 2),
                30,
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                126,
            ),
            1420,
            1,
            4096,
            Duration::from_secs(60),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        )
        .expect("bounded stack");
        assert!(stack.enqueue(&ipv4_tcp(), true));
        assert_eq!(
            stack.poll_quantum(Instant::ZERO),
            0,
            "TCP is not a foundation drop"
        );
        let mut syn_ack = Vec::new();
        assert_eq!(
            stack.take_output(|packet| {
                syn_ack.extend_from_slice(packet);
                true
            }),
            OutputResult::Sent
        );
        assert_eq!(syn_ack[33] & 0x12, 0x12);

        let ack = ipv4_tcp_after_syn(&syn_ack, 0x10, &[]);
        assert!(stack.enqueue(&ack, true));
        assert_eq!(
            stack.poll_quantum(Instant::from_millis(1)),
            0,
            "TCP is not a foundation drop"
        );
        let mut flow = flows.try_recv().expect("flow after completed handshake");
        assert_eq!(flow.target(), "192.0.2.1:443".parse().expect("target"));
        assert!(flows.try_recv().is_err(), "one handshake publishes once");

        let inbound = ipv4_tcp_after_syn(&syn_ack, 0x18, b"inbound");
        assert!(stack.enqueue(&inbound, true));
        assert_eq!(
            stack.poll_quantum(Instant::from_millis(2)),
            0,
            "TCP is not a foundation drop"
        );
        let mut received = [0; 7];
        flow.read_exact(&mut received).await.expect("stack to app");
        assert_eq!(&received, b"inbound");
        assert_ne!(
            stack.take_output(|_| true),
            OutputResult::Failed,
            "optional ACK leaves the fixed TX slot"
        );

        let bridge_capacity = stack.bridge_capacity;
        let outbound = vec![0x5a; bridge_capacity + 17];
        flow.write_all(&outbound[..bridge_capacity])
            .await
            .expect("fill app-to-stack bridge exactly");
        let mut overflow = Box::pin(flow.write_all(&outbound[bridge_capacity..]));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut overflow)
                .await
                .is_err(),
            "bytes beyond the bridge capacity apply backpressure"
        );
        stack.poll_quantum(Instant::from_millis(3));
        let mut observed = Vec::new();
        assert_eq!(
            stack.take_output(|packet| {
                observed.extend_from_slice(&packet[40..]);
                true
            }),
            OutputResult::Sent
        );
        overflow.await.expect("released bridge write");
        stack.poll_quantum(Instant::from_millis(4));
        assert_eq!(
            stack.take_output(|packet| {
                observed.extend_from_slice(&packet[40..]);
                true
            }),
            OutputResult::Sent
        );
        assert_eq!(observed, outbound, "full bridge drains without byte loss");

        drop(flow);
        stack.poll_quantum(Instant::from_millis(5));
        let mut reset = false;
        assert_eq!(
            stack.take_output(|packet| {
                reset = packet[33] & 0x04 != 0;
                true
            }),
            OutputResult::Sent
        );
        assert!(reset, "terminal drop emits a local TCP reset");
        assert_eq!(stack.live_tcp_flows(), 0);
        assert!(stack.enqueue(&ipv4_tcp(), true));
        assert_eq!(
            stack.flows[0]
                .as_ref()
                .expect("reused slot")
                .generation
                .generation,
            1,
            "reused tuples receive a new generation"
        );
    }

    #[tokio::test]
    async fn tcp_payload_fin_retransmission_and_final_ack_reap_without_reset() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let flow_count = Arc::new(AtomicUsize::new(0));
        let (mut stack, mut flows) = Stack::new(
            (
                Ipv4Addr::new(198, 18, 0, 2),
                30,
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                126,
            ),
            1420,
            1,
            4096,
            Duration::from_secs(60),
            Arc::clone(&flow_count),
        )
        .expect("bounded stack");
        assert!(stack.enqueue(&ipv4_tcp(), true));
        stack.poll_quantum(Instant::ZERO);
        let mut syn_ack = Vec::new();
        assert_eq!(
            stack.take_output(|packet| {
                syn_ack.extend_from_slice(packet);
                true
            }),
            OutputResult::Sent
        );
        assert!(stack.enqueue(&ipv4_tcp_after_syn(&syn_ack, 0x10, &[]), true));
        stack.poll_quantum(Instant::from_millis(1));
        let mut flow = flows.try_recv().expect("established flow");
        assert!(flows.try_recv().is_err(), "one handshake publishes once");
        assert_eq!(flow_count.load(Ordering::Acquire), 1);

        let request = b"request";
        let remote_fin = ipv4_tcp_after_syn(&syn_ack, 0x19, request);
        assert!(stack.enqueue(&remote_fin, true));
        stack.poll_quantum(Instant::from_millis(2));
        let mut received = [0; 7];
        flow.read_exact(&mut received)
            .await
            .expect("request payload");
        assert_eq!(&received, request);
        assert_eq!(flow.read(&mut [0; 1]).await.expect("remote FIN"), 0);
        let mut reset = false;
        assert_ne!(
            stack.take_output(|packet| {
                reset |= packet[33] & 0x04 != 0;
                true
            }),
            OutputResult::Failed
        );
        assert!(!reset, "remote payload+FIN is acknowledged without reset");

        let reply = b"reply";
        flow.write_all(reply).await.expect("half-close reply");
        let mut shutdown = Box::pin(flow.shutdown());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut shutdown)
                .await
                .is_err(),
            "shutdown waits for the owner poll"
        );
        stack.poll_quantum(Instant::from_millis(3));
        let mut reply_fin = Vec::new();
        assert_eq!(
            stack.take_output(|packet| {
                reply_fin.extend_from_slice(packet);
                true
            }),
            OutputResult::Sent
        );
        assert_eq!(&reply_fin[40..], reply);
        assert_ne!(reply_fin[33] & 0x01, 0, "reply carries local FIN");
        assert_eq!(reply_fin[33] & 0x04, 0, "reply carries no reset");

        stack.poll_quantum(Instant::from_millis(1_004));
        let mut retransmission = Vec::new();
        assert_eq!(
            stack.take_output(|packet| {
                retransmission.extend_from_slice(packet);
                true
            }),
            OutputResult::Sent
        );
        assert_eq!(&retransmission[24..28], &reply_fin[24..28]);
        assert_eq!(&retransmission[40..], reply);
        assert_ne!(retransmission[33] & 0x01, 0, "retransmission retains FIN");
        assert_eq!(
            retransmission[33] & 0x04,
            0,
            "retransmission carries no reset"
        );

        let mut final_ack = ipv4_tcp_after_syn(&syn_ack, 0x10, &[]);
        final_ack[24..28].copy_from_slice(&(1_u32 + request.len() as u32 + 1).to_be_bytes());
        let reply_sequence =
            u32::from_be_bytes(reply_fin[24..28].try_into().expect("reply sequence"));
        final_ack[28..32].copy_from_slice(
            &reply_sequence
                .wrapping_add(reply.len() as u32 + 1)
                .to_be_bytes(),
        );
        repair_ipv4_tcp_checksum(&mut final_ack);
        assert!(stack.enqueue(&final_ack, true));
        stack.poll_quantum(Instant::from_millis(1_005));
        reset = false;
        assert_eq!(
            stack.take_output(|packet| {
                reset |= packet[33] & 0x04 != 0;
                true
            }),
            OutputResult::Empty
        );
        assert!(!reset, "final ACK produces no reset");
        shutdown.await.expect("local FIN committed");
        assert_eq!(stack.live_tcp_flows(), 0);
        assert!(stack.flows[0].is_none(), "flow slot is reaped");
        assert!(stack.sockets.iter().next().is_none(), "socket is reaped");
        assert_eq!(
            stack
                .generations
                .current(0)
                .expect("recycled slot")
                .generation,
            1,
            "generation advances exactly once"
        );
        assert_eq!(flow_count.load(Ordering::Acquire), 0);

        drop(flow);
        stack.poll_quantum(Instant::from_millis(1_006));
        assert_eq!(
            stack.take_output(|_| true),
            OutputResult::Empty,
            "dropping a completed flow does not abort"
        );
    }

    #[test]
    fn tcp_idle_timeout_reclaims_an_unfinished_handshake() {
        let flow_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (mut stack, _) = Stack::new(
            (
                Ipv4Addr::new(198, 18, 0, 2),
                30,
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                126,
            ),
            1420,
            1,
            4096,
            Duration::from_secs(1),
            Arc::clone(&flow_count),
        )
        .expect("timeout stack");
        assert!(stack.enqueue(&ipv4_tcp(), true));
        stack.poll_quantum(Instant::ZERO);
        assert_eq!(stack.take_output(|_| true), OutputResult::Sent);
        stack.poll_quantum(Instant::from_millis(1_001));
        assert_eq!(stack.live_tcp_flows(), 0, "half-open flow timed out");
        assert_eq!(flow_count.load(Ordering::Acquire), 0);
    }

    #[test]
    fn stack_route_and_quantum_are_exact_and_output_is_foundation_dropped() {
        let (mut stack, _flows) = Stack::new(
            (
                Ipv4Addr::new(198, 18, 0, 2),
                30,
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                126,
            ),
            1420,
            8,
            4096,
            Duration::from_secs(60),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        )
        .expect("bounded stack");
        assert!(stack.has_exact_routes());
        let packet = ipv4_udp();
        for _ in 0..7 {
            assert!(stack.enqueue(&packet, true));
        }
        assert!(
            !stack.enqueue(&packet, true),
            "seven ingress plus one TX slot is the exact eight-slot pool"
        );
        assert_eq!(stack.poll_quantum(Instant::ZERO), 7);
        assert_eq!(stack.pending(), 0);
        assert_eq!(stack.discarded_packets(), 7);

        let valid_foundation_drops = stack.discarded_packets();
        let valid_egress = stack.validated_egress_packets();
        let rejected_egress = stack.rejected_egress_packets();
        stack
            .device
            .transmit(Instant::ZERO)
            .expect("fixed TX slot")
            .consume(1, |output| output[0] = 0);
        assert_eq!(
            stack.discarded_packets(),
            valid_foundation_drops,
            "invalid egress cannot be counted as a validated foundation packet"
        );
        assert_eq!(stack.validated_egress_packets(), valid_egress);
        assert_eq!(stack.rejected_egress_packets(), rejected_egress + 1);
    }

    #[test]
    fn generation_table_is_bounded_and_stale_ids_fail_closed() {
        let mut table = GenerationTable::new(2);
        let first = table.current(0).expect("first slot");
        assert!(table.recycle(first));
        assert!(
            !table.recycle(first),
            "stale generation must not touch reused slot"
        );
        assert!(table.current(2).is_none(), "capacity is exact");

        table.slots[1] = u32::MAX - 1;
        let last = table.current(1).expect("last usable generation");
        assert!(table.recycle(last));
        assert!(
            table.current(1).is_none(),
            "generation exhaustion permanently retires the slot"
        );
        assert!(
            !table.recycle(last),
            "exhaustion cannot resurrect an old ID"
        );
    }

    #[tokio::test]
    async fn owner_cancel_eof_panic_and_cleanup_conflict_are_reaped_before_join() {
        assert_eq!(
            map_owner_spawn::<(), _>(
                Err(std::io::Error::other("injected spawn failure")),
                "startup",
            ),
            Err("startup"),
            "owner spawn failure maps to startup"
        );

        for (cleanup_result, expected) in [
            (Ok::<(), ()>(()), OwnerExit::RuntimeFailed),
            (Err::<(), ()>(()), OwnerExit::CleanupFailed),
        ] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let owner_events = Arc::clone(&events);
            let thread = std::thread::spawn(move || {
                let owner = std::thread::current().id();
                owner_events.lock().expect("events").push(("stack", owner));
                let exit = finish_stack_setup::<(), _, _>(Err(()), (), |_| {
                    owner_events
                        .lock()
                        .expect("events")
                        .push(("cleanup", std::thread::current().id()));
                    cleanup_result
                })
                .expect_err("injected stack setup failure");
                owner_events
                    .lock()
                    .expect("events")
                    .push(("owner-exit", std::thread::current().id()));
                exit
            });
            assert_eq!(thread.join().expect("owner joins"), expected);
            events
                .lock()
                .expect("events")
                .push(("joined", std::thread::current().id()));
            let events = events.lock().expect("events");
            assert_eq!(
                events.iter().map(|event| event.0).collect::<Vec<_>>(),
                ["stack", "cleanup", "owner-exit", "joined"]
            );
            assert_eq!(events[0].1, events[1].1);
            assert_eq!(events[1].1, events[2].1);
            assert_ne!(events[2].1, events[3].1);
        }

        for exit in [OwnerExit::Stopped, OwnerExit::CleanupFailed] {
            let stop = Arc::new(AtomicBool::new(false));
            let active = Arc::new(AtomicBool::new(false));
            let events = Arc::new(Mutex::new(Vec::new()));
            let thread_stop = Arc::clone(&stop);
            let thread_events = Arc::clone(&events);
            let thread = std::thread::spawn(move || {
                while !thread_stop.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                thread_events.lock().expect("events").push("cleanup");
                exit
            });
            let guard = OwnerThread {
                control: OwnerControl {
                    stop,
                    active,
                    admitting: Arc::new(AtomicBool::new(false)),
                    #[cfg(all(windows, target_arch = "x86_64"))]
                    flow_count: Arc::new(AtomicUsize::new(0)),
                },
                #[cfg(all(windows, target_arch = "x86_64"))]
                wake: None,
                thread: Some(thread),
            };

            assert_eq!(guard.reap().await, exit);
            events.lock().expect("events").push("joined");
            assert_eq!(*events.lock().expect("events"), ["cleanup", "joined"]);
        }

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let guard = OwnerThread {
            control: OwnerControl {
                stop,
                active: Arc::new(AtomicBool::new(false)),
                admitting: Arc::new(AtomicBool::new(false)),
                #[cfg(all(windows, target_arch = "x86_64"))]
                flow_count: Arc::new(AtomicUsize::new(0)),
            },
            #[cfg(all(windows, target_arch = "x86_64"))]
            wake: None,
            thread: Some(std::thread::spawn(move || {
                while !thread_stop.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                panic!("injected owner panic")
            })),
        };
        assert_eq!(guard.reap().await, OwnerExit::CleanupFailed);

        let (sender, receiver) = tokio::sync::oneshot::channel();
        drop(sender);
        assert_eq!(
            reported_owner_exit(receiver.await),
            OwnerExit::CleanupFailed,
            "owner EOF is a cleanup failure"
        );
        assert_eq!(
            reconcile_owner_exit(OwnerExit::RuntimeFailed, OwnerExit::Stopped),
            OwnerExit::RuntimeFailed
        );
        assert_eq!(
            reconcile_owner_exit(OwnerExit::RuntimeFailed, OwnerExit::CleanupFailed),
            OwnerExit::CleanupFailed
        );
        assert_eq!(
            reconcile_owner_exit(OwnerExit::Stopped, OwnerExit::Stopped),
            OwnerExit::Stopped
        );
        assert_eq!(
            reconcile_owner_exit(OwnerExit::Stopped, OwnerExit::CleanupFailed),
            OwnerExit::CleanupFailed
        );

        tokio::time::timeout(Duration::from_secs(1), async {})
            .await
            .expect("owner table is bounded");
    }

    #[tokio::test]
    async fn tcp_handler_churn_is_reaped_and_panic_fails_the_required_root() {
        use ferrum2_runtime::{ProcessCause, ProcessRootExit, ProcessSupervisor};

        let (flow_sender, flow_receiver) = tokio::sync::mpsc::channel(2);
        let control = OwnerControl::new();
        let active = Arc::clone(&control.active);
        let owner_control = control.clone();
        let (done_sender, done_receiver) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            while !owner_control.stop.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            let _ = done_sender.send(OwnerExit::Stopped);
            OwnerExit::Stopped
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let root = ferrum2_runtime::ProcessRoot::new(move || async move {
            Ok::<_, &'static str>(TunRoot {
                owner: OwnerThread {
                    control,
                    #[cfg(all(windows, target_arch = "x86_64"))]
                    wake: None,
                    thread: Some(thread),
                },
                done: done_receiver,
                runtime: Some("runtime"),
                cleanup: Some("cleanup"),
                flows: flow_receiver,
                flow_count: Arc::new(AtomicUsize::new(0)),
                handle_tcp: Arc::new(move |flow, _| {
                    let calls = Arc::clone(&handler_calls);
                    Box::pin(async move {
                        drop(flow);
                        if calls.fetch_add(1, Ordering::SeqCst) == 32 {
                            panic!("injected TUN TCP handler panic");
                        }
                    })
                }),
            })
        });
        let supervisor = ProcessSupervisor::new(
            vec![root],
            Duration::from_secs(1),
            ferrum2_runtime::OwnerRegistry::new(),
        )
        .expect("one TUN root");
        let run = tokio::spawn(supervisor.run_until(std::future::pending::<()>()));
        while !active.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        for port in 10_000..10_033 {
            let (flow, _owner) =
                tcp_flow_pair(SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), port)), 4);
            flow_sender.send(flow).await.expect("bounded handler churn");
        }
        let report = run.await.expect("process report");
        assert_eq!(calls.load(Ordering::SeqCst), 33);
        assert!(matches!(
            report.cause(),
            ProcessCause::RootStopped {
                exit: ProcessRootExit::Failed("runtime"),
                ..
            }
        ));
    }
}
