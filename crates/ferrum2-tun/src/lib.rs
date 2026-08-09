#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ferrum2_runtime::{PreparedProcessRoot, ProcessCancellation, ProcessFuture, ProcessRoot};
use smoltcp::iface::{
    Config as InterfaceConfig, Interface, PollIngressSingleResult, Route, SocketSet,
};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address};

const PACKET_QUANTUM: usize = 8;
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
    pub max_udp_mappings: usize,
    pub max_udp_buffered_bytes: usize,
    pub owned_buffer_bytes: u64,
}

/// Builds one required process root around the private owner-thread implementation.
///
/// Error values are supplied by the binary so this deep module does not depend on
/// configuration, policy, DNS, protocol, or observability crates.
pub fn process_root<E, A, D>(
    config: Config,
    startup: E,
    runtime: E,
    cleanup: E,
    accepted: A,
    foundation_dropped: D,
) -> ProcessRoot<E>
where
    E: Copy + Send + 'static,
    A: Fn() + Send + Sync + 'static,
    D: Fn() + Send + Sync + 'static,
{
    ProcessRoot::new_cancellable(move |cancellation| async move {
        if !config_is_exact(&config) {
            return Err(startup);
        }
        prepare(
            config,
            startup,
            runtime,
            cleanup,
            cancellation,
            Box::new(accepted),
            Box::new(foundation_dropped),
        )
        .await
    })
}

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

async fn prepare<E>(
    config: Config,
    startup: E,
    runtime: E,
    cleanup: E,
    mut cancellation: ProcessCancellation,
    accepted: Box<dyn Fn() + Send + Sync>,
    foundation_dropped: Box<dyn Fn() + Send + Sync>,
) -> Result<Option<TunRoot<E>>, E>
where
    E: Copy + Send + 'static,
{
    let timeout = config.ready_timeout;
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(std::time::Instant::now);
    let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
    let (done_sender, done_receiver) = tokio::sync::oneshot::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let active = Arc::new(AtomicBool::new(false));
    let owner_stop = Arc::clone(&stop);
    let owner_active = Arc::clone(&active);
    let thread = std::thread::Builder::new()
        .name("ferrum2-tun-owner".into())
        .spawn(move || {
            let result = owner_main(
                config,
                owner_stop,
                owner_active,
                ready_sender,
                deadline,
                accepted,
                foundation_dropped,
            );
            let _ = done_sender.send(result);
            result
        })
        .map_err(|_| startup)?;
    let mut guard = OwnerThread {
        stop,
        active,
        #[cfg(all(windows, target_arch = "x86_64"))]
        wake: None,
        thread: Some(thread),
    };
    loop {
        if cancellation.is_cancelled() {
            return cancel_prepare(guard, cleanup).await;
        }
        if std::time::Instant::now() >= deadline {
            return Err(prepare_failure(guard, startup, cleanup).await);
        }
        match ready_receiver.try_recv() {
            Ok(OwnerReady::Ready {
                #[cfg(all(windows, target_arch = "x86_64"))]
                wake,
            }) => {
                if std::time::Instant::now() >= deadline {
                    return Err(prepare_failure(guard, startup, cleanup).await);
                }
                #[cfg(all(windows, target_arch = "x86_64"))]
                {
                    guard.wake = Some(wake);
                }
                return Ok(Some(TunRoot {
                    owner: guard,
                    done: done_receiver,
                    runtime: Some(runtime),
                    cleanup: Some(cleanup),
                }));
            }
            Ok(OwnerReady::Failed) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err(prepare_failure(guard, startup, cleanup).await);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return cancel_prepare(guard, cleanup).await;
            }
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
    }
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnerExit {
    Stopped,
    RuntimeFailed,
    CleanupFailed,
}

enum OwnerReady {
    Ready {
        #[cfg(all(windows, target_arch = "x86_64"))]
        wake: ferrum2_wintun::StopSignal,
    },
    Failed,
}

struct OwnerThread {
    stop: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
    #[cfg(all(windows, target_arch = "x86_64"))]
    wake: Option<ferrum2_wintun::StopSignal>,
    thread: Option<std::thread::JoinHandle<OwnerExit>>,
}

impl OwnerThread {
    fn signal(&self) {
        self.stop.store(true, Ordering::Release);
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

struct TunRoot<E> {
    owner: OwnerThread,
    done: tokio::sync::oneshot::Receiver<OwnerExit>,
    runtime: Option<E>,
    cleanup: Option<E>,
}

impl<E> PreparedProcessRoot<E> for TunRoot<E>
where
    E: Send + 'static,
{
    fn activate(&mut self) -> Result<(), E> {
        self.owner.active.store(true, Ordering::Release);
        Ok(())
    }

    fn run(
        mut self: Box<Self>,
        mut cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), E>> {
        Box::pin(async move {
            let reported = tokio::select! {
                result = &mut self.done => reported_owner_exit(result),
                () = cancellation.cancelled() => OwnerExit::Stopped,
            };
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

fn reported_owner_exit(
    result: Result<OwnerExit, tokio::sync::oneshot::error::RecvError>,
) -> OwnerExit {
    result.unwrap_or(OwnerExit::CleanupFailed)
}

fn reconcile_owner_exit(reported: OwnerExit, reaped: OwnerExit) -> OwnerExit {
    if reaped == OwnerExit::CleanupFailed || reported == OwnerExit::Stopped {
        reaped
    } else {
        reported
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn owner_main(
    config: Config,
    stop: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
    ready: std::sync::mpsc::SyncSender<OwnerReady>,
    deadline: std::time::Instant,
    accepted: Box<dyn Fn() + Send + Sync>,
    foundation_dropped: Box<dyn Fn() + Send + Sync>,
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
    let mut adapter = match ferrum2_wintun::Adapter::create(adapter_config, deadline, &stop) {
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
    let mut stack = match Stack::new(
        config.ipv4,
        config.ipv4_prefix,
        config.ipv6,
        config.ipv6_prefix,
        usize::from(config.mtu),
    ) {
        Ok(stack) => stack,
        Err(()) => {
            let _ = ready.send(OwnerReady::Failed);
            return match adapter.cleanup() {
                Ok(()) => OwnerExit::RuntimeFailed,
                Err(_) => OwnerExit::CleanupFailed,
            };
        }
    };
    let _flow_generations = GenerationTable::new(config.max_tcp_flows);
    let _mapping_generations = GenerationTable::new(config.max_udp_mappings);
    if std::time::Instant::now() >= deadline {
        let _ = ready.send(OwnerReady::Failed);
        return match adapter.cleanup() {
            Ok(()) => OwnerExit::RuntimeFailed,
            Err(_) => OwnerExit::CleanupFailed,
        };
    }
    if ready.send(OwnerReady::Ready { wake }).is_err() {
        stop.store(true, Ordering::Release);
    }

    let mut fatal = false;
    while !stop.load(Ordering::Acquire) {
        if !active.load(Ordering::Acquire) {
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
            if stack.enqueue(&received) {
                accepted();
            }
        }
        for _ in 0..stack.poll_quantum() {
            foundation_dropped();
        }
        if fatal {
            break;
        }
        match adapter.wait(Duration::from_millis(50)) {
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

#[cfg(not(all(windows, target_arch = "x86_64")))]
fn owner_main(
    _config: Config,
    _stop: Arc<AtomicBool>,
    _active: Arc<AtomicBool>,
    ready: std::sync::mpsc::SyncSender<OwnerReady>,
    _deadline: std::time::Instant,
    _accepted: Box<dyn Fn() + Send + Sync>,
    _foundation_dropped: Box<dyn Fn() + Send + Sync>,
) -> OwnerExit {
    let _ = ready.send(OwnerReady::Failed);
    OwnerExit::RuntimeFailed
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // Reserved IDs are allocated now; T04/T05 are the first admission users.
struct GenerationId {
    slot: usize,
    generation: u32,
}

struct GenerationTable {
    slots: Box<[u32]>,
}

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
struct PacketValidator {
    mtu: usize,
}

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

fn ipv4_unicast(address: Ipv4Addr) -> bool {
    !address.is_unspecified() && !address.is_multicast() && !address.is_broadcast()
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

struct MemoryDevice {
    ingress: [PacketSlot; INGRESS_SLOTS],
    ingress_head: usize,
    ingress_len: usize,
    output: Box<[u8]>,
    validator: PacketValidator,
    discarded_output: usize,
    rejected_output: usize,
}

impl MemoryDevice {
    fn new(mtu: usize) -> Self {
        Self {
            ingress: std::array::from_fn(|_| PacketSlot {
                len: 0,
                bytes: vec![0_u8; mtu].into_boxed_slice(),
            }),
            ingress_head: 0,
            ingress_len: 0,
            output: vec![0_u8; mtu].into_boxed_slice(),
            validator: PacketValidator::new(mtu),
            discarded_output: 0,
            rejected_output: 0,
        }
    }

    fn enqueue(&mut self, packet: &[u8]) -> bool {
        if self.ingress_len == INGRESS_SLOTS || !self.validator.accepts(packet) {
            return false;
        }
        let tail = (self.ingress_head + self.ingress_len) % INGRESS_SLOTS;
        self.ingress[tail].bytes[..packet.len()].copy_from_slice(packet);
        self.ingress[tail].len = packet.len();
        self.ingress_len += 1;
        true
    }

    fn dequeue_index(&mut self) -> Option<usize> {
        if self.ingress_len == 0 {
            return None;
        }
        let index = self.ingress_head;
        self.ingress_head = (self.ingress_head + 1) % INGRESS_SLOTS;
        self.ingress_len -= 1;
        Some(index)
    }
}

struct PacketSlot {
    len: usize,
    bytes: Box<[u8]>,
}

struct MemoryRx<'a>(&'a PacketSlot);

impl RxToken for MemoryRx<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0.bytes[..self.0.len])
    }
}

struct MemoryTx<'a> {
    validator: PacketValidator,
    discarded_output: &'a mut usize,
    rejected_output: &'a mut usize,
    output: &'a mut [u8],
}

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
        } else {
            *self.rejected_output += 1;
        }
        result
    }
}

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
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(MemoryTx {
            validator: self.validator,
            discarded_output: &mut self.discarded_output,
            rejected_output: &mut self.rejected_output,
            output: &mut self.output,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.validator.mtu;
        capabilities
    }
}

struct Stack {
    interface: Interface,
    sockets: SocketSet<'static>,
    device: MemoryDevice,
    foundation_dropped: usize,
}

impl Stack {
    fn new(
        ipv4: Ipv4Addr,
        ipv4_prefix: u8,
        ipv6: Ipv6Addr,
        ipv6_prefix: u8,
        mtu: usize,
    ) -> Result<Self, ()> {
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
        Ok(Self {
            interface,
            sockets: SocketSet::new(Vec::new()),
            device,
            foundation_dropped: 0,
        })
    }

    fn enqueue(&mut self, packet: &[u8]) -> bool {
        self.device.enqueue(packet)
    }

    fn poll_quantum(&mut self) -> usize {
        let mut processed = 0;
        while processed < PACKET_QUANTUM {
            if matches!(
                self.interface.poll_ingress_single(
                    Instant::from_millis(processed as i64),
                    &mut self.device,
                    &mut self.sockets,
                ),
                PollIngressSingleResult::None
            ) {
                break;
            }
            processed += 1;
        }
        self.foundation_dropped += processed;
        processed
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use smoltcp::phy::{Device, TxToken};
    use smoltcp::time::Instant;

    use super::{
        GenerationTable, MemoryTx, OwnerExit, OwnerThread, PacketValidator, Stack,
        reconcile_owner_exit, reported_owner_exit,
    };

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

    fn assert_ingress_and_egress(name: &str, packet: &[u8], mtu: usize, expected: bool) {
        let validator = PacketValidator::new(mtu);
        assert_eq!(validator.accepts(packet), expected, "ingress {name}");

        let mut accepted = 0;
        let mut rejected = 0;
        let mut output = vec![0_u8; packet.len().max(1)];
        MemoryTx {
            validator,
            discarded_output: &mut accepted,
            rejected_output: &mut rejected,
            output: &mut output,
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
    fn stack_route_and_quantum_are_exact_and_output_is_foundation_dropped() {
        let mut stack = Stack::new(
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
            1420,
        )
        .expect("bounded stack");
        assert!(stack.has_exact_routes());
        let packet = ipv4_udp();
        for _ in 0..7 {
            assert!(stack.enqueue(&packet));
        }
        assert!(
            !stack.enqueue(&packet),
            "seven ingress plus one TX slot is the exact eight-slot pool"
        );
        assert_eq!(stack.poll_quantum(), 7);
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
                stop,
                active,
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
            stop,
            active: Arc::new(AtomicBool::new(false)),
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
}
