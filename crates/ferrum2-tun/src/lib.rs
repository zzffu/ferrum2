#![forbid(unsafe_code)]

#[cfg(test)]
mod owner_harness_tests;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
mod packet;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
mod reassembly;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
mod scheduler;
mod supervisor;
mod tcp;
mod udp;
mod wake;

pub use supervisor::SessionCancellation;
pub use tcp::TcpFlow;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use udp::{Admission as UdpAdmission, InjectOutcome as UdpInjectOutcome, UdpTable};
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use udp::{GenerationId, GenerationTable};
pub use udp::{
    UdpAssociation, UdpCandidate, UdpCommitError, UdpDatagram, UdpFiltering, UdpPeerAuthorization,
    UdpPeerPolicyHandle, UdpPeerReservation, UdpPeerReservationOutcome, UdpResponseSendOutcome,
    UdpResponseSink, UdpTuple,
};
pub use wake::OwnerWake;

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use ferrum2_runtime::{
    OwnerRegistry, PreparedProcessRoot, ProcessCancellation, ProcessFuture, ProcessRoot,
};
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use smoltcp::iface::{
    Config as InterfaceConfig, Interface, PollIngressSingleResult, PollResult, Route, SocketHandle,
    SocketSet,
};
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use smoltcp::socket::tcp::{
    Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
};
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use smoltcp::time::Instant;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address};

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use packet::{
    ControlContext, ControlRateLimiter, Families, IpFamily, LocalControlKind, PacketParser,
    ParsedIpPacket, ParsedPacket, TransportMetadata, internet_checksum as checksum,
    ipv4_directed_broadcast, oversized_ingress_control, write_local_control_error,
};
#[cfg(all(windows, target_arch = "x86_64"))]
use packet::{ipv4_unicast, ipv6_unicast};
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use reassembly::{ReassemblyDropReason, ReassemblyOutcome, ReassemblyTable};
#[cfg(all(windows, target_arch = "x86_64"))]
use scheduler::StepOutcome;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use scheduler::{BudgetOutcome, FairScheduler, WorkStage};
#[cfg(all(windows, target_arch = "x86_64"))]
use supervisor::{NetworkDebounce, RestartBackoff, session_cancellation};

// Unsupported roots type-check bridge callbacks but never own a packet loop.
#[cfg(test)]
const PACKET_QUANTUM: usize = 8;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
const INGRESS_SLOTS: usize = 16;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
const TCP_REAP_QUANTUM: usize = 16;
#[cfg(all(windows, target_arch = "x86_64"))]
const OWNER_WORK_BUDGET: usize = 64;

/// Complete, already-validated construction input for the private TUN owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub adapter_name: Box<str>,
    pub ipv4: Option<(Ipv4Addr, u8)>,
    pub ipv6: Option<(Ipv6Addr, u8)>,
    pub mtu: u16,
    pub ring_capacity: u32,
    pub ready_timeout: Duration,
    pub max_tcp_flows: usize,
    pub tcp_buffer_bytes: usize,
    pub tcp_timeout: Duration,
    pub udp_timeout: Duration,
    pub max_udp_mappings: usize,
    pub udp_filtering: UdpFiltering,
    pub capture_routes: Vec<(IpAddr, u8)>,
    pub physical_endpoints: Vec<SocketAddr>,
    pub default_binder: bool,
    pub ipv4_dns_address: Option<Ipv4Addr>,
    pub ipv6_dns_address: Option<Ipv6Addr>,
}

/// Closed, low-cardinality reasons for rejecting work at the TUN boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunRejectReason {
    InvalidIpVersion,
    FamilyDisabled,
    InvalidIpLength,
    InvalidIpChecksum,
    InvalidExtensionHeader,
    UnsupportedIpProtocol,
    IcmpEchoUnsupported,
    FragmentMalformed,
    FragmentOverlap,
    FragmentTimeout,
    FragmentLimit,
    InvalidTransportLength,
    InvalidTransportChecksum,
    InvalidSource,
    InvalidDestination,
    IngressFull,
    TcpFlowLimit,
    UdpAssociationLimit,
    UdpCandidateTimeout,
    UdpQueueFull,
    UdpResponseFiltered,
    UdpResponseClosed,
    StaleGeneration,
    WintunRingFull,
}

/// Closed, identity-free reasons why one UDP response became terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpResponseDropReason {
    StaleGeneration,
    AssociationClosed,
    QueueFull,
    MalformedResponse,
    Filtered,
    InjectionRejected,
    SessionReset,
    Shutdown,
    OwnerFatal,
}

/// Closed address-family label for redacted TUN diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunIpFamily {
    Ipv4,
    Ipv6,
}

/// Closed diagnostic reasons that require a structured log in addition to metrics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunDiagnosticReason {
    WintunRingFull,
}

/// One redacted event emitted by the TUN owner or a generation-bound bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunEvent {
    PacketAccepted,
    PacketFoundationDropped,
    SessionStarted,
    SessionRestartStarted,
    SessionRestartSucceeded,
    SessionRestartFailed,
    SessionGeneration(u64),
    SessionActive(bool),
    PacketIngress,
    PacketEgress,
    PacketRejected(TunRejectReason),
    InternalEgressBackpressured,
    WintunRingFullDropped,
    TcpFlowsActive(usize),
    TcpFlowRejectedLimit,
    TcpFlowResetRestart,
    TcpBridgeBlocked,
    UdpAssociationsActive(usize),
    UdpCandidatesActive(usize),
    UdpAssociationCreated,
    UdpAssociationRejectedLimit,
    UdpDatagramQueueFull,
    UdpResponseQueueFull,
    UdpResponseFiltered,
    UdpResponseDropped(UdpResponseDropReason),
    UdpPendingResponses(usize),
    UdpStaleGeneration,
    ReassemblyEntriesActive(usize),
    ReassemblyStarted,
    ReassemblyCompleted,
    ReassemblyDroppedOverlap,
    ReassemblyDroppedTimeout,
    ReassemblyDroppedLimit,
    ReassemblyDroppedMalformed,
    NetworkChange,
    UnderlayBindStale,
    Diagnostic {
        reason: TunDiagnosticReason,
        family: TunIpFamily,
    },
}

#[derive(Clone)]
pub(crate) struct TunEventSink {
    emit: Arc<dyn Fn(TunEvent) + Send + Sync>,
}

impl TunEventSink {
    fn new(emit: impl Fn(TunEvent) + Send + Sync + 'static) -> Self {
        Self {
            emit: Arc::new(emit),
        }
    }

    pub(crate) fn emit(&self, event: TunEvent) {
        (self.emit)(event);
    }
}

impl Default for TunEventSink {
    fn default() -> Self {
        Self::new(|_| {})
    }
}

/// Generation-aware bridge from the current private Wintun session to client egress.
#[derive(Clone, Default)]
pub struct UnderlayPublisher {
    #[cfg(all(windows, target_arch = "x86_64"))]
    state: Arc<std::sync::RwLock<UnderlayState>>,
    #[cfg(all(windows, target_arch = "x86_64"))]
    events: Arc<std::sync::RwLock<TunEventSink>>,
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[derive(Default)]
struct UnderlayState {
    generation: u64,
    ready: bool,
    policy: Option<ferrum2_wintun::UnderlayPolicy>,
}

impl UnderlayPublisher {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    fn set_event_sink(&self, events: TunEventSink) {
        if let Ok(mut current) = self.events.write() {
            *current = events;
        }
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    fn emit_stale(&self) {
        if let Ok(events) = self.events.read() {
            events.emit(TunEvent::UnderlayBindStale);
            events.emit(TunEvent::PacketRejected(TunRejectReason::StaleGeneration));
        }
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    fn publish(&self, policy: Option<ferrum2_wintun::UnderlayPolicy>) -> Result<(), ()> {
        let mut state = self.state.write().map_err(|_| ())?;
        state.generation = state.generation.wrapping_add(1).max(1);
        state.ready = policy.is_some();
        state.policy = policy;
        Ok(())
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    fn invalidate(&self) -> Result<(), ()> {
        let mut state = self.state.write().map_err(|_| ())?;
        state.generation = state.generation.wrapping_add(1).max(1);
        state.ready = false;
        state.policy = None;
        Ok(())
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    pub fn bind_fixed<T: std::os::windows::io::AsRawSocket>(
        &self,
        socket: &T,
        endpoint: SocketAddr,
    ) -> Result<(), ferrum2_wintun::Error> {
        let (generation, policy) = self.policy_snapshot()?;
        if let Err(error) = policy.bind_fixed(socket, endpoint) {
            if !policy.generation_is_current() {
                self.emit_stale();
            }
            return Err(error);
        }
        self.require_generation(generation)
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    pub fn bind_target<T: std::os::windows::io::AsRawSocket>(
        &self,
        socket: &T,
        target: SocketAddr,
    ) -> Result<(), ferrum2_wintun::Error> {
        let (generation, policy) = self.policy_snapshot()?;
        if let Err(error) = policy.bind_target(socket, target) {
            if !policy.generation_is_current() {
                self.emit_stale();
            }
            return Err(error);
        }
        self.require_generation(generation)
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    fn policy_snapshot(
        &self,
    ) -> Result<(u64, ferrum2_wintun::UnderlayPolicy), ferrum2_wintun::Error> {
        let state = self.state.read().map_err(|_| {
            ferrum2_wintun::Error::new(ferrum2_wintun::ErrorKind::UnrecoverableCorruption)
        })?;
        if !state.ready {
            drop(state);
            self.emit_stale();
            return Err(ferrum2_wintun::Error::new(
                ferrum2_wintun::ErrorKind::RecoverableSession,
            ));
        }
        Ok((
            state.generation,
            state.policy.clone().ok_or(ferrum2_wintun::Error::new(
                ferrum2_wintun::ErrorKind::UnrecoverableCorruption,
            ))?,
        ))
    }

    #[cfg(all(windows, target_arch = "x86_64"))]
    fn require_generation(&self, generation: u64) -> Result<(), ferrum2_wintun::Error> {
        let state = self.state.read().map_err(|_| {
            ferrum2_wintun::Error::new(ferrum2_wintun::ErrorKind::UnrecoverableCorruption)
        })?;
        if state.ready && state.generation == generation {
            Ok(())
        } else {
            drop(state);
            self.emit_stale();
            Err(ferrum2_wintun::Error::new(
                ferrum2_wintun::ErrorKind::RecoverableSession,
            ))
        }
    }
}

/// Builds one required process root around the private owner-thread implementation.
///
/// Error values are supplied by the binary so this deep module does not depend on
/// configuration, policy, DNS, protocol, or observability crates.
#[cfg(all(windows, target_arch = "x86_64"))]
#[allow(clippy::too_many_arguments)]
pub fn process_root<E, H, U, M>(
    config: Config,
    underlay: UnderlayPublisher,
    startup: E,
    runtime: E,
    cleanup: E,
    registry: OwnerRegistry,
    handle_tcp: H,
    handle_udp: U,
    events: M,
) -> ProcessRoot<E>
where
    E: Copy + Send + 'static,
    H: Fn(TcpFlow, ProcessCancellation, SessionCancellation) -> ProcessFuture<()>
        + Send
        + Sync
        + 'static,
    U: Fn(UdpCandidate, ProcessCancellation, SessionCancellation) -> ProcessFuture<()>
        + Send
        + Sync
        + 'static,
    M: Fn(TunEvent) + Send + Sync + 'static,
{
    ProcessRoot::new_cancellable(move |cancellation| async move {
        if !config_is_exact(&config) {
            return Err(startup);
        }
        let events = TunEventSink::new(events);
        underlay.set_event_sink(events.clone());
        prepare(
            config,
            underlay,
            RootErrors {
                startup,
                runtime,
                cleanup,
            },
            cancellation,
            RootServices {
                registry,
                handle_tcp: Arc::new(handle_tcp),
                handle_udp: Arc::new(handle_udp),
                events,
            },
        )
        .await
    })
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
/// Builds a required root that fails during preparation on unsupported targets.
#[allow(clippy::too_many_arguments)]
pub fn process_root<E, H, U, M>(
    _config: Config,
    _underlay: UnderlayPublisher,
    startup: E,
    _runtime: E,
    _cleanup: E,
    _registry: OwnerRegistry,
    _handle_tcp: H,
    _handle_udp: U,
    _events: M,
) -> ProcessRoot<E>
where
    E: Copy + Send + 'static,
    H: Fn(TcpFlow, ProcessCancellation, SessionCancellation) -> ProcessFuture<()>
        + Send
        + Sync
        + 'static,
    U: Fn(UdpCandidate, ProcessCancellation, SessionCancellation) -> ProcessFuture<()>
        + Send
        + Sync
        + 'static,
    M: Fn(TunEvent) + Send + Sync + 'static,
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
struct RootServices {
    registry: OwnerRegistry,
    handle_tcp: TcpHandler,
    handle_udp: UdpHandler,
    events: TunEventSink,
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn config_is_exact(config: &Config) -> bool {
    if config.adapter_name.is_empty()
        || config.adapter_name.encode_utf16().count() >= 128
        || config.adapter_name.chars().any(char::is_control)
        || (config.ipv4.is_none() && config.ipv6.is_none())
        || config
            .ipv4
            .is_some_and(|address| !valid_ipv4_interface(address))
        || config
            .ipv6
            .is_some_and(|address| !valid_ipv6_interface(address))
        || !(1280..=1500).contains(&config.mtu)
        || !(131_072..=67_108_864).contains(&config.ring_capacity)
        || !config.ring_capacity.is_power_of_two()
        || !(Duration::from_secs(1)..=Duration::from_secs(60)).contains(&config.ready_timeout)
        || !(1..=4096).contains(&config.max_tcp_flows)
        || !(4096..=262_144).contains(&config.tcp_buffer_bytes)
        || !(Duration::from_secs(1)..=Duration::from_secs(86_400)).contains(&config.tcp_timeout)
        || !(ferrum2_runtime::MIN_UDP_IDLE_TIMEOUT..=ferrum2_runtime::MAX_UDP_IDLE_TIMEOUT)
            .contains(&config.udp_timeout)
        || !(1..=8192).contains(&config.max_udp_mappings)
        || config.capture_routes.len() > 256
        || config.physical_endpoints.len() > 256
        || !valid_ipv4_dns(config.ipv4_dns_address, config.ipv4)
        || !valid_ipv6_dns(config.ipv6_dns_address, config.ipv6)
        || config
            .capture_routes
            .iter()
            .any(|route| !valid_capture_route(*route, config.ipv4.is_some(), config.ipv6.is_some()))
        || config.physical_endpoints.iter().any(|endpoint| {
            endpoint.port() == 0
                || match endpoint.ip() {
                    IpAddr::V4(address) => !ipv4_unicast(address),
                    IpAddr::V6(address) => !ipv6_unicast(address),
                }
        })
    {
        return false;
    }
    true
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn valid_ipv4_interface((address, prefix): (Ipv4Addr, u8)) -> bool {
    if prefix > 32 || !ipv4_unicast(address) {
        return false;
    }
    let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
    let numeric = u32::from(address);
    let network = numeric & mask;
    numeric != network && numeric != network | !mask
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn valid_ipv6_interface((address, prefix): (Ipv6Addr, u8)) -> bool {
    if prefix > 128 || !ipv6_unicast(address) {
        return false;
    }
    let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
    let numeric = u128::from(address);
    numeric != numeric & mask
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn valid_ipv4_dns(address: Option<Ipv4Addr>, interface: Option<(Ipv4Addr, u8)>) -> bool {
    let Some(address) = address else {
        return true;
    };
    let Some((interface, prefix)) = interface else {
        return false;
    };
    let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
    let numeric = u32::from(address);
    let network = u32::from(interface) & mask;
    ipv4_unicast(address)
        && numeric & mask == network
        && numeric != u32::from(interface)
        && numeric != network
        && numeric != network | !mask
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn valid_ipv6_dns(address: Option<Ipv6Addr>, interface: Option<(Ipv6Addr, u8)>) -> bool {
    let Some(address) = address else {
        return true;
    };
    let Some((interface, prefix)) = interface else {
        return false;
    };
    let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
    let numeric = u128::from(address);
    ipv6_unicast(address)
        && numeric & mask == u128::from(interface) & mask
        && address != interface
        && numeric != numeric & mask
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn valid_capture_route(
    (address, prefix): (IpAddr, u8),
    ipv4_enabled: bool,
    ipv6_enabled: bool,
) -> bool {
    match address {
        IpAddr::V4(address) => {
            let mask = u32::MAX
                .checked_shl(u32::from(32_u8.saturating_sub(prefix)))
                .unwrap_or(0);
            ipv4_enabled
                && (1..=32).contains(&prefix)
                && u32::from(address) & mask == u32::from(address)
        }
        IpAddr::V6(address) => {
            let mask = u128::MAX
                .checked_shl(u32::from(128_u8.saturating_sub(prefix)))
                .unwrap_or(0);
            ipv6_enabled
                && (1..=128).contains(&prefix)
                && u128::from(address) & mask == u128::from(address)
        }
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
const fn map_packet_reject(reason: packet::PacketRejectReason) -> TunRejectReason {
    match reason {
        packet::PacketRejectReason::Empty | packet::PacketRejectReason::InvalidVersion => {
            TunRejectReason::InvalidIpVersion
        }
        packet::PacketRejectReason::DisabledFamily => TunRejectReason::FamilyDisabled,
        packet::PacketRejectReason::InvalidLength
        | packet::PacketRejectReason::JumbogramUnsupported => TunRejectReason::InvalidIpLength,
        packet::PacketRejectReason::InvalidHeaderChecksum => TunRejectReason::InvalidIpChecksum,
        packet::PacketRejectReason::InvalidSource => TunRejectReason::InvalidSource,
        packet::PacketRejectReason::InvalidDestination => TunRejectReason::InvalidDestination,
        packet::PacketRejectReason::InvalidIpv4Options
        | packet::PacketRejectReason::SourceRouteOption
        | packet::PacketRejectReason::ExtensionLimit
        | packet::PacketRejectReason::MalformedExtension => TunRejectReason::InvalidExtensionHeader,
        packet::PacketRejectReason::InvalidFragment => TunRejectReason::FragmentMalformed,
        packet::PacketRejectReason::UnsupportedProtocol => TunRejectReason::UnsupportedIpProtocol,
        packet::PacketRejectReason::IcmpEchoUnsupported => TunRejectReason::IcmpEchoUnsupported,
        packet::PacketRejectReason::InvalidTransport => TunRejectReason::InvalidTransportLength,
        packet::PacketRejectReason::InvalidTransportChecksum => {
            TunRejectReason::InvalidTransportChecksum
        }
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
async fn prepare<E>(
    config: Config,
    underlay: UnderlayPublisher,
    errors: RootErrors<E>,
    mut cancellation: ProcessCancellation,
    services: RootServices,
) -> Result<Option<TunRoot<E>>, E>
where
    E: Copy + Send + 'static,
{
    let RootServices {
        registry,
        handle_tcp,
        handle_udp,
        events,
    } = services;
    let timeout = config.ready_timeout;
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(std::time::Instant::now);
    let max_udp_associations = config.max_udp_mappings;
    let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
    let (flow_sender, flows) = tokio::sync::mpsc::channel(config.max_tcp_flows);
    let (datagram_sender, datagrams) = tokio::sync::mpsc::channel(max_udp_associations);
    let (done_sender, _done_receiver) = tokio::sync::oneshot::channel();
    let control = OwnerControl::new();
    let owner_control = control.clone();
    let owner_registry = registry.clone();
    let thread = map_owner_spawn(
        std::thread::Builder::new()
            .name("ferrum2-tun-owner".into())
            .spawn(move || {
                let result = owner_main(
                    config,
                    owner_control,
                    deadline,
                    OwnerSessionServices {
                        ready: ready_sender,
                        registry: owner_registry,
                        events,
                        underlay,
                        flow_output: flow_sender,
                        datagram_output: datagram_sender,
                        max_udp_associations,
                    },
                );
                let _ = done_sender.send(result);
                result
            }),
        errors.startup,
    )?;
    let guard = OwnerThread {
        control: control.clone(),
        work: OwnerWake::default(),
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
            Ok(OwnerReady::Ready { work }) => {
                if std::time::Instant::now() >= deadline {
                    return Err(prepare_failure(guard, errors.startup, errors.cleanup).await);
                }
                guard.work = work;
                return Ok(Some(TunRoot {
                    owner: guard,
                    done: _done_receiver,
                    runtime: Some(errors.runtime),
                    cleanup: Some(errors.cleanup),
                    flows,
                    datagrams,
                    flow_count: control.flow_count,
                    association_count: control.association_count,
                    registry,
                    handle_tcp,
                    handle_udp,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdapterErrorDisposition {
    RestartSession,
    RuntimeFailed,
    CleanupFailed,
}

#[cfg(all(windows, target_arch = "x86_64"))]
const fn classify_adapter_error(error: ferrum2_wintun::Error) -> AdapterErrorDisposition {
    match error.kind() {
        ferrum2_wintun::ErrorKind::RecoverableSession => AdapterErrorDisposition::RestartSession,
        ferrum2_wintun::ErrorKind::Cleanup => AdapterErrorDisposition::CleanupFailed,
        ferrum2_wintun::ErrorKind::InvalidInput
        | ferrum2_wintun::ErrorKind::UnrecoverableCorruption => {
            AdapterErrorDisposition::RuntimeFailed
        }
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
enum OwnerReady {
    Ready { work: OwnerWake },
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
    flow_count: Arc<AtomicUsize>,
    association_count: Arc<AtomicUsize>,
    registry: OwnerRegistry,
    handle_tcp: TcpHandler,
    handle_udp: UdpHandler,
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
    events: TunEventSink,
    underlay: UnderlayPublisher,
    flow_output: tokio::sync::mpsc::Sender<SessionItem<TcpFlow>>,
    datagram_output: tokio::sync::mpsc::Sender<SessionItem<UdpCandidate>>,
    max_udp_associations: usize,
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn packet_ip_family(packet: &[u8]) -> Option<TunIpFamily> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => Some(TunIpFamily::Ipv4),
        Some(6) => Some(TunIpFamily::Ipv6),
        _ => None,
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
const MANAGED_DNS_AUDIT_MILLIS: i64 = 5_000;

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
fn bounded_network_wait(
    base: Duration,
    now_millis: i64,
    debounce_deadline: Option<i64>,
    audit_deadline: Option<i64>,
) -> Duration {
    let deadline = [debounce_deadline, audit_deadline]
        .into_iter()
        .flatten()
        .min();
    let Some(deadline) = deadline else {
        return base;
    };
    let millis = u64::try_from(deadline.saturating_sub(now_millis).max(0)).unwrap_or(u64::MAX);
    base.min(Duration::from_millis(millis))
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
fn owner_wait_after_budget(budget: BudgetOutcome, bounded_wait: Duration) -> Duration {
    if budget.budget_exhausted {
        Duration::ZERO
    } else {
        bounded_wait
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn semantic_network_change_requires_restart(
    adapter: &mut ferrum2_wintun::Adapter,
    events: &TunEventSink,
) -> Result<bool, AdapterErrorDisposition> {
    match adapter.revalidate_network_change() {
        Ok(ferrum2_wintun::NetworkChangeOutcome::Unchanged) => Ok(false),
        Ok(
            ferrum2_wintun::NetworkChangeOutcome::Changed
            | ferrum2_wintun::NetworkChangeOutcome::ManagedStateDamaged(_),
        ) => {
            events.emit(TunEvent::NetworkChange);
            Ok(true)
        }
        Err(error) => {
            events.emit(TunEvent::NetworkChange);
            Err(classify_adapter_error(error))
        }
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn owner_main(
    config: Config,
    control: OwnerControl,
    initial_deadline: std::time::Instant,
    services: OwnerSessionServices,
) -> OwnerExit {
    let OwnerSessionServices {
        ready,
        registry,
        events,
        underlay,
        flow_output,
        datagram_output,
        max_udp_associations,
    } = services;
    let adapter_config = match build_adapter_config(&config) {
        Ok(adapter) => adapter,
        Err(_) => {
            let _ = ready.send(OwnerReady::Failed);
            return OwnerExit::RuntimeFailed;
        }
    };
    let current_work = Arc::new(std::sync::Mutex::new(None::<ferrum2_wintun::WorkSignal>));
    let signalled_work = Arc::clone(&current_work);
    let owner_thread = std::thread::current();
    let owner_wake = OwnerWake::new(move || {
        if let Ok(work) = signalled_work.lock()
            && let Some(work) = work.as_ref()
        {
            let _ = work.signal();
        }
        owner_thread.unpark();
    });
    let mut ready = Some(ready);
    let mut generation = 0_u64;
    let mut backoff = RestartBackoff::default();
    let supervisor_origin = std::time::Instant::now();
    let mut debounce = NetworkDebounce::default();
    let mut retry_delay = None;

    loop {
        if control.stop.load(Ordering::Acquire) || control.shutdown.load(Ordering::Acquire) {
            let _ = underlay.invalidate();
            return OwnerExit::Stopped;
        }
        if let Some(delay) = retry_delay.take()
            && !wait_owner_delay(&control, delay)
        {
            let _ = underlay.invalidate();
            return OwnerExit::Stopped;
        }
        let first_session = ready.is_some();
        if !first_session {
            events.emit(TunEvent::SessionRestartStarted);
        }
        let deadline = if first_session {
            initial_deadline
        } else {
            std::time::Instant::now()
                .checked_add(config.ready_timeout)
                .unwrap_or_else(std::time::Instant::now)
        };
        let mut adapter = match ferrum2_wintun::Adapter::create(
            adapter_config.clone(),
            deadline,
            &control.stop,
        ) {
            Ok(adapter) => adapter,
            Err(error) => {
                if control.stop.load(Ordering::Acquire) || control.shutdown.load(Ordering::Acquire)
                {
                    let _ = underlay.invalidate();
                    return OwnerExit::Stopped;
                }
                if error.is_cleanup_failure() {
                    if !first_session {
                        events.emit(TunEvent::SessionRestartFailed);
                    }
                    if let Some(ready) = ready.take() {
                        let _ = ready.send(OwnerReady::Failed);
                    }
                    return OwnerExit::CleanupFailed;
                }
                if first_session {
                    let now = std::time::Instant::now();
                    if now < initial_deadline {
                        retry_delay = Some(
                            backoff
                                .next_delay()
                                .min(initial_deadline.saturating_duration_since(now)),
                        );
                        continue;
                    }
                }
                if let Some(ready) = ready.take() {
                    let _ = ready.send(OwnerReady::Failed);
                    return OwnerExit::RuntimeFailed;
                }
                events.emit(TunEvent::SessionRestartFailed);
                retry_delay = Some(backoff.next_delay());
                continue;
            }
        };
        if let Ok(mut work) = current_work.lock() {
            *work = Some(adapter.work_signal());
        } else {
            if let Some(ready) = ready.take() {
                let _ = ready.send(OwnerReady::Failed);
            }
            return match adapter.cleanup() {
                Ok(()) => OwnerExit::RuntimeFailed,
                Err(_) => OwnerExit::CleanupFailed,
            };
        }

        generation = generation.wrapping_add(1).max(1);
        let (session_cancel_handle, session_cancel) =
            session_cancellation(generation, owner_wake.clone());
        debug_assert_eq!(session_cancel_handle.generation(), generation);
        let stack = Stack::new_with_udp(
            (config.ipv4, config.ipv6),
            usize::from(config.mtu),
            config.max_tcp_flows,
            config.tcp_buffer_bytes,
            config.tcp_timeout,
            Arc::clone(&control.flow_count),
            registry.clone(),
            max_udp_associations,
            config.udp_timeout,
            config.udp_filtering,
            generation,
            owner_wake.clone(),
        );
        let (mut stack, mut flows, mut datagrams) = match stack {
            Ok(ready_stack) => ready_stack,
            Err(()) => {
                session_cancel_handle.cancel();
                if let Ok(mut work) = current_work.lock() {
                    *work = None;
                }
                let cleanup = adapter.cleanup();
                if cleanup.is_err() {
                    if let Some(ready) = ready.take() {
                        let _ = ready.send(OwnerReady::Failed);
                    }
                    return OwnerExit::CleanupFailed;
                }
                if let Some(ready) = ready.take() {
                    let _ = ready.send(OwnerReady::Failed);
                    return OwnerExit::RuntimeFailed;
                }
                events.emit(TunEvent::SessionRestartFailed);
                retry_delay = Some(backoff.next_delay());
                continue;
            }
        };
        stack.set_event_sink(events.clone());
        if first_session && std::time::Instant::now() >= initial_deadline {
            session_cancel_handle.cancel();
            stack.quiesce(
                generation.wrapping_add(1).max(1),
                UdpResponseDropReason::OwnerFatal,
            );
            if let Ok(mut work) = current_work.lock() {
                *work = None;
            }
            let cleanup = adapter.cleanup();
            if let Some(ready) = ready.take() {
                let _ = ready.send(OwnerReady::Failed);
            }
            return if cleanup.is_err() {
                OwnerExit::CleanupFailed
            } else {
                OwnerExit::RuntimeFailed
            };
        }
        if adapter.managed_health() != Ok(ferrum2_wintun::ManagedTunHealth::Healthy) {
            session_cancel_handle.cancel();
            stack.quiesce(
                generation.wrapping_add(1).max(1),
                UdpResponseDropReason::SessionReset,
            );
            if let Ok(mut work) = current_work.lock() {
                *work = None;
            }
            let cleanup = adapter.cleanup();
            if cleanup.is_err() {
                if let Some(ready) = ready.take() {
                    let _ = ready.send(OwnerReady::Failed);
                }
                return OwnerExit::CleanupFailed;
            }
            if ready.is_some() {
                let now = std::time::Instant::now();
                if now < initial_deadline {
                    retry_delay = Some(
                        backoff
                            .next_delay()
                            .min(initial_deadline.saturating_duration_since(now)),
                    );
                    continue;
                }
            }
            if let Some(ready) = ready.take() {
                let _ = ready.send(OwnerReady::Failed);
                return OwnerExit::RuntimeFailed;
            }
            events.emit(TunEvent::SessionRestartFailed);
            retry_delay = Some(backoff.next_delay());
            continue;
        }
        if underlay.publish(adapter.underlay_policy()).is_err() {
            session_cancel_handle.cancel();
            stack.quiesce(
                generation.wrapping_add(1).max(1),
                UdpResponseDropReason::OwnerFatal,
            );
            if let Ok(mut work) = current_work.lock() {
                *work = None;
            }
            let cleanup = adapter.cleanup();
            if let Some(ready) = ready.take() {
                let _ = ready.send(OwnerReady::Failed);
            }
            return if cleanup.is_err() {
                OwnerExit::CleanupFailed
            } else {
                OwnerExit::RuntimeFailed
            };
        }
        events.emit(TunEvent::SessionGeneration(generation));
        events.emit(TunEvent::SessionActive(true));
        if first_session {
            events.emit(TunEvent::SessionStarted);
        } else {
            events.emit(TunEvent::SessionRestartSucceeded);
        }
        if let Some(sender) = ready.take()
            && sender
                .send(OwnerReady::Ready {
                    work: owner_wake.clone(),
                })
                .is_err()
        {
            control.stop.store(true, Ordering::Release);
        }
        control.admitting.store(
            control.active.load(Ordering::Acquire)
                && !control.shutdown.load(Ordering::Acquire)
                && !control.stop.load(Ordering::Acquire),
            Ordering::Release,
        );

        let mut pending_flow = None;
        let mut pending_datagram = None;
        let mut scheduler = FairScheduler::default();
        let clock_origin = std::time::Instant::now();
        let session_started = std::time::Instant::now();
        let audit_dns = config.ipv4_dns_address.is_some() || config.ipv6_dns_address.is_some();
        let mut next_dns_audit = audit_dns.then(|| {
            i64::try_from(supervisor_origin.elapsed().as_millis())
                .unwrap_or(i64::MAX)
                .saturating_add(MANAGED_DNS_AUDIT_MILLIS)
        });
        let mut raw_notification_generation = 0_u64;
        debounce.clear();
        let mut restart = false;
        let mut terminal_exit = None;
        'session: while !control.stop.load(Ordering::Acquire) {
            let supervisor_now =
                i64::try_from(supervisor_origin.elapsed().as_millis()).unwrap_or(i64::MAX);
            let debounced = debounce.take_ready(supervisor_now).is_some();
            let periodic_audit = !debounced
                && debounce.deadline_millis().is_none()
                && next_dns_audit.is_some_and(|deadline| supervisor_now >= deadline);
            if debounced || periodic_audit {
                if audit_dns {
                    next_dns_audit = Some(supervisor_now.saturating_add(MANAGED_DNS_AUDIT_MILLIS));
                }
                match semantic_network_change_requires_restart(&mut adapter, &events) {
                    Ok(false) => {}
                    Ok(true) | Err(AdapterErrorDisposition::RestartSession) => {
                        restart = true;
                        break;
                    }
                    Err(AdapterErrorDisposition::RuntimeFailed) => {
                        terminal_exit = Some(OwnerExit::RuntimeFailed);
                        break;
                    }
                    Err(AdapterErrorDisposition::CleanupFailed) => {
                        terminal_exit = Some(OwnerExit::CleanupFailed);
                        break;
                    }
                }
            }
            if !control.active.load(Ordering::Acquire) {
                let debounce_deadline = debounce.deadline_millis();
                let audit_deadline = next_dns_audit.filter(|_| debounce_deadline.is_none());
                let wait = bounded_network_wait(
                    Duration::from_millis(u64::from(u32::MAX - 1)),
                    supervisor_now,
                    debounce_deadline,
                    audit_deadline,
                );
                match adapter.wait(wait) {
                    Ok(
                        ferrum2_wintun::WaitOutcome::Stop
                        | ferrum2_wintun::WaitOutcome::Work
                        | ferrum2_wintun::WaitOutcome::Readable
                        | ferrum2_wintun::WaitOutcome::Timeout,
                    ) => {}
                    Ok(ferrum2_wintun::WaitOutcome::NetworkChanged) => {
                        raw_notification_generation =
                            raw_notification_generation.wrapping_add(1).max(1);
                        let observed_at = i64::try_from(supervisor_origin.elapsed().as_millis())
                            .unwrap_or(i64::MAX);
                        debounce.observe(raw_notification_generation, observed_at);
                    }
                    Err(error) => {
                        match classify_adapter_error(error) {
                            AdapterErrorDisposition::RestartSession => restart = true,
                            AdapterErrorDisposition::RuntimeFailed => {
                                terminal_exit = Some(OwnerExit::RuntimeFailed);
                            }
                            AdapterErrorDisposition::CleanupFailed => {
                                terminal_exit = Some(OwnerExit::CleanupFailed);
                            }
                        }
                        break;
                    }
                }
                continue;
            }
            let elapsed = i64::try_from(clock_origin.elapsed().as_millis()).unwrap_or(i64::MAX);
            let admitting = control.admitting.load(Ordering::Acquire);
            let mut adapter_failure = None;
            let budget = scheduler.run_budget(OWNER_WORK_BUDGET, |stage| match stage {
                WorkStage::Control => {
                    let forwarded_flow = forward_session_item(
                        &mut flows,
                        &mut pending_flow,
                        &flow_output,
                        &session_cancel,
                    );
                    let forwarded_datagram = forward_session_item(
                        &mut datagrams,
                        &mut pending_datagram,
                        &datagram_output,
                        &session_cancel,
                    );
                    StepOutcome::from_work(
                        forwarded_flow
                            || forwarded_datagram
                            || stack.process_one_udp_control(elapsed, admitting),
                    )
                }
                WorkStage::FlushOutput => {
                    match stack.flush_output(|packet| match adapter.send(packet) {
                        Ok(ferrum2_wintun::SendOutcome::Sent) => {
                            events.emit(TunEvent::PacketEgress);
                            OutputSendOutcome::Sent
                        }
                        Ok(ferrum2_wintun::SendOutcome::DroppedRingFull) => {
                            events.emit(TunEvent::WintunRingFullDropped);
                            events.emit(TunEvent::PacketRejected(TunRejectReason::WintunRingFull));
                            if let Some(family) = packet_ip_family(packet) {
                                events.emit(TunEvent::Diagnostic {
                                    reason: TunDiagnosticReason::WintunRingFull,
                                    family,
                                });
                            }
                            OutputSendOutcome::DroppedRingFull
                        }
                        Err(error) => {
                            adapter_failure = Some(classify_adapter_error(error));
                            OutputSendOutcome::Fatal
                        }
                    }) {
                        OutputFlushOutcome::Empty => StepOutcome::Idle,
                        OutputFlushOutcome::Sent | OutputFlushOutcome::DroppedRingFull => {
                            StepOutcome::Worked
                        }
                        OutputFlushOutcome::Fatal => StepOutcome::Fatal,
                    }
                }
                WorkStage::Stack => {
                    let outcome = stack.poll_stack_once(Instant::from_millis(elapsed));
                    for _ in 0..outcome.foundation_dropped {
                        events.emit(TunEvent::PacketFoundationDropped);
                    }
                    StepOutcome::from_work(outcome.worked)
                }
                WorkStage::Receive if stack.ingress_available() != 0 => {
                    let received = match adapter.receive() {
                        Ok(Some(packet)) => packet,
                        Ok(None) => return StepOutcome::Idle,
                        Err(error) => {
                            adapter_failure = Some(classify_adapter_error(error));
                            return StepOutcome::Fatal;
                        }
                    };
                    events.emit(TunEvent::PacketIngress);
                    let accepted = stack.enqueue_at(&received, admitting, elapsed);
                    if accepted {
                        events.emit(TunEvent::PacketAccepted);
                    }
                    StepOutcome::Worked
                }
                WorkStage::Receive => StepOutcome::Idle,
                WorkStage::UdpResponse => match stack.process_one_udp_response(elapsed) {
                    udp::ResponseProcessOutcome::Idle => StepOutcome::Idle,
                    udp::ResponseProcessOutcome::Deferred => {
                        events.emit(TunEvent::InternalEgressBackpressured);
                        StepOutcome::Worked
                    }
                    udp::ResponseProcessOutcome::Injected
                    | udp::ResponseProcessOutcome::Dropped(_) => StepOutcome::Worked,
                },
                WorkStage::Expire => StepOutcome::from_work(stack.expire_deadlines(elapsed)),
            });
            if budget.fatal {
                match adapter_failure.unwrap_or(AdapterErrorDisposition::RuntimeFailed) {
                    AdapterErrorDisposition::RestartSession => restart = true,
                    AdapterErrorDisposition::RuntimeFailed => {
                        terminal_exit = Some(OwnerExit::RuntimeFailed);
                    }
                    AdapterErrorDisposition::CleanupFailed => {
                        terminal_exit = Some(OwnerExit::CleanupFailed);
                    }
                }
                break 'session;
            }
            control
                .association_count
                .store(stack.live_udp_associations(), Ordering::Release);
            let debounce_deadline = debounce.deadline_millis();
            let audit_deadline = next_dns_audit.filter(|_| debounce_deadline.is_none());
            let wait = owner_wait_after_budget(
                budget,
                bounded_network_wait(
                    stack.next_wait_duration(elapsed),
                    supervisor_now,
                    debounce_deadline,
                    audit_deadline,
                ),
            );
            match adapter.wait(wait) {
                Ok(
                    ferrum2_wintun::WaitOutcome::Stop
                    | ferrum2_wintun::WaitOutcome::Readable
                    | ferrum2_wintun::WaitOutcome::Work
                    | ferrum2_wintun::WaitOutcome::Timeout,
                ) => {}
                Ok(ferrum2_wintun::WaitOutcome::NetworkChanged) => {
                    raw_notification_generation =
                        raw_notification_generation.wrapping_add(1).max(1);
                    let observed_at =
                        i64::try_from(supervisor_origin.elapsed().as_millis()).unwrap_or(i64::MAX);
                    debounce.observe(raw_notification_generation, observed_at);
                }
                Err(error) => {
                    match classify_adapter_error(error) {
                        AdapterErrorDisposition::RestartSession => restart = true,
                        AdapterErrorDisposition::RuntimeFailed => {
                            terminal_exit = Some(OwnerExit::RuntimeFailed);
                        }
                        AdapterErrorDisposition::CleanupFailed => {
                            terminal_exit = Some(OwnerExit::CleanupFailed);
                        }
                    }
                    break;
                }
            }
        }

        control.admitting.store(false, Ordering::Release);
        events.emit(TunEvent::SessionActive(false));
        let underlay_failed = underlay.invalidate().is_err();
        session_cancel_handle.cancel();
        let response_drop_reason = if terminal_exit.is_some() || underlay_failed {
            UdpResponseDropReason::OwnerFatal
        } else if restart {
            UdpResponseDropReason::SessionReset
        } else {
            UdpResponseDropReason::Shutdown
        };
        stack.quiesce(generation.wrapping_add(1).max(1), response_drop_reason);
        control.association_count.store(0, Ordering::Release);
        drop(pending_flow);
        drop(pending_datagram);
        drop(flows);
        drop(datagrams);
        drop(stack);
        if let Ok(mut work) = current_work.lock() {
            *work = None;
        }
        let cleanup = adapter.cleanup();
        if cleanup.is_err() {
            return OwnerExit::CleanupFailed;
        }
        if underlay_failed {
            return OwnerExit::RuntimeFailed;
        }
        if let Some(exit) = terminal_exit {
            return exit;
        }
        if control.stop.load(Ordering::Acquire)
            || control.shutdown.load(Ordering::Acquire)
            || !restart
        {
            return OwnerExit::Stopped;
        }
        if session_started.elapsed() >= Duration::from_secs(5) {
            backoff.reset();
        }
        let delay = backoff.next_delay();
        debounce.clear();
        retry_delay = Some(delay);
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn build_adapter_config(
    config: &Config,
) -> Result<ferrum2_wintun::AdapterConfig, ferrum2_wintun::Error> {
    let ipv4 = config
        .ipv4
        .map(|(address, prefix)| ferrum2_wintun::Ipv4Prefix::new(address, prefix))
        .transpose()?;
    let ipv6 = config
        .ipv6
        .map(|(address, prefix)| ferrum2_wintun::Ipv6Prefix::new(address, prefix))
        .transpose()?;
    let adapter = ferrum2_wintun::AdapterConfig::new(
        config.adapter_name.clone(),
        ipv4,
        ipv6,
        config.mtu,
        config.ring_capacity,
        config.ready_timeout,
    )?;
    if config.capture_routes.is_empty()
        && config.physical_endpoints.is_empty()
        && !config.default_binder
        && config.ipv4_dns_address.is_none()
        && config.ipv6_dns_address.is_none()
    {
        return Ok(adapter);
    }
    let routes =
        config
            .capture_routes
            .iter()
            .map(|(address, length)| match address {
                IpAddr::V4(address) => ferrum2_wintun::Ipv4Prefix::new(*address, *length)
                    .map(ferrum2_wintun::IpPrefix::V4),
                IpAddr::V6(address) => ferrum2_wintun::Ipv6Prefix::new(*address, *length)
                    .map(ferrum2_wintun::IpPrefix::V6),
            })
            .collect::<Result<Vec<_>, _>>()?;
    let managed = ferrum2_wintun::ManagedNetworkConfig::new(
        routes,
        config.physical_endpoints.clone(),
        config.default_binder,
        config.ipv4_dns_address,
        config.ipv6_dns_address,
    )?;
    adapter.with_managed_network(managed)
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn wait_owner_delay(control: &OwnerControl, delay: Duration) -> bool {
    let deadline = std::time::Instant::now()
        .checked_add(delay)
        .unwrap_or_else(std::time::Instant::now);
    loop {
        if control.stop.load(Ordering::Acquire) || control.shutdown.load(Ordering::Acquire) {
            return false;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return true;
        }
        std::thread::park_timeout(deadline.saturating_duration_since(now));
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn forward_session_item<T>(
    input: &mut tokio::sync::mpsc::Receiver<T>,
    pending: &mut Option<T>,
    output: &tokio::sync::mpsc::Sender<SessionItem<T>>,
    cancellation: &SessionCancellation,
) -> bool {
    if pending.is_none() {
        match input.try_recv() {
            Ok(value) => *pending = Some(value),
            Err(
                tokio::sync::mpsc::error::TryRecvError::Empty
                | tokio::sync::mpsc::error::TryRecvError::Disconnected,
            ) => return false,
        }
    }
    let value = pending.take().expect("pending session item");
    match output.try_send(SessionItem {
        value,
        cancellation: cancellation.clone(),
    }) {
        Ok(()) => true,
        Err(tokio::sync::mpsc::error::TrySendError::Full(item)) => {
            *pending = Some(item.value);
            false
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => true,
    }
}

#[derive(Clone, Copy)]
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
struct PacketValidator {
    mtu: usize,
    parser: PacketParser,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl PacketValidator {
    #[cfg(test)]
    const fn new(mtu: usize) -> Self {
        Self::with_families(mtu, Families::DUAL)
    }

    const fn with_families(mtu: usize, families: Families) -> Self {
        Self {
            mtu,
            parser: PacketParser::new(families),
        }
    }

    fn accepts(self, packet: &[u8]) -> bool {
        packet.len() <= self.mtu
            && matches!(self.parser.parse(packet), Ok(ParsedPacket::Complete(_)))
    }

    fn parse_ingress(self, packet: &[u8]) -> packet::ParseResult {
        self.parser.parse(packet)
    }

    fn parse_reassembled(self, packet: &[u8]) -> packet::ParseResult {
        self.parser.parse_reassembled(packet)
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[cfg(test)]
fn udp_datagram(packet: &[u8], mtu: usize) -> Option<(UdpTuple, &[u8], usize)> {
    let ParsedPacket::Complete(parsed) = PacketParser::new(Families::DUAL).parse(packet).ok()?
    else {
        return None;
    };
    udp_datagram_from_parsed(packet, parsed, mtu)
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
fn udp_datagram_from_parsed(
    packet: &[u8],
    parsed: ParsedIpPacket,
    mtu: usize,
) -> Option<(UdpTuple, &[u8], usize)> {
    let TransportMetadata::Udp(udp) = parsed.transport else {
        return None;
    };
    let payload_bound = match parsed.family {
        IpFamily::Ipv4 => mtu.checked_sub(28)?,
        IpFamily::Ipv6 => mtu.checked_sub(48)?,
    };
    Some((
        UdpTuple::new(
            SocketAddr::new(parsed.source, udp.source_port),
            SocketAddr::new(parsed.destination, udp.destination_port),
        ),
        packet.get(udp.payload_offset..udp.payload_offset + udp.payload_len)?,
        payload_bound,
    ))
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
struct MemoryDevice {
    ingress: [PacketSlot; INGRESS_SLOTS],
    ingress_head: usize,
    ingress_len: usize,
    output: Box<[u8]>,
    output_len: usize,
    validator: PacketValidator,
    validated_output: usize,
    rejected_output: usize,
    foundation_input: usize,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl MemoryDevice {
    fn new(mtu: usize, families: Families) -> Self {
        Self {
            ingress: std::array::from_fn(|_| PacketSlot {
                len: 0,
                foundation: false,
                parsed: None,
                bytes: Vec::with_capacity(mtu),
            }),
            ingress_head: 0,
            ingress_len: 0,
            output: vec![0_u8; mtu].into_boxed_slice(),
            output_len: 0,
            validator: PacketValidator::with_families(mtu, families),
            validated_output: 0,
            rejected_output: 0,
            foundation_input: 0,
        }
    }

    fn enqueue_parsed(&mut self, packet: &[u8], parsed: ParsedIpPacket) -> bool {
        if self.ingress_len == INGRESS_SLOTS {
            return false;
        }
        let tail = (self.ingress_head + self.ingress_len) % INGRESS_SLOTS;
        self.ingress[tail].bytes.clear();
        self.ingress[tail].bytes.extend_from_slice(packet);
        self.ingress[tail].len = packet.len();
        self.ingress[tail].foundation = matches!(parsed.transport, TransportMetadata::Udp(_));
        self.ingress[tail].parsed = Some(parsed);
        self.ingress_len += 1;
        true
    }

    fn ingress_available(&self) -> usize {
        INGRESS_SLOTS - self.ingress_len
    }

    fn has_output(&self) -> bool {
        self.output_len != 0
    }

    fn clear_session_buffers(&mut self) {
        for slot in &mut self.ingress {
            slot.bytes.clear();
            slot.len = 0;
            slot.foundation = false;
            slot.parsed = None;
        }
        self.ingress_head = 0;
        self.ingress_len = 0;
        self.output_len = 0;
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

    fn flush_output(
        &mut self,
        send: impl FnOnce(&[u8]) -> OutputSendOutcome,
    ) -> OutputFlushOutcome {
        if self.output_len == 0 {
            return OutputFlushOutcome::Empty;
        }
        match send(&self.output[..self.output_len]) {
            OutputSendOutcome::Sent => {
                self.output_len = 0;
                OutputFlushOutcome::Sent
            }
            OutputSendOutcome::DroppedRingFull => {
                self.output_len = 0;
                OutputFlushOutcome::DroppedRingFull
            }
            OutputSendOutcome::Fatal => OutputFlushOutcome::Fatal,
        }
    }

    fn inject_udp_response(&mut self, tuple: UdpTuple, payload: &[u8]) -> UdpInjectOutcome {
        if self.output_len != 0 {
            return UdpInjectOutcome::Backpressured;
        }
        let length = match write_udp_response(&mut self.output, tuple, payload) {
            Ok(length) => length,
            Err(reason) => {
                self.rejected_output += 1;
                return UdpInjectOutcome::Rejected(map_packet_reject(reason));
            }
        };
        match self.validator.parse_ingress(&self.output[..length]) {
            Ok(ParsedPacket::Complete(_)) => {}
            Ok(ParsedPacket::Fragment(_)) => {
                self.rejected_output += 1;
                return UdpInjectOutcome::Rejected(TunRejectReason::FragmentMalformed);
            }
            Err(rejected) => {
                self.rejected_output += 1;
                return UdpInjectOutcome::Rejected(map_packet_reject(rejected.reason));
            }
        }
        self.validated_output += 1;
        self.output_len = length;
        UdpInjectOutcome::Injected
    }

    fn inject_control_error(
        &mut self,
        original: &[u8],
        context: ControlContext,
        kind: LocalControlKind,
        now_millis: i64,
        limiter: &mut ControlRateLimiter,
    ) -> bool {
        if self.output_len != 0 {
            return false;
        }
        let Some(length) = write_local_control_error(
            &mut self.output,
            original,
            context,
            kind,
            self.validator.mtu,
        ) else {
            return false;
        };
        if !limiter.allow(now_millis) {
            return false;
        }
        self.output_len = length;
        true
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
fn write_udp_response(
    output: &mut [u8],
    tuple: UdpTuple,
    payload: &[u8],
) -> Result<usize, packet::PacketRejectReason> {
    let (header, source, target) = match (tuple.target().ip(), tuple.source().ip()) {
        (IpAddr::V4(source), IpAddr::V4(target)) => {
            let length = 28_usize
                .checked_add(payload.len())
                .ok_or(packet::PacketRejectReason::InvalidLength)?;
            let packet = output
                .get_mut(..length)
                .ok_or(packet::PacketRejectReason::InvalidLength)?;
            packet.fill(0);
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(
                &u16::try_from(length)
                    .map_err(|_| packet::PacketRejectReason::InvalidLength)?
                    .to_be_bytes(),
            );
            packet[8] = 64;
            packet[9] = 17;
            packet[12..16].copy_from_slice(&source.octets());
            packet[16..20].copy_from_slice(&target.octets());
            (20, IpAddr::V4(source), IpAddr::V4(target))
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            let udp_len = 8_usize
                .checked_add(payload.len())
                .ok_or(packet::PacketRejectReason::InvalidTransport)?;
            let length = 40_usize
                .checked_add(udp_len)
                .ok_or(packet::PacketRejectReason::InvalidLength)?;
            let packet = output
                .get_mut(..length)
                .ok_or(packet::PacketRejectReason::InvalidLength)?;
            packet.fill(0);
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(
                &u16::try_from(udp_len)
                    .map_err(|_| packet::PacketRejectReason::InvalidTransport)?
                    .to_be_bytes(),
            );
            packet[6] = 17;
            packet[7] = 64;
            packet[8..24].copy_from_slice(&source.octets());
            packet[24..40].copy_from_slice(&target.octets());
            (40, IpAddr::V6(source), IpAddr::V6(target))
        }
        _ => return Err(packet::PacketRejectReason::InvalidDestination),
    };
    let udp_len = 8_usize
        .checked_add(payload.len())
        .ok_or(packet::PacketRejectReason::InvalidTransport)?;
    output[header..header + 2].copy_from_slice(&tuple.target().port().to_be_bytes());
    output[header + 2..header + 4].copy_from_slice(&tuple.source().port().to_be_bytes());
    output[header + 4..header + 6].copy_from_slice(
        &u16::try_from(udp_len)
            .map_err(|_| packet::PacketRejectReason::InvalidTransport)?
            .to_be_bytes(),
    );
    output[header + 8..header + udp_len].copy_from_slice(payload);
    let length = udp_len as u32;
    let length_bytes = length.to_be_bytes();
    let next = [0_u8, 0, 0, 17];
    let udp_checksum = match (source, target) {
        (IpAddr::V4(source), IpAddr::V4(target)) => checksum(&[
            &source.octets(),
            &target.octets(),
            &next[2..],
            &length_bytes[2..],
            &output[header..header + udp_len],
        ]),
        (IpAddr::V6(source), IpAddr::V6(target)) => checksum(&[
            &source.octets(),
            &target.octets(),
            &length_bytes,
            &next,
            &output[header..header + udp_len],
        ]),
        _ => return Err(packet::PacketRejectReason::InvalidDestination),
    };
    output[header + 6..header + 8].copy_from_slice(
        &if udp_checksum == 0 {
            u16::MAX
        } else {
            udp_checksum
        }
        .to_be_bytes(),
    );
    if header == 20 {
        let header_checksum = checksum(&[&output[..20]]);
        output[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    }
    Ok(header + udp_len)
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputSendOutcome {
    Sent,
    DroppedRingFull,
    Fatal,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputFlushOutcome {
    Empty,
    Sent,
    DroppedRingFull,
    Fatal,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
struct PacketSlot {
    len: usize,
    foundation: bool,
    parsed: Option<ParsedIpPacket>,
    bytes: Vec<u8>,
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
    validated_output: &'a mut usize,
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
            *self.validated_output += 1;
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
                validated_output: &mut self.validated_output,
                rejected_output: &mut self.rejected_output,
                output: &mut self.output,
                output_len: &mut self.output_len,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        (self.output_len == 0).then_some(MemoryTx {
            validator: self.validator,
            validated_output: &mut self.validated_output,
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
    ipv4_interface: Option<(Ipv4Addr, u8)>,
    foundation_dropped: usize,
    flows: Box<[Option<TcpFlowEntry>]>,
    flow_index: HashMap<TcpTuple, GenerationId>,
    free_flow_slots: Vec<usize>,
    active_flow_head: Option<usize>,
    active_flow_tail: Option<usize>,
    live_tcp_flow_count: usize,
    generations: GenerationTable,
    tcp_buffer_bytes: usize,
    tcp_timeout_millis: u64,
    bridge_capacity: usize,
    next_flow_cursor: Option<usize>,
    next_reap_cursor: Option<usize>,
    packet_generation: u64,
    reassembly: ReassemblyTable,
    control_limiter: ControlRateLimiter,
    flow_sender: tokio::sync::mpsc::Sender<TcpFlow>,
    flow_count: Arc<AtomicUsize>,
    registry: OwnerRegistry,
    udp: UdpTable,
    owner_wake: OwnerWake,
    events: TunEventSink,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
type StackReady = (
    Stack,
    tokio::sync::mpsc::Receiver<TcpFlow>,
    tokio::sync::mpsc::Receiver<UdpCandidate>,
);

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
type InterfaceAddresses = (Option<(Ipv4Addr, u8)>, Option<(Ipv6Addr, u8)>);

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct StackPollOutcome {
    worked: bool,
    foundation_dropped: usize,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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
    _registry_owner: ferrum2_runtime::TunTcpFlowOwner,
    pending: Option<TcpFlow>,
    published: bool,
    remote_closed: bool,
    fin_started: bool,
    drive_rx_first: bool,
    active_prev: Option<usize>,
    active_next: Option<usize>,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl Stack {
    #[allow(clippy::too_many_arguments)]
    fn new_with_udp(
        addresses: InterfaceAddresses,
        mtu: usize,
        max_tcp_flows: usize,
        tcp_buffer_bytes: usize,
        tcp_timeout: Duration,
        flow_count: Arc<AtomicUsize>,
        registry: OwnerRegistry,
        max_udp_associations: usize,
        udp_timeout: Duration,
        udp_filtering: UdpFiltering,
        session_generation: u64,
        owner_wake: OwnerWake,
    ) -> Result<StackReady, ()> {
        let (ipv4, ipv6) = addresses;
        let families = Families {
            ipv4: ipv4.is_some(),
            ipv6: ipv6.is_some(),
        };
        if !families.ipv4 && !families.ipv6 {
            return Err(());
        }
        let mut device = MemoryDevice::new(mtu, families);
        let mut interface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            Instant::ZERO,
        );
        interface.update_ip_addrs(|addresses| {
            if let Some((address, prefix)) = ipv4 {
                addresses
                    .push(IpCidr::new(IpAddress::from(IpAddr::V4(address)), prefix))
                    .expect("validated address capacity");
            }
            if let Some((address, prefix)) = ipv6 {
                addresses
                    .push(IpCidr::new(IpAddress::from(IpAddr::V6(address)), prefix))
                    .expect("validated address capacity");
            }
        });
        interface.set_any_ip(true);
        if let Some((address, _)) = ipv4 {
            interface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::from(address.octets()))
                .map_err(|_| ())?;
        }
        if let Some((address, _)) = ipv6 {
            interface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Address::from(address.octets()))
                .map_err(|_| ())?;
        }
        if let (Some((ipv4, _)), Some(_)) = (ipv4, ipv6) {
            let mut third_rejected = false;
            interface.routes_mut().update(|routes| {
                third_rejected = routes.push(Route::new_ipv4_gateway(ipv4)).is_err();
            });
            if !third_rejected {
                return Err(());
            }
        }
        let (flow_sender, flow_receiver) = tokio::sync::mpsc::channel(max_tcp_flows);
        let (udp, datagrams) = UdpTable::with_options(
            max_udp_associations,
            udp_timeout,
            udp_filtering,
            session_generation,
            owner_wake.clone(),
        );
        let tcp_timeout_millis = u64::try_from(tcp_timeout.as_millis()).map_err(|_| ())?;
        Ok((
            Self {
                interface,
                sockets: SocketSet::new(Vec::with_capacity(max_tcp_flows)),
                device,
                ipv4_interface: ipv4,
                foundation_dropped: 0,
                flows: std::iter::repeat_with(|| None)
                    .take(max_tcp_flows)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                flow_index: HashMap::with_capacity(max_tcp_flows),
                free_flow_slots: (0..max_tcp_flows).rev().collect(),
                active_flow_head: None,
                active_flow_tail: None,
                live_tcp_flow_count: 0,
                generations: GenerationTable::new(max_tcp_flows),
                tcp_buffer_bytes,
                tcp_timeout_millis,
                bridge_capacity: tcp_buffer_bytes,
                next_flow_cursor: None,
                next_reap_cursor: None,
                packet_generation: 0,
                reassembly: ReassemblyTable::new(0),
                control_limiter: ControlRateLimiter::new(),
                flow_sender,
                flow_count,
                registry,
                udp,
                owner_wake,
                events: TunEventSink::default(),
            },
            flow_receiver,
            datagrams,
        ))
    }

    fn set_event_sink(&mut self, events: TunEventSink) {
        self.udp.set_event_sink(events.clone());
        self.events = events;
    }

    fn enqueue_at(&mut self, packet: &[u8], admitting: bool, now_millis: i64) -> bool {
        let parsed = match self.device.validator.parse_ingress(packet) {
            Ok(ParsedPacket::Complete(parsed)) => {
                if self.is_ipv4_directed_broadcast(parsed.destination) {
                    self.reject(TunRejectReason::InvalidDestination);
                    return false;
                }
                parsed
            }
            Ok(ParsedPacket::Fragment(fragment)) => {
                if self.is_ipv4_directed_broadcast(fragment.destination) {
                    self.reject(TunRejectReason::InvalidDestination);
                    return false;
                }
                if packet.len() > self.device.validator.mtu {
                    if self.reassembly.drop_key(fragment.key) {
                        self.events.emit(TunEvent::ReassemblyDroppedMalformed);
                        self.events
                            .emit(TunEvent::ReassemblyEntriesActive(self.reassembly.len()));
                    }
                    self.reject(TunRejectReason::FragmentMalformed);
                    return false;
                }
                let before = self.reassembly.len();
                let accepted =
                    self.reassembly
                        .accept(packet, fragment, now_millis, self.packet_generation);
                let after = self.reassembly.len();
                self.record_reassembly_timeouts(accepted.expired);
                let live_before = before.saturating_sub(accepted.expired);
                for _ in live_before..after {
                    self.events.emit(TunEvent::ReassemblyStarted);
                }
                if accepted.expired != 0 || after != before {
                    self.events.emit(TunEvent::ReassemblyEntriesActive(after));
                }
                match accepted.outcome {
                    ReassemblyOutcome::Pending => return true,
                    ReassemblyOutcome::Dropped(reason) => {
                        let reject = match reason {
                            ReassemblyDropReason::Malformed => {
                                self.events.emit(TunEvent::ReassemblyDroppedMalformed);
                                TunRejectReason::FragmentMalformed
                            }
                            ReassemblyDropReason::Overlap => {
                                self.events.emit(TunEvent::ReassemblyDroppedOverlap);
                                TunRejectReason::FragmentOverlap
                            }
                            ReassemblyDropReason::Limit => {
                                self.events.emit(TunEvent::ReassemblyDroppedLimit);
                                TunRejectReason::FragmentLimit
                            }
                        };
                        self.reject(reject);
                        return false;
                    }
                    ReassemblyOutcome::Atomic(normalized) => {
                        let Ok(ParsedPacket::Complete(parsed)) =
                            self.device.validator.parse_reassembled(&normalized)
                        else {
                            self.events.emit(TunEvent::ReassemblyDroppedMalformed);
                            self.reject(TunRejectReason::FragmentMalformed);
                            return false;
                        };
                        return self.enqueue_complete(
                            &normalized,
                            parsed,
                            admitting,
                            now_millis,
                            false,
                        );
                    }
                    ReassemblyOutcome::Complete(reassembled) => {
                        self.events.emit(TunEvent::ReassemblyCompleted);
                        let Ok(ParsedPacket::Complete(parsed)) =
                            self.device.validator.parse_reassembled(&reassembled)
                        else {
                            self.events.emit(TunEvent::ReassemblyDroppedMalformed);
                            self.reject(TunRejectReason::FragmentMalformed);
                            return false;
                        };
                        return self.enqueue_complete(
                            &reassembled,
                            parsed,
                            admitting,
                            now_millis,
                            true,
                        );
                    }
                }
            }
            Err(rejected) => {
                self.reject(map_packet_reject(rejected.reason));
                if let Some(key) = rejected.fragment_key
                    && self.reassembly.drop_key(key)
                {
                    self.events.emit(TunEvent::ReassemblyDroppedMalformed);
                    self.events
                        .emit(TunEvent::ReassemblyEntriesActive(self.reassembly.len()));
                }
                if rejected.reason == packet::PacketRejectReason::UnsupportedProtocol
                    && let Some(context) = rejected.control
                {
                    self.emit_local_control(
                        packet,
                        context,
                        LocalControlKind::ProtocolUnreachable,
                        now_millis,
                    );
                }
                return false;
            }
        };
        self.enqueue_complete(packet, parsed, admitting, now_millis, false)
    }

    fn is_ipv4_directed_broadcast(&self, destination: IpAddr) -> bool {
        matches!(
            (destination, self.ipv4_interface),
            (IpAddr::V4(destination), Some(interface))
                if ipv4_directed_broadcast(destination, interface)
        )
    }

    fn enqueue_complete(
        &mut self,
        packet: &[u8],
        parsed: ParsedIpPacket,
        admitting: bool,
        now_millis: i64,
        reassembled: bool,
    ) -> bool {
        if !parsed.metadata_matches(packet.len()) {
            self.reject(TunRejectReason::InvalidIpLength);
            return false;
        }
        if !reassembled && packet.len() > self.device.validator.mtu {
            if let Some((context, kind)) =
                oversized_ingress_control(packet, parsed, self.device.validator.mtu)
            {
                self.emit_local_control(packet, context, kind, now_millis);
            }
            self.reject(TunRejectReason::InvalidIpLength);
            return false;
        }
        if let Some((tuple, payload, payload_bound)) =
            udp_datagram_from_parsed(packet, parsed, self.device.validator.mtu)
        {
            let admitted = if reassembled {
                self.udp
                    .admit_reassembled(tuple, payload, payload_bound, now_millis, admitting)
            } else {
                self.udp
                    .admit(tuple, payload, payload_bound, now_millis, admitting)
            };
            if admitted == UdpAdmission::Dropped {
                self.emit_local_control(
                    packet,
                    parsed.control_context(),
                    LocalControlKind::PortUnreachable,
                    now_millis,
                );
                return false;
            }
            return true;
        }
        if self.device.ingress_len == INGRESS_SLOTS {
            self.emit_local_control(
                packet,
                parsed.control_context(),
                LocalControlKind::AdministrativelyProhibited,
                now_millis,
            );
            self.reject(TunRejectReason::IngressFull);
            return false;
        }
        match initial_tcp_tuple(parsed) {
            Ok(Some(tuple)) if !self.admit_tcp(tuple, admitting) => {
                self.emit_local_control(
                    packet,
                    parsed.control_context(),
                    LocalControlKind::AdministrativelyProhibited,
                    now_millis,
                );
                return false;
            }
            Err(()) => {
                self.emit_local_control(
                    packet,
                    parsed.control_context(),
                    LocalControlKind::AdministrativelyProhibited,
                    now_millis,
                );
                return false;
            }
            Ok(Some(_)) | Ok(None) => {}
        }
        self.device.enqueue_parsed(packet, parsed)
    }

    fn emit_local_control(
        &mut self,
        original: &[u8],
        context: ControlContext,
        kind: LocalControlKind,
        now_millis: i64,
    ) {
        let _ = self.device.inject_control_error(
            original,
            context,
            kind,
            now_millis,
            &mut self.control_limiter,
        );
    }

    fn reject(&self, reason: TunRejectReason) {
        self.events.emit(TunEvent::PacketRejected(reason));
    }

    fn admit_tcp(&mut self, tuple: TcpTuple, admitting: bool) -> bool {
        if self.flow_index.contains_key(&tuple) {
            return true;
        }
        if !admitting {
            self.reject(TunRejectReason::StaleGeneration);
            return false;
        }
        let Some(&slot) = self.free_flow_slots.last() else {
            self.events.emit(TunEvent::TcpFlowRejectedLimit);
            self.reject(TunRejectReason::TcpFlowLimit);
            return false;
        };
        let Some(generation) = self.generations.current(slot) else {
            self.reject(TunRejectReason::StaleGeneration);
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
            self.reject(TunRejectReason::InvalidDestination);
            return false;
        }
        let socket = self.sockets.add(socket);
        let (flow, owner) = tcp::tcp_flow_pair_with_events(
            tuple.target,
            self.bridge_capacity,
            self.owner_wake.clone(),
            self.events.clone(),
        );
        let registry_owner = self.registry.track_tun_tcp_flow();
        let claimed_slot = self
            .free_flow_slots
            .pop()
            .expect("observed TCP free slot remains available");
        debug_assert_eq!(claimed_slot, slot);
        self.flows[slot] = Some(TcpFlowEntry {
            tuple,
            generation,
            socket,
            owner,
            _registry_owner: registry_owner,
            pending: Some(flow),
            published: false,
            remote_closed: false,
            fin_started: false,
            drive_rx_first: true,
            active_prev: None,
            active_next: None,
        });
        let replaced = self.flow_index.insert(tuple, generation);
        debug_assert!(replaced.is_none(), "TCP tuple index admitted a duplicate");
        self.attach_tcp_flow(slot);
        self.flow_count.fetch_add(1, Ordering::AcqRel);
        self.events
            .emit(TunEvent::TcpFlowsActive(self.live_tcp_flows()));
        true
    }

    fn attach_tcp_flow(&mut self, slot: usize) {
        let previous = self.active_flow_tail;
        let entry = self.flows[slot]
            .as_mut()
            .expect("new TCP flow occupies its claimed slot");
        entry.active_prev = previous;
        entry.active_next = None;
        if let Some(previous) = previous {
            self.flows[previous]
                .as_mut()
                .expect("TCP active-list tail is live")
                .active_next = Some(slot);
        } else {
            self.active_flow_head = Some(slot);
        }
        self.active_flow_tail = Some(slot);
        self.live_tcp_flow_count += 1;
        self.next_flow_cursor.get_or_insert(slot);
        self.next_reap_cursor.get_or_insert(slot);
    }

    fn active_flow_successor(&self, slot: usize) -> Option<usize> {
        let entry = self.flows.get(slot)?.as_ref()?;
        entry.active_next.or(self.active_flow_head)
    }

    fn take_tcp_flow(&mut self, slot: usize) -> Option<TcpFlowEntry> {
        let entry = self.flows.get_mut(slot)?.take()?;
        match entry.active_prev {
            Some(previous) => {
                self.flows[previous]
                    .as_mut()
                    .expect("TCP active-list predecessor is live")
                    .active_next = entry.active_next;
            }
            None => self.active_flow_head = entry.active_next,
        }
        match entry.active_next {
            Some(next) => {
                self.flows[next]
                    .as_mut()
                    .expect("TCP active-list successor is live")
                    .active_prev = entry.active_prev;
            }
            None => self.active_flow_tail = entry.active_prev,
        }

        let replacement = entry.active_next.or(self.active_flow_head);
        if self.next_flow_cursor == Some(slot) {
            self.next_flow_cursor = replacement;
        }
        if self.next_reap_cursor == Some(slot) {
            self.next_reap_cursor = replacement;
        }
        let indexed = self.flow_index.remove(&entry.tuple);
        debug_assert_eq!(indexed, Some(entry.generation));
        self.live_tcp_flow_count -= 1;
        if self.generations.recycle(entry.generation) {
            self.free_flow_slots.push(slot);
        }
        self.flow_count.fetch_sub(1, Ordering::AcqRel);
        Some(entry)
    }

    fn live_tcp_flows(&self) -> usize {
        self.live_tcp_flow_count
    }

    fn live_udp_associations(&self) -> usize {
        self.udp.active_associations()
    }

    fn ingress_available(&self) -> usize {
        self.device.ingress_available()
    }

    fn has_output(&self) -> bool {
        self.device.has_output()
    }

    fn process_one_udp_control(&mut self, now_millis: i64, admitting: bool) -> bool {
        self.udp
            .process_one_control(now_millis, admitting)
            .is_some()
    }

    fn process_one_udp_response(&mut self, now_millis: i64) -> udp::ResponseProcessOutcome {
        let device = &mut self.device;
        self.udp.process_one_response(now_millis, |tuple, payload| {
            device.inject_udp_response(tuple, payload)
        })
    }

    fn expire_deadlines(&mut self, now_millis: i64) -> bool {
        let udp = self.udp.expire(now_millis);
        let fragments = self.reassembly.expire(now_millis);
        if fragments != 0 {
            self.record_reassembly_timeouts(fragments);
            self.events
                .emit(TunEvent::ReassemblyEntriesActive(self.reassembly.len()));
        }
        udp.candidates != 0 || udp.associations != 0 || fragments != 0
    }

    fn record_reassembly_timeouts(&self, count: usize) {
        for _ in 0..count {
            self.events.emit(TunEvent::ReassemblyDroppedTimeout);
            self.reject(TunRejectReason::FragmentTimeout);
        }
    }

    fn quiesce(
        &mut self,
        next_generation: u64,
        udp_response_drop_reason: UdpResponseDropReason,
    ) -> usize {
        let mut sockets = Vec::new();
        let mut reset = 0_usize;
        while let Some(slot) = self.active_flow_head {
            self.flows[slot]
                .as_mut()
                .expect("TCP active-list head is live")
                .owner
                .mark_reset();
            let entry = self
                .take_tcp_flow(slot)
                .expect("TCP active-list head remains removable");
            sockets.push(entry.socket);
            reset += 1;
        }
        for socket in sockets {
            self.sockets.remove(socket);
        }
        if reset != 0 {
            for _ in 0..reset {
                self.events.emit(TunEvent::TcpFlowResetRestart);
            }
        }
        self.udp
            .invalidate_session(next_generation, udp_response_drop_reason);
        self.reassembly.clear();
        self.device.clear_session_buffers();
        self.packet_generation = next_generation;
        self.events.emit(TunEvent::TcpFlowsActive(0));
        self.events.emit(TunEvent::UdpAssociationsActive(0));
        self.events.emit(TunEvent::UdpCandidatesActive(0));
        self.events.emit(TunEvent::ReassemblyEntriesActive(0));
        reset
    }

    fn next_wait_duration(&mut self, now_millis: i64) -> Duration {
        if self.device.ingress_len != 0 || self.has_output() || self.udp.has_pending_response() {
            return Duration::ZERO;
        }
        let now = Instant::from_millis(now_millis);
        let stack_delay = self
            .interface
            .poll_delay(now, &self.sockets)
            .map(|delay| Duration::from_millis(delay.total_millis()));
        let deadline_delay = [
            self.udp.next_deadline_millis(),
            self.reassembly.next_deadline_millis(),
        ]
        .into_iter()
        .flatten()
        .map(|deadline| {
            Duration::from_millis(
                u64::try_from(deadline.saturating_sub(now_millis).max(0)).unwrap_or(u64::MAX),
            )
        })
        .min();
        stack_delay
            .into_iter()
            .chain(deadline_delay)
            .min()
            .unwrap_or(Duration::from_millis(u64::from(u32::MAX - 1)))
    }

    #[cfg(test)]
    fn poll_udp_events(&mut self, now_millis: i64, admitting: bool) -> udp::EventOutcome {
        let device = &mut self.device;
        self.udp
            .process_events(now_millis, admitting, |tuple, payload| {
                device.inject_udp_response(tuple, payload)
            })
    }

    #[cfg(test)]
    fn poll_quantum(&mut self, now: Instant) -> usize {
        let mut foundation = 0;
        for _ in 0..PACKET_QUANTUM {
            let outcome = self.poll_stack_once(now);
            foundation += outcome.foundation_dropped;
            if !outcome.worked {
                break;
            }
        }
        foundation
    }

    fn poll_stack_once(&mut self, now: Instant) -> StackPollOutcome {
        let foundation_before = self.device.foundation_input;
        let ingress = self
            .interface
            .poll_ingress_single(now, &mut self.device, &mut self.sockets);
        let mut worked = ingress != PollIngressSingleResult::None;
        worked |= self.drive_tcp();
        worked |= self
            .interface
            .poll_egress(now, &mut self.device, &mut self.sockets)
            != PollResult::None;
        worked |= self.reap_tcp() != 0;
        let foundation_dropped = self.device.foundation_input - foundation_before;
        self.foundation_dropped += foundation_dropped;
        StackPollOutcome {
            worked,
            foundation_dropped,
        }
    }

    fn drive_tcp(&mut self) -> bool {
        let flow_visits = self.live_tcp_flow_count;
        if flow_visits == 0 {
            return false;
        }
        let mut worked = false;
        let start = self
            .next_flow_cursor
            .or(self.active_flow_head)
            .expect("non-empty TCP active list has a drive cursor");
        let per_flow_quantum = self.device.validator.mtu.saturating_mul(4).max(16 * 1024);
        let mut total_remaining = per_flow_quantum.saturating_mul(flow_visits.min(16));
        let mut index = start;
        let mut resume = self
            .active_flow_successor(start)
            .expect("TCP active-list cursor has a successor");

        for _ in 0..flow_visits {
            let next = self
                .active_flow_successor(index)
                .expect("visited TCP flow remains linked");
            let entry = self.flows[index]
                .as_mut()
                .expect("TCP active-list slot is live");
            let socket = self.sockets.get_mut::<TcpSocket>(entry.socket);

            if socket.state() == TcpState::Established
                && let Some(flow) = entry.pending.take()
            {
                match self.flow_sender.try_send(flow) {
                    Ok(()) => {
                        entry.published = true;
                        worked = true;
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(flow)) => {
                        entry.pending = Some(flow);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        socket.abort();
                        worked = true;
                    }
                }
            }

            if entry.owner.is_aborted() {
                socket.abort();
                worked = true;
            } else {
                let mut flow_remaining = per_flow_quantum.min(total_remaining);
                let receive_ready = entry.owner.application_capacity() != 0 && socket.can_recv();
                let send_ready = entry.owner.stack_buffered() != 0 && socket.may_send();
                let receive_first = entry.drive_rx_first;
                if receive_ready && send_ready {
                    entry.drive_rx_first = !entry.drive_rx_first;
                }
                for receive in [receive_first, !receive_first] {
                    if flow_remaining == 0 {
                        break;
                    }
                    if receive && entry.owner.application_capacity() != 0 && socket.can_recv() {
                        let received = socket
                            .recv(|bytes| {
                                let count = bytes.len().min(flow_remaining);
                                let copied = entry.owner.write_from_stack(&bytes[..count]);
                                (copied, copied)
                            })
                            .unwrap_or(0);
                        flow_remaining -= received;
                        total_remaining -= received;
                        if received != 0 {
                            worked = true;
                            resume = next;
                        }
                    } else if !receive && entry.owner.stack_buffered() != 0 && socket.may_send() {
                        let sent = entry.owner.drain_to_stack(|bytes| {
                            let count = bytes.len().min(flow_remaining);
                            socket.send_slice(&bytes[..count]).unwrap_or(0)
                        });
                        flow_remaining -= sent;
                        total_remaining -= sent;
                        if sent != 0 {
                            worked = true;
                            resume = next;
                        }
                    }
                }
                if socket.state() != TcpState::Closed
                    && !entry.remote_closed
                    && !socket.may_recv()
                    && entry.published
                {
                    entry.owner.mark_remote_closed();
                    entry.remote_closed = true;
                    worked = true;
                }
                if entry.owner.shutdown_requested()
                    && entry.owner.stack_buffered() == 0
                    && !entry.fin_started
                    && socket.may_send()
                {
                    socket.close();
                    entry.fin_started = true;
                    worked = true;
                }
            }

            if socket.state() == TcpState::Closed && !entry.remote_closed {
                entry.owner.mark_reset();
                worked = true;
            }
            index = next;
        }
        self.next_flow_cursor = Some(resume);
        worked
    }

    fn reap_tcp(&mut self) -> usize {
        let mut reaped = 0;
        let flow_visits = self.live_tcp_flow_count.min(TCP_REAP_QUANTUM);
        for _ in 0..flow_visits {
            let Some(index) = self.next_reap_cursor else {
                break;
            };
            self.next_reap_cursor = self.active_flow_successor(index);
            let remove = self.flows[index].as_ref().is_some_and(|entry| {
                let state = self.sockets.get::<TcpSocket>(entry.socket).state();
                state == TcpState::Closed || (state == TcpState::TimeWait && entry.remote_closed)
            });
            if remove && let Some(entry) = self.take_tcp_flow(index) {
                self.sockets.remove(entry.socket);
                reaped += 1;
            }
        }
        if reaped != 0 {
            self.events
                .emit(TunEvent::TcpFlowsActive(self.live_tcp_flows()));
        }
        reaped
    }

    fn pending_tcp_fin_generation(&self) -> Option<GenerationId> {
        let packet = &self.device.output[..self.device.output_len];
        let Ok(ParsedPacket::Complete(parsed)) = self.device.validator.parse_ingress(packet) else {
            return None;
        };
        let TransportMetadata::Tcp(tcp) = parsed.transport else {
            return None;
        };
        if tcp.flags & 0x01 == 0 {
            return None;
        }
        let tuple = TcpTuple {
            source: SocketAddr::new(parsed.destination, tcp.destination_port),
            target: SocketAddr::new(parsed.source, tcp.source_port),
        };
        let generation = self.flow_index.get(&tuple).copied()?;
        self.flows[generation.slot].as_ref().and_then(|entry| {
            (entry.generation == generation && entry.fin_started).then_some(generation)
        })
    }

    fn complete_sent_tcp_fin(&mut self, generation: GenerationId) {
        let Some(entry) = self.flows[generation.slot].as_mut() else {
            return;
        };
        if entry.generation == generation && entry.fin_started {
            entry.owner.mark_fin_sent();
        }
    }

    fn flush_output(
        &mut self,
        send: impl FnOnce(&[u8]) -> OutputSendOutcome,
    ) -> OutputFlushOutcome {
        let pending_fin = self.pending_tcp_fin_generation();
        let outcome = self.device.flush_output(send);
        if outcome == OutputFlushOutcome::Sent
            && let Some(generation) = pending_fin
        {
            self.complete_sent_tcp_fin(generation);
        }
        outcome
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
        self.device.validated_output
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
impl Stack {
    fn new(
        addresses: (Ipv4Addr, u8, Ipv6Addr, u8),
        mtu: usize,
        max_tcp_flows: usize,
        tcp_buffer_bytes: usize,
        tcp_timeout: Duration,
        flow_count: Arc<AtomicUsize>,
    ) -> Result<(Self, tokio::sync::mpsc::Receiver<TcpFlow>), ()> {
        let (stack, flows, _) = Stack::new_with_udp(
            (
                Some((addresses.0, addresses.1)),
                Some((addresses.2, addresses.3)),
            ),
            mtu,
            max_tcp_flows,
            tcp_buffer_bytes,
            tcp_timeout,
            flow_count,
            OwnerRegistry::new(),
            1,
            tcp_timeout,
            UdpFiltering::AddressDependent,
            0,
            OwnerWake::default(),
        )?;
        Ok((stack, flows))
    }

    fn enqueue(&mut self, packet: &[u8], admitting: bool) -> bool {
        self.enqueue_at(packet, admitting, 0)
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
fn initial_tcp_tuple(parsed: ParsedIpPacket) -> Result<Option<TcpTuple>, ()> {
    let TransportMetadata::Tcp(tcp) = parsed.transport else {
        return Ok(None);
    };
    if tcp.flags & 0x02 == 0 {
        return Ok(None);
    }
    if !tcp.is_initial_syn() {
        return Err(());
    }
    Ok(Some(TcpTuple {
        source: SocketAddr::new(parsed.source, tcp.source_port),
        target: SocketAddr::new(parsed.destination, tcp.destination_port),
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

    use super::reassembly::REASSEMBLY_TIMEOUT_MILLIS;
    use super::tcp::tcp_flow_pair;
    #[cfg(all(windows, target_arch = "x86_64"))]
    use super::{AdapterErrorDisposition, classify_adapter_error};
    use super::{
        Families, GenerationTable, INGRESS_SLOTS, MemoryDevice, MemoryTx, OutputFlushOutcome,
        OutputSendOutcome, OwnerControl, OwnerExit, OwnerRegistry, OwnerThread, OwnerWake,
        PacketParser, PacketValidator, ParsedPacket, SessionItem, Stack, TunEvent, TunEventSink,
        TunRejectReason, TunRoot, UdpFiltering, UdpPeerAuthorization, UdpResponseDropReason,
        UdpTuple, finish_stack_setup, map_owner_spawn, reconcile_owner_exit, reported_owner_exit,
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

    #[test]
    fn parser_address_rejections_preserve_the_public_source_destination_split() {
        assert_eq!(
            super::map_packet_reject(super::packet::PacketRejectReason::InvalidSource),
            TunRejectReason::InvalidSource
        );
        assert_eq!(
            super::map_packet_reject(super::packet::PacketRejectReason::InvalidDestination),
            TunRejectReason::InvalidDestination
        );
    }

    #[test]
    fn smoltcp_accepts_reassembled_rx_larger_than_reported_device_mtu() {
        use smoltcp::iface::{
            Config as InterfaceConfig, Interface, PollIngressSingleResult, SocketSet,
        };
        use smoltcp::socket::udp::{PacketBuffer, PacketMetadata, Socket as UdpSocket};
        use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};

        const REPORTED_MTU: usize = 1_280;
        const PAYLOAD_LEN: usize = 2_000;
        let packet = ipv4_udp_with_payload(PAYLOAD_LEN);
        let ParsedPacket::Complete(parsed) = PacketParser::new(Families::DUAL)
            .parse(&packet)
            .expect("canonical oversized packet")
        else {
            panic!("complete packet expected")
        };
        assert!(packet.len() > REPORTED_MTU);

        let mut device = MemoryDevice::new(REPORTED_MTU, Families::DUAL);
        assert_eq!(device.capabilities().max_transmission_unit, REPORTED_MTU);
        let mut interface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            Instant::ZERO,
        );
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(
                    IpAddress::Ipv4(Ipv4Address::new(192, 0, 2, 1)),
                    24,
                ))
                .expect("one interface address");
        });
        let rx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 1], vec![0_u8; PAYLOAD_LEN]);
        let tx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 1], vec![0_u8; 1]);
        let mut socket = UdpSocket::new(rx, tx);
        socket.bind(53).expect("UDP listener");
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(socket);

        assert!(device.enqueue_parsed(&packet, parsed));
        assert_ne!(
            interface.poll_ingress_single(Instant::ZERO, &mut device, &mut sockets),
            PollIngressSingleResult::None,
            "smoltcp 0.13.1 must not apply reported egress MTU to RX tokens"
        );
        let (payload, metadata) = sockets
            .get_mut::<UdpSocket>(handle)
            .recv()
            .expect("oversized RX delivered");
        assert_eq!(payload.len(), PAYLOAD_LEN);
        assert_eq!(metadata.endpoint.port, 10_000);
        assert_eq!(device.capabilities().max_transmission_unit, REPORTED_MTU);
    }

    #[test]
    fn capacity_aware_rotation_drains_eight_sixteen_and_sixty_four_packets() {
        use std::collections::VecDeque;

        use super::scheduler::StepOutcome;

        let packet = ipv4_tcp();
        let ParsedPacket::Complete(parsed) = PacketParser::new(Families::DUAL)
            .parse(&packet)
            .expect("canonical TCP packet")
        else {
            panic!("complete packet expected")
        };

        for count in [8, 16, 64] {
            let mut device = MemoryDevice::new(1_420, Families::DUAL);
            let mut source = VecDeque::from(vec![packet.clone(); count]);
            let mut scheduler = super::FairScheduler::default();
            let mut drained = 0;
            while !source.is_empty() || device.ingress_len != 0 {
                let outcome = scheduler.run_budget(64, |stage| match stage {
                    super::WorkStage::Receive if device.ingress_available() != 0 => {
                        let Some(packet) = source.pop_front() else {
                            return StepOutcome::Idle;
                        };
                        assert!(device.enqueue_parsed(&packet, parsed));
                        StepOutcome::Worked
                    }
                    super::WorkStage::Stack => {
                        if device.dequeue_index().is_some() {
                            drained += 1;
                            StepOutcome::Worked
                        } else {
                            StepOutcome::Idle
                        }
                    }
                    _ => StepOutcome::Idle,
                });
                assert!(!outcome.fatal);
                assert!(outcome.work_units != 0, "scheduler made bounded progress");
                assert!(device.ingress_len <= INGRESS_SLOTS);
            }
            assert_eq!(drained, count);
        }
    }

    #[test]
    fn ring_full_drops_exactly_one_complete_output_and_fatal_retains_it() {
        let mut device = MemoryDevice::new(1_420, Families::DUAL);
        let tuple = UdpTuple::new(
            "198.18.0.1:10000".parse().expect("local"),
            "192.0.2.1:53".parse().expect("remote"),
        );
        assert_eq!(
            device.inject_udp_response(tuple, b"one"),
            super::UdpInjectOutcome::Injected
        );
        assert_eq!(
            device.flush_output(|_| OutputSendOutcome::DroppedRingFull),
            OutputFlushOutcome::DroppedRingFull
        );
        assert_eq!(
            device.flush_output(|_| OutputSendOutcome::Sent),
            OutputFlushOutcome::Empty,
            "ring-full output is never retried"
        );

        assert_eq!(
            device.inject_udp_response(tuple, b"two"),
            super::UdpInjectOutcome::Injected
        );
        assert_eq!(
            device.flush_output(|_| OutputSendOutcome::Fatal),
            OutputFlushOutcome::Fatal
        );
        assert!(
            device.has_output(),
            "fatal send preserves evidence for cleanup"
        );
    }

    #[test]
    fn udp_injection_preserves_the_canonical_packet_reject_reason() {
        let mut device = MemoryDevice::new(1_420, Families::IPV4_ONLY);
        let ipv6 = UdpTuple::new(
            "[fd00::1]:10000".parse().expect("local IPv6"),
            "[2001:db8::1]:53".parse().expect("remote IPv6"),
        );
        assert_eq!(
            device.inject_udp_response(ipv6, b"disabled family"),
            super::UdpInjectOutcome::Rejected(super::TunRejectReason::FamilyDisabled)
        );
        let mixed = UdpTuple::new(
            "198.18.0.1:10000".parse().expect("local IPv4"),
            "[2001:db8::1]:53".parse().expect("remote IPv6"),
        );
        assert_eq!(
            device.inject_udp_response(mixed, b"mixed family"),
            super::UdpInjectOutcome::Rejected(super::TunRejectReason::InvalidDestination)
        );
        assert_eq!(device.rejected_output, 2);
        assert!(!device.has_output());
    }

    #[test]
    fn stack_injects_pmtu_feedback_at_a_fixed_rate() {
        use crate::packet::test_support::{ipv4_udp, repair_ipv4_header};

        const MTU: usize = 1_280;
        let (mut stack, _flows) = Stack::new(
            (
                Ipv4Addr::new(198, 18, 0, 2),
                30,
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                126,
            ),
            MTU,
            1,
            1_024,
            Duration::from_secs(60),
            Arc::new(AtomicUsize::new(0)),
        )
        .expect("bounded stack");
        let mut packet = ipv4_udp(&vec![0x5a; MTU], &[]);
        packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
        repair_ipv4_header(&mut packet);

        assert!(!stack.enqueue_at(&packet, true, 0));
        let mut control = Vec::new();
        assert_eq!(
            stack.flush_output(|packet| {
                control.extend_from_slice(packet);
                OutputSendOutcome::Sent
            }),
            OutputFlushOutcome::Sent
        );
        assert_eq!(&control[20..22], &[3, 4]);
        assert_eq!(u16::from_be_bytes([control[26], control[27]]), MTU as u16);

        assert!(!stack.enqueue_at(&packet, true, 99));
        assert_eq!(
            stack.flush_output(|_| OutputSendOutcome::Sent),
            OutputFlushOutcome::Empty
        );
        assert!(!stack.enqueue_at(&packet, true, 100));
        assert_eq!(
            stack.flush_output(|_| OutputSendOutcome::Sent),
            OutputFlushOutcome::Sent
        );
    }

    fn ipv4_udp_fragments() -> (Vec<u8>, Vec<u8>) {
        let packet = ipv4_udp();
        let mut first = packet[..20].to_vec();
        first.extend_from_slice(&packet[20..28]);
        first[2..4].copy_from_slice(&28_u16.to_be_bytes());
        first[4..6].copy_from_slice(&7_u16.to_be_bytes());
        first[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
        first[10..12].fill(0);
        let first_checksum = checksum(&[&first[..20]]);
        first[10..12].copy_from_slice(&first_checksum.to_be_bytes());

        let mut second = packet[..20].to_vec();
        second.extend_from_slice(&packet[28..]);
        second[2..4].copy_from_slice(&24_u16.to_be_bytes());
        second[4..6].copy_from_slice(&7_u16.to_be_bytes());
        second[6..8].copy_from_slice(&1_u16.to_be_bytes());
        second[10..12].fill(0);
        let second_checksum = checksum(&[&second[..20]]);
        second[10..12].copy_from_slice(&second_checksum.to_be_bytes());
        (first, second)
    }

    fn fragment_ipv4_udp(packet: &[u8], mtu: usize) -> Vec<Vec<u8>> {
        let fragment_capacity = ((mtu - 20) / 8) * 8;
        let transport = &packet[20..];
        transport
            .chunks(fragment_capacity)
            .enumerate()
            .map(|(index, chunk)| {
                let offset = index * fragment_capacity;
                let more = offset + chunk.len() < transport.len();
                let mut fragment = packet[..20].to_vec();
                fragment.extend_from_slice(chunk);
                let fragment_len = u16::try_from(fragment.len()).unwrap();
                fragment[2..4].copy_from_slice(&fragment_len.to_be_bytes());
                fragment[4..6].copy_from_slice(&77_u16.to_be_bytes());
                let offset_field =
                    u16::try_from(offset / 8).unwrap() | if more { 0x2000 } else { 0 };
                fragment[6..8].copy_from_slice(&offset_field.to_be_bytes());
                fragment[10..12].fill(0);
                let header = checksum(&[&fragment[..20]]);
                fragment[10..12].copy_from_slice(&header.to_be_bytes());
                fragment
            })
            .collect()
    }

    fn fragment_ipv6_udp(packet: &[u8], mtu: usize) -> Vec<Vec<u8>> {
        let fragment_capacity = ((mtu - 48) / 8) * 8;
        let transport = &packet[40..];
        transport
            .chunks(fragment_capacity)
            .enumerate()
            .map(|(index, chunk)| {
                let offset = index * fragment_capacity;
                let more = offset + chunk.len() < transport.len();
                let mut fragment = packet[..40].to_vec();
                fragment[4..6]
                    .copy_from_slice(&u16::try_from(8 + chunk.len()).unwrap().to_be_bytes());
                fragment[6] = 44;
                fragment.push(17);
                fragment.push(0);
                let offset_field =
                    u16::try_from(offset / 8).unwrap() << 3 | if more { 1 } else { 0 };
                fragment.extend_from_slice(&offset_field.to_be_bytes());
                fragment.extend_from_slice(&77_u32.to_be_bytes());
                fragment.extend_from_slice(chunk);
                fragment
            })
            .collect()
    }

    fn ipv4_tcp() -> Vec<u8> {
        ipv4_tcp_from_source_port(10_000)
    }

    fn ipv4_tcp_from_source_port(source_port: u16) -> Vec<u8> {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[198, 18, 0, 1]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
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
        packet[12..16].copy_from_slice(&syn_ack[16..20]);
        packet[16..20].copy_from_slice(&syn_ack[12..16]);
        packet[20..22].copy_from_slice(&syn_ack[22..24]);
        packet[22..24].copy_from_slice(&syn_ack[20..22]);
        packet[24..28].copy_from_slice(&1_u32.to_be_bytes());
        let server_sequence = u32::from_be_bytes(syn_ack[24..28].try_into().expect("SYN-ACK seq"));
        packet[28..32].copy_from_slice(&server_sequence.wrapping_add(1).to_be_bytes());
        packet[33] = flags;
        packet[40..].copy_from_slice(payload);
        repair_ipv4_header(&mut packet);
        repair_ipv4_tcp_checksum(&mut packet);
        packet
    }

    fn establish_ipv4_tcp_flow(
        stack: &mut Stack,
        flows: &mut tokio::sync::mpsc::Receiver<super::TcpFlow>,
        source_port: u16,
        now_millis: i64,
    ) -> (super::TcpFlow, Vec<u8>) {
        assert!(stack.enqueue(&ipv4_tcp_from_source_port(source_port), true));
        stack.poll_quantum(Instant::from_millis(now_millis));
        let mut syn_ack = Vec::new();
        assert_eq!(
            stack.flush_output(|packet| {
                syn_ack.extend_from_slice(packet);
                OutputSendOutcome::Sent
            }),
            OutputFlushOutcome::Sent
        );
        assert!(stack.enqueue(&ipv4_tcp_after_syn(&syn_ack, 0x10, &[]), true));
        stack.poll_quantum(Instant::from_millis(now_millis + 1));
        let flow = flows.try_recv().expect("flow after completed handshake");
        assert!(matches!(
            stack.flush_output(|_| OutputSendOutcome::Sent),
            OutputFlushOutcome::Empty | OutputFlushOutcome::Sent
        ));
        (flow, syn_ack)
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
            validated_output: &mut accepted,
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
        let ipv6_flow = ipv6_stack.flows[0].as_ref().expect("IPv6 flow");
        assert_eq!(ipv6_flow.tuple.source, "[fd00::2]:10000".parse().unwrap());
        assert_eq!(ipv6_flow.tuple.target, "[2001:db8::1]:443".parse().unwrap());
    }

    #[test]
    fn malformed_ipv6_options_are_rejected_before_tcp_admission() {
        let flow_count = Arc::new(AtomicUsize::new(0));
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
        .expect("IPv6 stack");
        let base = ipv6_tcp();
        let mut packet = Vec::with_capacity(base.len() + 8);
        packet.extend_from_slice(&base[..40]);
        packet[6] = 0;
        packet.extend_from_slice(&[6, 0, 0x22, 5, 0, 0, 0, 0]);
        packet.extend_from_slice(&base[40..]);
        packet[4..6].copy_from_slice(&28_u16.to_be_bytes());

        assert!(
            !stack.enqueue(&packet, true),
            "an option crossing the HBH header is rejected"
        );
        assert_eq!(stack.live_tcp_flows(), 0, "malformed options leaked a slot");
        assert_eq!(flow_count.load(Ordering::Acquire), 0);
    }

    #[test]
    fn tcp_flow_index_enforces_capacity_and_reuses_the_recycled_slot() {
        let flow_count = Arc::new(AtomicUsize::new(0));
        let (mut stack, _flows) = Stack::new(
            (
                Ipv4Addr::new(198, 18, 0, 2),
                30,
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                126,
            ),
            1420,
            3,
            4096,
            Duration::from_secs(60),
            Arc::clone(&flow_count),
        )
        .expect("three-flow stack");
        let observed = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&observed);
        stack.set_event_sink(TunEventSink::new(move |event| {
            captured.lock().expect("TCP events").push(event);
        }));
        let tuple = |source_port| super::TcpTuple {
            source: SocketAddr::from((Ipv4Addr::new(198, 18, 0, 2), source_port)),
            target: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 443)),
        };
        let first = tuple(10_000);
        let second = tuple(10_001);
        let third = tuple(10_002);
        let replacement = tuple(10_003);

        assert!(stack.admit_tcp(first, true));
        assert!(stack.admit_tcp(second, true));
        assert!(stack.admit_tcp(third, true));
        assert_eq!(stack.live_tcp_flows(), 3);
        assert_eq!(flow_count.load(Ordering::Acquire), 3);
        assert_eq!(stack.flow_index.len(), 3);
        assert!(stack.free_flow_slots.is_empty());

        assert!(stack.admit_tcp(first, true), "duplicate reuses its index");
        assert_eq!(stack.live_tcp_flows(), 3);
        observed.lock().expect("TCP events").clear();
        assert!(
            !stack.admit_tcp(replacement, true),
            "a distinct tuple cannot exceed the exact flow ceiling"
        );
        assert_eq!(
            *observed.lock().expect("TCP events"),
            [
                TunEvent::TcpFlowRejectedLimit,
                TunEvent::PacketRejected(TunRejectReason::TcpFlowLimit),
            ]
        );

        let recycled = stack.flow_index[&second];
        drop(
            stack.flows[recycled.slot]
                .as_mut()
                .expect("indexed flow is live")
                .pending
                .take(),
        );
        assert!(stack.drive_tcp(), "dropped bridge aborts its socket");
        assert_eq!(stack.reap_tcp(), 1);
        assert!(!stack.flow_index.contains_key(&second));
        assert_eq!(stack.live_tcp_flows(), 2);
        assert_eq!(flow_count.load(Ordering::Acquire), 2);

        assert!(stack.admit_tcp(replacement, true));
        let reused = stack.flow_index[&replacement];
        assert_eq!(reused.slot, recycled.slot, "free-list reuses the sole slot");
        assert_eq!(
            reused.generation,
            recycled.generation + 1,
            "slot reuse advances its generation exactly once"
        );
        assert_eq!(stack.live_tcp_flows(), 3);
        assert_eq!(flow_count.load(Ordering::Acquire), 3);
        assert!(stack.free_flow_slots.is_empty());

        let mut active = Vec::new();
        let mut current = stack.active_flow_head;
        while let Some(slot) = current {
            active.push(slot);
            current = stack.flows[slot]
                .as_ref()
                .expect("active slot is live")
                .active_next;
        }
        assert_eq!(active, [0, 2, 1], "reused slot rejoins at the fair tail");
    }

    #[test]
    fn tcp_flow_drive_rotates_across_only_the_live_slots() {
        let (mut stack, _flows) = Stack::new(
            (
                Ipv4Addr::new(198, 18, 0, 2),
                30,
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                126,
            ),
            1420,
            64,
            4096,
            Duration::from_secs(60),
            Arc::new(AtomicUsize::new(0)),
        )
        .expect("sparse flow table");
        for source_port in 10_000..10_003 {
            assert!(stack.admit_tcp(
                super::TcpTuple {
                    source: SocketAddr::from((Ipv4Addr::new(198, 18, 0, 2), source_port,)),
                    target: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 443)),
                },
                true,
            ));
        }
        assert_eq!(stack.next_flow_cursor, Some(0));
        for expected in [Some(1), Some(2), Some(0), Some(1)] {
            assert!(!stack.drive_tcp(), "idle listeners do not invent work");
            assert_eq!(
                stack.next_flow_cursor, expected,
                "each active flow gets the first visit in turn"
            );
        }
        assert_eq!(stack.live_tcp_flows(), 3);
        assert_eq!(stack.flow_index.len(), 3);
        assert_eq!(stack.free_flow_slots.len(), 61);

        for slot in [0, 1, 2] {
            drop(
                stack.flows[slot]
                    .as_mut()
                    .expect("live flow")
                    .pending
                    .take(),
            );
        }
        assert!(stack.drive_tcp());
        assert_eq!(stack.reap_tcp(), 3, "one live snapshot reaps every flow");
        assert_eq!(stack.live_tcp_flows(), 0);
        assert!(stack.flow_index.is_empty());
        assert_eq!(stack.free_flow_slots.len(), 64);
        assert_eq!(stack.active_flow_head, None);
        assert_eq!(stack.active_flow_tail, None);
        assert_eq!(stack.next_flow_cursor, None);
        assert_eq!(stack.next_reap_cursor, None);
    }

    #[test]
    fn tcp_reap_uses_a_bounded_rotating_cursor() {
        let flow_total = super::TCP_REAP_QUANTUM * 2 + 3;
        let (mut stack, _flows) = Stack::new(
            (
                Ipv4Addr::new(198, 18, 0, 2),
                30,
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                126,
            ),
            1420,
            flow_total,
            4096,
            Duration::from_secs(60),
            Arc::new(AtomicUsize::new(0)),
        )
        .expect("bounded reap stack");
        for offset in 0..flow_total {
            let source_port = 10_000 + u16::try_from(offset).expect("test port offset");
            assert!(stack.admit_tcp(
                super::TcpTuple {
                    source: SocketAddr::from((Ipv4Addr::new(198, 18, 0, 1), source_port)),
                    target: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 443)),
                },
                true,
            ));
            drop(
                stack.flows[offset]
                    .as_mut()
                    .expect("admitted flow")
                    .pending
                    .take(),
            );
        }
        assert!(stack.drive_tcp(), "dropped bridges abort every socket");

        assert_eq!(stack.reap_tcp(), super::TCP_REAP_QUANTUM);
        assert_eq!(
            stack.next_reap_cursor,
            Some(super::TCP_REAP_QUANTUM),
            "cleanup resumes after the bounded first slice"
        );
        assert_eq!(stack.live_tcp_flows(), super::TCP_REAP_QUANTUM + 3);
        assert_eq!(stack.reap_tcp(), super::TCP_REAP_QUANTUM);
        assert_eq!(stack.live_tcp_flows(), 3);
        assert_eq!(stack.reap_tcp(), 3);
        assert_eq!(stack.live_tcp_flows(), 0);
        assert_eq!(stack.next_reap_cursor, None);
        assert_eq!(stack.free_flow_slots.len(), flow_total);
    }

    #[test]
    fn configured_ipv4_directed_broadcast_never_reaches_tcp_or_udp_admission() {
        let flow_count = Arc::new(AtomicUsize::new(0));
        let (mut stack, mut flows, mut candidates) = Stack::new_with_udp(
            (
                Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
                Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
            ),
            1420,
            1,
            4096,
            Duration::from_secs(60),
            Arc::clone(&flow_count),
            OwnerRegistry::new(),
            1,
            Duration::from_secs(60),
            UdpFiltering::AddressDependent,
            1,
            OwnerWake::default(),
        )
        .expect("directed-broadcast stack");
        let observed = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&observed);
        stack.set_event_sink(TunEventSink::new(move |event| {
            captured.lock().expect("TUN events").push(event);
        }));

        let retarget = |packet: &mut [u8], destination: Ipv4Addr, protocol: u8| {
            packet[12..16].copy_from_slice(&Ipv4Addr::new(198, 18, 0, 2).octets());
            packet[16..20].copy_from_slice(&destination.octets());
            crate::packet::test_support::repair_transport_checksum(packet, 20, protocol);
            repair_ipv4_header(packet);
        };

        let mut broadcast_udp = ipv4_udp();
        retarget(&mut broadcast_udp, Ipv4Addr::new(198, 18, 0, 3), 17);
        assert!(!stack.enqueue_at(&broadcast_udp, true, 0));
        assert_eq!(stack.udp.provisional_candidates(), 0);
        assert_eq!(stack.udp.active_associations(), 0);
        assert!(candidates.try_recv().is_err());

        let mut broadcast_tcp = ipv4_tcp();
        retarget(&mut broadcast_tcp, Ipv4Addr::new(198, 18, 0, 3), 6);
        assert!(!stack.enqueue_at(&broadcast_tcp, true, 0));
        assert_eq!(stack.live_tcp_flows(), 0);
        assert_eq!(flow_count.load(Ordering::Acquire), 0);
        assert_eq!(stack.pending(), 0);
        assert!(flows.try_recv().is_err());
        assert_eq!(
            observed
                .lock()
                .expect("TUN events")
                .iter()
                .filter(|event| {
                    **event == TunEvent::PacketRejected(TunRejectReason::InvalidDestination)
                })
                .count(),
            2
        );

        let mut unicast_udp = ipv4_udp();
        retarget(&mut unicast_udp, Ipv4Addr::new(198, 18, 0, 1), 17);
        assert!(stack.enqueue_at(&unicast_udp, true, 1));
        let candidate = candidates.try_recv().expect("unicast UDP candidate");
        assert_eq!(
            candidate.first_target(),
            SocketAddr::from((Ipv4Addr::new(198, 18, 0, 1), 53))
        );

        let mut unicast_tcp = ipv4_tcp();
        retarget(&mut unicast_tcp, Ipv4Addr::new(198, 18, 0, 1), 6);
        assert!(stack.enqueue_at(&unicast_tcp, true, 1));
        assert_eq!(stack.live_tcp_flows(), 1);
        assert_eq!(flow_count.load(Ordering::Acquire), 1);
        assert_eq!(stack.pending(), 1);
    }

    #[tokio::test]
    async fn tcp_handshake_publishes_once_and_preserves_both_byte_directions() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let registry = OwnerRegistry::new();
        let (mut stack, mut flows, _datagrams) = Stack::new_with_udp(
            (
                Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
                Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
            ),
            1420,
            1,
            4096,
            Duration::from_secs(60),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            registry.clone(),
            1,
            Duration::from_secs(60),
            UdpFiltering::AddressDependent,
            0,
            OwnerWake::default(),
        )
        .expect("bounded stack");
        assert_eq!(registry.snapshot().active_tun_tcp_flows, 0);
        assert!(stack.enqueue(&ipv4_tcp(), true));
        assert_eq!(registry.snapshot().active_tun_tcp_flows, 1);
        assert_eq!(
            stack.poll_quantum(Instant::ZERO),
            0,
            "TCP is not a foundation drop"
        );
        let mut syn_ack = Vec::new();
        assert_eq!(
            stack.flush_output(|packet| {
                syn_ack.extend_from_slice(packet);
                OutputSendOutcome::Sent
            }),
            OutputFlushOutcome::Sent
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
            stack.flush_output(|_| OutputSendOutcome::Sent),
            OutputFlushOutcome::Fatal,
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
        assert_eq!(
            registry.snapshot().active_tun_tcp_flows,
            1,
            "the production Stack entry owns the pressured flow"
        );
        assert_eq!(bridge_capacity, 4096, "bridge uses tcp_buffer_bytes");
        let mut observed = vec![0_u8; bridge_capacity + 17];
        let first = stack.flows[0]
            .as_mut()
            .expect("live flow")
            .owner
            .read_to_stack(&mut observed[..bridge_capacity]);
        assert_eq!(first, bridge_capacity);
        overflow.await.expect("released bridge write");
        let second = stack.flows[0]
            .as_mut()
            .expect("live flow")
            .owner
            .read_to_stack(&mut observed[bridge_capacity..]);
        assert_eq!(second, 17);
        assert_eq!(observed, outbound, "full bridge drains without byte loss");

        drop(flow);
        stack.poll_quantum(Instant::from_millis(3));
        let mut reset = false;
        assert_eq!(
            stack.flush_output(|packet| {
                reset = packet[33] & 0x04 != 0;
                OutputSendOutcome::Sent
            }),
            OutputFlushOutcome::Sent
        );
        assert!(reset, "terminal drop emits a local TCP reset");
        assert_eq!(stack.live_tcp_flows(), 0);
        assert_eq!(registry.snapshot().active_tun_tcp_flows, 0);
        assert!(stack.enqueue(&ipv4_tcp(), true));
        assert_eq!(registry.snapshot().active_tun_tcp_flows, 1);
        assert_eq!(
            stack.flows[0]
                .as_ref()
                .expect("reused slot")
                .generation
                .generation,
            1,
            "reused tuples receive a new generation"
        );
        drop(stack);
        assert_eq!(
            registry.snapshot().active_tun_tcp_flows,
            0,
            "dropping Stack releases the production flow guard"
        );
    }

    #[tokio::test]
    async fn established_rst_packet_surfaces_connection_reset_to_the_application() {
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
            Arc::new(AtomicUsize::new(0)),
        )
        .expect("RST packet-path stack");
        let (mut flow, syn_ack) = establish_ipv4_tcp_flow(&mut stack, &mut flows, 10_000, 0);

        let rst = ipv4_tcp_after_syn(&syn_ack, 0x14, &[]);
        assert!(stack.enqueue(&rst, true));
        stack.poll_quantum(Instant::from_millis(2));

        let read_error = flow
            .read(&mut [0_u8; 1])
            .await
            .expect_err("an established RST is not EOF");
        assert_eq!(read_error.kind(), std::io::ErrorKind::ConnectionReset);
        let write_error = flow
            .write_all(b"after reset")
            .await
            .expect_err("an established RST rejects application writes");
        assert_eq!(write_error.kind(), std::io::ErrorKind::ConnectionReset);
        assert_eq!(stack.live_tcp_flows(), 0, "reset socket is reaped");
    }

    #[tokio::test]
    async fn tcp_drive_skips_blocked_flow_and_rotates_across_active_flows() {
        const FLOW_TOTAL: usize = 20;
        const BUFFER_BYTES: usize = 16 * 1024;
        let (mut stack, mut flows) = Stack::new(
            (
                Ipv4Addr::new(198, 18, 0, 2),
                30,
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                126,
            ),
            1420,
            FLOW_TOTAL,
            BUFFER_BYTES,
            Duration::from_secs(60),
            Arc::new(AtomicUsize::new(0)),
        )
        .expect("multi-flow fairness stack");
        let mut application_flows = Vec::with_capacity(FLOW_TOTAL);
        let mut syn_acks = Vec::with_capacity(FLOW_TOTAL);
        for offset in 0..FLOW_TOTAL {
            let (flow, syn_ack) = establish_ipv4_tcp_flow(
                &mut stack,
                &mut flows,
                10_000 + u16::try_from(offset).expect("test port offset"),
                i64::try_from(offset * 2).expect("test time"),
            );
            application_flows.push(flow);
            syn_acks.push(syn_ack);
        }

        let blocked_fill = vec![0x41; BUFFER_BYTES];
        assert_eq!(
            stack.flows[0]
                .as_mut()
                .expect("blocked flow")
                .owner
                .write_from_stack(&blocked_fill),
            BUFFER_BYTES
        );
        assert!(stack.enqueue(&ipv4_tcp_after_syn(&syn_acks[0], 0x18, b"blocked"), true));
        stack.poll_quantum(Instant::from_millis(100));
        assert!(matches!(
            stack.flush_output(|_| OutputSendOutcome::Sent),
            OutputFlushOutcome::Empty | OutputFlushOutcome::Sent
        ));

        let outbound = vec![0x5a; BUFFER_BYTES];
        for flow in application_flows.iter_mut().skip(1) {
            flow.write_all(&outbound)
                .await
                .expect("fill active flow bridge");
        }
        stack.next_flow_cursor = Some(0);
        assert!(stack.drive_tcp());
        assert_eq!(
            stack.flows[0]
                .as_ref()
                .expect("blocked flow")
                .owner
                .application_capacity(),
            0,
            "a blocked receive flow is skipped without consuming the byte budget"
        );
        for slot in 1..=16 {
            assert_eq!(
                stack.flows[slot]
                    .as_ref()
                    .expect("active flow")
                    .owner
                    .stack_buffered(),
                0,
                "the first quantum serves active slot {slot}"
            );
        }
        for slot in 17..FLOW_TOTAL {
            assert_eq!(
                stack.flows[slot]
                    .as_ref()
                    .expect("deferred flow")
                    .owner
                    .stack_buffered(),
                BUFFER_BYTES,
                "the global byte quantum defers slot {slot}"
            );
        }
        assert_eq!(stack.next_flow_cursor, Some(17));

        assert!(stack.drive_tcp());
        for slot in 1..FLOW_TOTAL {
            assert_eq!(
                stack.flows[slot]
                    .as_ref()
                    .expect("active flow")
                    .owner
                    .stack_buffered(),
                0,
                "the rotating cursor reaches slot {slot}"
            );
        }
    }

    #[tokio::test]
    async fn tcp_drive_alternates_rx_and_tx_at_the_262144_byte_buffer_limit() {
        const BUFFER_BYTES: usize = 262_144;
        const PAYLOAD_BYTES: usize = 1300;
        const SEGMENTS: usize = 28;
        const PER_FLOW_QUANTUM: usize = 16 * 1024;
        let (mut stack, mut flows) = Stack::new(
            (
                Ipv4Addr::new(198, 18, 0, 2),
                30,
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                126,
            ),
            1420,
            1,
            BUFFER_BYTES,
            Duration::from_secs(60),
            Arc::new(AtomicUsize::new(0)),
        )
        .expect("maximum TCP buffer stack");
        let (mut flow, syn_ack) = establish_ipv4_tcp_flow(&mut stack, &mut flows, 10_000, 0);
        assert_eq!(stack.bridge_capacity, BUFFER_BYTES);

        let application_fill = vec![0x41; BUFFER_BYTES];
        assert_eq!(
            stack.flows[0]
                .as_mut()
                .expect("live flow")
                .owner
                .write_from_stack(&application_fill),
            BUFFER_BYTES,
            "the configured maximum is the actual receive bridge capacity"
        );
        let payload = vec![0x33; PAYLOAD_BYTES];
        let mut sequence = 1_u32;
        for segment in 0..SEGMENTS {
            let mut packet = ipv4_tcp_after_syn(&syn_ack, 0x18, &payload);
            packet[24..28].copy_from_slice(&sequence.to_be_bytes());
            repair_ipv4_tcp_checksum(&mut packet);
            assert!(stack.enqueue(&packet, true));
            stack.poll_quantum(Instant::from_millis(2 + segment as i64));
            assert!(matches!(
                stack.flush_output(|_| OutputSendOutcome::Sent),
                OutputFlushOutcome::Empty | OutputFlushOutcome::Sent
            ));
            sequence = sequence.wrapping_add(PAYLOAD_BYTES as u32);
        }

        let mut drained_fill = vec![0_u8; BUFFER_BYTES];
        flow.read_exact(&mut drained_fill)
            .await
            .expect("release the maximum receive bridge");
        assert_eq!(drained_fill, application_fill);
        let outbound = vec![0x5a; PER_FLOW_QUANTUM * 2];
        flow.write_all(&outbound)
            .await
            .expect("queue simultaneous application output");

        assert!(stack.drive_tcp(), "first turn services sustained RX");
        assert_eq!(
            stack.flows[0]
                .as_ref()
                .expect("live flow")
                .owner
                .stack_buffered(),
            outbound.len(),
            "RX may use one shared per-flow quantum"
        );
        assert!(stack.drive_tcp(), "second turn services TX");
        assert_eq!(
            stack.flows[0]
                .as_ref()
                .expect("live flow")
                .owner
                .stack_buffered(),
            PER_FLOW_QUANTUM,
            "sustained RX cannot consume the next TX-priority quantum"
        );
    }

    #[tokio::test]
    async fn blocked_tcp_handler_does_not_make_the_owner_busy_loop() {
        const BUFFER_BYTES: usize = 4096;
        let (mut stack, mut flows) = Stack::new(
            (
                Ipv4Addr::new(198, 18, 0, 2),
                30,
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                126,
            ),
            1420,
            1,
            BUFFER_BYTES,
            Duration::from_secs(60),
            Arc::new(AtomicUsize::new(0)),
        )
        .expect("blocked handler stack");
        let (_flow, syn_ack) = establish_ipv4_tcp_flow(&mut stack, &mut flows, 10_000, 0);
        assert_eq!(
            stack.flows[0]
                .as_mut()
                .expect("live flow")
                .owner
                .write_from_stack(&vec![0x41; BUFFER_BYTES]),
            BUFFER_BYTES
        );
        assert!(stack.enqueue(&ipv4_tcp_after_syn(&syn_ack, 0x18, b"blocked"), true));
        stack.poll_quantum(Instant::from_millis(2));
        assert!(matches!(
            stack.flush_output(|_| OutputSendOutcome::Sent),
            OutputFlushOutcome::Empty | OutputFlushOutcome::Sent
        ));

        for _ in 0..32 {
            assert!(
                !stack.poll_stack_once(Instant::from_millis(2)).worked,
                "a handler that neither reads nor writes creates no owner work"
            );
            assert!(
                stack.next_wait_duration(2) > Duration::ZERO,
                "blocked bridge state preserves a protocol deadline wait"
            );
        }
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
            stack.flush_output(|packet| {
                syn_ack.extend_from_slice(packet);
                OutputSendOutcome::Sent
            }),
            OutputFlushOutcome::Sent
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
            stack.flush_output(|packet| {
                reset |= packet[33] & 0x04 != 0;
                OutputSendOutcome::Sent
            }),
            OutputFlushOutcome::Fatal
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
        assert!(stack.drive_tcp(), "owner drains the reply and requests FIN");
        assert!(
            stack.flows[0].as_ref().expect("live flow").fin_started,
            "the socket close request is recorded"
        );
        assert!(!stack.has_output(), "socket.close itself emits no packet");
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut shutdown)
                .await
                .is_err(),
            "shutdown remains pending between socket.close and FIN egress"
        );
        assert!(
            stack.poll_stack_once(Instant::from_millis(3)).worked,
            "smoltcp emits the queued reply and FIN"
        );
        assert_eq!(
            stack.flush_output(|_| OutputSendOutcome::DroppedRingFull),
            OutputFlushOutcome::DroppedRingFull
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut shutdown)
                .await
                .is_err(),
            "a ring-full FIN drop cannot complete shutdown"
        );

        assert!(
            stack.poll_stack_once(Instant::from_millis(1_004)).worked,
            "smoltcp retransmits the dropped reply and FIN"
        );
        let mut reply_fin = Vec::new();
        assert_eq!(
            stack.flush_output(|packet| {
                reply_fin.extend_from_slice(packet);
                OutputSendOutcome::Sent
            }),
            OutputFlushOutcome::Sent
        );
        tokio::time::timeout(Duration::from_millis(10), &mut shutdown)
            .await
            .expect("successful adapter FIN send wakes shutdown")
            .expect("shutdown succeeds only after the adapter accepts FIN");
        assert_eq!(&reply_fin[40..], reply);
        assert_ne!(reply_fin[33] & 0x01, 0, "reply carries local FIN");
        assert_eq!(reply_fin[33] & 0x04, 0, "reply carries no reset");

        stack.poll_quantum(Instant::from_millis(3_005));
        let mut retransmission = Vec::new();
        assert_eq!(
            stack.flush_output(|packet| {
                retransmission.extend_from_slice(packet);
                OutputSendOutcome::Sent
            }),
            OutputFlushOutcome::Sent
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
        stack.poll_quantum(Instant::from_millis(3_006));
        reset = false;
        assert_eq!(
            stack.flush_output(|packet| {
                reset |= packet[33] & 0x04 != 0;
                OutputSendOutcome::Sent
            }),
            OutputFlushOutcome::Empty
        );
        assert!(!reset, "final ACK produces no reset");
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
        stack.poll_quantum(Instant::from_millis(3_007));
        assert_eq!(
            stack.flush_output(|_| OutputSendOutcome::Sent),
            OutputFlushOutcome::Empty,
            "dropping a completed flow does not abort"
        );
    }

    #[tokio::test]
    async fn tcp_shutdown_waits_through_fatal_egress_until_session_reset() {
        use tokio::io::AsyncWriteExt;

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
        .expect("fatal egress stack");
        let (mut flow, _) = establish_ipv4_tcp_flow(&mut stack, &mut flows, 10_001, 0);
        let mut shutdown = Box::pin(flow.shutdown());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut shutdown)
                .await
                .is_err(),
            "shutdown waits for the owner"
        );
        assert!(stack.drive_tcp(), "owner requests a local FIN");
        assert!(
            stack.poll_stack_once(Instant::from_millis(2)).worked,
            "smoltcp emits the local FIN"
        );
        assert_eq!(
            stack.flush_output(|_| OutputSendOutcome::Fatal),
            OutputFlushOutcome::Fatal
        );
        assert!(
            stack.has_output(),
            "fatal egress retains the pending packet"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut shutdown)
                .await
                .is_err(),
            "fatal egress cannot report the FIN as sent"
        );

        assert_eq!(
            stack.quiesce(1, UdpResponseDropReason::SessionReset),
            1,
            "session reset reaps the live flow"
        );
        let error = tokio::time::timeout(Duration::from_millis(10), &mut shutdown)
            .await
            .expect("session reset wakes shutdown")
            .expect_err("session reset is not a successful shutdown");
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        assert!(!stack.has_output(), "session reset clears the fatal output");
        assert_eq!(flow_count.load(Ordering::Acquire), 0);
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
        assert_eq!(
            stack.flush_output(|_| OutputSendOutcome::Sent),
            OutputFlushOutcome::Sent
        );
        stack.poll_quantum(Instant::from_millis(1_001));
        assert_eq!(stack.live_tcp_flows(), 0, "half-open flow timed out");
        assert_eq!(flow_count.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn fragmented_udp_reaches_admission_only_after_out_of_order_reassembly() {
        let (first, second) = ipv4_udp_fragments();
        let (mut stack, _flows, mut candidates) = Stack::new_with_udp(
            (
                Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
                Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
            ),
            1420,
            1,
            4096,
            Duration::from_secs(60),
            Arc::new(AtomicUsize::new(0)),
            OwnerRegistry::new(),
            1,
            Duration::from_secs(60),
            UdpFiltering::AddressDependent,
            0,
            OwnerWake::default(),
        )
        .expect("UDP stack");

        assert!(stack.enqueue_at(&second, true, 1));
        assert!(matches!(
            candidates.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        assert!(stack.enqueue_at(&first, true, 2));
        let candidate = candidates.try_recv().expect("reassembled candidate");
        assert_eq!(candidate.payload(), &[0, 1, 2, 3]);
    }

    #[tokio::test]
    async fn atomic_ipv6_fragment_normalization_emits_no_reassembly_lifecycle_events() {
        let original = ipv6_udp();
        let mut atomic = original[..40].to_vec();
        atomic[4..6].copy_from_slice(
            &u16::try_from(original.len() - 40 + 8)
                .unwrap()
                .to_be_bytes(),
        );
        atomic[6] = 44;
        atomic.extend_from_slice(&[17, 0, 0, 0]);
        atomic.extend_from_slice(&99_u32.to_be_bytes());
        atomic.extend_from_slice(&original[40..]);

        let (mut stack, _flows, mut candidates) = Stack::new_with_udp(
            (
                Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
                Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
            ),
            1420,
            1,
            4096,
            Duration::from_secs(60),
            Arc::new(AtomicUsize::new(0)),
            OwnerRegistry::new(),
            1,
            Duration::from_secs(60),
            UdpFiltering::AddressDependent,
            0,
            OwnerWake::default(),
        )
        .expect("UDP stack");
        let observed = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&observed);
        stack.set_event_sink(TunEventSink::new(move |event| {
            captured.lock().expect("TUN events").push(event);
        }));

        assert!(stack.enqueue_at(&atomic, true, 0));
        assert_eq!(
            candidates
                .try_recv()
                .expect("normalized UDP candidate")
                .payload(),
            b"test"
        );
        assert_eq!(stack.reassembly.len(), 0);
        let reassembly_events = observed
            .lock()
            .expect("TUN events")
            .iter()
            .copied()
            .filter(|event| {
                matches!(
                    event,
                    TunEvent::ReassemblyEntriesActive(_)
                        | TunEvent::ReassemblyStarted
                        | TunEvent::ReassemblyCompleted
                        | TunEvent::ReassemblyDroppedOverlap
                        | TunEvent::ReassemblyDroppedTimeout
                        | TunEvent::ReassemblyDroppedLimit
                        | TunEvent::ReassemblyDroppedMalformed
                )
            })
            .collect::<Vec<_>>();
        assert!(
            reassembly_events.is_empty(),
            "atomic normalization is not a reassembly lifecycle: {reassembly_events:?}"
        );
    }

    #[test]
    fn fragment_admission_reports_expiration_and_replacement_at_equal_active_count() {
        let (first, _) = ipv4_udp_fragments();
        let mut replacement = first.clone();
        replacement[4..6].copy_from_slice(&8_u16.to_be_bytes());
        replacement[10..12].fill(0);
        let replacement_checksum = checksum(&[&replacement[..20]]);
        replacement[10..12].copy_from_slice(&replacement_checksum.to_be_bytes());

        let (mut stack, _flows, _candidates) = Stack::new_with_udp(
            (
                Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
                Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
            ),
            1420,
            1,
            4096,
            Duration::from_secs(60),
            Arc::new(AtomicUsize::new(0)),
            OwnerRegistry::new(),
            1,
            Duration::from_secs(60),
            UdpFiltering::AddressDependent,
            0,
            OwnerWake::default(),
        )
        .expect("UDP stack");
        let observed = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&observed);
        stack.set_event_sink(TunEventSink::new(move |event| {
            captured.lock().expect("TUN events").push(event);
        }));

        assert!(stack.enqueue_at(&first, true, 0));
        observed.lock().expect("TUN events").clear();
        assert!(stack.enqueue_at(&replacement, true, REASSEMBLY_TIMEOUT_MILLIS));

        assert_eq!(
            *observed.lock().expect("TUN events"),
            [
                TunEvent::ReassemblyDroppedTimeout,
                TunEvent::PacketRejected(TunRejectReason::FragmentTimeout),
                TunEvent::ReassemblyStarted,
                TunEvent::ReassemblyEntriesActive(1),
            ]
        );
        assert_eq!(stack.reassembly.len(), 1);
    }

    #[tokio::test]
    async fn reassembled_udp_larger_than_mtu_reaches_one_eim_association() {
        const MTU: usize = 1_280;
        let payload = vec![0x5a; 2_000];
        let cases = [
            (
                fragment_ipv4_udp(&crate::packet::test_support::ipv4_udp(&payload, &[]), MTU),
                MTU - 28,
            ),
            (
                fragment_ipv6_udp(&crate::packet::test_support::ipv6_udp(&payload), MTU),
                MTU - 48,
            ),
        ];

        for (fragments, response_payload_bound) in cases {
            assert!(fragments.iter().all(|fragment| fragment.len() <= MTU));
            let (mut stack, _flows, mut candidates) = Stack::new_with_udp(
                (
                    Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
                    Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
                ),
                MTU,
                1,
                4096,
                Duration::from_secs(60),
                Arc::new(AtomicUsize::new(0)),
                OwnerRegistry::new(),
                1,
                Duration::from_secs(60),
                UdpFiltering::AddressDependent,
                0,
                OwnerWake::default(),
            )
            .expect("UDP stack");

            for fragment in fragments.iter().rev() {
                assert!(stack.enqueue_at(fragment, true, 1));
            }
            let candidate = candidates.try_recv().expect("reassembled candidate");
            assert_eq!(candidate.payload(), payload);
            assert_eq!(candidate.packet_payload_bound(), response_payload_bound);
            let commit = tokio::spawn(candidate.commit_association());
            tokio::task::yield_now().await;
            assert_eq!(stack.poll_udp_events(2, true).committed, 1);
            let mut association = commit.await.unwrap().expect("association commit");
            assert_eq!(
                association
                    .receive()
                    .await
                    .expect("first datagram")
                    .payload(),
                payload
            );
        }
    }

    #[tokio::test]
    async fn udp_ipv4_ipv6_candidates_commit_and_inject_through_the_real_stack() {
        for (packet, expected_source, expected_target, response) in [
            (
                ipv4_udp(),
                "198.18.0.1:10000".parse().expect("IPv4 source"),
                "192.0.2.1:53".parse().expect("IPv4 target"),
                b"v4".as_slice(),
            ),
            (
                ipv6_udp(),
                "[::2]:10000".parse().expect("IPv6 source"),
                "[2001:db8::1]:53".parse().expect("IPv6 target"),
                b"v6".as_slice(),
            ),
        ] {
            let (mut stack, _flows, mut candidates) = Stack::new_with_udp(
                (
                    Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
                    Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
                ),
                1420,
                1,
                4096,
                Duration::from_secs(60),
                Arc::new(AtomicUsize::new(0)),
                OwnerRegistry::new(),
                1,
                Duration::from_secs(60),
                UdpFiltering::AddressDependent,
                0,
                OwnerWake::default(),
            )
            .expect("UDP stack");
            assert!(stack.enqueue_at(&packet, true, 0));
            assert_eq!(
                stack.live_udp_associations(),
                0,
                "provisional is not active"
            );
            let candidate = candidates.try_recv().expect("candidate");
            assert_eq!(candidate.tuple().source(), expected_source);
            assert_eq!(candidate.tuple().target(), expected_target);
            assert_eq!(candidate.payload(), &packet[packet.len() - 4..]);
            let commit = tokio::spawn(candidate.commit_association());
            tokio::task::yield_now().await;
            assert_eq!(stack.poll_udp_events(1, true).committed, 1);
            let mut mapping = commit.await.expect("commit task").expect("mapping");
            assert_eq!(
                mapping.receive().await.expect("first datagram").payload(),
                &packet[packet.len() - 4..]
            );
            assert!(matches!(
                mapping.authorize_peer(expected_target.ip()),
                UdpPeerAuthorization::Authorized
                    | UdpPeerAuthorization::AlreadyAuthorized
                    | UdpPeerAuthorization::NotRequired
            ));
            assert_eq!(
                mapping.send_response(expected_target, response),
                crate::UdpResponseSendOutcome::Queued
            );
            assert_eq!(stack.poll_udp_events(2, true).injected, 1);
            let mut emitted = Vec::new();
            assert_eq!(
                stack.flush_output(|packet| {
                    emitted.extend_from_slice(packet);
                    OutputSendOutcome::Sent
                }),
                OutputFlushOutcome::Sent
            );
            assert!(PacketValidator::new(1420).accepts(&emitted));
            let (reverse, payload, _) = crate::udp_datagram(&emitted, 1420).expect("UDP response");
            assert_eq!(reverse.source(), expected_target);
            assert_eq!(reverse.target(), expected_source);
            assert_eq!(payload, response);
        }
    }

    #[tokio::test]
    async fn session_quiesce_resets_tcp_invalidates_udp_and_discards_packet_state() {
        let flow_count = Arc::new(AtomicUsize::new(0));
        let (mut stack, _flows, mut candidates) = Stack::new_with_udp(
            (
                Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
                Some((Ipv6Addr::LOCALHOST, 128)),
            ),
            1420,
            2,
            4096,
            Duration::from_secs(60),
            Arc::clone(&flow_count),
            OwnerRegistry::new(),
            2,
            Duration::from_secs(60),
            UdpFiltering::AddressDependent,
            7,
            OwnerWake::default(),
        )
        .expect("restart test stack");
        assert!(stack.enqueue_at(&ipv4_tcp(), true, 0));
        let mut old_flow = stack
            .flows
            .iter_mut()
            .flatten()
            .next()
            .and_then(|entry| entry.pending.take())
            .expect("old-generation TCP flow");
        assert_eq!(flow_count.load(Ordering::Acquire), 1);

        let tuple = UdpTuple::new(
            "198.18.0.1:20000".parse().expect("source"),
            "192.0.2.9:53".parse().expect("target"),
        );
        assert_ne!(
            stack.udp.admit(tuple, b"request", 128, 0, true),
            super::UdpAdmission::Dropped
        );
        let candidate = candidates.try_recv().expect("old-generation candidate");
        stack.device.output_len = 1;
        assert!(stack.pending() != 0 && stack.has_output());

        assert_eq!(stack.quiesce(8, UdpResponseDropReason::SessionReset), 1);
        assert_eq!(
            stack.quiesce(8, UdpResponseDropReason::SessionReset),
            0,
            "quiesce is idempotent"
        );
        assert_eq!(flow_count.load(Ordering::Acquire), 0);
        assert_eq!(stack.live_tcp_flows(), 0);
        assert_eq!(stack.live_udp_associations(), 0);
        assert_eq!(stack.pending(), 0);
        assert!(!stack.has_output());
        assert_eq!(
            old_flow
                .write(b"stale")
                .await
                .expect_err("old flow is reset")
                .kind(),
            std::io::ErrorKind::ConnectionReset
        );
        assert!(matches!(
            candidate.commit_association().await,
            Err(crate::UdpCommitError::Unavailable | crate::UdpCommitError::Rejected)
        ));
    }

    #[test]
    fn stack_routes_are_exact_and_udp_candidates_bypass_foundation_drop() {
        let (mut stack, _flows, mut datagrams) = Stack::new_with_udp(
            (
                Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
                Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
            ),
            1420,
            8,
            4096,
            Duration::from_secs(60),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            OwnerRegistry::new(),
            1,
            Duration::from_secs(60),
            UdpFiltering::AddressDependent,
            0,
            OwnerWake::default(),
        )
        .expect("bounded stack");
        assert!(stack.has_exact_routes());
        let packet = ipv4_udp();
        assert!(
            stack.enqueue(&packet, true),
            "first UDP packet becomes a provisional candidate"
        );
        assert!(
            stack.enqueue(&packet, true),
            "a pending candidate queues subsequent datagrams without another mapping"
        );
        let _candidate = datagrams.try_recv().expect("one source candidate");
        assert!(matches!(
            datagrams.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        assert_eq!(stack.poll_quantum(Instant::ZERO), 0);
        assert_eq!(stack.pending(), 0);
        assert_eq!(
            stack.discarded_packets(),
            0,
            "T05 UDP no longer reaches the foundation drop"
        );

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

    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn wintun_error_kinds_have_exact_owner_dispositions() {
        for (kind, expected) in [
            (
                ferrum2_wintun::ErrorKind::RecoverableSession,
                AdapterErrorDisposition::RestartSession,
            ),
            (
                ferrum2_wintun::ErrorKind::InvalidInput,
                AdapterErrorDisposition::RuntimeFailed,
            ),
            (
                ferrum2_wintun::ErrorKind::UnrecoverableCorruption,
                AdapterErrorDisposition::RuntimeFailed,
            ),
            (
                ferrum2_wintun::ErrorKind::Cleanup,
                AdapterErrorDisposition::CleanupFailed,
            ),
        ] {
            assert_eq!(
                classify_adapter_error(ferrum2_wintun::Error::new(kind)),
                expected,
                "owner classification for {kind:?}"
            );
        }
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
                    shutdown: Arc::new(AtomicBool::new(false)),
                    active,
                    admitting: Arc::new(AtomicBool::new(false)),
                    #[cfg(all(windows, target_arch = "x86_64"))]
                    flow_count: Arc::new(AtomicUsize::new(0)),
                    #[cfg(all(windows, target_arch = "x86_64"))]
                    association_count: Arc::new(AtomicUsize::new(0)),
                },
                work: OwnerWake::default(),
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
                shutdown: Arc::new(AtomicBool::new(false)),
                active: Arc::new(AtomicBool::new(false)),
                admitting: Arc::new(AtomicBool::new(false)),
                #[cfg(all(windows, target_arch = "x86_64"))]
                flow_count: Arc::new(AtomicUsize::new(0)),
                #[cfg(all(windows, target_arch = "x86_64"))]
                association_count: Arc::new(AtomicUsize::new(0)),
            },
            work: OwnerWake::default(),
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
        use ferrum2_runtime::{OwnerRegistry, ProcessCause, ProcessRootExit, ProcessSupervisor};

        let (_session_handle, session) =
            super::supervisor::session_cancellation(1, OwnerWake::default());
        let (flow_sender, flow_receiver) = tokio::sync::mpsc::channel(2);
        let (_udp, datagram_receiver) =
            tokio::sync::mpsc::channel::<SessionItem<crate::UdpCandidate>>(1);
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
        let registry = OwnerRegistry::new();
        let root_registry = registry.clone();
        let root = ferrum2_runtime::ProcessRoot::new(move || async move {
            Ok::<_, &'static str>(TunRoot {
                owner: OwnerThread {
                    control,
                    work: OwnerWake::default(),
                    thread: Some(thread),
                },
                done: done_receiver,
                runtime: Some("runtime"),
                cleanup: Some("cleanup"),
                flows: flow_receiver,
                datagrams: datagram_receiver,
                flow_count: Arc::new(AtomicUsize::new(0)),
                association_count: Arc::new(AtomicUsize::new(0)),
                registry: root_registry,
                handle_tcp: Arc::new(move |flow, _, _| {
                    let calls = Arc::clone(&handler_calls);
                    Box::pin(async move {
                        drop(flow);
                        if calls.fetch_add(1, Ordering::SeqCst) == 32 {
                            panic!("injected TUN TCP handler panic");
                        }
                    })
                }),
                handle_udp: Arc::new(|_: crate::UdpCandidate, _, _| Box::pin(async {})),
            })
        });
        let supervisor =
            ProcessSupervisor::new(vec![root], Duration::from_secs(1), registry.clone())
                .expect("one TUN root");
        let run = tokio::spawn(supervisor.run_until(std::future::pending::<()>()));
        while !active.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        for port in 10_000..10_033 {
            let (flow, _owner) =
                tcp_flow_pair(SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), port)), 4);
            flow_sender
                .send(SessionItem {
                    value: flow,
                    cancellation: session.clone(),
                })
                .await
                .expect("bounded handler churn");
        }
        let report = run.await.expect("process report");
        assert_eq!(calls.load(Ordering::SeqCst), 33);
        assert_eq!(registry.snapshot().active_tun_handler_tasks, 0);
        assert!(matches!(
            report.cause(),
            ProcessCause::RootStopped {
                exit: ProcessRootExit::Failed("runtime"),
                ..
            }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn pressured_tcp_flow_survives_quiesce_and_forced_shutdown_reaps_every_owner() {
        use ferrum2_runtime::{
            OwnerRegistry, ProcessCause, ProcessCleanupFailure, ProcessExitKind, ProcessState,
            ProcessSupervisor,
        };

        struct HandlerDrop(Arc<AtomicUsize>);

        impl Drop for HandlerDrop {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        enum FakeOwnerRequest {
            Admit {
                flow: crate::TcpFlow,
                owner: super::tcp::FlowOwner,
                result: std::sync::mpsc::SyncSender<bool>,
            },
        }

        for owner_exit in [OwnerExit::Stopped, OwnerExit::CleanupFailed] {
            let registry = OwnerRegistry::new();
            let owner_registry = registry.clone();
            let root_registry = registry.clone();
            let (session_handle, session) =
                super::supervisor::session_cancellation(1, OwnerWake::default());
            let owner_session = session.clone();
            let (flow_sender, flow_receiver) = tokio::sync::mpsc::channel(2);
            let (_datagram_sender, datagram_receiver) =
                tokio::sync::mpsc::channel::<SessionItem<crate::UdpCandidate>>(1);
            let (owner_requests, requested_admissions) =
                std::sync::mpsc::channel::<FakeOwnerRequest>();
            let control = OwnerControl::new();
            let active = Arc::clone(&control.active);
            let admitting = Arc::clone(&control.admitting);
            let owner_control = control.clone();
            let flow_count = Arc::new(AtomicUsize::new(0));
            let owner_count = Arc::new(AtomicUsize::new(1));
            let owner_saw_aborted_flow = Arc::new(AtomicBool::new(false));
            let owner_flow_count = Arc::clone(&flow_count);
            let remaining_owners = Arc::clone(&owner_count);
            let saw_aborted_flow = Arc::clone(&owner_saw_aborted_flow);
            let (done_sender, done_receiver) = tokio::sync::oneshot::channel();
            let thread = std::thread::spawn(move || {
                let mut owners = Vec::new();
                while !owner_control.stop.load(Ordering::Acquire) {
                    match requested_admissions.try_recv() {
                        Ok(FakeOwnerRequest::Admit {
                            flow,
                            owner,
                            result,
                        }) => {
                            let accepted = owner_control.admitting.load(Ordering::Acquire)
                                && flow_sender
                                    .blocking_send(SessionItem {
                                        value: flow,
                                        cancellation: owner_session.clone(),
                                    })
                                    .is_ok();
                            if accepted {
                                owners.push((owner, owner_registry.track_tun_tcp_flow()));
                                owner_flow_count.fetch_add(1, Ordering::AcqRel);
                            }
                            let _ = result.send(accepted);
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                            std::thread::yield_now();
                        }
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                    }
                }

                let owned_flows = owners.len();
                saw_aborted_flow.store(
                    owned_flows != 0 && owners.iter().all(|(owner, _)| owner.is_aborted()),
                    Ordering::Release,
                );
                drop(owners);
                owner_flow_count.fetch_sub(owned_flows, Ordering::AcqRel);
                remaining_owners.fetch_sub(1, Ordering::AcqRel);
                let _ = done_sender.send(owner_exit);
                owner_exit
            });

            let pressured = Arc::new(tokio::sync::Notify::new());
            let pressure_reported = Arc::new(AtomicBool::new(false));
            let handler_starts = Arc::new(AtomicUsize::new(0));
            let handler_drops = Arc::new(AtomicUsize::new(0));
            let handler_pressured = Arc::clone(&pressured);
            let handler_pressure_reported = Arc::clone(&pressure_reported);
            let recorded_handler_starts = Arc::clone(&handler_starts);
            let recorded_handler_drops = Arc::clone(&handler_drops);
            let root_flow_count = Arc::clone(&flow_count);
            let root = ferrum2_runtime::ProcessRoot::new(move || async move {
                Ok::<_, &'static str>(TunRoot {
                    owner: OwnerThread {
                        control,
                        work: OwnerWake::default(),
                        thread: Some(thread),
                    },
                    done: done_receiver,
                    runtime: Some("runtime"),
                    cleanup: Some("cleanup"),
                    flows: flow_receiver,
                    datagrams: datagram_receiver,
                    flow_count: root_flow_count,
                    association_count: Arc::new(AtomicUsize::new(0)),
                    registry: root_registry,
                    handle_tcp: Arc::new(move |mut flow, _cancellation, _session| {
                        let pressured = Arc::clone(&handler_pressured);
                        let pressure_reported = Arc::clone(&handler_pressure_reported);
                        let starts = Arc::clone(&recorded_handler_starts);
                        let drops = Arc::clone(&recorded_handler_drops);
                        Box::pin(async move {
                            starts.fetch_add(1, Ordering::SeqCst);
                            let _drop = HandlerDrop(drops);
                            flow.write_all(b"full")
                                .await
                                .expect("fill the bounded application-to-stack bridge");
                            let unexpected = std::future::poll_fn(|context| {
                                match tokio::io::AsyncWrite::poll_write(
                                    std::pin::Pin::new(&mut flow),
                                    context,
                                    b"x",
                                ) {
                                    std::task::Poll::Pending => {
                                        if !pressure_reported.swap(true, Ordering::SeqCst) {
                                            pressured.notify_one();
                                        }
                                        std::task::Poll::Pending
                                    }
                                    ready => ready,
                                }
                            })
                            .await;
                            panic!(
                                "pressured flow completed before forced cancellation: {unexpected:?}"
                            );
                        })
                    }),
                    handle_udp: Arc::new(|_: crate::UdpCandidate, _, _| Box::pin(async {})),
                })
            });
            let supervisor =
                ProcessSupervisor::new(vec![root], Duration::from_secs(5), registry.clone())
                    .expect("one TUN root");
            let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
            let run = tokio::spawn(supervisor.run_until(async move {
                let _ = shutdown_receiver.await;
            }));

            for _ in 0..100 {
                if active.load(Ordering::Acquire) {
                    break;
                }
                tokio::task::yield_now().await;
            }
            assert!(active.load(Ordering::Acquire), "TUN root becomes active");

            let admit = |port| {
                let (flow, owner) =
                    tcp_flow_pair(SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), port)), 4);
                let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(0);
                owner_requests
                    .send(FakeOwnerRequest::Admit {
                        flow,
                        owner,
                        result: result_sender,
                    })
                    .expect("fake owner is accepting commands");
                result_receiver.recv().expect("fake owner admission result")
            };
            assert!(admit(10_000), "active TUN owner admits the first flow");
            tokio::time::timeout(Duration::from_secs(1), pressured.notified())
                .await
                .expect("TCP handler reaches real bridge backpressure");
            assert_eq!(handler_starts.load(Ordering::SeqCst), 1);
            assert_eq!(handler_drops.load(Ordering::SeqCst), 0);
            assert_eq!(flow_count.load(Ordering::Acquire), 1);
            assert_eq!(owner_count.load(Ordering::Acquire), 1);
            assert_eq!(registry.snapshot().active_tun_tcp_flows, 1);
            assert_eq!(registry.snapshot().active_tun_handler_tasks, 1);

            shutdown_sender.send(()).expect("request process shutdown");
            for _ in 0..100 {
                if !admitting.load(Ordering::Acquire) {
                    break;
                }
                tokio::task::yield_now().await;
            }
            assert!(
                !admitting.load(Ordering::Acquire),
                "quiescing reaches the fake owner"
            );
            assert!(!admit(10_001), "quiescing rejects a new TCP flow");
            assert_eq!(handler_starts.load(Ordering::SeqCst), 1);
            assert_eq!(flow_count.load(Ordering::Acquire), 1);

            tokio::time::advance(Duration::from_millis(4_999)).await;
            tokio::task::yield_now().await;
            assert!(
                !run.is_finished(),
                "pressured flow remains owned during grace"
            );
            assert_eq!(handler_drops.load(Ordering::SeqCst), 0);
            assert_eq!(flow_count.load(Ordering::Acquire), 1);
            assert_eq!(owner_count.load(Ordering::Acquire), 1);
            assert_eq!(registry.snapshot().active_process_roots, 1);
            assert_eq!(registry.snapshot().active_tun_tcp_flows, 1);
            assert_eq!(registry.snapshot().active_tun_handler_tasks, 1);

            tokio::time::advance(Duration::from_millis(1)).await;
            let report = run.await.expect("forced TUN process report");
            assert_eq!(handler_drops.load(Ordering::SeqCst), 1);
            assert_eq!(flow_count.load(Ordering::Acquire), 0);
            assert_eq!(owner_count.load(Ordering::Acquire), 0);
            assert!(owner_saw_aborted_flow.load(Ordering::Acquire));
            assert_eq!(report.cause(), &ProcessCause::ExternalShutdown);
            assert_eq!(report.forced_roots(), 1);
            assert_eq!(
                report.states(),
                &[
                    ProcessState::Validated,
                    ProcessState::Preparing,
                    ProcessState::Prepared,
                    ProcessState::Active,
                    ProcessState::Quiescing,
                    ProcessState::Draining,
                    ProcessState::Forced,
                    ProcessState::Stopped,
                ]
            );
            match owner_exit {
                OwnerExit::Stopped => {
                    assert_eq!(report.exit_kind(), ProcessExitKind::Forced);
                    assert!(report.cleanup_failure().is_none());
                }
                OwnerExit::CleanupFailed => {
                    assert_eq!(report.exit_kind(), ProcessExitKind::Failed);
                    assert!(matches!(
                        report.cleanup_failure(),
                        Some(ProcessCleanupFailure::RootFailed {
                            root,
                            error: "cleanup",
                        }) if root.get() == 0
                    ));
                }
                OwnerExit::RuntimeFailed => unreachable!("test owner outcome is closed"),
            }
            let stopped = registry.snapshot();
            assert_eq!(stopped.process_supervisors, 0);
            assert_eq!(stopped.prepared_process_roots, 0);
            assert_eq!(stopped.active_process_roots, 0);
            assert_eq!(stopped.active_tun_tcp_flows, 0);
            assert_eq!(stopped.active_tun_handler_tasks, 0);
            assert_eq!(stopped.process_root_reaps, 1);
            assert_eq!(stopped.process_forced_roots, 1);
            drop(session_handle);
        }
    }
}
