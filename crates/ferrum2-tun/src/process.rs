use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use ferrum2_net::NetworkSnapshot;
#[cfg(not(all(windows, target_arch = "x86_64")))]
use ferrum2_runtime::PreparedProcessRoot;
use ferrum2_runtime::{OwnerRegistry, ProcessCancellation, ProcessFuture, ProcessRoot};

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use crate::TunRejectReason;
#[cfg(all(windows, target_arch = "x86_64"))]
use crate::lifecycle::owner_main;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
use crate::packet;
#[cfg(all(windows, target_arch = "x86_64"))]
use crate::packet::{ipv4_unicast, ipv6_unicast};
use crate::{
    Config, SessionCancellation, TcpFlow, TunEvent, TunNetworkLifecycle, TunNetworkResetError,
    UdpCandidate, UnderlayPublisher,
};
#[cfg(all(windows, target_arch = "x86_64"))]
use crate::{
    NetworkLifecycleHandler, NetworkResetBridgeOutcome, OwnerControl, OwnerExit, OwnerReady,
    OwnerSessionServices, OwnerThread, OwnerWake, TcpHandler, TunEventSink, TunRoot, UdpHandler,
    map_owner_spawn,
};

/// Builds one required process root around the private owner-thread implementation.
///
/// Error values are supplied by the binary so this deep module does not depend on
/// configuration, policy, DNS, protocol, or observability crates.
/// The lifecycle callback publishes the first real snapshot during preparation, coordinates a
/// replacement stack before ordinary-reset admission, and brackets managed-plane rebuilds around
/// teardown and readback. Returning an error keeps admission closed and retries only the affected
/// lifecycle transition.
#[cfg(all(windows, target_arch = "x86_64"))]
#[allow(clippy::too_many_arguments)]
pub fn process_root<E, H, U, R, M>(
    config: Config,
    initial_network_generation: u64,
    underlay: UnderlayPublisher,
    network_catalog: ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
    startup: E,
    runtime: E,
    cleanup: E,
    registry: OwnerRegistry,
    handle_tcp: H,
    handle_udp: U,
    handle_network_lifecycle: R,
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
    R: Fn(
            Arc<NetworkSnapshot>,
            TunNetworkLifecycle,
        ) -> ProcessFuture<Result<(), TunNetworkResetError>>
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
            initial_network_generation,
            underlay,
            RootErrors {
                startup,
                runtime,
                cleanup,
            },
            cancellation,
            RootServices {
                registry,
                network_catalog,
                handle_tcp: Arc::new(handle_tcp),
                handle_udp: Arc::new(handle_udp),
                handle_network_lifecycle: Arc::new(handle_network_lifecycle),
                events,
            },
        )
        .await
    })
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
/// Builds a required root that fails during preparation on unsupported targets.
#[allow(clippy::too_many_arguments)]
pub fn process_root<E, H, U, R, M>(
    _config: Config,
    _initial_network_generation: u64,
    _underlay: UnderlayPublisher,
    _network_catalog: ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
    startup: E,
    _runtime: E,
    _cleanup: E,
    _registry: OwnerRegistry,
    _handle_tcp: H,
    _handle_udp: U,
    _handle_network_lifecycle: R,
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
    R: Fn(
            Arc<NetworkSnapshot>,
            TunNetworkLifecycle,
        ) -> ProcessFuture<Result<(), TunNetworkResetError>>
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
    network_catalog: ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
    handle_tcp: TcpHandler,
    handle_udp: UdpHandler,
    handle_network_lifecycle: NetworkLifecycleHandler,
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
pub(crate) const fn map_packet_reject(reason: packet::PacketRejectReason) -> TunRejectReason {
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
    initial_network_generation: u64,
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
        network_catalog,
        handle_tcp,
        handle_udp,
        handle_network_lifecycle,
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
    let (network_reset_sender, network_resets) = tokio::sync::mpsc::channel(1);
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
                    initial_network_generation,
                    owner_control,
                    deadline,
                    OwnerSessionServices {
                        ready: ready_sender,
                        registry: owner_registry,
                        network_catalog,
                        events,
                        underlay,
                        flow_output: flow_sender,
                        datagram_output: datagram_sender,
                        network_lifecycle_output: network_reset_sender,
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
            Ok(OwnerReady::Ready {
                work,
                snapshot,
                initialization,
            }) => {
                if std::time::Instant::now() >= deadline {
                    let _ = initialization.send(NetworkResetBridgeOutcome::Stopped);
                    return Err(prepare_failure(guard, errors.startup, errors.cleanup).await);
                }
                let mut initialization_cancellation = cancellation.clone();
                let initialized = tokio::select! {
                    biased;
                    () = initialization_cancellation.cancelled() => {
                        NetworkResetBridgeOutcome::Stopped
                    }
                    result = (handle_network_lifecycle)(snapshot, TunNetworkLifecycle::Initialize) => {
                        match result {
                            Ok(()) => NetworkResetBridgeOutcome::Completed,
                            Err(TunNetworkResetError) => NetworkResetBridgeOutcome::Retry,
                        }
                    }
                };
                let _ = initialization.send(initialized);
                if initialized != NetworkResetBridgeOutcome::Completed {
                    return if cancellation.is_cancelled() {
                        cancel_prepare(guard, errors.cleanup).await
                    } else {
                        Err(prepare_failure(guard, errors.startup, errors.cleanup).await)
                    };
                }
                guard.work = work;
                return Ok(Some(TunRoot {
                    owner: guard,
                    done: _done_receiver,
                    runtime: Some(errors.runtime),
                    cleanup: Some(errors.cleanup),
                    flows,
                    datagrams,
                    network_resets,
                    flow_count: control.flow_count,
                    association_count: control.association_count,
                    registry,
                    handle_tcp,
                    handle_udp,
                    handle_network_lifecycle,
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
