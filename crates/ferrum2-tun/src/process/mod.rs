use std::sync::Arc;

use ferrum2_net::NetworkSnapshot;
use ferrum2_runtime::{OwnerRegistry, ProcessCancellation, ProcessFuture, ProcessRoot};

use crate::{
    Config, SessionCancellation, TcpFlow, TunEvent, TunEventSink, TunNetworkLifecycle,
    TunNetworkResetError, UdpCandidate, UnderlayPublisher,
};

#[cfg(any(all(windows, target_arch = "x86_64", feature = "live-backend"), test))]
mod limits;

pub(crate) type TcpHandler = Arc<
    dyn Fn(TcpFlow, ProcessCancellation, SessionCancellation) -> ProcessFuture<()>
        + Send
        + Sync
        + 'static,
>;
pub(crate) type UdpHandler = Arc<
    dyn Fn(UdpCandidate, ProcessCancellation, SessionCancellation) -> ProcessFuture<()>
        + Send
        + Sync
        + 'static,
>;
pub(crate) type NetworkLifecycleHandler = Arc<
    dyn Fn(
            Arc<NetworkSnapshot>,
            TunNetworkLifecycle,
        ) -> ProcessFuture<Result<(), TunNetworkResetError>>
        + Send
        + Sync
        + 'static,
>;

#[derive(Clone, Copy)]
#[cfg_attr(
    not(all(windows, target_arch = "x86_64", feature = "live-backend", not(test))),
    allow(
        dead_code,
        reason = "hosted adapter consumes only startup while retaining one process_root request shape"
    )
)]
pub(super) struct RootErrors<E> {
    pub(super) startup: E,
    pub(super) runtime: E,
    pub(super) cleanup: E,
}

#[cfg_attr(
    not(all(windows, target_arch = "x86_64", feature = "live-backend", not(test))),
    allow(
        dead_code,
        reason = "hosted adapter consumes only startup while retaining one process_root request shape"
    )
)]
pub(super) struct RootSpec<E> {
    pub(super) config: Config,
    pub(super) initial_network_generation: u64,
    pub(super) underlay: UnderlayPublisher,
    pub(super) network_catalog: ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
    pub(super) errors: RootErrors<E>,
    pub(super) registry: OwnerRegistry,
    pub(super) handle_tcp: TcpHandler,
    pub(super) handle_udp: UdpHandler,
    pub(super) handle_network_lifecycle: NetworkLifecycleHandler,
    pub(super) events: TunEventSink,
}

/// Builds one required TUN process root.
///
/// Error values are supplied by the binary so this deep module does not depend on
/// configuration, policy, DNS, protocol, or observability crates.
/// The lifecycle callback owns initialization and every later network transition.
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
    implementation::build(RootSpec {
        config,
        initial_network_generation,
        underlay,
        network_catalog,
        errors: RootErrors {
            startup,
            runtime,
            cleanup,
        },
        registry,
        handle_tcp: Arc::new(handle_tcp),
        handle_udp: Arc::new(handle_udp),
        handle_network_lifecycle: Arc::new(handle_network_lifecycle),
        events: TunEventSink::new(events),
    })
}

#[cfg(all(windows, target_arch = "x86_64", feature = "live-backend", not(test)))]
#[path = "live.rs"]
mod implementation;
#[cfg(not(all(windows, target_arch = "x86_64", feature = "live-backend", not(test))))]
#[path = "hosted.rs"]
mod implementation;
