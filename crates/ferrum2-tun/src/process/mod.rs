use std::sync::Arc;

use ferrum2_net::NetworkSnapshot;
use ferrum2_runtime::{OwnerRegistry, ProcessCancellation, ProcessFuture, ProcessRoot};

use crate::{
    Config, SessionCancellation, TcpFlow, TunEvent, TunNetworkLifecycle, TunNetworkResetError,
    UdpCandidate, UnderlayPublisher,
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

/// Named inputs and handlers for one required TUN process root.
///
/// The lifecycle callback owns initialization and subsequent network transitions.
/// Error values retain the binary's startup, runtime, and cleanup classifications.
pub struct TunRootRequest<E> {
    pub config: Config,
    pub initial_network_generation: u64,
    pub underlay: UnderlayPublisher,
    pub network_catalog: ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
    pub startup: E,
    pub runtime: E,
    pub cleanup: E,
    pub registry: OwnerRegistry,
    /// Independent TUN UDP byte domain shared with the egress handlers.
    pub udp_buffer_budget: ferrum2_runtime::UdpBufferBudget,
    pub handle_tcp: TcpHandler,
    pub handle_udp: UdpHandler,
    pub handle_network_lifecycle: NetworkLifecycleHandler,
    pub events: Arc<dyn Fn(TunEvent) + Send + Sync + 'static>,
}

/// Builds one required TUN process root from its named dependencies.
pub fn process_root<E>(request: TunRootRequest<E>) -> ProcessRoot<E>
where
    E: Copy + Send + 'static,
{
    implementation::build(request)
}

#[cfg(all(windows, target_arch = "x86_64", feature = "live-backend", not(test)))]
#[path = "live.rs"]
mod implementation;
#[cfg(not(all(windows, target_arch = "x86_64", feature = "live-backend", not(test))))]
#[path = "hosted.rs"]
mod implementation;
