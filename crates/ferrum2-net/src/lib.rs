#![forbid(unsafe_code)]

mod capability;
mod model;
mod resolver;

pub use capability::{ResolvedSocketBinder, TcpResolver, UdpResolver};
pub use model::{
    InterfaceBinding, InterfaceBindingError, InterfaceLinkState, InterfaceOperationalState,
    NetworkFamily, NetworkInterfaceCatalog, NetworkInterfaceCatalogError, NetworkInterfaceKind,
    NetworkInterfaceObservation, NetworkInterfaceObservationError, NetworkRouteObservation,
    NetworkSnapshot, NetworkSnapshotCaptureError, NetworkSnapshotError, SystemBestRoute,
    SystemBestRouteError,
};
pub use resolver::{
    AutomaticInterfaceSelection, DialOptions, InterfaceResolutionError,
    InterfaceResolutionErrorKind, InterfaceSelectionSource,
    NETWORK_INTERFACE_RESOLUTION_CACHE_CAPACITY, NamedInterfaceResolution,
    NetworkInterfaceResolver, ResolvedInterface, RouteNetworkOptions,
};
