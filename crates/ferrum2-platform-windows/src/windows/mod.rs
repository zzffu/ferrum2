mod loader;
mod managed;
mod network;
mod notification;
mod strict_route;
mod wintun;

mod ffi;

pub use ffi::{
    Adapter, ReceivedPacket, StopSignal, WindowsNetworkChangeMonitor, WindowsResolvedSocketBinder,
    WorkSignal, bind_resolved_socket,
};
pub use network::{UnderlayPolicy, WindowsNetworkInterfaceCatalog};
