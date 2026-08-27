#![allow(unsafe_code)]

mod loader;
mod managed;
mod managed_dns;
pub(super) mod network;
mod notification;
mod strict_route;
mod wintun;

pub use network::{WindowsResolvedSocketBinder, bind_resolved_socket};
pub use notification::WindowsNetworkChangeMonitor;
pub use wintun::{Adapter, ReceivedPacket, StopSignal, WorkSignal};

pub use super::core::network::{UnderlayPolicy, WindowsNetworkInterfaceCatalog};
