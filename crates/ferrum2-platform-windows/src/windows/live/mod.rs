#![allow(unsafe_code)]

mod config_file;
mod loader;
mod managed;
mod managed_dns;
pub(super) mod network;
mod notification;
mod strict_route;
mod tcp_ingress;
mod wintun;

pub use config_file::{create_config_temporary, replace_config_file, validate_private_file};
pub use network::{WindowsResolvedSocketBinder, bind_resolved_socket};
pub use notification::WindowsNetworkChangeMonitor;
pub use wintun::{Adapter, ReceivedPacket, StopSignal, WorkSignal};

pub use super::core::network::{UnderlayPolicy, WindowsNetworkInterfaceCatalog};
