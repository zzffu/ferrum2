mod generation;
mod operations;
mod service;

pub use generation::{GenerationBoundSocketError, NetworkTcpStream, NetworkUdpSocket};
pub use operations::{
    NetworkSocketOperations, SystemNetworkSocketError, SystemNetworkSocketOperations,
};
pub use service::{NetworkSocketMode, NetworkSocketService, NetworkSocketServiceError};
