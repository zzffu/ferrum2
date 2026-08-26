use std::future::Future;
use std::io;
use std::net::SocketAddr;

use socket2::Socket;

use crate::ResolvedInterface;

/// Resolves a bounded ordered sequence of TCP socket candidates.
pub trait TcpResolver: Send + Sync {
    /// Bounded candidate storage or iterator returned by this resolver.
    type Candidates: IntoIterator<Item = SocketAddr> + Send;

    /// Resolves a validated ASCII domain and non-zero port.
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = io::Result<Self::Candidates>> + Send;
}

/// Resolves a bounded ordered sequence of UDP socket candidates.
pub trait UdpResolver: Send + Sync + 'static {
    /// Candidate storage or iterator returned by this resolver.
    type Candidates: IntoIterator<Item = SocketAddr> + Send;

    /// Resolves one validated ASCII domain and non-zero port.
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = io::Result<Self::Candidates>> + Send;
}

/// Applies one already-resolved interface decision to an unconnected platform socket.
///
/// Implementations must install the interface constraint before binding an optional source
/// address. Interface selection remains exclusively owned by [`crate::NetworkInterfaceResolver`].
pub trait ResolvedSocketBinder: Send + Sync {
    /// Closed platform binding error.
    type Error: Send;

    /// Applies `resolved` without connecting the socket or consulting a second route source.
    fn bind_resolved_socket(
        &self,
        socket: &Socket,
        destination: SocketAddr,
        resolved: &ResolvedInterface,
    ) -> Result<(), Self::Error>;
}
