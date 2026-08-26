use std::fmt;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use ferrum2_core::{AbortiveClose, LocalEndpoint};
use ferrum2_net::{ResolvedInterface, ResolvedSocketBinder};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpSocket, UdpSocket};

use crate::RuntimeTcpStream;

/// Injected seam for preparing and connecting family-specific TCP and UDP sockets.
///
/// `prepare_*` receives the single decision produced by the shared resolver. It must create an
/// unconnected socket for the destination family and apply that decision without re-resolving it.
pub trait NetworkSocketOperations: Send + Sync {
    type TcpSocket: Send;
    type TcpStream: AsyncRead + AsyncWrite + LocalEndpoint + AbortiveClose + Send + Unpin + 'static;
    type UdpSocket: Send + Sync + 'static;
    type Error: Send;

    fn prepare_tcp(
        &self,
        destination: SocketAddr,
        resolved: &ResolvedInterface,
    ) -> Result<Self::TcpSocket, Self::Error>;

    fn connect_tcp(
        &self,
        socket: Self::TcpSocket,
        destination: SocketAddr,
    ) -> impl Future<Output = Result<Self::TcpStream, Self::Error>> + Send;

    fn prepare_udp(
        &self,
        selection_destination: SocketAddr,
        resolved: &ResolvedInterface,
    ) -> Result<Self::UdpSocket, Self::Error>;

    fn connect_udp(
        &self,
        socket: Self::UdpSocket,
        destination: SocketAddr,
    ) -> impl Future<Output = Result<Self::UdpSocket, Self::Error>> + Send;
}

/// Production socket operations using Tokio sockets and one injected platform binder.
#[derive(Clone, Copy, Debug)]
pub struct SystemNetworkSocketOperations<B> {
    binder: B,
}

impl<B> SystemNetworkSocketOperations<B> {
    pub const fn new(binder: B) -> Self {
        Self { binder }
    }

    pub const fn binder(&self) -> &B {
        &self.binder
    }
}

impl<B> NetworkSocketOperations for SystemNetworkSocketOperations<B>
where
    B: ResolvedSocketBinder,
{
    type TcpSocket = TcpSocket;
    type TcpStream = RuntimeTcpStream;
    type UdpSocket = UdpSocket;
    type Error = SystemNetworkSocketError<B::Error>;

    fn prepare_tcp(
        &self,
        destination: SocketAddr,
        resolved: &ResolvedInterface,
    ) -> Result<Self::TcpSocket, Self::Error> {
        let socket = new_socket(destination, Type::STREAM, Protocol::TCP)
            .map_err(SystemNetworkSocketError::<B::Error>::Socket)?;
        self.binder
            .bind_resolved_socket(&socket, destination, resolved)
            .map_err(SystemNetworkSocketError::Binding)?;
        let stream: std::net::TcpStream = socket.into();
        Ok(TcpSocket::from_std_stream(stream))
    }

    async fn connect_tcp(
        &self,
        socket: Self::TcpSocket,
        destination: SocketAddr,
    ) -> Result<Self::TcpStream, Self::Error> {
        let stream = socket
            .connect(destination)
            .await
            .map_err(SystemNetworkSocketError::Socket)?;
        RuntimeTcpStream::from_connected(stream).map_err(SystemNetworkSocketError::Socket)
    }

    fn prepare_udp(
        &self,
        selection_destination: SocketAddr,
        resolved: &ResolvedInterface,
    ) -> Result<Self::UdpSocket, Self::Error> {
        let socket = new_socket(selection_destination, Type::DGRAM, Protocol::UDP)
            .map_err(SystemNetworkSocketError::<B::Error>::Socket)?;
        self.binder
            .bind_resolved_socket(&socket, selection_destination, resolved)
            .map_err(SystemNetworkSocketError::Binding)?;
        if resolved.source_address().is_none() {
            let local = match selection_destination {
                SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                SocketAddr::V6(_) => {
                    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
                }
            };
            socket
                .bind(&local.into())
                .map_err(SystemNetworkSocketError::Socket)?;
        }
        let socket: std::net::UdpSocket = socket.into();
        UdpSocket::from_std(socket).map_err(SystemNetworkSocketError::Socket)
    }

    async fn connect_udp(
        &self,
        socket: Self::UdpSocket,
        destination: SocketAddr,
    ) -> Result<Self::UdpSocket, Self::Error> {
        socket
            .connect(destination)
            .await
            .map_err(SystemNetworkSocketError::Socket)?;
        Ok(socket)
    }
}

fn new_socket(
    destination: SocketAddr,
    socket_type: Type,
    protocol: Protocol,
) -> io::Result<Socket> {
    let domain = match destination {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, socket_type, Some(protocol))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Closed production socket error. Nested platform and I/O values are never formatted.
pub enum SystemNetworkSocketError<E> {
    Socket(io::Error),
    Binding(E),
}

impl<E> fmt::Debug for SystemNetworkSocketError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(_) => formatter.write_str("Socket([closed])"),
            Self::Binding(_) => formatter.write_str("Binding([closed])"),
        }
    }
}
