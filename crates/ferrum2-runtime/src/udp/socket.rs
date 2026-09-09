use std::future::Future;
use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::BytesMut;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

/// One owned datagram socket used by a direct UDP session task.
pub trait DirectUdpSocket: Send + Sync + 'static {
    /// Sends one complete datagram to an IP candidate.
    fn send_to(
        &self,
        payload: &[u8],
        target: SocketAddr,
    ) -> impl Future<Output = io::Result<usize>> + Send;

    /// Attempts one non-blocking send without waiting for socket readiness.
    fn try_send_to(&self, _payload: &[u8], _target: SocketAddr) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }

    /// Waits until a non-blocking receive attempt may make progress.
    fn readable(&self) -> impl Future<Output = io::Result<()>> + Send;

    /// Receives one complete target datagram and its source address.
    fn recv_buf_from(
        &self,
        payload: &mut BytesMut,
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send;

    /// Attempts one non-blocking receive into spare `BytesMut` capacity.
    fn try_recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)>;
}

impl DirectUdpSocket for UdpSocket {
    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        UdpSocket::send_to(self, payload, target).await
    }

    fn try_send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        UdpSocket::try_send_to(self, payload, target)
    }

    async fn readable(&self) -> io::Result<()> {
        UdpSocket::readable(self).await
    }

    async fn recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_buf_from(self, payload).await
    }

    fn try_recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::try_recv_buf_from(self, payload)
    }
}

/// Production dual-stack socket that normalizes IPv4-mapped endpoints.
pub struct SystemDirectUdpSocket {
    socket: UdpSocket,
}

impl DirectUdpSocket for SystemDirectUdpSocket {
    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        let target = match target {
            SocketAddr::V4(target) => SocketAddr::V6(SocketAddrV6::new(
                target.ip().to_ipv6_mapped(),
                target.port(),
                0,
                0,
            )),
            SocketAddr::V6(target) => SocketAddr::V6(target),
        };
        self.socket.send_to(payload, target).await
    }

    fn try_send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        let target = match target {
            SocketAddr::V4(target) => SocketAddr::V6(SocketAddrV6::new(
                target.ip().to_ipv6_mapped(),
                target.port(),
                0,
                0,
            )),
            SocketAddr::V6(target) => SocketAddr::V6(target),
        };
        self.socket.try_send_to(payload, target)
    }

    async fn readable(&self) -> io::Result<()> {
        self.socket.readable().await
    }

    async fn recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        let (length, source) = self.socket.recv_buf_from(payload).await?;
        Ok((length, normalize_direct_source(source)))
    }

    fn try_recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        let (length, source) = self.socket.try_recv_buf_from(payload)?;
        Ok((length, normalize_direct_source(source)))
    }
}

fn normalize_direct_source(source: SocketAddr) -> SocketAddr {
    match source {
        SocketAddr::V6(source) => match source.ip().to_ipv4_mapped() {
            Some(ipv4) => SocketAddr::V4(SocketAddrV4::new(ipv4, source.port())),
            None => SocketAddr::V6(source),
        },
        SocketAddr::V4(source) => SocketAddr::V4(source),
    }
}

/// Creates one direct socket for one committed server session.
pub trait DirectUdpSocketFactory: Send + Sync + 'static {
    /// Owned direct socket.
    type Socket: DirectUdpSocket;
    /// Caller-owned, per-admission policy passed explicitly to the socket opener.
    type OpenContext: Send;

    /// Opens one unconnected datagram socket using the selected policy and first concrete
    /// destination. The runtime never stores or reconstructs this context.
    fn open(
        &self,
        context: Self::OpenContext,
        selection_destination: SocketAddr,
    ) -> impl Future<Output = io::Result<Self::Socket>> + Send;
}

/// Production one-socket-per-session factory.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDirectUdpSocketFactory;

impl DirectUdpSocketFactory for SystemDirectUdpSocketFactory {
    type Socket = SystemDirectUdpSocket;
    type OpenContext = ();

    async fn open(&self, (): (), _selection_destination: SocketAddr) -> io::Result<Self::Socket> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(false)?;
        socket.set_nonblocking(true)?;
        socket.bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)).into())?;
        let socket: std::net::UdpSocket = socket.into();
        Ok(SystemDirectUdpSocket {
            socket: UdpSocket::from_std(socket)?,
        })
    }
}
