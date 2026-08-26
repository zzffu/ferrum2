use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU16;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use ferrum2_core::TargetAddr;
use ferrum2_core::route::EgressPlanSnapshot;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};

use super::tracking::DnsTaskRegistrar;

const HICKORY_PLACEHOLDER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

pub(crate) fn hickory_placeholder(port: NonZeroU16) -> SocketAddr {
    SocketAddr::new(HICKORY_PLACEHOLDER_IP.into(), port.get())
}

/// Owned future returned by a DNS egress adapter.
pub type DnsIoFuture<T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'static>>;

/// Owned Tokio TCP I/O supplied to Hickory without changing DNS framing.
pub trait DnsTcpIo: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

impl<T> DnsTcpIo for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

/// Boxed TCP I/O returned by [`DnsEgress`].
pub type BoxedDnsTcpIo = Box<dyn DnsTcpIo>;

/// Datagram I/O connected to the logical target selected for one DNS query.
pub trait DnsDatagramIo: Send + Sync + Unpin + 'static {
    /// Polls one datagram received from the selected logical target.
    fn poll_recv(&self, context: &mut Context<'_>, buffer: &mut [u8]) -> Poll<io::Result<usize>>;

    /// Polls one complete datagram send to the selected logical target.
    fn poll_send(&self, context: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>>;
}

/// Boxed UDP I/O returned by [`DnsEgress`].
pub type BoxedDnsDatagramIo = Box<dyn DnsDatagramIo>;

/// Runtime-neutral selected egress for one DNS connection or socket.
pub trait DnsEgress: Send + Sync + 'static {
    /// Connects to the validated logical target through the optional concrete plan.
    fn connect_tcp(
        &self,
        target: TargetAddr,
        plan: Option<EgressPlanSnapshot>,
        timeout: Duration,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo>;

    /// Binds datagram I/O for the validated logical target and optional plan.
    fn bind_udp(
        &self,
        target: TargetAddr,
        plan: Option<EgressPlanSnapshot>,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo>;
}

/// Direct production egress using Tokio numeric sockets only.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDnsEgress;

impl DnsEgress for SystemDnsEgress {
    fn connect_tcp(
        &self,
        target: TargetAddr,
        plan: Option<EgressPlanSnapshot>,
        timeout: Duration,
        _tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo> {
        Box::pin(async move {
            if plan.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "detoured DNS egress requires an adapter",
                ));
            }
            let target = target.as_socket_addr().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "system DNS egress requires a numeric target",
                )
            })?;
            let stream = tokio::time::timeout(timeout, TcpStream::connect(target))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS connect timeout"))??;
            stream.set_nodelay(true)?;
            Ok(Box::new(stream) as BoxedDnsTcpIo)
        })
    }

    fn bind_udp(
        &self,
        target: TargetAddr,
        plan: Option<EgressPlanSnapshot>,
        _tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo> {
        Box::pin(async move {
            if plan.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "detoured DNS egress requires an adapter",
                ));
            }
            let target = target.as_socket_addr().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "system DNS egress requires a numeric target",
                )
            })?;
            let local = match target.ip() {
                IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
                IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
            };
            let socket = UdpSocket::bind(local).await?;
            socket.connect(target).await?;
            Ok(Box::new(SystemDnsDatagram(socket)) as BoxedDnsDatagramIo)
        })
    }
}

struct SystemDnsDatagram(UdpSocket);

impl DnsDatagramIo for SystemDnsDatagram {
    fn poll_recv(&self, context: &mut Context<'_>, buffer: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut read = ReadBuf::new(buffer);
        ready!(self.0.poll_recv(context, &mut read))?;
        Poll::Ready(Ok(read.filled().len()))
    }

    fn poll_send(&self, context: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        self.0.poll_send(context, buffer)
    }
}
