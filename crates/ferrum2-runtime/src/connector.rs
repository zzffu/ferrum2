use std::io;
use std::net::{SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::task::{Context, Poll};

use ferrum2_core::{
    AbortiveClose, ConnectError, ConnectErrorKind, Connector, LocalEndpoint, Outbound, TargetAddr,
};
use socket2::SockRef;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Supplies the one post-connect local-address query used by the TCP adapter.
pub trait SocketInspector: Send + Sync {
    /// Queries the connected socket's local address.
    fn local_addr(&self, stream: &TcpStream) -> io::Result<SocketAddr>;
}

/// Production socket inspector.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemSocketInspector;

impl SocketInspector for SystemSocketInspector {
    fn local_addr(&self, stream: &TcpStream) -> io::Result<SocketAddr> {
        stream.local_addr()
    }
}

/// An owned Tokio TCP stream with a validated, stored IPv4 local endpoint.
pub struct RuntimeTcpStream {
    stream: TcpStream,
    local_endpoint: SocketAddrV4,
}

impl RuntimeTcpStream {
    /// Validates and stores the connected socket's local IPv4 endpoint.
    pub fn from_connected(stream: TcpStream) -> io::Result<Self> {
        Self::from_connected_with_inspector(stream, &SystemSocketInspector)
    }

    /// Uses an injected inspector while preserving the production lookup ordering.
    pub fn from_connected_with_inspector<I>(stream: TcpStream, inspector: &I) -> io::Result<Self>
    where
        I: SocketInspector + ?Sized,
    {
        let local_endpoint = match inspector.local_addr(&stream)? {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "connected socket has no IPv4 local endpoint",
                ));
            }
        };
        Ok(Self {
            stream,
            local_endpoint,
        })
    }

    /// Returns the owned Tokio stream.
    pub fn into_inner(self) -> TcpStream {
        self.stream
    }
}

impl LocalEndpoint for RuntimeTcpStream {
    fn local_endpoint(&self) -> SocketAddrV4 {
        self.local_endpoint
    }
}

impl AbortiveClose for RuntimeTcpStream {
    type Error = io::Error;

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        SockRef::from(&self.stream).set_linger(Some(std::time::Duration::ZERO))
    }
}

impl AsRef<TcpStream> for RuntimeTcpStream {
    fn as_ref(&self) -> &TcpStream {
        &self.stream
    }
}

impl AsyncRead for RuntimeTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for RuntimeTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

/// Direct IPv4 TCP connector with a bounded connect deadline.
#[derive(Debug)]
pub struct TcpConnector<I = SystemSocketInspector> {
    inspector: I,
    connect_timeout: std::time::Duration,
}

impl TcpConnector<SystemSocketInspector> {
    /// Creates a production connector.
    pub fn new(connect_timeout: std::time::Duration) -> Self {
        Self {
            inspector: SystemSocketInspector,
            connect_timeout,
        }
    }
}

impl<I> TcpConnector<I> {
    /// Creates a connector with an injected post-connect socket inspector.
    pub fn with_inspector(inspector: I, connect_timeout: std::time::Duration) -> Self {
        Self {
            inspector,
            connect_timeout,
        }
    }
}

impl<I> Connector for TcpConnector<I>
where
    I: SocketInspector,
{
    type Stream = RuntimeTcpStream;

    fn connect(
        &self,
        target: &TargetAddr,
    ) -> impl std::future::Future<Output = Result<Self::Stream, ConnectError>> + Send {
        let address = target.as_socket_addr();
        async move {
            let Some(SocketAddr::V4(address)) = address else {
                return Err(ConnectError::new(ConnectErrorKind::Other));
            };
            let stream = match tokio::time::timeout(
                self.connect_timeout,
                TcpStream::connect(SocketAddr::V4(address)),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => return Err(connect_error_from_io(&error)),
                Err(_) => return Err(ConnectError::new(ConnectErrorKind::Timeout)),
            };
            RuntimeTcpStream::from_connected_with_inspector(stream, &self.inspector)
                .map_err(|_| ConnectError::new(ConnectErrorKind::Other))
        }
    }
}

fn connect_error_from_io(error: &io::Error) -> ConnectError {
    let kind = match error.kind() {
        io::ErrorKind::NetworkUnreachable => ConnectErrorKind::NetworkUnreachable,
        io::ErrorKind::HostUnreachable => ConnectErrorKind::HostUnreachable,
        io::ErrorKind::ConnectionRefused => ConnectErrorKind::ConnectionRefused,
        io::ErrorKind::TimedOut => ConnectErrorKind::Timeout,
        _ => ConnectErrorKind::Other,
    };
    ConnectError::new(kind)
}

/// Protocol-neutral direct outbound that accepts only M0 IPv4 targets.
#[derive(Clone, Debug)]
pub struct DirectOutbound<C> {
    connector: C,
}

impl<C> DirectOutbound<C> {
    /// Wraps a connector with direct-outbound target validation.
    pub fn new(connector: C) -> Self {
        Self { connector }
    }

    /// Returns the wrapped connector.
    pub fn into_inner(self) -> C {
        self.connector
    }
}

impl<C> Outbound for DirectOutbound<C>
where
    C: Connector,
{
    type Stream = C::Stream;
    type Error = ConnectError;

    fn open(
        &self,
        target: &TargetAddr,
    ) -> impl std::future::Future<Output = Result<Self::Stream, Self::Error>> + Send {
        let is_ipv4 = matches!(target.as_socket_addr(), Some(SocketAddr::V4(_)));
        async move {
            if !is_ipv4 {
                return Err(ConnectError::new(ConnectErrorKind::Other));
            }
            self.connector.connect(target).await
        }
    }
}
