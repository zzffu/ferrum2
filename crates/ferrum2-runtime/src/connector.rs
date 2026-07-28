use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
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

/// Establishes one raw TCP socket candidate used by the runtime connector.
pub trait TcpDialer: Send + Sync {
    /// Starts one TCP connection attempt.
    fn connect(
        &self,
        address: SocketAddr,
    ) -> impl std::future::Future<Output = io::Result<TcpStream>> + Send;
}

/// Production Tokio TCP dialer.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemTcpDialer;

impl TcpDialer for SystemTcpDialer {
    async fn connect(&self, address: SocketAddr) -> io::Result<TcpStream> {
        TcpStream::connect(address).await
    }
}

/// Resolves a bounded ordered sequence of TCP socket candidates.
pub trait TcpResolver: Send + Sync {
    /// Bounded candidate storage or iterator returned by this resolver.
    type Candidates: IntoIterator<Item = SocketAddr> + Send;

    /// Resolves a validated ASCII domain and non-zero port.
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl std::future::Future<Output = io::Result<Self::Candidates>> + Send;
}

/// Production system resolver.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemTcpResolver;

impl TcpResolver for SystemTcpResolver {
    type Candidates = Vec<SocketAddr>;

    async fn resolve(&self, host: &str, port: u16) -> io::Result<Self::Candidates> {
        Ok(tokio::net::lookup_host((host, port))
            .await?
            .take(MAX_RESOLVED_CANDIDATES)
            .collect())
    }
}

/// Maximum ordered candidates consumed from one domain resolution.
pub const MAX_RESOLVED_CANDIDATES: usize = 16;

/// An owned Tokio TCP stream with a validated, stored local endpoint.
pub struct RuntimeTcpStream {
    stream: TcpStream,
    local_endpoint: SocketAddr,
}

impl RuntimeTcpStream {
    /// Validates and stores the connected socket's local endpoint.
    pub fn from_connected(stream: TcpStream) -> io::Result<Self> {
        Self::from_connected_with_inspector(stream, &SystemSocketInspector)
    }

    /// Uses an injected inspector while preserving the production lookup ordering.
    pub fn from_connected_with_inspector<I>(stream: TcpStream, inspector: &I) -> io::Result<Self>
    where
        I: SocketInspector + ?Sized,
    {
        let local_endpoint = inspector.local_addr(&stream)?;
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
        match self.local_endpoint {
            SocketAddr::V4(endpoint) => endpoint,
            SocketAddr::V6(endpoint) => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, endpoint.port()),
        }
    }

    fn local_socket_addr(&self) -> SocketAddr {
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

/// Direct TCP connector with bounded system resolution and one absolute deadline.
#[derive(Debug)]
pub struct TcpConnector<I = SystemSocketInspector, D = SystemTcpDialer, R = SystemTcpResolver> {
    inspector: I,
    dialer: D,
    resolver: R,
    connect_timeout: std::time::Duration,
}

impl TcpConnector<SystemSocketInspector, SystemTcpDialer, SystemTcpResolver> {
    /// Creates a production connector.
    pub fn new(connect_timeout: std::time::Duration) -> Self {
        Self {
            inspector: SystemSocketInspector,
            dialer: SystemTcpDialer,
            resolver: SystemTcpResolver,
            connect_timeout,
        }
    }
}

impl<I> TcpConnector<I, SystemTcpDialer, SystemTcpResolver> {
    /// Creates a connector with an injected post-connect socket inspector.
    pub fn with_inspector(inspector: I, connect_timeout: std::time::Duration) -> Self {
        Self {
            inspector,
            dialer: SystemTcpDialer,
            resolver: SystemTcpResolver,
            connect_timeout,
        }
    }
}

impl<I, D> TcpConnector<I, D, SystemTcpResolver> {
    /// Creates a connector with injected dial and endpoint-inspection adapters.
    pub fn with_adapters(inspector: I, dialer: D, connect_timeout: std::time::Duration) -> Self {
        Self {
            inspector,
            dialer,
            resolver: SystemTcpResolver,
            connect_timeout,
        }
    }
}

impl<I, D, R> TcpConnector<I, D, R> {
    /// Creates a connector with all resolution, dial, and inspection adapters.
    pub fn with_resolution_adapters(
        inspector: I,
        dialer: D,
        resolver: R,
        connect_timeout: std::time::Duration,
    ) -> Self {
        Self {
            inspector,
            dialer,
            resolver,
            connect_timeout,
        }
    }
}

impl<I, D, R> Connector for TcpConnector<I, D, R>
where
    I: SocketInspector,
    D: TcpDialer,
    R: TcpResolver,
    <R::Candidates as IntoIterator>::IntoIter: Send,
{
    type Stream = RuntimeTcpStream;

    async fn connect(&self, target: &TargetAddr) -> Result<Self::Stream, ConnectError> {
        let deadline = tokio::time::Instant::now() + self.connect_timeout;
        if let Some(address) = target.as_socket_addr() {
            return connect_candidate(&self.inspector, &self.dialer, address, deadline).await;
        }

        let ferrum2_core::TargetHostRef::Domain(host) = target.host() else {
            return Err(ConnectError::new(ConnectErrorKind::Other));
        };
        let candidates = match tokio::time::timeout_at(
            deadline,
            self.resolver.resolve(host, target.port().get()),
        )
        .await
        {
            Ok(Ok(candidates)) => candidates,
            Ok(Err(_)) => {
                return Err(ConnectError::new(ConnectErrorKind::HostUnreachable));
            }
            Err(_) => return Err(ConnectError::new(ConnectErrorKind::Timeout)),
        };

        let mut attempted = false;
        let mut last_error = ConnectError::new(ConnectErrorKind::HostUnreachable);
        for address in candidates.into_iter().take(MAX_RESOLVED_CANDIDATES) {
            if tokio::time::Instant::now() >= deadline {
                return Err(ConnectError::new(ConnectErrorKind::Timeout));
            }
            attempted = true;
            match connect_candidate(&self.inspector, &self.dialer, address, deadline).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = error,
            }
        }
        if attempted {
            Err(last_error)
        } else {
            Err(ConnectError::new(ConnectErrorKind::HostUnreachable))
        }
    }
}

async fn connect_candidate<I, D>(
    inspector: &I,
    dialer: &D,
    address: SocketAddr,
    deadline: tokio::time::Instant,
) -> Result<RuntimeTcpStream, ConnectError>
where
    I: SocketInspector,
    D: TcpDialer,
{
    let stream = match tokio::time::timeout_at(deadline, dialer.connect(address)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => return Err(connect_error_from_io(&error)),
        Err(_) => return Err(ConnectError::new(ConnectErrorKind::Timeout)),
    };
    RuntimeTcpStream::from_connected_with_inspector(stream, inspector)
        .map_err(|_| ConnectError::new(ConnectErrorKind::Other))
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

/// Protocol-neutral direct outbound for every normalized target class.
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
        self.connector.connect(target)
    }
}
