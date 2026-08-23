use std::fmt;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};

use bytes::BytesMut;
use ferrum2_core::{AbortiveClose, LocalEndpoint};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpSocket, UdpSocket};
use tokio::sync::{RwLock, oneshot};

use crate::{
    DialOptions, DirectUdpSocket, InterfaceSelectionSource, NetworkInterfaceCatalog,
    NetworkInterfaceResolver, NetworkResetCoordinator, NetworkRuntimeCancellation,
    NetworkRuntimeOwner, NetworkRuntimeOwnerCancellation, NetworkRuntimeOwnerKind,
    NetworkRuntimeResourceAdmissionError, ResolvedInterface, RouteNetworkOptions, RuntimeTcpStream,
};

/// Applies one already-resolved interface decision to an unconnected platform socket.
///
/// Implementations must install the interface constraint before binding an optional source
/// address. Interface selection remains exclusively owned by [`NetworkInterfaceResolver`].
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

/// One shared generation-bound physical socket service.
///
/// All physical callers share the exact snapshot -> four-tier resolve -> unbound socket -> bind ->
/// generation check -> owner admission sequence implemented by this service and the reset
/// coordinator. Generation races retry that whole sequence at most once.
pub struct NetworkSocketService<C, O> {
    coordinator: NetworkResetCoordinator,
    resolver: NetworkInterfaceResolver<C>,
    operations: O,
}

impl<C, O> NetworkSocketService<C, O> {
    pub const fn new(
        coordinator: NetworkResetCoordinator,
        resolver: NetworkInterfaceResolver<C>,
        operations: O,
    ) -> Self {
        Self {
            coordinator,
            resolver,
            operations,
        }
    }

    pub const fn coordinator(&self) -> &NetworkResetCoordinator {
        &self.coordinator
    }

    pub const fn resolver(&self) -> &NetworkInterfaceResolver<C> {
        &self.resolver
    }

    pub const fn operations(&self) -> &O {
        &self.operations
    }
}

impl<C, O> NetworkSocketService<C, O>
where
    C: NetworkInterfaceCatalog,
    O: NetworkSocketOperations,
{
    /// Connects one TCP socket while reset cancellation can still close the in-flight attempt.
    pub async fn connect_tcp(
        &self,
        outbound: &DialOptions,
        route: &RouteNetworkOptions,
        destination: SocketAddr,
    ) -> Result<GenerationBoundTcpStream<O::TcpStream>, NetworkSocketServiceError<O::Error>> {
        let admitted = self
            .coordinator
            .prepare_and_admit_runtime_resource(
                &self.resolver,
                outbound,
                route,
                destination,
                NetworkRuntimeOwnerKind::TcpConnection,
                |resolved| self.operations.prepare_tcp(destination, resolved),
            )
            .map_err(NetworkSocketServiceError::Admission)?;
        let (socket, resolved, mut owner) = admitted.into_parts();
        let attempted_source = resolved.selection_source();
        let connect = self.operations.connect_tcp(socket, destination);
        tokio::pin!(connect);
        let stream = tokio::select! {
            biased;
            cancellation = owner.cancelled() => {
                return Err(NetworkSocketServiceError::Cancelled {
                    attempted_source,
                    cancellation,
                });
            }
            result = &mut connect => result.map_err(|error| NetworkSocketServiceError::Connection {
                attempted_source,
                error,
            })?,
        };
        if let Some(cancellation) = owner.cancellation_status_now() {
            drop(stream);
            return Err(NetworkSocketServiceError::Cancelled {
                attempted_source,
                cancellation,
            });
        }
        Ok(GenerationBoundTcpStream::new(stream, resolved, owner))
    }

    /// Opens one bound, unconnected UDP socket for a multi-target association.
    ///
    /// `selection_destination` is the first concrete target and is used only for family-aware
    /// interface selection and binding. The returned socket remains unconnected so later
    /// datagrams may use `send_to` and `recv_from` within that selected family.
    pub fn open_udp(
        &self,
        outbound: &DialOptions,
        route: &RouteNetworkOptions,
        selection_destination: SocketAddr,
    ) -> Result<GenerationBoundUdpSocket<O::UdpSocket>, NetworkSocketServiceError<O::Error>> {
        let admitted = self
            .coordinator
            .prepare_and_admit_runtime_resource(
                &self.resolver,
                outbound,
                route,
                selection_destination,
                NetworkRuntimeOwnerKind::UdpAssociation,
                |resolved| self.operations.prepare_udp(selection_destination, resolved),
            )
            .map_err(NetworkSocketServiceError::Admission)?;
        let (socket, resolved, owner) = admitted.into_parts();
        Ok(GenerationBoundUdpSocket::new(socket, resolved, owner))
    }

    /// Opens and explicitly connects one UDP socket to a single physical target.
    pub async fn connect_udp(
        &self,
        outbound: &DialOptions,
        route: &RouteNetworkOptions,
        destination: SocketAddr,
    ) -> Result<GenerationBoundUdpSocket<O::UdpSocket>, NetworkSocketServiceError<O::Error>> {
        let admitted = self
            .coordinator
            .prepare_and_admit_runtime_resource(
                &self.resolver,
                outbound,
                route,
                destination,
                NetworkRuntimeOwnerKind::UdpAssociation,
                |resolved| self.operations.prepare_udp(destination, resolved),
            )
            .map_err(NetworkSocketServiceError::Admission)?;
        let (socket, resolved, mut owner) = admitted.into_parts();
        let attempted_source = resolved.selection_source();
        let connect = self.operations.connect_udp(socket, destination);
        tokio::pin!(connect);
        let socket = tokio::select! {
            biased;
            cancellation = owner.cancelled() => {
                return Err(NetworkSocketServiceError::Cancelled {
                    attempted_source,
                    cancellation,
                });
            }
            result = &mut connect => result.map_err(|error| NetworkSocketServiceError::Connection {
                attempted_source,
                error,
            })?,
        };
        if let Some(cancellation) = owner.cancellation_status_now() {
            drop(socket);
            return Err(NetworkSocketServiceError::Cancelled {
                attempted_source,
                cancellation,
            });
        }
        Ok(GenerationBoundUdpSocket::new(socket, resolved, owner))
    }
}

impl<C, O> fmt::Debug for NetworkSocketService<C, O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkSocketService")
            .field("coordinator", &self.coordinator)
            .finish_non_exhaustive()
    }
}

/// Closed service failure retaining only the selected source and nested closed categories.
#[derive(Eq, PartialEq)]
pub enum NetworkSocketServiceError<E> {
    Admission(NetworkRuntimeResourceAdmissionError<E>),
    Connection {
        attempted_source: InterfaceSelectionSource,
        error: E,
    },
    Cancelled {
        attempted_source: InterfaceSelectionSource,
        cancellation: NetworkRuntimeOwnerCancellation,
    },
}

impl<E> NetworkSocketServiceError<E> {
    pub const fn attempted_source(&self) -> InterfaceSelectionSource {
        match self {
            Self::Admission(error) => error.attempted_source(),
            Self::Connection {
                attempted_source, ..
            }
            | Self::Cancelled {
                attempted_source, ..
            } => *attempted_source,
        }
    }
}

impl<E> fmt::Debug for NetworkSocketServiceError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => formatter.debug_tuple("Admission").field(error).finish(),
            Self::Connection {
                attempted_source, ..
            } => formatter
                .debug_struct("Connection")
                .field("attempted_source", attempted_source)
                .field("error", &"[closed]")
                .finish(),
            Self::Cancelled {
                attempted_source,
                cancellation,
            } => formatter
                .debug_struct("Cancelled")
                .field("attempted_source", attempted_source)
                .field("cancellation", cancellation)
                .finish(),
        }
    }
}

/// TCP stream retained with its exact interface decision and reset acknowledgement owner.
#[must_use = "dropping the wrapper closes the stream and acknowledges reset cancellation"]
pub struct GenerationBoundTcpStream<T> {
    stream: Arc<StdMutex<Option<T>>>,
    resolved: ResolvedInterface,
    local_socket_addr: SocketAddr,
    closed: Arc<StdMutex<Option<NetworkRuntimeOwnerCancellation>>>,
    cancellation: Pin<Box<dyn Future<Output = NetworkRuntimeOwnerCancellation> + Send>>,
    drop_signal: Option<oneshot::Sender<()>>,
    _monitor: tokio::task::JoinHandle<()>,
}

impl<T: LocalEndpoint + Send + 'static> GenerationBoundTcpStream<T> {
    fn new(stream: T, resolved: ResolvedInterface, owner: NetworkRuntimeOwner) -> Self {
        let local_socket_addr = stream.local_socket_addr();
        let stream = Arc::new(StdMutex::new(Some(stream)));
        let closed = Arc::new(StdMutex::new(None));
        let cancellation = owner.cancellation();
        let mut operation_cancellation = cancellation.clone();
        let mut monitor_cancellation = cancellation;
        let monitor_stream = Arc::clone(&stream);
        let monitor_closed = Arc::clone(&closed);
        let (drop_signal, drop_receiver) = oneshot::channel();
        let monitor = tokio::spawn(async move {
            let terminal = tokio::select! {
                biased;
                cancellation = monitor_cancellation.cancelled() => Some(cancellation),
                _ = drop_receiver => None,
            };
            lock_unpoisoned(&monitor_stream).take();
            if let Some(terminal) = terminal {
                *lock_unpoisoned(&monitor_closed) = Some(terminal);
            }
            drop(owner);
        });
        Self {
            stream,
            resolved,
            local_socket_addr,
            closed,
            cancellation: Box::pin(async move { operation_cancellation.cancelled().await }),
            drop_signal: Some(drop_signal),
            _monitor: monitor,
        }
    }
}

impl<T> GenerationBoundTcpStream<T> {
    pub const fn resolved_interface(&self) -> &ResolvedInterface {
        &self.resolved
    }

    /// Runs one synchronous adapter against the live stream without detaching its owner.
    pub fn with_stream<R>(&self, operation: impl FnOnce(&T) -> R) -> Option<R> {
        let stream = lock_unpoisoned(&self.stream);
        stream.as_ref().map(operation)
    }

    /// Runs one synchronous mutable adapter against the live stream without detaching its owner.
    pub fn with_stream_mut<R>(&mut self, operation: impl FnOnce(&mut T) -> R) -> Option<R> {
        let mut stream = lock_unpoisoned(&self.stream);
        stream.as_mut().map(operation)
    }

    pub fn closed(&self) -> Option<NetworkRuntimeOwnerCancellation> {
        *lock_unpoisoned(&self.closed)
    }

    fn poll_cancellation(&mut self, context: &mut Context<'_>) -> Poll<io::Error> {
        if let Some(cancellation) = self.closed() {
            return Poll::Ready(closed_io_error(cancellation));
        }
        match self.cancellation.as_mut().poll(context) {
            Poll::Ready(cancellation) => {
                self.close(cancellation);
                Poll::Ready(closed_io_error(cancellation))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn close_if_signalled(&mut self) -> Option<io::Error> {
        let cancellation = self.closed();
        if let Some(cancellation) = cancellation {
            self.close(cancellation);
            Some(closed_io_error(cancellation))
        } else {
            None
        }
    }

    fn close(&mut self, cancellation: NetworkRuntimeOwnerCancellation) {
        lock_unpoisoned(&self.stream).take();
        *lock_unpoisoned(&self.closed) = Some(cancellation);
    }

    fn poll_read_inner(
        &mut self,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>
    where
        T: AsyncRead + Unpin,
    {
        let result = {
            let mut stream = lock_unpoisoned(&self.stream);
            match stream.as_mut() {
                Some(stream) => Pin::new(stream).poll_read(context, buffer),
                None => Poll::Ready(Err(closed_resource_io_error())),
            }
        };
        if let Some(error) = self.close_if_signalled() {
            return Poll::Ready(Err(error));
        }
        result
    }
}

impl<T> Drop for GenerationBoundTcpStream<T> {
    fn drop(&mut self) {
        if let Some(drop_signal) = self.drop_signal.take() {
            let _ = drop_signal.send(());
        }
    }
}

impl<T> fmt::Debug for GenerationBoundTcpStream<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenerationBoundTcpStream")
            .field("stream", &"[closed]")
            .field("resolved", &self.resolved)
            .field("closed", &self.closed())
            .finish()
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for GenerationBoundTcpStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Poll::Ready(error) = this.poll_cancellation(context) {
            return Poll::Ready(Err(error));
        }
        this.poll_read_inner(context, buffer)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for GenerationBoundTcpStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Poll::Ready(error) = this.poll_cancellation(context) {
            return Poll::Ready(Err(error));
        }
        let result = {
            let mut stream = lock_unpoisoned(&this.stream);
            match stream.as_mut() {
                Some(stream) => Pin::new(stream).poll_write(context, buffer),
                None => Poll::Ready(Err(closed_resource_io_error())),
            }
        };
        if let Some(error) = this.close_if_signalled() {
            return Poll::Ready(Err(error));
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Poll::Ready(error) = this.poll_cancellation(context) {
            return Poll::Ready(Err(error));
        }
        let result = {
            let mut stream = lock_unpoisoned(&this.stream);
            match stream.as_mut() {
                Some(stream) => Pin::new(stream).poll_flush(context),
                None => Poll::Ready(Err(closed_resource_io_error())),
            }
        };
        if let Some(error) = this.close_if_signalled() {
            return Poll::Ready(Err(error));
        }
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Poll::Ready(error) = this.poll_cancellation(context) {
            return Poll::Ready(Err(error));
        }
        let result = {
            let mut stream = lock_unpoisoned(&this.stream);
            match stream.as_mut() {
                Some(stream) => Pin::new(stream).poll_shutdown(context),
                None => Poll::Ready(Err(closed_resource_io_error())),
            }
        };
        if let Some(error) = this.close_if_signalled() {
            return Poll::Ready(Err(error));
        }
        result
    }
}

impl<T> LocalEndpoint for GenerationBoundTcpStream<T> {
    fn local_endpoint(&self) -> SocketAddrV4 {
        match self.local_socket_addr {
            SocketAddr::V4(endpoint) => endpoint,
            SocketAddr::V6(endpoint) => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, endpoint.port()),
        }
    }

    fn local_socket_addr(&self) -> SocketAddr {
        self.local_socket_addr
    }
}

impl<T: AbortiveClose> AbortiveClose for GenerationBoundTcpStream<T> {
    type Error = GenerationBoundSocketError<T::Error>;

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        if let Some(cancellation) = self.closed() {
            self.close(cancellation);
        }
        lock_unpoisoned(&self.stream)
            .as_mut()
            .ok_or(GenerationBoundSocketError::Closed)?
            .mark_abortive()
            .map_err(GenerationBoundSocketError::Inner)
    }
}

/// UDP socket retained with its exact interface decision and reset acknowledgement owner.
#[must_use = "dropping the wrapper closes the socket and acknowledges reset cancellation"]
pub struct GenerationBoundUdpSocket<T> {
    socket: Arc<RwLock<Option<T>>>,
    resolved: ResolvedInterface,
    cancellation: NetworkRuntimeCancellation,
    closed: Arc<StdMutex<Option<NetworkRuntimeOwnerCancellation>>>,
    drop_signal: Option<oneshot::Sender<()>>,
    _monitor: tokio::task::JoinHandle<()>,
}

impl<T: Send + Sync + 'static> GenerationBoundUdpSocket<T> {
    fn new(socket: T, resolved: ResolvedInterface, owner: NetworkRuntimeOwner) -> Self {
        let cancellation = owner.cancellation();
        let mut monitor_cancellation = cancellation.clone();
        let socket = Arc::new(RwLock::new(Some(socket)));
        let closed = Arc::new(StdMutex::new(None));
        let monitor_socket = Arc::clone(&socket);
        let monitor_closed = Arc::clone(&closed);
        let (drop_signal, drop_receiver) = oneshot::channel();
        let monitor = tokio::spawn(async move {
            let terminal = tokio::select! {
                biased;
                cancellation = monitor_cancellation.cancelled() => Some(cancellation),
                _ = drop_receiver => None,
            };
            monitor_socket.write().await.take();
            if let Some(terminal) = terminal {
                *lock_unpoisoned(&monitor_closed) = Some(terminal);
            }
            drop(owner);
        });
        Self {
            socket,
            resolved,
            cancellation,
            closed,
            drop_signal: Some(drop_signal),
            _monitor: monitor,
        }
    }
}

impl<T> GenerationBoundUdpSocket<T> {
    pub async fn is_closed(&self) -> bool {
        self.socket.read().await.is_none()
    }

    pub const fn resolved_interface(&self) -> &ResolvedInterface {
        &self.resolved
    }

    pub const fn cancellation(&self) -> &NetworkRuntimeCancellation {
        &self.cancellation
    }

    pub fn closed(&self) -> Option<NetworkRuntimeOwnerCancellation> {
        *lock_unpoisoned(&self.closed)
    }

    async fn close(&self) {
        self.socket.write().await.take();
    }

    fn close_now(&self) {
        if let Ok(mut socket) = self.socket.try_write() {
            socket.take();
        }
    }
}

impl<T> Drop for GenerationBoundUdpSocket<T> {
    fn drop(&mut self) {
        if let Some(drop_signal) = self.drop_signal.take() {
            let _ = drop_signal.send(());
        }
    }
}

impl<T> fmt::Debug for GenerationBoundUdpSocket<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenerationBoundUdpSocket")
            .field("socket", &"[closed]")
            .field("resolved", &self.resolved)
            .field("cancelled", &self.closed())
            .finish()
    }
}

impl<T: DirectUdpSocket> DirectUdpSocket for GenerationBoundUdpSocket<T> {
    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        let mut cancellation = self.cancellation.clone();
        let outcome = tokio::select! {
            biased;
            cancellation = cancellation.cancelled() => Err(cancellation),
            result = async {
                let socket = self.socket.read().await;
                let socket = socket.as_ref().ok_or_else(closed_resource_io_error)?;
                socket.send_to(payload, target).await
            } => Ok(result),
        };
        match outcome {
            Err(cancellation) => {
                self.close().await;
                Err(closed_io_error(cancellation))
            }
            Ok(result) => {
                if let Some(cancellation) = self.cancellation.terminal_now() {
                    self.close().await;
                    Err(closed_io_error(cancellation))
                } else {
                    result
                }
            }
        }
    }

    async fn readable(&self) -> io::Result<()> {
        let mut cancellation = self.cancellation.clone();
        let outcome = tokio::select! {
            biased;
            cancellation = cancellation.cancelled() => Err(cancellation),
            result = async {
                let socket = self.socket.read().await;
                let socket = socket.as_ref().ok_or_else(closed_resource_io_error)?;
                socket.readable().await
            } => Ok(result),
        };
        match outcome {
            Err(cancellation) => {
                self.close().await;
                Err(closed_io_error(cancellation))
            }
            Ok(result) => {
                if let Some(cancellation) = self.cancellation.terminal_now() {
                    self.close().await;
                    Err(closed_io_error(cancellation))
                } else {
                    result
                }
            }
        }
    }

    async fn recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        let mut cancellation = self.cancellation.clone();
        let outcome = tokio::select! {
            biased;
            cancellation = cancellation.cancelled() => Err(cancellation),
            result = async {
                let socket = self.socket.read().await;
                let socket = socket.as_ref().ok_or_else(closed_resource_io_error)?;
                socket.recv_buf_from(payload).await
            } => Ok(result),
        };
        match outcome {
            Err(cancellation) => {
                self.close().await;
                Err(closed_io_error(cancellation))
            }
            Ok(result) => {
                if let Some(cancellation) = self.cancellation.terminal_now() {
                    self.close().await;
                    Err(closed_io_error(cancellation))
                } else {
                    result
                }
            }
        }
    }

    fn try_recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        if let Some(cancellation) = self.cancellation.terminal_now() {
            self.close_now();
            return Err(closed_io_error(cancellation));
        }
        let socket = self
            .socket
            .try_read()
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        let result = socket
            .as_ref()
            .ok_or_else(closed_resource_io_error)?
            .try_recv_buf_from(payload);
        drop(socket);
        if let Some(cancellation) = self.cancellation.terminal_now() {
            self.close_now();
            Err(closed_io_error(cancellation))
        } else {
            result
        }
    }
}

fn closed_resource_io_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "network generation closed",
    )
}

fn closed_io_error(_: NetworkRuntimeOwnerCancellation) -> io::Error {
    closed_resource_io_error()
}

/// Closed failure from applying a synchronous adapter after generation cancellation.
#[derive(Eq, PartialEq)]
pub enum GenerationBoundSocketError<E> {
    Closed,
    Inner(E),
}

impl<E> fmt::Debug for GenerationBoundSocketError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("Closed"),
            Self::Inner(_) => formatter.write_str("Inner([closed])"),
        }
    }
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

fn lock_unpoisoned<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
