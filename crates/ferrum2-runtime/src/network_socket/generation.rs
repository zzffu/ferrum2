use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};

use bytes::BytesMut;
use ferrum2_core::{AbortiveClose, LocalEndpoint};
use ferrum2_net::ResolvedInterface;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::reset::NetworkRuntimeOwnerCloser;
use crate::{
    DirectUdpSocket, NetworkRuntimeCancellation, NetworkRuntimeOwner,
    NetworkRuntimeOwnerCancellation,
};

/// TCP stream retained with its exact interface decision and reset acknowledgement owner.
#[must_use = "dropping the wrapper closes the stream and acknowledges reset cancellation"]
pub struct GenerationBoundTcpStream<T> {
    state: Arc<StdMutex<GenerationBoundTcpState<T>>>,
    resolved: ResolvedInterface,
    local_socket_addr: SocketAddr,
    closed: Arc<AtomicU8>,
    cancellation:
        Pin<Box<dyn Future<Output = NetworkRuntimeOwnerCancellation> + Send + Sync + 'static>>,
}

const TCP_OPEN: u8 = 0;
const TCP_CLOSED_RESET: u8 = 1;
const TCP_CLOSED_COORDINATOR: u8 = 2;
const TCP_CLOSED_DROPPED: u8 = 3;

struct GenerationBoundTcpState<T> {
    stream: Option<T>,
    owner: Option<NetworkRuntimeOwner>,
    terminal: Option<NetworkRuntimeOwnerCancellation>,
}

struct GenerationBoundTcpCloser<T> {
    state: Arc<StdMutex<GenerationBoundTcpState<T>>>,
    closed: Arc<AtomicU8>,
}

impl<T: Send + 'static> NetworkRuntimeOwnerCloser for GenerationBoundTcpCloser<T> {
    fn close(&self, cancellation: NetworkRuntimeOwnerCancellation) {
        close_generation_bound_tcp_state(&self.state, &self.closed, Some(cancellation));
    }
}

fn close_generation_bound_tcp_state<T>(
    state: &Arc<StdMutex<GenerationBoundTcpState<T>>>,
    closed: &Arc<AtomicU8>,
    terminal: Option<NetworkRuntimeOwnerCancellation>,
) {
    let mut state = lock_unpoisoned(state);
    if closed.load(Ordering::Relaxed) != TCP_OPEN {
        return;
    }
    let stream = state.stream.take();
    drop(stream);
    state.terminal = terminal;
    let closed_state = match terminal {
        Some(NetworkRuntimeOwnerCancellation::Reset(_)) => TCP_CLOSED_RESET,
        Some(NetworkRuntimeOwnerCancellation::CoordinatorDropped) => TCP_CLOSED_COORDINATOR,
        None => TCP_CLOSED_DROPPED,
    };
    closed.store(closed_state, Ordering::Release);
    let owner = state.owner.take();
    drop(owner);
}

impl<T: LocalEndpoint + Send + 'static> GenerationBoundTcpStream<T> {
    pub(super) fn new(
        stream: T,
        resolved: ResolvedInterface,
        owner: NetworkRuntimeOwner,
    ) -> Result<Self, NetworkRuntimeOwnerCancellation> {
        let local_socket_addr = stream.local_socket_addr();
        let cancellation = owner.cancellation();
        let mut operation_cancellation = cancellation.clone();
        let state = Arc::new(StdMutex::new(GenerationBoundTcpState {
            stream: Some(stream),
            owner: Some(owner),
            terminal: None,
        }));
        let closed = Arc::new(AtomicU8::new(TCP_OPEN));
        let closer: Arc<dyn NetworkRuntimeOwnerCloser> = Arc::new(GenerationBoundTcpCloser {
            state: Arc::clone(&state),
            closed: Arc::clone(&closed),
        });
        let attach_result = lock_unpoisoned(&state)
            .owner
            .as_ref()
            .expect("new TCP generation owner")
            .attach_closer(closer);
        let mut stream = Self {
            state,
            resolved,
            local_socket_addr,
            closed,
            cancellation: Box::pin(async move { operation_cancellation.cancelled().await }),
        };
        if let Err(cancellation) = attach_result {
            stream.close(cancellation);
            Err(cancellation)
        } else {
            Ok(stream)
        }
    }
}

impl<T> GenerationBoundTcpStream<T> {
    pub const fn resolved_interface(&self) -> &ResolvedInterface {
        &self.resolved
    }

    /// Runs one synchronous adapter against the live stream without detaching its owner.
    pub fn with_stream<R>(&self, operation: impl FnOnce(&T) -> R) -> Option<R> {
        if self.closed.load(Ordering::Acquire) != TCP_OPEN {
            return None;
        }
        let state = lock_unpoisoned(&self.state);
        state.stream.as_ref().map(operation)
    }

    /// Runs one synchronous mutable adapter against the live stream without detaching its owner.
    pub fn with_stream_mut<R>(&mut self, operation: impl FnOnce(&mut T) -> R) -> Option<R> {
        if self.closed.load(Ordering::Acquire) != TCP_OPEN {
            return None;
        }
        let mut state = lock_unpoisoned(&self.state);
        state.stream.as_mut().map(operation)
    }

    pub fn closed(&self) -> Option<NetworkRuntimeOwnerCancellation> {
        if self.closed.load(Ordering::Acquire) == TCP_OPEN {
            None
        } else {
            lock_unpoisoned(&self.state).terminal
        }
    }

    fn poll_cancellation(&mut self, context: &mut Context<'_>) -> Poll<io::Error> {
        let cancellation = { self.cancellation.as_mut().poll(context) };
        match cancellation {
            Poll::Ready(cancellation) => {
                self.close(cancellation);
                Poll::Ready(closed_io_error(cancellation))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn close_if_signalled(&mut self) -> Option<io::Error> {
        self.closed_error()
    }

    fn close(&mut self, cancellation: NetworkRuntimeOwnerCancellation) {
        close_generation_bound_tcp_state(&self.state, &self.closed, Some(cancellation));
    }

    fn closed_error(&self) -> Option<io::Error> {
        match self.closed.load(Ordering::Acquire) {
            TCP_OPEN => None,
            TCP_CLOSED_RESET | TCP_CLOSED_COORDINATOR => Some(
                lock_unpoisoned(&self.state)
                    .terminal
                    .map_or_else(closed_resource_io_error, closed_io_error),
            ),
            TCP_CLOSED_DROPPED => Some(closed_resource_io_error()),
            _ => unreachable!("invalid TCP generation close state"),
        }
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
            let mut state = lock_unpoisoned(&self.state);
            match state.stream.as_mut() {
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
        close_generation_bound_tcp_state(&self.state, &self.closed, None);
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
            let mut state = lock_unpoisoned(&this.state);
            match state.stream.as_mut() {
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
            let mut state = lock_unpoisoned(&this.state);
            match state.stream.as_mut() {
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
            let mut state = lock_unpoisoned(&this.state);
            match state.stream.as_mut() {
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
    fn local_socket_addr(&self) -> SocketAddr {
        self.local_socket_addr
    }
}

impl<T: AbortiveClose> AbortiveClose for GenerationBoundTcpStream<T> {
    type Error = GenerationBoundSocketError<T::Error>;

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        if self.closed.load(Ordering::Acquire) != TCP_OPEN {
            return Err(GenerationBoundSocketError::Closed);
        }
        lock_unpoisoned(&self.state)
            .stream
            .as_mut()
            .ok_or(GenerationBoundSocketError::Closed)?
            .mark_abortive()
            .map_err(GenerationBoundSocketError::Inner)
    }
}

/// Physical TCP stream using either the static bare fast path or dynamic reset ownership.
#[must_use = "dropping the wrapper closes the physical stream"]
pub struct NetworkTcpStream<T> {
    inner: NetworkTcpStreamInner<T>,
}

enum NetworkTcpStreamInner<T> {
    Static(StaticTcpStream<T>),
    Dynamic(GenerationBoundTcpStream<T>),
}

struct StaticTcpStream<T> {
    stream: T,
    resolved: ResolvedInterface,
    local_socket_addr: SocketAddr,
}

impl<T: LocalEndpoint + Send + 'static> NetworkTcpStream<T> {
    pub(super) fn static_socket(stream: T, resolved: ResolvedInterface) -> Self {
        let local_socket_addr = stream.local_socket_addr();
        Self {
            inner: NetworkTcpStreamInner::Static(StaticTcpStream {
                stream,
                resolved,
                local_socket_addr,
            }),
        }
    }

    pub(super) fn dynamic_socket(
        stream: T,
        resolved: ResolvedInterface,
        owner: NetworkRuntimeOwner,
    ) -> Result<Self, NetworkRuntimeOwnerCancellation> {
        GenerationBoundTcpStream::new(stream, resolved, owner).map(|stream| Self {
            inner: NetworkTcpStreamInner::Dynamic(stream),
        })
    }
}

impl<T> NetworkTcpStream<T> {
    pub const fn resolved_interface(&self) -> &ResolvedInterface {
        match &self.inner {
            NetworkTcpStreamInner::Static(stream) => &stream.resolved,
            NetworkTcpStreamInner::Dynamic(stream) => stream.resolved_interface(),
        }
    }

    pub const fn is_generation_bound(&self) -> bool {
        matches!(&self.inner, NetworkTcpStreamInner::Dynamic(_))
    }

    pub fn closed(&self) -> Option<NetworkRuntimeOwnerCancellation> {
        match &self.inner {
            NetworkTcpStreamInner::Static(_) => None,
            NetworkTcpStreamInner::Dynamic(stream) => stream.closed(),
        }
    }

    pub fn with_stream<R>(&self, operation: impl FnOnce(&T) -> R) -> Option<R> {
        match &self.inner {
            NetworkTcpStreamInner::Static(stream) => Some(operation(&stream.stream)),
            NetworkTcpStreamInner::Dynamic(stream) => stream.with_stream(operation),
        }
    }

    pub fn with_stream_mut<R>(&mut self, operation: impl FnOnce(&mut T) -> R) -> Option<R> {
        match &mut self.inner {
            NetworkTcpStreamInner::Static(stream) => Some(operation(&mut stream.stream)),
            NetworkTcpStreamInner::Dynamic(stream) => stream.with_stream_mut(operation),
        }
    }
}

impl<T> fmt::Debug for NetworkTcpStream<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkTcpStream")
            .field(
                "mode",
                if self.is_generation_bound() {
                    &"dynamic"
                } else {
                    &"static"
                },
            )
            .field("resolved", self.resolved_interface())
            .field("closed", &self.closed())
            .finish()
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for NetworkTcpStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            NetworkTcpStreamInner::Static(stream) => {
                Pin::new(&mut stream.stream).poll_read(context, buffer)
            }
            NetworkTcpStreamInner::Dynamic(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for NetworkTcpStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            NetworkTcpStreamInner::Static(stream) => {
                Pin::new(&mut stream.stream).poll_write(context, buffer)
            }
            NetworkTcpStreamInner::Dynamic(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            NetworkTcpStreamInner::Static(stream) => {
                Pin::new(&mut stream.stream).poll_flush(context)
            }
            NetworkTcpStreamInner::Dynamic(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            NetworkTcpStreamInner::Static(stream) => {
                Pin::new(&mut stream.stream).poll_shutdown(context)
            }
            NetworkTcpStreamInner::Dynamic(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

impl<T> LocalEndpoint for NetworkTcpStream<T> {
    fn local_socket_addr(&self) -> SocketAddr {
        match &self.inner {
            NetworkTcpStreamInner::Static(stream) => stream.local_socket_addr,
            NetworkTcpStreamInner::Dynamic(stream) => stream.local_socket_addr(),
        }
    }
}

impl<T: AbortiveClose> AbortiveClose for NetworkTcpStream<T> {
    type Error = GenerationBoundSocketError<T::Error>;

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        match &mut self.inner {
            NetworkTcpStreamInner::Static(stream) => stream
                .stream
                .mark_abortive()
                .map_err(GenerationBoundSocketError::Inner),
            NetworkTcpStreamInner::Dynamic(stream) => stream.mark_abortive(),
        }
    }
}

/// UDP socket retained with its exact interface decision and reset acknowledgement owner.
#[must_use = "dropping the wrapper closes the socket and acknowledges reset cancellation"]
pub struct GenerationBoundUdpSocket<T> {
    state: Arc<StdMutex<GenerationBoundUdpState<T>>>,
    resolved: ResolvedInterface,
    cancellation: NetworkRuntimeCancellation,
    closed: Arc<AtomicU8>,
}

const UDP_OPEN: u8 = 0;
const UDP_CLOSED_RESET: u8 = 1;
const UDP_CLOSED_COORDINATOR: u8 = 2;
const UDP_CLOSED_DROPPED: u8 = 3;

struct GenerationBoundUdpState<T> {
    resource: Option<Arc<GenerationBoundUdpResource<T>>>,
    terminal: Option<NetworkRuntimeOwnerCancellation>,
}

struct GenerationBoundUdpResource<T> {
    socket: Option<T>,
    owner: Option<NetworkRuntimeOwner>,
}

struct GenerationBoundUdpCloser<T> {
    state: Arc<StdMutex<GenerationBoundUdpState<T>>>,
    closed: Arc<AtomicU8>,
}

impl<T: Send + Sync + 'static> NetworkRuntimeOwnerCloser for GenerationBoundUdpCloser<T> {
    fn close(&self, cancellation: NetworkRuntimeOwnerCancellation) {
        close_generation_bound_udp_state(&self.state, &self.closed, Some(cancellation));
    }
}

impl<T> GenerationBoundUdpResource<T> {
    fn socket(&self) -> &T {
        self.socket.as_ref().expect("live UDP runtime resource")
    }
}

impl<T> Drop for GenerationBoundUdpResource<T> {
    fn drop(&mut self) {
        let socket = self.socket.take();
        drop(socket);
        let owner = self.owner.take();
        drop(owner);
    }
}

fn close_generation_bound_udp_state<T>(
    state: &Arc<StdMutex<GenerationBoundUdpState<T>>>,
    closed: &Arc<AtomicU8>,
    terminal: Option<NetworkRuntimeOwnerCancellation>,
) {
    let mut state = lock_unpoisoned(state);
    if closed.load(Ordering::Relaxed) != UDP_OPEN {
        return;
    }
    let resource = state.resource.take();
    state.terminal = terminal;
    let closed_state = match terminal {
        Some(NetworkRuntimeOwnerCancellation::Reset(_)) => UDP_CLOSED_RESET,
        Some(NetworkRuntimeOwnerCancellation::CoordinatorDropped) => UDP_CLOSED_COORDINATOR,
        None => UDP_CLOSED_DROPPED,
    };
    closed.store(closed_state, Ordering::Release);
    drop(state);
    drop(resource);
}

impl<T: Send + Sync + 'static> GenerationBoundUdpSocket<T> {
    pub(super) fn new(
        socket: T,
        resolved: ResolvedInterface,
        owner: NetworkRuntimeOwner,
    ) -> Result<Self, NetworkRuntimeOwnerCancellation> {
        let cancellation = owner.cancellation();
        let state = Arc::new(StdMutex::new(GenerationBoundUdpState {
            resource: Some(Arc::new(GenerationBoundUdpResource {
                socket: Some(socket),
                owner: Some(owner),
            })),
            terminal: None,
        }));
        let closed = Arc::new(AtomicU8::new(UDP_OPEN));
        let closer: Arc<dyn NetworkRuntimeOwnerCloser> = Arc::new(GenerationBoundUdpCloser {
            state: Arc::clone(&state),
            closed: Arc::clone(&closed),
        });
        let attach_result = lock_unpoisoned(&state)
            .resource
            .as_ref()
            .expect("new UDP generation resource")
            .owner
            .as_ref()
            .expect("new UDP generation owner")
            .attach_closer(closer);
        let socket = Self {
            state,
            resolved,
            cancellation,
            closed,
        };
        if let Err(cancellation) = attach_result {
            socket.close(cancellation);
            Err(cancellation)
        } else {
            Ok(socket)
        }
    }
}

impl<T> GenerationBoundUdpSocket<T> {
    pub async fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) != UDP_OPEN
    }

    pub const fn resolved_interface(&self) -> &ResolvedInterface {
        &self.resolved
    }

    pub fn closed(&self) -> Option<NetworkRuntimeOwnerCancellation> {
        if self.closed.load(Ordering::Acquire) == UDP_OPEN {
            None
        } else {
            lock_unpoisoned(&self.state).terminal
        }
    }

    fn live_resource(&self) -> io::Result<Arc<GenerationBoundUdpResource<T>>> {
        if self.closed.load(Ordering::Acquire) != UDP_OPEN {
            return Err(closed_resource_io_error());
        }
        lock_unpoisoned(&self.state)
            .resource
            .as_ref()
            .cloned()
            .ok_or_else(closed_resource_io_error)
    }

    fn try_live_resource(&self) -> io::Result<Arc<GenerationBoundUdpResource<T>>> {
        if self.closed.load(Ordering::Acquire) != UDP_OPEN {
            return Err(closed_resource_io_error());
        }
        let state = match self.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
        };
        state
            .resource
            .as_ref()
            .cloned()
            .ok_or_else(closed_resource_io_error)
    }

    fn close(&self, terminal: NetworkRuntimeOwnerCancellation) {
        close_generation_bound_udp_state(&self.state, &self.closed, Some(terminal));
    }
}

impl<T> Drop for GenerationBoundUdpSocket<T> {
    fn drop(&mut self) {
        close_generation_bound_udp_state(&self.state, &self.closed, None);
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
                let resource = self.live_resource()?;
                resource.socket().send_to(payload, target).await
            } => Ok(result),
        };
        match outcome {
            Err(cancellation) => {
                self.close(cancellation);
                Err(closed_io_error(cancellation))
            }
            Ok(result) => {
                if let Some(cancellation) = self.cancellation.terminal_now() {
                    self.close(cancellation);
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
                let resource = self.live_resource()?;
                resource.socket().readable().await
            } => Ok(result),
        };
        match outcome {
            Err(cancellation) => {
                self.close(cancellation);
                Err(closed_io_error(cancellation))
            }
            Ok(result) => {
                if let Some(cancellation) = self.cancellation.terminal_now() {
                    self.close(cancellation);
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
                let resource = self.live_resource()?;
                resource.socket().recv_buf_from(payload).await
            } => Ok(result),
        };
        match outcome {
            Err(cancellation) => {
                self.close(cancellation);
                Err(closed_io_error(cancellation))
            }
            Ok(result) => {
                if let Some(cancellation) = self.cancellation.terminal_now() {
                    self.close(cancellation);
                    Err(closed_io_error(cancellation))
                } else {
                    result
                }
            }
        }
    }

    fn try_recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        if let Some(cancellation) = self.cancellation.terminal_now() {
            self.close(cancellation);
            return Err(closed_io_error(cancellation));
        }
        let resource = self.try_live_resource()?;
        let result = resource.socket().try_recv_buf_from(payload);
        drop(resource);
        if let Some(cancellation) = self.cancellation.terminal_now() {
            self.close(cancellation);
            Err(closed_io_error(cancellation))
        } else {
            result
        }
    }
}

/// Physical UDP socket using either the static bare fast path or dynamic reset ownership.
#[must_use = "dropping the wrapper closes the physical socket"]
pub struct NetworkUdpSocket<T> {
    inner: NetworkUdpSocketInner<T>,
}

enum NetworkUdpSocketInner<T> {
    Static(StaticUdpSocket<T>),
    Dynamic(GenerationBoundUdpSocket<T>),
}

struct StaticUdpSocket<T> {
    socket: T,
    resolved: ResolvedInterface,
}

impl<T: Send + Sync + 'static> NetworkUdpSocket<T> {
    pub(super) const fn static_socket(socket: T, resolved: ResolvedInterface) -> Self {
        Self {
            inner: NetworkUdpSocketInner::Static(StaticUdpSocket { socket, resolved }),
        }
    }

    pub(super) fn dynamic_socket(
        socket: T,
        resolved: ResolvedInterface,
        owner: NetworkRuntimeOwner,
    ) -> Result<Self, NetworkRuntimeOwnerCancellation> {
        GenerationBoundUdpSocket::new(socket, resolved, owner).map(|socket| Self {
            inner: NetworkUdpSocketInner::Dynamic(socket),
        })
    }
}

impl<T> NetworkUdpSocket<T> {
    pub async fn is_closed(&self) -> bool {
        match &self.inner {
            NetworkUdpSocketInner::Static(_) => false,
            NetworkUdpSocketInner::Dynamic(socket) => socket.is_closed().await,
        }
    }

    pub const fn resolved_interface(&self) -> &ResolvedInterface {
        match &self.inner {
            NetworkUdpSocketInner::Static(socket) => &socket.resolved,
            NetworkUdpSocketInner::Dynamic(socket) => socket.resolved_interface(),
        }
    }

    pub const fn is_generation_bound(&self) -> bool {
        matches!(&self.inner, NetworkUdpSocketInner::Dynamic(_))
    }

    pub fn closed(&self) -> Option<NetworkRuntimeOwnerCancellation> {
        match &self.inner {
            NetworkUdpSocketInner::Static(_) => None,
            NetworkUdpSocketInner::Dynamic(socket) => socket.closed(),
        }
    }
}

impl<T> fmt::Debug for NetworkUdpSocket<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkUdpSocket")
            .field(
                "mode",
                if self.is_generation_bound() {
                    &"dynamic"
                } else {
                    &"static"
                },
            )
            .field("resolved", self.resolved_interface())
            .field("closed", &self.closed())
            .finish()
    }
}

impl<T: DirectUdpSocket> DirectUdpSocket for NetworkUdpSocket<T> {
    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        match &self.inner {
            NetworkUdpSocketInner::Static(socket) => socket.socket.send_to(payload, target).await,
            NetworkUdpSocketInner::Dynamic(socket) => socket.send_to(payload, target).await,
        }
    }

    async fn readable(&self) -> io::Result<()> {
        match &self.inner {
            NetworkUdpSocketInner::Static(socket) => socket.socket.readable().await,
            NetworkUdpSocketInner::Dynamic(socket) => socket.readable().await,
        }
    }

    async fn recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        match &self.inner {
            NetworkUdpSocketInner::Static(socket) => socket.socket.recv_buf_from(payload).await,
            NetworkUdpSocketInner::Dynamic(socket) => socket.recv_buf_from(payload).await,
        }
    }

    fn try_recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        match &self.inner {
            NetworkUdpSocketInner::Static(socket) => socket.socket.try_recv_buf_from(payload),
            NetworkUdpSocketInner::Dynamic(socket) => socket.try_recv_buf_from(payload),
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

fn lock_unpoisoned<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
