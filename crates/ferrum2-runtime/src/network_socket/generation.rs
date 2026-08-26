use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};

use bytes::BytesMut;
use ferrum2_core::{AbortiveClose, LocalEndpoint};
use ferrum2_net::ResolvedInterface;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;

use crate::{
    DirectUdpSocket, NetworkRuntimeCancellation, NetworkRuntimeOwner,
    NetworkRuntimeOwnerCancellation,
};

/// TCP stream retained with its exact interface decision and reset acknowledgement owner.
#[must_use = "dropping the wrapper closes the stream and acknowledges reset cancellation"]
pub struct GenerationBoundTcpStream<T> {
    stream: Arc<StdMutex<Option<T>>>,
    owner: Arc<StdMutex<Option<NetworkRuntimeOwner>>>,
    resolved: ResolvedInterface,
    local_socket_addr: SocketAddr,
    closed: Arc<StdMutex<Option<NetworkRuntimeOwnerCancellation>>>,
    cancellation: StdMutex<Pin<Box<dyn Future<Output = NetworkRuntimeOwnerCancellation> + Send>>>,
    drop_signal: Option<oneshot::Sender<()>>,
    _monitor: tokio::task::JoinHandle<()>,
}

impl<T: LocalEndpoint + Send + 'static> GenerationBoundTcpStream<T> {
    pub(super) fn new(stream: T, resolved: ResolvedInterface, owner: NetworkRuntimeOwner) -> Self {
        let local_socket_addr = stream.local_socket_addr();
        let stream = Arc::new(StdMutex::new(Some(stream)));
        let closed = Arc::new(StdMutex::new(None));
        let cancellation = owner.cancellation();
        let owner = Arc::new(StdMutex::new(Some(owner)));
        let mut operation_cancellation = cancellation.clone();
        let mut monitor_cancellation = cancellation;
        let monitor_stream = Arc::clone(&stream);
        let monitor_owner = Arc::clone(&owner);
        let monitor_closed = Arc::clone(&closed);
        let (drop_signal, drop_receiver) = oneshot::channel();
        let monitor = tokio::spawn(async move {
            let terminal = tokio::select! {
                biased;
                cancellation = monitor_cancellation.cancelled() => Some(cancellation),
                _ = drop_receiver => None,
            };
            let mut stream_guard = lock_unpoisoned(&monitor_stream);
            let stream = stream_guard.take();
            drop(stream);
            if let Some(terminal) = terminal {
                *lock_unpoisoned(&monitor_closed) = Some(terminal);
            }
            let owner = lock_unpoisoned(&monitor_owner).take();
            drop(owner);
            drop(stream_guard);
        });
        Self {
            stream,
            owner,
            resolved,
            local_socket_addr,
            closed,
            cancellation: StdMutex::new(Box::pin(async move {
                operation_cancellation.cancelled().await
            })),
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
        let cancellation = {
            let mut cancellation = lock_unpoisoned(&self.cancellation);
            cancellation.as_mut().poll(context)
        };
        match cancellation {
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
        let mut stream_guard = lock_unpoisoned(&self.stream);
        let stream = stream_guard.take();
        drop(stream);
        *lock_unpoisoned(&self.closed) = Some(cancellation);
        let owner = lock_unpoisoned(&self.owner).take();
        drop(owner);
        drop(stream_guard);
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
        let mut stream_guard = lock_unpoisoned(&self.stream);
        let stream = stream_guard.take();
        drop(stream);
        let owner = lock_unpoisoned(&self.owner).take();
        drop(owner);
        drop(stream_guard);
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
    resource: Arc<StdMutex<Option<Arc<GenerationBoundUdpResource<T>>>>>,
    resolved: ResolvedInterface,
    cancellation: NetworkRuntimeCancellation,
    closed: Arc<StdMutex<Option<NetworkRuntimeOwnerCancellation>>>,
    drop_signal: Option<oneshot::Sender<()>>,
    _monitor: tokio::task::JoinHandle<()>,
}

struct GenerationBoundUdpResource<T> {
    socket: Option<T>,
    owner: Option<NetworkRuntimeOwner>,
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

fn close_generation_bound_udp_resource<T>(
    resource: &Arc<StdMutex<Option<Arc<GenerationBoundUdpResource<T>>>>>,
    closed: &Arc<StdMutex<Option<NetworkRuntimeOwnerCancellation>>>,
    terminal: Option<NetworkRuntimeOwnerCancellation>,
) {
    if let Some(terminal) = terminal {
        *lock_unpoisoned(closed) = Some(terminal);
    }
    let mut resource_guard = lock_unpoisoned(resource);
    let resource = resource_guard.take();
    drop(resource);
    drop(resource_guard);
}

impl<T: Send + Sync + 'static> GenerationBoundUdpSocket<T> {
    pub(super) fn new(socket: T, resolved: ResolvedInterface, owner: NetworkRuntimeOwner) -> Self {
        let cancellation = owner.cancellation();
        let mut monitor_cancellation = cancellation.clone();
        let resource = Arc::new(StdMutex::new(Some(Arc::new(GenerationBoundUdpResource {
            socket: Some(socket),
            owner: Some(owner),
        }))));
        let closed = Arc::new(StdMutex::new(None));
        let monitor_resource = Arc::clone(&resource);
        let monitor_closed = Arc::clone(&closed);
        let (drop_signal, drop_receiver) = oneshot::channel();
        let monitor = tokio::spawn(async move {
            let terminal = tokio::select! {
                biased;
                cancellation = monitor_cancellation.cancelled() => Some(cancellation),
                _ = drop_receiver => None,
            };
            close_generation_bound_udp_resource(&monitor_resource, &monitor_closed, terminal);
        });
        Self {
            resource,
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
        lock_unpoisoned(&self.resource).is_none()
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

    fn live_resource(&self) -> io::Result<Arc<GenerationBoundUdpResource<T>>> {
        lock_unpoisoned(&self.resource)
            .as_ref()
            .cloned()
            .ok_or_else(closed_resource_io_error)
    }

    fn try_live_resource(&self) -> io::Result<Arc<GenerationBoundUdpResource<T>>> {
        let resource = match self.resource.try_lock() {
            Ok(resource) => resource,
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
        };
        resource
            .as_ref()
            .cloned()
            .ok_or_else(closed_resource_io_error)
    }

    fn close(&self, terminal: NetworkRuntimeOwnerCancellation) {
        close_generation_bound_udp_resource(&self.resource, &self.closed, Some(terminal));
    }
}

impl<T> Drop for GenerationBoundUdpSocket<T> {
    fn drop(&mut self) {
        close_generation_bound_udp_resource(&self.resource, &self.closed, None);
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
