//! Tokio adapters for the socket-free Shadowsocks transport interfaces.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use ::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use ferrum2_core::{AbortiveClose, ConnectError, Connector, LocalEndpoint, TargetAddr};

use crate::{FlowTerminal, PlainDuplex, ShadowsocksError, TransportIo};

/// Adapts a core connector so its streams implement [`TransportIo`].
pub struct TokioConnector<C> {
    inner: C,
}

impl<C> TokioConnector<C> {
    /// Wraps a connector without changing its connection policy.
    pub const fn new(inner: C) -> Self {
        Self { inner }
    }
}

impl<C> Connector for TokioConnector<C>
where
    C: Connector,
    C::Stream: AbortiveClose,
{
    type Stream = TokioTransport<C::Stream>;

    async fn connect(&self, target: &TargetAddr) -> Result<Self::Stream, ConnectError> {
        self.inner.connect(target).await.map(TokioTransport::new)
    }
}

/// Adapts Tokio byte I/O to the closed Shadowsocks transport interface.
pub struct TokioTransport<T> {
    inner: T,
}

impl<T> TokioTransport<T> {
    /// Wraps one Tokio transport without changing its ownership.
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T> LocalEndpoint for TokioTransport<T>
where
    T: LocalEndpoint,
{
    fn local_socket_addr(&self) -> SocketAddr {
        self.inner.local_socket_addr()
    }
}

impl<T> AbortiveClose for TokioTransport<T>
where
    T: AbortiveClose,
{
    type Error = T::Error;

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        self.inner.mark_abortive()
    }
}

impl<T> TransportIo for TokioTransport<T>
where
    T: AsyncRead + AsyncWrite + AbortiveClose + Send + Unpin,
{
    type IoError = io::Error;

    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        let mut buffer = ReadBuf::new(destination);
        match Pin::new(&mut self.inner).poll_read(cx, &mut buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buffer.filled().len())),
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::ErrorKind::Other.into())),
        }
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        Pin::new(&mut self.inner)
            .poll_write(cx, source)
            .map_err(|_| io::ErrorKind::Other.into())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::IoError>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(|_| io::ErrorKind::Other.into())
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::IoError>> {
        Pin::new(&mut self.inner)
            .poll_shutdown(cx)
            .map_err(|_| io::ErrorKind::Other.into())
    }
}

/// Adapts one decrypted Shadowsocks flow to Tokio [`AsyncRead`] and [`AsyncWrite`].
pub struct TokioFramed<F> {
    inner: F,
}

impl<F> TokioFramed<F> {
    /// Wraps a decrypted flow without changing protocol state.
    pub const fn new(inner: F) -> Self {
        Self { inner }
    }
}

impl<F> TokioFramed<F>
where
    F: PlainDuplex,
{
    /// Returns the immutable route terminal selected for the flow, when known.
    pub fn terminal(&self) -> Option<FlowTerminal> {
        self.inner.terminal()
    }
}

impl<F> AsyncRead for TokioFramed<F>
where
    F: PlainDuplex,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let remaining = buffer.remaining();
        let result = {
            let destination = buffer.initialize_unfilled();
            Pin::new(&mut self.inner).poll_read_plain(cx, destination)
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(read)) if read <= remaining => {
                buffer.advance(read);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::ErrorKind::InvalidData.into())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(framed_error(error))),
        }
    }
}

impl<F> AsyncWrite for TokioFramed<F>
where
    F: PlainDuplex,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner)
            .poll_write_plain(cx, source)
            .map_err(framed_error)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_flush_plain(cx)
            .map_err(framed_error)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_shutdown_plain(cx)
            .map_err(framed_error)
    }
}

fn framed_error(error: ShadowsocksError) -> io::Error {
    let kind = match error {
        ShadowsocksError::Detection(_) | ShadowsocksError::Protocol(_) => {
            io::ErrorKind::InvalidData
        }
        ShadowsocksError::Transport(_) | ShadowsocksError::Connect(_) => io::ErrorKind::Other,
    };
    kind.into()
}
