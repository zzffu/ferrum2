//! Tokio adapters for the socket-free Shadowsocks transport interfaces.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use ::tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};
use bytes::{BufMut, BytesMut};
use ferrum2_core::{AbortiveClose, ConnectError, Connector, LocalEndpoint, TargetAddr};
use ferrum2_crypto::{Clock, SecureRandom};
#[cfg(feature = "structural-metrics")]
use ferrum2_structural::StructuralLocal;

use crate::tcp::{FusedRelayDirection as CoreFusedRelayDirection, fused_relay};
use crate::{
    ClientFlow, FlowTerminal, PlainBufferedDuplex, PlainDuplex, ServerFlow, ShadowsocksError,
    TcpKeyProvider, TransportIo,
};

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

    fn poll_read_buf(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut BytesMut,
        limit: usize,
    ) -> Poll<Result<usize, Self::IoError>> {
        let mut limited = (&mut *destination).limit(limit);
        tokio_util::io::poll_read_buf(Pin::new(&mut self.inner), cx, &mut limited)
            .map_err(|_| io::ErrorKind::Other.into())
    }

    fn poll_read_initialized(
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

/// Direction of plaintext accepted by the fused single-hop relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FusedRelayDirection {
    /// Bytes read from the raw endpoint and admitted by the encrypted tunnel.
    PlainToTunnel,
    /// Authenticated tunnel bytes accepted by the raw endpoint.
    TunnelToPlain,
}

/// Runs the zero-copy payload relay for one concrete client flow.
pub async fn relay_client_flow<P, S, K, T, O>(
    plain: &mut P,
    flow: &mut ClientFlow<'_, S, K, T>,
    mut observe: O,
    #[cfg(feature = "structural-metrics")] structural: &StructuralLocal,
) -> io::Result<()>
where
    P: AsyncRead + AsyncWrite + Unpin,
    S: TransportIo,
    K: TcpKeyProvider + Sync,
    T: Clock + Sync,
    O: FnMut(FusedRelayDirection, usize) + Unpin,
{
    fused_relay(
        plain,
        flow,
        move |direction, bytes| {
            observe(public_fused_direction(direction), bytes);
        },
        #[cfg(feature = "structural-metrics")]
        structural,
    )
    .await
}

/// Runs the zero-copy payload relay for one concrete server flow.
pub async fn relay_server_flow<P, S, K, T, R, O>(
    plain: &mut P,
    flow: &mut ServerFlow<'_, S, K, T, R>,
    mut observe: O,
    #[cfg(feature = "structural-metrics")] structural: &StructuralLocal,
) -> io::Result<()>
where
    P: AsyncRead + AsyncWrite + Unpin,
    S: TransportIo,
    K: TcpKeyProvider + Sync,
    T: Clock + Sync,
    R: SecureRandom,
    O: FnMut(FusedRelayDirection, usize) + Unpin,
{
    fused_relay(
        plain,
        flow,
        move |direction, bytes| {
            observe(public_fused_direction(direction), bytes);
        },
        #[cfg(feature = "structural-metrics")]
        structural,
    )
    .await
}

const fn public_fused_direction(direction: CoreFusedRelayDirection) -> FusedRelayDirection {
    match direction {
        CoreFusedRelayDirection::PlainToTunnel => FusedRelayDirection::PlainToTunnel,
        CoreFusedRelayDirection::TunnelToPlain => FusedRelayDirection::TunnelToPlain,
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

impl<F> AsyncBufRead for TokioFramed<F>
where
    F: PlainBufferedDuplex,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner)
            .poll_fill_plain_buf(cx)
            .map_err(framed_error)
    }

    fn consume(mut self: Pin<&mut Self>, amount: usize) {
        Pin::new(&mut self.inner).consume_plain(amount);
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
