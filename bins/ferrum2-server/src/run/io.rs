use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use ferrum2_core::{AbortiveClose, LocalEndpoint};
use ferrum2_shadowsocks::{FlowTerminal, PlainDuplex, ShadowsocksError, TransportIo};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpSocket};

use super::RunError;

pub(super) fn bind_listener(
    address: std::net::SocketAddrV4,
    backlog: u32,
) -> Result<TcpListener, RunError> {
    let socket = TcpSocket::new_v4().map_err(|_| RunError::StartupBind)?;
    #[cfg(unix)]
    socket
        .set_reuseaddr(true)
        .map_err(|_| RunError::StartupBind)?;
    socket
        .bind(SocketAddr::V4(address))
        .map_err(|_| RunError::StartupBind)?;
    socket.listen(backlog).map_err(|_| RunError::StartupBind)
}

pub(super) async fn shutdown_signal() {
    #[cfg(windows)]
    {
        let Ok(mut ctrl_break) = tokio::signal::windows::ctrl_break() else {
            std::future::pending::<()>().await;
            return;
        };
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if result.is_err() {
                    std::future::pending::<()>().await;
                }
            }
            signal = ctrl_break.recv() => {
                if signal.is_none() {
                    std::future::pending::<()>().await;
                }
            }
        }
    }
    #[cfg(not(windows))]
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

pub(super) struct TokioTransport<T> {
    inner: T,
}

impl<T> TokioTransport<T> {
    pub(super) const fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T> LocalEndpoint for TokioTransport<T>
where
    T: LocalEndpoint,
{
    fn local_socket_addr(&self) -> std::net::SocketAddr {
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
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::from(io::ErrorKind::Other))),
        }
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        Pin::new(&mut self.inner)
            .poll_write(cx, source)
            .map_err(|_| io::Error::from(io::ErrorKind::Other))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::IoError>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(|_| io::Error::from(io::ErrorKind::Other))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::IoError>> {
        Pin::new(&mut self.inner)
            .poll_shutdown(cx)
            .map_err(|_| io::Error::from(io::ErrorKind::Other))
    }
}

pub(super) struct TokioFramed<F> {
    inner: F,
}

impl<F> TokioFramed<F> {
    pub(super) const fn new(inner: F) -> Self {
        Self { inner }
    }
}

impl<F> TokioFramed<F>
where
    F: PlainDuplex,
{
    pub(super) fn terminal(&self) -> Option<FlowTerminal> {
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
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::from(io::ErrorKind::InvalidData))),
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
    match error {
        ShadowsocksError::Detection(_) | ShadowsocksError::Protocol(_) => {
            io::Error::from(io::ErrorKind::InvalidData)
        }
        ShadowsocksError::Transport(_) | ShadowsocksError::Connect(_) => {
            io::Error::from(io::ErrorKind::Other)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use ferrum2_shadowsocks::TransportPhase;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;
    use crate::run::test_support::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn listener_policy_rebinds_after_traffic_and_excludes_live_contender() {
        let address = reserve_address();
        let listener = bind_listener(address, 1).expect("initial listener");
        let (client, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(address), listener.accept());
        let mut client = client.expect("client connect");
        let (mut accepted, _) = accepted.expect("listener accept");
        client.write_all(b"x").await.expect("client traffic");
        let mut request = [0_u8; 1];
        accepted
            .read_exact(&mut request)
            .await
            .expect("accepted traffic");
        accepted.write_all(b"y").await.expect("server traffic");
        accepted.shutdown().await.expect("server active close");
        let mut response = [0_u8; 1];
        client
            .read_exact(&mut response)
            .await
            .expect("client response");
        assert_eq!(response, *b"y");
        assert_eq!(client.read(&mut response).await.expect("client EOF"), 0);
        drop(accepted);
        drop(client);
        drop(listener);

        let rebound = bind_listener(address, 1).expect("exact listener restart");
        assert_eq!(
            bind_listener(address, 1).expect_err("live contender"),
            RunError::StartupBind
        );
        drop(rebound);
    }
    struct EndpointIo {
        inner: tokio::io::DuplexStream,
        endpoint: SocketAddrV4,
        aborts: Arc<AtomicUsize>,
    }

    impl AsyncRead for EndpointIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buffer)
        }
    }

    impl AsyncWrite for EndpointIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            source: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, source)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl LocalEndpoint for EndpointIo {
        fn local_socket_addr(&self) -> SocketAddr {
            SocketAddr::V4(self.endpoint)
        }
    }

    impl AbortiveClose for EndpointIo {
        type Error = io::Error;

        fn mark_abortive(&mut self) -> Result<(), Self::Error> {
            self.aborts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn adapter_contract_transport_delegates_io_and_abortive_close() {
        let endpoint = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_002);
        let aborts = Arc::new(AtomicUsize::new(0));
        let (inner, mut peer) = tokio::io::duplex(32);
        let mut transport = TokioTransport::new(EndpointIo {
            inner,
            endpoint,
            aborts: Arc::clone(&aborts),
        });

        peer.write_all(b"abc").await.expect("peer write");
        let mut read = [0_u8; 3];
        let count = std::future::poll_fn(|cx| Pin::new(&mut transport).poll_read(cx, &mut read))
            .await
            .expect("transport read");
        assert_eq!(count, 3);
        assert_eq!(&read, b"abc");

        let written = std::future::poll_fn(|cx| Pin::new(&mut transport).poll_write(cx, b"xyz"))
            .await
            .expect("transport write");
        assert_eq!(written, 3);
        let mut received = [0_u8; 3];
        peer.read_exact(&mut received).await.expect("peer read");
        assert_eq!(&received, b"xyz");

        std::future::poll_fn(|cx| Pin::new(&mut transport).poll_flush(cx))
            .await
            .expect("transport flush");
        transport.mark_abortive().expect("abortive delegation");
        assert_eq!(aborts.load(Ordering::SeqCst), 1);
    }

    struct FailingIo;

    impl AsyncRead for FailingIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("transport source sentinel")))
        }
    }

    impl AsyncWrite for FailingIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _source: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::other("transport source sentinel")))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("transport source sentinel")))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("transport source sentinel")))
        }
    }

    impl AbortiveClose for FailingIo {
        type Error = io::Error;

        fn mark_abortive(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn assert_source_free(error: io::Error) {
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.get_ref().is_none());
        assert!(!format!("{error:?}").contains("sentinel"));
    }

    #[tokio::test]
    async fn adapter_contract_transport_errors_are_fixed_and_source_free() {
        let mut transport = TokioTransport::new(FailingIo);
        let mut read = [0_u8; 1];
        assert_source_free(
            std::future::poll_fn(|cx| Pin::new(&mut transport).poll_read(cx, &mut read))
                .await
                .expect_err("read failure"),
        );
        assert_source_free(
            std::future::poll_fn(|cx| Pin::new(&mut transport).poll_write(cx, b"x"))
                .await
                .expect_err("write failure"),
        );
        assert_source_free(
            std::future::poll_fn(|cx| Pin::new(&mut transport).poll_flush(cx))
                .await
                .expect_err("flush failure"),
        );
        assert_source_free(
            std::future::poll_fn(|cx| Pin::new(&mut transport).poll_shutdown(cx))
                .await
                .expect_err("shutdown failure"),
        );
    }

    struct OneReadFlow {
        data: Option<&'static [u8]>,
        terminal: Option<FlowTerminal>,
    }

    impl PlainDuplex for OneReadFlow {
        fn poll_read_plain(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            destination: &mut [u8],
        ) -> Poll<Result<usize, ShadowsocksError>> {
            let data = self.data.take().unwrap_or_default();
            destination[..data.len()].copy_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }

        fn poll_write_plain(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            source: &[u8],
        ) -> Poll<Result<usize, ShadowsocksError>> {
            Poll::Ready(Ok(source.len()))
        }

        fn poll_flush_plain(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), ShadowsocksError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown_plain(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), ShadowsocksError>> {
            Poll::Ready(Ok(()))
        }

        fn terminal(&self) -> Option<FlowTerminal> {
            self.terminal
        }
    }

    #[tokio::test]
    async fn adapter_contract_framed_uses_initialized_readbuf_and_fixed_mapping() {
        let mut framed = TokioFramed::new(OneReadFlow {
            data: Some(b"xyz"),
            terminal: Some(FlowTerminal::Normal),
        });
        let mut read = [0xa5_u8; 3];
        framed.read_exact(&mut read).await.expect("framed read");
        assert_eq!(&read, b"xyz");
        assert_eq!(framed.terminal(), Some(FlowTerminal::Normal));

        for error in [
            ShadowsocksError::Detection(DetectionReason::Authentication),
            ShadowsocksError::Protocol(ProtocolReason::FrameBounds),
        ] {
            let mapped = framed_error(error);
            assert_eq!(mapped.kind(), io::ErrorKind::InvalidData);
            assert!(mapped.get_ref().is_none());
            assert!(!format!("{mapped:?}").contains("sentinel"));
        }
        for phase in [
            TransportPhase::Read,
            TransportPhase::Write,
            TransportPhase::WriteZero,
            TransportPhase::Flush,
            TransportPhase::Shutdown,
        ] {
            let mapped = framed_error(ShadowsocksError::Transport(phase));
            assert_eq!(mapped.kind(), io::ErrorKind::Other);
            assert!(mapped.get_ref().is_none());
            assert!(!format!("{mapped:?}").contains("sentinel"));
        }
    }
}
