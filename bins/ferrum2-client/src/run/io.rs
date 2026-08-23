use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use ferrum2_core::{AbortiveClose, LocalEndpoint};
#[cfg(any(not(windows), test))]
use ferrum2_core::{ConnectError, Connector, TargetAddr};
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

#[cfg(any(not(windows), test))]
pub(super) struct TokioConnector<C> {
    inner: C,
}

#[cfg(any(not(windows), test))]
impl<C> TokioConnector<C> {
    pub(super) const fn new(inner: C) -> Self {
        Self { inner }
    }
}

#[cfg(any(not(windows), test))]
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
    fn local_endpoint(&self) -> std::net::SocketAddrV4 {
        self.inner.local_endpoint()
    }

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
pub(in crate::run) mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Mutex;

    use ferrum2_shadowsocks::TransportPhase;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::Notify;

    use super::*;
    use crate::run::test_support::*;

    #[test]
    fn tokio_transport_preserves_full_ipv6_local_endpoint() {
        struct FullEndpoint;

        impl LocalEndpoint for FullEndpoint {
            fn local_endpoint(&self) -> std::net::SocketAddrV4 {
                std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)
            }

            fn local_socket_addr(&self) -> SocketAddr {
                SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 49_152)
            }
        }

        assert_eq!(
            TokioTransport::new(FullEndpoint).local_socket_addr(),
            "[::1]:49152".parse().expect("IPv6 endpoint")
        );
    }

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

    fn assert_source_free(error: io::Error) {
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.get_ref().is_none());
        assert!(!format!("{error:?}").contains("sentinel"));
    }

    #[tokio::test]
    async fn adapter_contract_transport_delegates_and_redacts_all_io_failures() {
        let endpoint = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_001);
        let aborts = Arc::new(AtomicUsize::new(0));
        let (inner, mut peer) = tokio::io::duplex(32);
        let mut delegated =
            TokioTransport::new(ScriptedIo::duplex(inner, endpoint, Arc::clone(&aborts)));
        peer.write_all(b"abc").await.expect("peer write");
        let mut data = [0_u8; 3];
        assert_eq!(
            std::future::poll_fn(|cx| Pin::new(&mut delegated).poll_read(cx, &mut data))
                .await
                .expect("read"),
            3
        );
        assert_eq!(&data, b"abc");
        assert_eq!(delegated.local_endpoint(), endpoint);
        delegated.mark_abortive().expect("abortive delegation");
        assert_eq!(aborts.load(Ordering::SeqCst), 1);

        let mut transport = TokioTransport::new(ScriptedIo::failing());
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

    #[tokio::test]
    async fn adapter_contract_connector_preserves_pending_target_and_endpoint() {
        let endpoint = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_004);
        let requested = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8_388))
            .expect("configured server target");
        let gate = Arc::new(Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let targets = Arc::new(Mutex::new(Vec::new()));
        let (inner, _peer) = tokio::io::duplex(32);
        let connector = TokioConnector::new(GateConnector {
            gate: Arc::clone(&gate),
            calls: Arc::clone(&calls),
            targets: Arc::clone(&targets),
            stream: Mutex::new(Some(ScriptedIo::duplex(
                inner,
                endpoint,
                Arc::new(AtomicUsize::new(0)),
            ))),
        });
        let task_target = requested.clone();
        let task = tokio::spawn(async move { connector.connect(&task_target).await });

        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            targets.lock().expect("connector targets").as_slice(),
            &[requested]
        );
        assert!(!task.is_finished(), "connector Pending must be preserved");

        gate.notify_one();
        let stream = task.await.expect("connector task").expect("connected");
        assert_eq!(stream.local_endpoint(), endpoint);
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
