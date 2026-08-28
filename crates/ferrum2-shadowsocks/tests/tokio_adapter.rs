#![cfg(feature = "tokio")]

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::BytesMut;
use ferrum2_core::{AbortiveClose, ConnectError, Connector, LocalEndpoint, TargetAddr};
use ferrum2_shadowsocks::tokio::{TokioConnector, TokioFramed, TokioTransport};
use ferrum2_shadowsocks::{
    DetectionReason, FlowTerminal, PlainBufferedDuplex, PlainDuplex, ProtocolReason,
    ShadowsocksError, TransportIo, TransportPhase,
};
use tokio::io::{
    AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf,
};
use tokio::sync::Notify;

struct EndpointIo {
    inner: tokio::io::DuplexStream,
    endpoint: SocketAddr,
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
        self.endpoint
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
async fn transport_delegates_io_endpoint_and_abortive_close() {
    let endpoint = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 40_002);
    let aborts = Arc::new(AtomicUsize::new(0));
    let (inner, mut peer) = tokio::io::duplex(32);
    let mut transport = TokioTransport::new(EndpointIo {
        inner,
        endpoint,
        aborts: Arc::clone(&aborts),
    });

    peer.write_all(b"abc").await.expect("peer write");
    let mut read = BytesMut::with_capacity(3);
    let count = std::future::poll_fn(|cx| Pin::new(&mut transport).poll_read_buf(cx, &mut read, 3))
        .await
        .expect("transport read");
    assert_eq!(count, 3);
    assert_eq!(read.as_ref(), b"abc");
    assert_eq!(transport.local_socket_addr(), endpoint);

    let written = std::future::poll_fn(|cx| Pin::new(&mut transport).poll_write(cx, b"xyz"))
        .await
        .expect("transport write");
    assert_eq!(written, 3);
    let mut received = [0_u8; 3];
    peer.read_exact(&mut received).await.expect("peer read");
    assert_eq!(&received, b"xyz");

    transport.mark_abortive().expect("abortive delegation");
    assert_eq!(aborts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn transport_appends_only_successful_bytes_with_exact_spare_limits() {
    let endpoint = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 40_003);
    let (inner, mut peer) = tokio::io::duplex(32);
    let mut transport = TokioTransport::new(EndpointIo {
        inner,
        endpoint,
        aborts: Arc::new(AtomicUsize::new(0)),
    });
    let mut scratch = BytesMut::with_capacity(32);
    scratch.extend_from_slice(b"prefix");
    let pointer = scratch.as_ptr();
    let capacity = scratch.capacity();

    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        Pin::new(&mut transport).poll_read_buf(&mut cx, &mut scratch, 3),
        Poll::Pending
    ));
    assert_eq!(scratch.as_ref(), b"prefix");
    assert_eq!(scratch.as_ptr(), pointer);
    assert_eq!(scratch.capacity(), capacity);

    peer.write_all(b"abcdefghij").await.expect("peer write");
    let first =
        std::future::poll_fn(|cx| Pin::new(&mut transport).poll_read_buf(cx, &mut scratch, 3))
            .await
            .expect("first limited read");
    assert_eq!(first, 3);
    assert_eq!(scratch.as_ref(), b"prefixabc");
    let second =
        std::future::poll_fn(|cx| Pin::new(&mut transport).poll_read_buf(cx, &mut scratch, 7))
            .await
            .expect("second limited read");
    assert_eq!(second, 7);
    assert_eq!(scratch.as_ref(), b"prefixabcdefghij");
    assert_eq!(scratch.as_ptr(), pointer);
    assert_eq!(scratch.capacity(), capacity);
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

fn assert_source_free(error: io::Error, expected: io::ErrorKind) {
    assert_eq!(error.kind(), expected);
    assert!(error.get_ref().is_none());
    assert!(!format!("{error:?}").contains("sentinel"));
}

#[tokio::test]
async fn transport_erases_all_io_error_sources() {
    let mut transport = TokioTransport::new(FailingIo);
    let mut read = BytesMut::with_capacity(1);
    assert_source_free(
        std::future::poll_fn(|cx| Pin::new(&mut transport).poll_read_buf(cx, &mut read, 1))
            .await
            .expect_err("read failure"),
        io::ErrorKind::Other,
    );
    assert!(read.is_empty(), "failed read must not expose spare bytes");
    assert_source_free(
        std::future::poll_fn(|cx| Pin::new(&mut transport).poll_write(cx, b"x"))
            .await
            .expect_err("write failure"),
        io::ErrorKind::Other,
    );
    assert_source_free(
        std::future::poll_fn(|cx| Pin::new(&mut transport).poll_flush(cx))
            .await
            .expect_err("flush failure"),
        io::ErrorKind::Other,
    );
    assert_source_free(
        std::future::poll_fn(|cx| Pin::new(&mut transport).poll_shutdown(cx))
            .await
            .expect_err("shutdown failure"),
        io::ErrorKind::Other,
    );
}

struct BufferedViewFlow {
    data: Vec<u8>,
    position: usize,
}

impl PlainDuplex for BufferedViewFlow {
    fn poll_read_plain(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, ShadowsocksError>> {
        let copied = destination.len().min(self.data.len() - self.position);
        destination[..copied].copy_from_slice(&self.data[self.position..self.position + copied]);
        self.position += copied;
        Poll::Ready(Ok(copied))
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
        None
    }
}

impl PlainBufferedDuplex for BufferedViewFlow {
    fn poll_fill_plain_buf(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<&[u8], ShadowsocksError>> {
        let this = self.get_mut();
        Poll::Ready(Ok(&this.data[this.position..]))
    }

    fn consume_plain(mut self: Pin<&mut Self>, amount: usize) {
        assert!(amount <= self.data.len() - self.position);
        self.position += amount;
    }
}

#[tokio::test]
async fn framed_buffer_view_advances_only_when_consumed() {
    let mut framed = TokioFramed::new(BufferedViewFlow {
        data: b"plaintext view".to_vec(),
        position: 0,
    });
    let first = framed.fill_buf().await.expect("first view");
    let first_pointer = first.as_ptr();
    assert_eq!(first, b"plaintext view");
    framed.consume(5);
    let second = framed.fill_buf().await.expect("second view");
    assert_eq!(second, b"text view");
    assert_eq!(second.as_ptr(), first_pointer.wrapping_add(5));
}

struct GateConnector {
    gate: Arc<Notify>,
    calls: Arc<AtomicUsize>,
    targets: Arc<Mutex<Vec<TargetAddr>>>,
    stream: Mutex<Option<EndpointIo>>,
}

impl Connector for GateConnector {
    type Stream = EndpointIo;

    fn connect(
        &self,
        target: &TargetAddr,
    ) -> impl Future<Output = Result<Self::Stream, ConnectError>> + Send {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.targets
            .lock()
            .expect("connector targets")
            .push(target.clone());
        async move {
            self.gate.notified().await;
            Ok(self
                .stream
                .lock()
                .expect("connector stream")
                .take()
                .expect("single connection"))
        }
    }
}

#[tokio::test]
async fn connector_preserves_pending_target_and_endpoint() {
    let endpoint = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 40_004);
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
        stream: Mutex::new(Some(EndpointIo {
            inner,
            endpoint,
            aborts: Arc::new(AtomicUsize::new(0)),
        })),
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
    assert_eq!(stream.local_socket_addr(), endpoint);
}

struct OneReadFlow {
    result: Option<Result<&'static [u8], ShadowsocksError>>,
    terminal: Option<FlowTerminal>,
}

impl PlainDuplex for OneReadFlow {
    fn poll_read_plain(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, ShadowsocksError>> {
        match self.result.take().unwrap_or(Ok(&[])) {
            Ok(data) => {
                destination[..data.len()].copy_from_slice(data);
                Poll::Ready(Ok(data.len()))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
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

impl PlainBufferedDuplex for OneReadFlow {
    fn poll_fill_plain_buf(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<&[u8], ShadowsocksError>> {
        match self.result.as_ref().unwrap_or(&Ok(&[])) {
            Ok(data) => Poll::Ready(Ok(data)),
            Err(error) => Poll::Ready(Err(*error)),
        }
    }

    fn consume_plain(mut self: Pin<&mut Self>, amount: usize) {
        match self.result.take().unwrap_or(Ok(&[])) {
            Ok(data) => assert_eq!(amount, data.len()),
            Err(_) => assert_eq!(amount, 0),
        }
    }
}

#[tokio::test]
async fn framed_uses_initialized_readbuf_and_closed_error_mapping() {
    let mut framed = TokioFramed::new(OneReadFlow {
        result: Some(Ok(b"xyz")),
        terminal: Some(FlowTerminal::Normal),
    });
    let mut read = [0xa5_u8; 3];
    framed.read_exact(&mut read).await.expect("framed read");
    assert_eq!(&read, b"xyz");
    assert_eq!(framed.terminal(), Some(FlowTerminal::Normal));

    for (error, kind) in [
        (
            ShadowsocksError::Detection(DetectionReason::Authentication),
            io::ErrorKind::InvalidData,
        ),
        (
            ShadowsocksError::Protocol(ProtocolReason::FrameBounds),
            io::ErrorKind::InvalidData,
        ),
        (
            ShadowsocksError::Transport(TransportPhase::Read),
            io::ErrorKind::Other,
        ),
        (
            ShadowsocksError::Connect(ferrum2_core::ConnectErrorKind::Other),
            io::ErrorKind::Other,
        ),
    ] {
        let mut framed = TokioFramed::new(OneReadFlow {
            result: Some(Err(error)),
            terminal: None,
        });
        let error = framed
            .read(&mut [0_u8; 1])
            .await
            .expect_err("closed adapter error");
        assert_source_free(error, kind);
    }
}
