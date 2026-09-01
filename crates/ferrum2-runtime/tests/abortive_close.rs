use std::io;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum2_core::AbortiveClose;
use ferrum2_runtime::{RuntimeTcpStream, relay_bidirectional};
use socket2::SockRef;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

async fn connected_pair() -> (RuntimeTcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener address");
    let connect = TcpStream::connect(address);
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(connect, accept);
    (
        RuntimeTcpStream::from_connected(client.expect("connect stream")).expect("IPv4 endpoint"),
        accepted.expect("accept stream").0,
    )
}

async fn connected_stream() -> RuntimeTcpStream {
    let (stream, peer) = connected_pair().await;
    drop(peer);
    stream
}

#[tokio::test]
async fn mark_abortive_alone_sets_zero_linger() {
    let mut stream = connected_stream().await;
    assert_eq!(SockRef::from(stream.as_ref()).linger().unwrap(), None);

    stream.mark_abortive().expect("set zero linger");

    assert_eq!(
        SockRef::from(stream.as_ref()).linger().unwrap(),
        Some(Duration::ZERO)
    );
}

#[tokio::test]
async fn ordinary_shutdown_does_not_set_linger() {
    let mut stream = connected_stream().await;

    stream.shutdown().await.expect("normal write shutdown");

    assert_eq!(SockRef::from(stream.as_ref()).linger().unwrap(), None);
}

#[tokio::test]
async fn ordinary_eof_does_not_set_linger() {
    let (mut stream, peer) = connected_pair().await;
    drop(peer);
    let mut byte = [0_u8; 1];

    assert_eq!(stream.read(&mut byte).await.expect("read EOF"), 0);
    assert_eq!(SockRef::from(stream.as_ref()).linger().unwrap(), None);
}

struct FailingRelayIo;

impl AsyncRead for FailingRelayIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("scripted relay failure")))
    }
}

impl AsyncWrite for FailingRelayIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn ordinary_relay_failure_does_not_set_linger() {
    let (mut stream, peer) = connected_pair().await;
    let mut failing = FailingRelayIo;

    assert!(
        relay_bidirectional(&mut stream, &mut failing)
            .await
            .is_err()
    );
    assert_eq!(SockRef::from(stream.as_ref()).linger().unwrap(), None);
    drop(peer);
}
