use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use ferrum2_runtime::{OwnerRegistry, RELAY_BUFFER_BYTES, relay_bidirectional_tracked};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct Endpoint<R, W> {
    reader: R,
    writer: W,
}

impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for Endpoint<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(context, buffer)
    }
}

impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for Endpoint<R, W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(context)
    }
}

struct CountingSource(Arc<AtomicUsize>);

impl AsyncRead for CountingSource {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let count = buffer.remaining();
        buffer.initialize_unfilled()[..count].fill(0x5a);
        buffer.advance(count);
        self.0.fetch_add(count, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

struct PendingReader;

impl AsyncRead for PendingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

struct StalledWriter(Arc<AtomicUsize>);

impl AsyncWrite for StalledWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

struct Sink;

impl AsyncWrite for Sink {
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
async fn stalled_writer_stops_upstream_at_one_fixed_buffer() {
    let bytes_read = Arc::new(AtomicUsize::new(0));
    let write_attempts = Arc::new(AtomicUsize::new(0));
    let registry = OwnerRegistry::new();
    let registry_for_owner = registry.clone();
    let mut inbound = Endpoint {
        reader: CountingSource(Arc::clone(&bytes_read)),
        writer: Sink,
    };
    let mut outbound = Endpoint {
        reader: PendingReader,
        writer: StalledWriter(Arc::clone(&write_attempts)),
    };

    let owner = tokio::spawn(async move {
        relay_bidirectional_tracked(&mut inbound, &mut outbound, &registry_for_owner).await
    });

    for _ in 0..100 {
        if write_attempts.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::task::yield_now().await;
    }

    assert_eq!(RELAY_BUFFER_BYTES, 16_384);
    assert_eq!(bytes_read.load(Ordering::SeqCst), RELAY_BUFFER_BYTES);
    assert_eq!(registry.snapshot().owned_buffers, 2);

    owner.abort();
    assert!(owner.await.expect_err("owner is cancelled").is_cancelled());
    assert_eq!(registry.snapshot().owned_buffers, 0);
}
