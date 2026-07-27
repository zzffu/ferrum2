use std::future::pending;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum2_runtime::{OwnerRegistry, RELAY_BUFFER_BYTES, relay_lifecycle};
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

struct CountingSource {
    payload: Vec<u8>,
    offset: usize,
    observed: Arc<AtomicUsize>,
}

impl AsyncRead for CountingSource {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let count = buffer
            .remaining()
            .min(self.payload.len().saturating_sub(self.offset));
        if count == 0 {
            return Poll::Ready(Ok(()));
        }
        let end = self.offset + count;
        buffer.put_slice(&self.payload[self.offset..end]);
        self.offset = end;
        self.observed.fetch_add(count, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

struct EofReader;

impl AsyncRead for EofReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct WriterState {
    open: AtomicBool,
    attempts: AtomicUsize,
    wake: Mutex<Option<std::task::Waker>>,
    bytes: Mutex<Vec<u8>>,
}

impl WriterState {
    fn resume(&self) {
        self.open.store(true, Ordering::SeqCst);
        if let Some(waker) = self.wake.lock().expect("wake lock").take() {
            waker.wake();
        }
    }
}

struct StalledWriter(Arc<WriterState>);

impl AsyncWrite for StalledWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.attempts.fetch_add(1, Ordering::SeqCst);
        if !self.0.open.load(Ordering::SeqCst) {
            *self.0.wake.lock().expect("wake lock") = Some(context.waker().clone());
            return Poll::Pending;
        }
        self.0
            .bytes
            .lock()
            .expect("bytes lock")
            .extend_from_slice(buffer);
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.0.open.load(Ordering::SeqCst) {
            Poll::Ready(Ok(()))
        } else {
            *self.0.wake.lock().expect("wake lock") = Some(context.waker().clone());
            Poll::Pending
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(context)
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
    let payload: Vec<u8> = (0..RELAY_BUFFER_BYTES * 2 + 37)
        .map(|index| (index % 251) as u8)
        .collect();
    let bytes_read = Arc::new(AtomicUsize::new(0));
    let writer = Arc::new(WriterState {
        open: AtomicBool::new(false),
        attempts: AtomicUsize::new(0),
        wake: Mutex::new(None),
        bytes: Mutex::new(Vec::new()),
    });
    let registry = OwnerRegistry::new();
    let registry_for_owner = registry.clone();
    let mut inbound = Endpoint {
        reader: CountingSource {
            payload: payload.clone(),
            offset: 0,
            observed: Arc::clone(&bytes_read),
        },
        writer: Sink,
    };
    let mut outbound = Endpoint {
        reader: EofReader,
        writer: StalledWriter(Arc::clone(&writer)),
    };

    let owner = tokio::spawn(async move {
        relay_lifecycle(
            &mut inbound,
            &mut outbound,
            Duration::from_secs(60),
            &registry_for_owner,
            pending(),
        )
        .await
    });

    for _ in 0..100 {
        if writer.attempts.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::task::yield_now().await;
    }

    assert_eq!(RELAY_BUFFER_BYTES, 16_384);
    assert_eq!(bytes_read.load(Ordering::SeqCst), RELAY_BUFFER_BYTES);
    assert_eq!(registry.snapshot().owned_buffers, 2);

    writer.resume();
    let stats = owner.await.expect("owner task").expect("relay completes");
    assert_eq!(stats.inbound_to_outbound, payload.len() as u64);
    assert_eq!(*writer.bytes.lock().expect("bytes lock"), payload);
    assert_eq!(registry.snapshot().owned_buffers, 0);
}
