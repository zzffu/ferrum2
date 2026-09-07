use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{Capture, Direction};

/// Observes successful reads exactly once; writes and transport lifecycle are unchanged.
/// Wrap the application reader as Upload and the upstream reader as Download.
pub struct ObservedIo<'a, IO> {
    inner: &'a mut IO,
    capture: &'a Capture,
    direction: Direction,
}

impl<'a, IO> ObservedIo<'a, IO> {
    pub fn new(inner: &'a mut IO, capture: &'a Capture, direction: Direction) -> Self {
        Self {
            inner,
            capture,
            direction,
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for ObservedIo<'_, IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut *self.inner).poll_read(cx, buffer);
        if let Poll::Ready(Ok(())) = &result {
            self.capture
                .observe(self.direction, &buffer.filled()[before..]);
        }
        result
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for ObservedIo<'_, IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write_vectored(cx, bytes)
    }
}
