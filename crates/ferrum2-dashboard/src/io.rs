use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::Connection;

/// The direction of bytes written to this endpoint, relative to the proxied client.
#[derive(Clone, Copy, Debug)]
pub enum Direction {
    Upload,
    Download,
}

/// Transparent I/O adapter counting successful writes only, never reads. Wrap the
/// upstream destination as Upload and the application destination as Download.
/// Flush, shutdown, vectored writes, errors and EOF retain the inner stream's behavior.
/// The lease is owned until this adapter is dropped; no background task is created.
pub struct ObservedIo<T> {
    inner: T,
    connection: Connection,
    direction: Direction,
}

impl<T> ObservedIo<T> {
    /// Wraps an endpoint without changing its shutdown or ownership semantics.
    pub fn new(inner: T, connection: Connection, direction: Direction) -> Self {
        Self {
            inner,
            connection,
            direction,
        }
    }

    fn count(&self, result: &Poll<io::Result<usize>>) {
        if let Poll::Ready(Ok(bytes)) = result {
            match self.direction {
                Direction::Upload => self.connection.upload(*bytes),
                Direction::Download => self.connection.download(*bytes),
            }
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ObservedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ObservedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.count(&result);
        result
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        this.count(&result);
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
