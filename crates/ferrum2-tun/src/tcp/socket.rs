use socket2::SockRef;
use std::io;
use std::net::Shutdown;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Socket I/O owned by the same generation lease. Production has one variant,
/// hence no virtual calls or additional allocation. The portable adapter uses
/// Tokio's bounded duplex transport, never a second TUN implementation.
pub(crate) enum FlowSocket {
    System(TcpStream),
    #[cfg(feature = "benchmark")]
    Memory(tokio::io::DuplexStream),
}
impl From<TcpStream> for FlowSocket {
    fn from(stream: TcpStream) -> Self {
        Self::System(stream)
    }
}
impl FlowSocket {
    #[cfg(any(
        all(windows, target_arch = "x86_64", feature = "live-backend"),
        test,
        feature = "benchmark"
    ))]
    pub(crate) fn set_nodelay(&self, enabled: bool) -> io::Result<()> {
        match self {
            Self::System(stream) => stream.set_nodelay(enabled),
            #[cfg(feature = "benchmark")]
            Self::Memory(_) => Ok(()), // Byte queues have no Nagle algorithm.
        }
    }
    /// Generation cancellation must not wait for the peer to consume queued data.
    /// Dropping with zero linger asks the system TCP stack for an abortive close;
    /// the packet owner must still deliver that kernel-generated reset via TUN.
    #[cfg(any(
        all(windows, target_arch = "x86_64", feature = "live-backend"),
        test,
        feature = "benchmark"
    ))]
    pub(crate) fn abort(self) -> io::Result<()> {
        match &self {
            Self::System(stream) => {
                SockRef::from(stream).set_linger(Some(std::time::Duration::ZERO))
            }
            #[cfg(feature = "benchmark")]
            Self::Memory(_) => Ok(()),
        }
    }

    pub(crate) fn close(&self) {
        match self {
            Self::System(stream) => {
                let _ = SockRef::from(stream).shutdown(Shutdown::Both);
            }
            #[cfg(feature = "benchmark")]
            Self::Memory(_) => {} // The owner immediately drops both-direction custody.
        }
    }
    pub(crate) fn shutdown(&mut self, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::System(stream) => Poll::Ready(SockRef::from(&*stream).shutdown(Shutdown::Write)),
            #[cfg(feature = "benchmark")]
            Self::Memory(stream) => Pin::new(stream).poll_shutdown(_context),
        }
    }
    #[cfg(test)]
    pub(crate) fn set_send_buffer_size(&self, size: usize) -> io::Result<()> {
        match self {
            Self::System(stream) => SockRef::from(stream).set_send_buffer_size(size),
            #[cfg(feature = "benchmark")]
            Self::Memory(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a system socket",
            )),
        }
    }
}
impl AsyncRead for FlowSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::System(stream) => Pin::new(stream).poll_read(context, buffer),
            #[cfg(feature = "benchmark")]
            Self::Memory(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}
impl AsyncWrite for FlowSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::System(stream) => Pin::new(stream).poll_write(context, buffer),
            #[cfg(feature = "benchmark")]
            Self::Memory(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::System(stream) => Pin::new(stream).poll_flush(context),
            #[cfg(feature = "benchmark")]
            Self::Memory(stream) => Pin::new(stream).poll_flush(context),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().shutdown(context)
    }
}
