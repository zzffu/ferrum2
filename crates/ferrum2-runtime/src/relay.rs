use std::fmt;
use std::future::{Future, pending};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use crate::OwnerRegistry;

/// Fixed application buffer capacity for each relay direction.
pub const RELAY_BUFFER_BYTES: usize = 32_768;
/// Fixed application buffers owned by each buffered-source relay lifecycle.
pub const BUFFERED_RELAY_BUFFERS_PER_CONNECTION: usize = 1;

/// Successfully forwarded byte totals retained by a relay outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayStats {
    /// Bytes forwarded from the inbound stream to the outbound stream.
    pub inbound_to_outbound: u64,
    /// Bytes forwarded from the outbound stream to the inbound stream.
    pub outbound_to_inbound: u64,
}

/// Relays both directions in the caller's task with fixed buffers and TCP half-close.
pub async fn relay_bidirectional<A, B>(inbound: &mut A, outbound: &mut B) -> io::Result<RelayStats>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (inbound_to_outbound, outbound_to_inbound) = tokio::io::copy_bidirectional_with_sizes(
        inbound,
        outbound,
        RELAY_BUFFER_BYTES,
        RELAY_BUFFER_BYTES,
    )
    .await?;
    Ok(RelayStats {
        inbound_to_outbound,
        outbound_to_inbound,
    })
}

const RELAY_POLL_READY_IO_BUDGET: usize = 64;
const RELAY_POLL_BYTE_BUDGET: usize = 256 * 1024;

struct BufferedSourceRelay<'a, R, P> {
    buffered: &'a mut R,
    peer: &'a mut P,
    reverse: Box<[u8]>,
    reverse_position: usize,
    reverse_filled: usize,
    reverse_flush_pending: bool,
    buffered_eof: bool,
    reverse_eof: bool,
    buffered_done: bool,
    reverse_done: bool,
    buffered_to_peer: u64,
    peer_to_buffered: u64,
}

impl<'a, R, P> BufferedSourceRelay<'a, R, P> {
    fn new(buffered: &'a mut R, peer: &'a mut P) -> Self {
        Self {
            buffered,
            peer,
            reverse: vec![0; RELAY_BUFFER_BYTES].into_boxed_slice(),
            reverse_position: 0,
            reverse_filled: 0,
            reverse_flush_pending: false,
            buffered_eof: false,
            reverse_eof: false,
            buffered_done: false,
            reverse_done: false,
            buffered_to_peer: 0,
            peer_to_buffered: 0,
        }
    }
}

impl<R, P> Future for BufferedSourceRelay<'_, R, P>
where
    R: AsyncBufRead + AsyncWrite + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<(u64, u64)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut ready_io = 0_usize;
        let mut bytes = 0_usize;

        loop {
            let mut progressed = false;

            if !this.buffered_done {
                if this.buffered_eof {
                    match Pin::new(&mut *this.peer).poll_shutdown(cx) {
                        Poll::Pending => {}
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            ready_io += 1;
                            progressed = true;
                            this.buffered_done = true;
                        }
                    }
                } else {
                    match Pin::new(&mut *this.buffered).poll_fill_buf(cx) {
                        Poll::Pending => {}
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok([])) => {
                            ready_io += 1;
                            progressed = true;
                            this.buffered_eof = true;
                        }
                        Poll::Ready(Ok(source)) => {
                            match Pin::new(&mut *this.peer).poll_write(cx, source) {
                                Poll::Pending => {}
                                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                                Poll::Ready(Ok(0)) => {
                                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                                }
                                Poll::Ready(Ok(written)) => {
                                    ready_io += 2;
                                    bytes = bytes.saturating_add(written);
                                    this.buffered_to_peer = this
                                        .buffered_to_peer
                                        .checked_add(written as u64)
                                        .ok_or(io::ErrorKind::Other)?;
                                    Pin::new(&mut *this.buffered).consume(written);
                                    progressed = true;
                                }
                            }
                        }
                    }
                }
            }

            if !this.reverse_done {
                if this.reverse_position < this.reverse_filled {
                    let source = &this.reverse[this.reverse_position..this.reverse_filled];
                    match Pin::new(&mut *this.buffered).poll_write(cx, source) {
                        Poll::Pending => {}
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        }
                        Poll::Ready(Ok(written)) => {
                            ready_io += 1;
                            bytes = bytes.saturating_add(written);
                            this.peer_to_buffered = this
                                .peer_to_buffered
                                .checked_add(written as u64)
                                .ok_or(io::ErrorKind::Other)?;
                            this.reverse_position += written;
                            progressed = true;
                            if this.reverse_position == this.reverse_filled {
                                this.reverse_position = 0;
                                this.reverse_filled = 0;
                                this.reverse_flush_pending = true;
                            }
                        }
                    }
                } else if this.reverse_flush_pending {
                    match Pin::new(&mut *this.buffered).poll_flush(cx) {
                        Poll::Pending => {}
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            ready_io += 1;
                            progressed = true;
                            this.reverse_flush_pending = false;
                        }
                    }
                } else if this.reverse_eof {
                    match Pin::new(&mut *this.buffered).poll_shutdown(cx) {
                        Poll::Pending => {}
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            ready_io += 1;
                            progressed = true;
                            this.reverse_done = true;
                        }
                    }
                } else {
                    let mut buffer = ReadBuf::new(&mut this.reverse);
                    match Pin::new(&mut *this.peer).poll_read(cx, &mut buffer) {
                        Poll::Pending => {}
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            ready_io += 1;
                            progressed = true;
                            this.reverse_filled = buffer.filled().len();
                            this.reverse_eof = this.reverse_filled == 0;
                        }
                    }
                }
            }

            if this.buffered_done && this.reverse_done {
                return Poll::Ready(Ok((this.buffered_to_peer, this.peer_to_buffered)));
            }
            if ready_io >= RELAY_POLL_READY_IO_BUDGET || bytes >= RELAY_POLL_BYTE_BUDGET {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if !progressed {
                return Poll::Pending;
            }
        }
    }
}

/// Relays with deterministic accounting for the two fixed application buffers.
pub async fn relay_bidirectional_tracked<A, B>(
    inbound: &mut A,
    outbound: &mut B,
    registry: &OwnerRegistry,
) -> io::Result<RelayStats>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let _inbound_buffer = registry.track_buffer();
    let _outbound_buffer = registry.track_buffer();
    relay_bidirectional(inbound, outbound).await
}

/// Closed failure categories for a bounded idle relay.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RelayRunError {
    /// A relay I/O operation failed.
    Io,
    /// No byte progress occurred during the idle interval.
    IdleTimeout,
    /// The flow owner requested cooperative cancellation.
    Cancelled,
}

impl fmt::Debug for RelayRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for RelayRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io => formatter.write_str("relay I/O failed"),
            Self::IdleTimeout => formatter.write_str("relay idle timeout"),
            Self::Cancelled => formatter.write_str("relay cancelled"),
        }
    }
}

impl std::error::Error for RelayRunError {}

/// A closed relay failure with direction-separated completed-write totals.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RelayFailure {
    /// Terminal failure category.
    pub kind: RelayRunError,
    /// Successfully forwarded bytes observed before the terminal failure.
    pub stats: RelayStats,
}

impl fmt::Debug for RelayFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayFailure")
            .field("kind", &self.kind)
            .field("stats", &self.stats)
            .finish()
    }
}

impl fmt::Display for RelayFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.kind, formatter)
    }
}

impl std::error::Error for RelayFailure {}

struct ActivityIo<'a, T> {
    inner: &'a mut T,
    activity: Arc<ActivitySignal>,
    bytes_written: u64,
}

struct ActivitySignal {
    dirty: AtomicBool,
    notify: Notify,
}

impl ActivitySignal {
    fn new() -> Self {
        Self {
            dirty: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn mark(&self) -> bool {
        if self.dirty.swap(true, Ordering::Release) {
            false
        } else {
            self.notify.notify_one();
            true
        }
    }

    fn take_dirty(&self) -> bool {
        self.dirty.swap(false, Ordering::AcqRel)
    }
}

impl<T> AsyncRead for ActivityIo<'_, T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_read(context, buffer)
    }
}

impl<T> AsyncBufRead for ActivityIo<'_, T>
where
    T: AsyncBufRead + Unpin,
{
    fn poll_fill_buf(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_fill_buf(context)
    }

    fn consume(self: Pin<&mut Self>, amount: usize) {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).consume(amount);
    }
}

impl<T> AsyncWrite for ActivityIo<'_, T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut *self.inner).poll_write(context, buffer);
        if let Poll::Ready(Ok(written)) = result {
            if written > 0 {
                self.bytes_written += written as u64;
                self.activity.mark();
            }
            Poll::Ready(Ok(written))
        } else {
            result
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(context)
    }
}

/// Relays in the caller's task and resets the idle deadline after byte progress.
pub async fn relay_bidirectional_with_idle_timeout<A, B>(
    inbound: &mut A,
    outbound: &mut B,
    idle_timeout: Duration,
) -> Result<RelayStats, RelayFailure>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    relay_with_controls(inbound, outbound, idle_timeout, pending()).await
}

/// Runs the complete T07 relay lifecycle in the caller's connection-owner task.
///
/// The seam owns exactly two fixed 32 KiB buffers, accounts for them in the
/// supplied registry, preserves half-close and backpressure, resets the idle
/// deadline only after forwarded bytes, and observes cooperative cancellation.
pub async fn relay_lifecycle<A, B, C>(
    inbound: &mut A,
    outbound: &mut B,
    idle_timeout: Duration,
    registry: &OwnerRegistry,
    cancellation: C,
) -> Result<RelayStats, RelayFailure>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
    C: Future<Output = ()>,
{
    let _inbound_buffer = registry.track_buffer();
    let _outbound_buffer = registry.track_buffer();
    relay_with_controls(inbound, outbound, idle_timeout, cancellation).await
}

/// Relays with the inbound receive view as the forward source.
///
/// Authenticated inbound bytes are written directly from their owner-provided
/// view. Only the outbound-to-inbound direction owns a fixed 32 KiB buffer.
pub async fn relay_lifecycle_buffered_inbound<A, B, C>(
    inbound: &mut A,
    outbound: &mut B,
    idle_timeout: Duration,
    registry: &OwnerRegistry,
    cancellation: C,
) -> Result<RelayStats, RelayFailure>
where
    A: AsyncBufRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
    C: Future<Output = ()>,
{
    let _outbound_buffer = registry.track_buffer();
    relay_with_controls_buffered_inbound(inbound, outbound, idle_timeout, cancellation).await
}

/// Relays with the outbound receive view as the reverse source.
///
/// Authenticated outbound bytes are written directly from their owner-provided
/// view. Only the inbound-to-outbound direction owns a fixed 32 KiB buffer.
pub async fn relay_lifecycle_buffered_outbound<A, B, C>(
    inbound: &mut A,
    outbound: &mut B,
    idle_timeout: Duration,
    registry: &OwnerRegistry,
    cancellation: C,
) -> Result<RelayStats, RelayFailure>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncBufRead + AsyncWrite + Unpin,
    C: Future<Output = ()>,
{
    let _inbound_buffer = registry.track_buffer();
    relay_with_controls_buffered_outbound(inbound, outbound, idle_timeout, cancellation).await
}

async fn relay_with_controls_buffered_inbound<A, B, C>(
    inbound: &mut A,
    outbound: &mut B,
    idle_timeout: Duration,
    cancellation: C,
) -> Result<RelayStats, RelayFailure>
where
    A: AsyncBufRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
    C: Future<Output = ()>,
{
    let activity = Arc::new(ActivitySignal::new());
    let mut inbound = ActivityIo {
        inner: inbound,
        activity: Arc::clone(&activity),
        bytes_written: 0,
    };
    let mut outbound = ActivityIo {
        inner: outbound,
        activity: Arc::clone(&activity),
        bytes_written: 0,
    };
    let outcome = run_buffered_with_controls(
        BufferedSourceRelay::new(&mut inbound, &mut outbound),
        activity,
        idle_timeout,
        cancellation,
    )
    .await;
    let stats = RelayStats {
        inbound_to_outbound: outbound.bytes_written,
        outbound_to_inbound: inbound.bytes_written,
    };
    outcome
        .map(|()| stats)
        .map_err(|kind| RelayFailure { kind, stats })
}

async fn relay_with_controls_buffered_outbound<A, B, C>(
    inbound: &mut A,
    outbound: &mut B,
    idle_timeout: Duration,
    cancellation: C,
) -> Result<RelayStats, RelayFailure>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncBufRead + AsyncWrite + Unpin,
    C: Future<Output = ()>,
{
    let activity = Arc::new(ActivitySignal::new());
    let mut inbound = ActivityIo {
        inner: inbound,
        activity: Arc::clone(&activity),
        bytes_written: 0,
    };
    let mut outbound = ActivityIo {
        inner: outbound,
        activity: Arc::clone(&activity),
        bytes_written: 0,
    };
    let outcome = run_buffered_with_controls(
        BufferedSourceRelay::new(&mut outbound, &mut inbound),
        activity,
        idle_timeout,
        cancellation,
    )
    .await;
    let stats = RelayStats {
        inbound_to_outbound: outbound.bytes_written,
        outbound_to_inbound: inbound.bytes_written,
    };
    outcome
        .map(|()| stats)
        .map_err(|kind| RelayFailure { kind, stats })
}

async fn run_buffered_with_controls<T, R, C>(
    relay: R,
    activity: Arc<ActivitySignal>,
    idle_timeout: Duration,
    cancellation: C,
) -> Result<(), RelayRunError>
where
    R: Future<Output = io::Result<T>>,
    C: Future<Output = ()>,
{
    let idle = async move {
        let timer = tokio::time::sleep(idle_timeout);
        tokio::pin!(timer);
        loop {
            let notified = activity.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if activity.take_dirty() {
                timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + idle_timeout);
                continue;
            }
            tokio::select! {
                biased;
                () = &mut timer => {
                    if activity.take_dirty() {
                        timer
                            .as_mut()
                            .reset(tokio::time::Instant::now() + idle_timeout);
                    } else {
                        return;
                    }
                }
                () = &mut notified => {
                    if activity.take_dirty() {
                        timer
                            .as_mut()
                            .reset(tokio::time::Instant::now() + idle_timeout);
                    }
                }
            }
        }
    };
    tokio::pin!(relay);
    tokio::pin!(idle);
    tokio::pin!(cancellation);
    tokio::select! {
        biased;
        () = &mut cancellation => Err(RelayRunError::Cancelled),
        result = &mut relay => result.map(|_| ()).map_err(|_| RelayRunError::Io),
        () = &mut idle => Err(RelayRunError::IdleTimeout),
    }
}

async fn relay_with_controls<A, B, C>(
    inbound: &mut A,
    outbound: &mut B,
    idle_timeout: Duration,
    cancellation: C,
) -> Result<RelayStats, RelayFailure>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
    C: Future<Output = ()>,
{
    let activity = Arc::new(ActivitySignal::new());
    let mut inbound = ActivityIo {
        inner: inbound,
        activity: Arc::clone(&activity),
        bytes_written: 0,
    };
    let mut outbound = ActivityIo {
        inner: outbound,
        activity: Arc::clone(&activity),
        bytes_written: 0,
    };
    let idle = async move {
        let timer = tokio::time::sleep(idle_timeout);
        tokio::pin!(timer);
        loop {
            let notified = activity.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if activity.take_dirty() {
                timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + idle_timeout);
                continue;
            }
            tokio::select! {
                biased;
                () = &mut timer => {
                    if activity.take_dirty() {
                        timer
                            .as_mut()
                            .reset(tokio::time::Instant::now() + idle_timeout);
                    } else {
                        return;
                    }
                }
                () = &mut notified => {
                    if activity.take_dirty() {
                        timer
                            .as_mut()
                            .reset(tokio::time::Instant::now() + idle_timeout);
                    }
                }
            }
        }
    };
    let outcome = {
        let relay = relay_bidirectional(&mut inbound, &mut outbound);
        tokio::pin!(relay);
        tokio::pin!(idle);
        tokio::pin!(cancellation);
        tokio::select! {
            biased;
            () = &mut cancellation => Err(RelayRunError::Cancelled),
            result = &mut relay => result.map(|_| ()).map_err(|_| RelayRunError::Io),
            () = &mut idle => Err(RelayRunError::IdleTimeout),
        }
    };
    let stats = RelayStats {
        inbound_to_outbound: outbound.bytes_written,
        outbound_to_inbound: inbound.bytes_written,
    };
    outcome
        .map(|()| stats)
        .map_err(|kind| RelayFailure { kind, stats })
}

#[cfg(test)]
mod tests {
    use super::ActivitySignal;

    #[test]
    fn activity_notifications_coalesce_until_the_idle_waiter_clears_dirty() {
        let activity = ActivitySignal::new();
        assert!(activity.mark());
        for _ in 0..1_000 {
            assert!(!activity.mark());
        }
        assert!(activity.take_dirty());
        assert!(activity.mark());
        assert!(activity.take_dirty());
        assert!(!activity.take_dirty());
    }
}
