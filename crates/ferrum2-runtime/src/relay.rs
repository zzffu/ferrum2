use std::fmt;
use std::future::{Future, pending, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use crate::OwnerRegistry;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Fixed application buffer capacity for each relay direction.
pub const RELAY_BUFFER_BYTES: usize = 32_768;

/// Successfully forwarded byte totals retained by a relay outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayStats {
    /// Bytes forwarded from the inbound stream to the outbound stream.
    pub inbound_to_outbound: u64,
    /// Bytes forwarded from the outbound stream to the inbound stream.
    pub outbound_to_inbound: u64,
}

/// Direction of bytes successfully accepted by a relay destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayDirection {
    /// Bytes accepted by the outbound destination from the inbound source.
    InboundToOutbound,
    /// Bytes accepted by the inbound destination from the outbound source.
    OutboundToInbound,
}

/// Cloneable progress recorder supplied to a specialized relay engine.
///
/// Engines call [`Self::record`] only after a destination accepts non-zero
/// bytes. The recorder owns direction-separated statistics and marks poll-local
/// activity for the lifecycle supervisor to observe after polling the engine.
/// It must remain owned by the supplied engine and must not be handed to a
/// detached task or called outside that engine's current poll. Recording does
/// not independently wake the lifecycle supervisor.
#[derive(Clone)]
pub struct RelayProgress {
    inner: Arc<RelayProgressInner>,
}

struct RelayProgressInner {
    activity: ActivitySignal,
    inbound_to_outbound: AtomicU64,
    outbound_to_inbound: AtomicU64,
}

impl RelayProgress {
    fn new() -> Self {
        Self {
            inner: Arc::new(RelayProgressInner {
                activity: ActivitySignal::new(),
                inbound_to_outbound: AtomicU64::new(0),
                outbound_to_inbound: AtomicU64::new(0),
            }),
        }
    }

    /// Records bytes successfully accepted by the selected destination.
    ///
    /// The supplied engine must call this during its current poll, before that
    /// poll returns `Pending` or `Ready`. This method does not wake the lifecycle
    /// supervisor; calling it from outside the engine or from a detached task
    /// violates the poll-local progress contract.
    pub fn record(&self, direction: RelayDirection, bytes: usize) {
        if bytes == 0 {
            return;
        }
        self.add_stats_only(direction, bytes as u64);
        self.mark_activity();
    }

    fn add_stats_only(&self, direction: RelayDirection, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let counter = match direction {
            RelayDirection::InboundToOutbound => &self.inner.inbound_to_outbound,
            RelayDirection::OutboundToInbound => &self.inner.outbound_to_inbound,
        };
        counter.fetch_add(bytes, Ordering::AcqRel);
    }

    fn mark_activity(&self) {
        self.inner.activity.mark();
    }

    fn stats(&self) -> RelayStats {
        RelayStats {
            inbound_to_outbound: self.inner.inbound_to_outbound.load(Ordering::Acquire),
            outbound_to_inbound: self.inner.outbound_to_inbound.load(Ordering::Acquire),
        }
    }
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
    progress: RelayProgress,
    direction: RelayDirection,
    bytes_written: u64,
}

struct ActivitySignal {
    dirty: AtomicBool,
}

impl ActivitySignal {
    fn new() -> Self {
        Self {
            dirty: AtomicBool::new(false),
        }
    }

    fn mark(&self) {
        self.dirty.store(true, Ordering::Release);
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
                self.progress.mark_activity();
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

impl<T> Drop for ActivityIo<'_, T> {
    fn drop(&mut self) {
        self.progress
            .add_stats_only(self.direction, self.bytes_written);
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

/// Supervises a specialized relay engine without acquiring generic relay buffers.
///
/// The engine owns its protocol-specific storage and reports completed writes
/// through the supplied [`RelayProgress`]. Cancellation wins over engine
/// completion, which wins over an idle deadline when outcomes become ready in
/// the same poll. Progress is poll-local: the engine reports it before returning
/// `Pending`, then the idle future observes it later in the same lifecycle poll.
pub async fn relay_lifecycle_with_engine<C, M, E>(
    idle_timeout: Duration,
    cancellation: C,
    make_engine: M,
) -> Result<RelayStats, RelayFailure>
where
    C: Future<Output = ()>,
    M: FnOnce(RelayProgress) -> E,
    E: Future<Output = io::Result<()>>,
{
    let progress = RelayProgress::new();
    let idle_progress = progress.clone();
    let idle = async move {
        let timer = tokio::time::sleep(idle_timeout);
        tokio::pin!(timer);
        poll_fn(|context| {
            if idle_progress.inner.activity.take_dirty() {
                timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + idle_timeout);
            }
            timer.as_mut().poll(context)
        })
        .await
    };
    let outcome = {
        let engine = make_engine(progress.clone());
        tokio::pin!(engine);
        tokio::pin!(idle);
        tokio::pin!(cancellation);
        tokio::select! {
            biased;
            () = &mut cancellation => Err(RelayRunError::Cancelled),
            result = &mut engine => result.map_err(|_| RelayRunError::Io),
            () = &mut idle => Err(RelayRunError::IdleTimeout),
        }
    };
    let stats = progress.stats();
    outcome
        .map(|()| stats)
        .map_err(|kind| RelayFailure { kind, stats })
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
    relay_lifecycle_with_engine(idle_timeout, cancellation, |progress| async move {
        let mut inbound = ActivityIo {
            inner: inbound,
            progress: progress.clone(),
            direction: RelayDirection::OutboundToInbound,
            bytes_written: 0,
        };
        let mut outbound = ActivityIo {
            inner: outbound,
            progress,
            direction: RelayDirection::InboundToOutbound,
            bytes_written: 0,
        };
        relay_bidirectional(&mut inbound, &mut outbound)
            .await
            .map(|_| ())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::ActivitySignal;

    #[test]
    fn activity_marks_coalesce_until_the_idle_waiter_clears_dirty() {
        let activity = ActivitySignal::new();
        activity.mark();
        for _ in 0..1_000 {
            activity.mark();
        }
        assert!(activity.take_dirty());
        assert!(!activity.take_dirty());
        activity.mark();
        assert!(activity.take_dirty());
        assert!(!activity.take_dirty());
    }
}
