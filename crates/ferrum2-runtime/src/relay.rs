use std::fmt;
use std::future::{Future, pending};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use crate::OwnerRegistry;

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
