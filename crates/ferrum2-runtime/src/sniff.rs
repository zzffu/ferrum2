use std::fmt;
use std::future::Future;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::OwnerRegistry;
use crate::owner::OwnerGuard;

/// Caller-owned parser feedback for the current bounded prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrefixDecision {
    Complete,
    ReadMore,
}

/// Closed reason why bounded prefix collection stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SniffPrefixOutcome {
    Complete,
    Timeout,
    Limit,
    Cancelled,
    ReadError,
    Unavailable,
}

/// A collected prefix whose formatting never exposes peer bytes.
pub struct SniffPrefix<P> {
    bytes: PrefixBytes<P>,
    outcome: SniffPrefixOutcome,
    _owner: Option<OwnerGuard>,
}

impl<P: AsRef<[u8]>> SniffPrefix<P> {
    pub const fn outcome(&self) -> SniffPrefixOutcome {
        self.outcome
    }

    pub fn capacity(&self) -> usize {
        self.bytes.capacity()
    }
}

impl<P: AsRef<[u8]>> AsRef<[u8]> for SniffPrefix<P> {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<P: AsRef<[u8]>> fmt::Debug for SniffPrefix<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SniffPrefix")
            .field("len", &self.bytes.as_ref().len())
            .field("capacity", &self.bytes.capacity())
            .field("outcome", &self.outcome)
            .finish()
    }
}

enum PrefixBytes<P> {
    Initial(P),
    Owned { bytes: Box<[u8]>, len: usize },
}

impl<P: AsRef<[u8]>> PrefixBytes<P> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Initial(bytes) => bytes.as_ref(),
            Self::Owned { bytes, len } => &bytes[..*len],
        }
    }

    fn capacity(&self) -> usize {
        match self {
            Self::Initial(bytes) => bytes.as_ref().len(),
            Self::Owned { bytes, .. } => bytes.len(),
        }
    }

    fn writable(&mut self, max_bytes: usize) -> &mut [u8] {
        let len = self.as_ref().len();
        if self.capacity() == len {
            let next = len.saturating_add(len.max(64)).min(max_bytes);
            let mut bytes = vec![0_u8; next].into_boxed_slice();
            bytes[..len].copy_from_slice(self.as_ref());
            *self = Self::Owned { bytes, len };
        }
        match self {
            Self::Initial(_) => unreachable!("full initial prefix must become owned"),
            Self::Owned { bytes, len } => &mut bytes[*len..],
        }
    }

    fn commit(&mut self, count: usize) -> bool {
        match self {
            Self::Initial(_) => false,
            Self::Owned { bytes, len } if count <= bytes.len() - *len => {
                *len += count;
                true
            }
            Self::Owned { .. } => false,
        }
    }
}

/// Lazily grows one caller-owned prefix under one absolute deadline.
#[allow(clippy::too_many_arguments)]
pub async fn collect_sniff_prefix<E, C, R, I, P>(
    prefix: P,
    max_bytes: usize,
    max_aggregate_bytes: usize,
    registry: &OwnerRegistry,
    timeout: Duration,
    cancellation: C,
    mut read: R,
    mut inspect: I,
) -> SniffPrefix<P>
where
    C: Future,
    R: FnMut(&mut Context<'_>, &mut [u8]) -> Poll<Result<usize, E>>,
    I: FnMut(&[u8]) -> PrefixDecision,
    P: AsRef<[u8]>,
{
    let mut prefix = PrefixBytes::Initial(prefix);
    let finish = |bytes, outcome, owner| SniffPrefix {
        bytes,
        outcome,
        _owner: owner,
    };
    tokio::pin!(cancellation);
    tokio::select! {
        biased;
        _ = &mut cancellation => {
            return finish(prefix, SniffPrefixOutcome::Cancelled, None);
        }
        _ = std::future::ready(()) => {}
    }
    if prefix.as_ref().len() > max_bytes {
        return finish(prefix, SniffPrefixOutcome::Limit, None);
    }
    if inspect(prefix.as_ref()) == PrefixDecision::Complete {
        return finish(prefix, SniffPrefixOutcome::Complete, None);
    }
    if prefix.as_ref().len() == max_bytes {
        return finish(prefix, SniffPrefixOutcome::Limit, None);
    }
    let Some(deadline) = tokio::time::Instant::now().checked_add(timeout) else {
        return finish(prefix, SniffPrefixOutcome::Timeout, None);
    };
    let Some(owner) = registry.track_sniff_buffer(max_bytes, max_aggregate_bytes) else {
        return finish(prefix, SniffPrefixOutcome::Unavailable, None);
    };
    let deadline = tokio::time::sleep_until(deadline);
    tokio::pin!(deadline);

    loop {
        if prefix.as_ref().len() == max_bytes {
            return finish(prefix, SniffPrefixOutcome::Limit, Some(owner));
        }
        let result = tokio::select! {
            biased;
            _ = &mut cancellation => {
                return finish(prefix, SniffPrefixOutcome::Cancelled, Some(owner));
            }
            _ = &mut deadline => {
                return finish(prefix, SniffPrefixOutcome::Timeout, Some(owner));
            }
            result = std::future::poll_fn(|context| read(context, prefix.writable(max_bytes))) => result,
        };
        match result {
            Ok(0) | Err(_) => {
                return finish(prefix, SniffPrefixOutcome::ReadError, Some(owner));
            }
            Ok(count) if prefix.commit(count) => {}
            Ok(_) => return finish(prefix, SniffPrefixOutcome::ReadError, Some(owner)),
        }
        if inspect(prefix.as_ref()) == PrefixDecision::Complete {
            return finish(prefix, SniffPrefixOutcome::Complete, Some(owner));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::io;
    use std::task::Poll;
    use std::time::Duration;

    use crate::{PrefixDecision, SniffPrefixOutcome, collect_sniff_prefix};

    #[tokio::test]
    async fn sniff_prefix_collects_fragmented_reads_lazily_and_exactly() {
        let registry = crate::OwnerRegistry::new();
        let mut chunks = VecDeque::from([&b"bc"[..], &b"def"[..]]);
        let prefix = collect_sniff_prefix(
            Vec::from(&b"a"[..]),
            16_384,
            16_384,
            &registry,
            Duration::from_secs(1),
            std::future::pending::<()>(),
            |_context, destination| {
                let chunk = chunks.pop_front().expect("bounded scripted read");
                destination[..chunk.len()].copy_from_slice(chunk);
                Poll::Ready(Ok::<_, io::Error>(chunk.len()))
            },
            |bytes| {
                if bytes == b"abcdef" {
                    PrefixDecision::Complete
                } else {
                    PrefixDecision::ReadMore
                }
            },
        )
        .await;
        assert!(
            prefix.capacity() < 16_384,
            "collector allocated the full limit"
        );
        assert_eq!(prefix.outcome(), SniffPrefixOutcome::Complete);
        assert_eq!(prefix.as_ref(), b"abcdef");
        drop(prefix);
        assert_eq!(registry.snapshot().sniff_buffered_bytes, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn sniff_prefix_uses_one_deadline_and_closed_terminal_outcomes() {
        let registry = crate::OwnerRegistry::new();
        let mut timed = Box::pin(collect_sniff_prefix(
            Vec::from(&b"prefix"[..]),
            64,
            64,
            &registry,
            Duration::from_millis(300),
            std::future::pending::<()>(),
            |_context, _destination| Poll::Pending::<Result<usize, io::Error>>,
            |_| PrefixDecision::ReadMore,
        ));
        tokio::select! {
            biased;
            _ = &mut timed => panic!("collector completed before its absolute deadline"),
            _ = tokio::task::yield_now() => {}
        }
        tokio::time::advance(Duration::from_millis(299)).await;
        tokio::select! {
            biased;
            _ = &mut timed => panic!("collector reset or shortened its deadline"),
            _ = tokio::task::yield_now() => {}
        }
        tokio::time::advance(Duration::from_millis(1)).await;
        let timed = timed.await;
        assert_eq!(timed.as_ref(), b"prefix");
        assert_eq!(timed.outcome(), SniffPrefixOutcome::Timeout);
        drop(timed);

        let limit = collect_sniff_prefix(
            Vec::from(&b"full"[..]),
            4,
            4,
            &registry,
            Duration::from_secs(1),
            std::future::pending::<()>(),
            |_context, _destination| -> Poll<io::Result<usize>> {
                panic!("limit performed read I/O")
            },
            |_| PrefixDecision::ReadMore,
        )
        .await;
        assert_eq!(limit.as_ref(), b"full");
        assert_eq!(limit.outcome(), SniffPrefixOutcome::Limit);
        let oversized = collect_sniff_prefix(
            Vec::from(&b"oversized"[..]),
            4,
            4,
            &registry,
            Duration::from_secs(1),
            std::future::pending::<()>(),
            |_context, _destination| -> Poll<io::Result<usize>> {
                panic!("oversized prefix performed read I/O")
            },
            |_| PrefixDecision::Complete,
        )
        .await;
        assert_eq!(oversized.outcome(), SniffPrefixOutcome::Limit);

        for (name, read, expected) in [
            ("EOF", Ok(0), SniffPrefixOutcome::ReadError),
            (
                "oversized adapter result",
                Ok(65),
                SniffPrefixOutcome::ReadError,
            ),
            (
                "read error",
                Err(io::Error::other("sentinel")),
                SniffPrefixOutcome::ReadError,
            ),
        ] {
            let mut read = Some(read);
            let result = collect_sniff_prefix(
                Vec::new(),
                64,
                64,
                &registry,
                Duration::from_secs(1),
                std::future::pending::<()>(),
                move |_context, _destination| {
                    Poll::Ready(read.take().expect("one terminal scripted read"))
                },
                |_| PrefixDecision::ReadMore,
            )
            .await;
            assert_eq!(result.outcome(), expected, "{name}");
        }

        let cancelled = collect_sniff_prefix(
            Vec::from(&b"kept"[..]),
            64,
            64,
            &registry,
            Duration::from_secs(1),
            std::future::ready(()),
            |_context, _destination| Poll::Ready(Ok::<_, io::Error>(0)),
            |_| PrefixDecision::ReadMore,
        )
        .await;
        assert_eq!(cancelled.as_ref(), b"kept");
        assert_eq!(cancelled.outcome(), SniffPrefixOutcome::Cancelled);
    }

    #[test]
    fn sniff_prefix_debug_redacts_peer_bytes() {
        let rendered = format!(
            "{:?}",
            super::SniffPrefix {
                bytes: super::PrefixBytes::Initial(Vec::from(&b"secret.test"[..])),
                outcome: SniffPrefixOutcome::Complete,
                _owner: None,
            }
        );
        assert!(!rendered.contains("secret.test"));
        assert!(rendered.contains("len: 11"));
    }

    #[tokio::test]
    async fn sniff_prefix_ready_cancellation_precedes_every_fast_path() {
        for (name, prefix, max_bytes, timeout, complete, ready_read) in [
            (
                "complete",
                b"complete".as_slice(),
                64,
                Duration::from_secs(1),
                true,
                false,
            ),
            (
                "exact limit",
                b"limit".as_slice(),
                5,
                Duration::from_secs(1),
                false,
                false,
            ),
            (
                "oversize",
                b"oversize".as_slice(),
                4,
                Duration::from_secs(1),
                false,
                false,
            ),
            (
                "ready read",
                b"".as_slice(),
                64,
                Duration::from_secs(1),
                false,
                true,
            ),
            (
                "ready deadline",
                b"".as_slice(),
                64,
                Duration::ZERO,
                false,
                false,
            ),
        ] {
            let registry = crate::OwnerRegistry::new();
            let inspected = Cell::new(false);
            let read_polled = Cell::new(false);
            let result = collect_sniff_prefix(
                prefix.to_vec(),
                max_bytes,
                max_bytes,
                &registry,
                timeout,
                std::future::ready(()),
                |_context, _destination| {
                    read_polled.set(true);
                    if ready_read {
                        Poll::Ready(Ok::<_, io::Error>(0))
                    } else {
                        Poll::Pending
                    }
                },
                |_| {
                    inspected.set(true);
                    if complete {
                        PrefixDecision::Complete
                    } else {
                        PrefixDecision::ReadMore
                    }
                },
            )
            .await;
            assert_eq!(result.as_ref(), prefix, "{name}");
            assert_eq!(result.outcome(), SniffPrefixOutcome::Cancelled, "{name}");
            assert!(!inspected.get(), "{name} inspected before cancellation");
            assert!(!read_polled.get(), "{name} read before cancellation");
        }
    }

    #[tokio::test]
    async fn sniff_prefix_owns_exact_capacity_and_releases_every_terminal_path() {
        let registry = crate::OwnerRegistry::new();
        let (cancel, cancelled) = tokio::sync::oneshot::channel::<()>();
        let mut waiting = Box::pin(collect_sniff_prefix(
            Vec::from(&b"a"[..]),
            777,
            777,
            &registry,
            Duration::from_secs(1),
            cancelled,
            |_context, _destination| Poll::Pending::<io::Result<usize>>,
            |_| PrefixDecision::ReadMore,
        ));
        tokio::select! {
            biased;
            result = &mut waiting => panic!("waiting collector completed: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }
        assert_eq!(registry.snapshot().owned_buffers, 1);
        assert_eq!(registry.snapshot().sniff_buffered_bytes, 777);

        let unavailable = collect_sniff_prefix(
            Vec::new(),
            777,
            777,
            &registry,
            Duration::from_secs(1),
            std::future::pending::<()>(),
            |_context, _destination| Poll::Pending::<io::Result<usize>>,
            |_| PrefixDecision::ReadMore,
        )
        .await;
        assert_eq!(unavailable.outcome(), SniffPrefixOutcome::Unavailable);
        drop(unavailable);
        assert_eq!(registry.snapshot().sniff_buffered_bytes, 777);

        cancel.send(()).expect("cancel waiting collector");
        let cancelled = waiting.await;
        assert_eq!(cancelled.outcome(), SniffPrefixOutcome::Cancelled);
        assert_eq!(cancelled.capacity(), 65);
        assert_eq!(cancelled.as_ref(), b"a");
        drop(cancelled);
        assert_eq!(registry.snapshot().owned_buffers, 0);
        assert_eq!(registry.snapshot().sniff_buffered_bytes, 0);

        let read_error = collect_sniff_prefix(
            Vec::from(&b"kept"[..]),
            777,
            777,
            &registry,
            Duration::from_secs(1),
            std::future::pending::<()>(),
            |_context, _destination| Poll::Ready(Err(io::Error::other("sentinel"))),
            |_| PrefixDecision::ReadMore,
        )
        .await;
        assert_eq!(read_error.outcome(), SniffPrefixOutcome::ReadError);
        assert_eq!(registry.snapshot().sniff_buffered_bytes, 777);
        drop(read_error);
        assert_eq!(registry.snapshot().sniff_buffered_bytes, 0);

        let limit = collect_sniff_prefix(
            Vec::from(&b"full"[..]),
            4,
            4,
            &registry,
            Duration::from_secs(1),
            std::future::pending::<()>(),
            |_context, _destination| Poll::Pending::<io::Result<usize>>,
            |_| PrefixDecision::ReadMore,
        )
        .await;
        assert_eq!(limit.outcome(), SniffPrefixOutcome::Limit);
        assert_eq!(registry.snapshot().sniff_buffered_bytes, 0);
    }
}
