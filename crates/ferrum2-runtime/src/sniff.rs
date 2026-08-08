use std::fmt;
use std::future::Future;
use std::task::{Context, Poll};
use std::time::Duration;

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
}

/// A collected prefix whose formatting never exposes peer bytes.
pub struct SniffPrefix {
    bytes: Vec<u8>,
    outcome: SniffPrefixOutcome,
}

impl SniffPrefix {
    pub fn into_parts(self) -> (Vec<u8>, SniffPrefixOutcome) {
        (self.bytes, self.outcome)
    }
}

impl fmt::Debug for SniffPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SniffPrefix")
            .field("len", &self.bytes.len())
            .field("outcome", &self.outcome)
            .finish()
    }
}

/// Lazily grows one caller-owned prefix under one absolute deadline.
pub async fn collect_sniff_prefix<E, C, R, I>(
    mut prefix: Vec<u8>,
    max_bytes: usize,
    timeout: Duration,
    cancellation: C,
    mut read: R,
    mut inspect: I,
) -> SniffPrefix
where
    C: Future,
    R: FnMut(&mut Context<'_>, &mut [u8]) -> Poll<Result<usize, E>>,
    I: FnMut(&[u8]) -> PrefixDecision,
{
    let finish = |bytes, outcome| SniffPrefix { bytes, outcome };
    if prefix.len() > max_bytes {
        return finish(prefix, SniffPrefixOutcome::Limit);
    }
    if inspect(&prefix) == PrefixDecision::Complete {
        return finish(prefix, SniffPrefixOutcome::Complete);
    }
    let Some(deadline) = tokio::time::Instant::now().checked_add(timeout) else {
        return finish(prefix, SniffPrefixOutcome::Timeout);
    };
    let deadline = tokio::time::sleep_until(deadline);
    tokio::pin!(cancellation, deadline);
    let mut buffer = [0_u8; 1024];

    loop {
        let Some(remaining) = max_bytes.checked_sub(prefix.len()) else {
            return finish(prefix, SniffPrefixOutcome::Limit);
        };
        if remaining == 0 {
            return finish(prefix, SniffPrefixOutcome::Limit);
        }
        let read_len = remaining.min(buffer.len());
        let result = tokio::select! {
            biased;
            _ = &mut cancellation => {
                return finish(prefix, SniffPrefixOutcome::Cancelled);
            }
            _ = &mut deadline => {
                return finish(prefix, SniffPrefixOutcome::Timeout);
            }
            result = std::future::poll_fn(|context| read(context, &mut buffer[..read_len])) => result,
        };
        match result {
            Ok(0) | Err(_) => return finish(prefix, SniffPrefixOutcome::ReadError),
            Ok(count) if count <= read_len => prefix.extend_from_slice(&buffer[..count]),
            Ok(_) => return finish(prefix, SniffPrefixOutcome::ReadError),
        }
        if inspect(&prefix) == PrefixDecision::Complete {
            return finish(prefix, SniffPrefixOutcome::Complete);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::task::Poll;
    use std::time::Duration;

    use crate::{PrefixDecision, SniffPrefixOutcome, collect_sniff_prefix};

    #[tokio::test]
    async fn sniff_prefix_collects_fragmented_reads_lazily_and_exactly() {
        let mut chunks = VecDeque::from([&b"bc"[..], &b"def"[..]]);
        let prefix = collect_sniff_prefix(
            Vec::from(&b"a"[..]),
            16_384,
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
        let (bytes, outcome) = prefix.into_parts();

        assert_eq!(outcome, SniffPrefixOutcome::Complete);
        assert_eq!(bytes, b"abcdef");
        assert!(
            bytes.capacity() < 16_384,
            "collector allocated the full limit"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn sniff_prefix_uses_one_deadline_and_closed_terminal_outcomes() {
        let mut timed = Box::pin(collect_sniff_prefix(
            Vec::from(&b"prefix"[..]),
            64,
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
        let (bytes, outcome) = timed.await.into_parts();
        assert_eq!(
            (bytes.as_slice(), outcome),
            (b"prefix".as_slice(), SniffPrefixOutcome::Timeout)
        );

        let limit = collect_sniff_prefix(
            Vec::from(&b"full"[..]),
            4,
            Duration::from_secs(1),
            std::future::pending::<()>(),
            |_context, _destination| -> Poll<io::Result<usize>> {
                panic!("limit performed read I/O")
            },
            |_| PrefixDecision::ReadMore,
        )
        .await;
        assert_eq!(
            limit.into_parts(),
            (Vec::from(&b"full"[..]), SniffPrefixOutcome::Limit)
        );
        let oversized = collect_sniff_prefix(
            Vec::from(&b"oversized"[..]),
            4,
            Duration::from_secs(1),
            std::future::pending::<()>(),
            |_context, _destination| -> Poll<io::Result<usize>> {
                panic!("oversized prefix performed read I/O")
            },
            |_| PrefixDecision::Complete,
        )
        .await;
        assert_eq!(oversized.into_parts().1, SniffPrefixOutcome::Limit);

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
                Duration::from_secs(1),
                std::future::pending::<()>(),
                move |_context, _destination| {
                    Poll::Ready(read.take().expect("one terminal scripted read"))
                },
                |_| PrefixDecision::ReadMore,
            )
            .await;
            assert_eq!(result.into_parts().1, expected, "{name}");
        }

        let cancelled = collect_sniff_prefix(
            Vec::from(&b"kept"[..]),
            64,
            Duration::from_secs(1),
            std::future::ready(()),
            |_context, _destination| Poll::Ready(Ok::<_, io::Error>(0)),
            |_| PrefixDecision::ReadMore,
        )
        .await;
        assert_eq!(
            cancelled.into_parts(),
            (Vec::from(&b"kept"[..]), SniffPrefixOutcome::Cancelled)
        );
    }

    #[test]
    fn sniff_prefix_debug_redacts_peer_bytes() {
        let rendered = format!(
            "{:?}",
            super::SniffPrefix {
                bytes: Vec::from(&b"secret.test"[..]),
                outcome: SniffPrefixOutcome::Complete,
            }
        );
        assert!(!rendered.contains("secret.test"));
        assert!(rendered.contains("len: 11"));
    }
}
