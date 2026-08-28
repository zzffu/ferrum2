use std::future::pending;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum2_runtime::{
    BUFFERED_RELAY_BUFFERS_PER_CONNECTION, OwnerRegistry, RELAY_BUFFER_BYTES, RelayRunError,
    relay_lifecycle_buffered_inbound, relay_lifecycle_buffered_outbound,
};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

struct BufferedEndpoint {
    source: Vec<u8>,
    consumed: usize,
    received: Vec<u8>,
    staged: Vec<u8>,
    write_limit: usize,
    write_lengths: Vec<usize>,
    fill_calls: usize,
    consume_calls: usize,
    async_read_calls: usize,
    shutdowns: usize,
    flushes: usize,
}

impl BufferedEndpoint {
    fn new(source: Vec<u8>, write_limit: usize) -> Self {
        Self {
            source,
            consumed: 0,
            received: Vec::new(),
            staged: Vec::new(),
            write_limit,
            write_lengths: Vec::new(),
            fill_calls: 0,
            consume_calls: 0,
            async_read_calls: 0,
            shutdowns: 0,
            flushes: 0,
        }
    }
}

impl AsyncRead for BufferedEndpoint {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.async_read_calls += 1;
        let copied = buffer.remaining().min(self.source.len() - self.consumed);
        buffer.put_slice(&self.source[self.consumed..self.consumed + copied]);
        self.consumed += copied;
        Poll::Ready(Ok(()))
    }
}

impl AsyncBufRead for BufferedEndpoint {
    fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        this.fill_calls += 1;
        Poll::Ready(Ok(&this.source[this.consumed..]))
    }

    fn consume(mut self: Pin<&mut Self>, amount: usize) {
        assert!(amount <= self.source.len() - self.consumed);
        self.consumed += amount;
        self.consume_calls += 1;
    }
}

impl AsyncWrite for BufferedEndpoint {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = source.len().min(self.write_limit);
        self.write_lengths.push(written);
        self.staged.extend_from_slice(&source[..written]);
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flushes += 1;
        let staged = std::mem::take(&mut self.staged);
        self.received.extend_from_slice(&staged);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        assert!(self.staged.is_empty(), "relay must flush staged writes");
        self.shutdowns += 1;
        Poll::Ready(Ok(()))
    }
}

struct PeerEndpoint {
    source: Vec<u8>,
    read_position: usize,
    received: Vec<u8>,
    write_limit: usize,
    read_limit: usize,
    read_calls: usize,
    expected_view_base: usize,
    pending_write_once: bool,
    pending_view: Option<(usize, usize)>,
    pending_read_after: Option<usize>,
    pending_read_polls: usize,
    direct_view_writes: usize,
    shutdowns: usize,
}

impl PeerEndpoint {
    fn new(
        source: Vec<u8>,
        write_limit: usize,
        expected_view_base: usize,
        pending_write_once: bool,
    ) -> Self {
        Self {
            source,
            read_position: 0,
            received: Vec::new(),
            write_limit,
            read_limit: usize::MAX,
            read_calls: 0,
            expected_view_base,
            pending_write_once,
            pending_view: None,
            pending_read_after: None,
            pending_read_polls: 0,
            direct_view_writes: 0,
            shutdowns: 0,
        }
    }

    fn with_read_limit(mut self, read_limit: usize) -> Self {
        assert!(read_limit > 0);
        self.read_limit = read_limit;
        self
    }

    fn with_pending_read_polls_after(mut self, bytes: usize, polls: usize) -> Self {
        self.pending_read_after = Some(bytes);
        self.pending_read_polls = polls;
        self
    }
}

impl AsyncRead for PeerEndpoint {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.read_calls += 1;
        if self
            .pending_read_after
            .is_some_and(|bytes| self.read_position >= bytes)
            && self.pending_read_polls > 0
        {
            self.pending_read_polls -= 1;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let copied = buffer
            .remaining()
            .min(self.read_limit)
            .min(self.source.len() - self.read_position);
        buffer.put_slice(&self.source[self.read_position..self.read_position + copied]);
        self.read_position += copied;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for PeerEndpoint {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        let observed = (source.as_ptr() as usize, source.len());
        assert_eq!(observed.0, self.expected_view_base + self.received.len());
        if let Some(pending_view) = self.pending_view.take() {
            assert_eq!(observed, pending_view, "Pending must retain the same view");
        }
        if self.pending_write_once {
            self.pending_write_once = false;
            self.pending_view = Some(observed);
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let written = source.len().min(self.write_limit);
        self.received.extend_from_slice(&source[..written]);
        self.direct_view_writes += 1;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdowns += 1;
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn buffered_inbound_writes_direct_views_across_partial_write_and_backpressure() {
    let forward: Vec<u8> = (0..(RELAY_BUFFER_BYTES * 2 + 17))
        .map(|index| (index % 251) as u8)
        .collect();
    let reverse = b"bounded reverse direction".to_vec();
    let mut buffered = BufferedEndpoint::new(forward.clone(), 3);
    let expected_view_base = buffered.source.as_ptr() as usize;
    let mut peer = PeerEndpoint::new(reverse.clone(), 997, expected_view_base, true);
    let registry = OwnerRegistry::new();

    let stats = relay_lifecycle_buffered_inbound(
        &mut buffered,
        &mut peer,
        Duration::from_secs(30),
        &registry,
        pending(),
    )
    .await
    .expect("buffered relay");

    assert_eq!(stats.inbound_to_outbound, forward.len() as u64);
    assert_eq!(stats.outbound_to_inbound, reverse.len() as u64);
    assert_eq!(peer.received, forward);
    assert_eq!(buffered.received, reverse);
    assert_eq!(
        buffered.async_read_calls, 0,
        "forward source must use views"
    );
    assert!(buffered.fill_calls > 1);
    assert_eq!(buffered.consume_calls, peer.direct_view_writes);
    assert_eq!(buffered.shutdowns, 1);
    assert!(buffered.flushes > 0);
    assert_eq!(peer.shutdowns, 1);
    assert_eq!(registry.snapshot().owned_buffers, 0);
}

#[tokio::test]
async fn buffered_outbound_preserves_directional_stats_and_direct_reverse_view() {
    let outbound_plaintext = b"authenticated response view".to_vec();
    let inbound_plaintext = b"client upload".to_vec();
    let mut outbound = BufferedEndpoint::new(outbound_plaintext.clone(), 2);
    let expected_view_base = outbound.source.as_ptr() as usize;
    let mut inbound = PeerEndpoint::new(inbound_plaintext.clone(), 4, expected_view_base, false);
    let registry = OwnerRegistry::new();

    let stats = relay_lifecycle_buffered_outbound(
        &mut inbound,
        &mut outbound,
        Duration::from_secs(30),
        &registry,
        pending(),
    )
    .await
    .expect("buffered reverse relay");

    assert_eq!(stats.inbound_to_outbound, inbound_plaintext.len() as u64);
    assert_eq!(stats.outbound_to_inbound, outbound_plaintext.len() as u64);
    assert_eq!(outbound.received, inbound_plaintext);
    assert_eq!(inbound.received, outbound_plaintext);
    assert_eq!(outbound.async_read_calls, 0);
    assert!(outbound.flushes > 0);
    assert_eq!(registry.snapshot().owned_buffers, 0);
}

#[tokio::test]
async fn continuous_ready_reverse_reads_are_batched_until_eof() {
    const READ_LIMIT: usize = 1_024;
    let reverse: Vec<u8> = (0..(RELAY_BUFFER_BYTES * 3 + 17))
        .map(|index| (index % 251) as u8)
        .collect();
    let mut buffered = BufferedEndpoint::new(Vec::new(), usize::MAX);
    let expected_view_base = buffered.source.as_ptr() as usize;
    let mut peer = PeerEndpoint::new(reverse.clone(), usize::MAX, expected_view_base, false)
        .with_read_limit(READ_LIMIT);
    let registry = OwnerRegistry::new();

    let stats = relay_lifecycle_buffered_inbound(
        &mut buffered,
        &mut peer,
        Duration::from_secs(30),
        &registry,
        pending(),
    )
    .await
    .expect("buffered relay");

    assert_eq!(stats.inbound_to_outbound, 0);
    assert_eq!(stats.outbound_to_inbound, reverse.len() as u64);
    assert_eq!(buffered.received, reverse);
    assert_eq!(peer.read_calls, reverse.len().div_ceil(READ_LIMIT) + 1);
    assert_eq!(
        buffered.write_lengths,
        [
            RELAY_BUFFER_BYTES,
            RELAY_BUFFER_BYTES,
            RELAY_BUFFER_BYTES,
            17,
        ]
    );
    assert_eq!(buffered.flushes, 1, "continuous reads must flush at EOF");
    assert_eq!(registry.snapshot().owned_buffers, 0);
}

#[tokio::test]
async fn empty_and_exact_capacity_reverse_eof_never_writes_an_empty_slice() {
    const READ_LIMIT: usize = 1_024;
    for reverse_len in [0, RELAY_BUFFER_BYTES, RELAY_BUFFER_BYTES * 2] {
        let reverse = vec![0x5a; reverse_len];
        let mut buffered = BufferedEndpoint::new(Vec::new(), usize::MAX);
        let expected_view_base = buffered.source.as_ptr() as usize;
        let mut peer = PeerEndpoint::new(reverse.clone(), usize::MAX, expected_view_base, false)
            .with_read_limit(READ_LIMIT);
        let registry = OwnerRegistry::new();

        let stats = relay_lifecycle_buffered_inbound(
            &mut buffered,
            &mut peer,
            Duration::from_secs(30),
            &registry,
            pending(),
        )
        .await
        .expect("buffered relay");

        assert_eq!(stats.inbound_to_outbound, 0);
        assert_eq!(stats.outbound_to_inbound, reverse_len as u64);
        assert_eq!(buffered.received, reverse);
        assert_eq!(
            buffered.write_lengths,
            vec![RELAY_BUFFER_BYTES; reverse_len / RELAY_BUFFER_BYTES]
        );
        assert_eq!(buffered.flushes, usize::from(reverse_len > 0));
        assert_eq!(registry.snapshot().owned_buffers, 0);
    }
}

#[tokio::test]
async fn pending_reverse_reader_flushes_the_partial_batch_before_resuming() {
    const READ_LIMIT: usize = 1_024;
    const FIRST_BURST: usize = READ_LIMIT * 3;
    let reverse = vec![0x5a; READ_LIMIT * 8];
    let mut buffered = BufferedEndpoint::new(Vec::new(), usize::MAX);
    let expected_view_base = buffered.source.as_ptr() as usize;
    let mut peer = PeerEndpoint::new(reverse.clone(), usize::MAX, expected_view_base, false)
        .with_read_limit(READ_LIMIT)
        .with_pending_read_polls_after(FIRST_BURST, 2);
    let registry = OwnerRegistry::new();

    let stats = relay_lifecycle_buffered_inbound(
        &mut buffered,
        &mut peer,
        Duration::from_secs(30),
        &registry,
        pending(),
    )
    .await
    .expect("buffered relay");

    assert_eq!(stats.outbound_to_inbound, reverse.len() as u64);
    assert_eq!(buffered.received, reverse);
    assert_eq!(
        buffered.write_lengths,
        [FIRST_BURST, reverse.len() - FIRST_BURST]
    );
    assert_eq!(buffered.flushes, 2, "reader Pending and EOF each flush");
    assert_eq!(registry.snapshot().owned_buffers, 0);
}

struct NeverEndpoint;

impl AsyncRead for NeverEndpoint {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncBufRead for NeverEndpoint {
    fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        Poll::Pending
    }

    fn consume(self: Pin<&mut Self>, amount: usize) {
        assert_eq!(amount, 0);
    }
}

impl AsyncWrite for NeverEndpoint {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _source: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

#[tokio::test]
async fn buffered_lifecycle_owns_one_buffer_and_releases_it_on_cancel() {
    let registry = Arc::new(OwnerRegistry::new());
    let cancel = Arc::new(Notify::new());
    let task_registry = Arc::clone(&registry);
    let task_cancel = Arc::clone(&cancel);
    let task = tokio::spawn(async move {
        let mut inbound = NeverEndpoint;
        let mut outbound = NeverEndpoint;
        relay_lifecycle_buffered_inbound(
            &mut inbound,
            &mut outbound,
            Duration::from_secs(30),
            &task_registry,
            task_cancel.notified(),
        )
        .await
    });

    for _ in 0..10 {
        if registry.snapshot().owned_buffers == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(registry.snapshot().owned_buffers, 1);
    cancel.notify_one();
    let failure = task
        .await
        .expect("relay task")
        .expect_err("cancelled relay");
    assert_eq!(failure.kind, RelayRunError::Cancelled);
    assert_eq!(registry.snapshot().owned_buffers, 0);
}

#[test]
fn ten_thousand_buffered_connections_own_ten_thousand_not_twenty_thousand_buffers() {
    const CONNECTIONS: usize = 10_000;
    assert_eq!(BUFFERED_RELAY_BUFFERS_PER_CONNECTION, 1);
    assert_eq!(CONNECTIONS * BUFFERED_RELAY_BUFFERS_PER_CONNECTION, 10_000);
    assert_eq!(
        CONNECTIONS * BUFFERED_RELAY_BUFFERS_PER_CONNECTION * RELAY_BUFFER_BYTES,
        327_680_000
    );
}
