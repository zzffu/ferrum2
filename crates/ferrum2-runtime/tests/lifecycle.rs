use std::collections::VecDeque;
use std::future::{pending, ready};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum2_runtime::{
    AcceptListener, BoundedSupervisor, DEFAULT_HANDSHAKE_TIMEOUT, DeadlineError, OwnerRegistry,
    RelayFailure, RelayRunError, RelayStats, SupervisorError,
    relay_bidirectional_with_idle_timeout, relay_lifecycle, with_deadline,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Notify;

struct Endpoint<R, W> {
    reader: R,
    writer: W,
}

impl<R, W> AsyncRead for Endpoint<R, W>
where
    R: AsyncRead + Unpin,
    W: Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(context, buffer)
    }
}

impl<R, W> AsyncWrite for Endpoint<R, W>
where
    R: Unpin,
    W: AsyncWrite + Unpin,
{
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

struct BytesReader {
    bytes: &'static [u8],
    offset: usize,
}

impl BytesReader {
    fn new(bytes: &'static [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl AsyncRead for BytesReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let count = buffer
            .remaining()
            .min(self.bytes.len().saturating_sub(self.offset));
        if count > 0 {
            let end = self.offset + count;
            buffer.put_slice(&self.bytes[self.offset..end]);
            self.offset = end;
        }
        Poll::Ready(Ok(()))
    }
}

struct PendingReader;

impl AsyncRead for PendingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

struct SinkWriter;

impl AsyncWrite for SinkWriter {
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

struct PartialThenErrorWriter {
    remaining_before_error: usize,
}

impl AsyncWrite for PartialThenErrorWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.remaining_before_error == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "scripted write failure",
            )));
        }
        let written = buffer.len().min(self.remaining_before_error);
        self.remaining_before_error -= written;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct WriteZeroWriter;

impl AsyncWrite for WriteZeroWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(0))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct PendingWriter;

impl AsyncWrite for PendingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

struct CountingBytesReader {
    bytes: &'static [u8],
    offset: usize,
    observed: Arc<AtomicUsize>,
    gate: Arc<WriteGate>,
}

impl AsyncRead for CountingBytesReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.gate.open.load(Ordering::SeqCst) {
            *self.gate.waker.lock().expect("waker lock") = Some(context.waker().clone());
            return Poll::Pending;
        }
        let count = buffer
            .remaining()
            .min(self.bytes.len().saturating_sub(self.offset));
        if count > 0 {
            let end = self.offset + count;
            buffer.put_slice(&self.bytes[self.offset..end]);
            self.offset = end;
            self.observed.fetch_add(count, Ordering::SeqCst);
        }
        Poll::Ready(Ok(()))
    }
}

struct WriteGate {
    open: AtomicBool,
    waker: Mutex<Option<std::task::Waker>>,
}

impl WriteGate {
    fn new() -> Self {
        Self {
            open: AtomicBool::new(false),
            waker: Mutex::new(None),
        }
    }

    fn open(&self) {
        self.open.store(true, Ordering::SeqCst);
        if let Some(waker) = self.waker.lock().expect("waker lock").take() {
            waker.wake();
        }
    }
}

struct GateOpeningWriter {
    gate: Arc<WriteGate>,
}

impl AsyncWrite for GateOpeningWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.gate.open();
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct GatedPartialThenErrorWriter {
    gate: Arc<WriteGate>,
    remaining_before_error: usize,
}

impl AsyncWrite for GatedPartialThenErrorWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.gate.open.load(Ordering::SeqCst) {
            *self.gate.waker.lock().expect("waker lock") = Some(context.waker().clone());
            return Poll::Pending;
        }
        if self.remaining_before_error == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "scripted reverse write failure",
            )));
        }
        let written = buffer.len().min(self.remaining_before_error);
        self.remaining_before_error -= written;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct ScriptedListener {
    accepts: Arc<AtomicUsize>,
    responses: Mutex<VecDeque<Result<usize, io::ErrorKind>>>,
    available: Notify,
}

impl ScriptedListener {
    fn new(
        responses: impl IntoIterator<Item = Result<usize, io::ErrorKind>>,
    ) -> (Self, Arc<AtomicUsize>) {
        let accepts = Arc::new(AtomicUsize::new(0));
        (
            Self {
                accepts: Arc::clone(&accepts),
                responses: Mutex::new(responses.into_iter().collect()),
                available: Notify::new(),
            },
            accepts,
        )
    }
}

impl AcceptListener for ScriptedListener {
    type Stream = usize;

    async fn accept(&self) -> io::Result<Self::Stream> {
        self.accepts.fetch_add(1, Ordering::SeqCst);
        loop {
            if let Some(result) = self.responses.lock().expect("response lock").pop_front() {
                return result.map_err(|kind| io::Error::new(kind, "scripted accept failure"));
            }
            self.available.notified().await;
        }
    }
}

#[tokio::test]
async fn permit_is_owned_before_accept_and_caps_connection_tasks() {
    let (listener, accept_calls) = ScriptedListener::new([Ok(1), Ok(2)]);
    let registry = OwnerRegistry::new();
    let supervisor =
        BoundedSupervisor::new(listener, 1, Duration::ZERO, registry.clone()).expect("valid cap");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let run = tokio::spawn(supervisor.run_until(
        |_stream, mut cancellation| async move { cancellation.cancelled().await },
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    for _ in 0..100 {
        if registry.snapshot().connection_tasks == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }

    assert_eq!(accept_calls.load(Ordering::SeqCst), 1);
    assert_eq!(registry.snapshot().owned_permits, 1);
    assert_eq!(registry.snapshot().connection_tasks, 1);

    shutdown_tx.send(()).expect("request shutdown");
    run.await
        .expect("supervisor task")
        .expect("operator shutdown succeeds");
    assert_eq!(registry.snapshot().owned_permits, 0);
    assert_eq!(registry.snapshot().connection_tasks, 0);
    assert_eq!(registry.snapshot().active_supervisor_children, 0);
    assert_eq!(registry.snapshot().listeners, 0);
}

#[tokio::test]
async fn listener_failure_is_process_fatal_and_reaps_children() {
    let (listener, _accept_calls) = ScriptedListener::new([Err(io::ErrorKind::PermissionDenied)]);
    let registry = OwnerRegistry::new();
    let supervisor =
        BoundedSupervisor::new(listener, 1, Duration::ZERO, registry.clone()).expect("valid cap");

    let result = supervisor
        .run_until(|_stream, _cancellation| async {}, pending::<()>())
        .await;

    assert_eq!(result, Err(SupervisorError::ListenerFailure));
    assert_eq!(registry.snapshot().owned_permits, 0);
    assert_eq!(registry.snapshot().active_supervisor_children, 0);
    assert_eq!(registry.snapshot().listeners, 0);
}

#[tokio::test(start_paused = true)]
async fn handshake_timeout_uses_the_five_second_monotonic_deadline() {
    assert_eq!(DEFAULT_HANDSHAKE_TIMEOUT, Duration::from_secs(5));
    let task = tokio::spawn(with_deadline(
        DEFAULT_HANDSHAKE_TIMEOUT,
        pending::<Result<(), io::Error>>(),
    ));
    tokio::task::yield_now().await;

    tokio::time::advance(Duration::from_secs(5)).await;

    assert!(matches!(
        task.await.expect("deadline task"),
        Err(DeadlineError::Timeout)
    ));
}

#[tokio::test(start_paused = true)]
async fn idle_relay_times_out_without_forwarded_bytes() {
    let (_application, mut inbound) = tokio::io::duplex(64);
    let (mut outbound, _target) = tokio::io::duplex(64);
    let relay = tokio::spawn(async move {
        relay_bidirectional_with_idle_timeout(&mut inbound, &mut outbound, Duration::from_secs(5))
            .await
    });
    tokio::task::yield_now().await;

    tokio::time::advance(Duration::from_secs(5)).await;

    assert_eq!(
        relay.await.expect("relay task"),
        Err(RelayFailure {
            kind: RelayRunError::IdleTimeout,
            stats: RelayStats {
                inbound_to_outbound: 0,
                outbound_to_inbound: 0,
            },
        })
    );
}

#[tokio::test]
async fn partial_write_then_error_retains_the_exact_completed_prefix() {
    let mut inbound = Endpoint {
        reader: BytesReader::new(b"completed-prefix-and-unwritten-suffix"),
        writer: SinkWriter,
    };
    let mut outbound = Endpoint {
        reader: PendingReader,
        writer: PartialThenErrorWriter {
            remaining_before_error: 9,
        },
    };

    let failure =
        relay_bidirectional_with_idle_timeout(&mut inbound, &mut outbound, Duration::from_secs(60))
            .await
            .expect_err("second write fails");

    assert_eq!(
        failure,
        RelayFailure {
            kind: RelayRunError::Io,
            stats: RelayStats {
                inbound_to_outbound: 9,
                outbound_to_inbound: 0,
            },
        }
    );
    assert_eq!(failure.to_string(), "relay I/O failed");
    assert!(!format!("{failure:?}").contains("scripted write failure"));
    assert!(std::error::Error::source(&failure).is_none());
}

#[tokio::test]
async fn asymmetric_bidirectional_failure_keeps_direction_mapping() {
    let gate = Arc::new(WriteGate::new());
    let mut inbound = Endpoint {
        reader: BytesReader::new(b"abc"),
        writer: GatedPartialThenErrorWriter {
            gate: Arc::clone(&gate),
            remaining_before_error: 5,
        },
    };
    let mut outbound = Endpoint {
        reader: BytesReader::new(b"reverse-data"),
        writer: GateOpeningWriter { gate },
    };

    let failure =
        relay_bidirectional_with_idle_timeout(&mut inbound, &mut outbound, Duration::from_secs(60))
            .await
            .expect_err("reverse direction fails after both directions progress");

    assert_eq!(
        failure,
        RelayFailure {
            kind: RelayRunError::Io,
            stats: RelayStats {
                inbound_to_outbound: 3,
                outbound_to_inbound: 5,
            },
        }
    );
}

#[tokio::test(start_paused = true)]
async fn idle_timeout_after_progress_retains_completed_stats() {
    let (mut application, mut inbound) = tokio::io::duplex(64);
    let (mut outbound, mut target) = tokio::io::duplex(64);
    let relay = tokio::spawn(async move {
        relay_bidirectional_with_idle_timeout(&mut inbound, &mut outbound, Duration::from_secs(5))
            .await
    });
    tokio::task::yield_now().await;

    application
        .write_all(b"abc")
        .await
        .expect("write application bytes");
    let mut forwarded = [0_u8; 3];
    target
        .read_exact(&mut forwarded)
        .await
        .expect("read forwarded bytes");
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(5)).await;

    assert_eq!(
        relay.await.expect("relay task"),
        Err(RelayFailure {
            kind: RelayRunError::IdleTimeout,
            stats: RelayStats {
                inbound_to_outbound: 3,
                outbound_to_inbound: 0,
            },
        })
    );
}

#[tokio::test(start_paused = true)]
async fn read_ahead_into_a_pending_writer_counts_zero_and_does_not_reset_idle() {
    let observed = Arc::new(AtomicUsize::new(0));
    let observed_by_reader = Arc::clone(&observed);
    let read_gate = Arc::new(WriteGate::new());
    let read_gate_for_relay = Arc::clone(&read_gate);
    let relay = tokio::spawn(async move {
        let mut inbound = Endpoint {
            reader: CountingBytesReader {
                bytes: b"read-but-not-written",
                offset: 0,
                observed: observed_by_reader,
                gate: read_gate_for_relay,
            },
            writer: SinkWriter,
        };
        let mut outbound = Endpoint {
            reader: PendingReader,
            writer: PendingWriter,
        };
        relay_bidirectional_with_idle_timeout(&mut inbound, &mut outbound, Duration::from_secs(5))
            .await
    });

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(4)).await;
    assert_eq!(observed.load(Ordering::SeqCst), 0);
    assert!(!relay.is_finished(), "idle interval has one second left");

    read_gate.open();
    for _ in 0..100 {
        if observed.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(observed.load(Ordering::SeqCst), 20);
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(
        relay.is_finished(),
        "successful reads must not reset the armed idle deadline"
    );

    assert_eq!(
        relay.await.expect("relay task"),
        Err(RelayFailure {
            kind: RelayRunError::IdleTimeout,
            stats: RelayStats {
                inbound_to_outbound: 0,
                outbound_to_inbound: 0,
            },
        })
    );
}

#[tokio::test]
async fn write_zero_is_io_failure_with_zero_completed_stats() {
    let mut inbound = Endpoint {
        reader: BytesReader::new(b"not-accepted"),
        writer: SinkWriter,
    };
    let mut outbound = Endpoint {
        reader: PendingReader,
        writer: WriteZeroWriter,
    };

    let failure =
        relay_bidirectional_with_idle_timeout(&mut inbound, &mut outbound, Duration::from_secs(60))
            .await
            .expect_err("write zero is an I/O failure");

    assert_eq!(
        failure,
        RelayFailure {
            kind: RelayRunError::Io,
            stats: RelayStats {
                inbound_to_outbound: 0,
                outbound_to_inbound: 0,
            },
        }
    );
}

#[tokio::test]
async fn ready_shutdown_prevents_every_simultaneously_ready_accept() {
    let post_shutdown_accepts = Arc::new(AtomicUsize::new(0));

    for iteration in 0..512 {
        let listener = ScriptedListener {
            accepts: Arc::clone(&post_shutdown_accepts),
            responses: Mutex::new([Ok(iteration)].into_iter().collect()),
            available: Notify::new(),
        };
        let supervisor = BoundedSupervisor::new(listener, 1, Duration::ZERO, OwnerRegistry::new())
            .expect("valid cap");

        supervisor
            .run_until(|_stream, _cancellation| async {}, ready(()))
            .await
            .expect("ready shutdown is controlled");
    }

    assert_eq!(post_shutdown_accepts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn transient_accept_failure_yields_then_accepts_the_next_stream() {
    let (listener, accept_calls) = ScriptedListener::new([Err(io::ErrorKind::Interrupted), Ok(7)]);
    let registry = OwnerRegistry::new();
    let supervisor =
        BoundedSupervisor::new(listener, 1, Duration::ZERO, registry.clone()).expect("valid cap");
    let completed = Arc::new(Notify::new());
    let completed_by_handler = Arc::clone(&completed);
    let handled = Arc::new(AtomicUsize::new(0));
    let handled_by_handler = Arc::clone(&handled);

    supervisor
        .run_until(
            move |stream, _cancellation| {
                let completed = Arc::clone(&completed_by_handler);
                let handled = Arc::clone(&handled_by_handler);
                async move {
                    assert_eq!(stream, 7);
                    handled.fetch_add(1, Ordering::SeqCst);
                    completed.notify_one();
                }
            },
            completed.notified(),
        )
        .await
        .expect("transient accept error is retried");

    assert_eq!(accept_calls.load(Ordering::SeqCst), 2);
    assert_eq!(handled.load(Ordering::SeqCst), 1);
    assert_eq!(registry.snapshot().active_supervisor_children, 0);
    assert_eq!(registry.snapshot().owned_permits, 0);
}

#[tokio::test]
async fn non_transient_accept_failure_cancels_and_reaps_a_live_child() {
    let (listener, accept_calls) =
        ScriptedListener::new([Ok(1), Err(io::ErrorKind::PermissionDenied)]);
    let registry = OwnerRegistry::new();
    let supervisor = BoundedSupervisor::new(listener, 2, Duration::from_secs(1), registry.clone())
        .expect("valid cap");
    let cancellation_observed = Arc::new(AtomicUsize::new(0));
    let observed_by_handler = Arc::clone(&cancellation_observed);

    let result = supervisor
        .run_until(
            move |_stream, mut cancellation| {
                let observed = Arc::clone(&observed_by_handler);
                async move {
                    cancellation.cancelled().await;
                    observed.fetch_add(1, Ordering::SeqCst);
                }
            },
            pending::<()>(),
        )
        .await;

    assert_eq!(result, Err(SupervisorError::ListenerFailure));
    assert_eq!(accept_calls.load(Ordering::SeqCst), 2);
    assert_eq!(cancellation_observed.load(Ordering::SeqCst), 1);
    let snapshot = registry.snapshot();
    assert_eq!(snapshot.active_supervisor_children, 0);
    assert_eq!(snapshot.connection_tasks, 0);
    assert_eq!(snapshot.owned_buffers, 0);
    assert_eq!(snapshot.owned_permits, 0);
    assert_eq!(snapshot.listeners, 0);
    assert_eq!(snapshot.forced_shutdowns, 0);
}

#[tokio::test(start_paused = true)]
async fn relay_lifecycle_cancel_retains_asymmetric_stats_and_returns_buffers() {
    let (mut application, mut inbound) = tokio::io::duplex(64);
    let (mut outbound, mut target) = tokio::io::duplex(64);
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let registry_for_relay = registry.clone();
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    let relay = tokio::spawn(async move {
        relay_lifecycle(
            &mut inbound,
            &mut outbound,
            Duration::from_secs(5),
            &registry_for_relay,
            async move {
                let _ = cancel_rx.await;
            },
        )
        .await
    });
    tokio::task::yield_now().await;
    assert_eq!(registry.snapshot().owned_buffers, 2);

    tokio::time::advance(Duration::from_secs(4)).await;
    application.write_all(b"x").await.expect("write one byte");
    let mut forwarded = [0_u8; 1];
    target
        .read_exact(&mut forwarded)
        .await
        .expect("byte is forwarded");
    assert_eq!(forwarded, *b"x");
    target.write_all(b"yz").await.expect("write reverse bytes");
    let mut reverse = [0_u8; 2];
    application
        .read_exact(&mut reverse)
        .await
        .expect("reverse bytes are forwarded");
    assert_eq!(reverse, *b"yz");

    tokio::time::advance(Duration::from_secs(4)).await;
    tokio::task::yield_now().await;
    assert!(
        !relay.is_finished(),
        "forwarded byte reset the idle deadline"
    );

    cancel_tx
        .send(())
        .expect("request cooperative cancellation");
    assert_eq!(
        relay.await.expect("relay owner"),
        Err(RelayFailure {
            kind: RelayRunError::Cancelled,
            stats: RelayStats {
                inbound_to_outbound: 1,
                outbound_to_inbound: 2,
            },
        })
    );
    assert_eq!(registry.snapshot(), baseline);
}
