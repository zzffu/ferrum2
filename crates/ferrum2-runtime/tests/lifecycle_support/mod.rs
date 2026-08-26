#![allow(dead_code, unused_imports)]

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
    PreparedProcessRoot, ProcessCause, ProcessCleanupFailure, ProcessExitKind, ProcessFuture,
    ProcessRoot, ProcessRootEventPhase, ProcessRootExit, ProcessRootExitCategory, ProcessState,
    ProcessSupervisor, RelayFailure, RelayRunError, RelayStats, SupervisorError,
    relay_bidirectional_with_idle_timeout, relay_lifecycle, with_deadline,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Notify;

const REQUIRED_ROOT_COUNT: usize = 3;

pub(crate) struct Endpoint<R, W> {
    pub(crate) reader: R,
    pub(crate) writer: W,
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

pub(crate) struct BytesReader {
    pub(crate) bytes: &'static [u8],
    pub(crate) offset: usize,
}

impl BytesReader {
    pub(crate) fn new(bytes: &'static [u8]) -> Self {
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

pub(crate) struct PendingReader;

impl AsyncRead for PendingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

pub(crate) struct SinkWriter;

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

pub(crate) struct PartialThenErrorWriter {
    pub(crate) remaining_before_error: usize,
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

pub(crate) struct WriteZeroWriter;

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

pub(crate) struct PendingWriter;

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

pub(crate) struct CountingBytesReader {
    pub(crate) bytes: &'static [u8],
    pub(crate) offset: usize,
    pub(crate) observed: Arc<AtomicUsize>,
    pub(crate) gate: Arc<WriteGate>,
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

pub(crate) struct WriteGate {
    pub(crate) open: AtomicBool,
    pub(crate) waker: Mutex<Option<std::task::Waker>>,
}

impl WriteGate {
    pub(crate) fn new() -> Self {
        Self {
            open: AtomicBool::new(false),
            waker: Mutex::new(None),
        }
    }

    pub(crate) fn open(&self) {
        self.open.store(true, Ordering::SeqCst);
        if let Some(waker) = self.waker.lock().expect("waker lock").take() {
            waker.wake();
        }
    }
}

pub(crate) struct GateOpeningWriter {
    pub(crate) gate: Arc<WriteGate>,
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

pub(crate) struct GatedPartialThenErrorWriter {
    pub(crate) gate: Arc<WriteGate>,
    pub(crate) remaining_before_error: usize,
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

pub(crate) struct ScriptedListener {
    pub(crate) accepts: Arc<AtomicUsize>,
    pub(crate) responses: Mutex<VecDeque<Result<usize, io::ErrorKind>>>,
    pub(crate) available: Notify,
}

impl ScriptedListener {
    pub(crate) fn new(
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

#[derive(Clone, Copy)]
pub(crate) enum StartupFailure {
    Prepare(usize),
    Activate(usize),
}

pub(crate) struct FakeProcessRoot {
    pub(crate) index: usize,
    pub(crate) activation_failure: Option<usize>,
    pub(crate) events: Arc<Mutex<Vec<String>>>,
    pub(crate) polls: Arc<AtomicUsize>,
}

impl PreparedProcessRoot<&'static str> for FakeProcessRoot {
    fn activate(&mut self) -> Result<(), &'static str> {
        self.events
            .lock()
            .expect("event lock")
            .push(format!("activate:{}", self.index));
        if self.activation_failure == Some(self.index) {
            Err("activation")
        } else {
            Ok(())
        }
    }

    fn run(
        self: Box<Self>,
        mut cancellation: ferrum2_runtime::ProcessCancellation,
    ) -> ProcessFuture<Result<(), &'static str>> {
        Box::pin(async move {
            self.polls.fetch_add(1, Ordering::SeqCst);
            cancellation.cancelled().await;
            self.events
                .lock()
                .expect("event lock")
                .push(format!("stopped:{}", self.index));
            Ok(())
        })
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), &'static str>> {
        Box::pin(async move {
            self.events
                .lock()
                .expect("event lock")
                .push(format!("rollback:{}", self.index));
            Ok(())
        })
    }
}

pub(crate) fn fake_process_roots(
    failure: StartupFailure,
    events: Arc<Mutex<Vec<String>>>,
    polls: Arc<AtomicUsize>,
) -> Vec<ProcessRoot<&'static str>> {
    (0..REQUIRED_ROOT_COUNT)
        .map(|index| {
            let events = Arc::clone(&events);
            let polls = Arc::clone(&polls);
            ProcessRoot::new(move || async move {
                events
                    .lock()
                    .expect("event lock")
                    .push(format!("prepare:{index}"));
                if matches!(failure, StartupFailure::Prepare(failed) if failed == index) {
                    return Err("preparation");
                }
                Ok(FakeProcessRoot {
                    index,
                    activation_failure: match failure {
                        StartupFailure::Activate(failed) => Some(failed),
                        StartupFailure::Prepare(_) => None,
                    },
                    events,
                    polls,
                })
            })
        })
        .collect()
}

pub(crate) struct HandoffRoot {
    pub(crate) index: usize,
    pub(crate) panic_on_run: bool,
    pub(crate) events: Arc<Mutex<Vec<String>>>,
}

impl Drop for HandoffRoot {
    fn drop(&mut self) {
        self.events
            .lock()
            .expect("event lock")
            .push(format!("terminal:{}", self.index));
    }
}

impl PreparedProcessRoot<&'static str> for HandoffRoot {
    fn activate(&mut self) -> Result<(), &'static str> {
        Ok(())
    }

    fn run(
        self: Box<Self>,
        mut cancellation: ferrum2_runtime::ProcessCancellation,
    ) -> ProcessFuture<Result<(), &'static str>> {
        self.events
            .lock()
            .expect("event lock")
            .push(format!("handoff:{}", self.index));
        assert!(!self.panic_on_run, "scripted synchronous run panic");
        Box::pin(async move {
            let _root_owner = self;
            cancellation.cancelled().await;
            pending().await
        })
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), &'static str>> {
        self.events
            .lock()
            .expect("event lock")
            .push(format!("rollback:{}", self.index));
        Box::pin(ready(Ok(())))
    }
}

#[derive(Clone, Copy)]
pub(crate) enum RootRun {
    Complete,
    Fail,
    Panic,
    AwaitCancellation,
}

pub(crate) struct RunningFakeRoot {
    pub(crate) behavior: RootRun,
}

impl PreparedProcessRoot<&'static str> for RunningFakeRoot {
    fn activate(&mut self) -> Result<(), &'static str> {
        Ok(())
    }

    fn run(
        self: Box<Self>,
        mut cancellation: ferrum2_runtime::ProcessCancellation,
    ) -> ProcessFuture<Result<(), &'static str>> {
        Box::pin(async move {
            match self.behavior {
                RootRun::Complete => Ok(()),
                RootRun::Fail => Err("root"),
                RootRun::Panic => panic!("scripted root panic"),
                RootRun::AwaitCancellation => {
                    cancellation.cancelled().await;
                    Ok(())
                }
            }
        })
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), &'static str>> {
        Box::pin(ready(Ok(())))
    }
}

pub(crate) fn running_root(behavior: RootRun) -> ProcessRoot<&'static str> {
    ProcessRoot::new(move || async move { Ok(RunningFakeRoot { behavior }) })
}
