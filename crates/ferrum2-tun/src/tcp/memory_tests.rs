use super::*;
use std::sync::atomic::AtomicUsize;
use std::sync::{Weak, mpsc};
use std::task::Wake;
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(10);

// All flow ownership and potentially blocking callbacks stay on detached-on-
// timeout workers. In particular, timeout unwinding cannot drop a TcpFlow on
// the test thread and block on the very mutex whose deadlock we are detecting.
fn bounded(scenario: impl FnOnce() + Send + 'static) {
    let (done, completion) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(scenario));
        let _ = done.send(result);
    });
    let result = completion
        .recv_timeout(WAIT)
        .expect("memory flow scenario timed out");
    worker.join().expect("scenario worker completion");
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[derive(Default)]
struct CountWake(AtomicUsize);

impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

struct ReentrantFenceWake {
    shared: Weak<FlowShared>,
    calls: AtomicUsize,
}

impl Wake for ReentrantFenceWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // Real consumer action: cancellation may synchronously request another
        // idempotent fence. Count only callbacks whose nested fence returned.
        if let Some(shared) = self.shared.upgrade() {
            TcpSocketLease { shared }.fence().expect("reentrant fence");
        }
        self.calls.fetch_add(1, Ordering::Relaxed);
    }
}

fn memory_flow() -> (TcpFlow, tokio::io::DuplexStream, TcpSocketLease) {
    let (socket, peer) = tokio::io::duplex(1);
    let (flow, lease) = tcp_flow_from_stream(
        FlowSocket::Memory(socket),
        "198.18.0.2:10000".parse().expect("original source"),
        "192.0.2.1:443".parse().expect("target"),
        1,
        &OwnerRegistry::new(),
        OwnerWake::default(),
    );
    (flow, peer, lease)
}

fn fill_write_capacity(flow: &mut TcpFlow) {
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(flow).poll_write(&mut context, b"x"),
        Poll::Ready(Ok(1))
    ));
}

fn poll_io(flow: &mut TcpFlow, write: bool, waker: &Waker) -> Poll<Result<(), io::ErrorKind>> {
    let mut context = Context::from_waker(waker);
    let result = if write {
        Pin::new(flow)
            .poll_write(&mut context, b"y")
            .map(|result| result.map(|_| ()))
    } else {
        let mut byte = [0];
        Pin::new(flow).poll_read(&mut context, &mut ReadBuf::new(&mut byte))
    };
    result.map(|result| result.map_err(|error| error.kind()))
}

fn pending_registered(flow: &mut TcpFlow, write: bool, waker: &Waker) {
    assert_eq!(poll_io(flow, write, waker), Poll::Pending);
    // Establish that the cancellation slot (not just DuplexStream readiness)
    // contains this waiter before choosing the fence interleaving.
    let state = flow.shared.state.lock().expect("cancellation state");
    let waiter = if write { &state.write } else { &state.read };
    assert!(
        waiter
            .as_ref()
            .is_some_and(|registered| registered.will_wake(waker))
    );
}

fn assert_reset(flow: &mut TcpFlow) {
    for write in [false, true] {
        assert_eq!(
            poll_io(flow, write, Waker::noop()),
            Poll::Ready(Err(io::ErrorKind::ConnectionReset))
        );
    }
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut *flow).poll_flush(&mut context),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset
    ));
    assert!(matches!(
        Pin::new(flow).poll_shutdown(&mut context),
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset
    ));
}

#[test]
fn fence_wakes_an_already_registered_pending_reader_and_writer() {
    bounded(|| {
        for write in [false, true] {
            let (mut flow, _peer, lease) = memory_flow();
            if write {
                fill_write_capacity(&mut flow);
            }
            let wake = Arc::new(CountWake::default());
            let waker = Waker::from(Arc::clone(&wake));
            pending_registered(&mut flow, write, &waker);
            let before_fence = wake.0.load(Ordering::Relaxed);
            lease.fence().expect("fence registered waiter");
            assert!(wake.0.load(Ordering::Relaxed) > before_fence);
            assert_reset(&mut flow);
        }
    });
}

#[test]
fn fence_wakes_the_current_waiter_after_pending_repoll() {
    bounded(|| {
        for write in [false, true] {
            let (mut flow, _peer, lease) = memory_flow();
            if write {
                fill_write_capacity(&mut flow);
            }
            let old = Arc::new(CountWake::default());
            let current = Arc::new(CountWake::default());
            pending_registered(&mut flow, write, &Waker::from(old));
            pending_registered(&mut flow, write, &Waker::from(Arc::clone(&current)));
            let before_fence = current.0.load(Ordering::Relaxed);
            lease.fence().expect("fence replacement waiter");
            // Old or duplicate wakes are harmless; the current waiter must wake.
            assert!(current.0.load(Ordering::Relaxed) > before_fence);
            assert_reset(&mut flow);
        }
    });
}

#[test]
fn fence_before_io_returns_reset_even_when_the_socket_would_be_ready() {
    bounded(|| {
        let (mut flow, mut peer, lease) = memory_flow();
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut peer).poll_write(&mut context, b"r"),
            Poll::Ready(Ok(1))
        ));
        // Read has data and write has capacity; neither may bypass the fence.
        lease.fence().expect("fence before poll");
        assert_reset(&mut flow);
    });
}

#[test]
fn registered_cancellation_callback_can_synchronously_reenter_fence() {
    bounded(|| {
        for write in [false, true] {
            let (mut flow, _peer, lease) = memory_flow();
            if write {
                fill_write_capacity(&mut flow);
            }
            let wake = Arc::new(ReentrantFenceWake {
                shared: Arc::downgrade(&lease.shared),
                calls: AtomicUsize::new(0),
            });
            pending_registered(&mut flow, write, &Waker::from(Arc::clone(&wake)));
            let before_fence = wake.calls.load(Ordering::Relaxed);
            lease.fence().expect("outer fence");
            assert!(wake.calls.load(Ordering::Relaxed) > before_fence);
            assert_reset(&mut flow);
        }
    });
}

#[test]
fn write_half_close_preserves_reads_until_reset_takes_precedence() {
    bounded(|| {
        let (mut flow, mut peer, lease) = memory_flow();
        let wake = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&wake));
        pending_registered(&mut flow, false, &waker);
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut flow).poll_shutdown(&mut context),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(
            poll_io(&mut flow, true, Waker::noop()),
            Poll::Ready(Err(io::ErrorKind::BrokenPipe))
        );
        let mut byte = [0];
        let mut eof = ReadBuf::new(&mut byte);
        assert!(matches!(
            Pin::new(&mut peer).poll_read(&mut context, &mut eof),
            Poll::Ready(Ok(()))
        ));
        assert!(eof.filled().is_empty());
        assert!(matches!(
            Pin::new(&mut peer).poll_write(&mut context, b"r"),
            Poll::Ready(Ok(1))
        ));
        let mut received = ReadBuf::new(&mut byte);
        assert!(matches!(
            Pin::new(&mut flow).poll_read(&mut context, &mut received),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(received.filled(), b"r");
        pending_registered(&mut flow, false, &waker);
        let before_fence = wake.0.load(Ordering::Relaxed);
        lease.fence().expect("reset after half close");
        assert!(wake.0.load(Ordering::Relaxed) > before_fence);
        assert_reset(&mut flow);
    });
}

#[test]
fn concurrent_fence_cannot_lose_pending_read_or_write_wakes() {
    bounded(|| {
        for write in [false, true] {
            for _ in 0..64 {
                let (mut flow, _peer, lease) = memory_flow();
                if write {
                    fill_write_capacity(&mut flow);
                }
                let wake = Arc::new(ReentrantFenceWake {
                    shared: Arc::downgrade(&lease.shared),
                    calls: AtomicUsize::new(0),
                });
                let waker = Waker::from(Arc::clone(&wake));
                let (ready, readiness) = mpsc::channel();
                let (poll_start, poll_go) = mpsc::sync_channel(1);
                let (fence_start, fence_go) = mpsc::sync_channel(1);
                let (polled, poll_done) = mpsc::channel();
                let (fenced, fence_done) = mpsc::channel();
                let poll_ready = ready.clone();
                let poll = std::thread::spawn(move || {
                    poll_ready.send(()).expect("poll ready");
                    poll_go.recv_timeout(WAIT).expect("poll start");
                    let result = poll_io(&mut flow, write, &waker);
                    let _ = polled.send((flow, result));
                });
                let fence = std::thread::spawn(move || {
                    ready.send(()).expect("fence ready");
                    fence_go.recv_timeout(WAIT).expect("fence start");
                    lease.fence().expect("concurrent fence");
                    let _ = fenced.send(());
                });
                // Release both ready workers without guessing their scheduling.
                readiness.recv_timeout(WAIT).expect("first worker ready");
                readiness.recv_timeout(WAIT).expect("second worker ready");
                poll_start.send(()).expect("release poll");
                fence_start.send(()).expect("release fence");
                fence_done.recv_timeout(WAIT).expect("fence completion");
                fence.join().expect("fence thread");
                let (mut flow, result) = poll_done.recv_timeout(WAIT).expect("poll completion");
                poll.join().expect("poll thread");
                match result {
                    Poll::Pending => assert!(
                        wake.calls.load(Ordering::Relaxed) > 0,
                        "pending cancellation must wake"
                    ),
                    Poll::Ready(Err(kind)) => assert_eq!(kind, io::ErrorKind::ConnectionReset),
                    Poll::Ready(Ok(())) => {
                        panic!("empty read/full write cannot complete successfully")
                    }
                }
                assert_reset(&mut flow);
            }
        }
    });
}
