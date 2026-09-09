use super::*;
use std::sync::atomic::AtomicUsize;
use std::sync::{Barrier, Weak};
use std::task::Wake;

struct ReentrantFenceWake {
    shared: Weak<FlowShared>,
    calls: AtomicUsize,
}

impl Wake for ReentrantFenceWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // Real consumer action, not a lock-shape assertion: a cancelled task may
        // synchronously request another idempotent fence from its wake callback.
        if let Some(shared) = self.shared.upgrade() {
            TcpSocketLease { shared }.fence().expect("reentrant fence");
        }
        self.calls.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn concurrent_fence_cannot_lose_pending_read_or_write_wakes() {
    for write in [false, true] {
        for _ in 0..64 {
            let (socket, _peer) = tokio::io::duplex(1);
            let (mut flow, lease) = tcp_flow_from_stream(
                FlowSocket::Memory(socket),
                "192.0.2.1:443".parse().expect("target"),
                1,
                &OwnerRegistry::new(),
                OwnerWake::default(),
            );
            if write {
                let mut context = Context::from_waker(Waker::noop());
                assert!(matches!(
                    Pin::new(&mut flow).poll_write(&mut context, b"x"),
                    Poll::Ready(Ok(1))
                ));
            }
            let wake = Arc::new(ReentrantFenceWake {
                shared: Arc::downgrade(&lease.shared),
                calls: AtomicUsize::new(0),
            });
            let waker = Waker::from(Arc::clone(&wake));
            let barrier = Arc::new(Barrier::new(2));
            let poll_barrier = Arc::clone(&barrier);
            let poll = std::thread::spawn(move || {
                let mut context = Context::from_waker(&waker);
                poll_barrier.wait();
                let result = if write {
                    Pin::new(&mut flow)
                        .poll_write(&mut context, b"y")
                        .map(|result| result.map(|_| ()))
                } else {
                    let mut byte = [0];
                    Pin::new(&mut flow).poll_read(&mut context, &mut ReadBuf::new(&mut byte))
                };
                (
                    flow,
                    result.map(|result| result.map_err(|error| error.kind())),
                )
            });
            barrier.wait();
            lease.fence().expect("concurrent fence");
            let (mut flow, result) = poll.join().expect("poll thread");
            match result {
                Poll::Pending => assert!(
                    wake.calls.load(Ordering::Relaxed) > 0,
                    "pending cancellation must wake"
                ),
                Poll::Ready(Err(kind)) => assert_eq!(kind, io::ErrorKind::ConnectionReset),
                Poll::Ready(Ok(())) => panic!("empty read/full write cannot complete successfully"),
            }
            let mut context = Context::from_waker(Waker::noop());
            assert!(
                matches!(Pin::new(&mut flow).poll_write(&mut context, b"late"), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset)
            );
        }
    }
}
