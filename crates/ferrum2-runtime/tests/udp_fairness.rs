use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_runtime::{
    AccountedDatagram, DirectUdpPacketHandler, DirectUdpRuntime, DirectUdpSocket,
    DirectUdpSocketFactory, OwnerRegistry, UDP_SESSION_QUEUE_DEPTH, UdpDirection, UdpSessionHandle,
    UdpSessionManager,
};
use tokio::sync::Notify;
use tokio::time::Instant;

mod udp_support;
use udp_support::{
    empty_resolver, ip_datagram, limits, recording_runtime, selection_destination, socket_fixture,
};

struct ReplenishingSocket {
    manager: UdpSessionManager,
    handle: Arc<OnceLock<UdpSessionHandle>>,
    sends: Arc<AtomicUsize>,
}

impl DirectUdpSocket for ReplenishingSocket {
    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.try_send_to(payload, target)
    }

    fn try_send_to(&self, payload: &[u8], _target: SocketAddr) -> io::Result<usize> {
        let sent = self.sends.fetch_add(1, Ordering::SeqCst) + 1;
        // A finite producer bounds the regression test even if the task never
        // yields. It represents a peer refilling each newly available slot.
        if sent < 64 {
            self.manager
                .reserve_datagram(*self.handle.get().unwrap(), UdpDirection::ToTarget, 7)
                .unwrap()
                .commit(ip_datagram(b"request"), Instant::now())
                .unwrap();
        }
        Ok(payload.len())
    }

    async fn readable(&self) -> io::Result<()> {
        Ok(())
    }

    async fn recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        self.try_recv_buf_from(payload)
    }

    fn try_recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        payload.extend_from_slice(b"reply");
        Ok((5, selection_destination()))
    }
}

struct SocketFactory {
    manager: UdpSessionManager,
    handle: Arc<OnceLock<UdpSessionHandle>>,
    sends: Arc<AtomicUsize>,
}

impl DirectUdpSocketFactory for SocketFactory {
    type Socket = ReplenishingSocket;
    type OpenContext = ();

    async fn open(&self, (): (), _: SocketAddr) -> io::Result<Self::Socket> {
        Ok(ReplenishingSocket {
            manager: self.manager.clone(),
            handle: Arc::clone(&self.handle),
            sends: Arc::clone(&self.sends),
        })
    }
}

struct ObserveResponse {
    sends: Arc<AtomicUsize>,
    observed_sends: Arc<AtomicUsize>,
    completed: Arc<Notify>,
}

impl DirectUdpPacketHandler for ObserveResponse {
    type Error = ();

    async fn handle_target_response(
        &self,
        _: UdpSessionHandle,
        response: AccountedDatagram,
    ) -> Result<(), Self::Error> {
        assert_eq!(response.datagram().payload(), b"reply");
        self.observed_sends
            .store(self.sends.load(Ordering::SeqCst), Ordering::SeqCst);
        self.completed.notify_one();
        // End the task after its first response, including on old code.
        Err(())
    }
}

#[tokio::test(start_paused = true)]
async fn replenished_request_queue_cannot_starve_an_already_ready_response() {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let manager = UdpSessionManager::new(limits(1), registry.clone());
    let handle = Arc::new(OnceLock::new());
    let sends = Arc::new(AtomicUsize::new(0));
    let observed_sends = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(Notify::new());
    let mut runtime = DirectUdpRuntime::with_shared_adapters(
        manager.clone(),
        Duration::from_secs(1),
        empty_resolver(),
        SocketFactory {
            manager,
            handle: Arc::clone(&handle),
            sends: Arc::clone(&sends),
        },
        ObserveResponse {
            sends: Arc::clone(&sends),
            observed_sends: Arc::clone(&observed_sends),
            completed: Arc::clone(&completed),
        },
        registry.clone(),
    );
    let admission = runtime
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
        .unwrap();
    // Publish the committed handle before yielding to its owner task.
    handle
        .set(
            runtime
                .commit_session(admission, ip_datagram(b"request"), Instant::now())
                .unwrap(),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), completed.notified())
        .await
        .unwrap();
    assert_eq!(runtime.shutdown(Duration::ZERO).await, 0);
    assert_eq!(registry.snapshot(), baseline);
    assert!(
        observed_sends.load(Ordering::SeqCst) <= UDP_SESSION_QUEUE_DEPTH,
        "ready response was postponed through {} requests",
        observed_sends.load(Ordering::SeqCst)
    );
}

#[tokio::test(start_paused = true)]
async fn one_coalesced_notification_drains_a_request_burst_without_any_response() {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let (socket, sends) = socket_fixture(Duration::ZERO, []);
    let (mut runtime, _) = recording_runtime(
        &registry,
        empty_resolver(),
        socket,
        Duration::from_secs(1),
        /* block */ false,
    );
    let admission = runtime
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
        .unwrap();
    let handle = runtime
        .commit_session(admission, ip_datagram(b"request"), Instant::now())
        .unwrap();
    for _ in 1..UDP_SESSION_QUEUE_DEPTH {
        runtime
            .reserve_datagram(handle, 7)
            .unwrap()
            .commit(ip_datagram(b"request"), Instant::now())
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while sends.lock().unwrap().len() != UDP_SESSION_QUEUE_DEPTH {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("coalesced notifications must not strand queued requests");
    assert_eq!(runtime.shutdown(Duration::from_secs(1)).await, 0);
    assert_eq!(registry.snapshot(), baseline);
}

#[tokio::test(start_paused = true)]
async fn continuously_ready_io_yields_so_another_task_can_cancel_the_session() {
    const RESPONSE_GUARD: usize = 1024;
    struct ReadyResponses {
        count: Arc<AtomicUsize>,
        started: Arc<Notify>,
    }

    impl DirectUdpPacketHandler for ReadyResponses {
        type Error = ();

        async fn handle_target_response(
            &self,
            _: UdpSessionHandle,
            _: AccountedDatagram,
        ) -> Result<(), Self::Error> {
            let count = self.count.fetch_add(1, Ordering::SeqCst) + 1;
            if count == 1 {
                self.started.notify_one();
            }
            // Finite guard keeps a noncooperative implementation from hanging
            // the test. The cancellation task must run before reaching it.
            if count == RESPONSE_GUARD {
                Err(())
            } else {
                Ok(())
            }
        }
    }

    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let manager = UdpSessionManager::new(limits(1), registry.clone());
    let handle_slot = Arc::new(OnceLock::new());
    let count = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let mut runtime = DirectUdpRuntime::with_shared_adapters(
        manager.clone(),
        Duration::from_secs(1),
        empty_resolver(),
        SocketFactory {
            manager: manager.clone(),
            handle: Arc::clone(&handle_slot),
            sends: Arc::new(AtomicUsize::new(0)),
        },
        ReadyResponses {
            count: Arc::clone(&count),
            started: Arc::clone(&started),
        },
        registry.clone(),
    );
    let admission = runtime
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
        .unwrap();
    let handle = runtime
        .commit_session(admission, ip_datagram(b"request"), Instant::now())
        .unwrap();
    handle_slot.set(handle).unwrap();
    started.notified().await;
    let observed = count.load(Ordering::SeqCst);
    manager.remove(handle);
    assert_eq!(runtime.shutdown(Duration::from_secs(1)).await, 0);
    assert_eq!(registry.snapshot(), baseline);
    assert!(
        observed < RESPONSE_GUARD,
        "I/O monopolized its runtime through {observed} responses"
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_before_first_poll_drains_every_admitted_request() {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let (socket, sends) = socket_fixture(Duration::ZERO, []);
    let (mut runtime, _) = recording_runtime(
        &registry,
        empty_resolver(),
        socket,
        Duration::from_secs(1),
        /* block */ false,
    );
    let admission = runtime
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
        .unwrap();
    let handle = runtime
        .commit_session(admission, ip_datagram(b"request"), Instant::now())
        .unwrap();
    for _ in 1..UDP_SESSION_QUEUE_DEPTH {
        runtime
            .reserve_datagram(handle, 7)
            .unwrap()
            .commit(ip_datagram(b"request"), Instant::now())
            .unwrap();
    }
    assert_eq!(runtime.shutdown(Duration::from_secs(1)).await, 0);
    assert_eq!(registry.snapshot(), baseline);
    assert_eq!(
        *sends.lock().unwrap(),
        vec![selection_destination(); UDP_SESSION_QUEUE_DEPTH]
    );
}
