use std::collections::VecDeque;
use std::future::pending;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_core::{Datagram, TargetAddr};
use ferrum2_runtime::{
    AccountedDatagram, DEFAULT_UDP_IDLE_TIMEOUT, DEFAULT_UDP_MAX_BUFFERED_BYTES,
    DEFAULT_UDP_MAX_SESSIONS, DirectUdpPacketHandler, DirectUdpRuntime, DirectUdpSocket,
    DirectUdpSocketFactory, MAX_UDP_IDLE_TIMEOUT, MAX_UDP_MAX_BUFFERED_BYTES, MAX_UDP_MAX_SESSIONS,
    MIN_UDP_IDLE_TIMEOUT, MIN_UDP_MAX_BUFFERED_BYTES, MIN_UDP_MAX_SESSIONS, OwnerRegistry,
    UDP_SESSION_QUEUE_DEPTH, UdpCommitError, UdpDirection, UdpLimitError, UdpResolver,
    UdpRuntimeError, UdpRuntimeLimits, UdpSessionHandle, UdpSessionManager,
};
use tokio::sync::Notify;
use tokio::time::Instant;

fn limits(max_sessions: usize) -> UdpRuntimeLimits {
    UdpRuntimeLimits::new(
        max_sessions,
        MIN_UDP_MAX_BUFFERED_BYTES,
        MIN_UDP_IDLE_TIMEOUT,
    )
    .expect("valid test limits")
}

fn ip_datagram(payload: &'static [u8]) -> Datagram {
    Datagram::new(
        TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)).expect("non-zero target"),
        BytesMut::from(payload),
        payload.len(),
    )
    .expect("bounded datagram")
}

fn ip_datagram_with_capacity(payload: &[u8], capacity: usize) -> Datagram {
    let mut owned = BytesMut::with_capacity(capacity);
    owned.extend_from_slice(payload);
    Datagram::new(
        TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)).expect("non-zero target"),
        owned,
        capacity,
    )
    .expect("bounded datagram")
}

fn domain_datagram(payload: &'static [u8]) -> Datagram {
    Datagram::new(
        TargetAddr::domain("example.test", 53).expect("bounded target"),
        BytesMut::from(payload),
        payload.len(),
    )
    .expect("bounded datagram")
}

fn committed_session(
    manager: &UdpSessionManager,
    now: Instant,
    payload: &'static [u8],
) -> UdpSessionHandle {
    let session = manager.reserve_session(now).expect("session capacity");
    let reservation = session
        .reserve_datagram(UdpDirection::ToTarget, payload.len())
        .expect("datagram capacity");
    session
        .commit(reservation, ip_datagram(payload), now)
        .expect("commit session")
}

#[test]
fn validated_limits_freeze_defaults_and_inclusive_ranges() {
    let defaults = UdpRuntimeLimits::default();
    assert_eq!(defaults.max_sessions(), DEFAULT_UDP_MAX_SESSIONS);
    assert_eq!(
        defaults.max_buffered_bytes(),
        DEFAULT_UDP_MAX_BUFFERED_BYTES
    );
    assert_eq!(defaults.idle_timeout(), DEFAULT_UDP_IDLE_TIMEOUT);

    for (sessions, bytes, idle) in [
        (
            MIN_UDP_MAX_SESSIONS,
            MIN_UDP_MAX_BUFFERED_BYTES,
            MIN_UDP_IDLE_TIMEOUT,
        ),
        (
            MAX_UDP_MAX_SESSIONS,
            MAX_UDP_MAX_BUFFERED_BYTES,
            MAX_UDP_IDLE_TIMEOUT,
        ),
    ] {
        assert!(UdpRuntimeLimits::new(sessions, bytes, idle).is_ok());
    }
    assert_eq!(
        UdpRuntimeLimits::new(0, MIN_UDP_MAX_BUFFERED_BYTES, MIN_UDP_IDLE_TIMEOUT),
        Err(UdpLimitError::Sessions)
    );
    assert_eq!(
        UdpRuntimeLimits::new(
            MIN_UDP_MAX_SESSIONS,
            MIN_UDP_MAX_BUFFERED_BYTES - 1,
            MIN_UDP_IDLE_TIMEOUT
        ),
        Err(UdpLimitError::BufferedBytes)
    );
    assert_eq!(
        UdpRuntimeLimits::new(
            MIN_UDP_MAX_SESSIONS,
            MIN_UDP_MAX_BUFFERED_BYTES,
            MIN_UDP_IDLE_TIMEOUT - Duration::from_millis(1)
        ),
        Err(UdpLimitError::IdleTimeout)
    );
}

#[tokio::test(start_paused = true)]
async fn reservation_queue_and_generation_table_is_single_charge_and_fail_closed() {
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(limits(1), registry.clone());
    let now = Instant::now();
    let handle = committed_session(&manager, now, b"one");

    let rejected = manager
        .reserve_datagram(handle, UdpDirection::ToTarget, 16)
        .expect("capacity precedes protocol commit");
    let result = rejected.commit_with(ip_datagram_with_capacity(b"rejected", 16), now, || {
        assert_eq!(registry.snapshot().udp_buffered_bytes, 3 + 16);
        Err("protocol rejection")
    });
    assert!(matches!(result, Err(UdpCommitError::Protocol(_))));
    assert_eq!(registry.snapshot().udp_queued_datagrams, 1);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 3);

    for payload in [b"two".as_slice(), b"three", b"four"] {
        let reservation = manager
            .reserve_datagram(handle, UdpDirection::ToTarget, 16)
            .expect("queue capacity");
        let mut owned = BytesMut::with_capacity(16);
        owned.extend_from_slice(payload);
        reservation
            .commit(
                Datagram::new(
                    TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)).expect("target"),
                    owned,
                    16,
                )
                .expect("bounded"),
                now,
            )
            .expect("post-validation commit");
    }
    assert_eq!(
        manager
            .reserve_datagram(handle, UdpDirection::ToTarget, 16)
            .unwrap_err(),
        UdpRuntimeError::QueueFull
    );
    assert_eq!(
        registry.snapshot().udp_queued_datagrams,
        UDP_SESSION_QUEUE_DEPTH
    );
    assert_eq!(registry.snapshot().udp_buffered_bytes, 3 + 16 * 3);

    let moved = manager
        .pop(handle, UdpDirection::ToTarget)
        .expect("live generation")
        .expect("queued datagram");
    assert_eq!(moved.allocated_capacity(), 3);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 3 + 16 * 3);
    drop(moved);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 16 * 3);

    for _ in 0..UDP_SESSION_QUEUE_DEPTH {
        manager
            .reserve_datagram(handle, UdpDirection::ToClient, 4)
            .expect("independent response queue")
            .commit(ip_datagram_with_capacity(b"r", 4), now)
            .expect("response queue commit");
    }
    assert!(matches!(
        manager.reserve_datagram(handle, UdpDirection::ToClient, 4),
        Err(UdpRuntimeError::QueueFull)
    ));
    assert_eq!(registry.snapshot().udp_queued_datagrams, 7);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 16 * 3 + 4 * 4);

    assert!(manager.remove(handle));
    assert_eq!(registry.snapshot().udp_sessions, 0);
    assert_eq!(registry.snapshot().udp_queued_datagrams, 0);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 0);

    let recreated = committed_session(&manager, now, b"new");
    assert!(matches!(
        manager.reserve_datagram(handle, UdpDirection::ToTarget, 1),
        Err(UdpRuntimeError::Cancelled)
    ));
    manager.remove(recreated);
}

#[test]
fn global_byte_permits_use_exact_capacity_and_release_after_moves() {
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(limits(1), registry.clone());
    let budget = manager.buffer_budget();
    let mut reservations = Vec::new();
    for _ in 0..16 {
        reservations.push(budget.reserve(65_507).expect("within one MiB budget"));
    }
    assert_eq!(budget.reserved_bytes(), 1_048_112);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 1_048_112);
    assert!(matches!(
        budget.reserve(465),
        Err(UdpRuntimeError::BufferLimit)
    ));

    let moved = reservations.pop().expect("reservation");
    assert_eq!(budget.reserved_bytes(), 1_048_112);
    drop(moved);
    assert_eq!(budget.reserved_bytes(), 982_605);
    drop(reservations);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
}

#[tokio::test(start_paused = true)]
async fn full_admission_purges_only_the_deterministic_oldest_expired_session() {
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(limits(2), registry.clone());
    let start = Instant::now();
    let oldest = committed_session(&manager, start, b"oldest");
    tokio::time::advance(Duration::from_secs(1)).await;
    let newer = committed_session(&manager, Instant::now(), b"newer");

    tokio::time::advance(Duration::from_secs(58)).await;
    assert_eq!(
        manager.reserve_session(Instant::now()).unwrap_err(),
        UdpRuntimeError::SessionLimit
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    let replacement = manager
        .reserve_session(Instant::now())
        .expect("oldest is exactly idle-expired");
    assert!(matches!(
        manager.reserve_datagram(oldest, UdpDirection::ToTarget, 0),
        Err(UdpRuntimeError::Cancelled)
    ));
    assert!(
        manager
            .reserve_datagram(newer, UdpDirection::ToTarget, 0)
            .is_ok()
    );
    drop(replacement);
    manager.remove(newer);
    assert_eq!(registry.snapshot().udp_sessions, 0);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
}

#[test]
fn concurrent_capacity_one_admission_has_exactly_one_owner() {
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(limits(1), registry.clone());
    let barrier = Arc::new(Barrier::new(17));
    let now = Instant::now();
    let mut threads = Vec::new();
    for _ in 0..16 {
        let manager = manager.clone();
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            manager.reserve_session(now)
        }));
    }
    barrier.wait();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().expect("admission thread"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(UdpRuntimeError::SessionLimit)))
            .count(),
        15
    );
    drop(results);
    assert_eq!(registry.snapshot().udp_sessions, 0);
}

#[derive(Clone)]
struct ScriptedResolver {
    delay: Duration,
    candidates: Vec<SocketAddr>,
    calls: Arc<AtomicUsize>,
}

impl UdpResolver for ScriptedResolver {
    type Candidates = Vec<SocketAddr>;

    async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Self::Candidates> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        Ok(self.candidates.clone())
    }
}

#[derive(Clone)]
struct ScriptedSocket {
    send_delay: Duration,
    send_failures: Arc<Mutex<VecDeque<bool>>>,
    sends: Arc<Mutex<Vec<SocketAddr>>>,
    responses: SharedResponses,
    response_ready: Arc<Notify>,
}

type SharedResponses = Arc<Mutex<VecDeque<(Vec<u8>, SocketAddr)>>>;

impl DirectUdpSocket for ScriptedSocket {
    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.sends.lock().expect("send lock").push(target);
        tokio::time::sleep(self.send_delay).await;
        if self
            .send_failures
            .lock()
            .expect("failure lock")
            .pop_front()
            .unwrap_or(false)
        {
            Err(io::Error::other("scripted send failure"))
        } else {
            Ok(payload.len())
        }
    }

    async fn recv_from(&self, payload: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            if let Some((response, source)) =
                self.responses.lock().expect("response lock").pop_front()
            {
                payload[..response.len()].copy_from_slice(&response);
                return Ok((response.len(), source));
            }
            self.response_ready.notified().await;
        }
    }
}

#[derive(Clone)]
struct ScriptedFactory {
    socket: ScriptedSocket,
    opens: Arc<AtomicUsize>,
}

impl DirectUdpSocketFactory for ScriptedFactory {
    type Socket = ScriptedSocket;

    async fn open(&self) -> io::Result<Self::Socket> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        Ok(self.socket.clone())
    }
}

#[derive(Clone)]
struct RecordingHandler {
    responses: Arc<Mutex<Vec<Vec<u8>>>>,
    entered: Arc<Notify>,
    block: bool,
}

impl DirectUdpPacketHandler for RecordingHandler {
    type Error = ();

    async fn handle_target_response(
        &self,
        _session: UdpSessionHandle,
        response: AccountedDatagram,
    ) -> Result<(), Self::Error> {
        self.responses
            .lock()
            .expect("handler lock")
            .push(response.datagram().payload().to_vec());
        self.entered.notify_one();
        if self.block {
            pending::<()>().await;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct FailingGateHandler {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

impl DirectUdpPacketHandler for FailingGateHandler {
    type Error = ();

    async fn handle_target_response(
        &self,
        _session: UdpSessionHandle,
        _response: AccountedDatagram,
    ) -> Result<(), Self::Error> {
        self.entered.notify_one();
        self.release.notified().await;
        Err(())
    }
}

fn socket_fixture(
    delay: Duration,
    failures: impl IntoIterator<Item = bool>,
) -> (ScriptedSocket, Arc<Mutex<Vec<SocketAddr>>>) {
    let sends = Arc::new(Mutex::new(Vec::new()));
    (
        ScriptedSocket {
            send_delay: delay,
            send_failures: Arc::new(Mutex::new(failures.into_iter().collect())),
            sends: Arc::clone(&sends),
            responses: Arc::new(Mutex::new(VecDeque::new())),
            response_ready: Arc::new(Notify::new()),
        },
        sends,
    )
}

async fn wait_for_zero_udp_owners(registry: &OwnerRegistry) {
    for _ in 0..200 {
        let snapshot = registry.snapshot();
        if snapshot.udp_sessions == 0
            && snapshot.udp_sockets == 0
            && snapshot.udp_tasks == 0
            && snapshot.udp_queued_datagrams == 0
            && snapshot.udp_buffered_bytes == 0
            && snapshot.udp_scratch_buffers == 0
        {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("UDP owners did not return to baseline");
}

#[tokio::test(start_paused = true)]
async fn domain_resolution_and_candidate_sends_share_one_absolute_deadline() {
    let registry = OwnerRegistry::new();
    let candidates: Vec<_> = (1..=17)
        .map(|last| SocketAddr::from(([192, 0, 2, last], 53)))
        .collect();
    let resolver_calls = Arc::new(AtomicUsize::new(0));
    let resolver = ScriptedResolver {
        delay: Duration::from_secs(2),
        candidates,
        calls: Arc::clone(&resolver_calls),
    };
    let (socket, sends) = socket_fixture(Duration::from_secs(3), [true, true, true]);
    let factory = ScriptedFactory {
        socket,
        opens: Arc::new(AtomicUsize::new(0)),
    };
    let handler = RecordingHandler {
        responses: Arc::new(Mutex::new(Vec::new())),
        entered: Arc::new(Notify::new()),
        block: false,
    };
    let mut runtime = DirectUdpRuntime::with_adapters(
        limits(1),
        Duration::from_secs(7),
        resolver,
        factory,
        handler,
        registry.clone(),
    );
    let rejected = runtime
        .reserve_session(Instant::now(), 7)
        .await
        .expect("reserve before protocol commit");
    assert!(matches!(
        runtime.commit_session_with(rejected, ip_datagram(b"request"), Instant::now(), || {
            Err("replay race")
        }),
        Err(UdpCommitError::Protocol(_))
    ));
    assert_eq!(registry.snapshot().udp_sessions, 0);
    assert_eq!(registry.snapshot().udp_sockets, 0);
    assert_eq!(registry.snapshot().udp_tasks, 0);

    let admission = runtime
        .reserve_session(Instant::now(), 7)
        .await
        .expect("reserve direct session");
    runtime
        .commit_session(admission, domain_datagram(b"request"), Instant::now())
        .expect("commit after protocol validation");
    tokio::task::yield_now().await;

    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    wait_for_zero_udp_owners(&registry).await;

    assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
    assert_eq!(sends.lock().expect("send lock").len(), 2);
    runtime.shutdown(Duration::ZERO).await;
}

#[tokio::test(start_paused = true)]
async fn resolver_consumes_zero_one_sixteen_and_at_most_sixteen_candidates() {
    for (candidate_count, expected_sends) in [(0, 0), (1, 1), (16, 16), (17, 16)] {
        let registry = OwnerRegistry::new();
        let candidates: Vec<_> = (1..=candidate_count)
            .map(|last| SocketAddr::from(([192, 0, 2, last as u8], 53)))
            .collect();
        let resolver = ScriptedResolver {
            delay: Duration::ZERO,
            candidates,
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let (socket, sends) =
            socket_fixture(Duration::ZERO, std::iter::repeat_n(true, candidate_count));
        let factory = ScriptedFactory {
            socket,
            opens: Arc::new(AtomicUsize::new(0)),
        };
        let handler = RecordingHandler {
            responses: Arc::new(Mutex::new(Vec::new())),
            entered: Arc::new(Notify::new()),
            block: false,
        };
        let mut runtime = DirectUdpRuntime::with_adapters(
            limits(1),
            Duration::from_secs(10),
            resolver,
            factory,
            handler,
            registry.clone(),
        );
        let admission = runtime
            .reserve_session(Instant::now(), 7)
            .await
            .expect("reserve direct session");
        runtime
            .commit_session(admission, domain_datagram(b"request"), Instant::now())
            .expect("commit session");
        wait_for_zero_udp_owners(&registry).await;
        assert_eq!(sends.lock().expect("send lock").len(), expected_sends);
        runtime.shutdown(Duration::ZERO).await;
    }
}

#[tokio::test(start_paused = true)]
async fn direct_session_idle_expiry_reaps_socket_task_queue_scratch_and_bytes() {
    let registry = OwnerRegistry::new();
    let (socket, sends) = socket_fixture(Duration::ZERO, []);
    let factory = ScriptedFactory {
        socket,
        opens: Arc::new(AtomicUsize::new(0)),
    };
    let resolver = ScriptedResolver {
        delay: Duration::ZERO,
        candidates: Vec::new(),
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let handler = RecordingHandler {
        responses: Arc::new(Mutex::new(Vec::new())),
        entered: Arc::new(Notify::new()),
        block: false,
    };
    let mut runtime = DirectUdpRuntime::with_adapters(
        limits(1),
        Duration::from_secs(10),
        resolver,
        factory,
        handler,
        registry.clone(),
    );
    let admission = runtime
        .reserve_session(Instant::now(), 7)
        .await
        .expect("reserve direct session");
    runtime
        .commit_session(admission, ip_datagram(b"request"), Instant::now())
        .expect("commit session");
    tokio::task::yield_now().await;
    assert_eq!(sends.lock().expect("send lock").len(), 1);

    tokio::time::advance(MIN_UDP_IDLE_TIMEOUT).await;
    wait_for_zero_udp_owners(&registry).await;
    runtime.shutdown(Duration::ZERO).await;
}

#[tokio::test(start_paused = true)]
async fn expired_replacement_churn_never_exceeds_the_direct_owner_limit() {
    let registry = OwnerRegistry::new();
    let (socket, _) = socket_fixture(Duration::ZERO, []);
    let factory = ScriptedFactory {
        socket,
        opens: Arc::new(AtomicUsize::new(0)),
    };
    let resolver = ScriptedResolver {
        delay: Duration::ZERO,
        candidates: Vec::new(),
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let handler = RecordingHandler {
        responses: Arc::new(Mutex::new(Vec::new())),
        entered: Arc::new(Notify::new()),
        block: false,
    };
    let mut runtime = DirectUdpRuntime::with_adapters(
        limits(1),
        Duration::from_secs(10),
        resolver,
        factory,
        handler,
        registry.clone(),
    );
    let mut activity = Instant::now();
    let initial = runtime
        .reserve_session(activity, 7)
        .await
        .expect("initial direct owner");
    runtime
        .commit_session(initial, ip_datagram(b"request"), activity)
        .expect("commit initial owner");
    tokio::task::yield_now().await;

    for _ in 0..32 {
        activity += MIN_UDP_IDLE_TIMEOUT;
        assert_eq!(
            runtime.reserve_session(activity, 7).await.unwrap_err(),
            UdpRuntimeError::SessionLimit
        );
        let retiring = registry.snapshot();
        assert!(retiring.udp_sockets <= 1);
        assert!(retiring.udp_tasks <= 1);
        wait_for_zero_udp_owners(&registry).await;

        let replacement = runtime
            .reserve_session(activity, 7)
            .await
            .expect("retired owner releases fixed slot");
        runtime
            .commit_session(replacement, ip_datagram(b"request"), activity)
            .expect("commit bounded replacement");
        tokio::task::yield_now().await;
        let active = registry.snapshot();
        assert_eq!(active.udp_sockets, 1);
        assert_eq!(active.udp_tasks, 1);
    }

    runtime.shutdown(Duration::from_secs(1)).await;
    wait_for_zero_udp_owners(&registry).await;
}

#[tokio::test(start_paused = true)]
async fn handler_failure_does_not_refresh_activity_before_final_generation_recheck() {
    let registry = OwnerRegistry::new();
    let (socket, _) = socket_fixture(Duration::ZERO, []);
    let responses = Arc::clone(&socket.responses);
    let response_ready = Arc::clone(&socket.response_ready);
    let factory = ScriptedFactory {
        socket,
        opens: Arc::new(AtomicUsize::new(0)),
    };
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let handler = FailingGateHandler {
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    };
    let resolver = ScriptedResolver {
        delay: Duration::ZERO,
        candidates: Vec::new(),
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let mut runtime = DirectUdpRuntime::with_adapters(
        limits(1),
        Duration::from_secs(10),
        resolver,
        factory,
        handler,
        registry.clone(),
    );
    let started = Instant::now();
    let admission = runtime
        .reserve_session(started, 7)
        .await
        .expect("reserve direct session");
    runtime
        .commit_session(admission, ip_datagram(b"request"), started)
        .expect("commit session");
    tokio::task::yield_now().await;

    tokio::time::advance(Duration::from_secs(30)).await;
    responses
        .lock()
        .expect("response lock")
        .push_back((b"reply".to_vec(), SocketAddr::from(([127, 0, 0, 1], 9000))));
    response_ready.notify_one();
    entered.notified().await;
    tokio::time::advance(Duration::from_secs(30)).await;

    let replacement = runtime
        .sessions()
        .reserve_session(Instant::now())
        .expect("uncommitted handler response must not refresh activity");
    release.notify_one();
    for _ in 0..200 {
        let snapshot = registry.snapshot();
        if snapshot.udp_sockets == 0 && snapshot.udp_tasks == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(registry.snapshot().udp_sockets, 0);
    assert_eq!(registry.snapshot().udp_tasks, 0);
    drop(replacement);
    runtime.shutdown(Duration::ZERO).await;
    wait_for_zero_udp_owners(&registry).await;
}

#[tokio::test(start_paused = true)]
async fn graceful_shutdown_drains_admitted_queue_before_reaping() {
    let registry = OwnerRegistry::new();
    let (socket, sends) = socket_fixture(Duration::ZERO, []);
    let factory = ScriptedFactory {
        socket,
        opens: Arc::new(AtomicUsize::new(0)),
    };
    let resolver = ScriptedResolver {
        delay: Duration::ZERO,
        candidates: Vec::new(),
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let handler = RecordingHandler {
        responses: Arc::new(Mutex::new(Vec::new())),
        entered: Arc::new(Notify::new()),
        block: false,
    };
    let mut runtime = DirectUdpRuntime::with_adapters(
        limits(1),
        Duration::from_secs(10),
        resolver,
        factory,
        handler,
        registry.clone(),
    );
    let admission = runtime
        .reserve_session(Instant::now(), 7)
        .await
        .expect("reserve direct session");
    runtime
        .commit_session(admission, ip_datagram(b"request"), Instant::now())
        .expect("commit session");

    runtime.shutdown(Duration::from_secs(5)).await;
    assert_eq!(sends.lock().expect("send lock").len(), 1);
    assert_eq!(registry.snapshot().udp_forced_shutdowns, 0);
    wait_for_zero_udp_owners(&registry).await;
}

#[tokio::test(start_paused = true)]
async fn response_cancel_and_forced_shutdown_reap_every_owner() {
    let registry = OwnerRegistry::new();
    let (socket, _) = socket_fixture(Duration::ZERO, []);
    socket
        .responses
        .lock()
        .expect("response lock")
        .push_back((b"reply".to_vec(), SocketAddr::from(([127, 0, 0, 1], 9000))));
    socket.response_ready.notify_one();
    let factory = ScriptedFactory {
        socket,
        opens: Arc::new(AtomicUsize::new(0)),
    };
    let entered = Arc::new(Notify::new());
    let handler = RecordingHandler {
        responses: Arc::new(Mutex::new(Vec::new())),
        entered: Arc::clone(&entered),
        block: true,
    };
    let resolver = ScriptedResolver {
        delay: Duration::ZERO,
        candidates: Vec::new(),
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let mut runtime = DirectUdpRuntime::with_adapters(
        limits(1),
        Duration::from_secs(10),
        resolver,
        factory,
        handler,
        registry.clone(),
    );
    let admission = runtime
        .reserve_session(Instant::now(), 7)
        .await
        .expect("reserve direct session");
    runtime
        .commit_session(admission, ip_datagram(b"request"), Instant::now())
        .expect("commit session");
    entered.notified().await;
    assert_eq!(registry.snapshot().udp_sessions, 1);
    assert_eq!(registry.snapshot().udp_sockets, 1);
    assert_eq!(registry.snapshot().udp_tasks, 1);

    let shutdown = tokio::spawn(runtime.shutdown(Duration::from_secs(5)));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(5)).await;
    shutdown.await.expect("shutdown task");
    wait_for_zero_udp_owners(&registry).await;
    assert_eq!(registry.snapshot().udp_forced_shutdowns, 1);
}
