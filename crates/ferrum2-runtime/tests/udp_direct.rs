#![allow(dead_code, unused_imports)]

use std::collections::VecDeque;
use std::future::pending;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_core::{Datagram, TargetAddr};
use ferrum2_net::UdpResolver;
use ferrum2_runtime::{
    AccountedDatagram, DEFAULT_UDP_IDLE_TIMEOUT, DEFAULT_UDP_MAX_BUFFERED_BYTES,
    DEFAULT_UDP_MAX_SESSIONS, DirectUdpPacketHandler, DirectUdpRuntime, DirectUdpSocket,
    DirectUdpSocketFactory, MAX_UDP_IDLE_TIMEOUT, MAX_UDP_MAX_BUFFERED_BYTES, MAX_UDP_MAX_SESSIONS,
    MAX_UDP_WIRE_DATAGRAM_BYTES, MIN_UDP_IDLE_TIMEOUT, MIN_UDP_MAX_BUFFERED_BYTES,
    MIN_UDP_MAX_SESSIONS, OwnerRegistry, PreparedProcessRoot, ProcessCancellation, ProcessFuture,
    ProcessRoot, ProcessSupervisor, UDP_SESSION_QUEUE_DEPTH, UdpCommitError, UdpDirection,
    UdpLimitError, UdpRuntimeError, UdpRuntimeLimits, UdpSessionHandle, UdpSessionManager,
};
use tokio::sync::Notify;
use tokio::time::Instant;

mod udp_support;
use udp_support::*;

#[tokio::test]
async fn direct_socket_factory_receives_explicit_context_and_first_concrete_destination() {
    let registry = OwnerRegistry::new();
    let (socket, _) = socket_fixture(Duration::ZERO, []);
    let inner = scripted_factory(socket);
    let selections = Arc::clone(&inner.selections);
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let factory = ContextRecordingFactory {
        inner,
        contexts: Arc::clone(&contexts),
    };
    let mut runtime = DirectUdpRuntime::with_adapters(
        limits(1),
        Duration::from_secs(1),
        empty_resolver(),
        factory,
        RecordingHandler::default(),
        registry.clone(),
    );
    let selected = SocketAddr::from(([198, 51, 100, 44], 53));

    let admission = runtime
        .reserve_session(Instant::now(), 7, 41, selected)
        .await
        .expect("target-aware socket admission");

    assert_eq!(
        selections
            .lock()
            .expect("selection destinations")
            .as_slice(),
        &[selected]
    );
    assert_eq!(contexts.lock().expect("open contexts").as_slice(), &[41]);
    drop(admission);
    runtime.shutdown(Duration::ZERO).await;
    wait_for_zero_udp_owners(&registry).await;
}

#[tokio::test]
async fn initial_candidates_select_socket_and_send_first_domain_datagram_without_reresolving() {
    let registry = OwnerRegistry::new();
    let first = SocketAddr::from(([192, 0, 2, 41], 53));
    let second = SocketAddr::from(([192, 0, 2, 42], 53));
    let later = SocketAddr::from(([192, 0, 2, 43], 53));
    let resolver_calls = Arc::new(AtomicUsize::new(0));
    let resolver = ScriptedResolver {
        delay: Duration::ZERO,
        candidates: vec![later],
        calls: Arc::clone(&resolver_calls),
    };
    let (socket, sends) = socket_fixture(Duration::ZERO, [true, false, false]);
    let factory = scripted_factory(socket);
    let selections = Arc::clone(&factory.selections);
    let mut runtime = DirectUdpRuntime::with_adapters(
        limits(1),
        Duration::from_secs(1),
        resolver,
        factory,
        RecordingHandler::default(),
        registry.clone(),
    );
    let now = Instant::now();

    let admission = runtime
        .reserve_session_with_initial_candidates(now, 7, (), vec![first, second])
        .await
        .expect("pre-resolved direct session");
    let handle = runtime
        .commit_session(admission, domain_datagram(b"first__"), now)
        .expect("commit first domain datagram");
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if sends.lock().expect("send lock").len() >= 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("initial candidate sends");

    assert_eq!(
        selections.lock().expect("selection lock").as_slice(),
        &[first]
    );
    assert_eq!(
        sends.lock().expect("send lock").as_slice(),
        &[first, second]
    );
    assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);

    runtime
        .reserve_datagram(handle, 7)
        .expect("later datagram capacity")
        .commit(domain_datagram(b"second_"), Instant::now())
        .expect("commit later domain datagram");
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if sends.lock().expect("send lock").len() >= 3 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("later resolved send");

    assert_eq!(
        sends.lock().expect("send lock").as_slice(),
        &[first, second, later]
    );
    assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);

    assert!(runtime.remove_session(handle));
    wait_for_zero_udp_owners(&registry).await;
    runtime.shutdown(Duration::ZERO).await;
}

#[tokio::test]
async fn shared_manager_couples_session_byte_and_direct_owner_capacity() {
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(limits(1), registry.clone());
    let (first_socket, sends) = socket_fixture(Duration::ZERO, []);
    let send_completed = Arc::clone(&first_socket.send_completed);
    let (second_socket, _) = socket_fixture(Duration::ZERO, []);
    let (empty_socket, _) = socket_fixture(Duration::ZERO, []);
    let mut first = shared_runtime(manager.clone(), &registry, first_socket);
    let mut second = shared_runtime(manager.clone(), &registry, second_socket);
    let empty = shared_runtime(manager, &registry, empty_socket);

    let admission = first
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
        .expect("first shared admission");
    let handle = first
        .commit_session(admission, ip_datagram(b"request"), Instant::now())
        .expect("first shared commit");
    empty.shutdown(Duration::ZERO).await;
    send_completed.notified().await;
    assert_eq!(sends.lock().expect("send lock").len(), 1);
    assert!(first.remove_session(handle));
    assert_eq!(
        second
            .reserve_session(Instant::now(), 7, (), selection_destination())
            .await
            .unwrap_err(),
        UdpRuntimeError::SessionLimit,
        "removed generation cannot outlive the inseparable direct-owner bound"
    );
    wait_for_zero_udp_owners(&registry).await;
    drop(
        second
            .reserve_session(Instant::now(), 7, (), selection_destination())
            .await
            .expect("shared owner slot returned"),
    );
    first.shutdown(Duration::ZERO).await;
    second.shutdown(Duration::ZERO).await;
    wait_for_zero_udp_owners(&registry).await;
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
    let (mut runtime, _) =
        recording_runtime(&registry, resolver, socket, Duration::from_secs(7), false);
    let rejected = runtime
        .reserve_session(Instant::now(), 7, (), selection_destination())
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
        .reserve_session(Instant::now(), 7, (), selection_destination())
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
async fn association_resolves_every_datagram_reuses_hint_and_never_falls_back() {
    let registry = OwnerRegistry::new();
    let resolver_calls = Arc::new(AtomicUsize::new(0));
    let first = SocketAddr::from(([192, 0, 2, 1], 53));
    let second = SocketAddr::from(([192, 0, 2, 2], 53));
    let resolver = FailingOnCallResolver {
        candidates: vec![first, second],
        fail_on_call: 3,
        calls: Arc::clone(&resolver_calls),
    };
    let (socket, sends) = socket_fixture(Duration::ZERO, [true, false, false]);
    let mut runtime = DirectUdpRuntime::with_adapters(
        limits(1),
        Duration::from_secs(10),
        resolver,
        scripted_factory(socket),
        RecordingHandler::default(),
        registry.clone(),
    );
    let now = Instant::now();
    let admission = runtime
        .reserve_session(now, 7, (), selection_destination())
        .await
        .expect("reserve direct session");
    let handle = runtime
        .commit_session(admission, domain_datagram(b"first__"), now)
        .expect("commit first datagram");
    for _ in 0..200 {
        if sends.lock().expect("send lock").len() >= 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(&sends.lock().expect("send lock")[..], &[first, second]);
    assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);

    runtime
        .reserve_datagram(handle, 7)
        .expect("second capacity")
        .commit(domain_datagram(b"second_"), Instant::now())
        .expect("commit second datagram");
    for _ in 0..200 {
        if sends.lock().expect("send lock").len() >= 3 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        &sends.lock().expect("send lock")[..],
        &[first, second, second]
    );
    assert_eq!(resolver_calls.load(Ordering::SeqCst), 2);

    runtime
        .reserve_datagram(handle, 7)
        .expect("failure capacity")
        .commit(domain_datagram(b"failure"), Instant::now())
        .expect("commit resolver failure datagram");
    wait_for_zero_udp_owners(&registry).await;
    assert_eq!(resolver_calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        &sends.lock().expect("send lock")[..],
        &[first, second, second],
        "configured resolver failure must not trigger another resolver or socket fallback"
    );

    runtime.shutdown(Duration::ZERO).await;
    wait_for_zero_udp_owners(&registry).await;
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
        let (mut runtime, _) =
            recording_runtime(&registry, resolver, socket, Duration::from_secs(10), false);
        let admission = runtime
            .reserve_session(Instant::now(), 7, (), selection_destination())
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
    let (mut runtime, _) = recording_runtime(
        &registry,
        empty_resolver(),
        socket,
        Duration::from_secs(10),
        false,
    );
    let admission = runtime
        .reserve_session(Instant::now(), 7, (), selection_destination())
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
    let (mut runtime, _) = recording_runtime(
        &registry,
        empty_resolver(),
        socket,
        Duration::from_secs(10),
        false,
    );
    let mut activity = Instant::now();
    let initial = runtime
        .reserve_session(activity, 7, (), selection_destination())
        .await
        .expect("initial direct owner");
    runtime
        .commit_session(initial, ip_datagram(b"request"), activity)
        .expect("commit initial owner");
    tokio::task::yield_now().await;

    for _ in 0..32 {
        activity += MIN_UDP_IDLE_TIMEOUT;
        assert_eq!(
            runtime
                .reserve_session(activity, 7, (), selection_destination())
                .await
                .unwrap_err(),
            UdpRuntimeError::SessionLimit
        );
        let retiring = registry.snapshot();
        assert!(retiring.udp_sockets <= 1);
        assert!(retiring.udp_tasks <= 1);
        wait_for_zero_udp_owners(&registry).await;

        let replacement = runtime
            .reserve_session(activity, 7, (), selection_destination())
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

#[tokio::test]
async fn direct_response_awaits_handler_without_creating_a_queue_owner() {
    let registry = OwnerRegistry::new();
    let (socket, _) = socket_fixture(Duration::ZERO, []);
    socket
        .responses
        .lock()
        .expect("response lock")
        .push_back((b"reply".to_vec(), SocketAddr::from(([127, 0, 0, 1], 9000))));
    socket.response_ready.notify_one();
    let (mut runtime, entered) = recording_runtime(
        &registry,
        empty_resolver(),
        socket,
        Duration::from_secs(10),
        true,
    );
    let admission = runtime
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
        .expect("reserve direct session");
    runtime
        .commit_session(admission, ip_datagram(b"request"), Instant::now())
        .expect("commit session");

    entered.notified().await;
    let handling = registry.snapshot();
    assert_eq!(handling.udp_sessions, 1);
    assert_eq!(handling.udp_sockets, 1);
    assert_eq!(handling.udp_tasks, 1);
    assert_eq!(handling.udp_queued_datagrams, 0);
    assert_eq!(handling.udp_buffered_bytes, MAX_UDP_WIRE_DATAGRAM_BYTES);
    assert_eq!(handling.udp_scratch_buffers, 0);

    assert_eq!(runtime.shutdown(Duration::ZERO).await, 1);
    wait_for_zero_udp_owners(&registry).await;
}

#[tokio::test]
async fn direct_response_preserves_to_client_queue_backpressure() {
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(limits(1), registry.clone());
    let (socket, _) = socket_fixture(Duration::ZERO, []);
    let send_completed = Arc::clone(&socket.send_completed);
    let responses = Arc::clone(&socket.responses);
    let response_ready = Arc::clone(&socket.response_ready);
    let handled = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = DirectUdpRuntime::with_shared_adapters(
        manager.clone(),
        Duration::from_secs(10),
        empty_resolver(),
        scripted_factory(socket),
        RecordingHandler {
            responses: Arc::clone(&handled),
            entered: Arc::new(Notify::new()),
            block: false,
        },
        registry.clone(),
    );
    let now = Instant::now();
    let admission = runtime
        .reserve_session(now, 7, (), selection_destination())
        .await
        .expect("reserve direct session");
    let handle = runtime
        .commit_session(admission, ip_datagram(b"request"), now)
        .expect("commit session");
    send_completed.notified().await;

    for _ in 0..UDP_SESSION_QUEUE_DEPTH {
        manager
            .reserve_datagram(handle, UdpDirection::ToClient, 4)
            .expect("response queue capacity")
            .commit(ip_datagram_with_capacity(b"held", 4), Instant::now())
            .expect("fill response queue");
    }
    assert_eq!(
        registry.snapshot().udp_queued_datagrams,
        UDP_SESSION_QUEUE_DEPTH
    );
    responses
        .lock()
        .expect("response lock")
        .push_back((b"reply".to_vec(), SocketAddr::from(([127, 0, 0, 1], 9000))));
    response_ready.notify_one();

    wait_for_zero_udp_owners(&registry).await;
    assert!(handled.lock().expect("handler lock").is_empty());
    runtime.shutdown(Duration::ZERO).await;
    wait_for_zero_udp_owners(&registry).await;
}

#[tokio::test(start_paused = true)]
async fn successful_direct_response_refreshes_activity_after_handler_completion() {
    let registry = OwnerRegistry::new();
    let (socket, _) = socket_fixture(Duration::ZERO, []);
    let responses = Arc::clone(&socket.responses);
    let response_ready = Arc::clone(&socket.response_ready);
    let (mut runtime, entered) = recording_runtime(
        &registry,
        empty_resolver(),
        socket,
        Duration::from_secs(10),
        false,
    );
    let started = Instant::now();
    let admission = runtime
        .reserve_session(started, 7, (), selection_destination())
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
    tokio::task::yield_now().await;

    tokio::time::advance(Duration::from_secs(30)).await;
    tokio::task::yield_now().await;
    assert_eq!(runtime.sessions().session_count(), 1);

    tokio::time::advance(Duration::from_secs(30)).await;
    wait_for_zero_udp_owners(&registry).await;
    runtime.shutdown(Duration::ZERO).await;
}

#[tokio::test(start_paused = true)]
async fn handler_failure_does_not_refresh_activity_before_final_generation_recheck() {
    let registry = OwnerRegistry::new();
    let (socket, _) = socket_fixture(Duration::ZERO, []);
    let responses = Arc::clone(&socket.responses);
    let response_ready = Arc::clone(&socket.response_ready);
    let factory = scripted_factory(socket);
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let handler = FailingGateHandler {
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    };
    let mut runtime = DirectUdpRuntime::with_adapters(
        limits(1),
        Duration::from_secs(10),
        empty_resolver(),
        factory,
        handler,
        registry.clone(),
    );
    let started = Instant::now();
    let admission = runtime
        .reserve_session(started, 7, (), selection_destination())
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
