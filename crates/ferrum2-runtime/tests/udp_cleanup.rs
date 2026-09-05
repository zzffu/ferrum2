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

#[tokio::test(start_paused = true)]
async fn panicking_response_handler_retires_session_and_restores_admission() {
    struct PanickingHandler;

    impl DirectUdpPacketHandler for PanickingHandler {
        type Error = ();

        async fn handle_target_response(
            &self,
            _session: UdpSessionHandle,
            _response: AccountedDatagram,
        ) -> Result<(), Self::Error> {
            panic!("injected response handler failure");
        }
    }

    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let (socket, _) = socket_fixture(Duration::ZERO, []);
    socket
        .responses
        .lock()
        .unwrap()
        .push_back((b"reply".to_vec(), SocketAddr::from(([127, 0, 0, 1], 9000))));
    let mut runtime = DirectUdpRuntime::with_adapters(
        limits(1),
        Duration::from_secs(10),
        empty_resolver(),
        scripted_factory(socket),
        PanickingHandler,
        registry.clone(),
    );
    let mut removals = runtime.sessions().subscribe_removals();
    let admission = runtime
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
        .unwrap();
    let handle = runtime
        .commit_session(admission, ip_datagram(b"request"), Instant::now())
        .unwrap();
    wait_for_zero_udp_owners(&registry).await;
    assert_eq!(removals.try_recv(), Ok(handle));
    assert_eq!(registry.snapshot(), baseline);

    let next = runtime
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
        .expect("panic must not strand the only session slot");
    drop(next);
    assert_eq!(runtime.shutdown(Duration::ZERO).await, 0);
    assert_eq!(registry.snapshot(), baseline);
}

#[tokio::test(start_paused = true)]
async fn dropping_one_runtime_retires_unpolled_session_without_stopping_shared_capacity() {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let manager = UdpSessionManager::new(limits(1), registry.clone());
    let (socket, _) = socket_fixture(Duration::ZERO, []);
    let mut dropped = shared_runtime(manager.clone(), &registry, socket.clone());
    let mut survivor = shared_runtime(manager, &registry, socket);
    let admission = dropped
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
        .unwrap();
    dropped
        .commit_session(admission, ip_datagram(b"request"), Instant::now())
        .unwrap();
    // No yield: abort before the spawned task has ever been polled.
    drop(dropped);
    wait_for_zero_udp_owners(&registry).await;
    assert_eq!(registry.snapshot(), baseline);
    let admission = survivor
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
        .expect("another runtime sharing capacity must remain usable");
    drop(admission);
    assert_eq!(survivor.shutdown(Duration::ZERO).await, 0);
    assert_eq!(registry.snapshot(), baseline);
}

#[tokio::test(start_paused = true)]
async fn graceful_shutdown_drains_admitted_queue_before_reaping() {
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

    runtime.shutdown(Duration::from_secs(5)).await;
    assert_eq!(sends.lock().expect("send lock").len(), 1);
    assert_eq!(registry.snapshot().udp_forced_shutdowns, 0);
    wait_for_zero_udp_owners(&registry).await;
}

#[tokio::test(start_paused = true)]
async fn process_deadline_forces_response_handler_and_reaps_every_udp_owner() {
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
    assert_eq!(registry.snapshot().udp_sessions, 1);
    assert_eq!(registry.snapshot().udp_sockets, 1);
    assert_eq!(registry.snapshot().udp_tasks, 1);

    let supervisor = ProcessSupervisor::new(
        vec![ProcessRoot::new(move || async move {
            Ok(UdpProcessRoot(runtime))
        })],
        Duration::ZERO,
        registry.clone(),
    )
    .expect("one UDP process root");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let process = tokio::spawn(supervisor.run_until(async move {
        let _ = shutdown_rx.await;
    }));
    for _ in 0..100 {
        if registry.snapshot().active_process_roots == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(registry.snapshot().active_process_roots, 1);
    shutdown_tx.send(()).expect("request process shutdown");
    let report = process.await.expect("process supervisor task");

    assert_eq!(report.forced_roots(), 1);
    assert_eq!(registry.snapshot().udp_forced_shutdowns, 1);
    wait_for_zero_udp_owners(&registry).await;
}
