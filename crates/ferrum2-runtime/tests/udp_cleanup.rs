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
    let completion = runtime.next_completion().await.expect("joined panic");
    assert_eq!(completion.session(), handle);
    assert!(matches!(
        completion.terminal(),
        ferrum2_runtime::DirectUdpTerminal::Panicked
    ));
    assert!(completion.unexpected_failure());
    wait_for_zero_udp_owners(&registry).await;
    assert_eq!(removals.try_recv(), Ok(handle));
    assert_eq!(registry.snapshot(), baseline);

    let next = runtime
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
        .expect("panic must not strand the only session slot");
    drop(next);
    let report = runtime.shutdown(Duration::ZERO).await;
    assert_eq!(report.forced(), 0);
    assert!(report.cleanup_failed());
    assert_eq!(report.terminals().panicked, 1);
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
    // External custody survives dropping the run owner before its first poll.
    let mut cleanup = dropped.take_cleanup().expect("external custody");
    drop(dropped);
    assert_eq!(registry.snapshot().udp_tasks, 1);
    let report = cleanup.shutdown(Duration::ZERO).await;
    assert_eq!(report.forced(), 1);
    assert!(!report.cleanup_failed());
    assert!(matches!(
        report.completions()[0].terminal(),
        ferrum2_runtime::DirectUdpTerminal::Aborted
    ));
    wait_for_zero_udp_owners(&registry).await;
    let mut baseline = baseline;
    baseline.udp_forced_shutdowns = 1;
    assert_eq!(registry.snapshot(), baseline);
    let admission = survivor
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
        .expect("another runtime sharing capacity must remain usable");
    drop(admission);
    assert_eq!(survivor.shutdown(Duration::ZERO).await.forced(), 0);
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

    let report = runtime.shutdown(Duration::from_secs(5)).await;
    assert_eq!(report.terminals().completed, 1);
    assert!(!report.cleanup_failed());
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

#[tokio::test(start_paused = true)]
async fn cancelled_shutdown_retains_joined_terminals_and_original_deadline() {
    let registry = OwnerRegistry::new();
    let (socket, _) = socket_fixture(Duration::ZERO, []);
    socket
        .responses
        .lock()
        .unwrap()
        .push_back((b"reply".to_vec(), SocketAddr::from(([127, 0, 0, 1], 9000))));
    let entered = Arc::new(Notify::new());
    let mut runtime = DirectUdpRuntime::with_adapters(
        limits(2),
        Duration::from_secs(10),
        empty_resolver(),
        scripted_factory(socket),
        RecordingHandler {
            entered: Arc::clone(&entered),
            responses: Arc::new(Mutex::new(Vec::new())),
            block: true,
        },
        registry.clone(),
    );
    let first = runtime
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
        .unwrap();
    runtime
        .commit_session(first, ip_datagram(b"request"), Instant::now())
        .unwrap();
    entered.notified().await;
    let second = runtime
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
        .unwrap();
    let second_handle = runtime
        .commit_session(second, domain_datagram(b"request"), Instant::now())
        .unwrap();
    let started = Instant::now();
    let mut stopping = Box::pin(runtime.shutdown(Duration::from_secs(5)));
    tokio::select! {
        biased;
        _ = &mut stopping => panic!("blocked handler cannot finish graceful shutdown"),
        () = async {
            while registry.snapshot().udp_tasks != 1 { tokio::task::yield_now().await; }
        } => {}
    }
    drop(stopping);
    assert_eq!(registry.snapshot().udp_tasks, 1);
    assert_eq!(
        runtime
            .reserve_session(Instant::now(), 7, (), selection_destination())
            .await
            .unwrap_err(),
        UdpRuntimeError::Cancelled
    );
    let report = runtime.shutdown(Duration::from_secs(600)).await;
    assert_eq!(
        Instant::now().duration_since(started),
        Duration::from_secs(5)
    );
    assert_eq!(report.forced(), 1);
    assert!(!report.cleanup_failed());
    assert_eq!(report.terminals().resolve_failed, 1);
    assert_eq!(report.terminals().aborted, 1);
    assert_eq!(report.completions().len(), 2);
    assert_eq!(report.completions()[0].session(), second_handle);
    assert!(matches!(
        report.completions()[0].terminal(),
        ferrum2_runtime::DirectUdpTerminal::ResolveFailed
    ));
    wait_for_zero_udp_owners(&registry).await;
}

#[tokio::test(start_paused = true)]
async fn finished_unjoined_task_keeps_capacity_until_its_terminal_is_consumed() {
    let registry = OwnerRegistry::new();
    let (socket, _) = socket_fixture(Duration::ZERO, []);
    let (mut runtime, _) = recording_runtime(
        &registry,
        empty_resolver(),
        socket,
        Duration::from_secs(10),
        false,
    );
    let mut removed = runtime.sessions().subscribe_removals();
    let admission = runtime
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
        .unwrap();
    let handle = runtime
        .commit_session(admission, domain_datagram(b"request"), Instant::now())
        .unwrap();
    assert_eq!(removed.recv().await, Ok(handle));
    assert_eq!(registry.snapshot().udp_sockets, 0);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
    assert_eq!(registry.snapshot().udp_tasks, 1);
    assert_eq!(
        runtime
            .reserve_session(Instant::now(), 7, (), selection_destination())
            .await
            .unwrap_err(),
        UdpRuntimeError::SessionLimit
    );
    let completion = runtime.next_completion().await.expect("joined terminal");
    assert_eq!(completion.session(), handle);
    assert!(matches!(
        completion.terminal(),
        ferrum2_runtime::DirectUdpTerminal::ResolveFailed
    ));
    assert!(!completion.unexpected_failure());
    assert!(runtime.try_next_completion().is_none());
    drop(
        runtime
            .reserve_session(Instant::now(), 7, (), selection_destination())
            .await
            .expect("permit releases only at join"),
    );
    let report = runtime.shutdown(Duration::ZERO).await;
    assert_eq!(report.terminals().resolve_failed, 1);
    assert!(report.completions().is_empty());
    assert!(!report.cleanup_failed());
    wait_for_zero_udp_owners(&registry).await;
}

#[tokio::test(start_paused = true)]
async fn root_constructor_panic_still_joins_its_direct_children() {
    struct PanickingRoot(DirectUdpRuntime<ScriptedResolver, ScriptedFactory, RecordingHandler>);
    impl PreparedProcessRoot<()> for PanickingRoot {
        fn take_run_cleanup(&mut self) -> Option<ProcessFuture<Result<(), ()>>> {
            let mut cleanup = self.0.take_cleanup()?;
            Some(Box::pin(async move {
                let report = cleanup.shutdown(Duration::ZERO).await;
                if report.cleanup_failed() {
                    Err(())
                } else {
                    Ok(())
                }
            }))
        }
        fn activate(&mut self) -> Result<(), ()> {
            Ok(())
        }
        fn run(self: Box<Self>, _: ProcessCancellation) -> ProcessFuture<Result<(), ()>> {
            panic!("closed root constructor fault")
        }
        fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), ()>> {
            Box::pin(async { Ok(()) })
        }
    }
    let registry = OwnerRegistry::new();
    let root_registry = registry.clone();
    let supervisor = ProcessSupervisor::new(
        vec![ProcessRoot::new(move || async move {
            let (socket, _) = socket_fixture(Duration::ZERO, []);
            let (mut runtime, _) = recording_runtime(
                &root_registry,
                empty_resolver(),
                socket,
                Duration::from_secs(10),
                false,
            );
            let admission = runtime
                .reserve_session(Instant::now(), 7, (), selection_destination())
                .await
                .unwrap();
            runtime
                .commit_session(admission, ip_datagram(b"request"), Instant::now())
                .unwrap();
            Ok(PanickingRoot(runtime))
        })],
        Duration::ZERO,
        registry.clone(),
    )
    .unwrap();
    let report = supervisor.run_until(pending()).await;
    assert!(matches!(
        report.cause(),
        ferrum2_runtime::ProcessCause::ActivationPanicked { .. }
    ));
    assert!(report.cleanup_failure().is_none());
    wait_for_zero_udp_owners(&registry).await;
}

#[tokio::test]
async fn receive_failure_is_joined_closed_data_without_source_error_text() {
    struct ReceiveFailure;
    impl DirectUdpSocket for ReceiveFailure {
        async fn send_to(&self, payload: &[u8], _: SocketAddr) -> io::Result<usize> {
            Ok(payload.len())
        }
        async fn readable(&self) -> io::Result<()> {
            Err(io::Error::other("sensitive injected receive source"))
        }
        async fn recv_buf_from(&self, _: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
            unreachable!("readiness fails first")
        }
        fn try_recv_buf_from(&self, _: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
            unreachable!("readiness fails first")
        }
    }
    struct Factory;
    impl DirectUdpSocketFactory for Factory {
        type Socket = ReceiveFailure;
        type OpenContext = ();
        async fn open(&self, _: (), _: SocketAddr) -> io::Result<Self::Socket> {
            Ok(ReceiveFailure)
        }
    }
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let mut runtime = DirectUdpRuntime::with_adapters(
        limits(1),
        Duration::from_secs(1),
        empty_resolver(),
        Factory,
        RecordingHandler::default(),
        registry.clone(),
    );
    let admission = runtime
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
        .unwrap();
    let handle = runtime
        .commit_session(admission, ip_datagram(b"request"), Instant::now())
        .unwrap();
    let completion = runtime.next_completion().await.unwrap();
    assert_eq!(completion.session(), handle);
    assert!(matches!(
        completion.terminal(),
        ferrum2_runtime::DirectUdpTerminal::ReceiveFailed
    ));
    assert!(!format!("{completion:?}").contains("sensitive injected receive source"));
    let report = runtime.shutdown(Duration::ZERO).await;
    assert_eq!(report.terminals().receive_failed, 1);
    assert!(!report.cleanup_failed());
    assert_eq!(registry.snapshot(), baseline);
}

#[tokio::test(start_paused = true)]
async fn unpolled_abort_drops_physical_socket_before_releasing_join_ownership() {
    struct Socket {
        registry: OwnerRegistry,
        dropped: Arc<Mutex<Option<(usize, usize)>>>,
    }
    impl Drop for Socket {
        fn drop(&mut self) {
            let snapshot = self.registry.snapshot();
            *self.dropped.lock().unwrap() = Some((snapshot.udp_sockets, snapshot.udp_tasks));
        }
    }
    impl DirectUdpSocket for Socket {
        async fn send_to(&self, _: &[u8], _: SocketAddr) -> io::Result<usize> {
            pending().await
        }
        async fn readable(&self) -> io::Result<()> {
            pending().await
        }
        async fn recv_buf_from(&self, _: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
            pending().await
        }
        fn try_recv_buf_from(&self, _: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }
    struct Factory {
        socket: Mutex<Option<Socket>>,
    }
    impl DirectUdpSocketFactory for Factory {
        type Socket = Socket;
        type OpenContext = ();
        async fn open(&self, _: (), _: SocketAddr) -> io::Result<Socket> {
            Ok(self.socket.lock().unwrap().take().unwrap())
        }
    }
    let registry = OwnerRegistry::new();
    let dropped = Arc::new(Mutex::new(None));
    let mut runtime = DirectUdpRuntime::with_adapters(
        limits(1),
        Duration::from_secs(1),
        empty_resolver(),
        Factory {
            socket: Mutex::new(Some(Socket {
                registry: registry.clone(),
                dropped: Arc::clone(&dropped),
            })),
        },
        RecordingHandler::default(),
        registry.clone(),
    );
    let admission = runtime
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
        .unwrap();
    runtime
        .commit_session(admission, ip_datagram(b"request"), Instant::now())
        .unwrap();
    let mut cleanup = runtime.take_cleanup().unwrap();
    drop(runtime);
    let report = cleanup.shutdown(Duration::ZERO).await;
    assert_eq!(report.forced(), 1);
    assert_eq!(*dropped.lock().unwrap(), Some((1, 1)));
    assert!(matches!(
        report.completions()[0].terminal(),
        ferrum2_runtime::DirectUdpTerminal::Aborted
    ));
    wait_for_zero_udp_owners(&registry).await;
}

#[tokio::test]
async fn rejected_protocol_commit_keeps_owner_capacity_until_socket_drop_finishes() {
    struct DropGate {
        entered: Notify,
        released: std::sync::Mutex<bool>,
        changed: std::sync::Condvar,
    }
    struct Socket(Option<Arc<DropGate>>);
    impl Drop for Socket {
        fn drop(&mut self) {
            if let Some(gate) = &self.0 {
                gate.entered.notify_one();
                let mut released = gate.released.lock().unwrap();
                while !*released {
                    released = gate.changed.wait(released).unwrap();
                }
            }
        }
    }
    impl DirectUdpSocket for Socket {
        async fn send_to(&self, _: &[u8], _: SocketAddr) -> io::Result<usize> {
            pending().await
        }
        async fn readable(&self) -> io::Result<()> {
            pending().await
        }
        async fn recv_buf_from(&self, _: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
            pending().await
        }
        fn try_recv_buf_from(&self, _: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }
    struct Factory(Option<Arc<DropGate>>);
    impl DirectUdpSocketFactory for Factory {
        type Socket = Socket;
        type OpenContext = ();
        async fn open(&self, _: (), _: SocketAddr) -> io::Result<Socket> {
            Ok(Socket(self.0.clone()))
        }
    }
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let manager = UdpSessionManager::new(limits(1), registry.clone());
    let gate = Arc::new(DropGate {
        entered: Notify::new(),
        released: std::sync::Mutex::new(false),
        changed: std::sync::Condvar::new(),
    });
    let mut first = DirectUdpRuntime::with_shared_adapters(
        manager.clone(),
        Duration::from_secs(1),
        empty_resolver(),
        Factory(Some(Arc::clone(&gate))),
        RecordingHandler::default(),
        registry.clone(),
    );
    let mut second = DirectUdpRuntime::with_shared_adapters(
        manager,
        Duration::from_secs(1),
        empty_resolver(),
        Factory(None),
        RecordingHandler::default(),
        registry.clone(),
    );
    let admission = first
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
        .unwrap();
    let rejecting = tokio::task::spawn_blocking(move || {
        let result =
            first.commit_session_with(admission, ip_datagram(b"request"), Instant::now(), || {
                Err(())
            });
        (first, result)
    });
    gate.entered.notified().await;
    let sockets_during_drop = registry.snapshot().udp_sockets;
    let replacement = match second
        .reserve_session(Instant::now(), 7, (), selection_destination())
        .await
    {
        Ok(admission) => {
            drop(admission);
            Ok(())
        }
        Err(error) => Err(error),
    };
    *gate.released.lock().unwrap() = true;
    gate.changed.notify_one();
    let (mut first, rejected) = rejecting.await.unwrap();
    assert!(matches!(rejected, Err(UdpCommitError::Protocol(()))));
    assert_eq!(sockets_during_drop, 1);
    assert_eq!(replacement, Err(UdpRuntimeError::SessionLimit));
    drop(
        second
            .reserve_session(Instant::now(), 7, (), selection_destination())
            .await
            .expect("socket closure releases permit"),
    );
    assert!(!first.shutdown(Duration::ZERO).await.cleanup_failed());
    assert!(!second.shutdown(Duration::ZERO).await.cleanup_failed());
    assert_eq!(registry.snapshot(), baseline);
}
