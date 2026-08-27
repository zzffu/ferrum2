use super::support::*;

#[test]
fn only_managed_damage_escalates_a_network_change_to_full_rebuild() {
    assert_eq!(
        classify_network_change(ferrum2_platform_windows::NetworkChangeOutcome::Unchanged),
        NetworkChangeTransition::Unchanged
    );
    assert_eq!(
        classify_network_change(ferrum2_platform_windows::NetworkChangeOutcome::Changed),
        NetworkChangeTransition::ResetNetwork {
            settle_underlay: false,
        }
    );
    for damage in [
        ferrum2_platform_windows::ManagedStateDamage::Adapter,
        ferrum2_platform_windows::ManagedStateDamage::Session,
        ferrum2_platform_windows::ManagedStateDamage::Address,
        ferrum2_platform_windows::ManagedStateDamage::Route,
        ferrum2_platform_windows::ManagedStateDamage::Dns,
        ferrum2_platform_windows::ManagedStateDamage::StrictRoute,
        ferrum2_platform_windows::ManagedStateDamage::OwnershipLedger,
    ] {
        assert_eq!(
            classify_network_change(
                ferrum2_platform_windows::NetworkChangeOutcome::ManagedStateDamaged(damage)
            ),
            NetworkChangeTransition::FullRebuild(map_managed_state_damage(damage)),
            "managed damage {damage:?}"
        );
    }
}

#[test]
fn transient_underlay_revalidation_failure_resets_without_rebuilding_managed_state() {
    let recoverable = ferrum2_platform_windows::Error::new(
        ferrum2_platform_windows::ErrorKind::RecoverableSession,
    );
    assert_eq!(
        classify_network_change_error(recoverable),
        NetworkChangeErrorDisposition::ResetNetwork {
            settle_underlay: true,
        }
    );
    for kind in [
        ferrum2_platform_windows::ErrorKind::InvalidInput,
        ferrum2_platform_windows::ErrorKind::UnrecoverableCorruption,
    ] {
        assert_eq!(
            classify_network_change_error(ferrum2_platform_windows::Error::new(kind)),
            NetworkChangeErrorDisposition::RuntimeFailed,
            "revalidation error {kind:?}"
        );
    }
    assert_eq!(
        classify_network_change_error(ferrum2_platform_windows::Error::new(
            ferrum2_platform_windows::ErrorKind::Cleanup,
        )),
        NetworkChangeErrorDisposition::CleanupFailed
    );
}

#[test]
fn reset_retries_transient_readback_errors_without_tearing_down_managed_state() {
    assert_eq!(
        classify_network_reset_health(Ok(ferrum2_platform_windows::ManagedTunHealth::Healthy)),
        NetworkResetHealthDisposition::Healthy
    );
    for damage in [
        ferrum2_platform_windows::ManagedStateDamage::Adapter,
        ferrum2_platform_windows::ManagedStateDamage::Session,
        ferrum2_platform_windows::ManagedStateDamage::Address,
        ferrum2_platform_windows::ManagedStateDamage::Route,
        ferrum2_platform_windows::ManagedStateDamage::Dns,
        ferrum2_platform_windows::ManagedStateDamage::StrictRoute,
        ferrum2_platform_windows::ManagedStateDamage::OwnershipLedger,
    ] {
        assert_eq!(
            classify_network_reset_health(Ok(ferrum2_platform_windows::ManagedTunHealth::Damaged(
                damage
            ))),
            NetworkResetHealthDisposition::FullRebuild(map_managed_state_damage(damage))
        );
    }
    let recoverable = ferrum2_platform_windows::Error::new(
        ferrum2_platform_windows::ErrorKind::RecoverableSession,
    );
    assert_eq!(
        classify_network_reset_health(Err(recoverable)),
        NetworkResetHealthDisposition::Retry
    );
    assert_eq!(
        classify_network_reset_refresh_error(recoverable),
        NetworkResetHealthDisposition::Retry
    );
    for kind in [
        ferrum2_platform_windows::ErrorKind::InvalidInput,
        ferrum2_platform_windows::ErrorKind::UnrecoverableCorruption,
    ] {
        let error = ferrum2_platform_windows::Error::new(kind);
        assert_eq!(
            classify_network_reset_health(Err(error)),
            NetworkResetHealthDisposition::RuntimeFailed,
            "health error {kind:?}"
        );
        assert_eq!(
            classify_network_reset_refresh_error(error),
            NetworkResetHealthDisposition::RuntimeFailed,
            "refresh error {kind:?}"
        );
    }
    let cleanup =
        ferrum2_platform_windows::Error::new(ferrum2_platform_windows::ErrorKind::Cleanup);
    assert_eq!(
        classify_network_reset_health(Err(cleanup)),
        NetworkResetHealthDisposition::CleanupFailed
    );
    assert_eq!(
        classify_network_reset_refresh_error(cleanup),
        NetworkResetHealthDisposition::CleanupFailed
    );
}

#[test]
fn wintun_error_kinds_have_exact_owner_dispositions() {
    for (kind, expected) in [
        (
            ferrum2_platform_windows::ErrorKind::RecoverableSession,
            AdapterErrorDisposition::FullRebuild(crate::TunNetworkFullRebuildReason::SessionDamage),
        ),
        (
            ferrum2_platform_windows::ErrorKind::InvalidInput,
            AdapterErrorDisposition::RuntimeFailed,
        ),
        (
            ferrum2_platform_windows::ErrorKind::UnrecoverableCorruption,
            AdapterErrorDisposition::RuntimeFailed,
        ),
        (
            ferrum2_platform_windows::ErrorKind::Cleanup,
            AdapterErrorDisposition::CleanupFailed,
        ),
    ] {
        assert_eq!(
            classify_adapter_error(ferrum2_platform_windows::Error::new(kind)),
            expected,
            "owner classification for {kind:?}"
        );
    }
}

#[tokio::test]
async fn owner_cancel_eof_panic_and_cleanup_conflict_are_reaped_before_join() {
    assert_eq!(
        map_owner_spawn::<(), _>(
            Err(std::io::Error::other("injected spawn failure")),
            "startup",
        ),
        Err("startup"),
        "owner spawn failure maps to startup"
    );

    for (cleanup_result, expected) in [
        (Ok::<(), ()>(()), OwnerExit::RuntimeFailed),
        (Err::<(), ()>(()), OwnerExit::CleanupFailed),
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let owner_events = Arc::clone(&events);
        let thread = std::thread::spawn(move || {
            let owner = std::thread::current().id();
            owner_events.lock().expect("events").push(("stack", owner));
            let exit = finish_stack_setup::<(), _, _>(Err(()), (), |_| {
                owner_events
                    .lock()
                    .expect("events")
                    .push(("cleanup", std::thread::current().id()));
                cleanup_result
            })
            .expect_err("injected stack setup failure");
            owner_events
                .lock()
                .expect("events")
                .push(("owner-exit", std::thread::current().id()));
            exit
        });
        assert_eq!(thread.join().expect("owner joins"), expected);
        events
            .lock()
            .expect("events")
            .push(("joined", std::thread::current().id()));
        let events = events.lock().expect("events");
        assert_eq!(
            events.iter().map(|event| event.0).collect::<Vec<_>>(),
            ["stack", "cleanup", "owner-exit", "joined"]
        );
        assert_eq!(events[0].1, events[1].1);
        assert_eq!(events[1].1, events[2].1);
        assert_ne!(events[2].1, events[3].1);
    }

    for exit in [OwnerExit::Stopped, OwnerExit::CleanupFailed] {
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicBool::new(false));
        let events = Arc::new(Mutex::new(Vec::new()));
        let thread_stop = Arc::clone(&stop);
        let thread_events = Arc::clone(&events);
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            thread_events.lock().expect("events").push("cleanup");
            exit
        });
        let guard = OwnerThread {
            control: OwnerControl {
                stop,
                shutdown: Arc::new(AtomicBool::new(false)),
                active,
                admitting: Arc::new(AtomicBool::new(false)),
                flow_count: Arc::new(AtomicUsize::new(0)),
                association_count: Arc::new(AtomicUsize::new(0)),
            },
            work: OwnerWake::default(),
            thread: Some(thread),
        };

        assert_eq!(guard.reap().await, exit);
        events.lock().expect("events").push("joined");
        assert_eq!(*events.lock().expect("events"), ["cleanup", "joined"]);
    }

    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let guard = OwnerThread {
        control: OwnerControl {
            stop,
            shutdown: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicBool::new(false)),
            admitting: Arc::new(AtomicBool::new(false)),
            flow_count: Arc::new(AtomicUsize::new(0)),
            association_count: Arc::new(AtomicUsize::new(0)),
        },
        work: OwnerWake::default(),
        thread: Some(std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            panic!("injected owner panic")
        })),
    };
    assert_eq!(guard.reap().await, OwnerExit::CleanupFailed);

    let (sender, receiver) = tokio::sync::oneshot::channel();
    drop(sender);
    assert_eq!(
        reported_owner_exit(receiver.await),
        OwnerExit::CleanupFailed,
        "owner EOF is a cleanup failure"
    );
    assert_eq!(
        reconcile_owner_exit(OwnerExit::RuntimeFailed, OwnerExit::Stopped),
        OwnerExit::RuntimeFailed
    );
    assert_eq!(
        reconcile_owner_exit(OwnerExit::RuntimeFailed, OwnerExit::CleanupFailed),
        OwnerExit::CleanupFailed
    );
    assert_eq!(
        reconcile_owner_exit(OwnerExit::Stopped, OwnerExit::Stopped),
        OwnerExit::Stopped
    );
    assert_eq!(
        reconcile_owner_exit(OwnerExit::Stopped, OwnerExit::CleanupFailed),
        OwnerExit::CleanupFailed
    );

    tokio::time::timeout(Duration::from_secs(1), async {})
        .await
        .expect("owner table is bounded");
}

#[tokio::test]
async fn network_lifecycle_bridge_reports_retry_before_completion() {
    use ferrum2_net::NetworkSnapshot;
    use ferrum2_runtime::{ProcessCause, ProcessRoot, ProcessSupervisor};

    let (_flow_sender, flows) = tokio::sync::mpsc::channel(1);
    let (_datagram_sender, datagrams) =
        tokio::sync::mpsc::channel::<SessionItem<crate::UdpCandidate>>(1);
    let (network_reset_sender, network_resets) = tokio::sync::mpsc::channel(1);
    let control = OwnerControl::new();
    let active = Arc::clone(&control.active);
    let flow_count = Arc::clone(&control.flow_count);
    let association_count = Arc::clone(&control.association_count);
    let owner_control = control.clone();
    let (done_sender, done) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        while !owner_control.stop.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        let _ = done_sender.send(OwnerExit::Stopped);
        OwnerExit::Stopped
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = Arc::clone(&calls);
    let registry = OwnerRegistry::new();
    let root_registry = registry.clone();
    let root = ProcessRoot::new(move || async move {
        Ok::<_, &'static str>(TunRoot {
            owner: OwnerThread {
                control,
                work: OwnerWake::default(),
                thread: Some(thread),
            },
            done,
            runtime: Some("runtime"),
            cleanup: Some("cleanup"),
            flows,
            datagrams,
            network_resets,
            flow_count,
            association_count,
            registry: root_registry,
            handle_tcp: Arc::new(|_, _, _| Box::pin(async {})),
            handle_udp: Arc::new(|_, _, _| Box::pin(async {})),
            handle_network_lifecycle: Arc::new(move |_, _| {
                let call = handler_calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    if call == 0 {
                        Err(crate::TunNetworkResetError)
                    } else {
                        Ok(())
                    }
                })
            }),
        })
    });
    let supervisor = ProcessSupervisor::new(vec![root], Duration::from_secs(1), registry).unwrap();
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let run = tokio::spawn(supervisor.run_until(async move {
        let _ = shutdown_receiver.await;
    }));
    while !active.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }

    for (generation, expected) in [
        (2, NetworkResetBridgeOutcome::Retry),
        (3, NetworkResetBridgeOutcome::Completed),
    ] {
        let (completion, completed) = tokio::sync::oneshot::channel();
        network_reset_sender
            .send(NetworkResetRequest {
                snapshot: Arc::new(NetworkSnapshot::new(generation, None, None).unwrap()),
                lifecycle: crate::TunNetworkLifecycle::ResetNetwork(
                    TunNetworkResetReason::NetworkChange,
                ),
                completion,
            })
            .await
            .unwrap();
        assert_eq!(completed.await.unwrap(), expected);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    shutdown_sender.send(()).unwrap();
    let report = run.await.unwrap();
    assert_eq!(report.cause(), &ProcessCause::ExternalShutdown);
}

#[tokio::test]
async fn tcp_handler_churn_is_reaped_and_panic_fails_the_required_root() {
    use ferrum2_runtime::{OwnerRegistry, ProcessCause, ProcessRootExit, ProcessSupervisor};

    let (_session_handle, session) =
        crate::supervisor::runtime::session_cancellation(1, OwnerWake::default());
    let (flow_sender, flow_receiver) = tokio::sync::mpsc::channel(2);
    let (_udp, datagram_receiver) =
        tokio::sync::mpsc::channel::<SessionItem<crate::UdpCandidate>>(1);
    let (_network_reset, network_resets) =
        tokio::sync::mpsc::channel::<crate::NetworkResetRequest>(1);
    let control = OwnerControl::new();
    let active = Arc::clone(&control.active);
    let flow_count = Arc::clone(&control.flow_count);
    let association_count = Arc::clone(&control.association_count);
    let owner_control = control.clone();
    let (done_sender, done_receiver) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        while !owner_control.stop.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        let _ = done_sender.send(OwnerExit::Stopped);
        OwnerExit::Stopped
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = Arc::clone(&calls);
    let registry = OwnerRegistry::new();
    let root_registry = registry.clone();
    let root = ferrum2_runtime::ProcessRoot::new(move || async move {
        Ok::<_, &'static str>(TunRoot {
            owner: OwnerThread {
                control,
                work: OwnerWake::default(),
                thread: Some(thread),
            },
            done: done_receiver,
            runtime: Some("runtime"),
            cleanup: Some("cleanup"),
            flows: flow_receiver,
            datagrams: datagram_receiver,
            network_resets,
            flow_count,
            association_count,
            registry: root_registry,
            handle_tcp: Arc::new(move |flow, _, _| {
                let calls = Arc::clone(&handler_calls);
                Box::pin(async move {
                    drop(flow);
                    if calls.fetch_add(1, Ordering::SeqCst) == 32 {
                        panic!("injected TUN TCP handler panic");
                    }
                })
            }),
            handle_udp: Arc::new(|_: crate::UdpCandidate, _, _| Box::pin(async {})),
            handle_network_lifecycle: Arc::new(|_, _| Box::pin(async { Ok(()) })),
        })
    });
    let supervisor = ProcessSupervisor::new(vec![root], Duration::from_secs(1), registry.clone())
        .expect("one TUN root");
    let run = tokio::spawn(supervisor.run_until(std::future::pending::<()>()));
    while !active.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }
    for port in 10_000..10_033 {
        let (flow, _owner) =
            tcp_flow_pair(SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), port)), 4);
        flow_sender
            .send(SessionItem {
                value: flow,
                cancellation: session.clone(),
            })
            .await
            .expect("bounded handler churn");
    }
    let report = run.await.expect("process report");
    assert_eq!(calls.load(Ordering::SeqCst), 33);
    assert_eq!(registry.snapshot().active_tun_handler_tasks, 0);
    assert!(matches!(
        report.cause(),
        ProcessCause::RootStopped {
            exit: ProcessRootExit::Failed("runtime"),
            ..
        }
    ));
}

#[tokio::test(start_paused = true)]
async fn pressured_tcp_flow_survives_quiesce_and_forced_shutdown_reaps_every_owner() {
    use ferrum2_runtime::{
        OwnerRegistry, ProcessCause, ProcessCleanupFailure, ProcessExitKind, ProcessState,
        ProcessSupervisor,
    };

    struct HandlerDrop(Arc<AtomicUsize>);

    impl Drop for HandlerDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    enum FakeOwnerRequest {
        Admit {
            flow: crate::TcpFlow,
            owner: crate::tcp::FlowOwner,
            result: std::sync::mpsc::SyncSender<bool>,
        },
    }

    for owner_exit in [OwnerExit::Stopped, OwnerExit::CleanupFailed] {
        let registry = OwnerRegistry::new();
        let owner_registry = registry.clone();
        let root_registry = registry.clone();
        let (session_handle, session) =
            crate::supervisor::runtime::session_cancellation(1, OwnerWake::default());
        let owner_session = session.clone();
        let (flow_sender, flow_receiver) = tokio::sync::mpsc::channel(2);
        let (_datagram_sender, datagram_receiver) =
            tokio::sync::mpsc::channel::<SessionItem<crate::UdpCandidate>>(1);
        let (_network_reset_sender, network_resets) =
            tokio::sync::mpsc::channel::<crate::NetworkResetRequest>(1);
        let (owner_requests, requested_admissions) = std::sync::mpsc::channel::<FakeOwnerRequest>();
        let control = OwnerControl::new();
        let active = Arc::clone(&control.active);
        let admitting = Arc::clone(&control.admitting);
        let flow_count = Arc::clone(&control.flow_count);
        let owner_control = control.clone();
        let owner_count = Arc::new(AtomicUsize::new(1));
        let owner_saw_aborted_flow = Arc::new(AtomicBool::new(false));
        let owner_flow_count = Arc::clone(&flow_count);
        let remaining_owners = Arc::clone(&owner_count);
        let saw_aborted_flow = Arc::clone(&owner_saw_aborted_flow);
        let (done_sender, done_receiver) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let mut owners = Vec::new();
            while !owner_control.stop.load(Ordering::Acquire) {
                match requested_admissions.try_recv() {
                    Ok(FakeOwnerRequest::Admit {
                        flow,
                        owner,
                        result,
                    }) => {
                        let accepted = owner_control.admitting.load(Ordering::Acquire)
                            && flow_sender
                                .blocking_send(SessionItem {
                                    value: flow,
                                    cancellation: owner_session.clone(),
                                })
                                .is_ok();
                        if accepted {
                            owners.push((owner, owner_registry.track_tun_tcp_flow()));
                            owner_flow_count.fetch_add(1, Ordering::AcqRel);
                        }
                        let _ = result.send(accepted);
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        std::thread::yield_now();
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                }
            }

            let owned_flows = owners.len();
            saw_aborted_flow.store(
                owned_flows != 0 && owners.iter().all(|(owner, _)| owner.is_aborted()),
                Ordering::Release,
            );
            drop(owners);
            owner_flow_count.fetch_sub(owned_flows, Ordering::AcqRel);
            remaining_owners.fetch_sub(1, Ordering::AcqRel);
            let _ = done_sender.send(owner_exit);
            owner_exit
        });

        let pressured = Arc::new(tokio::sync::Notify::new());
        let pressure_reported = Arc::new(AtomicBool::new(false));
        let handler_starts = Arc::new(AtomicUsize::new(0));
        let handler_drops = Arc::new(AtomicUsize::new(0));
        let handler_pressured = Arc::clone(&pressured);
        let handler_pressure_reported = Arc::clone(&pressure_reported);
        let recorded_handler_starts = Arc::clone(&handler_starts);
        let recorded_handler_drops = Arc::clone(&handler_drops);
        let root_flow_count = Arc::clone(&flow_count);
        let root = ferrum2_runtime::ProcessRoot::new(move || async move {
            Ok::<_, &'static str>(TunRoot {
                owner: OwnerThread {
                    control,
                    work: OwnerWake::default(),
                    thread: Some(thread),
                },
                done: done_receiver,
                runtime: Some("runtime"),
                cleanup: Some("cleanup"),
                flows: flow_receiver,
                datagrams: datagram_receiver,
                network_resets,
                flow_count: root_flow_count,
                association_count: Arc::new(AtomicUsize::new(0)),
                registry: root_registry,
                handle_tcp: Arc::new(move |mut flow, _cancellation, _session| {
                    let pressured = Arc::clone(&handler_pressured);
                    let pressure_reported = Arc::clone(&handler_pressure_reported);
                    let starts = Arc::clone(&recorded_handler_starts);
                    let drops = Arc::clone(&recorded_handler_drops);
                    Box::pin(async move {
                        starts.fetch_add(1, Ordering::SeqCst);
                        let _drop = HandlerDrop(drops);
                        flow.write_all(b"full")
                            .await
                            .expect("fill the bounded application-to-stack bridge");
                        let unexpected =
                            std::future::poll_fn(
                                |context| match tokio::io::AsyncWrite::poll_write(
                                    std::pin::Pin::new(&mut flow),
                                    context,
                                    b"x",
                                ) {
                                    std::task::Poll::Pending => {
                                        if !pressure_reported.swap(true, Ordering::SeqCst) {
                                            pressured.notify_one();
                                        }
                                        std::task::Poll::Pending
                                    }
                                    ready => ready,
                                },
                            )
                            .await;
                        panic!(
                            "pressured flow completed before forced cancellation: {unexpected:?}"
                        );
                    })
                }),
                handle_udp: Arc::new(|_: crate::UdpCandidate, _, _| Box::pin(async {})),
                handle_network_lifecycle: Arc::new(|_, _| Box::pin(async { Ok(()) })),
            })
        });
        let supervisor =
            ProcessSupervisor::new(vec![root], Duration::from_secs(5), registry.clone())
                .expect("one TUN root");
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(supervisor.run_until(async move {
            let _ = shutdown_receiver.await;
        }));

        for _ in 0..100 {
            if active.load(Ordering::Acquire) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(active.load(Ordering::Acquire), "TUN root becomes active");

        let admit = |port| {
            let (flow, owner) =
                tcp_flow_pair(SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), port)), 4);
            let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(0);
            owner_requests
                .send(FakeOwnerRequest::Admit {
                    flow,
                    owner,
                    result: result_sender,
                })
                .expect("fake owner is accepting commands");
            result_receiver.recv().expect("fake owner admission result")
        };
        assert!(admit(10_000), "active TUN owner admits the first flow");
        tokio::time::timeout(Duration::from_secs(1), pressured.notified())
            .await
            .expect("TCP handler reaches real bridge backpressure");
        assert_eq!(handler_starts.load(Ordering::SeqCst), 1);
        assert_eq!(handler_drops.load(Ordering::SeqCst), 0);
        assert_eq!(flow_count.load(Ordering::Acquire), 1);
        assert_eq!(owner_count.load(Ordering::Acquire), 1);
        assert_eq!(registry.snapshot().active_tun_tcp_flows, 1);
        assert_eq!(registry.snapshot().active_tun_handler_tasks, 1);

        shutdown_sender.send(()).expect("request process shutdown");
        for _ in 0..100 {
            if !admitting.load(Ordering::Acquire) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            !admitting.load(Ordering::Acquire),
            "quiescing reaches the fake owner"
        );
        assert!(!admit(10_001), "quiescing rejects a new TCP flow");
        assert_eq!(handler_starts.load(Ordering::SeqCst), 1);
        assert_eq!(flow_count.load(Ordering::Acquire), 1);

        tokio::time::advance(Duration::from_millis(4_999)).await;
        tokio::task::yield_now().await;
        assert!(
            !run.is_finished(),
            "pressured flow remains owned during grace"
        );
        assert_eq!(handler_drops.load(Ordering::SeqCst), 0);
        assert_eq!(flow_count.load(Ordering::Acquire), 1);
        assert_eq!(owner_count.load(Ordering::Acquire), 1);
        assert_eq!(registry.snapshot().active_process_roots, 1);
        assert_eq!(registry.snapshot().active_tun_tcp_flows, 1);
        assert_eq!(registry.snapshot().active_tun_handler_tasks, 1);

        tokio::time::advance(Duration::from_millis(1)).await;
        let report = run.await.expect("forced TUN process report");
        assert_eq!(handler_drops.load(Ordering::SeqCst), 1);
        assert_eq!(flow_count.load(Ordering::Acquire), 0);
        assert_eq!(owner_count.load(Ordering::Acquire), 0);
        assert!(owner_saw_aborted_flow.load(Ordering::Acquire));
        assert_eq!(report.cause(), &ProcessCause::ExternalShutdown);
        assert_eq!(report.forced_roots(), 1);
        assert_eq!(
            report.states(),
            &[
                ProcessState::Validated,
                ProcessState::Preparing,
                ProcessState::Prepared,
                ProcessState::Active,
                ProcessState::Quiescing,
                ProcessState::Draining,
                ProcessState::Forced,
                ProcessState::Stopped,
            ]
        );
        match owner_exit {
            OwnerExit::Stopped => {
                assert_eq!(report.exit_kind(), ProcessExitKind::Forced);
                assert!(report.cleanup_failure().is_none());
            }
            OwnerExit::CleanupFailed => {
                assert_eq!(report.exit_kind(), ProcessExitKind::Failed);
                assert!(matches!(
                    report.cleanup_failure(),
                    Some(ProcessCleanupFailure::RootFailed {
                        root,
                        error: "cleanup",
                    }) if root.get() == 0
                ));
            }
            OwnerExit::RuntimeFailed => unreachable!("test owner outcome is closed"),
        }
        let stopped = registry.snapshot();
        assert_eq!(stopped.process_supervisors, 0);
        assert_eq!(stopped.prepared_process_roots, 0);
        assert_eq!(stopped.active_process_roots, 0);
        assert_eq!(stopped.active_tun_tcp_flows, 0);
        assert_eq!(stopped.active_tun_handler_tasks, 0);
        assert_eq!(stopped.process_root_reaps, 1);
        assert_eq!(stopped.process_forced_roots, 1);
        drop(session_handle);
    }
}
