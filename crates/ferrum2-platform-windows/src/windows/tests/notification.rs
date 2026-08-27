use super::support::{
    AF_UNSPEC, Error, ErrorKind, NetworkChangeWaitOperations, NetworkChangeWaitOutcome,
    NotificationContext, cancel_notification_handles, classify_notification_luid,
    close_notification_handles, leak_notification_owners, managed_notification_family,
    subscribe_notification_sequence, wait_for_network_change,
};

enum PublicationObservation<T> {
    Blocked,
    Early(T),
    Disconnected,
    Timeout,
}

fn observe_publication<T>(
    context: &NotificationContext,
    receiver: &std::sync::mpsc::Receiver<T>,
    expected_luid: u64,
    deadline: std::time::Instant,
) -> (bool, bool, PublicationObservation<T>) {
    let mut owner_observed = false;
    let mut drain_observed = false;
    loop {
        owner_observed |=
            context.owned_luid.load(std::sync::atomic::Ordering::SeqCst) == expected_luid;
        drain_observed |= context
            .drain_wait_observed
            .load(std::sync::atomic::Ordering::SeqCst);
        match receiver.try_recv() {
            Ok(result) => {
                return (
                    owner_observed,
                    drain_observed,
                    PublicationObservation::Early(result),
                );
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return (
                    owner_observed,
                    drain_observed,
                    PublicationObservation::Disconnected,
                );
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        if owner_observed && drain_observed {
            return (
                owner_observed,
                drain_observed,
                PublicationObservation::Blocked,
            );
        }
        if std::time::Instant::now() >= deadline {
            return (
                owner_observed,
                drain_observed,
                PublicationObservation::Timeout,
            );
        }
        std::thread::yield_now();
    }
}

struct InjectedNetworkChangeWait {
    stop_reads: std::collections::VecDeque<bool>,
    generations: std::collections::VecDeque<u64>,
    current_generation: u64,
    signals: std::collections::VecDeque<NetworkChangeWaitOutcome>,
    reset_calls: usize,
    wait_calls: usize,
}

impl InjectedNetworkChangeWait {
    fn new(
        stop_reads: impl IntoIterator<Item = bool>,
        generations: impl IntoIterator<Item = u64>,
        signals: impl IntoIterator<Item = NetworkChangeWaitOutcome>,
    ) -> Self {
        Self {
            stop_reads: stop_reads.into_iter().collect(),
            generations: generations.into_iter().collect(),
            current_generation: 0,
            signals: signals.into_iter().collect(),
            reset_calls: 0,
            wait_calls: 0,
        }
    }
}

impl NetworkChangeWaitOperations for InjectedNetworkChangeWait {
    fn stop_is_set(&mut self) -> Result<bool, Error> {
        Ok(self.stop_reads.pop_front().unwrap_or(false))
    }

    fn generation(&mut self) -> u64 {
        if let Some(generation) = self.generations.pop_front() {
            self.current_generation = generation;
        }
        self.current_generation
    }

    fn reset_network_change(&mut self) -> Result<(), Error> {
        self.reset_calls += 1;
        Ok(())
    }

    fn wait_for_signal(&mut self, _: u32) -> Result<NetworkChangeWaitOutcome, Error> {
        self.wait_calls += 1;
        self.signals.pop_front().ok_or(Error)
    }
}

#[test]
fn network_change_wait_state_machine_closes_stop_change_and_timeout() {
    let mut observed = 7;
    let mut stopped = InjectedNetworkChangeWait::new([true], [], []);
    assert_eq!(
        wait_for_network_change(&mut observed, std::time::Duration::ZERO, &mut stopped),
        Ok(NetworkChangeWaitOutcome::Stopped)
    );
    assert_eq!(observed, 7);
    assert_eq!(stopped.reset_calls, 0);
    assert_eq!(stopped.wait_calls, 0);

    let mut observed = 0;
    let mut changed = InjectedNetworkChangeWait::new([false, false], [1, 2], []);
    assert_eq!(
        wait_for_network_change(&mut observed, std::time::Duration::ZERO, &mut changed),
        Ok(NetworkChangeWaitOutcome::Changed)
    );
    assert_eq!(
        observed, 2,
        "generation racing with ResetEvent is folded into the observation"
    );
    assert_eq!(changed.reset_calls, 1);
    assert_eq!(changed.wait_calls, 0);

    let mut observed = 11;
    let mut timed_out = InjectedNetworkChangeWait::new([false], [11], []);
    assert_eq!(
        wait_for_network_change(&mut observed, std::time::Duration::ZERO, &mut timed_out,),
        Ok(NetworkChangeWaitOutcome::TimedOut)
    );
    assert_eq!(observed, 11);
    assert_eq!(timed_out.reset_calls, 0);
    assert_eq!(timed_out.wait_calls, 0);
}

#[test]
fn network_change_wait_stop_wins_after_reset_or_change_wake() {
    let mut observed = 0;
    let mut during_reset = InjectedNetworkChangeWait::new([false, true], [1, 2], []);
    assert_eq!(
        wait_for_network_change(&mut observed, std::time::Duration::ZERO, &mut during_reset,),
        Ok(NetworkChangeWaitOutcome::Stopped)
    );
    assert_eq!(observed, 2);
    assert_eq!(during_reset.reset_calls, 1);

    let mut observed = 0;
    let mut after_wake =
        InjectedNetworkChangeWait::new([false, true], [0], [NetworkChangeWaitOutcome::Changed]);
    assert_eq!(
        wait_for_network_change(
            &mut observed,
            std::time::Duration::from_secs(1),
            &mut after_wake,
        ),
        Ok(NetworkChangeWaitOutcome::Stopped)
    );
    assert_eq!(observed, 0);
    assert_eq!(after_wake.reset_calls, 1);
    assert_eq!(after_wake.wait_calls, 1);
}

#[test]
fn notification_publication_waits_for_inflight_classifier() {
    const OWN_LUID: u64 = 0x1020_3040;
    const FOREIGN_LUID: u64 = 0x5060_7080;

    for (name, notified_luid, expected_generation, expected_ok) in [
        ("exact own", OWN_LUID, 1, true),
        ("foreign", FOREIGN_LUID, 2, false),
    ] {
        let context = NotificationContext::new(None);
        let entered = std::sync::Barrier::new(2);
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (publisher_tx, publisher_rx) = std::sync::mpsc::sync_channel(1);

        let outcome = std::thread::scope(|scope| {
            let callback_context = &context;
            let callback_entered = &entered;
            let callback = scope.spawn(move || {
                classify_notification_luid(callback_context, notified_luid, || {
                    callback_entered.wait();
                    let _ = release_rx.recv();
                });
            });
            entered.wait();
            let publisher = scope.spawn(|| {
                let result = context.publish_owned_luid(
                    OWN_LUID,
                    std::time::Instant::now() + std::time::Duration::from_secs(1),
                    &std::sync::atomic::AtomicBool::new(false),
                );
                publisher_tx
                    .send((
                        result.is_ok(),
                        context
                            .generation
                            .load(std::sync::atomic::Ordering::Acquire),
                    ))
                    .unwrap();
            });
            let (owner_observed, drain_observed, observation) = observe_publication(
                &context,
                &publisher_rx,
                OWN_LUID,
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            );
            let (early, disconnected, timed_out) = match observation {
                PublicationObservation::Blocked => (None, false, false),
                PublicationObservation::Early(result) => (Some(result), false, false),
                PublicationObservation::Disconnected => (None, true, false),
                PublicationObservation::Timeout => (None, false, true),
            };
            let released = release_tx.send(()).is_ok();
            drop(release_tx);
            let callback_joined = callback.join().is_ok();
            let publisher_joined = publisher.join().is_ok();
            let completed_while_paused = early.is_some();
            let result = early.or_else(|| {
                publisher_rx
                    .recv_timeout(std::time::Duration::from_secs(1))
                    .ok()
            });
            (
                owner_observed,
                drain_observed,
                completed_while_paused,
                disconnected,
                timed_out,
                released,
                callback_joined,
                publisher_joined,
                result,
            )
        });

        assert!(outcome.0, "{name}: owner publication was not observed");
        assert!(outcome.1, "{name}: drain wait was not observed");
        assert!(
            !outcome.2,
            "{name}: owner publication completed before the callback classified its LUID"
        );
        assert!(!outcome.3, "{name}: publisher result channel disconnected");
        assert!(!outcome.4, "{name}: publisher observation timed out");
        assert!(outcome.5, "{name}: callback release failed");
        assert!(outcome.6, "{name}: callback thread failed");
        assert!(outcome.7, "{name}: publisher thread failed");
        let generation_at_publication = outcome
            .8
            .expect("publisher result missing after callback release");
        assert_eq!(
            generation_at_publication.1, expected_generation,
            "{name}: callback classification was not reflected before publication returned"
        );
        assert_eq!(
            generation_at_publication.0, expected_ok,
            "{name}: publication result"
        );
        assert_eq!(
            context
                .generation
                .load(std::sync::atomic::Ordering::Acquire),
            expected_generation,
            "{name}: final notification generation"
        );
    }
}

#[test]
fn notification_publication_observer_bounds_failure_paths() {
    const OWN_LUID: u64 = 0x1020_3040;
    let context = NotificationContext::new(None);

    let (publisher_tx, publisher_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let timeout = observe_publication(&context, &publisher_rx, OWN_LUID, std::time::Instant::now());
    assert!(matches!(timeout.2, PublicationObservation::Timeout));
    drop(publisher_tx);
    let disconnected = observe_publication(
        &context,
        &publisher_rx,
        OWN_LUID,
        std::time::Instant::now() + std::time::Duration::from_secs(1),
    );
    assert!(matches!(
        disconnected.2,
        PublicationObservation::Disconnected
    ));

    let (publisher_tx, publisher_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let publisher = std::thread::spawn(move || {
        let _publisher_tx = publisher_tx;
        let _release_tx = release_tx;
        panic!("synthetic publisher panic");
    });
    let panic_observation = observe_publication(
        &context,
        &publisher_rx,
        OWN_LUID,
        std::time::Instant::now() + std::time::Duration::from_secs(1),
    );
    let release_disconnected = release_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .is_err();
    let publisher_panicked = publisher.join().is_err();
    assert!(matches!(
        panic_observation.2,
        PublicationObservation::Disconnected
    ));
    assert!(
        release_disconnected,
        "panic did not release callback channel"
    );
    assert!(publisher_panicked, "synthetic publisher did not panic");
}

#[test]
fn notification_publication_deadline_and_cancellation_fail_closed() {
    const OWN_LUID: u64 = 0x1020_3040;

    for (name, cancelled, deadline) in [
        (
            "cancelled",
            true,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        ),
        ("expired", false, std::time::Instant::now()),
    ] {
        let context = NotificationContext::new(None);
        let entered = std::sync::Barrier::new(2);
        let release = std::sync::Barrier::new(2);
        let cancelled = std::sync::atomic::AtomicBool::new(cancelled);

        let result = std::thread::scope(|scope| {
            let callback = scope.spawn(|| {
                classify_notification_luid(&context, OWN_LUID, || {
                    entered.wait();
                    release.wait();
                });
            });
            entered.wait();
            let result = context.publish_owned_luid(OWN_LUID, deadline, &cancelled);
            release.wait();
            callback.join().unwrap();
            result
        });

        assert!(result.is_err(), "{name}: publication did not fail closed");
    }
}

#[test]
fn network_change_notifications_cover_each_callback_and_runtime_owned_events() {
    const OWN_LUID: u64 = 0x1020_3040;
    const FOREIGN_LUID: u64 = 0x5060_7080;

    #[derive(Clone, Copy, Debug)]
    enum Callback {
        Route,
        Interface,
        Address,
    }

    #[derive(Clone, Copy)]
    enum Action {
        Notify(Option<u64>),
        Publish(u64),
        Monitor,
    }

    fn notify(_: Callback, context: &NotificationContext, luid: Option<u64>) {
        classify_notification_luid(context, luid.unwrap_or_default(), || {});
    }

    let cases: &[(&str, &[Action], bool)] = &[
        (
            "repeated own before publication",
            &[
                Action::Notify(Some(OWN_LUID)),
                Action::Notify(Some(OWN_LUID)),
                Action::Publish(OWN_LUID),
            ],
            true,
        ),
        (
            "foreign before publication",
            &[
                Action::Notify(Some(FOREIGN_LUID)),
                Action::Publish(OWN_LUID),
            ],
            true,
        ),
        (
            "own then foreign before publication",
            &[
                Action::Notify(Some(OWN_LUID)),
                Action::Notify(Some(FOREIGN_LUID)),
                Action::Publish(OWN_LUID),
            ],
            true,
        ),
        (
            "foreign then own before publication",
            &[
                Action::Notify(Some(FOREIGN_LUID)),
                Action::Notify(Some(OWN_LUID)),
                Action::Publish(OWN_LUID),
            ],
            true,
        ),
        (
            "null row",
            &[Action::Notify(None), Action::Publish(OWN_LUID)],
            true,
        ),
        (
            "zero row LUID",
            &[Action::Notify(Some(0)), Action::Publish(OWN_LUID)],
            true,
        ),
        (
            "own after publication",
            &[Action::Publish(OWN_LUID), Action::Notify(Some(OWN_LUID))],
            true,
        ),
        (
            "foreign after publication",
            &[
                Action::Publish(OWN_LUID),
                Action::Notify(Some(FOREIGN_LUID)),
            ],
            true,
        ),
        (
            "same owner republished",
            &[Action::Publish(OWN_LUID), Action::Publish(OWN_LUID)],
            false,
        ),
        (
            "different owner republished",
            &[Action::Publish(OWN_LUID), Action::Publish(FOREIGN_LUID)],
            true,
        ),
        ("zero owner published", &[Action::Publish(0)], true),
        (
            "owned runtime mutation",
            &[
                Action::Publish(OWN_LUID),
                Action::Monitor,
                Action::Notify(Some(OWN_LUID)),
            ],
            true,
        ),
    ];
    for callback in [Callback::Route, Callback::Interface, Callback::Address] {
        for (name, actions, changed) in cases {
            let context = NotificationContext::new(None);
            for action in *actions {
                match action {
                    Action::Notify(value) => notify(callback, &context, *value),
                    Action::Publish(value) => {
                        let _ = context.publish_owned_luid(
                            *value,
                            std::time::Instant::now() + std::time::Duration::from_secs(1),
                            &std::sync::atomic::AtomicBool::new(false),
                        );
                    }
                    Action::Monitor => context.monitor_runtime(),
                }
            }
            assert_eq!(context.generation() != 0, *changed, "{callback:?}: {name}");
        }
    }
}

#[test]
fn notification_cancel_retains_only_failed_handles_for_safe_retry() {
    struct Context(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for Context {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    for failed in [1_u8, 2, 3] {
        let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = vec![1_u8, 2, 3];
        let mut context = Some(Context(drops.clone()));
        let mut calls = Vec::new();
        assert!(cancel_notification_handles(
            &mut handles,
            &mut context,
            |handle| {
                calls.push(*handle);
                *handle != failed
            }
        ));
        assert_eq!(calls, [3, 2, 1]);
        assert_eq!(handles, [failed], "only the live callback owner survives");
        assert!(context.is_some());
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);

        calls.clear();
        assert!(!cancel_notification_handles(
            &mut handles,
            &mut context,
            |handle| {
                calls.push(*handle);
                true
            }
        ));
        assert_eq!(calls, [failed]);
        assert!(handles.is_empty());
        assert!(context.is_none());
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut handles = vec![4_u8];
    let mut context = Some(Context(drops.clone()));
    assert!(cancel_notification_handles(
        &mut handles,
        &mut context,
        |_| false
    ));
    leak_notification_owners(&mut handles, &mut context);
    assert!(handles.is_empty());
    assert!(context.is_none());
    assert_eq!(
        drops.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "persistent callback ownership is intentionally retained"
    );
}

#[test]
fn explicit_notification_close_is_exact_or_reports_safe_leak() {
    struct Context(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for Context {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut handles = vec![1_u8, 2, 3];
    let mut context = Some(Context(drops.clone()));
    let mut cancelled = Vec::new();
    assert_eq!(
        close_notification_handles(&mut handles, &mut context, |handle| {
            cancelled.push(*handle);
            true
        }),
        Ok(())
    );
    assert_eq!(cancelled, [3, 2, 1]);
    assert!(handles.is_empty());
    assert!(context.is_none());
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);

    let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut handles = vec![4_u8, 5, 6];
    let mut context = Some(Context(drops.clone()));
    let error =
        close_notification_handles(&mut handles, &mut context, |handle| *handle != 5).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cleanup);
    assert!(handles.is_empty());
    assert!(context.is_none());
    assert_eq!(
        drops.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "failed cancellation intentionally leaks callback-reachable context"
    );
}

#[test]
fn notification_subscription_failure_cleans_each_completed_ordinal() {
    assert_eq!(managed_notification_family(), AF_UNSPEC);

    struct Context(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for Context {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    for failed in 0..3 {
        let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut subscribed = Vec::new();
        let mut cancelled = Vec::new();
        assert!(
            subscribe_notification_sequence(
                Context(drops.clone()),
                |ordinal| {
                    subscribed.push(ordinal);
                    if ordinal == failed {
                        Err(Error)
                    } else {
                        Ok(ordinal)
                    }
                },
                |handle| {
                    cancelled.push(*handle);
                    true
                },
            )
            .is_err()
        );
        assert_eq!(subscribed, (0..=failed).collect::<Vec<_>>());
        assert_eq!(cancelled, (0..failed).rev().collect::<Vec<_>>());
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut cancelled = Vec::new();
    assert!(
        subscribe_notification_sequence(
            Context(drops.clone()),
            |ordinal| if ordinal == 2 {
                Err(Error)
            } else {
                Ok(ordinal)
            },
            |handle| {
                cancelled.push(*handle);
                *handle != 1
            },
        )
        .is_err()
    );
    assert_eq!(cancelled, [1, 0]);
    assert_eq!(
        drops.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a failed cancellation retains the callback context"
    );
}
