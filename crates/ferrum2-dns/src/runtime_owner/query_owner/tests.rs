use super::*;
use crate::runtime_owner::RuntimeStats;
use crate::runtime_owner::command_loop::runtime_stats;
use crate::runtime_provider::SystemDnsEgress;
use std::time::Duration;

type Reply = Pin<Box<dyn Future<Output = DnsError>>>;

#[tokio::test(flavor = "current_thread")]
async fn queued_children_preserve_joined_root_failure_without_starting_bodies() {
    for kind in 0..3 {
        let admission = Arc::new(tokio::sync::Semaphore::new(1));
        let counters = Arc::new(RuntimeCounters::default());
        let root = DnsQueryContext::root(
            admission.clone().try_acquire_owned().unwrap(),
            counters.clone(),
            Instant::now() + Duration::from_secs(2),
        );
        let child = root.scope().child(2).unwrap();
        let (root_command, mut root_reply) = command(kind, root);
        let (child_command, child_reply) = command(kind, child);
        let (mut root, _, _) = QueryState::new(root_command);
        root.body
            .spawn(async { panic!("injected finite root failure") });
        let mut owner = QueryOwner::default();
        owner.records.push(QueryRecord(Some(root)));
        // The child has been accepted but remains queued while the root fails.
        assert!(
            tokio::time::timeout(Duration::from_millis(10), owner.next())
                .await
                .is_err()
        );
        assert!(futures_util::poll!(&mut root_reply).is_pending());
        assert_eq!(admission.available_permits(), 0);
        owner.spawn(
            child_command,
            Arc::new(vec![]),
            Arc::new(SystemDnsEgress),
            counters.clone(),
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while owner.next().await.is_some() {}
        })
        .await
        .unwrap();
        assert_eq!(child_reply.await, DnsError::Runtime);
        assert_eq!(root_reply.await, DnsError::Runtime);
        assert!(owner.failed());
        assert_eq!(admission.available_permits(), 1);
        assert_eq!(runtime_stats(&counters), RuntimeStats::default());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_queue_drain_preserves_chain_failure_for_every_command() {
    for failed in [false, true] {
        for kind in 0..3 {
            let admission = Arc::new(tokio::sync::Semaphore::new(1));
            let counters = Arc::new(RuntimeCounters::default());
            let root = DnsQueryContext::root(
                admission.clone().try_acquire_owned().unwrap(),
                counters.clone(),
                Instant::now() + Duration::from_secs(2),
            );
            let child = root.scope().child(2).unwrap();
            if failed {
                root.task_failed();
            }
            let (root_command, root_reply) = command(kind, root);
            let (child_command, child_reply) = command(kind, child);
            let (send, receive) = tokio::sync::mpsc::channel(2);
            send.try_send(root_command).unwrap();
            send.try_send(child_command).unwrap();
            let (shutdown, stopped) = oneshot::channel();
            shutdown.send(()).unwrap();
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                crate::runtime_owner::command_loop::run_commands(
                    receive,
                    stopped,
                    Arc::new(vec![]),
                    Arc::new(SystemDnsEgress),
                    counters.clone(),
                    tokio::runtime::Handle::current(),
                ),
            )
            .await
            .unwrap();
            let expected = if failed {
                DnsError::Runtime
            } else {
                DnsError::Shutdown
            };
            assert_eq!(root_reply.await, expected);
            assert_eq!(child_reply.await, expected);
            assert_eq!(result.is_err(), failed);
            assert_eq!(admission.available_permits(), 1);
            assert_eq!(runtime_stats(&counters), RuntimeStats::default());
        }
    }
}

fn command(kind: usize, context: DnsQueryContext) -> (Command, Reply) {
    let deadline = context.deadline();
    let name = Name::from_ascii("owner.test.").unwrap();
    match kind {
        0 => {
            let (reply, receive) = oneshot::channel();
            (
                Command::Lookup {
                    server: 0,
                    name,
                    record_type: RecordType::A,
                    deadline,
                    reply,
                    context,
                },
                Box::pin(async { receive.await.unwrap().unwrap_err() }),
            )
        }
        1 => {
            let (reply, receive) = oneshot::channel();
            (
                Command::LookupIps {
                    server: 0,
                    name,
                    deadline,
                    reply,
                    context,
                },
                Box::pin(async { receive.await.unwrap().unwrap_err() }),
            )
        }
        2 => {
            let (reply, receive) = oneshot::channel();
            (
                Command::Query {
                    server: 0,
                    request: Message::new(
                        0,
                        hickory_proto::op::MessageType::Query,
                        hickory_proto::op::OpCode::Query,
                    ),
                    deadline,
                    reply,
                    context,
                },
                Box::pin(async { receive.await.unwrap().unwrap_err() }),
            )
        }
        _ => unreachable!("three command variants"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn every_command_retains_admission_through_abort_before_first_poll_and_panic_join() {
    for kind in 0..3 {
        for stop_before_poll in [true, false] {
            let admission = Arc::new(tokio::sync::Semaphore::new(1));
            let counters = Arc::new(RuntimeCounters::default());
            let context = DnsQueryContext::root(
                admission.clone().try_acquire_owned().unwrap(),
                counters.clone(),
                Instant::now() + Duration::from_secs(2),
            );
            let (command, reply) = command(kind, context);
            let mut owner = QueryOwner::default();
            // Empty injected servers panic on body polling, before provider creation.
            owner.spawn(
                command,
                Arc::new(vec![]),
                Arc::new(SystemDnsEgress),
                counters.clone(),
            );
            assert_eq!(admission.available_permits(), 0);
            if stop_before_poll {
                owner.stop();
            }
            assert_eq!(admission.available_permits(), 0);
            tokio::time::timeout(Duration::from_secs(2), owner.next())
                .await
                .unwrap();
            assert!(owner.is_empty());
            assert_eq!(
                reply.await,
                if stop_before_poll {
                    DnsError::Shutdown
                } else {
                    DnsError::Runtime
                }
            );
            assert_eq!(owner.failed(), !stop_before_poll);
            assert_eq!(admission.available_permits(), 1);
            assert_eq!(runtime_stats(&counters), RuntimeStats::default());
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn root_reply_waits_for_nested_context_and_closed_chain_rejects_registration() {
    let admission = Arc::new(tokio::sync::Semaphore::new(1));
    let counters = Arc::new(RuntimeCounters::default());
    let context = DnsQueryContext::root(
        admission.clone().try_acquire_owned().unwrap(),
        counters.clone(),
        Instant::now() + Duration::from_secs(2),
    );
    let scope = context.scope();
    let child = scope.child(2).unwrap();
    let (command, mut reply) = command(0, context);
    let mut owner = QueryOwner::default();
    owner.spawn(
        command,
        Arc::new(vec![]),
        Arc::new(SystemDnsEgress),
        counters.clone(),
    );
    owner.stop();
    assert!(scope.child(2).is_none());
    // Poll the owner through body cancellation, but keep the nested owner alive.
    assert!(
        tokio::time::timeout(Duration::from_millis(10), owner.next())
            .await
            .is_err()
    );
    assert!(futures_util::poll!(&mut reply).is_pending());
    assert_eq!(admission.available_permits(), 0);
    drop(child);
    tokio::time::timeout(Duration::from_secs(2), owner.next())
        .await
        .unwrap();
    assert_eq!(reply.await, DnsError::Shutdown);
    assert_eq!(admission.available_permits(), 1);
    assert_eq!(runtime_stats(&counters), RuntimeStats::default());
}

#[tokio::test(flavor = "current_thread")]
async fn independently_polled_nested_records_wake_each_other_on_close_and_failure() {
    for child_fails in [false, true] {
        let admission = Arc::new(tokio::sync::Semaphore::new(1));
        let counters = Arc::new(RuntimeCounters::default());
        let root = DnsQueryContext::root(
            admission.clone().try_acquire_owned().unwrap(),
            counters.clone(),
            Instant::now() + Duration::from_secs(2),
        );
        let child = root.scope().child(2).unwrap();
        let (root_command, root_reply) = command(0, root);
        let (child_command, child_reply) = command(0, child);
        let (mut root, _, _) = QueryState::new(root_command);
        let (mut child, _, _) = QueryState::new(child_command);
        let (release, receive) = oneshot::channel::<()>();
        let triggered = async move {
            receive.await.unwrap();
            assert!(!child_fails, "injected nested body panic");
            QueryBodyResult::Failed(DnsError::Timeout)
        };
        if child_fails {
            child.body.spawn(triggered);
            root.body.spawn(std::future::pending());
        } else {
            root.body.spawn(triggered);
            child.body.spawn(std::future::pending());
        }
        let mut owner = QueryOwner::default();
        owner.records.push(QueryRecord(Some(root)));
        owner.records.push(QueryRecord(Some(child)));
        // Both supervisors register distinct wakers before either chain transition.
        assert!(futures_util::poll!(Box::pin(owner.next())).is_pending());
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while owner.next().await.is_some() {}
        })
        .await
        .unwrap();
        assert_eq!(
            root_reply.await,
            if child_fails {
                DnsError::Runtime
            } else {
                DnsError::Timeout
            }
        );
        assert_eq!(
            child_reply.await,
            if child_fails {
                DnsError::Runtime
            } else {
                DnsError::Shutdown
            }
        );
        assert_eq!(owner.failed(), child_fails);
        assert_eq!(admission.available_permits(), 1);
        assert_eq!(runtime_stats(&counters), RuntimeStats::default());
    }
}
