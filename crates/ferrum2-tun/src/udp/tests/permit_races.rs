use super::*;
use std::sync::mpsc as sync_mpsc;
use std::task::{Context, Poll, Waker};

const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(5);
const REMOTE: &str = "192.0.2.1:53";

fn bounded(scenario: impl FnOnce() + Send + 'static) {
    let (done, completion) = sync_mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(scenario));
        let _ = done.send(result);
    });
    let result = completion
        .recv_timeout(Duration::from_secs(10))
        .expect("permit race must finish without a deadlock");
    worker.join().expect("completed permit worker");
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

// Poll real async methods at known readiness boundaries, without a scheduler,
// sleeps, or an unbounded wait for a control message to happen to arrive.
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("operation was not ready at the controlled boundary"),
    }
}

fn establish(
    table: &mut UdpTable,
    candidates: &mut mpsc::Receiver<UdpCandidate>,
) -> UdpAssociation {
    assert_eq!(
        table.admit(endpoints(10_000, REMOTE), b"first", 128, 0, true),
        Admission::Provisional
    );
    let candidate = candidates.try_recv().unwrap();
    let mut future = std::pin::pin!(candidate.commit_association());
    let mut context = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut context).is_pending());
    assert_eq!(table.process_one_control(0, true), Some(true));
    let mut association = match future.as_mut().poll(&mut context) {
        Poll::Ready(Ok(association)) => association,
        _ => panic!("owner commit must complete the real candidate future"),
    };
    drop(ready(association.receive()).unwrap());
    association
}

fn fixture() -> (
    UdpTable,
    mpsc::Receiver<UdpCandidate>,
    UdpAssociation,
    ferrum2_runtime::UdpBufferBudget,
) {
    let (mut table, mut candidates, _) = table(1, 60_000, UdpFiltering::EndpointIndependent, 7);
    let budget =
        ferrum2_runtime::UdpBufferBudget::new_tun(64, ferrum2_runtime::OwnerRegistry::new());
    table.set_buffer_budget(budget.clone());
    let association = establish(&mut table, &mut candidates);
    assert_eq!(budget.reserved_bytes(), 0);
    (table, candidates, association, budget)
}

struct HookReset;

impl Drop for HookReset {
    fn drop(&mut self) {
        RESPONSE_RESERVED_HOOK.with(|hook| {
            hook.borrow_mut().take();
        });
    }
}

// The owner transition runs only after send has validated and acquired its
// permit. Every synchronous receive is bounded. On owner panic, dropping the
// release sender unblocks the worker; its thread-local hook is unwind-safe.
fn during_reservation<R>(
    sink: &UdpResponseSink,
    payload: &[u8],
    transition: impl FnOnce() -> R,
) -> (UdpResponseSendOutcome, R) {
    std::thread::scope(|scope| {
        let (reserved_tx, reserved_rx) = sync_mpsc::channel();
        let (release_tx, release_rx) = sync_mpsc::channel();
        let (result_tx, result_rx) = sync_mpsc::channel();
        scope.spawn(move || {
            let _reset = HookReset;
            RESPONSE_RESERVED_HOOK.with(|hook| {
                assert!(hook.borrow().is_none());
                *hook.borrow_mut() = Some(Box::new(move || {
                    reserved_tx.send(()).unwrap();
                    release_rx
                        .recv_timeout(RENDEZVOUS_TIMEOUT)
                        .expect("owner releases permit rendezvous");
                }));
            });
            result_tx.send(sink.send(v4(REMOTE), payload)).unwrap();
        });
        reserved_rx
            .recv_timeout(RENDEZVOUS_TIMEOUT)
            .expect("send reaches successful try_reserve");
        let value = transition();
        release_tx.send(()).unwrap();
        let outcome = result_rx
            .recv_timeout(RENDEZVOUS_TIMEOUT)
            .expect("send completes after permit release");
        (outcome, value)
    })
}

fn inject_exact(table: &mut UdpTable, expected: &[u8]) {
    assert_eq!(
        table.process_one_response(1, |tuple, payload| {
            assert_eq!(tuple, endpoints(10_000, REMOTE));
            assert_eq!(payload, expected);
            InjectOutcome::Injected
        }),
        ResponseProcessOutcome::Injected
    );
}

fn reject_stale(table: &mut UdpTable) {
    assert_eq!(
        table.process_one_response(1, |_, _| panic!("stale response reached injection")),
        ResponseProcessOutcome::Dropped(UdpResponseDropReason::StaleGeneration)
    );
}

#[test]
fn receiver_close_preserves_reserved_send_fifo_and_finishes_after_drain() {
    bounded(|| {
        let (mut table, _candidates, association, budget) = fixture();
        let sink = association.response_sink();
        assert_eq!(
            sink.send(v4(REMOTE), b"before"),
            UdpResponseSendOutcome::Queued
        );
        let (outcome, ()) = during_reservation(&sink, b"reserved", || {
            table.response_receiver_for_test().close();
            inject_exact(&mut table, b"before");
            assert!(
                matches!(
                    table.response_receiver_for_test().try_recv(),
                    Err(mpsc::error::TryRecvError::Empty)
                ),
                "close cannot finish while send holds an outstanding permit"
            );
            assert_eq!(budget.reserved_bytes(), 0);
        });
        assert_eq!(outcome, UdpResponseSendOutcome::Queued);
        assert_eq!(
            sink.send(v4(REMOTE), b"late"),
            UdpResponseSendOutcome::Closed
        );
        inject_exact(&mut table, b"reserved");
        assert!(matches!(
            table.response_receiver_for_test().try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
        assert!(ready(table.response_receiver_for_test().recv()).is_none());
        assert_eq!(budget.reserved_bytes(), 0);
    });
}

#[test]
fn receiver_drop_during_reserved_send_releases_payload_without_delivery() {
    bounded(|| {
        let (table, _candidates, association, budget) = fixture();
        let sink = association.response_sink();
        let (outcome, ()) = during_reservation(&sink, b"reserved", || drop(table));
        // Destruction, unlike Receiver::close, cannot leave a consumer to drain an
        // outstanding permit. The owner lifetime gate rejects this late commit.
        assert_eq!(outcome, UdpResponseSendOutcome::Closed);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(
            sink.send(v4(REMOTE), b"late"),
            UdpResponseSendOutcome::StaleGeneration
        );
        assert_eq!(budget.reserved_bytes(), 0);
    });
}

#[test]
fn association_close_and_slot_reuse_reject_reserved_old_response() {
    bounded(|| {
        let (mut table, mut candidates, association, budget) = fixture();
        let sink = association.response_sink();
        let old_id = sink.lease.id;
        let (outcome, fresh) = during_reservation(&sink, b"old", || {
            drop(association);
            assert_eq!(table.process_one_control(0, true), Some(false));
            assert_eq!(table.active_entries(), 0);
            let fresh = establish(&mut table, &mut candidates);
            assert_eq!(fresh.lease.id.slot, old_id.slot);
            assert_ne!(fresh.lease.id, old_id);
            fresh
        });
        assert_eq!(outcome, UdpResponseSendOutcome::Queued);
        reject_stale(&mut table);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(
            fresh.send_response(v4(REMOTE), b"fresh"),
            UdpResponseSendOutcome::Queued
        );
        inject_exact(&mut table, b"fresh");
        assert_eq!(budget.reserved_bytes(), 0);
    });
}

#[test]
fn session_fence_rejects_reserved_response_before_owner_retirement() {
    bounded(|| {
        let (mut table, _candidates, association, budget) = fixture();
        let sink = association.response_sink();
        let (outcome, ()) = during_reservation(&sink, b"old", || {
            table.fence_session(8);
            assert_eq!(table.active_associations(), 1);
        });
        assert_eq!(outcome, UdpResponseSendOutcome::Queued);
        reject_stale(&mut table);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(
            sink.send(v4(REMOTE), b"late"),
            UdpResponseSendOutcome::StaleGeneration
        );
        table.invalidate_session(8, UdpResponseDropReason::SessionReset);
        assert_eq!(table.active_entries(), 0);
        assert_eq!(budget.reserved_bytes(), 0);
    });
}

#[test]
fn session_invalidation_before_permit_send_cannot_deliver_into_fresh_association() {
    bounded(|| {
        let (mut table, mut candidates, association, budget) = fixture();
        let sink = association.response_sink();
        let (outcome, fresh) = during_reservation(&sink, b"old", || {
            table.invalidate_session(8, UdpResponseDropReason::SessionReset);
            assert_eq!(budget.reserved_bytes(), 0);
            establish(&mut table, &mut candidates)
        });
        assert_eq!(outcome, UdpResponseSendOutcome::Queued);
        reject_stale(&mut table);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(
            fresh.send_response(v4(REMOTE), b"fresh"),
            UdpResponseSendOutcome::Queued
        );
        inject_exact(&mut table, b"fresh");
        assert_eq!(budget.reserved_bytes(), 0);
    });
}

#[test]
fn budget_exhausted_after_reservation_releases_permit_and_closed_channel_finishes() {
    bounded(|| {
        let (mut table, _candidates, association, budget) = fixture();
        let sink = association.response_sink();
        let (outcome, held) = during_reservation(&sink, b"reserved", || {
            let held = budget.reserve(64).unwrap();
            table.response_receiver_for_test().close();
            assert!(matches!(
                table.response_receiver_for_test().try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
            held
        });
        assert_eq!(outcome, UdpResponseSendOutcome::QueueFull);
        assert_eq!(budget.reserved_bytes(), 64);
        drop(held);
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(matches!(
            table.response_receiver_for_test().try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
        assert!(ready(table.response_receiver_for_test().recv()).is_none());
        assert_eq!(
            table.process_one_response(1, |_, _| panic!(
                "failed budget reservation enqueued a response"
            )),
            ResponseProcessOutcome::Idle
        );
    });
}

#[test]
fn owner_drop_rejects_all_concurrently_reserved_sink_clones() {
    bounded(|| {
        const SENDERS: usize = 4;
        let (table, _candidates, association, budget) = fixture();
        let sink = association.response_sink();
        std::thread::scope(|scope| {
            let (reserved_tx, reserved_rx) = sync_mpsc::channel();
            let (result_tx, result_rx) = sync_mpsc::channel();
            let mut releases = Vec::new();
            for ordinal in 0..SENDERS {
                let cloned_sink = sink.clone();
                let reserved_tx = reserved_tx.clone();
                let result_tx = result_tx.clone();
                let (release_tx, release_rx) = sync_mpsc::channel();
                releases.push(release_tx);
                scope.spawn(move || {
                    let _reset = HookReset;
                    RESPONSE_RESERVED_HOOK.with(|hook| {
                        assert!(hook.borrow().is_none());
                        *hook.borrow_mut() = Some(Box::new(move || {
                            reserved_tx.send(()).unwrap();
                            release_rx
                                .recv_timeout(RENDEZVOUS_TIMEOUT)
                                .expect("owner releases every reserved sender");
                        }));
                    });
                    let payload = [u8::try_from(ordinal).unwrap(); 8];
                    result_tx
                        .send(cloned_sink.send(v4(REMOTE), &payload))
                        .unwrap();
                });
            }
            drop(reserved_tx);
            drop(result_tx);
            for _ in 0..SENDERS {
                reserved_rx
                    .recv_timeout(RENDEZVOUS_TIMEOUT)
                    .expect("every clone reserves before owner destruction");
            }
            drop(table);
            for release in releases {
                release.send(()).unwrap();
            }
            for _ in 0..SENDERS {
                assert_eq!(
                    result_rx
                        .recv_timeout(RENDEZVOUS_TIMEOUT)
                        .expect("every clone finishes after owner destruction"),
                    UdpResponseSendOutcome::Closed
                );
            }
        });
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(
            sink.send(v4(REMOTE), b"late"),
            UdpResponseSendOutcome::StaleGeneration
        );
        assert_eq!(budget.reserved_bytes(), 0);
    });
}
