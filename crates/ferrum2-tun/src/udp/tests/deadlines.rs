use super::*;

#[tokio::test]
async fn same_tick_traffic_keeps_one_refresh_timer_and_expires_exactly() {
    let (mut table, mut candidates, _) = table(8, 100, UdpFiltering::EndpointIndependent, 1);
    let tuple = endpoints(10_001, "192.0.2.1:53");
    assert_eq!(
        table.admit(tuple, b"first", 1392, 0, true),
        Admission::Provisional
    );
    let mut association = commit(&mut table, candidates.recv().await.unwrap(), 0).await;
    drop(association.receive().await.unwrap());
    // Snapshot includes the stale candidate timer; same-tick traffic adds none.
    assert_eq!(table.next_deadline_millis(), Some(100));
    let timers = table.deadline_entry_count();
    for _ in 0..64 {
        assert_eq!(
            table.admit(tuple, b"same", 1392, 0, true),
            Admission::Mapped
        );
        assert_eq!(association.receive().await.unwrap().payload(), b"same");
        assert_eq!(
            association.send_response(tuple.target(), b"reply"),
            UdpResponseSendOutcome::Queued
        );
        assert_eq!(
            table.process_one_response(0, |actual, payload| {
                assert_eq!(actual, tuple);
                assert_eq!(payload, b"reply");
                InjectOutcome::Injected
            }),
            ResponseProcessOutcome::Injected
        );
        assert_eq!(
            table.deadline_entry_count(),
            timers,
            "unchanged deadline must not grow the heap"
        );
    }
    assert_eq!(
        table.admit(tuple, b"later", 1392, 1, true),
        Admission::Mapped
    );
    drop(association.receive().await.unwrap());
    assert_eq!(table.expire(100), ExpireOutcome::default());
    assert_eq!(table.next_deadline_millis(), Some(101));
    assert_eq!(
        table.expire(101),
        ExpireOutcome {
            candidates: 0,
            associations: 1
        }
    );
    assert!(association.receive().await.is_none());
}

#[tokio::test]
async fn equal_candidate_and_association_deadlines_survive_slot_and_session_reuse() {
    let (mut table, mut candidates, _) = table(1, 5000, UdpFiltering::EndpointIndependent, 1);
    let tuple = endpoints(10_001, "192.0.2.1:53");
    for generation in 1..=3 {
        for _ in 0..3 {
            assert_eq!(
                table.admit(tuple, b"first", 1392, 0, true),
                Admission::Provisional
            );
            let association = commit(&mut table, candidates.recv().await.unwrap(), 0).await;
            assert_eq!(table.next_deadline_millis(), Some(5000));
            assert_eq!(table.expire(4999), ExpireOutcome::default());
            drop(association);
            assert_eq!(table.process_one_control(0, true), Some(false));
        }
        // Reused slot has the identical deadline but a different GenerationId.
        assert_eq!(
            table.admit(tuple, b"live", 1392, 0, true),
            Admission::Provisional
        );
        let association = commit(&mut table, candidates.recv().await.unwrap(), 0).await;
        assert_eq!(table.expire(4999), ExpireOutcome::default());
        assert_eq!(
            table.expire(5000),
            ExpireOutcome {
                candidates: 0,
                associations: 1
            }
        );
        assert_eq!(
            association.send_response(tuple.target(), b"late"),
            UdpResponseSendOutcome::Closed
        );
        drop(association);
        table.invalidate_session(generation + 1, UdpResponseDropReason::SessionReset);
    }
}

#[tokio::test]
async fn saturated_refresh_keeps_the_existing_timer_live() {
    let (mut table, mut candidates, _) = table(1, 5000, UdpFiltering::EndpointIndependent, 1);
    let tuple = endpoints(10_001, "192.0.2.1:53");
    let start = i64::MAX - 5000;
    assert_eq!(
        table.admit(tuple, b"first", 1392, start, true),
        Admission::Provisional
    );
    let association = commit(&mut table, candidates.recv().await.unwrap(), start).await;
    for now in [start + 1, i64::MAX - 1] {
        assert_eq!(
            association.send_response(tuple.target(), b"reply"),
            UdpResponseSendOutcome::Queued
        );
        assert_eq!(
            table.process_one_response(now, |_, _| InjectOutcome::Injected),
            ResponseProcessOutcome::Injected
        );
        assert_eq!(table.next_deadline_millis(), Some(i64::MAX));
    }
    assert_eq!(table.expire(i64::MAX - 1), ExpireOutcome::default());
    assert_eq!(
        table.expire(i64::MAX),
        ExpireOutcome {
            candidates: 0,
            associations: 1
        }
    );
}
