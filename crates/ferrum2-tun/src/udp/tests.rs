use super::*;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

fn v4(address: &str) -> SocketAddr {
    address.parse().expect("IPv4 socket address")
}

fn v6(address: &str) -> SocketAddr {
    address.parse().expect("IPv6 socket address")
}

fn endpoints(source_port: u16, target: &str) -> UdpDatagramEndpoints {
    UdpDatagramEndpoints::new(v4(&format!("198.18.0.1:{source_port}")), v4(target))
}

fn table(
    capacity: usize,
    idle_millis: u64,
    filtering: UdpFiltering,
    generation: u64,
) -> (UdpTable, mpsc::Receiver<UdpCandidate>, Arc<AtomicUsize>) {
    let wakes = Arc::new(AtomicUsize::new(0));
    let wake_count = Arc::clone(&wakes);
    let (table, candidates) = UdpTable::with_options(
        capacity,
        Duration::from_millis(idle_millis),
        filtering,
        generation,
        OwnerWake::new(move || {
            wake_count.fetch_add(1, Ordering::Relaxed);
        }),
    );
    (table, candidates, wakes)
}

#[test]
fn udp_filtering_defaults_to_endpoint_independent() {
    assert_eq!(UdpFiltering::default(), UdpFiltering::EndpointIndependent);
}

async fn commit(table: &mut UdpTable, candidate: UdpCandidate, now_millis: i64) -> UdpAssociation {
    let task = tokio::spawn(candidate.commit_association());
    tokio::task::yield_now().await;
    assert_eq!(table.process_one_control(now_millis, true), Some(true));
    task.await.expect("commit task").expect("association")
}

#[test]
fn invalid_admission_endpoints_emit_exact_source_or_destination_reason() {
    let (mut table, _candidates, _) = table(1, 60_000, UdpFiltering::AddressDependent, 1);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&observed);
    table.set_event_sink(TunEventSink::new(move |event| {
        captured.lock().expect("UDP events").push(event);
    }));
    let cases = [
        (
            UdpDatagramEndpoints::new(v4("0.0.0.0:10000"), v4("192.0.2.1:53")),
            TunRejectReason::InvalidSource,
        ),
        (
            UdpDatagramEndpoints::new(v4("198.18.0.1:0"), v4("192.0.2.1:53")),
            TunRejectReason::InvalidSource,
        ),
        (
            UdpDatagramEndpoints::new(v4("198.18.0.1:10000"), v4("192.0.2.1:0")),
            TunRejectReason::InvalidDestination,
        ),
        (
            UdpDatagramEndpoints::new(v4("198.18.0.1:10000"), v4("224.0.0.1:53")),
            TunRejectReason::InvalidDestination,
        ),
        (
            UdpDatagramEndpoints::new(v4("198.18.0.1:10000"), v6("[2001:db8::1]:53")),
            TunRejectReason::InvalidDestination,
        ),
    ];

    for (tuple, reason) in cases {
        observed.lock().expect("UDP events").clear();
        assert_eq!(table.admit(tuple, b"q", 1_392, 0, true), Admission::Dropped);
        assert_eq!(
            *observed.lock().expect("UDP events"),
            [TunEvent::PacketRejected(reason)]
        );
        assert_eq!(table.active_entries(), 0);
    }
}

#[tokio::test]
async fn c2_response_backpressure_preserves_current_event_and_does_not_consume_next() {
    let (mut table, mut candidates, _) = table(1, 60_000, UdpFiltering::AddressDependent, 1);
    assert_eq!(
        table.admit(endpoints(10_000, "192.0.2.1:53"), b"q", 1_392, 0, true),
        Admission::Provisional
    );
    let association = commit(&mut table, candidates.recv().await.unwrap(), 1).await;
    assert_eq!(
        association.authorize_peer(v4("192.0.2.1:1").ip()),
        UdpPeerAuthorization::Authorized
    );
    let sink = association.response_sink();
    assert_eq!(
        sink.send(v4("192.0.2.1:53"), b"first"),
        UdpResponseSendOutcome::Queued
    );
    assert_eq!(
        sink.send(v4("192.0.2.1:5353"), b"second"),
        UdpResponseSendOutcome::Queued
    );

    let mut observed = Vec::new();
    assert_eq!(
        table.process_one_response(2, |tuple, payload| {
            observed.push((tuple.target(), payload.to_vec()));
            InjectOutcome::Backpressured
        }),
        ResponseProcessOutcome::Deferred
    );
    assert!(table.has_pending_response());
    assert_eq!(observed, [(v4("192.0.2.1:53"), b"first".to_vec())]);
    assert_eq!(
        table.process_one_response(3, |tuple, payload| {
            observed.push((tuple.target(), payload.to_vec()));
            InjectOutcome::Injected
        }),
        ResponseProcessOutcome::Injected
    );
    assert!(!table.has_pending_response());
    assert_eq!(
        table.process_one_response(4, |tuple, payload| {
            observed.push((tuple.target(), payload.to_vec()));
            InjectOutcome::Injected
        }),
        ResponseProcessOutcome::Injected
    );
    assert_eq!(
        observed,
        [
            (v4("192.0.2.1:53"), b"first".to_vec()),
            (v4("192.0.2.1:53"), b"first".to_vec()),
            (v4("192.0.2.1:5353"), b"second".to_vec()),
        ]
    );
}

#[tokio::test]
async fn delayed_then_rejected_response_counts_one_terminal_drop_and_reject() {
    let (mut table, mut candidates, _) = table(1, 60_000, UdpFiltering::EndpointIndependent, 1);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&observed);
    table.set_event_sink(TunEventSink::new(move |event| {
        captured.lock().expect("UDP events").push(event);
    }));
    assert_eq!(
        table.admit(endpoints(10_000, "192.0.2.1:53"), b"q", 1_392, 0, true),
        Admission::Provisional
    );
    let association = commit(&mut table, candidates.recv().await.unwrap(), 1).await;
    let sink = association.response_sink();
    assert_eq!(
        sink.send(v4("192.0.2.1:53"), b"response"),
        UdpResponseSendOutcome::Queued
    );
    observed.lock().expect("UDP events").clear();

    assert_eq!(
        table.process_one_response(2, |_, _| InjectOutcome::Backpressured),
        ResponseProcessOutcome::Deferred
    );
    assert_eq!(
        table.process_one_response(3, |_, _| {
            InjectOutcome::Rejected(TunRejectReason::InvalidIpChecksum)
        }),
        ResponseProcessOutcome::Dropped(UdpResponseDropReason::InjectionRejected)
    );
    assert_eq!(
        *observed.lock().expect("UDP events"),
        [
            TunEvent::UdpPendingResponses(1),
            TunEvent::UdpPendingResponses(0),
            TunEvent::UdpResponseDropped(UdpResponseDropReason::InjectionRejected),
            TunEvent::PacketRejected(TunRejectReason::InvalidIpChecksum),
        ]
    );
}

#[tokio::test]
async fn response_queue_full_emits_specific_and_generic_reject_once() {
    let (mut table, mut candidates, _) = table(1, 60_000, UdpFiltering::AddressDependent, 1);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&observed);
    table.set_event_sink(TunEventSink::new(move |event| {
        captured.lock().expect("UDP events").push(event);
    }));
    assert_eq!(
        table.admit(endpoints(10_000, "192.0.2.1:53"), b"q", 1_392, 0, true),
        Admission::Provisional
    );
    let association = commit(&mut table, candidates.recv().await.unwrap(), 1).await;
    assert_eq!(
        association.authorize_peer(v4("192.0.2.1:1").ip()),
        UdpPeerAuthorization::Authorized
    );
    let sink = association.response_sink();
    for index in 0..RESPONSE_QUEUE_PACKETS_PER_ASSOCIATION {
        assert_eq!(
            sink.send(v4("192.0.2.1:53"), &[u8::try_from(index).unwrap()]),
            UdpResponseSendOutcome::Queued
        );
    }
    observed.lock().expect("UDP events").clear();
    assert_eq!(
        sink.send(v4("192.0.2.1:53"), b"full"),
        UdpResponseSendOutcome::QueueFull
    );
    assert_eq!(
        *observed.lock().expect("UDP events"),
        [
            TunEvent::UdpResponseQueueFull,
            TunEvent::UdpResponseDropped(UdpResponseDropReason::QueueFull),
            TunEvent::PacketRejected(TunRejectReason::UdpQueueFull),
        ]
    );
}

#[tokio::test]
async fn filtered_response_counts_one_terminal_drop_and_reject() {
    let (mut table, mut candidates, _) = table(1, 60_000, UdpFiltering::AddressDependent, 1);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&observed);
    table.set_event_sink(TunEventSink::new(move |event| {
        captured.lock().expect("UDP events").push(event);
    }));
    assert_eq!(
        table.admit(endpoints(10_000, "192.0.2.1:53"), b"q", 1_392, 0, true),
        Admission::Provisional
    );
    let association = commit(&mut table, candidates.recv().await.unwrap(), 1).await;
    observed.lock().expect("UDP events").clear();

    assert_eq!(
        association.send_response(v4("203.0.113.1:53"), b"filtered"),
        UdpResponseSendOutcome::Filtered
    );
    assert_eq!(
        *observed.lock().expect("UDP events"),
        [
            TunEvent::UdpResponseFiltered,
            TunEvent::UdpResponseDropped(UdpResponseDropReason::Filtered),
            TunEvent::PacketRejected(TunRejectReason::UdpResponseFiltered),
        ]
    );
}

#[tokio::test]
async fn stale_response_counts_one_terminal_drop_and_reject() {
    let (mut table, mut candidates, _) = table(1, 60_000, UdpFiltering::EndpointIndependent, 1);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&observed);
    table.set_event_sink(TunEventSink::new(move |event| {
        captured.lock().expect("UDP events").push(event);
    }));
    assert_eq!(
        table.admit(endpoints(10_000, "192.0.2.1:53"), b"q", 1_392, 0, true),
        Admission::Provisional
    );
    let association = commit(&mut table, candidates.recv().await.unwrap(), 1).await;
    assert_eq!(
        association.send_response(v4("203.0.113.1:53"), b"stale"),
        UdpResponseSendOutcome::Queued
    );
    table.set_session_epoch_for_test(2);
    observed.lock().expect("UDP events").clear();

    assert_eq!(
        table.process_one_response(2, |_, _| InjectOutcome::Injected),
        ResponseProcessOutcome::Dropped(UdpResponseDropReason::StaleGeneration)
    );
    assert_eq!(
        *observed.lock().expect("UDP events"),
        [
            TunEvent::UdpStaleGeneration,
            TunEvent::UdpResponseDropped(UdpResponseDropReason::StaleGeneration),
            TunEvent::PacketRejected(TunRejectReason::StaleGeneration),
        ]
    );
}

#[tokio::test]
async fn reset_consumes_pending_response_once_before_table_drop() {
    let (mut table, mut candidates, _) = table(1, 60_000, UdpFiltering::EndpointIndependent, 1);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&observed);
    table.set_event_sink(TunEventSink::new(move |event| {
        captured.lock().expect("UDP events").push(event);
    }));
    assert_eq!(
        table.admit(endpoints(10_000, "192.0.2.1:53"), b"q", 1_392, 0, true),
        Admission::Provisional
    );
    let association = commit(&mut table, candidates.recv().await.unwrap(), 1).await;
    assert_eq!(
        association.send_response(v4("203.0.113.1:53"), b"pending"),
        UdpResponseSendOutcome::Queued
    );
    observed.lock().expect("UDP events").clear();
    assert_eq!(
        table.process_one_response(2, |_, _| InjectOutcome::Backpressured),
        ResponseProcessOutcome::Deferred
    );

    table.invalidate_session(2, UdpResponseDropReason::SessionReset);
    let after_reset = observed.lock().expect("UDP events").clone();
    assert_eq!(
        after_reset
            .iter()
            .filter(|event| matches!(event, TunEvent::UdpResponseDropped(_)))
            .count(),
        1
    );
    assert_eq!(
        after_reset
            .iter()
            .filter(|event| matches!(event, TunEvent::PacketRejected(_)))
            .count(),
        1
    );
    assert_eq!(
        after_reset
            .iter()
            .filter_map(|event| match event {
                TunEvent::UdpPendingResponses(pending) => Some(*pending),
                _ => None,
            })
            .collect::<Vec<_>>(),
        [1, 0]
    );
    assert!(after_reset.contains(&TunEvent::UdpResponseDropped(
        UdpResponseDropReason::SessionReset
    )));
    assert!(after_reset.contains(&TunEvent::PacketRejected(TunRejectReason::StaleGeneration)));

    drop(table);
    assert_eq!(
        *observed.lock().expect("UDP events"),
        after_reset,
        "UdpTable::drop must not recount a response consumed by reset"
    );
}

#[tokio::test]
async fn table_drop_counts_pending_response_once_as_shutdown() {
    let (mut table, mut candidates, _) = table(1, 60_000, UdpFiltering::EndpointIndependent, 1);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&observed);
    table.set_event_sink(TunEventSink::new(move |event| {
        captured.lock().expect("UDP events").push(event);
    }));
    assert_eq!(
        table.admit(endpoints(10_000, "192.0.2.1:53"), b"q", 1_392, 0, true),
        Admission::Provisional
    );
    let association = commit(&mut table, candidates.recv().await.unwrap(), 1).await;
    assert_eq!(
        association.send_response(v4("203.0.113.1:53"), b"pending"),
        UdpResponseSendOutcome::Queued
    );
    observed.lock().expect("UDP events").clear();
    assert_eq!(
        table.process_one_response(2, |_, _| InjectOutcome::Backpressured),
        ResponseProcessOutcome::Deferred
    );

    drop(table);
    let shutdown = observed.lock().expect("UDP events").clone();
    assert_eq!(
        shutdown
            .iter()
            .filter(|event| matches!(event, TunEvent::UdpResponseDropped(_)))
            .count(),
        1
    );
    assert_eq!(
        shutdown
            .iter()
            .filter(|event| matches!(event, TunEvent::PacketRejected(_)))
            .count(),
        1
    );
    assert!(shutdown.contains(&TunEvent::UdpResponseDropped(
        UdpResponseDropReason::Shutdown
    )));
    assert!(shutdown.contains(&TunEvent::PacketRejected(
        TunRejectReason::UdpResponseClosed
    )));
    assert_eq!(
        shutdown
            .iter()
            .filter_map(|event| match event {
                TunEvent::UdpPendingResponses(pending) => Some(*pending),
                _ => None,
            })
            .collect::<Vec<_>>(),
        [1, 0]
    );
}

#[tokio::test]
async fn c8_lifecycle_control_is_reliable_when_data_queues_are_congested() {
    let (mut table, mut candidates, wakes) = table(1, 60_000, UdpFiltering::EndpointIndependent, 1);
    let key = endpoints(10_001, "192.0.2.1:53");
    assert_eq!(
        table.admit(key, b"first", 1_392, 0, true),
        Admission::Provisional
    );
    let association = commit(&mut table, candidates.recv().await.unwrap(), 1).await;

    for _ in 1..DATAGRAM_QUEUE_PACKETS {
        assert_eq!(table.admit(key, b"data", 1_392, 2, true), Admission::Mapped);
    }
    assert_eq!(
        table.admit(key, b"full", 1_392, 2, true),
        Admission::Dropped
    );
    let sink = association.response_sink();
    let mut queued = 0;
    loop {
        match sink.send(v4("203.0.113.1:53"), b"response") {
            UdpResponseSendOutcome::Queued => queued += 1,
            UdpResponseSendOutcome::QueueFull => break,
            other => panic!("unexpected response outcome: {other:?}"),
        }
    }
    assert!(queued > 0);
    drop(association);
    assert_eq!(table.process_one_control(3, true), Some(false));
    assert_eq!(table.active_associations(), 0);
    assert_eq!(table.active_entries(), 0);
    assert!(wakes.load(Ordering::Relaxed) >= queued + 2);
}

#[tokio::test]
async fn c9_candidate_timeout_is_fixed_five_seconds_and_separate_from_idle() {
    let (mut table, mut candidates, _) = table(1, 60_000, UdpFiltering::AddressDependent, 9);
    assert_eq!(
        table.admit(endpoints(10_002, "192.0.2.1:53"), b"q", 1_392, 10, true),
        Admission::Provisional
    );
    let candidate = candidates.recv().await.unwrap();
    assert_eq!(table.expire(5_009), ExpireOutcome::default());
    assert_eq!(table.provisional_candidates(), 1);
    assert_eq!(
        table.expire(5_010),
        ExpireOutcome {
            candidates: 1,
            associations: 0,
        }
    );
    assert_eq!(table.active_entries(), 0);
    assert!(matches!(
        candidate.commit_association().await,
        Err(UdpCommitError::Rejected)
    ));

    assert_eq!(
        table.admit(
            endpoints(10_002, "192.0.2.2:53"),
            b"new",
            1_392,
            6_000,
            true,
        ),
        Admission::Provisional
    );
    let association = commit(&mut table, candidates.recv().await.unwrap(), 6_001).await;
    assert_eq!(table.expire(11_001), ExpireOutcome::default());
    assert_eq!(
        table.active_associations(),
        1,
        "association idle deadline is not the candidate deadline"
    );
    drop(association);
    table.process_one_control(11_002, true);
}

#[tokio::test]
async fn c10_hash_index_free_list_counts_and_generation_deadlines_are_exact() {
    let (mut table, mut candidates, _) = table(1, 10, UdpFiltering::EndpointIndependent, 3);
    let first = endpoints(10_003, "192.0.2.1:53");
    assert_eq!(
        table.admit(first, b"one", 1_392, 0, true),
        Admission::Provisional
    );
    assert_eq!(table.index_len_for_test(), 1);
    assert_eq!(table.free_slots_for_test(), 0);
    assert_eq!(table.next_deadline_millis(), Some(5_000));
    let mut association = commit(&mut table, candidates.recv().await.unwrap(), 1).await;
    assert_eq!(table.next_deadline_millis(), Some(11));
    assert_eq!(table.active_associations(), 1);
    assert_eq!(table.provisional_candidates(), 0);
    assert_eq!(
        table.admit(endpoints(10_004, "192.0.2.2:53"), b"new", 1_392, 2, true),
        Admission::Dropped,
        "capacity pressure drops the new source and never evicts live state"
    );
    assert_eq!(table.active_associations(), 1);

    drop(association.receive().await.expect("first datagram"));
    assert_eq!(
        table.admit(first, b"refresh", 1_392, 8, true),
        Admission::Mapped
    );
    assert_eq!(
        table.next_deadline_millis(),
        Some(18),
        "deadline lookup lazily removes the superseded association entry"
    );
    assert_eq!(
        table.expire(11),
        ExpireOutcome::default(),
        "generation-checked stale heap deadline is ignored"
    );
    assert_eq!(table.active_associations(), 1);
    assert_eq!(
        table.expire(18),
        ExpireOutcome {
            candidates: 0,
            associations: 1,
        }
    );
    assert_eq!(table.active_entries(), 0);
    assert_eq!(table.index_len_for_test(), 0);
    assert_eq!(table.free_slots_for_test(), 1);
    assert_eq!(table.next_deadline_millis(), None);
    drop(association);

    assert_eq!(
        table.admit(
            endpoints(10_004, "192.0.2.2:53"),
            b"reused",
            1_392,
            19,
            true,
        ),
        Admission::Provisional
    );
    assert_eq!(table.active_entries(), 1);
    drop(candidates.recv().await.unwrap());
    while table.process_one_control(20, true).is_some() {}
    assert_eq!(table.active_entries(), 0);
}

#[tokio::test]
async fn deadline_heap_stays_capacity_bounded_under_high_rate_refresh() {
    let capacity = 4;
    let (mut table, mut candidates, _) =
        table(capacity, 100, UdpFiltering::EndpointIndependent, 31);
    assert_eq!(
        table.admit(endpoints(10_031, "192.0.2.1:53"), b"q", 1_392, 0, true),
        Admission::Provisional
    );
    let association = commit(&mut table, candidates.recv().await.unwrap(), 1).await;
    let sink = association.response_sink();

    for now_millis in 2..=4_097 {
        assert_eq!(
            sink.send(v4("192.0.2.1:53"), b"response"),
            UdpResponseSendOutcome::Queued
        );
        assert_eq!(
            table.process_one_response(now_millis, |_, _| InjectOutcome::Injected),
            ResponseProcessOutcome::Injected
        );
        assert!(
            table.deadline_entry_count() <= capacity * 2,
            "lazy refresh entries must remain bounded by configured capacity"
        );
    }

    assert_eq!(table.next_deadline_millis(), Some(4_197));
    assert_eq!(table.expire(4_196), ExpireOutcome::default());
    assert_eq!(
        table.expire(4_197),
        ExpireOutcome {
            candidates: 0,
            associations: 1,
        }
    );
    assert_eq!(table.deadline_entry_count(), 0);
    drop(association);
}

#[tokio::test]
async fn expired_close_notice_is_an_idempotent_lifecycle_noop() {
    let (mut table, mut candidates, _) = table(1, 10, UdpFiltering::EndpointIndependent, 41);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&observed);
    table.set_event_sink(TunEventSink::new(move |event| {
        captured.lock().expect("UDP events").push(event);
    }));
    assert_eq!(
        table.admit(
            endpoints(10_005, "192.0.2.1:53"),
            b"request",
            1_392,
            0,
            true,
        ),
        Admission::Provisional
    );
    let association = commit(&mut table, candidates.recv().await.unwrap(), 1).await;

    drop(association);
    assert_eq!(
        table.expire(11),
        ExpireOutcome {
            candidates: 0,
            associations: 1,
        }
    );
    observed.lock().expect("UDP events").clear();

    assert_eq!(table.process_one_control(12, true), Some(false));
    assert!(
        observed.lock().expect("UDP events").is_empty(),
        "an already-expired close cannot reject work or a packet"
    );
}

#[tokio::test]
async fn stale_commit_notice_remains_counted_and_fail_closed() {
    let (mut table, mut candidates, _) = table(1, 60_000, UdpFiltering::EndpointIndependent, 41);
    let first = endpoints(10_005, "192.0.2.1:53");
    let observed = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&observed);
    table.set_event_sink(TunEventSink::new(move |event| {
        captured.lock().expect("UDP events").push(event);
    }));
    assert_eq!(
        table.admit(first, b"request", 1_392, 0, true),
        Admission::Provisional
    );
    let commit = tokio::spawn(candidates.recv().await.unwrap().commit_association());
    tokio::task::yield_now().await;
    table.invalidate_session(42, UdpResponseDropReason::SessionReset);
    assert_eq!(
        table.admit(first, b"fresh", 1_392, 1, true),
        Admission::Provisional
    );
    let fresh_candidate = candidates.recv().await.unwrap();
    observed.lock().expect("UDP events").clear();

    assert_eq!(table.process_one_control(2, true), Some(false));
    assert_eq!(
        *observed.lock().expect("UDP events"),
        [
            TunEvent::UdpStaleGeneration,
            TunEvent::PacketRejected(TunRejectReason::StaleGeneration),
        ]
    );
    assert!(matches!(
        commit.await.expect("commit task"),
        Err(UdpCommitError::Rejected)
    ));
    assert_eq!(
        table.provisional_candidates(),
        1,
        "the old commit cannot mutate the reused slot"
    );
    drop(fresh_candidate);
    assert_eq!(table.process_one_control(3, true), Some(false));
    assert_eq!(table.active_entries(), 0);
}

#[tokio::test]
async fn c17_stale_generation_handles_cannot_commit_close_or_inject() {
    let (mut table, mut candidates, _) = table(1, 60_000, UdpFiltering::EndpointIndependent, 41);
    let first = endpoints(10_005, "192.0.2.1:53");
    assert_eq!(
        table.admit(first, b"old", 1_392, 0, true),
        Admission::Provisional
    );
    let stale_candidate = candidates.recv().await.unwrap();
    table.invalidate_session(42, UdpResponseDropReason::SessionReset);
    assert!(matches!(
        stale_candidate.commit_association().await,
        Err(UdpCommitError::Rejected)
    ));

    assert_eq!(
        table.admit(first, b"new", 1_392, 1, true),
        Admission::Provisional
    );
    let association = commit(&mut table, candidates.recv().await.unwrap(), 2).await;
    let stale_sink = association.response_sink();
    assert_eq!(
        stale_sink.send(v4("203.0.113.1:53"), b"queued"),
        UdpResponseSendOutcome::Queued
    );
    table.invalidate_session(43, UdpResponseDropReason::SessionReset);
    assert_eq!(
        stale_sink.send(v4("203.0.113.1:53"), b"late"),
        UdpResponseSendOutcome::StaleGeneration
    );
    assert_eq!(
        table.process_one_response(3, |_, _| InjectOutcome::Injected),
        ResponseProcessOutcome::Idle,
        "restart clears queued old-generation responses"
    );

    assert_eq!(
        table.admit(first, b"fresh", 1_392, 4, true),
        Admission::Provisional
    );
    drop(association);
    while table.process_one_control(5, true).is_some() {}
    assert_eq!(
        table.provisional_candidates(),
        1,
        "stale close cannot remove a reused slot"
    );
    drop(candidates.recv().await.unwrap());
    while table.process_one_control(6, true).is_some() {}
    assert_eq!(table.active_entries(), 0);
}

#[tokio::test]
async fn c19_eim_adf_eif_and_actual_response_source_are_enforced() {
    let (mut adf, mut candidates, _) = table(3, 60_000, UdpFiltering::AddressDependent, 1);
    let source = v4("198.18.0.1:10");
    let first_target = v4("192.0.2.1:53");
    let second_target = v4("198.51.100.2:5353");
    assert_eq!(
        adf.admit(
            UdpDatagramEndpoints::new(source, first_target),
            b"one",
            1_392,
            0,
            true,
        ),
        Admission::Provisional
    );
    assert_eq!(
        adf.admit(
            UdpDatagramEndpoints::new(source, second_target),
            b"two",
            1_392,
            1,
            true,
        ),
        Admission::CandidateQueued,
        "different targets share one source-keyed candidate"
    );
    assert_eq!(adf.provisional_candidates(), 1);
    let mut association = commit(&mut adf, candidates.recv().await.unwrap(), 2).await;
    assert_eq!(association.source(), source);
    assert_eq!(association.first_target(), first_target);
    assert_eq!(association.receive().await.unwrap().target(), first_target);
    assert_eq!(association.receive().await.unwrap().target(), second_target);

    let other_v4_source = v4("198.18.0.1:11");
    let v6_source = v6("[2001:db8::10]:10");
    assert_eq!(
        adf.admit(
            UdpDatagramEndpoints::new(other_v4_source, first_target),
            b"other-port",
            1_392,
            2,
            true
        ),
        Admission::Provisional,
        "a different local source port is a distinct association key"
    );
    assert_eq!(
        adf.admit(
            UdpDatagramEndpoints::new(v6_source, v6("[2001:db8::20]:53")),
            b"v6",
            1_392,
            2,
            true
        ),
        Admission::Provisional,
        "IPv4 and IPv6 local sources are distinct association keys"
    );
    let other_v4 = candidates.recv().await.unwrap();
    let other_v6 = candidates.recv().await.unwrap();
    assert_eq!(other_v4.source(), other_v4_source);
    assert_eq!(other_v6.source(), v6_source);
    drop(other_v4);
    drop(other_v6);
    while adf.process_one_control(2, true).is_some() {}
    assert_eq!(adf.active_associations(), 1);

    let allowed_ip = first_target.ip();
    assert_eq!(
        association.authorize_peer(allowed_ip),
        UdpPeerAuthorization::Authorized
    );
    let sink = association.response_sink();
    let actual_source = v4("192.0.2.1:9999");
    assert_eq!(
        sink.send(actual_source, b"allowed"),
        UdpResponseSendOutcome::Queued
    );
    assert_eq!(
        sink.send(v4("203.0.113.9:53"), b"filtered"),
        UdpResponseSendOutcome::Filtered
    );
    assert_eq!(
        sink.send(v6("[2001:db8::1]:53"), b"mixed"),
        UdpResponseSendOutcome::InvalidSource
    );
    assert_eq!(
        sink.send(v4("224.0.0.1:53"), b"multicast"),
        UdpResponseSendOutcome::InvalidSource
    );
    assert_eq!(
        sink.send(v4("0.0.0.0:53"), b"unspecified"),
        UdpResponseSendOutcome::InvalidSource
    );
    let mut injected = None;
    assert_eq!(
        adf.process_one_response(3, |tuple, payload| {
            injected = Some((tuple, payload.to_vec()));
            InjectOutcome::Injected
        }),
        ResponseProcessOutcome::Injected
    );
    assert_eq!(
        injected,
        Some((
            UdpDatagramEndpoints::new(source, actual_source),
            b"allowed".to_vec()
        ))
    );

    for index in 0..(UDP_ADF_PEER_CAP - 1) {
        let peer = IpAddr::V4(std::net::Ipv4Addr::new(
            10,
            u8::try_from(index / 254).unwrap(),
            u8::try_from(index % 254 + 1).unwrap(),
            1,
        ));
        assert_eq!(
            association.authorize_peer(peer),
            UdpPeerAuthorization::Authorized
        );
    }
    assert_eq!(
        association.authorize_peer(v4("11.0.0.1:1").ip()),
        UdpPeerAuthorization::LimitReached,
        "peer cap drops new authorization without evicting old peers"
    );
    assert_eq!(
        sink.send(actual_source, b"still-authorized"),
        UdpResponseSendOutcome::Queued
    );

    assert_eq!(
        adf.admit(
            UdpDatagramEndpoints::new(source, v6("[2001:db8::1]:53")),
            b"mixed",
            1_392,
            4,
            true
        ),
        Admission::Dropped
    );
    assert_eq!(
        adf.admit(
            UdpDatagramEndpoints::new(source, v4("224.0.0.1:53")),
            b"multicast",
            1_392,
            4,
            true
        ),
        Admission::Dropped
    );

    let (mut eif, mut eif_candidates, _) = table(1, 60_000, UdpFiltering::EndpointIndependent, 7);
    assert_eq!(
        eif.admit(endpoints(11, "192.0.2.10:53"), b"q", 1_392, 0, true),
        Admission::Provisional
    );
    let eif_association = commit(&mut eif, eif_candidates.recv().await.unwrap(), 1).await;
    assert_eq!(
        eif_association.send_response(v4("203.0.113.77:65000"), b"unseen"),
        UdpResponseSendOutcome::Queued
    );
    assert_eq!(
        eif_association.send_response(v6("[2001:db8::77]:65000"), b"mixed"),
        UdpResponseSendOutcome::InvalidSource
    );
}

#[test]
fn adf_peer_reservations_are_bounded_and_authorize_only_on_commit() {
    fn handle(filtering: UdpFiltering) -> UdpPeerPolicyHandle {
        UdpPeerPolicyHandle {
            inner: Arc::new(PeerPolicy::new(filtering, "198.18.0.1".parse().unwrap())),
        }
    }

    fn reserved(outcome: UdpPeerReservationOutcome) -> UdpPeerReservation {
        match outcome {
            UdpPeerReservationOutcome::Reserved(reservation) => reservation,
            _ => panic!("expected a peer reservation"),
        }
    }

    let policy = handle(UdpFiltering::AddressDependent);
    let peer = "192.0.2.1".parse().unwrap();
    let first = reserved(policy.reserve_peer(peer));
    let second = reserved(policy.reserve_peer(peer));
    assert_eq!(policy.inner.allows(v4("192.0.2.1:53")), Ok(false));
    assert_eq!(first.commit(), UdpPeerAuthorization::Authorized);
    assert_eq!(policy.inner.allows(v4("192.0.2.1:5353")), Ok(true));
    assert_eq!(second.commit(), UdpPeerAuthorization::AlreadyAuthorized);
    assert!(matches!(
        policy.reserve_peer(peer),
        UdpPeerReservationOutcome::AlreadyAuthorized
    ));

    let bounded = handle(UdpFiltering::AddressDependent);
    let mut reservations = Vec::with_capacity(UDP_ADF_PEER_CAP);
    for index in 0..UDP_ADF_PEER_CAP {
        let peer = IpAddr::V4(std::net::Ipv4Addr::new(
            10,
            u8::try_from(index / 254).unwrap(),
            u8::try_from(index % 254 + 1).unwrap(),
            1,
        ));
        reservations.push(reserved(bounded.reserve_peer(peer)));
    }
    assert!(matches!(
        bounded.reserve_peer("11.0.0.1".parse().unwrap()),
        UdpPeerReservationOutcome::LimitReached
    ));
    drop(reservations.pop());
    let replacement = reserved(bounded.reserve_peer("11.0.0.1".parse().unwrap()));
    assert_eq!(replacement.commit(), UdpPeerAuthorization::Authorized);
    drop(reservations);

    assert!(matches!(
        policy.reserve_peer("224.0.0.1".parse().unwrap()),
        UdpPeerReservationOutcome::InvalidPeer
    ));
    assert!(matches!(
        policy.reserve_peer("2001:db8::1".parse().unwrap()),
        UdpPeerReservationOutcome::InvalidPeer
    ));
    assert!(matches!(
        handle(UdpFiltering::EndpointIndependent).reserve_peer("203.0.113.1".parse().unwrap()),
        UdpPeerReservationOutcome::NotRequired
    ));
}
