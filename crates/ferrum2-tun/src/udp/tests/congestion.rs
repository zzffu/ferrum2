use super::*;

#[tokio::test]
async fn full_ingress_and_response_queues_do_not_copy_rejected_payloads() {
    let (mut table, mut candidates, _) = table(1, 60_000, UdpFiltering::EndpointIndependent, 1);
    let tuple = endpoints(10_000, "192.0.2.1:53");
    assert_eq!(
        table.admit(tuple, b"first", 128, 0, true),
        Admission::Provisional
    );
    let mut association = commit(&mut table, candidates.recv().await.unwrap(), 0).await;
    drop(association.receive().await.unwrap());
    for sequence in 0..DATAGRAM_QUEUE_PACKETS {
        assert_eq!(
            table.admit(tuple, &[sequence as u8], 128, 0, true),
            Admission::Mapped
        );
        assert_eq!(
            association.send_response(tuple.target(), &[sequence as u8]),
            UdpResponseSendOutcome::Queued
        );
    }
    // No await between snapshots: count this thread's actual Box payload copies,
    // not retained bytes (which would miss allocate-then-drop churn).
    let copies = PAYLOAD_COPIES.get();
    for _ in 0..64 {
        assert_eq!(
            table.admit(tuple, b"discard", 128, 0, true),
            Admission::Dropped
        );
        assert_eq!(
            association.send_response(tuple.target(), b"discard"),
            UdpResponseSendOutcome::QueueFull
        );
    }
    assert_eq!(PAYLOAD_COPIES.get() - copies, 0);
    for sequence in 0..DATAGRAM_QUEUE_PACKETS {
        assert_eq!(
            association.receive().await.unwrap().payload(),
            &[sequence as u8]
        );
        assert_eq!(
            table.process_one_response(0, |actual, payload| {
                assert_eq!(actual, tuple);
                assert_eq!(payload, &[sequence as u8]);
                InjectOutcome::Injected
            }),
            ResponseProcessOutcome::Injected
        );
    }
    let copies = PAYLOAD_COPIES.get();
    assert_eq!(
        table.admit(tuple, b"resumed", 128, 0, true),
        Admission::Mapped
    );
    assert_eq!(
        association.send_response(tuple.target(), b"resumed"),
        UdpResponseSendOutcome::Queued
    );
    assert_eq!(PAYLOAD_COPIES.get() - copies, 2);
    assert_eq!(association.receive().await.unwrap().payload(), b"resumed");
    assert_eq!(
        table.process_one_response(0, |_, payload| {
            assert_eq!(payload, b"resumed");
            InjectOutcome::Injected
        }),
        ResponseProcessOutcome::Injected
    );
}

#[tokio::test]
async fn budget_failure_releases_reserved_queue_slots_in_both_directions() {
    let (mut table, mut candidates, _) = table(1, 60_000, UdpFiltering::EndpointIndependent, 1);
    let budget =
        ferrum2_runtime::UdpBufferBudget::new_tun(64, ferrum2_runtime::OwnerRegistry::new());
    table.set_buffer_budget(budget.clone());
    let tuple = endpoints(10_000, "192.0.2.1:53");
    assert_eq!(
        table.admit(tuple, b"first", 128, 0, true),
        Admission::Provisional
    );
    let mut association = commit(&mut table, candidates.recv().await.unwrap(), 0).await;
    drop(association.receive().await.unwrap());
    let held = budget.reserve(64).unwrap();
    for _ in 0..64 {
        assert_eq!(table.admit(tuple, b"x", 128, 0, true), Admission::Dropped);
        assert_eq!(
            association.send_response(tuple.target(), b"x"),
            UdpResponseSendOutcome::QueueFull
        );
    }
    drop(held);
    for sequence in 0..DATAGRAM_QUEUE_PACKETS {
        assert_eq!(
            table.admit(tuple, &[sequence as u8], 128, 0, true),
            Admission::Mapped
        );
        assert_eq!(
            association.send_response(tuple.target(), &[sequence as u8]),
            UdpResponseSendOutcome::Queued
        );
    }
    for sequence in 0..DATAGRAM_QUEUE_PACKETS {
        assert_eq!(
            association.receive().await.unwrap().payload(),
            &[sequence as u8]
        );
        assert_eq!(
            table.process_one_response(0, |_, payload| {
                assert_eq!(payload, &[sequence as u8]);
                InjectOutcome::Injected
            }),
            ResponseProcessOutcome::Injected
        );
    }
    assert_eq!(budget.reserved_bytes(), 0);
}

#[tokio::test]
async fn validation_and_budget_errors_keep_precedence_over_congestion_and_disconnect() {
    let (mut table, mut candidates, _) = table(1, 60_000, UdpFiltering::EndpointIndependent, 1);
    let budget =
        ferrum2_runtime::UdpBufferBudget::new_tun(64, ferrum2_runtime::OwnerRegistry::new());
    table.set_buffer_budget(budget.clone());
    let tuple = endpoints(10_000, "192.0.2.1:53");
    assert_eq!(
        table.admit(tuple, b"first", 8, 0, true),
        Admission::Provisional
    );
    let mut association = commit(&mut table, candidates.recv().await.unwrap(), 0).await;
    drop(association.receive().await.unwrap());
    let (sender, events) = std::sync::mpsc::channel();
    table.set_event_sink(TunEventSink::new(move |event| {
        sender.send(event).expect("event receiver")
    }));
    let held = budget.reserve(64).unwrap();
    assert_eq!(
        table.admit(tuple, b"too long", 1, 0, true),
        Admission::Dropped
    );
    assert_eq!(
        events.try_iter().collect::<Vec<_>>(),
        [TunEvent::PacketRejected(
            TunRejectReason::InvalidTransportLength
        )]
    );
    let mut sink = association.response_sink();
    // Model receiver closure while the lease still passes its initial check.
    let (sender, receiver) = mpsc::channel(1);
    drop(receiver);
    sink.responses = sender;
    assert_eq!(
        sink.send(tuple.target(), b"too long!"),
        UdpResponseSendOutcome::PayloadTooLarge
    );
    assert_eq!(
        sink.send(v4("0.0.0.0:53"), b"x"),
        UdpResponseSendOutcome::InvalidSource
    );
    assert_eq!(
        sink.send(tuple.target(), b"x"),
        UdpResponseSendOutcome::QueueFull
    );
    drop(held);
    assert_eq!(
        sink.send(tuple.target(), b"x"),
        UdpResponseSendOutcome::Closed
    );
    assert_eq!(budget.reserved_bytes(), 0);
}
