use super::support::*;

#[tokio::test]
async fn tcp_egress_wave_reaches_every_ready_flow_before_starting_another_wave() {
    const FLOW_TOTAL: usize = 20;
    const BUFFER_BYTES: usize = 16 * 1024;
    let (mut stack, mut flows) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        1420,
        FLOW_TOTAL,
        BUFFER_BYTES,
        Duration::from_secs(60),
        Arc::new(AtomicUsize::new(0)),
    )
    .expect("multi-flow egress stack");
    let mut application_flows = Vec::with_capacity(FLOW_TOTAL);
    for offset in 0..FLOW_TOTAL {
        let (flow, _) = establish_ipv4_tcp_flow(
            &mut stack,
            &mut flows,
            10_000 + u16::try_from(offset).expect("test port offset"),
            i64::try_from(offset * 2).expect("test time"),
        );
        application_flows.push(flow);
    }

    let outbound = vec![0x5a; BUFFER_BYTES];
    for flow in &mut application_flows {
        flow.write_all(&outbound)
            .await
            .expect("fill every application bridge");
    }
    stack.next_flow_cursor = Some(0);
    assert!(stack.drive_tcp(), "first bridge quantum reaches 16 flows");
    assert!(
        stack.drive_tcp(),
        "second bridge quantum reaches tail flows"
    );
    assert!(
        stack
            .flows
            .iter()
            .flatten()
            .all(|entry| entry.owner.stack_buffered() == 0),
        "every application bridge reaches its smoltcp socket"
    );
    assert!(!stack.has_output());

    let validated_before = stack.validated_egress_packets();
    assert!(
        stack.poll_stack_once(Instant::from_millis(100)).worked,
        "one empty-queue poll builds an egress wave"
    );
    assert_eq!(
        stack.device.output_count, FLOW_TOTAL,
        "one smoltcp pass emits at most one packet for every ready socket"
    );
    assert_eq!(
        stack.validated_egress_packets() - validated_before,
        FLOW_TOTAL
    );

    let mut destination_ports = Vec::with_capacity(FLOW_TOTAL);
    assert_eq!(
        stack.flush_output(|packet| {
            destination_ports.push(u16::from_be_bytes([packet[22], packet[23]]));
            OutputSendOutcome::Sent
        }),
        OutputFlushOutcome::Sent
    );
    let validated_during_wave = stack.validated_egress_packets();
    let _ = stack.poll_stack_once(Instant::from_millis(101));
    assert_eq!(
        stack.validated_egress_packets(),
        validated_during_wave,
        "a partially drained wave cannot grow from the fixed socket scan origin"
    );
    assert_eq!(stack.device.output_count, FLOW_TOTAL - 1);

    while stack.has_output() {
        assert_eq!(
            stack.flush_output(|packet| {
                destination_ports.push(u16::from_be_bytes([packet[22], packet[23]]));
                OutputSendOutcome::Sent
            }),
            OutputFlushOutcome::Sent
        );
    }
    destination_ports.sort_unstable();
    assert_eq!(
        destination_ports,
        (10_000..10_000 + u16::try_from(FLOW_TOTAL).expect("flow total")).collect::<Vec<_>>(),
        "the first bounded wave reaches every flow exactly once"
    );
}

#[tokio::test]
async fn tcp_drive_alternates_rx_and_tx_at_the_262144_byte_buffer_limit() {
    const BUFFER_BYTES: usize = 262_144;
    const PAYLOAD_BYTES: usize = 1300;
    const SEGMENTS: usize = 28;
    const PER_FLOW_QUANTUM: usize = 16 * 1024;
    let (mut stack, mut flows) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        1420,
        1,
        BUFFER_BYTES,
        Duration::from_secs(60),
        Arc::new(AtomicUsize::new(0)),
    )
    .expect("maximum TCP buffer stack");
    let (mut flow, syn_ack) = establish_ipv4_tcp_flow(&mut stack, &mut flows, 10_000, 0);
    assert_eq!(stack.bridge_capacity, BUFFER_BYTES);

    let application_fill = vec![0x41; BUFFER_BYTES];
    assert_eq!(
        stack.flows[0]
            .as_mut()
            .expect("live flow")
            .owner
            .write_from_stack(&application_fill),
        BUFFER_BYTES,
        "the configured maximum is the actual receive bridge capacity"
    );
    let payload = vec![0x33; PAYLOAD_BYTES];
    let mut sequence = 1_u32;
    for segment in 0..SEGMENTS {
        let mut packet = ipv4_tcp_after_syn(&syn_ack, 0x18, &payload);
        packet[24..28].copy_from_slice(&sequence.to_be_bytes());
        repair_ipv4_tcp_checksum(&mut packet);
        assert!(stack.enqueue(&packet, true));
        stack.poll_quantum(Instant::from_millis(2 + segment as i64));
        assert!(matches!(
            stack.flush_output(|_| OutputSendOutcome::Sent),
            OutputFlushOutcome::Empty | OutputFlushOutcome::Sent
        ));
        sequence = sequence.wrapping_add(PAYLOAD_BYTES as u32);
    }

    let mut drained_fill = vec![0_u8; BUFFER_BYTES];
    flow.read_exact(&mut drained_fill)
        .await
        .expect("release the maximum receive bridge");
    assert_eq!(drained_fill, application_fill);
    let outbound = vec![0x5a; PER_FLOW_QUANTUM * 2];
    flow.write_all(&outbound)
        .await
        .expect("queue simultaneous application output");

    assert!(stack.drive_tcp(), "first turn services sustained RX");
    assert_eq!(
        stack.flows[0]
            .as_ref()
            .expect("live flow")
            .owner
            .stack_buffered(),
        outbound.len(),
        "RX may use one shared per-flow quantum"
    );
    assert!(stack.drive_tcp(), "second turn services TX");
    assert_eq!(
        stack.flows[0]
            .as_ref()
            .expect("live flow")
            .owner
            .stack_buffered(),
        PER_FLOW_QUANTUM,
        "sustained RX cannot consume the next TX-priority quantum"
    );
}

#[tokio::test]
async fn blocked_tcp_handler_does_not_make_the_owner_busy_loop() {
    const BUFFER_BYTES: usize = 4096;
    let (mut stack, mut flows) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        1420,
        1,
        BUFFER_BYTES,
        Duration::from_secs(60),
        Arc::new(AtomicUsize::new(0)),
    )
    .expect("blocked handler stack");
    let (_flow, syn_ack) = establish_ipv4_tcp_flow(&mut stack, &mut flows, 10_000, 0);
    assert_eq!(
        stack.flows[0]
            .as_mut()
            .expect("live flow")
            .owner
            .write_from_stack(&vec![0x41; BUFFER_BYTES]),
        BUFFER_BYTES
    );
    assert!(stack.enqueue(&ipv4_tcp_after_syn(&syn_ack, 0x18, b"blocked"), true));
    stack.poll_quantum(Instant::from_millis(2));
    assert!(matches!(
        stack.flush_output(|_| OutputSendOutcome::Sent),
        OutputFlushOutcome::Empty | OutputFlushOutcome::Sent
    ));

    for _ in 0..32 {
        assert!(
            !stack.poll_stack_once(Instant::from_millis(2)).worked,
            "a handler that neither reads nor writes creates no owner work"
        );
        assert!(
            stack.next_wait_duration(2) > Duration::ZERO,
            "blocked bridge state preserves a protocol deadline wait"
        );
    }
}

#[tokio::test]
async fn tcp_payload_fin_retransmission_and_final_ack_reap_without_reset() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let flow_count = Arc::new(AtomicUsize::new(0));
    let (mut stack, mut flows) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        1420,
        1,
        4096,
        Duration::from_secs(60),
        Arc::clone(&flow_count),
    )
    .expect("bounded stack");
    assert!(stack.enqueue(&ipv4_tcp(), true));
    stack.poll_quantum(Instant::ZERO);
    let mut syn_ack = Vec::new();
    assert_eq!(
        stack.flush_output(|packet| {
            syn_ack.extend_from_slice(packet);
            OutputSendOutcome::Sent
        }),
        OutputFlushOutcome::Sent
    );
    assert!(stack.enqueue(&ipv4_tcp_after_syn(&syn_ack, 0x10, &[]), true));
    stack.poll_quantum(Instant::from_millis(1));
    let mut flow = flows.try_recv().expect("established flow");
    assert!(flows.try_recv().is_err(), "one handshake publishes once");
    assert_eq!(flow_count.load(Ordering::Acquire), 1);

    let request = b"request";
    let remote_fin = ipv4_tcp_after_syn(&syn_ack, 0x19, request);
    assert!(stack.enqueue(&remote_fin, true));
    stack.poll_quantum(Instant::from_millis(2));
    let mut received = [0; 7];
    flow.read_exact(&mut received)
        .await
        .expect("request payload");
    assert_eq!(&received, request);
    assert_eq!(flow.read(&mut [0; 1]).await.expect("remote FIN"), 0);
    let mut reset = false;
    assert_ne!(
        stack.flush_output(|packet| {
            reset |= packet[33] & 0x04 != 0;
            OutputSendOutcome::Sent
        }),
        OutputFlushOutcome::Fatal
    );
    assert!(!reset, "remote payload+FIN is acknowledged without reset");

    let reply = b"reply";
    flow.write_all(reply).await.expect("half-close reply");
    let mut shutdown = Box::pin(flow.shutdown());
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut shutdown)
            .await
            .is_err(),
        "shutdown waits for the owner poll"
    );
    assert!(stack.drive_tcp(), "owner drains the reply and requests FIN");
    assert!(
        stack.flows[0].as_ref().expect("live flow").fin_started,
        "the socket close request is recorded"
    );
    assert!(!stack.has_output(), "socket.close itself emits no packet");
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut shutdown)
            .await
            .is_err(),
        "shutdown remains pending between socket.close and FIN egress"
    );
    assert!(
        stack.poll_stack_once(Instant::from_millis(3)).worked,
        "smoltcp emits the queued reply and FIN"
    );
    assert_eq!(
        stack.flush_output(|_| OutputSendOutcome::DroppedRingFull),
        OutputFlushOutcome::DroppedRingFull
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut shutdown)
            .await
            .is_err(),
        "a ring-full FIN drop cannot complete shutdown"
    );

    assert!(
        stack.poll_stack_once(Instant::from_millis(1_004)).worked,
        "smoltcp retransmits the dropped reply and FIN"
    );
    let mut reply_fin = Vec::new();
    assert_eq!(
        stack.flush_output(|packet| {
            reply_fin.extend_from_slice(packet);
            OutputSendOutcome::Sent
        }),
        OutputFlushOutcome::Sent
    );
    tokio::time::timeout(Duration::from_millis(10), &mut shutdown)
        .await
        .expect("successful adapter FIN send wakes shutdown")
        .expect("shutdown succeeds only after the adapter accepts FIN");
    assert_eq!(&reply_fin[40..], reply);
    assert_ne!(reply_fin[33] & 0x01, 0, "reply carries local FIN");
    assert_eq!(reply_fin[33] & 0x04, 0, "reply carries no reset");

    stack.poll_quantum(Instant::from_millis(3_005));
    let mut retransmission = Vec::new();
    assert_eq!(
        stack.flush_output(|packet| {
            retransmission.extend_from_slice(packet);
            OutputSendOutcome::Sent
        }),
        OutputFlushOutcome::Sent
    );
    assert_eq!(&retransmission[24..28], &reply_fin[24..28]);
    assert_eq!(&retransmission[40..], reply);
    assert_ne!(retransmission[33] & 0x01, 0, "retransmission retains FIN");
    assert_eq!(
        retransmission[33] & 0x04,
        0,
        "retransmission carries no reset"
    );

    let mut final_ack = ipv4_tcp_after_syn(&syn_ack, 0x10, &[]);
    final_ack[24..28].copy_from_slice(&(1_u32 + request.len() as u32 + 1).to_be_bytes());
    let reply_sequence = u32::from_be_bytes(reply_fin[24..28].try_into().expect("reply sequence"));
    final_ack[28..32].copy_from_slice(
        &reply_sequence
            .wrapping_add(reply.len() as u32 + 1)
            .to_be_bytes(),
    );
    repair_ipv4_tcp_checksum(&mut final_ack);
    assert!(stack.enqueue(&final_ack, true));
    stack.poll_quantum(Instant::from_millis(3_006));
    reset = false;
    assert_eq!(
        stack.flush_output(|packet| {
            reset |= packet[33] & 0x04 != 0;
            OutputSendOutcome::Sent
        }),
        OutputFlushOutcome::Empty
    );
    assert!(!reset, "final ACK produces no reset");
    assert_eq!(stack.live_tcp_flows(), 0);
    assert!(stack.flows[0].is_none(), "flow slot is reaped");
    assert!(stack.sockets.iter().next().is_none(), "socket is reaped");
    assert_eq!(
        stack
            .generations
            .current(0)
            .expect("recycled slot")
            .generation,
        1,
        "generation advances exactly once"
    );
    assert_eq!(flow_count.load(Ordering::Acquire), 0);

    drop(flow);
    stack.poll_quantum(Instant::from_millis(3_007));
    assert_eq!(
        stack.flush_output(|_| OutputSendOutcome::Sent),
        OutputFlushOutcome::Empty,
        "dropping a completed flow does not abort"
    );
}

#[tokio::test]
async fn tcp_shutdown_waits_through_fatal_egress_until_session_reset() {
    use tokio::io::AsyncWriteExt;

    let flow_count = Arc::new(AtomicUsize::new(0));
    let (mut stack, mut flows) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        1420,
        1,
        4096,
        Duration::from_secs(60),
        Arc::clone(&flow_count),
    )
    .expect("fatal egress stack");
    let (mut flow, _) = establish_ipv4_tcp_flow(&mut stack, &mut flows, 10_001, 0);
    let mut shutdown = Box::pin(flow.shutdown());
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut shutdown)
            .await
            .is_err(),
        "shutdown waits for the owner"
    );
    assert!(stack.drive_tcp(), "owner requests a local FIN");
    assert!(
        stack.poll_stack_once(Instant::from_millis(2)).worked,
        "smoltcp emits the local FIN"
    );
    assert_eq!(
        stack.flush_output(|_| OutputSendOutcome::Fatal),
        OutputFlushOutcome::Fatal
    );
    assert!(
        stack.has_output(),
        "fatal egress retains the pending packet"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut shutdown)
            .await
            .is_err(),
        "fatal egress cannot report the FIN as sent"
    );

    assert_eq!(
        stack.quiesce(1, UdpResponseDropReason::SessionReset),
        1,
        "session reset reaps the live flow"
    );
    let error = tokio::time::timeout(Duration::from_millis(10), &mut shutdown)
        .await
        .expect("session reset wakes shutdown")
        .expect_err("session reset is not a successful shutdown");
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(!stack.has_output(), "session reset clears the fatal output");
    assert_eq!(flow_count.load(Ordering::Acquire), 0);
}

#[test]
fn tcp_idle_timeout_reclaims_an_unfinished_handshake() {
    let flow_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (mut stack, _) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        1420,
        1,
        4096,
        Duration::from_secs(1),
        Arc::clone(&flow_count),
    )
    .expect("timeout stack");
    assert!(stack.enqueue(&ipv4_tcp(), true));
    stack.poll_quantum(Instant::ZERO);
    assert_eq!(
        stack.flush_output(|_| OutputSendOutcome::Sent),
        OutputFlushOutcome::Sent
    );
    stack.poll_quantum(Instant::from_millis(1_001));
    assert_eq!(
        stack.live_tcp_flows(),
        1,
        "the timed-out flow remains owned while its reset is queued"
    );
    let mut reset = false;
    assert_eq!(
        stack.flush_output(|packet| {
            reset = packet[33] & 0x04 != 0;
            OutputSendOutcome::Sent
        }),
        OutputFlushOutcome::Sent
    );
    assert!(reset, "the half-open timeout emits a reset");
    stack.poll_quantum(Instant::from_millis(1_002));
    assert_eq!(stack.live_tcp_flows(), 0, "half-open flow timed out");
    assert_eq!(flow_count.load(Ordering::Acquire), 0);
}
