use super::*;
use crate::packet::test_support::repair_transport_checksum;

fn tcp_sequence(template: &[u8], sequence: u32) -> Vec<u8> {
    let mut packet = template.to_vec();
    packet[33] = 0x10;
    packet[24..28].copy_from_slice(&sequence.to_be_bytes());
    repair_transport_checksum(&mut packet, 20, 6);
    packet
}

fn udp_response(sequence: u32) -> Vec<u8> {
    let mut packet = ipv4_udp(&sequence.to_be_bytes(), &[]);
    packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
    packet[16..20].copy_from_slice(&[198, 18, 0, 1]);
    packet[20..22].copy_from_slice(&53_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&10_000_u16.to_be_bytes());
    repair_ipv4_header(&mut packet);
    repair_transport_checksum(&mut packet, 20, 17);
    packet
}

async fn sustained_output(tcp_per_round: usize, udp_per_round: usize, pause_output: bool) {
    let mut harness = OwnerSessionHarness::new();
    let syn = ipv4_tcp_with_options(&[]);
    assert!(harness.stack.enqueue_at(&syn, true, 0));
    harness.run_work_budget(64);
    let translated = harness.adapter.sent_packets.pop().expect("translated SYN");
    assert!(harness.adapter.sent_packets.is_empty());
    assert!(
        harness
            .stack
            .enqueue_at(&ipv4_udp(b"request", &[]), true, 0)
    );
    let candidate = harness.candidates.try_recv().unwrap();
    let commit = tokio::spawn(async move { candidate.commit_association().await });
    tokio::task::yield_now().await;
    harness.run_work_budget(64);
    let association = commit.await.unwrap().unwrap();
    let remote = "192.0.2.1:53".parse().unwrap();
    let mut expected_tcp = Vec::new();
    let mut expected_udp = Vec::new();
    let mut observed = 0;
    let mut silent_rounds = [0; 2];

    for round in 0..256 {
        // Refill for the entire observation window, never just burst then drain.
        for _ in 0..tcp_per_round {
            let sequence = u32::try_from(expected_tcp.len()).unwrap();
            harness
                .adapter
                .receives
                .push_back(FakeReceiveOutcome::Packet(tcp_sequence(&syn, sequence)));
            expected_tcp.push(tcp_sequence(&translated, sequence));
        }
        for _ in 0..udp_per_round {
            let sequence = u32::try_from(expected_udp.len()).unwrap();
            match association.send_response(remote, &sequence.to_be_bytes()) {
                UdpResponseSendOutcome::Queued => expected_udp.push(udp_response(sequence)),
                UdpResponseSendOutcome::QueueFull => break,
                outcome => panic!("unexpected response admission: {outcome:?}"),
            }
        }
        harness.adapter.output_paused = pause_output && (80..96).contains(&round);
        let outcome = harness.run_work_budget(FairScheduler::STAGE_COUNT);
        assert!(!outcome.fatal);
        let mut progressed = [false; 2];
        for packet in &harness.adapter.sent_packets[observed..] {
            let index = match packet[9] {
                6 => 0,
                17 => 1,
                protocol => panic!("unexpected output protocol {protocol}"),
            };
            progressed[index] = true;
        }
        observed = harness.adapter.sent_packets.len();
        for (index, rate) in [tcp_per_round, udp_per_round].into_iter().enumerate() {
            if harness.adapter.output_paused || rate == 0 || progressed[index] {
                silent_rounds[index] = 0;
            } else {
                silent_rounds[index] += 1;
                assert!(
                    silent_rounds[index] <= 3,
                    "protocol {index} starved at round {round}: TCP rate {tcp_per_round}, UDP rate {udp_per_round}"
                );
            }
        }
    }

    // Drain only AFTER the sustained-progress assertions. Every admitted packet
    // must retain its per-protocol order, payload, tuple and valid checksums.
    harness.adapter.output_paused = false;
    for _ in 0..256 {
        if harness.run_work_budget(64).work_units == 0 {
            break;
        }
    }
    let actual_tcp = harness
        .adapter
        .sent_packets
        .iter()
        .filter(|p| p[9] == 6)
        .cloned()
        .collect::<Vec<_>>();
    let actual_udp = harness
        .adapter
        .sent_packets
        .iter()
        .filter(|p| p[9] == 17)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(actual_tcp, expected_tcp);
    assert_eq!(actual_udp, expected_udp);
    assert!(harness.adapter.receives.is_empty());
    assert!(!harness.stack.has_output());
    assert_eq!(harness.stack.ingress_available(), crate::INGRESS_SLOTS);
    assert!(
        !harness
            .events()
            .iter()
            .any(|e| matches!(e, TunEvent::WintunRingFullDropped))
    );
}

#[tokio::test]
async fn sustained_tcp_and_udp_share_output_under_both_load_directions() {
    sustained_output(4, 1, false).await;
    sustained_output(1, 4, false).await;
}

#[tokio::test]
async fn sustained_single_protocol_never_waits_for_an_absent_competitor() {
    sustained_output(1, 0, false).await;
    sustained_output(0, 1, false).await;
}

#[tokio::test]
async fn sustained_mixed_output_recovers_from_withheld_sink_turns() {
    sustained_output(1, 1, true).await;
}
