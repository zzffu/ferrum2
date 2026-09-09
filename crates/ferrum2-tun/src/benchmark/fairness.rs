//! Independent `mixed-sustained-v1` recipe, outside the v2 aggregate.
//! Each window runs exactly 256 six-stage scheduler rotations at logical time 0.
//! Rotations 80..96 withhold the output sink; all other rotations are writable.
//! Quick: 32 windows, 64-byte payloads. Confirm: 64 windows, 1460-byte payloads
//! (1500-byte IPv4 TCP packets, 1488-byte IPv4 UDP packets).
//! Setup fills all 16 TCP ingress slots and eight UDP responses. Every rotation
//! attempts one UDP response; its Receive stage replenishes at most one TCP
//! packet into a free slot. Neither source stops producing during the window.
//! Payloads encode their per-protocol admission index in the first eight bytes;
//! all payloads and bounded output slots are allocated before timing. The timer
//! includes production enqueue/send/capture cost, but not setup or validation.
//! No drain is included: counts describe only the sustained window, and admitted
//! but unobserved packets remain queued at its end. Gaps include leading/trailing
//! silence in each writable segment, exclude paused rotations, and report resume
//! latency separately. Starvation is reported rather than panicking, so the same
//! recipe can measure the pre-fix baseline; consumers must require bounded_progress.
//! Stage batching is intentionally absent: run_budget changes the number of
//! round-robin visits, not the quota of a stage. Real stage batching requires a
//! production owner-stage quota seam; repeating a stage here would copy policy.

use super::owner::{Owner, parse, validate};
use super::recipe::{MTU, endpoints, packet};
use crate::UdpResponseSendOutcome;
use crate::packet::TransportMetadata;
use crate::scheduler::{FairScheduler, StepOutcome, WorkStage};
use crate::stack::{OutputFlushOutcome, OutputSendOutcome};
use std::net::SocketAddr;
use std::time::Instant;

const ROUNDS: usize = 256;
const PAUSE_START: usize = 80;
const PAUSE_END: usize = 96;
const RESPONSE_PREFILL: usize = 8;
const GAP_BOUND: usize = 3;

pub(super) fn trial(scenario: &str, mode: &str) -> Result<String, &'static str> {
    if scenario != "mixed-sustained" {
        return Err("unknown scenario");
    }
    let (bytes, windows) = match mode {
        "Quick" => (64, 32),
        "Confirm" => (1460, 64),
        _ => return Err("unknown mode"),
    };
    let diagnostic = run(bytes);
    let mut elapsed = 0;
    for _ in 0..windows {
        let result = run(bytes);
        assert_eq!(result.observation, diagnostic.observation);
        elapsed += result.elapsed;
    }
    let o = diagnostic.observation;
    let checked = ROUNDS * windows;
    let visits = o.visits.map(|n| n * windows);
    let work = o.work * windows;
    let tcp = o.outputs[0] * windows;
    let udp = o.outputs[1] * windows;
    let tcp_admitted = o.tcp_admitted * windows;
    let udp_admitted = o.udp_admitted * windows;
    let udp_full = o.udp_full * windows;
    let starved = o.max_gap.iter().any(|&gap| gap > GAP_BOUND);
    let bounded = !starved && o.resume.iter().all(|&delay| delay <= GAP_BOUND);
    Ok(format!(
        "{{\"schema_version\":1,\"kind\":\"ferrum2.tun-detail.trial\",\"scenario\":\"{scenario}\",\"mode\":\"{mode}\",\"recipe_id\":\"mixed-sustained-v1/{mode}\",\"checked_units\":{checked},\"elapsed_nanoseconds\":{elapsed},\"unit\":\"scheduler_rotation\",\"observation\":{{\"payload_bytes\":{bytes},\"timed_windows\":{windows},\"rotations_per_window\":{ROUNDS},\"paused_rotations_per_window\":16,\"stage_budget_per_rotation\":6,\"stage_visits\":{visits:?},\"work_units\":{work},\"tcp_outputs\":{tcp},\"udp_outputs\":{udp},\"tcp_admitted_including_prefill\":{tcp_admitted},\"udp_admitted_including_prefill\":{udp_admitted},\"udp_queue_full_attempts\":{udp_full},\"tcp_max_gap_rotations\":{tcp_gap},\"udp_max_gap_rotations\":{udp_gap},\"tcp_resume_rotations\":{tcp_resume},\"udp_resume_rotations\":{udp_resume},\"progress_bound_rotations\":{GAP_BOUND},\"starved\":{starved},\"bounded_progress\":{bounded},\"event_poll_delay_rotations\":null}}}}",
        tcp_gap = o.max_gap[0],
        udp_gap = o.max_gap[1],
        tcp_resume = o.resume[0],
        udp_resume = o.resume[1],
    ))
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Observation {
    visits: [usize; 6],
    work: usize,
    outputs: [usize; 2],
    tcp_admitted: usize,
    udp_admitted: usize,
    udp_full: usize,
    max_gap: [usize; 2],
    resume: [usize; 2],
}

struct ResultWindow {
    elapsed: u128,
    observation: Observation,
}

struct Capture {
    bytes: Vec<u8>,
    round: usize,
}

fn payloads(bytes: usize, count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|sequence| {
            let mut payload: Vec<_> = (0..bytes)
                .map(|offset| (sequence.wrapping_mul(31).wrapping_add(offset)) as u8)
                .collect();
            payload[..8].copy_from_slice(&(sequence as u64).to_be_bytes());
            payload
        })
        .collect()
}

fn run(bytes: usize) -> ResultWindow {
    let mut owner = Owner::new(1);
    // Avoid timing diagnostic atomic event accounting from the generic Owner.
    owner.stack.set_event_sink(crate::TunEventSink::new(|_| {}));
    let (tcp_source, tcp_target) = endpoints(false, 0);
    let (udp_source, udp_target) = endpoints(false, 1);
    owner.enqueue(&packet(tcp_source, tcp_target, Some(0x02), &[]));
    owner.begin_capture(1, 0, false);
    owner.drain(&mut |_| {});
    assert_eq!(owner.output, 1);
    let syn = parse(&owner.capture[0]);
    let TransportMetadata::Tcp(tcp) = syn.transport else {
        panic!("translated TCP SYN");
    };
    let translated_source = SocketAddr::new(syn.source, tcp.source_port);
    let translated_target = SocketAddr::new(syn.destination, tcp.destination_port);
    owner.enqueue(&packet(udp_source, udp_target, None, b"request"));
    let mut association = owner.commit();
    owner.receive(&mut association, udp_target, b"request");
    let (socket, _peer) = tokio::io::duplex(1);
    owner
        .stack
        .accept_packet_socket(tcp_source, tcp_target, socket);
    assert!(owner.stack.expire_deadlines(0));
    // Retain the published TcpFlow for the complete measurement window.
    let _flow = owner.flows.try_recv().expect("published TCP flow");

    let tcp_payloads = payloads(bytes, ROUNDS + crate::INGRESS_SLOTS);
    let udp_payloads = payloads(bytes, ROUNDS + RESPONSE_PREFILL);
    let tcp_packets: Vec<_> = tcp_payloads
        .iter()
        .map(|payload| packet(tcp_source, tcp_target, Some(0x10), payload))
        .collect();
    let mut observation = Observation::default();
    for input in &tcp_packets[..crate::INGRESS_SLOTS] {
        assert!(owner.stack.enqueue_at(input, true, 0));
        observation.tcp_admitted += 1;
    }
    for payload in &udp_payloads[..RESPONSE_PREFILL] {
        assert_eq!(
            association.send_response(udp_target, payload),
            UdpResponseSendOutcome::Queued
        );
        observation.udp_admitted += 1;
    }
    let mut capture: Vec<_> = (0..ROUNDS)
        .map(|_| Capture {
            bytes: Vec::with_capacity(MTU),
            round: 0,
        })
        .collect();
    let mut captured = 0;
    let mut scheduler = FairScheduler::default();
    let mut fatal = false;
    let mut unexpected_send = false;
    let mut ingress_rejected = false;
    let started = Instant::now();
    for round in 0..ROUNDS {
        match association.send_response(udp_target, &udp_payloads[observation.udp_admitted]) {
            UdpResponseSendOutcome::Queued => observation.udp_admitted += 1,
            UdpResponseSendOutcome::QueueFull => observation.udp_full += 1,
            _ => unexpected_send = true,
        }
        let writable = !(PAUSE_START..PAUSE_END).contains(&round);
        let outcome = scheduler.run_budget(FairScheduler::STAGE_COUNT, |stage| {
            let index = match stage {
                WorkStage::Control => 0,
                WorkStage::FlushOutput => 1,
                WorkStage::Stack => 2,
                WorkStage::Receive => 3,
                WorkStage::UdpResponse => 4,
                WorkStage::Expire => 5,
            };
            observation.visits[index] += 1;
            match stage {
                WorkStage::Receive if owner.stack.ingress_available() != 0 => {
                    let admitted =
                        owner
                            .stack
                            .enqueue_at(&tcp_packets[observation.tcp_admitted], true, 0);
                    observation.tcp_admitted += usize::from(admitted);
                    ingress_rejected |= !admitted;
                    StepOutcome::from_work(admitted)
                }
                WorkStage::Receive => StepOutcome::Idle,
                WorkStage::FlushOutput if writable => {
                    match owner.stack.flush_output(|output| {
                        let Some(slot) = capture.get_mut(captured) else {
                            return OutputSendOutcome::Fatal;
                        };
                        if output.len() > slot.bytes.capacity() {
                            return OutputSendOutcome::Fatal;
                        }
                        slot.bytes.extend_from_slice(output);
                        slot.round = round;
                        captured += 1;
                        OutputSendOutcome::Sent
                    }) {
                        OutputFlushOutcome::Empty => StepOutcome::Idle,
                        OutputFlushOutcome::Sent => StepOutcome::Worked,
                        _ => StepOutcome::Fatal,
                    }
                }
                WorkStage::FlushOutput => StepOutcome::Idle,
                _ => owner
                    .stack
                    .owner_internal_step(stage, 0, true)
                    .expect("internal owner stage"),
            }
        });
        observation.work += outcome.work_units;
        fatal |= outcome.fatal;
    }
    let elapsed = started.elapsed().as_nanos();

    assert!(!fatal && !unexpected_send && !ingress_rejected);
    assert_eq!(observation.visits, [ROUNDS; 6]);
    assert_eq!(
        observation.udp_admitted + observation.udp_full,
        RESPONSE_PREFILL + ROUNDS
    );
    assert_eq!(owner.stack.ingress_available(), 0, "TCP remains backlogged");
    let mut last_output = [None; 2];
    let mut cursor = 0;
    for round in 0..ROUNDS {
        if (PAUSE_START..PAUSE_END).contains(&round) {
            assert!(cursor == captured || capture[cursor].round != round);
            last_output = [None; 2];
            continue;
        }
        let segment_start = if round < PAUSE_START { 0 } else { PAUSE_END };
        if cursor < captured && capture[cursor].round == round {
            let output = &capture[cursor].bytes;
            let parsed = parse(output);
            let protocol = match parsed.transport {
                TransportMetadata::Tcp(_) => 0,
                TransportMetadata::Udp(_) => 1,
            };
            let sequence = observation.outputs[protocol];
            if protocol == 0 {
                assert!(sequence < observation.tcp_admitted);
                validate(
                    output,
                    translated_source,
                    translated_target,
                    &tcp_payloads[sequence],
                );
                assert_eq!(output[33], 0x10);
                assert_eq!(&output[24..28], &7_u32.to_be_bytes());
            } else {
                assert!(sequence < observation.udp_admitted);
                validate(output, udp_target, udp_source, &udp_payloads[sequence]);
            }
            let gap = last_output[protocol].map_or(round - segment_start + 1, |last| round - last);
            observation.max_gap[protocol] = observation.max_gap[protocol].max(gap);
            if round >= PAUSE_END && observation.resume[protocol] == 0 {
                observation.resume[protocol] = round - PAUSE_END + 1;
            }
            last_output[protocol] = Some(round);
            observation.outputs[protocol] += 1;
            cursor += 1;
        }
        for (protocol, last) in last_output.iter().enumerate() {
            let silence = last.map_or(round - segment_start + 1, |last| round - last);
            observation.max_gap[protocol] = observation.max_gap[protocol].max(silence);
        }
    }
    assert_eq!(cursor, captured);
    for delay in &mut observation.resume {
        if *delay == 0 {
            *delay = ROUNDS - PAUSE_END;
        }
    }
    ResultWindow {
        elapsed,
        observation,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn both_protocols_progress_and_udp_takes_the_first_recovered_slot() {
        for payload_bytes in [64, 1460] {
            let observed = super::run(payload_bytes).observation;
            assert!(
                observed
                    .max_gap
                    .into_iter()
                    .all(|gap| (1..=3).contains(&gap)),
                "both protocols must progress throughout each writable segment"
            );
            assert!(
                (1..=3).contains(&observed.resume[0]),
                "TCP must resume after the sink becomes writable"
            );
            assert_eq!(
                observed.resume[1], 1,
                "deferred UDP must use the first recovered output opportunity"
            );
            assert_eq!(
                observed.outputs.into_iter().sum::<usize>(),
                239,
                "the fixed window must not lose writable output opportunities"
            );
        }
    }
}
