use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::runtime::Builder;

#[cfg(test)]
use crate::packet::ParsedFragment;
use crate::packet::{Families, MAX_REASSEMBLED_PACKET, PacketParser, ParsedPacket};
use crate::reassembly::{
    MAX_FRAGMENTS_PER_ENTRY, MAX_REASSEMBLY_ENTRIES, REASSEMBLY_TIMEOUT_MILLIS, ReassemblyOutcome,
    ReassemblyTable,
};
use crate::udp::{
    Admission, InjectOutcome, ResponseProcessOutcome, UdpAssociation, UdpCandidate, UdpCommitError,
    UdpDatagramEndpoints, UdpFiltering, UdpResponseSendOutcome, UdpResponseSink, UdpTable,
};
use crate::{OwnerWake, TunRejectReason, UdpResponseDropReason};

/// Hard upper bound accepted by this target, including framing bytes.
pub const MAX_FUZZ_INPUT_BYTES: usize = 256 * 1024;

const MAX_PACKET_BYTES: usize = MAX_REASSEMBLED_PACKET;
const MAX_FRAMES: usize = MAX_FRAGMENTS_PER_ENTRY;
const HEX_CORPUS_MAGIC: &[u8] = b"F2HX\n";

/// Exercises canonical parsing, stateful fragment reassembly, expiry, and generation changes.
///
/// Binary inputs use one selector byte followed by up to 128 frames. Each frame is an operation
/// byte, a big-endian `u16` packet length, and that many packet bytes. Committed seed files may use
/// the `F2HX` newline-delimited hexadecimal form so reviewed packet fixtures remain readable.
pub fn fuzz_packet_reassembly(input: &[u8]) {
    if input.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    if let Some(hex) = input.strip_prefix(HEX_CORPUS_MAGIC) {
        exercise_hex_corpus(hex);
    } else {
        let _ = exercise_binary_input(input);
    }
}

fn exercise_binary_input(input: &[u8]) -> usize {
    let selector = input.first().copied().unwrap_or_default();
    let mut table = ReassemblyTable::new(u64::from(selector));
    let mut generation = u64::from(selector);
    let mut now_millis = 0_i64;
    let mut cursor = usize::from(!input.is_empty());
    let mut frames = 0_usize;

    // Keep an unstructured path so packet corpora and minimized crash inputs do not depend on the
    // sequence framing. Stateful frames below exercise reassembly-specific transitions.
    exercise_packet(
        parser_for(0),
        &mut table,
        &input[..input.len().min(MAX_PACKET_BYTES)],
        now_millis,
        generation,
        false,
    );

    while cursor < input.len() && frames < MAX_FRAMES {
        let previous_cursor = cursor;
        let remaining = &input[cursor..];
        if remaining.len() < 3 {
            let packet = &remaining[..remaining.len().min(MAX_PACKET_BYTES)];
            exercise_packet(
                parser_for(selector),
                &mut table,
                packet,
                now_millis,
                generation,
                false,
            );
            break;
        }

        let operation = remaining[0];
        let requested = usize::from(u16::from_be_bytes([remaining[1], remaining[2]]));
        cursor += 3;
        let available = requested.min(input.len() - cursor);
        let packet = &input[cursor..cursor + available];
        cursor += available;
        assert!(cursor > previous_cursor, "binary framing failed to advance");

        if operation & 0x04 != 0 {
            table.clear();
            assert_reassembly_state_reclaimed(&mut table);
        }
        if operation & 0x08 != 0 {
            generation = generation.wrapping_add(1);
            table.set_generation(generation);
            assert_reassembly_state_reclaimed(&mut table);
        }
        now_millis = now_millis.saturating_add(
            i64::from(operation >> 4)
                .saturating_mul(1_000)
                .saturating_add(i64::try_from(packet.len()).unwrap_or(i64::MAX)),
        );

        exercise_packet(
            parser_for(selector ^ operation),
            &mut table,
            packet,
            now_millis,
            generation,
            operation & 0x02 != 0,
        );
        frames += 1;
        assert!(frames <= MAX_FRAMES);

        if operation & 0x80 != 0 {
            expire_all_reassembly_state(
                &mut table,
                now_millis.saturating_add(REASSEMBLY_TIMEOUT_MILLIS),
            );
        }
        let _ = table.next_deadline_millis();
        assert!(table.len() <= MAX_REASSEMBLY_ENTRIES);

        if available != requested {
            break;
        }
    }

    expire_all_reassembly_state(&mut table, i64::MAX);
    frames
}

fn exercise_hex_corpus(input: &[u8]) {
    let parser = parser_for(0);
    let mut table = ReassemblyTable::new(1);
    let mut generation = 1_u64;
    let mut now_millis = 0_i64;
    for (ordinal, line) in input
        .split(|byte| *byte == b'\n')
        .take(MAX_FRAMES)
        .enumerate()
    {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        match line {
            b"@clear" => {
                table.clear();
                assert_reassembly_state_reclaimed(&mut table);
                continue;
            }
            b"@expire" => {
                now_millis = now_millis.saturating_add(REASSEMBLY_TIMEOUT_MILLIS);
                expire_all_reassembly_state(&mut table, now_millis);
                continue;
            }
            b"@generation" => {
                generation = generation.wrapping_add(1);
                table.set_generation(generation);
                assert_reassembly_state_reclaimed(&mut table);
                continue;
            }
            _ => {}
        }
        let Some(packet) = decode_hex_packet(line) else {
            continue;
        };
        now_millis = now_millis.saturating_add(i64::try_from(ordinal).unwrap_or(i64::MAX));
        exercise_packet(parser, &mut table, &packet, now_millis, generation, false);
        assert!(table.len() <= MAX_REASSEMBLY_ENTRIES);
    }
    expire_all_reassembly_state(&mut table, i64::MAX);
}

fn expire_all_reassembly_state(table: &mut ReassemblyTable, now_millis: i64) {
    let live_entries = table.len();
    assert_eq!(table.expire(now_millis), live_entries);
    assert_reassembly_state_reclaimed(table);
}

fn assert_reassembly_state_reclaimed(table: &mut ReassemblyTable) {
    assert_eq!(table.len(), 0);
    assert_eq!(table.next_deadline_millis(), None);
}

fn exercise_packet(
    parser: PacketParser,
    table: &mut ReassemblyTable,
    packet: &[u8],
    now_millis: i64,
    generation: u64,
    drop_after_parse: bool,
) {
    if packet.len() > MAX_PACKET_BYTES {
        return;
    }

    match parser.parse(packet) {
        Ok(ParsedPacket::Complete(parsed)) => {
            assert!(parsed.metadata_matches(packet.len()));
        }
        Ok(ParsedPacket::Fragment(fragment)) => {
            let key = fragment.key;
            let accepted = table.accept(packet, fragment, now_millis, generation);
            match accepted.outcome {
                ReassemblyOutcome::Atomic(rebuilt) | ReassemblyOutcome::Complete(rebuilt) => {
                    assert!(rebuilt.len() <= MAX_PACKET_BYTES);
                    match parser.parse_reassembled(&rebuilt) {
                        Ok(ParsedPacket::Complete(parsed)) => {
                            assert!(parsed.metadata_matches(rebuilt.len()));
                        }
                        Ok(ParsedPacket::Fragment(_)) => {
                            panic!("reassembled parsing accepted another fragment")
                        }
                        Err(_) => {}
                    }
                }
                ReassemblyOutcome::Pending | ReassemblyOutcome::Dropped(_) => {}
            }
            if drop_after_parse {
                let _ = table.drop_key(key);
            }
        }
        Err(reject) => {
            if drop_after_parse && let Some(key) = reject.fragment_key {
                let _ = table.drop_key(key);
            }
        }
    }
}

const fn parser_for(selector: u8) -> PacketParser {
    let families = match selector & 0x03 {
        1 => Families {
            ipv4: true,
            ipv6: false,
        },
        2 => Families {
            ipv4: false,
            ipv6: true,
        },
        3 => Families {
            ipv4: false,
            ipv6: false,
        },
        _ => Families {
            ipv4: true,
            ipv6: true,
        },
    };
    PacketParser::new(families)
}

fn decode_hex_packet(input: &[u8]) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(2) || input.len() > MAX_PACKET_BYTES * 2 {
        return None;
    }
    let mut packet = Vec::with_capacity(input.len() / 2);
    for pair in input.chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        packet.push((high << 4) | low);
    }
    Some(packet)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod deterministic_properties {
    use super::*;

    const IPV4_FIRST_FRAGMENT: &[u8] =
        b"4500002461012000401171b3c6120001c000020127100035001ac3f0666978747572652d";
    const IPV4_SECOND_FRAGMENT: &[u8] =
        b"4500001e61010002401191b7c6120001c000020176342d7061796c6f6164";

    #[test]
    fn binary_framing_makes_progress_up_to_the_frame_bound() {
        let mut input = vec![0_u8];
        for _ in 0..=MAX_FRAMES {
            input.extend_from_slice(&[0, 0, 0]);
        }

        assert_eq!(exercise_binary_input(&input), MAX_FRAMES);
    }

    #[test]
    fn expiry_reclaims_entries_and_deadlines() {
        let first = decode_hex_packet(IPV4_FIRST_FRAGMENT).expect("reviewed first fragment");
        let mut table = ReassemblyTable::new(7);
        let accepted = table.accept(&first, parse_fragment(&first), 0, 7);

        assert_eq!(accepted.outcome, ReassemblyOutcome::Pending);
        assert_eq!(accepted.expired, 0);
        assert_eq!(table.len(), 1);
        assert_eq!(
            table.next_deadline_millis(),
            Some(REASSEMBLY_TIMEOUT_MILLIS)
        );

        expire_all_reassembly_state(&mut table, REASSEMBLY_TIMEOUT_MILLIS);
    }

    #[test]
    fn generation_change_prevents_cross_generation_reassembly() {
        let first = decode_hex_packet(IPV4_FIRST_FRAGMENT).expect("reviewed first fragment");
        let second = decode_hex_packet(IPV4_SECOND_FRAGMENT).expect("reviewed second fragment");
        let mut table = ReassemblyTable::new(11);

        let first_generation = table.accept(&first, parse_fragment(&first), 0, 11);
        assert_eq!(first_generation.outcome, ReassemblyOutcome::Pending);
        assert_eq!(table.len(), 1);

        let next_generation = table.accept(&second, parse_fragment(&second), 1, 12);
        assert_eq!(next_generation.outcome, ReassemblyOutcome::Pending);
        assert_eq!(table.len(), 1);

        let completed = table.accept(&first, parse_fragment(&first), 2, 12);
        let ReassemblyOutcome::Complete(rebuilt) = completed.outcome else {
            panic!("current-generation fragment pair did not complete");
        };
        match parser_for(0).parse_reassembled(&rebuilt) {
            Ok(ParsedPacket::Complete(parsed)) => {
                assert!(parsed.metadata_matches(rebuilt.len()));
            }
            other => panic!("completed packet did not parse canonically: {other:?}"),
        }
        assert_reassembly_state_reclaimed(&mut table);
    }

    fn parse_fragment(packet: &[u8]) -> ParsedFragment {
        match parser_for(0).parse(packet) {
            Ok(ParsedPacket::Fragment(fragment)) => fragment,
            other => panic!("reviewed fragment did not parse as a fragment: {other:?}"),
        }
    }
}

/// Hard input bound for the UDP reset state-sequence target.
pub const MAX_UDP_RESET_FUZZ_INPUT_BYTES: usize = 4 * 1024;

const MAX_STEPS: usize = 256;
const MAX_CAPACITY: usize = 8;
const MAX_RETAINED_STALE_SINKS: usize = 16;

/// Exercises the production source-keyed UDP table across bounded reset interleavings.
///
/// This target is entirely in memory. It never creates a TUN adapter, socket, route, WFP object,
/// or background thread. Input bytes select admissions, provisional commits, response injection,
/// expiry, association closes, and network-generation changes.
pub fn fuzz_udp_reset_races(input: &[u8]) {
    if input.len() > MAX_UDP_RESET_FUZZ_INPUT_BYTES {
        return;
    }
    let runtime = Builder::new_current_thread()
        .build()
        .expect("bounded current-thread runtime");
    runtime.block_on(exercise(input));
}

async fn exercise(input: &[u8]) {
    let selector = input.first().copied().unwrap_or_default();
    let capacity = usize::from(selector % MAX_CAPACITY as u8) + 1;
    let filtering = if selector & 0x80 == 0 {
        UdpFiltering::EndpointIndependent
    } else {
        UdpFiltering::AddressDependent
    };
    let wake_count = Arc::new(AtomicUsize::new(0));
    let observed_wakes = Arc::clone(&wake_count);
    let wake = OwnerWake::new(move || {
        observed_wakes.fetch_add(1, Ordering::Relaxed);
    });
    let mut generation = 1_u64;
    let (mut table, mut candidates) = UdpTable::with_options(
        capacity,
        Duration::from_millis(1_000),
        filtering,
        generation,
        wake,
    );
    let mut associations = Vec::<UdpAssociation>::with_capacity(capacity);
    let mut stale_sinks = VecDeque::with_capacity(MAX_RETAINED_STALE_SINKS);
    let mut now_millis = 0_i64;

    for (ordinal, frame) in input.chunks(4).take(MAX_STEPS).enumerate() {
        let operation = frame.first().copied().unwrap_or_default();
        let source_selector = frame.get(1).copied().unwrap_or(operation);
        let target_selector = frame.get(2).copied().unwrap_or(source_selector);
        let policy = frame.get(3).copied().unwrap_or(target_selector);
        now_millis = now_millis.saturating_add(i64::from(policy & 0x0f));

        match operation % 8 {
            0 => {
                let endpoints = endpoints(source_selector, target_selector);
                let payload = frame;
                let payload_bound = payload.len().saturating_add(usize::from(policy & 0x1f));
                let _ = table.admit(endpoints, payload, payload_bound, now_millis, true);
            }
            1 => {
                if let Ok(candidate) = candidates.try_recv() {
                    let source = candidate.source();
                    let first_target = candidate.first_target();
                    let packet_bound = candidate.packet_payload_bound();
                    let selected_bound = if policy & 0x40 == 0 {
                        packet_bound
                    } else {
                        packet_bound.saturating_add(1)
                    };
                    let commit = tokio::spawn(async move {
                        candidate
                            .commit_association_with_payload_bound(selected_bound)
                            .await
                    });
                    tokio::task::yield_now().await;

                    if policy & 0x80 != 0 {
                        reset_table(
                            &mut table,
                            &mut generation,
                            &mut associations,
                            &mut stale_sinks,
                        );
                    }
                    for _ in 0..capacity.saturating_add(2) {
                        let _ = table.process_one_control(now_millis, true);
                        tokio::task::yield_now().await;
                        if commit.is_finished() {
                            break;
                        }
                    }
                    if !commit.is_finished() {
                        reset_table(
                            &mut table,
                            &mut generation,
                            &mut associations,
                            &mut stale_sinks,
                        );
                    }
                    match commit.await.expect("commit task must not panic") {
                        Ok(mut association) => {
                            assert_eq!(association.source(), source);
                            assert_eq!(association.first_target(), first_target);
                            let first = association
                                .receive()
                                .await
                                .expect("committed candidate retains its first datagram");
                            assert_eq!(first.source(), source);
                            assert_eq!(first.target(), first_target);
                            retain_stale_sink(&mut stale_sinks, association.response_sink());
                            associations.push(association);
                            assert!(associations.len() <= capacity);
                        }
                        Err(UdpCommitError::Rejected | UdpCommitError::Unavailable) => {}
                    }
                }
            }
            2 => {
                if let Some(association) =
                    associations.get(usize::from(source_selector) % associations.len().max(1))
                {
                    let response_source = target(source_selector, target_selector);
                    let payload = frame;
                    let _ = association.send_response(response_source, payload);
                    let injection = policy % 3;
                    let _ = table.process_one_response(now_millis, |endpoints, bytes| {
                        assert!(endpoints.source().port() != 0);
                        assert!(endpoints.target().port() != 0);
                        assert!(!bytes.is_empty() && bytes.len() <= 4);
                        match injection {
                            0 => InjectOutcome::Injected,
                            1 => InjectOutcome::Backpressured,
                            _ => InjectOutcome::Rejected(TunRejectReason::InvalidDestination),
                        }
                    });
                }
            }
            3 => reset_table(
                &mut table,
                &mut generation,
                &mut associations,
                &mut stale_sinks,
            ),
            4 => {
                let association_index = usize::from(source_selector) % associations.len().max(1);
                if let Some(association) = associations.get_mut(association_index) {
                    let first_target = association.first_target();
                    let endpoints = UdpDatagramEndpoints::new(
                        association.source(),
                        target(source_selector, target_selector),
                    );
                    let admission = table.admit(endpoints, frame, frame.len(), now_millis, true);
                    if matches!(admission, Admission::Mapped | Admission::CandidateQueued) {
                        let datagram = association
                            .receive()
                            .await
                            .expect("accepted mapped datagram remains queued");
                        assert_eq!(datagram.source(), association.source());
                        assert_ne!(datagram.target().port(), 0);
                        assert_eq!(association.first_target(), first_target);
                    }
                }
            }
            5 => {
                if !associations.is_empty() {
                    let index = usize::from(source_selector) % associations.len();
                    let association = associations.swap_remove(index);
                    retain_stale_sink(&mut stale_sinks, association.response_sink());
                    drop(association);
                    let _ = table.process_one_control(now_millis, true);
                }
            }
            6 => {
                for _ in 0..=capacity {
                    if table
                        .process_one_control(now_millis, policy & 0x80 == 0)
                        .is_none()
                    {
                        break;
                    }
                }
                let outcome = table.process_one_response(now_millis, |_, _| {
                    if policy & 1 == 0 {
                        InjectOutcome::Injected
                    } else {
                        InjectOutcome::Backpressured
                    }
                });
                assert!(matches!(
                    outcome,
                    ResponseProcessOutcome::Idle
                        | ResponseProcessOutcome::Injected
                        | ResponseProcessOutcome::Deferred
                        | ResponseProcessOutcome::Dropped(_)
                ));
            }
            _ => {
                now_millis = now_millis.saturating_add(i64::from(policy).saturating_mul(1_000));
                let _ = table.expire(now_millis);
                let _ = table.next_deadline_millis();
            }
        }

        assert!(table.active_associations() <= capacity);
        assert!(associations.len() <= capacity);
        assert!(ordinal < MAX_STEPS);
        assert!(
            wake_count.load(Ordering::Relaxed) <= (ordinal + 1).saturating_mul(8).saturating_add(8)
        );
    }

    reset_table(
        &mut table,
        &mut generation,
        &mut associations,
        &mut stale_sinks,
    );
    drain_stale_candidates(&mut table, &mut candidates).await;
    assert_reclaimed(&mut table);

    for slot in 0..capacity {
        let source_selector = u8::try_from(slot).unwrap_or_default();
        assert_eq!(
            table.admit(
                endpoints(source_selector, source_selector),
                b"fresh",
                5,
                now_millis,
                true,
            ),
            Admission::Provisional,
            "reset must restore every admission slot"
        );
    }
    generation = next_generation(generation);
    table.invalidate_session(generation, UdpResponseDropReason::SessionReset);
    drain_stale_candidates(&mut table, &mut candidates).await;
    assert_reclaimed(&mut table);

    for sink in stale_sinks {
        assert!(matches!(
            sink.send(target(0, 0), b"late"),
            UdpResponseSendOutcome::StaleGeneration | UdpResponseSendOutcome::Closed
        ));
    }
}

fn reset_table(
    table: &mut UdpTable,
    generation: &mut u64,
    associations: &mut Vec<UdpAssociation>,
    stale_sinks: &mut VecDeque<UdpResponseSink>,
) {
    for association in associations.iter() {
        retain_stale_sink(stale_sinks, association.response_sink());
    }
    *generation = next_generation(*generation);
    table.invalidate_session(*generation, UdpResponseDropReason::SessionReset);
    associations.clear();
    assert_reclaimed(table);
}

async fn drain_stale_candidates(
    table: &mut UdpTable,
    candidates: &mut tokio::sync::mpsc::Receiver<UdpCandidate>,
) {
    while let Ok(candidate) = candidates.try_recv() {
        assert!(matches!(
            candidate.commit_association().await,
            Err(UdpCommitError::Rejected | UdpCommitError::Unavailable)
        ));
    }
    while table.process_one_control(0, true).is_some() {}
}

fn assert_reclaimed(table: &mut UdpTable) {
    assert_eq!(table.active_associations(), 0);
    assert!(!table.has_pending_response());
    assert_eq!(table.next_deadline_millis(), None);
}

fn retain_stale_sink(stale_sinks: &mut VecDeque<UdpResponseSink>, sink: UdpResponseSink) {
    if stale_sinks.len() == MAX_RETAINED_STALE_SINKS {
        stale_sinks.pop_front();
    }
    stale_sinks.push_back(sink);
}

fn next_generation(generation: u64) -> u64 {
    let next = generation.wrapping_add(1);
    if next == 0 { 1 } else { next }
}

fn endpoints(source_selector: u8, target_selector: u8) -> UdpDatagramEndpoints {
    UdpDatagramEndpoints::new(
        source(source_selector),
        target(source_selector, target_selector),
    )
}

fn source(selector: u8) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(10, 0, selector / 254, selector % 254 + 1),
        10_000 + u16::from(selector),
    ))
}

fn target(source_selector: u8, target_selector: u8) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(198, 51, 100, target_selector % 254 + 1),
        20_000 + u16::from(source_selector ^ target_selector),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_sequences_cover_reset_before_and_after_commit() {
        for input in [
            &b"\x01\x00\x00\x00\x00\x01\x01\x00\x01\x00\x00\x80"[..],
            &b"\x82\x00\x00\x00\x01\x00\x00\x80\x03\x00\x00\x00"[..],
            &b"\x04\x01\x02\x00\x01\x01\x02\x00\x02\x01\x02\x00\x03\x00\x00\x00"[..],
        ] {
            fuzz_udp_reset_races(input);
        }
    }

    #[test]
    fn oversized_input_is_rejected_without_allocating_runtime_state() {
        fuzz_udp_reset_races(&vec![0; MAX_UDP_RESET_FUZZ_INPUT_BYTES + 1]);
    }
}
