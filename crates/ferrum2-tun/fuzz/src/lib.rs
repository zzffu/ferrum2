#![forbid(unsafe_code)]

// Compile the production parser and reassembler directly into the fuzz package. This keeps their
// crate-private types private and avoids exposing a production-only fuzz API.
#[allow(dead_code)]
#[path = "../../src/packet.rs"]
mod packet;
#[allow(dead_code)]
#[path = "../../src/reassembly.rs"]
mod reassembly;
#[allow(dead_code)]
#[path = "../../src/udp.rs"]
mod udp;
#[allow(dead_code)]
#[path = "../../src/wake.rs"]
mod wake;

mod config_legacy;
mod strict_route;
mod udp_reset;

use std::sync::Arc;

pub use config_legacy::{MAX_CONFIG_LEGACY_FUZZ_INPUT_BYTES, fuzz_config_legacy_fields};
use packet::{Families, PacketParser, ParsedPacket};
use reassembly::{
    MAX_REASSEMBLY_ENTRIES, REASSEMBLY_TIMEOUT_MILLIS, ReassemblyOutcome, ReassemblyTable,
};
pub use strict_route::{MAX_STRICT_ROUTE_FUZZ_INPUT_BYTES, fuzz_strict_route_rule_builder};
pub use udp_reset::{MAX_UDP_RESET_FUZZ_INPUT_BYTES, fuzz_udp_reset_races};
pub(crate) use wake::OwnerWake;

/// Closed reasons needed by the production UDP state machine compiled into this fuzz package.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TunRejectReason {
    InvalidIpChecksum,
    InvalidTransportLength,
    InvalidSource,
    InvalidDestination,
    UdpAssociationLimit,
    UdpCandidateTimeout,
    UdpQueueFull,
    UdpResponseFiltered,
    UdpResponseClosed,
    StaleGeneration,
}

/// Closed terminal outcomes needed by the production UDP response path.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UdpResponseDropReason {
    StaleGeneration,
    AssociationClosed,
    QueueFull,
    MalformedResponse,
    Filtered,
    InjectionRejected,
    SessionReset,
    Shutdown,
    OwnerFatal,
}

/// Identity-free events emitted while fuzzing the production UDP state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TunEvent {
    PacketRejected(TunRejectReason),
    UdpAssociationsActive(usize),
    UdpCandidatesActive(usize),
    UdpAssociationCreated,
    UdpAssociationRejectedLimit,
    UdpDatagramQueueFull,
    UdpResponseQueueFull,
    UdpResponseFiltered,
    UdpResponseDropped(UdpResponseDropReason),
    UdpPendingResponses(usize),
    UdpStaleGeneration,
}

#[derive(Clone)]
pub(crate) struct TunEventSink {
    emit: Arc<dyn Fn(TunEvent) + Send + Sync>,
}

impl TunEventSink {
    pub(crate) fn new(emit: impl Fn(TunEvent) + Send + Sync + 'static) -> Self {
        Self {
            emit: Arc::new(emit),
        }
    }

    pub(crate) fn emit(&self, event: TunEvent) {
        (self.emit)(event);
    }
}

impl Default for TunEventSink {
    fn default() -> Self {
        Self::new(|_| {})
    }
}

/// Hard upper bound accepted by this target, including framing bytes.
pub const MAX_FUZZ_INPUT_BYTES: usize = 256 * 1024;

const MAX_PACKET_BYTES: usize = packet::MAX_REASSEMBLED_PACKET;
const MAX_FRAMES: usize = reassembly::MAX_FRAGMENTS_PER_ENTRY;
const HEX_CORPUS_MAGIC: &[u8] = b"F2HX\n";

// `reassembly.rs` keeps its production tests beside the implementation. When that source is
// compiled directly into this independent package under `cargo test`, provide the narrow
// admission predicate those tests exercise without pulling the complete TUN owner into the fuzz
// crate.
#[cfg(test)]
fn initial_tcp_tuple(parsed: packet::ParsedIpPacket) -> Result<Option<()>, ()> {
    let packet::TransportMetadata::Tcp(tcp) = parsed.transport else {
        return Ok(None);
    };
    if tcp.flags & 0x02 == 0 {
        return Ok(None);
    }
    if !tcp.is_initial_syn() {
        return Err(());
    }
    Ok(Some(()))
}

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

    fn parse_fragment(packet: &[u8]) -> packet::ParsedFragment {
        match parser_for(0).parse(packet) {
            Ok(ParsedPacket::Fragment(fragment)) => fragment,
            other => panic!("reviewed fragment did not parse as a fragment: {other:?}"),
        }
    }
}
