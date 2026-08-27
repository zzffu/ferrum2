use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

use crate::packet::{
    FragmentKey, FragmentReconstruction, IpFamily, MAX_REASSEMBLED_PACKET, ParsedFragment,
    internet_checksum,
};

pub(crate) const REASSEMBLY_TIMEOUT_MILLIS: i64 = 30_000;
pub(crate) const MAX_FRAGMENTS_PER_ENTRY: usize = 128;
pub(crate) const MAX_REASSEMBLY_ENTRIES: usize = 1_024;

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ReassemblyOutcome {
    Pending,
    Atomic(Vec<u8>),
    Complete(Vec<u8>),
    Dropped(ReassemblyDropReason),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ReassemblyAccept {
    pub(crate) outcome: ReassemblyOutcome,
    pub(crate) expired: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReassemblyDropReason {
    Malformed,
    Overlap,
    Limit,
}

#[derive(Clone, Debug)]
struct Piece {
    offset: usize,
    bytes: Vec<u8>,
}

impl Piece {
    fn end(&self) -> usize {
        self.offset + self.bytes.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Layout {
    Ipv4 {
        normalized_header: Vec<u8>,
        first_header: Option<Vec<u8>>,
    },
    Ipv6 {
        normalized_prefix: Vec<u8>,
        fragment_header_offset: usize,
        previous_next_header_offset: usize,
        upper_protocol: u8,
    },
}

#[derive(Debug)]
struct Entry {
    deadline_millis: i64,
    deadline_id: u64,
    layout: Layout,
    final_payload_len: Option<usize>,
    pieces: Vec<Piece>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DeadlineEntry {
    deadline_millis: i64,
    deadline_id: u64,
    key: FragmentKey,
}

#[derive(Debug)]
pub(crate) struct ReassemblyTable {
    generation: u64,
    entries: HashMap<FragmentKey, Entry>,
    deadlines: BinaryHeap<Reverse<DeadlineEntry>>,
    next_deadline_id: u64,
}

impl ReassemblyTable {
    pub(crate) fn new(generation: u64) -> Self {
        Self {
            generation,
            entries: HashMap::new(),
            deadlines: BinaryHeap::new(),
            next_deadline_id: 0,
        }
    }

    pub(crate) fn set_generation(&mut self, generation: u64) {
        if self.generation != generation {
            self.generation = generation;
            self.entries.clear();
            self.deadlines.clear();
        }
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.deadlines.clear();
    }

    pub(crate) fn drop_key(&mut self, key: FragmentKey) -> bool {
        self.entries.remove(&key).is_some()
    }

    pub(crate) fn accept(
        &mut self,
        packet: &[u8],
        fragment: ParsedFragment,
        now_millis: i64,
        generation: u64,
    ) -> ReassemblyAccept {
        self.set_generation(generation);
        let expired = self.expire(now_millis);
        let outcome = self.accept_current(packet, fragment, now_millis);
        ReassemblyAccept { outcome, expired }
    }

    fn accept_current(
        &mut self,
        packet: &[u8],
        fragment: ParsedFragment,
        now_millis: i64,
    ) -> ReassemblyOutcome {
        if !fragment.identity_matches_key()
            || fragment.payload_offset.checked_add(fragment.payload_len) != Some(packet.len())
            || fragment.payload_len == 0
        {
            self.entries.remove(&fragment.key);
            return ReassemblyOutcome::Dropped(ReassemblyDropReason::Malformed);
        }

        if fragment.is_atomic() {
            return reconstruct_atomic_ipv6(packet, fragment).map_or(
                ReassemblyOutcome::Dropped(ReassemblyDropReason::Malformed),
                ReassemblyOutcome::Atomic,
            );
        }

        let layout = match layout_for(packet, fragment) {
            Some(layout) => layout,
            None => {
                self.entries.remove(&fragment.key);
                return ReassemblyOutcome::Dropped(ReassemblyDropReason::Malformed);
            }
        };
        if !self.entries.contains_key(&fragment.key) {
            if self.entries.len() >= MAX_REASSEMBLY_ENTRIES {
                return ReassemblyOutcome::Dropped(ReassemblyDropReason::Limit);
            }
            self.compact_deadlines_if_needed();
            let deadline_millis = now_millis.saturating_add(REASSEMBLY_TIMEOUT_MILLIS);
            let deadline_id = self.next_deadline_id;
            self.next_deadline_id = self.next_deadline_id.wrapping_add(1);
            self.entries.insert(
                fragment.key,
                Entry {
                    deadline_millis,
                    deadline_id,
                    layout: layout.clone(),
                    final_payload_len: None,
                    pieces: Vec::new(),
                },
            );
            self.deadlines.push(Reverse(DeadlineEntry {
                deadline_millis,
                deadline_id,
                key: fragment.key,
            }));
        }

        let payload_end = match fragment.offset.checked_add(fragment.payload_len) {
            Some(end) if end <= MAX_REASSEMBLED_PACKET => end,
            _ => {
                self.entries.remove(&fragment.key);
                return ReassemblyOutcome::Dropped(ReassemblyDropReason::Malformed);
            }
        };
        let entry = self
            .entries
            .get_mut(&fragment.key)
            .expect("entry was inserted or already present");
        if !layouts_compatible(&entry.layout, &layout) {
            self.entries.remove(&fragment.key);
            return ReassemblyOutcome::Dropped(ReassemblyDropReason::Malformed);
        }
        merge_first_header(&mut entry.layout, layout);

        if entry.pieces.len() == MAX_FRAGMENTS_PER_ENTRY {
            self.entries.remove(&fragment.key);
            return ReassemblyOutcome::Dropped(ReassemblyDropReason::Limit);
        }
        if entry
            .pieces
            .iter()
            .any(|piece| fragment.offset < piece.end() && piece.offset < payload_end)
        {
            self.entries.remove(&fragment.key);
            return ReassemblyOutcome::Dropped(ReassemblyDropReason::Overlap);
        }
        if let Some(final_len) = entry.final_payload_len {
            if payload_end > final_len || (!fragment.more_fragments && payload_end != final_len) {
                self.entries.remove(&fragment.key);
                return ReassemblyOutcome::Dropped(ReassemblyDropReason::Malformed);
            }
        } else if !fragment.more_fragments {
            if entry.pieces.iter().any(|piece| piece.end() > payload_end) {
                self.entries.remove(&fragment.key);
                return ReassemblyOutcome::Dropped(ReassemblyDropReason::Malformed);
            }
            entry.final_payload_len = Some(payload_end);
        }

        entry.pieces.push(Piece {
            offset: fragment.offset,
            bytes: packet[fragment.payload_offset..].to_vec(),
        });
        entry.pieces.sort_unstable_by_key(|piece| piece.offset);

        let Some(final_len) = entry.final_payload_len else {
            return ReassemblyOutcome::Pending;
        };
        let mut cursor = 0;
        for piece in &entry.pieces {
            if piece.offset != cursor {
                return ReassemblyOutcome::Pending;
            }
            cursor = piece.end();
        }
        if cursor != final_len {
            return ReassemblyOutcome::Pending;
        }

        let entry = self
            .entries
            .remove(&fragment.key)
            .expect("complete entry remains present");
        reconstruct(entry, final_len).map_or(
            ReassemblyOutcome::Dropped(ReassemblyDropReason::Malformed),
            ReassemblyOutcome::Complete,
        )
    }

    pub(crate) fn next_deadline_millis(&mut self) -> Option<i64> {
        self.prune_stale_deadlines();
        self.deadlines
            .peek()
            .map(|Reverse(deadline)| deadline.deadline_millis)
    }

    pub(crate) fn expire(&mut self, now_millis: i64) -> usize {
        let mut expired = 0;
        loop {
            self.prune_stale_deadlines();
            let Some(Reverse(deadline)) = self.deadlines.peek().copied() else {
                break;
            };
            if deadline.deadline_millis > now_millis {
                break;
            }
            self.deadlines.pop();
            if self.deadline_is_current(deadline) {
                self.entries.remove(&deadline.key);
                expired += 1;
            }
        }
        expired
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    fn deadline_is_current(&self, deadline: DeadlineEntry) -> bool {
        self.entries.get(&deadline.key).is_some_and(|entry| {
            entry.deadline_millis == deadline.deadline_millis
                && entry.deadline_id == deadline.deadline_id
        })
    }

    fn prune_stale_deadlines(&mut self) {
        while self
            .deadlines
            .peek()
            .is_some_and(|Reverse(deadline)| !self.deadline_is_current(*deadline))
        {
            self.deadlines.pop();
        }
    }

    fn compact_deadlines_if_needed(&mut self) {
        if self.deadlines.len() <= MAX_REASSEMBLY_ENTRIES.saturating_mul(2) {
            return;
        }
        self.deadlines = self
            .entries
            .iter()
            .map(|(key, entry)| {
                Reverse(DeadlineEntry {
                    deadline_millis: entry.deadline_millis,
                    deadline_id: entry.deadline_id,
                    key: *key,
                })
            })
            .collect();
    }
}

fn layout_for(packet: &[u8], fragment: ParsedFragment) -> Option<Layout> {
    match fragment.reconstruction {
        FragmentReconstruction::Ipv4 { header_len } => {
            let header = packet.get(..header_len)?;
            let mut normalized_header = header.to_vec();
            normalized_header[2..4].fill(0);
            normalized_header[6..8].fill(0);
            normalized_header[10..12].fill(0);
            Some(Layout::Ipv4 {
                normalized_header,
                first_header: (fragment.offset == 0).then(|| header.to_vec()),
            })
        }
        FragmentReconstruction::Ipv6 {
            fragment_header_offset,
            previous_next_header_offset,
        } => {
            if previous_next_header_offset >= fragment_header_offset {
                return None;
            }
            let mut normalized_prefix = packet.get(..fragment_header_offset)?.to_vec();
            normalized_prefix[4..6].fill(0);
            Some(Layout::Ipv6 {
                normalized_prefix,
                fragment_header_offset,
                previous_next_header_offset,
                upper_protocol: fragment.upper_protocol,
            })
        }
    }
}

fn layouts_compatible(current: &Layout, incoming: &Layout) -> bool {
    match (current, incoming) {
        (
            Layout::Ipv4 {
                normalized_header: current,
                ..
            },
            Layout::Ipv4 {
                normalized_header: incoming,
                ..
            },
        ) => current == incoming,
        (
            Layout::Ipv6 {
                normalized_prefix: current_prefix,
                fragment_header_offset: current_fragment,
                previous_next_header_offset: current_previous,
                upper_protocol: current_protocol,
            },
            Layout::Ipv6 {
                normalized_prefix: incoming_prefix,
                fragment_header_offset: incoming_fragment,
                previous_next_header_offset: incoming_previous,
                upper_protocol: incoming_protocol,
            },
        ) => {
            current_prefix == incoming_prefix
                && current_fragment == incoming_fragment
                && current_previous == incoming_previous
                && current_protocol == incoming_protocol
        }
        _ => false,
    }
}

fn merge_first_header(current: &mut Layout, incoming: Layout) {
    if let (
        Layout::Ipv4 {
            normalized_header,
            first_header,
        },
        Layout::Ipv4 {
            normalized_header: incoming_normalized,
            first_header: Some(incoming_first),
        },
    ) = (current, incoming)
    {
        *normalized_header = incoming_normalized;
        *first_header = Some(incoming_first);
    }
}

fn reconstruct(entry: Entry, final_payload_len: usize) -> Option<Vec<u8>> {
    match entry.layout {
        Layout::Ipv4 {
            first_header: Some(mut header),
            ..
        } => {
            let total_len = header.len().checked_add(final_payload_len)?;
            if total_len > MAX_REASSEMBLED_PACKET {
                return None;
            }
            header[2..4].copy_from_slice(&u16::try_from(total_len).ok()?.to_be_bytes());
            let flags = u16::from_be_bytes([header[6], header[7]]) & 0x4000;
            header[6..8].copy_from_slice(&flags.to_be_bytes());
            header[10..12].fill(0);
            let checksum = internet_checksum(&[&header]);
            header[10..12].copy_from_slice(&checksum.to_be_bytes());
            let mut packet = header;
            append_pieces(&mut packet, entry.pieces);
            Some(packet)
        }
        Layout::Ipv4 {
            first_header: None, ..
        } => None,
        Layout::Ipv6 {
            mut normalized_prefix,
            fragment_header_offset,
            previous_next_header_offset,
            upper_protocol,
        } => {
            let total_len = fragment_header_offset.checked_add(final_payload_len)?;
            if total_len > MAX_REASSEMBLED_PACKET || fragment_header_offset < 40 {
                return None;
            }
            normalized_prefix[previous_next_header_offset] = upper_protocol;
            normalized_prefix[4..6]
                .copy_from_slice(&u16::try_from(total_len - 40).ok()?.to_be_bytes());
            let mut packet = normalized_prefix;
            append_pieces(&mut packet, entry.pieces);
            Some(packet)
        }
    }
}

fn append_pieces(packet: &mut Vec<u8>, pieces: Vec<Piece>) {
    for piece in pieces {
        packet.extend_from_slice(&piece.bytes);
    }
}

fn reconstruct_atomic_ipv6(packet: &[u8], fragment: ParsedFragment) -> Option<Vec<u8>> {
    if fragment.family != IpFamily::Ipv6 {
        return None;
    }
    let FragmentReconstruction::Ipv6 {
        fragment_header_offset,
        previous_next_header_offset,
    } = fragment.reconstruction
    else {
        return None;
    };
    let new_len = packet.len().checked_sub(8)?;
    if fragment_header_offset < 40
        || previous_next_header_offset >= fragment_header_offset
        || new_len > MAX_REASSEMBLED_PACKET
    {
        return None;
    }
    let mut rebuilt = Vec::with_capacity(new_len);
    rebuilt.extend_from_slice(packet.get(..fragment_header_offset)?);
    rebuilt[previous_next_header_offset] = fragment.upper_protocol;
    rebuilt.extend_from_slice(packet.get(fragment.payload_offset..)?);
    rebuilt[4..6].copy_from_slice(&u16::try_from(new_len - 40).ok()?.to_be_bytes());
    Some(rebuilt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::test_support::{
        ipv4_tcp_with_options, ipv4_udp, ipv6_udp, repair_ipv4_header, repair_transport_checksum,
    };
    use crate::packet::{
        Families, IP_PROTOCOL_TCP, PacketParser, PacketRejectReason, ParsedPacket,
        TransportMetadata,
    };

    fn ipv4_packet_fragments(packet: &[u8], sizes: &[usize], id: u16) -> Vec<Vec<u8>> {
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        let transport = &packet[header_len..];
        assert!(!sizes.is_empty());
        assert_eq!(sizes.iter().sum::<usize>(), transport.len());
        assert!(
            sizes
                .iter()
                .take(sizes.len() - 1)
                .all(|size| *size != 0 && size.is_multiple_of(8))
        );
        assert!(sizes.last().is_some_and(|size| *size != 0));

        let mut offset = 0_usize;
        sizes
            .iter()
            .enumerate()
            .map(|(index, size)| {
                let more = index + 1 != sizes.len();
                let mut fragment = packet[..header_len].to_vec();
                fragment.extend_from_slice(&transport[offset..offset + size]);
                let fragment_len = u16::try_from(fragment.len()).expect("fragment length");
                fragment[2..4].copy_from_slice(&fragment_len.to_be_bytes());
                fragment[4..6].copy_from_slice(&id.to_be_bytes());
                let mut field = u16::try_from(offset / 8).expect("fragment offset");
                if more {
                    field |= 0x2000;
                }
                fragment[6..8].copy_from_slice(&field.to_be_bytes());
                repair_ipv4_header(&mut fragment);
                offset += size;
                fragment
            })
            .collect()
    }

    fn ipv6_packet_fragments(
        packet: &[u8],
        unfragmentable_len: usize,
        previous_next_header_offset: usize,
        sizes: &[usize],
        id: u32,
    ) -> Vec<Vec<u8>> {
        assert!(unfragmentable_len >= 40);
        assert!(previous_next_header_offset < unfragmentable_len);
        let fragmentable = &packet[unfragmentable_len..];
        assert!(!sizes.is_empty());
        assert_eq!(sizes.iter().sum::<usize>(), fragmentable.len());
        assert!(
            sizes
                .iter()
                .take(sizes.len() - 1)
                .all(|size| *size != 0 && size.is_multiple_of(8))
        );
        assert!(sizes.last().is_some_and(|size| *size != 0));
        let upper_protocol = packet[previous_next_header_offset];

        let mut offset = 0_usize;
        sizes
            .iter()
            .enumerate()
            .map(|(index, size)| {
                let more = index + 1 != sizes.len();
                let mut fragment = packet[..unfragmentable_len].to_vec();
                fragment[previous_next_header_offset] = 44;
                fragment.extend_from_slice(&[upper_protocol, 0, 0, 0]);
                let flags = u16::try_from(offset).expect("fragment offset") | u16::from(more);
                fragment[unfragmentable_len + 2..unfragmentable_len + 4]
                    .copy_from_slice(&flags.to_be_bytes());
                fragment.extend_from_slice(&id.to_be_bytes());
                fragment.extend_from_slice(&fragmentable[offset..offset + size]);
                let payload_len =
                    u16::try_from(fragment.len() - 40).expect("IPv6 fragment payload length");
                fragment[4..6].copy_from_slice(&payload_len.to_be_bytes());
                offset += size;
                fragment
            })
            .collect()
    }

    fn ipv6_tcp_syn(payload: &[u8]) -> Vec<u8> {
        let tcp_len = 20 + payload.len();
        let mut packet = ipv6_udp(b"");
        packet.resize(40 + tcp_len, 0);
        packet[4..6].copy_from_slice(&u16::try_from(tcp_len).unwrap().to_be_bytes());
        packet[6] = IP_PROTOCOL_TCP;
        packet[40..42].copy_from_slice(&10_000_u16.to_be_bytes());
        packet[42..44].copy_from_slice(&443_u16.to_be_bytes());
        packet[52] = 5 << 4;
        packet[53] = 0x02;
        packet[54..56].copy_from_slice(&8_192_u16.to_be_bytes());
        packet[60..].copy_from_slice(payload);
        repair_transport_checksum(&mut packet, 40, IP_PROTOCOL_TCP);
        packet
    }

    fn ipv6_udp_with_hop_by_hop(payload: &[u8]) -> Vec<u8> {
        let base = ipv6_udp(payload);
        let mut packet = base[..40].to_vec();
        packet[6] = 0;
        packet.extend_from_slice(&[17, 0, 1, 4, 0, 0, 0, 0]);
        packet.extend_from_slice(&base[40..]);
        let payload_len = u16::try_from(packet.len() - 40).expect("IPv6 payload length");
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
        packet
    }

    fn ipv6_udp_with_destination_options(payload: &[u8]) -> Vec<u8> {
        let base = ipv6_udp(payload);
        let mut packet = base[..40].to_vec();
        packet[6] = 60;
        packet.extend_from_slice(&[17, 0, 1, 4, 0, 0, 0, 0]);
        packet.extend_from_slice(&base[40..]);
        let payload_len = u16::try_from(packet.len() - 40).expect("IPv6 payload length");
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
        packet
    }

    fn expected_ipv4_reassembly(mut packet: Vec<u8>, id: u16) -> Vec<u8> {
        packet[4..6].copy_from_slice(&id.to_be_bytes());
        let flags = u16::from_be_bytes([packet[6], packet[7]]) & 0x4000;
        packet[6..8].copy_from_slice(&flags.to_be_bytes());
        repair_ipv4_header(&mut packet);
        packet
    }

    fn complete_reassembly(
        parser: PacketParser,
        table: &mut ReassemblyTable,
        fragments: &[Vec<u8>],
        generation: u64,
    ) -> Vec<u8> {
        for (index, fragment) in fragments.iter().enumerate() {
            let metadata = parsed_fragment(parser, fragment);
            let accepted = table.accept(fragment, metadata, index as i64, generation);
            if index + 1 == fragments.len() {
                let ReassemblyOutcome::Complete(packet) = accepted.outcome else {
                    panic!("final fragment did not complete: {:?}", accepted.outcome)
                };
                return packet;
            }
            assert_eq!(accepted.outcome, ReassemblyOutcome::Pending);
        }
        unreachable!("fragment sequence is non-empty")
    }

    fn ipv4_fragments(payload: &[u8], split: usize, id: u16) -> (Vec<u8>, Vec<u8>) {
        ipv4_fragments_with_options(payload, split, id, &[])
    }

    fn ipv4_fragments_with_options(
        payload: &[u8],
        split: usize,
        id: u16,
        options: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let packet = ipv4_udp(payload, options);
        assert_eq!(split % 8, 0);
        let fragments = ipv4_packet_fragments(
            &packet,
            &[split, packet.len() - 20 - options.len() - split],
            id,
        );
        (fragments[0].clone(), fragments[1].clone())
    }

    fn ipv6_fragments(payload: &[u8], split: usize, id: u32) -> (Vec<u8>, Vec<u8>) {
        let packet = ipv6_udp(payload);
        assert_eq!(split % 8, 0);
        let fragments =
            ipv6_packet_fragments(&packet, 40, 6, &[split, packet.len() - 40 - split], id);
        (fragments[0].clone(), fragments[1].clone())
    }

    fn parsed_fragment(parser: PacketParser, packet: &[u8]) -> ParsedFragment {
        let ParsedPacket::Fragment(fragment) = parser.parse(packet).expect("valid fragment") else {
            panic!("fragment expected")
        };
        fragment
    }

    #[test]
    fn reassembles_ipv4_and_ipv6_strictly_out_of_order_then_reparses() {
        let parser = PacketParser::new(Families::DUAL);
        for (first, second) in [
            ipv4_fragments(b"abcdefghijklmnop", 16, 7),
            ipv6_fragments(b"abcdefghijklmnop", 16, 7),
        ] {
            let mut table = ReassemblyTable::new(1);
            let second_meta = parsed_fragment(parser, &second);
            assert_eq!(
                table.accept(&second, second_meta, 1, 1).outcome,
                ReassemblyOutcome::Pending
            );
            let first_meta = parsed_fragment(parser, &first);
            let ReassemblyOutcome::Complete(packet) =
                table.accept(&first, first_meta, 2, 1).outcome
            else {
                panic!("reassembly should complete")
            };
            assert!(matches!(
                parser.parse_reassembled(&packet),
                Ok(ParsedPacket::Complete(_))
            ));
        }
    }

    #[test]
    fn strips_atomic_ipv6_fragment_before_reparse() {
        let parser = PacketParser::new(Families::DUAL);
        let (mut atomic, _) = ipv6_fragments(b"atomic", 8, 99);
        let pending = atomic.clone();
        let original = ipv6_udp(b"atomic");
        atomic.truncate(48);
        atomic.extend_from_slice(&original[40..]);
        atomic[42..44].fill(0);
        let atomic_payload_len = u16::try_from(atomic.len() - 40).unwrap();
        atomic[4..6].copy_from_slice(&atomic_payload_len.to_be_bytes());
        let pending_meta = parsed_fragment(parser, &pending);
        let meta = parsed_fragment(parser, &atomic);
        let mut table = ReassemblyTable::new(1);
        assert_eq!(
            table.accept(&pending, pending_meta, 0, 1).outcome,
            ReassemblyOutcome::Pending
        );
        let ReassemblyOutcome::Atomic(rebuilt) = table.accept(&atomic, meta, 1, 1).outcome else {
            panic!("atomic fragment should be stripped")
        };
        assert_eq!(rebuilt, original);
        assert_eq!(
            table.len(),
            1,
            "atomic datagrams do not join or evict an in-progress entry with the same ID"
        );
        assert!(matches!(
            parser.parse_reassembled(&rebuilt),
            Ok(ParsedPacket::Complete(_))
        ));
    }

    #[test]
    fn overlap_or_duplicate_drops_the_entire_entry() {
        let parser = PacketParser::new(Families::DUAL);
        for (first, second) in [
            ipv4_fragments(b"abcdefghijklmnop", 16, 5),
            ipv6_fragments(b"abcdefghijklmnop", 16, 5),
        ] {
            let first_meta = parsed_fragment(parser, &first);
            let mut table = ReassemblyTable::new(1);
            assert_eq!(
                table.accept(&first, first_meta, 0, 1).outcome,
                ReassemblyOutcome::Pending
            );
            assert_eq!(
                table.accept(&first, first_meta, 1, 1).outcome,
                ReassemblyOutcome::Dropped(ReassemblyDropReason::Overlap)
            );
            assert_eq!(table.len(), 0);
            let second_meta = parsed_fragment(parser, &second);
            assert_eq!(
                table.accept(&second, second_meta, 2, 1).outcome,
                ReassemblyOutcome::Pending
            );
        }
    }

    #[test]
    fn first_fragment_header_mismatch_drops_prior_last_fragment() {
        let parser = PacketParser::new(Families::DUAL);
        let (mut first, second) =
            ipv4_fragments_with_options(b"abcdefghijklmnop", 16, 15, &[1, 1, 1, 0]);
        let second_meta = parsed_fragment(parser, &second);
        let mut table = ReassemblyTable::new(1);
        assert_eq!(
            table.accept(&second, second_meta, 0, 1).outcome,
            ReassemblyOutcome::Pending
        );

        first[20..24].copy_from_slice(&[2, 2, 1, 0]);
        repair_ipv4_header(&mut first);
        let first_meta = parsed_fragment(parser, &first);
        assert_eq!(
            table.accept(&first, first_meta, 1, 1).outcome,
            ReassemblyOutcome::Dropped(ReassemblyDropReason::Malformed)
        );
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn timeout_and_generation_change_prevent_cross_epoch_completion() {
        let parser = PacketParser::new(Families::DUAL);
        let (first, second) = ipv4_fragments(b"abcdefghijklmnop", 16, 6);
        let first_meta = parsed_fragment(parser, &first);
        let second_meta = parsed_fragment(parser, &second);
        let mut table = ReassemblyTable::new(1);
        assert_eq!(
            table.accept(&first, first_meta, 0, 1).outcome,
            ReassemblyOutcome::Pending
        );
        let expired = table.accept(&second, second_meta, REASSEMBLY_TIMEOUT_MILLIS, 1);
        assert_eq!(expired.outcome, ReassemblyOutcome::Pending);
        assert_eq!(expired.expired, 1);
        assert_eq!(
            table
                .accept(&first, first_meta, REASSEMBLY_TIMEOUT_MILLIS + 1, 2)
                .outcome,
            ReassemblyOutcome::Pending
        );
        assert_eq!(table.len(), 1);
        table.clear();
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn completed_key_reuse_prunes_stale_heap_deadline_without_expiring_new_entry() {
        let parser = PacketParser::new(Families::DUAL);
        let (first, second) = ipv4_fragments(b"abcdefghijklmnop", 16, 16);
        let first_meta = parsed_fragment(parser, &first);
        let second_meta = parsed_fragment(parser, &second);
        let mut table = ReassemblyTable::new(1);

        assert_eq!(
            table.accept(&first, first_meta, 0, 1).outcome,
            ReassemblyOutcome::Pending
        );
        assert!(matches!(
            table.accept(&second, second_meta, 1, 1).outcome,
            ReassemblyOutcome::Complete(_)
        ));
        assert_eq!(table.len(), 0);

        assert_eq!(
            table.accept(&first, first_meta, 10, 1).outcome,
            ReassemblyOutcome::Pending
        );
        assert_eq!(
            table.next_deadline_millis(),
            Some(10 + REASSEMBLY_TIMEOUT_MILLIS)
        );
        assert_eq!(table.expire(REASSEMBLY_TIMEOUT_MILLIS), 0);
        assert_eq!(table.len(), 1);
        assert_eq!(table.expire(10 + REASSEMBLY_TIMEOUT_MILLIS), 1);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn earliest_deadline_and_expire_count_track_only_live_entries() {
        let parser = PacketParser::new(Families::DUAL);
        let (first, _) = ipv4_fragments(b"abcdefghijklmnop", 16, 21);
        let (second, _) = ipv4_fragments(b"abcdefghijklmnop", 16, 22);
        let first_meta = parsed_fragment(parser, &first);
        let second_meta = parsed_fragment(parser, &second);
        let mut table = ReassemblyTable::new(1);
        assert_eq!(
            table.accept(&first, first_meta, 10, 1).outcome,
            ReassemblyOutcome::Pending
        );
        assert_eq!(
            table.accept(&second, second_meta, 20, 1).outcome,
            ReassemblyOutcome::Pending
        );
        assert_eq!(
            table.next_deadline_millis(),
            Some(10 + REASSEMBLY_TIMEOUT_MILLIS)
        );
        assert_eq!(table.expire(10 + REASSEMBLY_TIMEOUT_MILLIS - 1), 0);
        assert_eq!(table.expire(10 + REASSEMBLY_TIMEOUT_MILLIS), 1);
        assert_eq!(
            table.next_deadline_millis(),
            Some(20 + REASSEMBLY_TIMEOUT_MILLIS)
        );
        assert_eq!(table.expire(20 + REASSEMBLY_TIMEOUT_MILLIS), 1);
        assert_eq!(table.next_deadline_millis(), None);
    }

    #[test]
    fn reassembles_three_fragment_tcp_and_preserves_initial_syn_semantics() {
        let parser = PacketParser::new(Families::DUAL);
        let ipv4 = ipv4_tcp_with_options(&[1; 24]);
        let ipv6 = ipv6_tcp_syn(&[0x5a; 28]);
        let cases = [
            (
                expected_ipv4_reassembly(ipv4.clone(), 0x4101),
                ipv4_packet_fragments(&ipv4, &[16, 16, 12], 0x4101),
            ),
            (
                ipv6.clone(),
                ipv6_packet_fragments(&ipv6, 40, 6, &[16, 16, 16], 0x4102),
            ),
        ];

        for (original, fragments) in cases {
            let sequence = vec![
                fragments[2].clone(),
                fragments[0].clone(),
                fragments[1].clone(),
            ];
            let rebuilt = complete_reassembly(parser, &mut ReassemblyTable::new(41), &sequence, 41);
            assert_eq!(rebuilt, original);
            let ParsedPacket::Complete(parsed) = parser
                .parse_reassembled(&rebuilt)
                .expect("reassembled TCP SYN")
            else {
                panic!("complete TCP packet expected")
            };
            let TransportMetadata::Tcp(tcp) = parsed.transport else {
                panic!("TCP metadata expected")
            };
            assert_eq!(
                tcp.flags & 0x17,
                0x02,
                "reassembled packet remains an initial SYN"
            );
        }
    }

    #[test]
    fn fragmented_dns_reaches_post_reassembly_udp_dispatch_metadata() {
        let parser = PacketParser::new(Families::DUAL);
        let dns_query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let ipv4 = ipv4_udp(&dns_query, &[]);
        let ipv6 = ipv6_udp(&dns_query);
        let cases = [
            (
                expected_ipv4_reassembly(ipv4.clone(), 0xd501),
                ipv4_packet_fragments(&ipv4, &[8, 8, 17], 0xd501),
            ),
            (
                ipv6.clone(),
                ipv6_packet_fragments(&ipv6, 40, 6, &[8, 8, 17], 0xd502),
            ),
        ];

        for (original, fragments) in cases {
            let sequence = vec![
                fragments[1].clone(),
                fragments[2].clone(),
                fragments[0].clone(),
            ];
            let rebuilt = complete_reassembly(parser, &mut ReassemblyTable::new(51), &sequence, 51);
            assert_eq!(rebuilt, original);
            let ParsedPacket::Complete(parsed) = parser
                .parse_reassembled(&rebuilt)
                .expect("reassembled DNS datagram")
            else {
                panic!("complete UDP packet expected")
            };
            let TransportMetadata::Udp(udp) = parsed.transport else {
                panic!("UDP metadata expected")
            };
            assert_eq!(udp.destination_port, 53);
            assert_eq!(udp.payload_len, dns_query.len());
            assert_eq!(&rebuilt[udp.payload_offset..], &dns_query);
        }
    }

    #[test]
    fn missing_head_and_missing_tail_remain_pending_until_expiry() {
        let parser = PacketParser::new(Families::DUAL);
        let ipv4 = ipv4_udp(&[0x44; 40], &[]);
        let ipv6 = ipv6_udp(&[0x66; 40]);
        let cases = [
            ipv4_packet_fragments(&ipv4, &[16, 16, 16], 0x5201),
            ipv6_packet_fragments(&ipv6, 40, 6, &[16, 16, 16], 0x5202),
        ];

        for fragments in cases {
            let mut missing_head = ReassemblyTable::new(52);
            for fragment in &fragments[1..] {
                let metadata = parsed_fragment(parser, fragment);
                assert_eq!(
                    missing_head.accept(fragment, metadata, 0, 52).outcome,
                    ReassemblyOutcome::Pending
                );
            }
            assert_eq!(missing_head.len(), 1);
            assert_eq!(missing_head.expire(REASSEMBLY_TIMEOUT_MILLIS - 1), 0);
            assert_eq!(missing_head.expire(REASSEMBLY_TIMEOUT_MILLIS), 1);

            let mut missing_tail = ReassemblyTable::new(52);
            for fragment in &fragments[..2] {
                let metadata = parsed_fragment(parser, fragment);
                assert_eq!(
                    missing_tail.accept(fragment, metadata, 7, 52).outcome,
                    ReassemblyOutcome::Pending
                );
            }
            assert_eq!(missing_tail.len(), 1);
            assert_eq!(missing_tail.expire(7 + REASSEMBLY_TIMEOUT_MILLIS - 1), 0);
            assert_eq!(missing_tail.expire(7 + REASSEMBLY_TIMEOUT_MILLIS), 1);
        }
    }

    #[test]
    fn fragment_ids_isolate_concurrent_datagrams_and_same_key_collisions_fail_closed() {
        let parser = PacketParser::new(Families::DUAL);
        let packet_a = ipv4_udp(b"aaaaaaaaaaaaaaaa", &[]);
        let packet_b = ipv4_udp(b"bbbbbbbbbbbbbbbb", &[]);
        let a = ipv4_packet_fragments(&packet_a, &[16, 8], 0x5301);
        let b = ipv4_packet_fragments(&packet_b, &[16, 8], 0x5302);
        let mut table = ReassemblyTable::new(53);

        for fragment in [&a[0], &b[0]] {
            let metadata = parsed_fragment(parser, fragment);
            assert_eq!(
                table.accept(fragment, metadata, 0, 53).outcome,
                ReassemblyOutcome::Pending
            );
        }
        let b_meta = parsed_fragment(parser, &b[1]);
        assert_eq!(
            table.accept(&b[1], b_meta, 1, 53).outcome,
            ReassemblyOutcome::Complete(expected_ipv4_reassembly(packet_b, 0x5302))
        );
        let a_meta = parsed_fragment(parser, &a[1]);
        assert_eq!(
            table.accept(&a[1], a_meta, 2, 53).outcome,
            ReassemblyOutcome::Complete(expected_ipv4_reassembly(packet_a, 0x5301))
        );

        let collision_a =
            ipv4_packet_fragments(&ipv4_udp(b"aaaaaaaaaaaaaaaa", &[]), &[16, 8], 0x53ff);
        let collision_b =
            ipv4_packet_fragments(&ipv4_udp(b"bbbbbbbbbbbbbbbb", &[]), &[16, 8], 0x53ff);
        let mut collision = ReassemblyTable::new(53);
        let first_meta = parsed_fragment(parser, &collision_a[0]);
        assert_eq!(
            collision.accept(&collision_a[0], first_meta, 0, 53).outcome,
            ReassemblyOutcome::Pending
        );
        let conflicting_meta = parsed_fragment(parser, &collision_b[0]);
        assert_eq!(
            collision
                .accept(&collision_b[0], conflicting_meta, 1, 53)
                .outcome,
            ReassemblyOutcome::Dropped(ReassemblyDropReason::Overlap)
        );
        assert_eq!(collision.len(), 0);
    }

    #[test]
    fn reassembled_packet_boundary_is_exactly_65535_for_both_families() {
        let parser = PacketParser::new(Families::DUAL);

        let ipv4 = ipv4_udp(&vec![0x4a; MAX_REASSEMBLED_PACKET - 20 - 8], &[]);
        assert_eq!(ipv4.len(), MAX_REASSEMBLED_PACKET);
        let ipv4_fragments = ipv4_packet_fragments(&ipv4, &[32_768, 32_736, 11], 0x5401);
        let rebuilt =
            complete_reassembly(parser, &mut ReassemblyTable::new(54), &ipv4_fragments, 54);
        assert_eq!(rebuilt, expected_ipv4_reassembly(ipv4, 0x5401));
        assert!(matches!(
            parser.parse_reassembled(&rebuilt),
            Ok(ParsedPacket::Complete(_))
        ));

        let mut ipv4_over = ipv4_fragments[2].clone();
        let field = u16::from_be_bytes([ipv4_over[6], ipv4_over[7]]) + 1;
        ipv4_over[6..8].copy_from_slice(&field.to_be_bytes());
        repair_ipv4_header(&mut ipv4_over);
        assert_eq!(
            parser
                .parse(&ipv4_over)
                .expect_err("IPv4 reassembled size over 65535")
                .reason,
            PacketRejectReason::InvalidFragment
        );

        let ipv6 = ipv6_udp(&vec![0x6a; MAX_REASSEMBLED_PACKET - 40 - 8]);
        assert_eq!(ipv6.len(), MAX_REASSEMBLED_PACKET);
        let ipv6_fragments = ipv6_packet_fragments(&ipv6, 40, 6, &[32_768, 32_720, 7], 0x5402);
        let rebuilt =
            complete_reassembly(parser, &mut ReassemblyTable::new(54), &ipv6_fragments, 54);
        assert_eq!(rebuilt, ipv6);
        assert!(matches!(
            parser.parse_reassembled(&rebuilt),
            Ok(ParsedPacket::Complete(_))
        ));

        let mut ipv6_over = ipv6.clone();
        ipv6_over.push(0);
        let fragments = ipv6_packet_fragments(&ipv6_over, 40, 6, &[32_768, 32_720, 8], 0x54ff);
        let mut table = ReassemblyTable::new(54);
        for fragment in &fragments[..2] {
            let metadata = parsed_fragment(parser, fragment);
            assert_eq!(
                table.accept(fragment, metadata, 0, 54).outcome,
                ReassemblyOutcome::Pending
            );
        }
        let metadata = parsed_fragment(parser, &fragments[2]);
        assert_eq!(
            table.accept(&fragments[2], metadata, 0, 54).outcome,
            ReassemblyOutcome::Dropped(ReassemblyDropReason::Malformed)
        );
    }

    #[test]
    fn ipv6_extensions_before_and_after_fragment_reassemble_canonically() {
        let parser = PacketParser::new(Families::DUAL);
        let before = ipv6_udp_with_hop_by_hop(&[0x11; 24]);
        let before_fragments = ipv6_packet_fragments(&before, 48, 40, &[16, 16], 0x5501);
        let rebuilt =
            complete_reassembly(parser, &mut ReassemblyTable::new(55), &before_fragments, 55);
        assert_eq!(rebuilt, before);
        let ParsedPacket::Complete(parsed) = parser
            .parse_reassembled(&rebuilt)
            .expect("Hop-by-Hop before Fragment")
        else {
            panic!("complete packet expected")
        };
        assert_eq!(parsed.transport_offset, 48);

        let after = ipv6_udp_with_destination_options(&[0x22; 24]);
        let after_fragments = ipv6_packet_fragments(&after, 40, 6, &[16, 24], 0x5502);
        let rebuilt =
            complete_reassembly(parser, &mut ReassemblyTable::new(55), &after_fragments, 55);
        assert_eq!(rebuilt, after);
        let ParsedPacket::Complete(parsed) = parser
            .parse_reassembled(&rebuilt)
            .expect("Destination Options after Fragment")
        else {
            panic!("complete packet expected")
        };
        assert_eq!(parsed.transport_offset, 48);
    }

    #[test]
    fn second_ipv6_fragment_header_is_rejected_before_or_after_reassembly() {
        let parser = PacketParser::new(Families::DUAL);
        let (mut direct, _) = ipv6_fragments(b"second-fragment", 16, 0x5601);
        direct[40] = 44;
        let rejected = parser
            .parse(&direct)
            .expect_err("Fragment directly naming Fragment");
        assert_eq!(rejected.reason, PacketRejectReason::UnsupportedProtocol);
        assert!(rejected.fragment_key.is_some());

        let udp = ipv6_udp(b"nested-fragment");
        let mut nested = udp[..40].to_vec();
        nested[6] = 60;
        nested.extend_from_slice(&[44, 0, 1, 4, 0, 0, 0, 0]);
        nested.extend_from_slice(&[17, 0, 0, 0, 0x56, 0x02, 0, 1]);
        nested.extend_from_slice(&udp[40..]);
        let nested_len = nested.len() - 40;
        nested[4..6].copy_from_slice(&u16::try_from(nested_len).unwrap().to_be_bytes());
        let fragmentable_len = nested.len() - 40;
        let fragments = ipv6_packet_fragments(&nested, 40, 6, &[16, fragmentable_len - 16], 0x5603);
        let rebuilt = complete_reassembly(parser, &mut ReassemblyTable::new(56), &fragments, 56);
        assert_eq!(
            parser
                .parse_reassembled(&rebuilt)
                .expect_err("second Fragment after fragmentable extension")
                .reason,
            PacketRejectReason::UnsupportedProtocol
        );
    }

    #[test]
    fn ipv6_unfragmentable_prefix_mismatch_drops_the_whole_entry() {
        let parser = PacketParser::new(Families::DUAL);
        let packet = ipv6_udp_with_hop_by_hop(&[0x33; 24]);
        let mut fragments = ipv6_packet_fragments(&packet, 48, 40, &[16, 16], 0x5701);
        fragments[1][44] ^= 1;

        let mut table = ReassemblyTable::new(57);
        let first_meta = parsed_fragment(parser, &fragments[0]);
        assert_eq!(
            table.accept(&fragments[0], first_meta, 0, 57).outcome,
            ReassemblyOutcome::Pending
        );
        let second_meta = parsed_fragment(parser, &fragments[1]);
        assert_eq!(
            table.accept(&fragments[1], second_meta, 1, 57).outcome,
            ReassemblyOutcome::Dropped(ReassemblyDropReason::Malformed)
        );
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn disabled_family_fragments_are_rejected_before_allocating_reassembly_state() {
        let (ipv4, _) = ipv4_fragments(b"disabled-family", 16, 0x5801);
        let (ipv6, _) = ipv6_fragments(b"disabled-family", 16, 0x5802);
        for (parser, fragment) in [
            (PacketParser::new(Families::IPV6_ONLY), ipv4),
            (PacketParser::new(Families::IPV4_ONLY), ipv6),
        ] {
            let rejected = parser
                .parse(&fragment)
                .expect_err("disabled family fragment");
            assert_eq!(rejected.reason, PacketRejectReason::DisabledFamily);
            assert_eq!(rejected.fragment_key, None);
        }
    }

    #[test]
    fn generation_change_discards_partial_state_before_accepting_new_epoch_fragments() {
        let parser = PacketParser::new(Families::DUAL);
        let (first, second) = ipv4_fragments(b"restart-generation", 16, 0x5901);
        let first_meta = parsed_fragment(parser, &first);
        let second_meta = parsed_fragment(parser, &second);
        let mut table = ReassemblyTable::new(100);

        assert_eq!(
            table.accept(&first, first_meta, 0, 100).outcome,
            ReassemblyOutcome::Pending
        );
        assert_eq!(
            table.accept(&second, second_meta, 1, 101).outcome,
            ReassemblyOutcome::Pending,
            "new generation tail cannot complete with stale head"
        );
        assert_eq!(table.len(), 1);
        assert!(matches!(
            table.accept(&first, first_meta, 2, 101).outcome,
            ReassemblyOutcome::Complete(_)
        ));
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn malformed_fragment_header_matrix_fails_closed() {
        let parser = PacketParser::new(Families::DUAL);
        let (ipv4, _) = ipv4_fragments(b"negative-matrix", 16, 0x5a01);

        let mut bad_checksum = ipv4.clone();
        bad_checksum[8] ^= 1;
        assert_eq!(
            parser
                .parse(&bad_checksum)
                .expect_err("bad fragment checksum")
                .reason,
            PacketRejectReason::InvalidHeaderChecksum
        );

        let mut df_and_mf = ipv4.clone();
        df_and_mf[6..8].copy_from_slice(&0x6000_u16.to_be_bytes());
        repair_ipv4_header(&mut df_and_mf);
        assert_eq!(
            parser.parse(&df_and_mf).expect_err("DF and MF").reason,
            PacketRejectReason::InvalidFragment
        );

        let mut short_nonfinal = ipv4;
        short_nonfinal.pop();
        let short_len = u16::try_from(short_nonfinal.len()).unwrap();
        short_nonfinal[2..4].copy_from_slice(&short_len.to_be_bytes());
        repair_ipv4_header(&mut short_nonfinal);
        assert_eq!(
            parser
                .parse(&short_nonfinal)
                .expect_err("non-final fragment length is not a multiple of eight")
                .reason,
            PacketRejectReason::InvalidFragment
        );

        let (mut ipv6, _) = ipv6_fragments(b"negative-matrix", 16, 0x5a02);
        ipv6[42..44].copy_from_slice(&0x0002_u16.to_be_bytes());
        assert_eq!(
            parser
                .parse(&ipv6)
                .expect_err("reserved IPv6 Fragment bits")
                .reason,
            PacketRejectReason::InvalidFragment
        );
    }

    #[test]
    fn deterministic_mutation_corpus_never_panics_parser_or_reassembly() {
        fn next(state: &mut u64) -> u64 {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state
        }

        let parser = PacketParser::new(Families::DUAL);
        let (ipv4_first, ipv4_last) = ipv4_fragments(b"mutation-seed-payload", 16, 0x5b01);
        let before = ipv6_udp_with_hop_by_hop(b"mutation-seed-payload");
        let mut seeds = vec![ipv4_first, ipv4_last];
        seeds.extend(ipv6_packet_fragments(
            &before,
            48,
            40,
            &[16, before.len() - 48 - 16],
            0x5b02,
        ));
        seeds.push(ipv4_udp(b"complete-seed", &[]));
        seeds.push(ipv6_udp(b"complete-seed"));

        let mut state = 0x8f3c_2a19_74d6_b5e1_u64;
        let mut table = ReassemblyTable::new(0);
        for case in 0..4_096_u64 {
            let seed_index = (next(&mut state) as usize) % seeds.len();
            let mut packet = seeds[seed_index].clone();
            match next(&mut state) % 5 {
                0 => {
                    let new_len = (next(&mut state) as usize) % (packet.len() + 1);
                    packet.truncate(new_len);
                }
                1 => {
                    let mutations = 1 + (next(&mut state) as usize % 8);
                    for _ in 0..mutations {
                        let index = (next(&mut state) as usize) % packet.len();
                        packet[index] ^= next(&mut state) as u8;
                    }
                }
                2 => {
                    let extra = next(&mut state) as usize % 33;
                    for _ in 0..extra {
                        packet.push(next(&mut state) as u8);
                    }
                }
                3 => {
                    let length = next(&mut state) as usize % 1_024;
                    packet.clear();
                    packet.reserve(length);
                    for _ in 0..length {
                        packet.push(next(&mut state) as u8);
                    }
                }
                _ => {}
            }

            let generation = case / 257;
            match parser.parse(&packet) {
                Ok(ParsedPacket::Complete(parsed)) => {
                    assert!(parsed.metadata_matches(packet.len()));
                }
                Ok(ParsedPacket::Fragment(fragment)) => {
                    let accepted = table.accept(&packet, fragment, case as i64, generation);
                    match accepted.outcome {
                        ReassemblyOutcome::Atomic(rebuilt)
                        | ReassemblyOutcome::Complete(rebuilt) => {
                            let _ = parser.parse_reassembled(&rebuilt);
                        }
                        ReassemblyOutcome::Pending | ReassemblyOutcome::Dropped(_) => {}
                    }
                }
                Err(rejected) => {
                    if let Some(key) = rejected.fragment_key {
                        table.drop_key(key);
                    }
                }
            }
        }
    }

    #[test]
    fn packet_corpus_exercises_stable_parser_and_reassembly_contracts() {
        fn decode_hex(encoded: &str) -> Vec<u8> {
            assert!(!encoded.is_empty());
            assert!(encoded.len().is_multiple_of(2));
            assert!(
                encoded
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "fixture hex must be canonical lowercase ASCII"
            );
            encoded
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let high = char::from(pair[0]).to_digit(16).expect("hex high nibble");
                    let low = char::from(pair[1]).to_digit(16).expect("hex low nibble");
                    u8::try_from((high << 4) | low).expect("hex byte")
                })
                .collect()
        }

        fn accept_fragment(
            parser: PacketParser,
            table: &mut ReassemblyTable,
            packet: &[u8],
            now_millis: i64,
            generation: u64,
        ) -> ReassemblyAccept {
            let fragment = parsed_fragment(parser, packet);
            table.accept(packet, fragment, now_millis, generation)
        }

        const CORPUS: &str = include_str!("../tests/fixtures/packets/reassembly-v1.hex");
        const PROVENANCE: &str = include_str!("../tests/fixtures/packets/PROVENANCE.toml");
        assert!(
            !CORPUS.contains('\r'),
            "packet corpus must use canonical LF"
        );
        assert!(CORPUS.ends_with('\n'), "packet corpus needs a final LF");
        assert!(
            !PROVENANCE.contains('\r') && PROVENANCE.ends_with('\n'),
            "packet provenance must use canonical LF with a final LF"
        );
        assert!(PROVENANCE.contains(
            "consumer = \"crates/ferrum2-tun/src/reassembly.rs packet_corpus_exercises_stable_parser_and_reassembly_contracts\""
        ));
        let documented_digest = PROVENANCE
            .lines()
            .find_map(|line| line.strip_prefix("corpus_sha256 = \"")?.strip_suffix('"'))
            .expect("packet provenance SHA-256");
        assert_eq!(documented_digest.len(), 64);
        assert!(
            documented_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "provenance digest must be lowercase SHA-256"
        );

        let parser = PacketParser::new(Families::DUAL);
        let mut active_case = "";
        let mut table = ReassemblyTable::new(97);
        let mut closed_cases = std::collections::BTreeSet::new();
        let mut cases = std::collections::BTreeSet::new();
        let mut operations = std::collections::BTreeSet::new();
        let mut row_count = 0_usize;
        for (line_number, line) in CORPUS.lines().enumerate() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split('|');
            let name = fields.next().expect("fixture case name");
            let expected = fields.next().expect("fixture expectation");
            let encoded = fields.next().expect("fixture packet bytes");
            assert!(fields.next().is_none(), "extra field on line {line_number}");
            assert!(
                name.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
                "non-canonical case name on line {line_number}"
            );
            let packet = decode_hex(encoded);
            row_count += 1;
            cases.insert(name);
            operations.insert(expected);

            if name != active_case {
                assert!(
                    !closed_cases.contains(name),
                    "case {name} has non-contiguous rows"
                );
                if !active_case.is_empty() {
                    closed_cases.insert(active_case);
                }
                table = ReassemblyTable::new(97);
                active_case = name;
            }
            match expected {
                "pending" => assert_eq!(
                    accept_fragment(parser, &mut table, &packet, 0, 97),
                    ReassemblyAccept {
                        outcome: ReassemblyOutcome::Pending,
                        expired: 0,
                    },
                    "{name}"
                ),
                "complete" | "timeout_complete" | "restart_complete" => {
                    let (now_millis, generation) = match expected {
                        "complete" => (1, 97),
                        "timeout_complete" => (REASSEMBLY_TIMEOUT_MILLIS + 1, 97),
                        "restart_complete" => (2, 98),
                        _ => unreachable!(),
                    };
                    let accepted =
                        accept_fragment(parser, &mut table, &packet, now_millis, generation);
                    assert_eq!(accepted.expired, 0, "{name}");
                    let ReassemblyOutcome::Complete(rebuilt) = accepted.outcome else {
                        panic!("{name} did not complete: {:?}", accepted.outcome)
                    };
                    assert!(matches!(
                        parser.parse_reassembled(&rebuilt),
                        Ok(ParsedPacket::Complete(_))
                    ));
                }
                "overlap" | "collision" => {
                    assert_eq!(
                        accept_fragment(parser, &mut table, &packet, 1, 97),
                        ReassemblyAccept {
                            outcome: ReassemblyOutcome::Dropped(ReassemblyDropReason::Overlap),
                            expired: 0,
                        },
                        "{name}"
                    );
                    assert_eq!(table.len(), 0, "{name} collision state survived");
                }
                "timeout_pending" => assert_eq!(
                    accept_fragment(parser, &mut table, &packet, REASSEMBLY_TIMEOUT_MILLIS, 97,),
                    ReassemblyAccept {
                        outcome: ReassemblyOutcome::Pending,
                        expired: 1,
                    },
                    "expired head must not complete with the fixed tail"
                ),
                "restart_pending" => assert_eq!(
                    accept_fragment(parser, &mut table, &packet, 1, 98),
                    ReassemblyAccept {
                        outcome: ReassemblyOutcome::Pending,
                        expired: 0,
                    },
                    "old-generation head must not complete after restart"
                ),
                "boundary_65535" => {
                    let fragment = parsed_fragment(parser, &packet);
                    let prefix_len = match fragment.reconstruction {
                        FragmentReconstruction::Ipv4 { header_len } => header_len,
                        FragmentReconstruction::Ipv6 {
                            fragment_header_offset,
                            ..
                        } => fragment_header_offset,
                    };
                    assert_eq!(
                        prefix_len
                            .checked_add(fragment.offset)
                            .and_then(|length| length.checked_add(fragment.payload_len)),
                        Some(MAX_REASSEMBLED_PACKET),
                        "{name} exact reconstructed boundary"
                    );
                    assert_eq!(
                        table.accept(&packet, fragment, 0, 97),
                        ReassemblyAccept {
                            outcome: ReassemblyOutcome::Pending,
                            expired: 0,
                        },
                        "{name} compact terminal fragment"
                    );
                }
                "unsupported" => {
                    let rejected = parser.parse(&packet).expect_err("unsupported fixture");
                    assert_eq!(
                        rejected.reason,
                        PacketRejectReason::UnsupportedProtocol,
                        "{name}"
                    );
                    assert!(rejected.fragment_key.is_some(), "{name} key attribution");
                    assert_eq!(table.len(), 0, "{name} allocated reassembly state");
                }
                "malformed_extension"
                | "invalid_checksum"
                | "invalid_length"
                | "invalid_fragment" => {
                    let expected_reason = match expected {
                        "malformed_extension" => PacketRejectReason::MalformedExtension,
                        "invalid_checksum" => PacketRejectReason::InvalidHeaderChecksum,
                        "invalid_length" => PacketRejectReason::InvalidLength,
                        "invalid_fragment" => PacketRejectReason::InvalidFragment,
                        _ => unreachable!(),
                    };
                    let rejected = parser.parse(&packet).expect_err("negative corpus vector");
                    assert_eq!(rejected.reason, expected_reason, "{name}");
                    assert_eq!(
                        rejected.fragment_key.is_some(),
                        expected == "invalid_fragment",
                        "{name} fragment-key attribution"
                    );
                    assert_eq!(table.len(), 0, "{name} allocated reassembly state");
                }
                "disabled" => {
                    let disabled_parser = match packet[0] >> 4 {
                        4 => PacketParser::new(Families::IPV6_ONLY),
                        6 => PacketParser::new(Families::IPV4_ONLY),
                        version => panic!("invalid fixture IP version {version}"),
                    };
                    let rejected = disabled_parser
                        .parse(&packet)
                        .expect_err("disabled-family fixture");
                    assert_eq!(
                        rejected.reason,
                        PacketRejectReason::DisabledFamily,
                        "{name}"
                    );
                    assert_eq!(rejected.fragment_key, None, "{name} key attribution");
                    assert_eq!(table.len(), 0, "{name} allocated reassembly state");
                }
                other => panic!("unknown fixture expectation {other}"),
            }
        }

        assert_eq!(row_count, 26, "packet corpus row count changed");
        assert!(PROVENANCE.contains("row_count = 26"));
        for required in [
            "boundary_65535",
            "collision",
            "complete",
            "disabled",
            "invalid_checksum",
            "invalid_fragment",
            "invalid_length",
            "malformed_extension",
            "overlap",
            "restart_complete",
            "restart_pending",
            "timeout_complete",
            "timeout_pending",
            "unsupported",
        ] {
            assert!(
                operations.contains(required),
                "missing {required} operation"
            );
        }
        for required in [
            "ipv4_boundary_65535",
            "ipv4_disabled",
            "ipv4_id_collision",
            "ipv4_restart_stale",
            "ipv4_timeout",
            "ipv6_boundary_65535",
            "ipv6_destination_udp",
            "ipv6_disabled",
            "ipv6_hbh_udp",
        ] {
            assert!(cases.contains(required), "missing {required} case");
        }
    }

    #[test]
    fn fragment_and_entry_limits_drop_without_evicting_existing_entries() {
        let parser = PacketParser::new(Families::DUAL);
        let mut table = ReassemblyTable::new(1);
        for id in 0..MAX_REASSEMBLY_ENTRIES {
            let (first, _) = ipv4_fragments(b"abcdefghijklmnop", 16, id as u16);
            let meta = parsed_fragment(parser, &first);
            assert_eq!(
                table.accept(&first, meta, 0, 1).outcome,
                ReassemblyOutcome::Pending
            );
        }
        let (extra, _) = ipv4_fragments(b"abcdefghijklmnop", 16, u16::MAX);
        let meta = parsed_fragment(parser, &extra);
        assert_eq!(
            table.accept(&extra, meta, 0, 1).outcome,
            ReassemblyOutcome::Dropped(ReassemblyDropReason::Limit)
        );
        assert_eq!(table.len(), MAX_REASSEMBLY_ENTRIES);

        let mut table = ReassemblyTable::new(1);
        for index in 0..=MAX_FRAGMENTS_PER_ENTRY {
            let mut fragment = ipv4_fragments(b"abcdefghijklmnop", 16, 8).0;
            let field = 0x2000 | u16::try_from(index * 2).unwrap();
            fragment[6..8].copy_from_slice(&field.to_be_bytes());
            repair_ipv4_header(&mut fragment);
            let meta = parsed_fragment(parser, &fragment);
            let outcome = table.accept(&fragment, meta, 0, 1).outcome;
            if index == MAX_FRAGMENTS_PER_ENTRY {
                assert_eq!(
                    outcome,
                    ReassemblyOutcome::Dropped(ReassemblyDropReason::Limit)
                );
            } else {
                assert_eq!(outcome, ReassemblyOutcome::Pending);
            }
        }
        assert_eq!(table.len(), 0);
    }
}
