//! Established tuple rewrite, not parser, scheduler, socket-I/O or OS throughput.
//! Recipe v1: 32 published mappings in 64 slots; 1024 two-packet rounds/window.
//! Quick: 64-byte payload and 64 windows. Confirm: MTU 1500 minus the family IP
//! header and 20-byte TCP header, and 128 windows. One complete warm window is
//! untimed. Each pair visits mapping round % 32; even mappings go forward then
//! reverse, odd mappings reverse then forward. Every rewrite advances time 1ms.
//! After each window, untimed expiry advances to two milliseconds before the
//! earliest refreshed deadline. This exposes the exact minimum via real expiry
//! and makes the next window cross each old deadline between its two directions.
//! Inputs, expected bytes, metadata, captures and result slots are prepared off
//! clock. Timing includes rewrite calls, logical-tick increments and result stores.

use super::owner::parse;
use super::recipe::{MTU, endpoints, packet};
use crate::packet::{ParsedIpPacket, TransportMetadata, internet_checksum};
use crate::system_tcp::{PortQuarantine, SystemTcp};
use crate::{OwnerWake, TunRejectReason};
use ferrum2_runtime::OwnerRegistry;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ACTIVE: usize = 32;
const CAPACITY: usize = 64;
const ROUNDS: usize = 1024;
const PACKETS: usize = ROUNDS * 2;
const TIMEOUT_MILLIS: i64 = 4096;

struct Fixture {
    input: Vec<u8>,
    expected: Vec<u8>,
    capture: Vec<u8>,
    parsed: ParsedIpPacket,
    result: Result<(), TunRejectReason>,
}

// Encode the global packet ordinal in both the TCP sequence and payload. The
// expected tuple is independently constructed by recipe::packet, not obtained
// by applying the production rewriter to another copy of the input.
fn stamp(bytes: &mut [u8], ordinal: usize, ip_header: usize) {
    bytes[ip_header + 4..ip_header + 8].copy_from_slice(
        &u32::try_from(ordinal)
            .expect("bounded sequence")
            .to_be_bytes(),
    );
    bytes[ip_header + 20..ip_header + 28].copy_from_slice(
        &u64::try_from(ordinal)
            .expect("bounded ordinal")
            .to_be_bytes(),
    );
    bytes[ip_header + 16..ip_header + 18].fill(0);
    let length = u16::try_from(bytes.len() - ip_header)
        .expect("MTU transport")
        .to_be_bytes();
    let checksum = if ip_header == 20 {
        internet_checksum(&[&bytes[12..20], &[0, 6], &length, &bytes[ip_header..]])
    } else {
        internet_checksum(&[
            &bytes[8..40],
            &[0, 0],
            &length,
            &[0, 0, 0, 6],
            &bytes[ip_header..],
        ])
    };
    bytes[ip_header + 16..ip_header + 18].copy_from_slice(&checksum.to_be_bytes());
}

fn prepare(fixtures: &mut [Fixture], window: usize, ip_header: usize) {
    for (index, fixture) in fixtures.iter_mut().enumerate() {
        let ordinal = window * PACKETS + index + 1;
        stamp(&mut fixture.input, ordinal, ip_header);
        stamp(&mut fixture.expected, ordinal, ip_header);
        fixture.parsed = parse(&fixture.input);
        parse(&fixture.expected);
        // Restoring the original tuple makes a missing rewrite fail full-byte
        // comparison even when the same capture storage was used last window.
        fixture.capture.copy_from_slice(&fixture.input);
        fixture.result = Err(TunRejectReason::InvalidDestination);
    }
}

fn window(system: &mut SystemTcp, fixtures: &mut [Fixture], now: &mut i64) {
    for fixture in fixtures {
        *now += 1;
        fixture.result = system.rewrite(&mut fixture.capture, fixture.parsed, true, *now);
    }
}

fn validate(fixtures: &[Fixture]) -> usize {
    let mut checked = 0;
    for (index, fixture) in fixtures.iter().enumerate() {
        assert_eq!(fixture.result, Ok(()), "rewrite result at packet {index}");
        assert_eq!(
            fixture.capture, fixture.expected,
            "complete ordered packet {index}"
        );
        parse(&fixture.capture);
        checked += 1;
    }
    assert_eq!(checked, PACKETS);
    checked
}

pub(super) fn trial(scenario: &str, mode: &str) -> Result<String, &'static str> {
    let ipv6 = match scenario {
        "tcp-established-v4" => false,
        "tcp-established-v6" => true,
        _ => return Err("unknown established detail scenario"),
    };
    let ip_header = if ipv6 { 40 } else { 20 };
    let (payload_len, windows) = match mode {
        "Quick" => (64, 64),
        "Confirm" => (MTU - ip_header - 20, 128),
        _ => return Err("mode must be Quick or Confirm"),
    };
    let count = Arc::new(AtomicUsize::new(0));
    let (mut system, mut receiver) = SystemTcp::new(
        CAPACITY,
        Duration::from_millis(TIMEOUT_MILLIS as u64),
        1,
        Arc::clone(&count),
        OwnerRegistry::new(),
        OwnerWake::default(),
        Arc::new(Mutex::new(PortQuarantine::default())),
    );
    system
        .configure_packet_bindings(
            if ipv6 {
                (
                    None,
                    Some(("2001:db8:ffff::1".parse().expect("fixture"), 126)),
                )
            } else {
                (Some(("198.18.0.1".parse().expect("fixture"), 30)), None)
            },
            if ipv6 {
                (None, Some(20001))
            } else {
                (Some(20000), None)
            },
        )
        .expect("memory-only listener identity");

    let mut tuples = Vec::with_capacity(ACTIVE);
    let mut flows = Vec::with_capacity(ACTIVE);
    let mut peers = Vec::with_capacity(ACTIVE);
    for index in 0..ACTIVE {
        let (source, target) = endpoints(ipv6, index);
        let mut syn = packet(source, target, Some(2), &[]);
        let parsed = parse(&syn);
        system
            .rewrite(&mut syn, parsed, true, 0)
            .expect("create SYN mapping");
        let translated = parse(&syn);
        let TransportMetadata::Tcp(tcp) = translated.transport else {
            panic!("translated SYN must remain TCP");
        };
        let peer = SocketAddr::new(translated.source, tcp.source_port);
        let listener = SocketAddr::new(translated.destination, tcp.destination_port);
        assert_eq!(syn, packet(peer, listener, Some(2), &[]));
        tuples.push((source, target, peer, listener));
        let (socket, peer_socket) = tokio::io::duplex(MTU);
        system.accept_packet_socket(source, target, socket);
        assert!(system.expire(0), "accept must publish actual flow");
        let flow = receiver.try_recv().expect("published established flow");
        assert_eq!(flow.target(), target);
        flows.push(flow);
        peers.push(peer_socket);
    }
    assert!(receiver.try_recv().is_err());
    assert_eq!(count.load(Ordering::Acquire), ACTIVE);
    assert_eq!(system.next_deadline_millis(), Some(TIMEOUT_MILLIS));

    let payload: Vec<u8> = (0..payload_len)
        .map(|index| ((index * 37 + 11) % 256) as u8)
        .collect();
    let mut fixtures = Vec::with_capacity(PACKETS);
    for round in 0..ROUNDS {
        let mapping = round % ACTIVE;
        let (source, target, peer, listener) = tuples[mapping];
        for direction in 0..2 {
            let forward = direction == mapping % 2;
            let (input, expected) = if forward {
                (
                    packet(source, target, Some(0x10), &payload),
                    packet(peer, listener, Some(0x10), &payload),
                )
            } else {
                (
                    packet(listener, peer, Some(0x10), &payload),
                    packet(target, source, Some(0x10), &payload),
                )
            };
            fixtures.push(Fixture {
                parsed: parse(&input),
                capture: input.clone(),
                input,
                expected,
                result: Err(TunRejectReason::InvalidDestination),
            });
        }
    }

    let mut now = 0;
    let mut elapsed = 0;
    let mut checked = 0;
    let mut earliest_deadline = 0;
    for index in 0..=windows {
        prepare(&mut fixtures, index, ip_header);
        if index == 0 {
            window(&mut system, &mut fixtures, &mut now);
            validate(&fixtures);
        } else {
            let started = Instant::now();
            window(&mut system, &mut fixtures, &mut now);
            elapsed += started.elapsed().as_nanos();
            checked += validate(&fixtures);
        }
        // Last visits are in mapping order, two milliseconds apart. The final
        // direction differs by mapping parity, so exact per-mapping deadlines
        // below check both forward and reverse refresh, not just reverse.
        earliest_deadline = now + TIMEOUT_MILLIS - 2 * (ACTIVE as i64 - 1);
        now = earliest_deadline - 2;
        assert!(
            !system.expire(now),
            "all published mappings must remain live"
        );
        assert_eq!(count.load(Ordering::Acquire), ACTIVE);
        assert_eq!(system.next_deadline_millis(), Some(earliest_deadline));
    }
    assert_eq!(checked, windows * PACKETS);

    // Stop traffic and exercise the exact boundary, not a sampled timeout or
    // rewritten retired tuple (which can still be accepted during quarantine).
    assert!(!system.expire(earliest_deadline - 1));
    assert_eq!(count.load(Ordering::Acquire), ACTIVE);
    for index in 0..ACTIVE {
        let due = earliest_deadline + 2 * index as i64;
        assert_eq!(system.next_deadline_millis(), Some(due));
        assert!(system.expire(due));
        assert_eq!(count.load(Ordering::Acquire), ACTIVE - index - 1);
    }
    assert_eq!(flows.len(), ACTIVE);
    assert_eq!(peers.len(), ACTIVE);
    // Both ends survive every timed window and the exact expiration checks.
    drop(flows);
    drop(peers);

    let family = if ipv6 { "v6" } else { "v4" };
    let recipe_id = format!("tun-memory-established-v1-{family}-{mode}");
    let packet_len = ip_header + 20 + payload_len;
    let rewritten_bytes = checked * packet_len;
    let directions = checked / 2;
    let timed_ticks = checked;
    Ok(format!(
        "{{\"schema_version\":1,\"kind\":\"ferrum2.tun-detail.trial\",\"scenario\":\"{scenario}\",\"mode\":\"{mode}\",\"recipe_id\":\"{recipe_id}\",\"checked_units\":{checked},\"elapsed_nanoseconds\":{elapsed},\"unit\":\"packets\",\"observation\":{{\"active_mappings\":{ACTIVE},\"capacity\":{CAPACITY},\"published_flows\":{ACTIVE},\"mtu\":{MTU},\"ip_header_bytes\":{ip_header},\"tcp_header_bytes\":20,\"payload_bytes\":{payload_len},\"packet_bytes\":{packet_len},\"rewritten_bytes\":{rewritten_bytes},\"forward_packets\":{directions},\"reverse_packets\":{directions},\"deadline_refreshes\":{checked},\"timeout_millis\":{TIMEOUT_MILLIS},\"windows\":{windows},\"rounds_per_window\":{ROUNDS},\"packets_per_window\":{PACKETS},\"warmup_windows\":1,\"timed_logical_ticks\":{timed_ticks},\"window_gap_millis\":4032,\"expired_mappings\":{ACTIVE}}}}}"
    ))
}
