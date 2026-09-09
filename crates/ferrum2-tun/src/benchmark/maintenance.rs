//! Sparse TCP maintenance, independently named from the v2 aggregate workloads.
//! Recipe v1: both modes use eight live, immediately published IPv4 mappings,
//! logical setup time 0 and maintenance time 1 ms (well before the 30 s timeout).
//! Quick configures 128 slots; Confirm configures 4096. Each of 4096 independent
//! windows performs exactly one Stack::expire_deadlines call. Sixteen prepared
//! windows share a clock interval, repeated 256 times, to reduce timer noise.
//! Changed drops exactly one published flow in each window before starting the
//! clock; Idle retains all eight. One full batch is warmed and checked untimed.
//! Setup, flow drops, packet/socket checks and teardown are outside the clock.
//! The denominator is expire calls, NOT slots visited: the changed path includes
//! notification consumption, retirement/fencing/quarantine and deadline upkeep;
//! both paths include the Stack's empty UDP/reassembly maintenance. No scan or
//! allocation counts are inferred. Capacity comparisons retain identical work.

use super::owner::{Owner, parse, validate};
use super::recipe::{endpoints, packet};
use crate::TcpFlow;
use crate::packet::{TransportMetadata, internet_checksum};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

const ACTIVE: usize = 8;
const BATCH_WIDTH: usize = 16;
const BATCHES: usize = 256;

struct Mapping {
    syn: Vec<u8>,
    translated_source: SocketAddr,
    translated_target: SocketAddr,
    flow: Option<TcpFlow>,
    peer: DuplexStream,
}

struct Window {
    owner: Owner,
    mappings: Vec<Mapping>,
    worked: bool,
}

impl Window {
    fn new(capacity: usize, changed: bool) -> Self {
        let mut owner = Owner::new(capacity);
        let mut mappings = Vec::with_capacity(ACTIVE);
        for index in 0..ACTIVE {
            let (source, target) = endpoints(false, index);
            let syn = packet(source, target, Some(2), &[]);
            let mut translated = None;
            owner.enqueue(&syn);
            owner.drain(&mut |bytes| {
                let parsed = parse(bytes);
                let TransportMetadata::Tcp(tcp) = parsed.transport else {
                    panic!("SYN must remain TCP");
                };
                assert_eq!(tcp.flags, 2);
                assert!(translated.is_none(), "one rewritten SYN per mapping");
                translated = Some((
                    SocketAddr::new(parsed.source, tcp.source_port),
                    SocketAddr::new(parsed.destination, tcp.destination_port),
                ));
            });
            let (translated_source, translated_target) =
                translated.expect("mapping must produce a rewritten SYN");
            let (socket, peer) = tokio::io::duplex(8);
            owner.stack.accept_packet_socket(source, target, socket);
            // Accept/publication must progress on this first control opportunity,
            // not an accidental deadline advance or a timeout-driven scan.
            assert!(owner.stack.expire_deadlines(owner.now));
            let flow = owner.flows.try_recv().expect("immediate flow publication");
            assert_eq!(flow.target(), target);
            assert!(owner.flows.try_recv().is_err(), "exactly one publication");
            mappings.push(Mapping {
                syn,
                translated_source,
                translated_target,
                flow: Some(flow),
                peer,
            });
        }
        assert_eq!(owner.input, ACTIVE);
        assert_eq!(owner.output, ACTIVE);
        assert_eq!(owner.rejected, 0);
        assert!(!owner.stack.expire_deadlines(owner.now));
        owner.now = 1;
        if changed {
            // No owner operation may consume this notification before timing.
            drop(mappings[0].flow.take().expect("published dropped flow"));
        }
        Self {
            owner,
            mappings,
            worked: false,
        }
    }

    fn validate(&mut self, changed: bool) {
        assert_eq!(self.worked, changed, "only a dropped flow needs retirement");
        assert!(!self.owner.stack.expire_deadlines(self.owner.now));
        assert!(self.owner.flows.try_recv().is_err());
        let mut context = Context::from_waker(Waker::noop());
        for (index, mapping) in self.mappings.iter_mut().enumerate() {
            let surviving = !changed || index != 0;
            // A retired tuple rejects its original SYN during quarantine; a live
            // tuple still rewrites it. A missing, non-retired mapping would admit
            // a new SYN, so the negative probe also checks retirement identity.
            assert_eq!(
                self.owner
                    .stack
                    .enqueue_at(&mapping.syn, true, self.owner.now),
                surviving,
                "exact mapping identity after maintenance"
            );
            let mut outputs = 0;
            self.owner.drain(&mut |bytes| {
                outputs += 1;
                if surviving {
                    validate(bytes, mapping.translated_source, mapping.translated_target, &[]);
                    assert!(matches!(parse(bytes).transport, TransportMetadata::Tcp(tcp) if tcp.flags == 2));
                } else {
                    assert!(bytes.len() >= 28);
                    assert_eq!(bytes[0], 0x45);
                    assert_eq!(bytes[9], 1);
                    assert_eq!(&bytes[20..22], &[3, 13]);
                    assert_eq!(internet_checksum(&[&bytes[..20]]), 0);
                    assert_eq!(internet_checksum(&[&bytes[20..]]), 0);
                }
            });
            assert_eq!(outputs, 1, "rewritten SYN or administrative rejection");
            if let Some(flow) = &mut mapping.flow {
                // Surviving publication must remain usable, not merely resident.
                let payload = [index as u8 + 1];
                assert!(matches!(
                    Pin::new(flow).poll_write(&mut context, &payload),
                    Poll::Ready(Ok(1))
                ));
                let mut bytes = [0];
                let mut buffer = ReadBuf::new(&mut bytes);
                assert!(matches!(
                    Pin::new(&mut mapping.peer).poll_read(&mut context, &mut buffer),
                    Poll::Ready(Ok(()))
                ));
                assert_eq!(buffer.filled(), payload);
            } else {
                // The pre-timed drop closes the stream; verify its observable EOF.
                let mut bytes = [0];
                let mut buffer = ReadBuf::new(&mut bytes);
                assert!(matches!(
                    Pin::new(&mut mapping.peer).poll_read(&mut context, &mut buffer),
                    Poll::Ready(Ok(()))
                ));
                assert!(buffer.filled().is_empty(), "retired socket must reach EOF");
            }
        }
        assert!(
            self.owner.flows.try_recv().is_err(),
            "no probe republishes a flow"
        );
    }
}

fn expire(windows: &mut [Window]) {
    for window in windows {
        window.worked = std::hint::black_box(window.owner.stack.expire_deadlines(window.owner.now));
    }
}

pub(super) fn trial(scenario: &str, mode: &str) -> Result<String, &'static str> {
    let changed = match scenario {
        "tcp-maintenance-idle" => false,
        "tcp-maintenance-changed" => true,
        _ => return Err("unknown maintenance detail scenario"),
    };
    let capacity = match mode {
        "Quick" => 128,
        "Confirm" => 4096,
        _ => return Err("mode must be Quick or Confirm"),
    };
    let mut elapsed = 0;
    for batch in 0..=BATCHES {
        let mut windows = (0..BATCH_WIDTH)
            .map(|_| Window::new(capacity, changed))
            .collect::<Vec<_>>();
        if batch == 0 {
            expire(&mut windows);
        } else {
            let started = Instant::now();
            expire(&mut windows);
            elapsed += started.elapsed().as_nanos();
        }
        for window in &mut windows {
            window.validate(changed);
        }
    }
    let checked = BATCHES * BATCH_WIDTH;
    let published = checked * ACTIVE;
    let dropped = if changed { checked } else { 0 };
    let survived = published - dropped;
    let state = if changed { "changed" } else { "idle" };
    let recipe_id = format!("tun-tcp-maintenance-v1-{state}-{mode}");
    Ok(format!(
        "{{\"schema_version\":1,\"kind\":\"ferrum2.tun-detail.trial\",\"scenario\":\"{scenario}\",\"mode\":\"{mode}\",\"recipe_id\":\"{recipe_id}\",\"checked_units\":{checked},\"elapsed_nanoseconds\":{elapsed},\"unit\":\"expire_calls\",\"observation\":{{\"configured_tcp_capacity\":{capacity},\"active_mappings_per_window\":{ACTIVE},\"windows\":{checked},\"expire_calls_per_window\":1,\"timed_batches\":{BATCHES},\"windows_per_batch\":{BATCH_WIDTH},\"untimed_warmup_windows\":{BATCH_WIDTH},\"published_flows\":{published},\"predropped_flows\":{dropped},\"retired_flows\":{dropped},\"surviving_flows\":{survived},\"worked_expire_calls\":{dropped},\"setup_logical_millis\":0,\"expire_logical_millis\":1,\"scan_slots_observed\":null,\"cost_scope\":\"one Stack::expire_deadlines call; empty UDP and reassembly; changed includes retirement, fencing, quarantine and deadline upkeep\"}}}}"
    ))
}
