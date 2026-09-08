//! Portable, packet-only performance entry. No runtime, socket, adapter or network
//! operations are started. Logical time is explicit; only batch timing uses Instant.
//! Every trial first executes an untimed correctness/storage diagnostic, then
//! fixed repeated timed batches into preallocated packet/owned-datagram capture.
//! Each batch is checked afterward; setup and validation time are never subtracted.
//! `peak_packet_storage_bytes` is the diagnostic pass's observed retained packet
//! buffer capacities, reassembly headers/pieces, charged UDP payloads and fixtures
//! (including preallocated capture). It excludes metadata, allocator overhead,
//! transient buffers between samples, mock socket storage and process RSS.
mod owner;
mod recipe;

use crate::packet::TransportMetadata;
use crate::{UdpResponseDropReason, UdpResponseSendOutcome};
use owner::{Owner, parse, validate};
use recipe::{endpoints, fragments, packet};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Instant;

/// Runs one closed recipe and returns exactly one trial object. Invalid arguments
/// fail before any work. A failed correctness assertion never produces a trial.
pub fn trial(scenario: &str, mode: &str) -> Result<String, &'static str> {
    let confirm = match mode {
        "Quick" => false,
        "Confirm" => true,
        _ => return Err("mode must be Quick or Confirm"),
    };
    let hash = workload_hash(scenario, mode).ok_or("unknown scenario")?;
    let diagnostic = run(scenario, confirm, false);
    // Initial real A/A runs showed up to 36% noise in sub-millisecond batches.
    // Aggregate fixed repeated windows without timing setup or full validation.
    let batches = if confirm { 64 } else { 128 };
    let mut checked = 0;
    let mut elapsed = 0;
    let mut input = 0;
    let mut output = 0;
    let mut rejected = 0;
    for _ in 0..batches {
        let measured = run(scenario, confirm, true);
        assert_eq!(
            measured.packets, diagnostic.packets,
            "timed output must equal fully validated diagnostic output"
        );
        assert_eq!(measured.datagrams.len(), diagnostic.datagrams.len());
        for (actual, expected) in measured.datagrams.iter().zip(&diagnostic.datagrams) {
            assert_eq!(
                (actual.source(), actual.target(), actual.payload()),
                (expected.source(), expected.target(), expected.payload())
            );
        }
        checked += measured.stats.0;
        elapsed += measured.stats.2;
        input += measured.stats.3;
        output += measured.stats.4;
        rejected += measured.stats.5;
    }
    let unit = diagnostic.stats.1;
    let peak = diagnostic.stats.6;
    Ok(format!(
        "{{\"schema_version\":1,\"kind\":\"ferrum2.tun-mock.trial\",\"scenario\":\"{scenario}\",\"mode\":\"{mode}\",\"checked_units\":{checked},\"elapsed_nanoseconds\":{elapsed},\"unit\":\"{unit}\",\"workload_sha256\":\"{hash}\",\"observation\":{{\"input_units\":{input},\"output_units\":{output},\"rejected_units\":{rejected},\"peak_packet_storage_bytes\":{peak}}}}}"
    ))
}

struct Run {
    stats: (usize, &'static str, u128, usize, usize, usize, usize),
    packets: Vec<Vec<u8>>,
    datagrams: Vec<crate::UdpDatagram>,
}

fn run(scenario: &str, confirm: bool, measuring: bool) -> Run {
    let mut packets = Vec::new();
    let mut datagrams = Vec::new();
    let scale = if confirm { 4 } else { 1 };
    let states = if confirm { 128 } else { 32 };
    let payload = vec![0x5a; if confirm { 512 } else { 64 }];
    let (checked, unit, elapsed, input, output, rejected, peak) = match scenario {
        "tcp-rewrite" => {
            let mut owner = Owner::new(states);
            let mut recipes = Vec::new();
            for index in 0..states {
                let (source, target) = endpoints(confirm && index % 2 != 0, index);
                owner.enqueue(&packet(source, target, Some(2), &[]));
                let mut rewritten = None;
                owner.drain(&mut |bytes| {
                    let parsed = parse(bytes);
                    let TransportMetadata::Tcp(tcp) = parsed.transport else {
                        panic!("TCP output");
                    };
                    rewritten = Some((
                        SocketAddr::new(parsed.source, tcp.source_port),
                        SocketAddr::new(parsed.destination, tcp.destination_port),
                    ));
                });
                let (peer, listener) = rewritten.expect("SYN translated");
                recipes.push((packet(source, target, Some(0x10), &payload), peer, listener));
                recipes.push((packet(listener, peer, Some(0x10), &payload), target, source));
            }
            let fixtures =
                payload.capacity() + recipes.iter().map(|r| r.0.capacity()).sum::<usize>();
            owner.clear_observations();
            let checked = 2048 * scale;
            owner.begin_capture(checked, 0, measuring);
            let started = Instant::now();
            for index in 0..checked {
                let (bytes, source, target) = &recipes[index % recipes.len()];
                owner.enqueue(bytes);
                owner.drain(&mut |bytes| validate(bytes, *source, *target, &payload));
            }
            let elapsed = started.elapsed().as_nanos();
            packets = owner.capture;
            (
                checked,
                "packets",
                elapsed,
                owner.input,
                owner.output,
                owner.rejected,
                owner.peak + fixtures,
            )
        }
        "tcp-churn" => {
            let mut owner = Owner::new(states);
            let recipes = (0..states)
                .map(|index| {
                    let (source, target) = endpoints(confirm && index % 2 != 0, index);
                    (
                        packet(source, target, Some(2), &[]),
                        packet(source, target, Some(4), &[]),
                    )
                })
                .collect::<Vec<_>>();
            let fixtures = recipes
                .iter()
                .map(|r| r.0.capacity() + r.1.capacity())
                .sum::<usize>();
            let checked = 512 * scale;
            let mut sockets = (0..checked)
                .map(|_| {
                    let (socket, peer) = tokio::io::duplex(1024);
                    (Some(socket), peer)
                })
                .collect::<Vec<_>>();
            let mut published = Vec::with_capacity(checked);
            owner.begin_capture(checked * 2, 0, measuring);
            let started = Instant::now();
            for index in 0..checked {
                if index % states == 0 {
                    owner.now += 240_001;
                    owner.stack.expire_deadlines(owner.now);
                }
                let (syn, reset) = &recipes[index % states];
                owner.enqueue(syn);
                owner.drain(&mut |bytes| { assert!(matches!(parse(bytes).transport, TransportMetadata::Tcp(tcp) if tcp.flags == 2)); });
                let (source, target) =
                    endpoints(confirm && index % states % 2 != 0, index % states);
                owner.stack.accept_packet_socket(
                    source,
                    target,
                    sockets[index].0.take().expect("one accept"),
                );
                owner.stack.expire_deadlines(owner.now);
                published.push(
                    owner
                        .flows
                        .try_recv()
                        .expect("generation-checked flow publication"),
                );
                owner.enqueue(reset);
                owner.drain(&mut |bytes| { assert!(matches!(parse(bytes).transport, TransportMetadata::Tcp(tcp) if tcp.flags == 4)); });
                owner.now += 1;
                assert!(
                    owner.stack.expire_deadlines(owner.now),
                    "RST mapping retires on logical deadline"
                );
            }
            let elapsed = started.elapsed().as_nanos();
            for (index, flow) in published.iter_mut().enumerate() {
                assert_eq!(
                    flow.target(),
                    endpoints(confirm && index % states % 2 != 0, index % states).1
                );
                let mut context = std::task::Context::from_waker(std::task::Waker::noop());
                assert!(
                    matches!(tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(flow), &mut context, b"late"), std::task::Poll::Ready(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionReset)
                );
            }
            packets = owner.capture;
            (
                checked,
                "flows",
                elapsed,
                owner.input,
                owner.output,
                owner.rejected,
                owner.peak + fixtures,
            )
        }
        "udp-roundtrip" | "fragment-reassembly" | "mixed-backpressure" => {
            let mut owner = Owner::new(states);
            let fragmented = scenario == "fragment-reassembly";
            let mixed = scenario == "mixed-backpressure";
            let mut recipes = Vec::new();
            let mut associations = Vec::new();
            for index in 0..states {
                let (source, target) = endpoints(confirm && !fragmented && index % 2 != 0, index);
                let bytes = packet(source, target, None, &payload);
                owner.enqueue(&bytes);
                let mut association = owner.commit();
                owner.receive(&mut association, target, &payload);
                associations.push(association);
                let pieces = if fragmented {
                    fragments(&bytes).to_vec()
                } else {
                    vec![bytes]
                };
                recipes.push((pieces, source, target));
            }
            let (tcp_source, tcp_target) = endpoints(false, states + 1);
            let mut tcp_rewrite = None;
            let tcp = if mixed {
                owner.enqueue(&packet(tcp_source, tcp_target, Some(2), &[]));
                owner.drain(&mut |bytes| {
                    let parsed = parse(bytes);
                    let TransportMetadata::Tcp(tcp) = parsed.transport else {
                        panic!("TCP output");
                    };
                    tcp_rewrite = Some((
                        SocketAddr::new(parsed.source, tcp.source_port),
                        SocketAddr::new(parsed.destination, tcp.destination_port),
                    ));
                });
                packet(tcp_source, tcp_target, Some(0x10), &payload)
            } else {
                Vec::new()
            };
            let fixtures = payload.capacity()
                + tcp.capacity()
                + recipes
                    .iter()
                    .flat_map(|r| &r.0)
                    .map(Vec::capacity)
                    .sum::<usize>();
            owner.clear_observations();
            let checked = if fragmented {
                1024 * scale
            } else {
                2048 * scale
            };
            owner.begin_capture(checked, checked, measuring);
            let started = Instant::now();
            if mixed {
                for batch in 0..checked / 16 {
                    let mut expected_udp = 0;
                    let mut expected_tcp = 0;
                    for offset in 0..8 {
                        let index = (batch * 8 + offset) % states;
                        let (pieces, _, target) = &recipes[index];
                        owner.enqueue(&tcp);
                        owner.enqueue(&pieces[0]);
                        owner.receive(&mut associations[index], *target, &payload);
                        assert_eq!(
                            associations[index].send_response(*target, &payload),
                            UdpResponseSendOutcome::Queued
                        );
                    }
                    owner.turn(false, &mut |_| panic!("sink turn withheld"));
                    assert!(owner.stack.has_output());
                    assert!(
                        owner.deferred.load(Ordering::Relaxed) > 0,
                        "real response backpressure required"
                    );
                    owner.drain(&mut |bytes| {
                        let parsed = parse(bytes);
                        match parsed.transport {
                            TransportMetadata::Tcp(_) => {
                                let (source, target) = tcp_rewrite.expect("TCP mapping");
                                validate(bytes, source, target, &payload);
                                expected_tcp += 1;
                            }
                            TransportMetadata::Udp(udp) => {
                                let index = usize::from(udp.destination_port - 10000);
                                let (_, source, target) = &recipes[index];
                                validate(bytes, *target, *source, &payload);
                                expected_udp += 1;
                            }
                        }
                    });
                    if !measuring {
                        assert_eq!((expected_tcp, expected_udp), (8, 8));
                    }
                }
            } else if fragmented {
                for group in 0..checked / states {
                    let first = if confirm && group % 2 == 0 { 0 } else { 1 };
                    for (pieces, _, _) in &recipes {
                        owner.enqueue(&pieces[first]);
                    }
                    if !measuring {
                        assert_eq!(owner.stack.reassembly.len(), states);
                    }
                    for (slot, (pieces, source, target)) in recipes.iter().enumerate().rev() {
                        owner.enqueue(&pieces[1 - first]);
                        owner.receive(&mut associations[slot], *target, &payload);
                        assert_eq!(
                            associations[slot].send_response(*target, &payload),
                            UdpResponseSendOutcome::Queued
                        );
                        owner.sample();
                        owner.drain(&mut |bytes| validate(bytes, *target, *source, &payload));
                    }
                    if !measuring {
                        assert_eq!(owner.stack.reassembly.len(), 0);
                    }
                }
            } else {
                for index in 0..checked {
                    let slot = index % states;
                    let (pieces, source, target) = &recipes[slot];
                    owner.enqueue(&pieces[0]);
                    owner.receive(&mut associations[slot], *target, &payload);
                    assert_eq!(
                        associations[slot].send_response(*target, &payload),
                        UdpResponseSendOutcome::Queued
                    );
                    owner.sample();
                    owner.drain(&mut |bytes| validate(bytes, *target, *source, &payload));
                }
            }
            let elapsed = started.elapsed().as_nanos();
            if !measuring {
                let min = *owner.stage_visits.iter().min().expect("stages");
                let max = *owner.stage_visits.iter().max().expect("stages");
                assert!(
                    min > 0 && max - min <= 1,
                    "all owner stages receive bounded fair turns"
                );
            }
            packets = owner.capture;
            datagrams = owner.received;
            (
                checked,
                if mixed { "packets" } else { "datagrams" },
                elapsed,
                owner.input,
                owner.output,
                owner.rejected,
                owner.peak + fixtures,
            )
        }
        "state-reset" => {
            let checked = 32 * scale;
            let recipes = (0..states)
                .map(|index| {
                    let (source, target) = endpoints(false, index);
                    let udp = packet(source, target, None, &payload);
                    let pieces = fragments(&udp);
                    (
                        source,
                        target,
                        udp,
                        packet(source, target, Some(2), &[]),
                        pieces,
                    )
                })
                .collect::<Vec<_>>();
            let mut owners = Vec::with_capacity(checked);
            let mut leases = Vec::with_capacity(checked);
            let mut tcp_leases = Vec::with_capacity(checked * states);
            let mut peers = Vec::with_capacity(checked * states);
            for _ in 0..checked {
                let mut owner = Owner::new(states);
                let mut associations = Vec::with_capacity(states);
                for (source, target, udp, tcp, pieces) in &recipes {
                    owner.enqueue(udp);
                    let mut association = owner.commit();
                    owner.receive(&mut association, *target, &payload);
                    associations.push(association);
                    owner.enqueue(tcp);
                    owner.drain(&mut |bytes| {
                        parse(bytes);
                    });
                    let (socket, peer) = tokio::io::duplex(1024);
                    owner.stack.accept_packet_socket(*source, *target, socket);
                    owner.stack.expire_deadlines(owner.now);
                    tcp_leases.push(owner.flows.try_recv().expect("published active flow"));
                    peers.push(peer);
                    owner.enqueue(&pieces[0]);
                }
                for (association, (_, target, _, _, _)) in associations.iter().zip(&recipes) {
                    assert_eq!(
                        association.send_response(*target, &payload),
                        UdpResponseSendOutcome::Queued
                    );
                }
                assert_eq!(owner.stack.live_udp_associations(), states);
                assert_eq!(owner.stack.reassembly.len(), states);
                owner.sample();
                owner.measuring = measuring;
                leases.push(associations);
                owners.push(owner);
            }
            let fixtures = payload.capacity()
                + recipes
                    .iter()
                    .map(|r| {
                        r.2.capacity()
                            + r.3.capacity()
                            + r.4.iter().map(Vec::capacity).sum::<usize>()
                    })
                    .sum::<usize>();
            let peak = owners.iter().map(|o| o.peak).sum::<usize>() + fixtures;
            let mut retired = Vec::with_capacity(checked);
            let mut stale = Vec::with_capacity(checked);
            let started = Instant::now();
            for (owner, associations) in owners.iter_mut().zip(&leases) {
                owner
                    .stack
                    .fence_generation(1)
                    .expect("new generation fence");
                retired.push(
                    owner
                        .stack
                        .retire_generation(1, UdpResponseDropReason::StaleGeneration)
                        .expect("retirement"),
                );
                stale.push(associations[0].send_response(recipes[0].1, &payload));
            }
            let elapsed = started.elapsed().as_nanos();
            assert!(retired.iter().all(|count| *count == states));
            assert!(
                stale
                    .iter()
                    .all(|outcome| *outcome == UdpResponseSendOutcome::StaleGeneration)
            );
            for owner in &owners {
                assert_eq!(owner.stack.reassembly.len(), 0);
                assert_eq!(owner.stack.live_udp_associations(), 0);
                assert_eq!(owner.stack.ingress_available(), crate::INGRESS_SLOTS);
                assert!(!owner.stack.has_output());
            }
            for flow in &mut tcp_leases {
                let mut context = std::task::Context::from_waker(std::task::Waker::noop());
                assert!(
                    matches!(tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(flow), &mut context, b"late"), std::task::Poll::Ready(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionReset)
                );
            }
            (checked, "resets", elapsed, checked, 0, checked, peak)
        }
        _ => unreachable!("closed recipe names"),
    };
    assert!(elapsed > 0);
    let (expected_input, expected_output, expected_rejected) = match scenario {
        "tcp-churn" => (checked * 2, checked * 2, 0),
        "fragment-reassembly" => (checked * 2, checked, 0),
        "state-reset" => (checked, 0, checked),
        _ => (checked, checked, 0),
    };
    assert_eq!(
        (input, output, rejected),
        (expected_input, expected_output, expected_rejected)
    );
    Run {
        stats: (checked, unit, elapsed, input, output, rejected, peak),
        packets,
        datagrams,
    }
}

fn workload_hash(scenario: &str, mode: &str) -> Option<&'static str> {
    // SHA256 of UTF-8 `ferrum2.tun-mock.v2\n{scenario}\n{mode}\n{batches}\n`.
    Some(match (scenario, mode) {
        ("tcp-rewrite", "Quick") => {
            "b8285240f37c7c8c1e8435b80d5949bc73136e0b38284675ef47d9c1890ef884"
        }
        ("tcp-rewrite", "Confirm") => {
            "61def97589682b4503e1ffd54d666b3ec46e81c704c9d39cbfc7e59bc34ab87f"
        }
        ("tcp-churn", "Quick") => {
            "65d64e12f09bc02e8452606c8beb76d7b0fe09defde60c239721cc5c23f84972"
        }
        ("tcp-churn", "Confirm") => {
            "63a4bc9c62e8a4db424f68331c4cd387f0b311bfb76b2df9322ee1dfc9dd7ec2"
        }
        ("udp-roundtrip", "Quick") => {
            "a67b7d30ec12fd895ca6cee5156e8ab0ca52f3f04b226bbf043c84bf58211d10"
        }
        ("udp-roundtrip", "Confirm") => {
            "173aabfabe2421c1935c7373af1cc31700473b3e316ad3950af55d9e27e0d6f2"
        }
        ("fragment-reassembly", "Quick") => {
            "92b73e70e9d4133697b3e588aea372c6688ace3510913426d2a1e8740007c11a"
        }
        ("fragment-reassembly", "Confirm") => {
            "7186a69cd78e0121196b40c18dfc35fd6b8a46f051a9180c1de0b36a0d9ce268"
        }
        ("mixed-backpressure", "Quick") => {
            "3354062bd81d56907e3cfa7a0da2625258c5fed1fe0b7f64a8f656470724b81f"
        }
        ("mixed-backpressure", "Confirm") => {
            "cafd6912811af7fda96914af007e0ba80be77b8ac0ae7da76af56fc5bffa4821"
        }
        ("state-reset", "Quick") => {
            "aa4cfb15baab289c894c6b67e5a2f654967115233ae123f494b238fa9a95ff94"
        }
        ("state-reset", "Confirm") => {
            "a39be736c4909d9de999250544e1511166ca40755e4a240bbb4a214dc84609b3"
        }
        _ => return None,
    })
}
