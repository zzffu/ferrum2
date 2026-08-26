use super::contract::{
    ProbeArgs, Scenario, parse_probe, parse_udp_diagnostic_finalize, parse_workload,
};
use super::diagnostic::{
    FRAGMENT_ACTIVE, FRAGMENT_MINIMUM_DATAGRAMS, FRAGMENT_PAYLOAD, FRAGMENT_REPLY_BUFFER,
    FRAGMENT_WARMUP, FragmentPhase, FragmentWorkloadAccounting, IO_TIMEOUT, RING_BURST_ATTEMPTS,
    ROUTE_DATAGRAMS_PER_TARGET, ROUTE_PAYLOAD, ROUTE_SOURCE_SLOTS, ROUTE_TARGET_SLOTS,
    UDP_DIAGNOSTIC_PAYLOAD_LEN, UDP_PAYLOAD, UdpDiagnosticFinalizeArgs,
    udp_diagnostic_finalize_marker,
};
use super::workload::{
    checked_payload, configure_tcp, connected_udp, elapsed_rate, fragment_batch_round_trip,
    fragment_retry_budget, fragment_workload_batch_round_trip, sequenced_payload, tcp_fairness,
    tcp_round_trip, tcp_single, udp_packets, udp_round_trip, unconnected_udp,
};
use super::workload_diagnostic::udp_associations;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::time::Instant;

pub(crate) fn route_target_addresses(
    target_ip: IpAddr,
    base_port: u16,
) -> Result<Vec<SocketAddr>, String> {
    let last_port = base_port
        .checked_add((ROUTE_TARGET_SLOTS - 1) as u16)
        .ok_or_else(|| "UDP route-once target port range overflows".to_owned())?;
    if last_port == 0 {
        return Err("UDP route-once target port range is invalid".to_owned());
    }
    Ok((0..ROUTE_TARGET_SLOTS)
        .map(|slot| SocketAddr::new(target_ip, base_port + slot as u16))
        .collect())
}

pub(crate) const fn route_target_order(source_slot: usize) -> [usize; ROUTE_TARGET_SLOTS] {
    if source_slot.is_multiple_of(2) {
        [0, 1, 2, 3]
    } else {
        [1, 0, 2, 3]
    }
}

pub(crate) fn send_route_targets(
    socket: &UdpSocket,
    source_slot: usize,
    round: usize,
    targets: &[SocketAddr],
    target_slots: &[usize],
) -> Result<(), String> {
    for &target_slot in target_slots {
        let sequence = ((source_slot as u64) << 32) | ((round as u64) << 16) | target_slot as u64;
        let payload = sequenced_payload(ROUTE_PAYLOAD, sequence)?;
        let sent = socket
            .send_to(&payload, targets[target_slot])
            .map_err(|error| format!("multi-target UDP send failed: {error}"))?;
        if sent != payload.len() {
            return Err("multi-target UDP sent a partial datagram".to_owned());
        }
    }
    Ok(())
}

pub(crate) fn receive_route_targets(
    socket: &UdpSocket,
    source_slot: usize,
    round: usize,
    targets: &[SocketAddr],
    expected_target_slots: &[usize],
) -> Result<(), String> {
    let mut seen = HashSet::with_capacity(expected_target_slots.len());
    let mut reply = [0_u8; ROUTE_PAYLOAD];
    for _ in expected_target_slots {
        let (received, response_source) = socket
            .recv_from(&mut reply)
            .map_err(|error| format!("multi-target UDP receive failed: {error}"))?;
        if received != ROUTE_PAYLOAD {
            return Err("multi-target UDP payload length mismatch".to_owned());
        }
        let target_slot = targets
            .iter()
            .position(|target| *target == response_source)
            .ok_or_else(|| {
                "multi-target UDP response source is outside the target set".to_owned()
            })?;
        if !expected_target_slots.contains(&target_slot) || !seen.insert(target_slot) {
            return Err(
                "multi-target UDP received an unexpected or duplicate target response".to_owned(),
            );
        }
        let sequence = ((source_slot as u64) << 32) | ((round as u64) << 16) | target_slot as u64;
        if reply != sequenced_payload(ROUTE_PAYLOAD, sequence)?[..] {
            return Err("multi-target UDP payload mismatch".to_owned());
        }
    }
    Ok(())
}

pub(crate) fn udp_route_once(target_ip: IpAddr, base_port: u16) -> Result<Value, String> {
    let targets = route_target_addresses(target_ip, base_port)?;
    let sockets = (0..ROUTE_SOURCE_SLOTS)
        .map(|_| unconnected_udp(target_ip))
        .collect::<Result<Vec<_>, _>>()?;
    let start = Instant::now();
    for (source_slot, socket) in sockets.iter().enumerate() {
        send_route_targets(
            socket,
            source_slot,
            0,
            &targets,
            &route_target_order(source_slot)[..1],
        )?;
    }
    for (source_slot, socket) in sockets.iter().enumerate() {
        receive_route_targets(
            socket,
            source_slot,
            0,
            &targets,
            &route_target_order(source_slot)[..1],
        )?;
    }
    let association_creation_elapsed = start.elapsed();
    for (source_slot, socket) in sockets.iter().enumerate() {
        send_route_targets(
            socket,
            source_slot,
            0,
            &targets,
            &route_target_order(source_slot)[1..],
        )?;
    }
    for (source_slot, socket) in sockets.iter().enumerate() {
        receive_route_targets(
            socket,
            source_slot,
            0,
            &targets,
            &route_target_order(source_slot)[1..],
        )?;
    }
    for round in 1..ROUTE_DATAGRAMS_PER_TARGET {
        for (source_slot, socket) in sockets.iter().enumerate() {
            send_route_targets(
                socket,
                source_slot,
                round,
                &targets,
                &route_target_order(source_slot),
            )?;
        }
        for (source_slot, socket) in sockets.iter().enumerate() {
            receive_route_targets(
                socket,
                source_slot,
                round,
                &targets,
                &route_target_order(source_slot),
            )?;
        }
    }
    let elapsed = start.elapsed();
    let datagrams = (ROUTE_SOURCE_SLOTS * ROUTE_TARGET_SLOTS * ROUTE_DATAGRAMS_PER_TARGET) as u64;
    let associations = (0..ROUTE_SOURCE_SLOTS)
        .map(|source_slot| {
            json!({
                "source_slot": source_slot,
                "target_slots": (0..ROUTE_TARGET_SLOTS).collect::<Vec<_>>(),
                "first_target_slot": if source_slot % 2 == 0 { 0 } else { 1 },
                "datagrams_sent": ROUTE_TARGET_SLOTS * ROUTE_DATAGRAMS_PER_TARGET,
                "replies_received": ROUTE_TARGET_SLOTS * ROUTE_DATAGRAMS_PER_TARGET,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "measurements": {
            "elapsed_nanoseconds": u64::try_from(elapsed.as_nanos())
                .map_err(|_| "multi-target UDP elapsed time overflow".to_owned())?,
            "association_creation_elapsed_nanoseconds": u64::try_from(
                association_creation_elapsed.as_nanos()
            ).map_err(|_| "multi-target UDP association time overflow".to_owned())?,
            "packet_rate": elapsed_rate(datagrams, elapsed, "multi-target UDP packet rate")?,
        },
        "checked_units": datagrams,
        "associations": associations,
        "checks": {
            "every_reply_accounted": true,
            "payload_exact": true,
            "multi_target_sources": true,
            "no_gso": true,
        }
    }))
}

pub(crate) fn fragments(address: SocketAddr) -> Result<Value, String> {
    let socket = connected_udp(address)?;
    let mut reply = [0_u8; FRAGMENT_REPLY_BUFFER];
    let mut sequence = 0_u64;
    let mut accounting = FragmentWorkloadAccounting::default();
    let warmup_deadline = Instant::now() + FRAGMENT_WARMUP;
    while Instant::now() < warmup_deadline {
        sequence = fragment_workload_batch_round_trip(
            &socket,
            FragmentPhase::Warmup,
            sequence,
            &mut reply,
            &mut accounting,
        )?;
    }
    let start = Instant::now();
    let deadline = start + FRAGMENT_ACTIVE;
    while Instant::now() < deadline
        || accounting.active_unique_datagrams < FRAGMENT_MINIMUM_DATAGRAMS
    {
        sequence = fragment_workload_batch_round_trip(
            &socket,
            FragmentPhase::Active,
            sequence,
            &mut reply,
            &mut accounting,
        )?;
    }
    let elapsed = start.elapsed();
    let bytes = accounting
        .active_unique_datagrams
        .checked_mul(FRAGMENT_PAYLOAD as u64)
        .ok_or_else(|| "fragment byte count overflow".to_owned())?;
    let total_unique_datagrams = accounting.total_unique_datagrams()?;
    let total_request_attempts = accounting.total_request_attempts()?;
    let retry_budget = fragment_retry_budget(total_unique_datagrams);
    let expected_request_attempts = total_unique_datagrams
        .checked_add(accounting.retransmissions)
        .ok_or_else(|| "fragment request accounting overflow".to_owned())?;
    if sequence != total_unique_datagrams
        || total_request_attempts != expected_request_attempts
        || accounting.retransmissions > retry_budget
        || accounting.ack_window_expirations != accounting.retransmissions
        || accounting.duplicate_or_stale_acks > accounting.retransmissions
    {
        return Err("fragment workload accounting invariants failed".to_owned());
    }
    Ok(json!({
        "measurements": {
            "reassembly_rate": elapsed_rate(bytes, elapsed, "fragment reassembly")?
        },
        "checked_units": accounting.active_unique_datagrams,
        "accounting": {
            "warmup_unique_datagrams": accounting.warmup_unique_datagrams,
            "warmup_request_attempts": accounting.warmup_request_attempts,
            "active_unique_datagrams": accounting.active_unique_datagrams,
            "active_request_attempts": accounting.active_request_attempts,
            "total_unique_datagrams": total_unique_datagrams,
            "total_request_attempts": total_request_attempts,
            "retransmissions": accounting.retransmissions,
            "ack_window_expirations": accounting.ack_window_expirations,
            "duplicate_or_stale_acks": accounting.duplicate_or_stale_acks,
            "retry_budget": retry_budget,
        },
        "checks": {
            "payload_exact": true,
            "no_gso": true,
            "all_sequences_acknowledged": true,
            "bounded_retransmissions": true,
        }
    }))
}

pub(crate) fn ring_full(address: SocketAddr) -> Result<Value, String> {
    let socket = connected_udp(address)?;
    let payload = checked_payload(UDP_PAYLOAD, 4);
    let start = Instant::now();
    let mut attempts = 0_u64;
    while attempts < RING_BURST_ATTEMPTS {
        let sent = socket
            .send(&payload)
            .map_err(|error| format!("ring-full burst send failed: {error}"))?;
        if sent != payload.len() {
            return Err("ring-full burst sent a partial datagram".to_owned());
        }
        attempts += 1;
    }
    Ok(json!({
        "measurements": {
            "attempted_datagrams": attempts,
            "send_rate": elapsed_rate(attempts, start.elapsed(), "ring burst")?
        },
        "checked_units": attempts,
        "checks": {"no_gso": true}
    }))
}

pub(crate) fn write_observation(
    path: &Path,
    scenario: Scenario,
    observation: Value,
) -> Result<(), String> {
    let document = json!({
        "schema_version": 1,
        "kind": "windows_tun_guest_workload",
        "scenario": scenario.label(),
        "observation": observation,
        "status": "PASS"
    });
    let encoded = serde_json::to_vec_pretty(&document)
        .map_err(|error| format!("serialize Windows TUN workload failed: {error}"))?;
    if encoded.len() > 64 * 1024 {
        return Err("Windows TUN workload observation exceeds 64 KiB".to_owned());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create Windows TUN workload output failed: {error}"))?;
    let result = output
        .write_all(&encoded)
        .and_then(|()| output.write_all(b"\n"))
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("write Windows TUN workload output failed: {error}"));
    if result.is_err() {
        drop(output);
        let _ = fs::remove_file(path);
    }
    result
}

pub(crate) fn run_workload(arguments: &[OsString]) -> Result<String, String> {
    let arguments = parse_workload(arguments)?;
    let address = SocketAddr::new(
        arguments.target_ip,
        match arguments.scenario {
            Scenario::TcpSingle | Scenario::TcpFairness => arguments.tcp_port,
            _ => arguments.udp_port,
        },
    );
    let observation = match arguments.scenario {
        Scenario::TcpSingle => tcp_single(address)?,
        Scenario::TcpFairness => tcp_fairness(address)?,
        Scenario::UdpPackets => udp_packets(address)?,
        Scenario::UdpAssociations => udp_associations(
            address,
            arguments.association_source.as_ref().ok_or_else(|| {
                "UDP association fixed source arguments were not retained".to_owned()
            })?,
            arguments.diagnostic.as_ref(),
        )?,
        Scenario::UdpRouteOnce => udp_route_once(arguments.target_ip, arguments.udp_port)?,
        Scenario::Fragments => fragments(address)?,
        Scenario::RingFull => ring_full(address)?,
    };
    write_observation(&arguments.output, arguments.scenario, observation)?;
    Ok(format!(
        "windows_tun_workload status=PASS scenario={}",
        arguments.scenario.label()
    ))
}

pub(crate) fn probe(arguments: &ProbeArgs) -> Result<(), String> {
    let tcp_address = SocketAddr::new(arguments.target_ip, arguments.tcp_port);
    let mut stream = TcpStream::connect_timeout(&tcp_address, IO_TIMEOUT)
        .map_err(|error| format!("Windows TUN TCP probe connect failed: {error}"))?;
    configure_tcp(&stream)?;
    let payload = checked_payload(1_024, 5);
    let mut reply = vec![0; payload.len()];
    tcp_round_trip(&mut stream, &payload, &mut reply)?;
    for udp_address in route_target_addresses(arguments.target_ip, arguments.udp_port)? {
        let socket = connected_udp(udp_address)?;
        let mut udp_reply = vec![0; payload.len()];
        udp_round_trip(&socket, &payload, &mut udp_reply)?;
    }
    let fragment_socket = connected_udp(SocketAddr::new(arguments.target_ip, arguments.udp_port))?;
    let mut fragment_reply = [0_u8; FRAGMENT_REPLY_BUFFER];
    if fragment_batch_round_trip(&fragment_socket, 1, 0, &mut fragment_reply)? != 1 {
        return Err("Windows TUN fragment path probe sequence mismatch".to_owned());
    }
    Ok(())
}

pub(crate) fn run_probe(arguments: &[OsString]) -> Result<String, String> {
    let arguments = parse_probe(arguments)?;
    probe(&arguments)?;
    Ok("windows_tun_probe status=PASS protocols=tcp,udp".to_owned())
}

pub(crate) fn finalize_udp_diagnostic(arguments: UdpDiagnosticFinalizeArgs) -> Result<(), String> {
    let targets = route_target_addresses(arguments.target_ip, arguments.udp_port)?;
    let socket = UdpSocket::bind(SocketAddr::new(arguments.target_ip, 0)).map_err(|error| {
        format!("bind Windows TUN UDP diagnostic finalize socket failed: {error}")
    })?;
    socket.set_read_timeout(Some(IO_TIMEOUT)).map_err(|error| {
        format!("set Windows TUN UDP diagnostic finalize read timeout failed: {error}")
    })?;
    socket
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| {
            format!("set Windows TUN UDP diagnostic finalize write timeout failed: {error}")
        })?;
    let local = socket.local_addr().map_err(|error| {
        format!("read Windows TUN UDP diagnostic finalize local address failed: {error}")
    })?;
    if local.ip() != arguments.target_ip {
        return Err("Windows TUN UDP diagnostic finalize socket IP mismatch".to_owned());
    }
    let marker = udp_diagnostic_finalize_marker(arguments.run_nonce).encode();
    let mut reply = [0_u8; UDP_DIAGNOSTIC_PAYLOAD_LEN];
    for target in targets {
        let sent = socket.send_to(&marker, target).map_err(|error| {
            format!("send Windows TUN UDP diagnostic finalize marker failed: {error}")
        })?;
        if sent != marker.len() {
            return Err("Windows TUN UDP diagnostic finalize marker send was partial".to_owned());
        }
        let (received, peer) = socket.recv_from(&mut reply).map_err(|error| {
            format!("receive Windows TUN UDP diagnostic finalize echo failed: {error}")
        })?;
        if peer != target || received != marker.len() || reply[..received] != marker {
            return Err("Windows TUN UDP diagnostic finalize echo mismatch".to_owned());
        }
    }
    Ok(())
}

pub(crate) fn run_udp_diagnostic_finalize(arguments: &[OsString]) -> Result<String, String> {
    let arguments = parse_udp_diagnostic_finalize(arguments)?;
    finalize_udp_diagnostic(arguments)?;
    let last_port = arguments
        .udp_port
        .checked_add((ROUTE_TARGET_SLOTS - 1) as u16)
        .expect("validated Windows TUN UDP diagnostic finalize port range");
    Ok(format!(
        "windows_tun_udp_diagnostic_finalize status=PASS target={} udp_ports={}..{}",
        arguments.target_ip, arguments.udp_port, last_port
    ))
}
