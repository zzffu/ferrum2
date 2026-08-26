use super::diagnostic::{
    ASSOCIATIONS, FRAGMENT_ACK_LEN, FRAGMENT_ACK_TAG, FRAGMENT_ACK_WINDOW, FRAGMENT_BATCH,
    FRAGMENT_PAYLOAD, FRAGMENT_REPLY_BUFFER, FRAGMENT_REQUEST_TAG,
    FRAGMENT_RETRY_BUDGET_UNIQUE_DATAGRAMS, FragmentAckBatch, FragmentPhase,
    FragmentWorkloadAccounting, IO_TIMEOUT, SUPPORT_TCP_IDLE_TIMEOUT, TCP_FAIRNESS_ACTIVE,
    TCP_FAIRNESS_FLOWS, TCP_FAIRNESS_PAYLOAD, TCP_FAIRNESS_READINESS_PAYLOAD, TCP_FAIRNESS_WARMUP,
    TCP_SINGLE_ACTIVE, TCP_SINGLE_MINIMUM_BYTES, TCP_SINGLE_PAYLOAD, TCP_SINGLE_WARMUP, UDP_ACTIVE,
    UDP_BATCH, UDP_MINIMUM_DATAGRAMS, UDP_PAYLOAD, UDP_WARMUP, UdpAssociationSourceArgs,
};
use serde_json::{Value, json};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) fn checked_payload_byte(index: usize, seed: u64) -> u8 {
    ((index as u64).wrapping_mul(131).wrapping_add(seed) & 0xff) as u8
}

pub(crate) fn checked_payload(length: usize, seed: u64) -> Vec<u8> {
    (0..length)
        .map(|index| checked_payload_byte(index, seed))
        .collect()
}

pub(crate) fn configure_tcp_with_read_timeout(
    stream: &TcpStream,
    read_timeout: Duration,
) -> Result<(), String> {
    stream
        .set_nodelay(true)
        .map_err(|error| format!("set TCP_NODELAY failed: {error}"))?;
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|error| format!("set TCP read timeout failed: {error}"))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set TCP write timeout failed: {error}"))?;
    Ok(())
}

pub(crate) fn configure_tcp(stream: &TcpStream) -> Result<(), String> {
    configure_tcp_with_read_timeout(stream, IO_TIMEOUT)
}

pub(crate) fn configure_support_tcp(stream: &TcpStream) -> Result<(), String> {
    configure_tcp_with_read_timeout(stream, SUPPORT_TCP_IDLE_TIMEOUT)
}

pub(crate) fn tcp_round_trip(
    stream: &mut TcpStream,
    payload: &[u8],
    reply: &mut [u8],
) -> Result<(), String> {
    stream
        .write_all(payload)
        .map_err(|error| format!("TCP workload write failed: {error}"))?;
    stream
        .read_exact(reply)
        .map_err(|error| format!("TCP workload read failed: {error}"))?;
    if reply != payload {
        return Err("TCP workload payload mismatch".to_owned());
    }
    Ok(())
}

pub(crate) fn elapsed_rate(units: u64, elapsed: Duration, name: &str) -> Result<u64, String> {
    let nanos = elapsed.as_nanos();
    if units == 0 || nanos == 0 {
        return Err(format!("{name} has no measured work"));
    }
    let rate = u128::from(units)
        .checked_mul(1_000_000_000)
        .ok_or_else(|| format!("{name} rate numerator overflow"))?
        / nanos;
    u64::try_from(rate.max(1)).map_err(|_| format!("{name} rate overflow"))
}

pub(crate) fn tcp_single(address: SocketAddr) -> Result<Value, String> {
    let mut stream = TcpStream::connect_timeout(&address, IO_TIMEOUT)
        .map_err(|error| format!("TCP single-flow connect failed: {error}"))?;
    configure_tcp(&stream)?;
    let payload = checked_payload(TCP_SINGLE_PAYLOAD, 1);
    let mut reply = vec![0; payload.len()];
    let warmup_deadline = Instant::now() + TCP_SINGLE_WARMUP;
    let mut warmup_bytes = 0_u64;
    while Instant::now() < warmup_deadline {
        tcp_round_trip(&mut stream, &payload, &mut reply)?;
        warmup_bytes = warmup_bytes
            .checked_add(payload.len() as u64)
            .ok_or_else(|| "TCP single-flow warmup byte count overflow".to_owned())?;
    }
    let start = Instant::now();
    let deadline = start + TCP_SINGLE_ACTIVE;
    let mut checked_bytes = 0_u64;
    while Instant::now() < deadline {
        tcp_round_trip(&mut stream, &payload, &mut reply)?;
        checked_bytes = checked_bytes
            .checked_add(payload.len() as u64)
            .ok_or_else(|| "TCP single-flow byte count overflow".to_owned())?;
    }
    let elapsed = start.elapsed();
    if checked_bytes < TCP_SINGLE_MINIMUM_BYTES {
        return Err("TCP single-flow correctness coverage is below 64 MiB".to_owned());
    }
    let cpu_payload_bytes = warmup_bytes
        .checked_add(checked_bytes)
        .ok_or_else(|| "TCP single-flow total byte count overflow".to_owned())?;
    Ok(json!({
        "measurements": {
            "throughput": elapsed_rate(checked_bytes, elapsed, "TCP throughput")?,
            "cpu_payload_bytes": cpu_payload_bytes
        },
        "checked_units": checked_bytes,
        "checks": {
            "single_flow_only": true,
            "payload_exact": true,
            "no_gso": true
        }
    }))
}

pub(crate) fn tcp_fairness(address: SocketAddr) -> Result<Value, String> {
    let start = Arc::new(OnceLock::new());
    let cancel = Arc::new(AtomicBool::new(false));
    let mut streams = Vec::with_capacity(TCP_FAIRNESS_FLOWS);
    for flow in 0..TCP_FAIRNESS_FLOWS {
        let mut stream = TcpStream::connect_timeout(&address, IO_TIMEOUT)
            .map_err(|error| format!("fairness connect failed: {error}"))?;
        configure_tcp(&stream)?;
        let readiness = checked_payload(TCP_FAIRNESS_READINESS_PAYLOAD, flow as u64);
        let mut reply = vec![0; readiness.len()];
        tcp_round_trip(&mut stream, &readiness, &mut reply)
            .map_err(|error| format!("fairness readiness flow {flow} failed: {error}"))?;
        streams.push(stream);
    }
    let mut workers = Vec::with_capacity(TCP_FAIRNESS_FLOWS);
    for (flow, mut stream) in streams.into_iter().enumerate() {
        let worker_start = Arc::clone(&start);
        let worker_cancel = Arc::clone(&cancel);
        let worker = thread::Builder::new()
            .name(format!("tun-fairness-{flow:03}"))
            .spawn(move || -> Result<u64, String> {
                let payload = checked_payload(TCP_FAIRNESS_PAYLOAD, flow as u64);
                let mut reply = vec![0; payload.len()];
                let common_start = loop {
                    if let Some(start) = worker_start.get() {
                        break *start;
                    }
                    if worker_cancel.load(Ordering::Acquire) {
                        return Err("fairness start was cancelled".to_owned());
                    }
                    thread::sleep(Duration::from_millis(1));
                };
                let warmup_deadline = common_start + TCP_FAIRNESS_WARMUP;
                while Instant::now() < warmup_deadline {
                    tcp_round_trip(&mut stream, &payload, &mut reply)?;
                }
                let deadline = warmup_deadline + TCP_FAIRNESS_ACTIVE;
                let mut bytes = 0_u64;
                while Instant::now() < deadline {
                    tcp_round_trip(&mut stream, &payload, &mut reply)?;
                    bytes = bytes
                        .checked_add(payload.len() as u64)
                        .ok_or_else(|| "fairness byte count overflow".to_owned())?;
                }
                Ok(bytes)
            });
        match worker {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                cancel.store(true, Ordering::Release);
                for worker in workers {
                    let _ = worker.join();
                }
                return Err(format!("spawn fairness worker failed: {error}"));
            }
        }
    }
    start
        .set(Instant::now() + Duration::from_millis(100))
        .map_err(|_| "fairness start was already set".to_owned())?;
    let mut values = Vec::with_capacity(TCP_FAIRNESS_FLOWS);
    let mut first_failure = None;
    for worker in workers {
        match worker.join() {
            Ok(Ok(value)) => values.push(value),
            Ok(Err(error)) => {
                first_failure.get_or_insert(error);
            }
            Err(_) => {
                first_failure.get_or_insert("fairness worker panicked".to_owned());
            }
        }
    }
    if let Some(error) = first_failure {
        return Err(error);
    }
    if values.contains(&0) {
        return Err("fairness workload starved at least one flow".to_owned());
    }
    let sum = values.iter().try_fold(0_u128, |sum, value| {
        sum.checked_add(u128::from(*value))
            .ok_or_else(|| "fairness sum overflow".to_owned())
    })?;
    let squares = values.iter().try_fold(0_u128, |sum, value| {
        let value = u128::from(*value);
        sum.checked_add(
            value
                .checked_mul(value)
                .ok_or_else(|| "fairness square overflow".to_owned())?,
        )
        .ok_or_else(|| "fairness square sum overflow".to_owned())
    })?;
    let numerator = sum
        .checked_mul(sum)
        .and_then(|value| value.checked_mul(1_000_000_000))
        .ok_or_else(|| "fairness numerator overflow".to_owned())?;
    let denominator = (TCP_FAIRNESS_FLOWS as u128)
        .checked_mul(squares)
        .ok_or_else(|| "fairness denominator overflow".to_owned())?;
    let jain_ppb =
        u64::try_from(numerator / denominator).map_err(|_| "fairness index overflow".to_owned())?;
    Ok(json!({
        "measurements": {"fairness": jain_ppb},
        "checked_units": TCP_FAIRNESS_FLOWS,
        "checks": {
            "all_256_flows_ready": true,
            "all_256_flows_nonzero": true,
            "payload_exact": true,
            "no_gso": true
        }
    }))
}

pub(crate) fn connected_udp(address: SocketAddr) -> Result<UdpSocket, String> {
    let bind = match address {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => "[::]:0"
            .parse::<SocketAddr>()
            .map_err(|_| "internal IPv6 wildcard is invalid".to_owned())?,
    };
    let socket =
        UdpSocket::bind(bind).map_err(|error| format!("UDP workload bind failed: {error}"))?;
    socket
        .connect(address)
        .map_err(|error| format!("UDP workload connect failed: {error}"))?;
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set UDP read timeout failed: {error}"))?;
    socket
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set UDP write timeout failed: {error}"))?;
    Ok(socket)
}

pub(crate) fn udp_association_source_endpoint(
    arguments: &UdpAssociationSourceArgs,
    association_index: usize,
) -> Result<SocketAddr, String> {
    if association_index >= ASSOCIATIONS {
        return Err(format!(
            "UDP association index is outside the source range: index={association_index}"
        ));
    }
    let offset = u16::try_from(association_index).map_err(|_| {
        format!("UDP association source offset overflow: index={association_index}")
    })?;
    let port = arguments
        .source_port_first
        .checked_add(offset)
        .ok_or_else(|| {
            format!("UDP association source port overflow: index={association_index}")
        })?;
    let endpoint = SocketAddr::new(arguments.source_ip, port);
    if port > arguments.source_port_last {
        return Err(format!(
            "UDP association source endpoint is outside the fixed range: index={association_index} endpoint={endpoint}"
        ));
    }
    Ok(endpoint)
}

pub(crate) fn connected_udp_association(
    address: SocketAddr,
    arguments: &UdpAssociationSourceArgs,
    association_index: usize,
) -> Result<UdpSocket, String> {
    let endpoint = udp_association_source_endpoint(arguments, association_index)?;
    let socket = UdpSocket::bind(endpoint).map_err(|error| {
        format!(
            "UDP association fixed-source bind failed: index={association_index} endpoint={endpoint} error={error}"
        )
    })?;
    socket.connect(address).map_err(|error| {
        format!(
            "UDP association fixed-source connect failed: index={association_index} endpoint={endpoint} target={address} error={error}"
        )
    })?;
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| {
            format!(
                "set UDP association fixed-source read timeout failed: index={association_index} endpoint={endpoint} error={error}"
            )
        })?;
    socket
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| {
            format!(
                "set UDP association fixed-source write timeout failed: index={association_index} endpoint={endpoint} error={error}"
            )
        })?;
    let local = socket.local_addr().map_err(|error| {
        format!(
            "read UDP association fixed-source local address failed: index={association_index} endpoint={endpoint} error={error}"
        )
    })?;
    if local != endpoint {
        return Err(format!(
            "UDP association fixed-source local address mismatch: index={association_index} endpoint={endpoint} actual={local}"
        ));
    }
    Ok(socket)
}

pub(crate) fn unconnected_udp(address: IpAddr) -> Result<UdpSocket, String> {
    let bind = match address {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => "[::]:0"
            .parse::<SocketAddr>()
            .map_err(|_| "internal IPv6 wildcard is invalid".to_owned())?,
    };
    let socket = UdpSocket::bind(bind)
        .map_err(|error| format!("multi-target UDP workload bind failed: {error}"))?;
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set multi-target UDP read timeout failed: {error}"))?;
    socket
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set multi-target UDP write timeout failed: {error}"))?;
    Ok(socket)
}

pub(crate) fn udp_round_trip(
    socket: &UdpSocket,
    payload: &[u8],
    reply: &mut [u8],
) -> Result<(), String> {
    let sent = socket
        .send(payload)
        .map_err(|error| format!("UDP workload send failed: {error}"))?;
    if sent != payload.len() {
        return Err("UDP workload sent a partial datagram".to_owned());
    }
    let received = socket
        .recv(reply)
        .map_err(|error| format!("UDP workload receive failed: {error}"))?;
    if received != payload.len() || &reply[..received] != payload {
        return Err("UDP workload payload mismatch".to_owned());
    }
    Ok(())
}

pub(crate) fn sequenced_payload(length: usize, sequence: u64) -> Result<Vec<u8>, String> {
    if length < std::mem::size_of::<u64>() {
        return Err("sequenced UDP payload is too short".to_owned());
    }
    let mut payload = checked_payload(length, sequence);
    payload[..8].copy_from_slice(&sequence.to_be_bytes());
    Ok(payload)
}

pub(crate) fn fragment_request(sequence: u64) -> Vec<u8> {
    let mut payload = checked_payload(FRAGMENT_PAYLOAD, sequence);
    payload[..8].copy_from_slice(&FRAGMENT_REQUEST_TAG);
    payload[8..16].copy_from_slice(&sequence.to_be_bytes());
    payload
}

pub(crate) fn fragment_request_sequence(payload: &[u8]) -> Result<u64, String> {
    if payload.len() != FRAGMENT_PAYLOAD {
        return Err("fragment request payload length mismatch".to_owned());
    }
    if !payload.starts_with(&FRAGMENT_REQUEST_TAG) {
        return Err("fragment request protocol tag mismatch".to_owned());
    }
    let mut encoded_sequence = [0_u8; 8];
    encoded_sequence.copy_from_slice(&payload[8..16]);
    let sequence = u64::from_be_bytes(encoded_sequence);
    if payload[16..]
        .iter()
        .enumerate()
        .any(|(offset, byte)| *byte != checked_payload_byte(offset + 16, sequence))
    {
        return Err("fragment request payload mismatch".to_owned());
    }
    Ok(sequence)
}

pub(crate) fn fragment_ack(sequence: u64) -> [u8; FRAGMENT_ACK_LEN] {
    let mut ack = [0_u8; FRAGMENT_ACK_LEN];
    ack[..8].copy_from_slice(&FRAGMENT_ACK_TAG);
    ack[8..16].copy_from_slice(&sequence.to_be_bytes());
    ack[16..24].copy_from_slice(&(FRAGMENT_PAYLOAD as u64).to_be_bytes());
    ack
}

pub(crate) fn fragment_ack_sequence(payload: &[u8]) -> Result<u64, String> {
    if payload.len() != FRAGMENT_ACK_LEN {
        return Err("fragment ACK payload length mismatch".to_owned());
    }
    if !payload.starts_with(&FRAGMENT_ACK_TAG) {
        return Err("fragment ACK protocol tag mismatch".to_owned());
    }
    let mut encoded_sequence = [0_u8; 8];
    encoded_sequence.copy_from_slice(&payload[8..16]);
    let mut encoded_request_len = [0_u8; 8];
    encoded_request_len.copy_from_slice(&payload[16..24]);
    if u64::from_be_bytes(encoded_request_len) != FRAGMENT_PAYLOAD as u64 {
        return Err("fragment ACK request length mismatch".to_owned());
    }
    Ok(u64::from_be_bytes(encoded_sequence))
}

pub(crate) fn fragment_ack_for_request(
    payload: &[u8],
) -> Result<Option<[u8; FRAGMENT_ACK_LEN]>, String> {
    if !payload.starts_with(&FRAGMENT_REQUEST_TAG) {
        return Ok(None);
    }
    let sequence = fragment_request_sequence(payload)?;
    Ok(Some(fragment_ack(sequence)))
}

pub(crate) fn udp_batch_round_trip(
    socket: &UdpSocket,
    payload_len: usize,
    batch: usize,
    first_sequence: u64,
    reply: &mut [u8],
) -> Result<u64, String> {
    if batch == 0 || reply.len() < payload_len {
        return Err("UDP batch bounds are invalid".to_owned());
    }
    let end_sequence = first_sequence
        .checked_add(batch as u64)
        .ok_or_else(|| "UDP batch sequence overflow".to_owned())?;
    for sequence in first_sequence..end_sequence {
        let payload = sequenced_payload(payload_len, sequence)?;
        if socket
            .send(&payload)
            .map_err(|error| format!("UDP batch send failed: {error}"))?
            != payload.len()
        {
            return Err("UDP batch sent a partial datagram".to_owned());
        }
    }
    let mut seen = vec![false; batch];
    for _ in 0..batch {
        let received = socket
            .recv(reply)
            .map_err(|error| format!("UDP batch receive failed: {error}"))?;
        if received != payload_len {
            return Err("UDP batch payload length mismatch".to_owned());
        }
        let mut encoded_sequence = [0_u8; 8];
        encoded_sequence.copy_from_slice(&reply[..8]);
        let sequence = u64::from_be_bytes(encoded_sequence);
        if !(first_sequence..end_sequence).contains(&sequence) {
            return Err("UDP batch reply sequence is outside the request set".to_owned());
        }
        let offset = (sequence - first_sequence) as usize;
        if std::mem::replace(&mut seen[offset], true) {
            return Err("UDP batch contained a duplicate reply".to_owned());
        }
        if reply[..received] != sequenced_payload(payload_len, sequence)? {
            return Err("UDP batch payload mismatch".to_owned());
        }
    }
    Ok(end_sequence)
}

pub(crate) fn fragment_batch_round_trip(
    socket: &UdpSocket,
    batch: usize,
    first_sequence: u64,
    reply: &mut [u8],
) -> Result<u64, String> {
    if batch == 0 || reply.len() < FRAGMENT_REPLY_BUFFER {
        return Err("fragment batch bounds are invalid".to_owned());
    }
    let end_sequence = first_sequence
        .checked_add(batch as u64)
        .ok_or_else(|| "fragment batch sequence overflow".to_owned())?;
    for sequence in first_sequence..end_sequence {
        let payload = fragment_request(sequence);
        if socket
            .send(&payload)
            .map_err(|error| format!("fragment batch send failed: {error}"))?
            != payload.len()
        {
            return Err("fragment batch sent a partial datagram".to_owned());
        }
    }
    let mut seen = vec![false; batch];
    for _ in 0..batch {
        let received = socket
            .recv(reply)
            .map_err(|error| format!("fragment ACK receive failed: {error}"))?;
        let sequence = fragment_ack_sequence(&reply[..received])?;
        if !(first_sequence..end_sequence).contains(&sequence) {
            return Err("fragment ACK sequence is outside the request set".to_owned());
        }
        let offset = (sequence - first_sequence) as usize;
        if std::mem::replace(&mut seen[offset], true) {
            return Err("fragment batch contained a duplicate ACK".to_owned());
        }
    }
    Ok(end_sequence)
}

pub(crate) fn fragment_retry_budget(unique_datagrams: u64) -> u64 {
    unique_datagrams
        .div_ceil(FRAGMENT_RETRY_BUDGET_UNIQUE_DATAGRAMS)
        .max(1)
}

pub(crate) fn fragment_batch_failure(
    error: &str,
    batch: &FragmentAckBatch,
    retry_budget: u64,
) -> String {
    let missing_sequences = batch.missing_sequences();
    format!(
        "{error}; first={} end={} seen={} missing={} missing_sequences={missing_sequences:?} budget={retry_budget}",
        batch.first_sequence,
        batch.end_sequence,
        batch.seen_bitmap(),
        missing_sequences.len(),
    )
}

pub(crate) fn send_fragment_request(socket: &UdpSocket, sequence: u64) -> Result<(), String> {
    let payload = fragment_request(sequence);
    if socket
        .send(&payload)
        .map_err(|error| format!("fragment request send failed: {error}"))?
        != payload.len()
    {
        return Err("fragment request send was partial".to_owned());
    }
    Ok(())
}

pub(crate) fn receive_fragment_ack_window(
    socket: &UdpSocket,
    reply: &mut [u8],
    batch: &mut FragmentAckBatch,
    accounting: &mut FragmentWorkloadAccounting,
    retry_budget: u64,
) -> Result<bool, String> {
    let deadline = Instant::now() + FRAGMENT_ACK_WINDOW;
    while !batch.complete() {
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        socket
            .set_read_timeout(Some(deadline.duration_since(now)))
            .map_err(|error| {
                fragment_batch_failure(
                    &format!("set fragment ACK window failed: {error}"),
                    batch,
                    retry_budget,
                )
            })?;
        let received = match socket.recv(reply) {
            Ok(received) => received,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Ok(false);
            }
            Err(error) => {
                return Err(fragment_batch_failure(
                    &format!("fragment ACK receive failed: {error}"),
                    batch,
                    retry_budget,
                ));
            }
        };
        let sequence = fragment_ack_sequence(&reply[..received])
            .map_err(|error| fragment_batch_failure(&error, batch, retry_budget))?;
        accounting
            .observe_ack(batch, sequence)
            .map_err(|error| fragment_batch_failure(&error, batch, retry_budget))?;
    }
    Ok(true)
}

pub(crate) fn fragment_workload_batch_round_trip(
    socket: &UdpSocket,
    phase: FragmentPhase,
    first_sequence: u64,
    reply: &mut [u8],
    accounting: &mut FragmentWorkloadAccounting,
) -> Result<u64, String> {
    if reply.len() < FRAGMENT_REPLY_BUFFER {
        return Err(format!(
            "fragment workload reply buffer is invalid; first={first_sequence} end={first_sequence} seen=<none> missing={FRAGMENT_BATCH} budget=1"
        ));
    }
    let mut batch = FragmentAckBatch::new(first_sequence, FRAGMENT_BATCH).map_err(|error| {
        format!(
            "{error}; first={first_sequence} end=<overflow> seen=<none> missing={FRAGMENT_BATCH} budget=1"
        )
    })?;
    let prospective_unique = accounting
        .total_unique_datagrams()
        .and_then(|value| {
            value
                .checked_add(FRAGMENT_BATCH as u64)
                .ok_or_else(|| "fragment prospective unique count overflow".to_owned())
        })
        .map_err(|error| fragment_batch_failure(&error, &batch, 1))?;
    let retry_budget = fragment_retry_budget(prospective_unique);
    accounting
        .record_initial_attempts(phase, FRAGMENT_BATCH as u64)
        .map_err(|error| fragment_batch_failure(&error, &batch, retry_budget))?;
    for sequence in batch.first_sequence..batch.end_sequence {
        send_fragment_request(socket, sequence)
            .map_err(|error| fragment_batch_failure(&error, &batch, retry_budget))?;
    }
    if !receive_fragment_ack_window(socket, reply, &mut batch, accounting, retry_budget)? {
        accounting
            .record_ack_window_expiration()
            .map_err(|error| fragment_batch_failure(&error, &batch, retry_budget))?;
        let missing_sequence = batch
            .sole_missing_sequence()
            .map_err(|error| fragment_batch_failure(&error, &batch, retry_budget))?;
        accounting
            .record_retransmission(phase, missing_sequence, retry_budget)
            .map_err(|error| fragment_batch_failure(&error, &batch, retry_budget))?;
        send_fragment_request(socket, missing_sequence)
            .map_err(|error| fragment_batch_failure(&error, &batch, retry_budget))?;
        if !receive_fragment_ack_window(socket, reply, &mut batch, accounting, retry_budget)? {
            accounting
                .record_ack_window_expiration()
                .map_err(|error| fragment_batch_failure(&error, &batch, retry_budget))?;
            return Err(fragment_batch_failure(
                "fragment ACK remained missing after its only retransmission",
                &batch,
                retry_budget,
            ));
        }
    }
    accounting
        .record_unique_datagrams(phase, FRAGMENT_BATCH as u64)
        .map_err(|error| fragment_batch_failure(&error, &batch, retry_budget))?;
    Ok(batch.end_sequence)
}

pub(crate) fn udp_packets(address: SocketAddr) -> Result<Value, String> {
    let socket = connected_udp(address)?;
    let mut reply = vec![0; UDP_PAYLOAD];
    let mut sequence = 0_u64;
    let warmup_deadline = Instant::now() + UDP_WARMUP;
    while Instant::now() < warmup_deadline {
        sequence = udp_batch_round_trip(&socket, UDP_PAYLOAD, UDP_BATCH, sequence, &mut reply)?;
    }
    let start = Instant::now();
    let deadline = start + UDP_ACTIVE;
    let mut datagrams = 0_u64;
    while Instant::now() < deadline {
        sequence = udp_batch_round_trip(&socket, UDP_PAYLOAD, UDP_BATCH, sequence, &mut reply)?;
        datagrams = datagrams
            .checked_add(UDP_BATCH as u64)
            .ok_or_else(|| "UDP datagram count overflow".to_owned())?;
    }
    let elapsed = start.elapsed();
    if datagrams < UDP_MINIMUM_DATAGRAMS {
        return Err("UDP packet-rate correctness coverage is below 4096 echoes".to_owned());
    }
    Ok(json!({
        "measurements": {
            "packet_rate": elapsed_rate(datagrams, elapsed, "UDP packet rate")?
        },
        "checked_units": datagrams,
        "checks": {
            "every_reply_accounted": true,
            "payload_exact": true,
            "no_gso": true
        }
    }))
}

pub(crate) fn association_round(
    sockets: &[UdpSocket],
    seed_prefix: u64,
    reply: &mut [u8; 32],
    batch_associations: usize,
    phase: &str,
) -> Result<(), String> {
    if batch_associations == 0 || !sockets.len().is_multiple_of(batch_associations) {
        return Err("association batch bounds are invalid".to_owned());
    }
    for (batch_index, batch) in sockets.chunks(batch_associations).enumerate() {
        let base = batch_index * batch_associations;
        for (offset, socket) in batch.iter().enumerate() {
            let seed = seed_prefix
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add((base + offset) as u64);
            let payload = checked_payload(32, seed);
            if socket
                .send(&payload)
                .map_err(|error| {
                    format!(
                        "association batch send failed: phase={phase} association_index={} error={error}",
                        base + offset
                    )
                })?
                != payload.len()
            {
                return Err(format!(
                    "association batch sent a partial datagram: phase={phase} association_index={}",
                    base + offset
                ));
            }
        }
        for (offset, socket) in batch.iter().enumerate() {
            let seed = seed_prefix
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add((base + offset) as u64);
            let payload = checked_payload(32, seed);
            let received = socket
                .recv(reply)
                .map_err(|error| {
                    format!(
                        "association batch receive failed: phase={phase} association_index={} error={error}",
                        base + offset
                    )
                })?;
            if received != payload.len() || reply[..received] != payload {
                return Err(format!(
                    "association batch payload mismatch: phase={phase} association_index={}",
                    base + offset
                ));
            }
        }
    }
    Ok(())
}
