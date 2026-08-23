use serde_json::{Value, json};
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const TCP_SINGLE_WARMUP: Duration = Duration::from_secs(10);
const TCP_SINGLE_ACTIVE: Duration = Duration::from_secs(60);
const TCP_SINGLE_PAYLOAD: usize = 65_536;
const TCP_SINGLE_MINIMUM_BYTES: u64 = 64 * 1024 * 1024;
const TCP_FAIRNESS_WARMUP: Duration = Duration::from_secs(10);
const TCP_FAIRNESS_ACTIVE: Duration = Duration::from_secs(30);
const TCP_FAIRNESS_FLOWS: usize = 256;
const TCP_FAIRNESS_PAYLOAD: usize = 16_384;
const UDP_WARMUP: Duration = Duration::from_secs(5);
const UDP_ACTIVE: Duration = Duration::from_secs(30);
const UDP_PAYLOAD: usize = 1_200;
const UDP_BATCH: usize = 64;
const UDP_MINIMUM_DATAGRAMS: u64 = 4_096;
const ASSOCIATIONS: usize = 8_192;
const ASSOCIATION_BATCH: usize = 256;
const ASSOCIATION_LOOKUP_ROUNDS: usize = 64;
const ASSOCIATION_WARMUP: Duration = Duration::from_secs(5);
const FRAGMENT_WARMUP: Duration = Duration::from_secs(5);
const FRAGMENT_ACTIVE: Duration = Duration::from_secs(30);
const FRAGMENT_PAYLOAD: usize = 1_440;
const FRAGMENT_BATCH: usize = 8;
const FRAGMENT_MINIMUM_DATAGRAMS: u64 = 4_096;
const FRAGMENT_REQUEST_TAG: [u8; 8] = *b"F2FRQ001";
const FRAGMENT_ACK_TAG: [u8; 8] = *b"F2FAK001";
const FRAGMENT_ACK_LEN: usize = 24;
const FRAGMENT_REPLY_BUFFER: usize = FRAGMENT_ACK_LEN + 1;
const PERFORMANCE_TUN_MTU: usize = 1_420;
const SUPPORT_UNDERLAY_IPV4_MTU: usize = 1_500;
const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const FRAGMENT_IPV4_RESPONSE_BOUND: usize = PERFORMANCE_TUN_MTU - IPV4_HEADER_LEN - UDP_HEADER_LEN;
const RING_BURST_ATTEMPTS: u64 = 1_000_000;
const ROUTE_SOURCE_SLOTS: usize = 64;
const ROUTE_TARGET_SLOTS: usize = 4;
const ROUTE_DATAGRAMS_PER_TARGET: usize = 32;
const ROUTE_PAYLOAD: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const SUPPORT_MAX_TCP_CONNECTIONS: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    TcpSingle,
    TcpFairness,
    UdpPackets,
    UdpAssociations,
    UdpRouteOnce,
    Fragments,
    RingFull,
}

impl Scenario {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "tcp-single-flow" => Ok(Self::TcpSingle),
            "tcp-256-flow-fairness" => Ok(Self::TcpFairness),
            "udp-packets-per-second" => Ok(Self::UdpPackets),
            "udp-8192-association-lookup-expiry" => Ok(Self::UdpAssociations),
            "udp-route-once" => Ok(Self::UdpRouteOnce),
            "fragment-reassembly-throughput" => Ok(Self::Fragments),
            "wintun-ring-full-drop-rate" => Ok(Self::RingFull),
            _ => Err("unsupported Windows TUN workload scenario".to_owned()),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::TcpSingle => "tcp-single-flow",
            Self::TcpFairness => "tcp-256-flow-fairness",
            Self::UdpPackets => "udp-packets-per-second",
            Self::UdpAssociations => "udp-8192-association-lookup-expiry",
            Self::UdpRouteOnce => "udp-route-once",
            Self::Fragments => "fragment-reassembly-throughput",
            Self::RingFull => "wintun-ring-full-drop-rate",
        }
    }
}

struct WorkloadArgs {
    scenario: Scenario,
    target_ip: IpAddr,
    tcp_port: u16,
    udp_port: u16,
    output: PathBuf,
}

struct ProbeArgs {
    target_ip: IpAddr,
    tcp_port: u16,
    udp_port: u16,
}

struct SupportArgs {
    listen_ip: IpAddr,
    tcp_port: u16,
    udp_port: u16,
}

fn parse_pairs(arguments: &[OsString]) -> Result<Vec<(String, String)>, String> {
    let mut chunks = arguments.chunks_exact(2);
    let mut pairs = Vec::new();
    for pair in &mut chunks {
        let flag = pair[0]
            .to_str()
            .ok_or_else(|| "Windows TUN option name is not UTF-8".to_owned())?;
        let value = pair[1]
            .to_str()
            .ok_or_else(|| format!("Windows TUN option {flag} is not UTF-8"))?;
        pairs.push((flag.to_owned(), value.to_owned()));
    }
    if !chunks.remainder().is_empty() {
        return Err("every Windows TUN option requires one value".to_owned());
    }
    Ok(pairs)
}

fn take_unique(slot: &mut Option<String>, value: String, flag: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("duplicate Windows TUN option: {flag}"));
    }
    Ok(())
}

fn parse_port(value: Option<String>, flag: &str) -> Result<u16, String> {
    let value = value.ok_or_else(|| format!("missing Windows TUN option: {flag}"))?;
    let port = value
        .parse::<u16>()
        .map_err(|_| format!("{flag} must be a decimal TCP/UDP port"))?;
    if port == 0 || port.to_string() != value {
        return Err(format!("{flag} must be a canonical nonzero port"));
    }
    Ok(port)
}

fn parse_workload(arguments: &[OsString]) -> Result<WorkloadArgs, String> {
    let mut scenario = None;
    let mut target_ip = None;
    let mut tcp_port = None;
    let mut udp_port = None;
    let mut output = None;
    for (flag, value) in parse_pairs(arguments)? {
        match flag.as_str() {
            "--scenario" => take_unique(&mut scenario, value, &flag)?,
            "--target-ip" => take_unique(&mut target_ip, value, &flag)?,
            "--tcp-port" => take_unique(&mut tcp_port, value, &flag)?,
            "--udp-port" => take_unique(&mut udp_port, value, &flag)?,
            "--output" => take_unique(&mut output, value, &flag)?,
            _ => return Err(format!("unsupported Windows TUN option: {flag}")),
        }
    }
    let scenario = Scenario::parse(
        &scenario.ok_or_else(|| "missing Windows TUN option: --scenario".to_owned())?,
    )?;
    let target_ip = target_ip
        .ok_or_else(|| "missing Windows TUN option: --target-ip".to_owned())?
        .parse::<IpAddr>()
        .map_err(|_| "--target-ip must be an IP literal".to_owned())?;
    if target_ip.is_unspecified() || target_ip.is_loopback() || target_ip.is_multicast() {
        return Err("--target-ip must be a non-loopback unicast address".to_owned());
    }
    let output =
        PathBuf::from(output.ok_or_else(|| "missing Windows TUN option: --output".to_owned())?);
    if output.as_os_str().is_empty() || output.exists() {
        return Err("Windows TUN workload output baseline must be absent".to_owned());
    }
    if output.parent().is_none_or(|parent| !parent.is_dir()) {
        return Err("Windows TUN workload output parent must exist".to_owned());
    }
    Ok(WorkloadArgs {
        scenario,
        target_ip,
        tcp_port: parse_port(tcp_port, "--tcp-port")?,
        udp_port: parse_port(udp_port, "--udp-port")?,
        output,
    })
}

fn parse_probe(arguments: &[OsString]) -> Result<ProbeArgs, String> {
    let mut target_ip = None;
    let mut tcp_port = None;
    let mut udp_port = None;
    for (flag, value) in parse_pairs(arguments)? {
        match flag.as_str() {
            "--target-ip" => take_unique(&mut target_ip, value, &flag)?,
            "--tcp-port" => take_unique(&mut tcp_port, value, &flag)?,
            "--udp-port" => take_unique(&mut udp_port, value, &flag)?,
            _ => return Err(format!("unsupported Windows TUN probe option: {flag}")),
        }
    }
    let target_ip = target_ip
        .ok_or_else(|| "missing Windows TUN option: --target-ip".to_owned())?
        .parse::<IpAddr>()
        .map_err(|_| "--target-ip must be an IP literal".to_owned())?;
    if target_ip.is_unspecified() || target_ip.is_loopback() || target_ip.is_multicast() {
        return Err("--target-ip must be a non-loopback unicast address".to_owned());
    }
    Ok(ProbeArgs {
        target_ip,
        tcp_port: parse_port(tcp_port, "--tcp-port")?,
        udp_port: parse_port(udp_port, "--udp-port")?,
    })
}

fn parse_support(arguments: &[OsString]) -> Result<SupportArgs, String> {
    let mut listen_ip = None;
    let mut tcp_port = None;
    let mut udp_port = None;
    for (flag, value) in parse_pairs(arguments)? {
        match flag.as_str() {
            "--listen-ip" => take_unique(&mut listen_ip, value, &flag)?,
            "--tcp-port" => take_unique(&mut tcp_port, value, &flag)?,
            "--udp-port" => take_unique(&mut udp_port, value, &flag)?,
            _ => return Err(format!("unsupported Windows TUN support option: {flag}")),
        }
    }
    let listen_ip = listen_ip
        .ok_or_else(|| "missing Windows TUN option: --listen-ip".to_owned())?
        .parse::<IpAddr>()
        .map_err(|_| "--listen-ip must be an IP literal".to_owned())?;
    if listen_ip.is_multicast() {
        return Err("--listen-ip cannot be multicast".to_owned());
    }
    Ok(SupportArgs {
        listen_ip,
        tcp_port: parse_port(tcp_port, "--tcp-port")?,
        udp_port: parse_port(udp_port, "--udp-port")?,
    })
}

fn checked_payload_byte(index: usize, seed: u64) -> u8 {
    ((index as u64).wrapping_mul(131).wrapping_add(seed) & 0xff) as u8
}

fn checked_payload(length: usize, seed: u64) -> Vec<u8> {
    (0..length)
        .map(|index| checked_payload_byte(index, seed))
        .collect()
}

fn configure_tcp(stream: &TcpStream) -> Result<(), String> {
    stream
        .set_nodelay(true)
        .map_err(|error| format!("set TCP_NODELAY failed: {error}"))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set TCP read timeout failed: {error}"))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set TCP write timeout failed: {error}"))?;
    Ok(())
}

fn tcp_round_trip(stream: &mut TcpStream, payload: &[u8], reply: &mut [u8]) -> Result<(), String> {
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

fn elapsed_rate(units: u64, elapsed: Duration, name: &str) -> Result<u64, String> {
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

fn tcp_single(address: SocketAddr) -> Result<Value, String> {
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

fn tcp_fairness(address: SocketAddr) -> Result<Value, String> {
    let start = Arc::new(OnceLock::new());
    let cancel = Arc::new(AtomicBool::new(false));
    let mut streams = Vec::with_capacity(TCP_FAIRNESS_FLOWS);
    for _ in 0..TCP_FAIRNESS_FLOWS {
        let stream = TcpStream::connect_timeout(&address, IO_TIMEOUT)
            .map_err(|error| format!("fairness connect failed: {error}"))?;
        configure_tcp(&stream)?;
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
            "all_256_flows_nonzero": true,
            "payload_exact": true,
            "no_gso": true
        }
    }))
}

fn connected_udp(address: SocketAddr) -> Result<UdpSocket, String> {
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

fn unconnected_udp(address: IpAddr) -> Result<UdpSocket, String> {
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

fn udp_round_trip(socket: &UdpSocket, payload: &[u8], reply: &mut [u8]) -> Result<(), String> {
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

fn sequenced_payload(length: usize, sequence: u64) -> Result<Vec<u8>, String> {
    if length < std::mem::size_of::<u64>() {
        return Err("sequenced UDP payload is too short".to_owned());
    }
    let mut payload = checked_payload(length, sequence);
    payload[..8].copy_from_slice(&sequence.to_be_bytes());
    Ok(payload)
}

fn fragment_request(sequence: u64) -> Vec<u8> {
    let mut payload = checked_payload(FRAGMENT_PAYLOAD, sequence);
    payload[..8].copy_from_slice(&FRAGMENT_REQUEST_TAG);
    payload[8..16].copy_from_slice(&sequence.to_be_bytes());
    payload
}

fn fragment_request_sequence(payload: &[u8]) -> Result<u64, String> {
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

fn fragment_ack(sequence: u64) -> [u8; FRAGMENT_ACK_LEN] {
    let mut ack = [0_u8; FRAGMENT_ACK_LEN];
    ack[..8].copy_from_slice(&FRAGMENT_ACK_TAG);
    ack[8..16].copy_from_slice(&sequence.to_be_bytes());
    ack[16..24].copy_from_slice(&(FRAGMENT_PAYLOAD as u64).to_be_bytes());
    ack
}

fn fragment_ack_sequence(payload: &[u8]) -> Result<u64, String> {
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

fn fragment_ack_for_request(payload: &[u8]) -> Result<Option<[u8; FRAGMENT_ACK_LEN]>, String> {
    if !payload.starts_with(&FRAGMENT_REQUEST_TAG) {
        return Ok(None);
    }
    let sequence = fragment_request_sequence(payload)?;
    Ok(Some(fragment_ack(sequence)))
}

fn udp_batch_round_trip(
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

fn fragment_batch_round_trip(
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

fn udp_packets(address: SocketAddr) -> Result<Value, String> {
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

fn association_round(
    sockets: &[UdpSocket],
    seed_prefix: u64,
    reply: &mut [u8; 32],
) -> Result<(), String> {
    for (batch_index, batch) in sockets.chunks(ASSOCIATION_BATCH).enumerate() {
        let base = batch_index * ASSOCIATION_BATCH;
        for (offset, socket) in batch.iter().enumerate() {
            let seed = seed_prefix
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add((base + offset) as u64);
            let payload = checked_payload(32, seed);
            if socket
                .send(&payload)
                .map_err(|error| format!("association batch send failed: {error}"))?
                != payload.len()
            {
                return Err("association batch sent a partial datagram".to_owned());
            }
        }
        for (offset, socket) in batch.iter().enumerate() {
            let seed = seed_prefix
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add((base + offset) as u64);
            let payload = checked_payload(32, seed);
            let received = socket
                .recv(reply)
                .map_err(|error| format!("association batch receive failed: {error}"))?;
            if received != payload.len() || reply[..received] != payload {
                return Err("association batch payload mismatch".to_owned());
            }
        }
    }
    Ok(())
}

fn udp_associations(address: SocketAddr) -> Result<Value, String> {
    let mut sockets = Vec::with_capacity(ASSOCIATIONS);
    let mut reply = [0_u8; 32];
    for _ in 0..ASSOCIATIONS {
        sockets.push(connected_udp(address)?);
    }
    let warmup_deadline = Instant::now() + ASSOCIATION_WARMUP;
    let mut warmup_round = 0_u64;
    while Instant::now() < warmup_deadline || warmup_round == 0 {
        association_round(&sockets, warmup_round, &mut reply)?;
        warmup_round = warmup_round
            .checked_add(1)
            .ok_or_else(|| "association warmup round overflow".to_owned())?;
    }
    let start = Instant::now();
    let mut lookups = 0_u64;
    for round in 0..ASSOCIATION_LOOKUP_ROUNDS {
        association_round(&sockets, warmup_round + round as u64, &mut reply)?;
        lookups = lookups
            .checked_add(ASSOCIATIONS as u64)
            .ok_or_else(|| "association lookup count overflow".to_owned())?;
    }
    let elapsed = start.elapsed();
    let expected = (ASSOCIATIONS * ASSOCIATION_LOOKUP_ROUNDS) as u64;
    if lookups != expected {
        return Err("association workload lookup count mismatch".to_owned());
    }
    // Refresh the whole key set as one burst so the collector can observe the
    // exact 8192-entry peak before the fixed idle timeout starts expiring it.
    association_round(&sockets, u32::MAX as u64, &mut reply)?;
    drop(sockets);
    Ok(json!({
        "measurements": {
            "lookup_rate": elapsed_rate(lookups, elapsed, "association lookup")?
        },
        "checked_units": lookups,
        "checks": {
            "exactly_8192_associations": true,
            "all_lookups_hit": true,
            "no_gso": true
        }
    }))
}

fn route_target_addresses(target_ip: IpAddr, base_port: u16) -> Result<Vec<SocketAddr>, String> {
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

const fn route_target_order(source_slot: usize) -> [usize; ROUTE_TARGET_SLOTS] {
    if source_slot.is_multiple_of(2) {
        [0, 1, 2, 3]
    } else {
        [1, 0, 2, 3]
    }
}

fn send_route_targets(
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

fn receive_route_targets(
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

fn udp_route_once(target_ip: IpAddr, base_port: u16) -> Result<Value, String> {
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

fn fragments(address: SocketAddr) -> Result<Value, String> {
    let socket = connected_udp(address)?;
    let mut reply = [0_u8; FRAGMENT_REPLY_BUFFER];
    let mut sequence = 0_u64;
    let warmup_deadline = Instant::now() + FRAGMENT_WARMUP;
    while Instant::now() < warmup_deadline {
        sequence = fragment_batch_round_trip(&socket, FRAGMENT_BATCH, sequence, &mut reply)?;
    }
    let start = Instant::now();
    let deadline = start + FRAGMENT_ACTIVE;
    let mut datagrams = 0_u64;
    while Instant::now() < deadline || datagrams < FRAGMENT_MINIMUM_DATAGRAMS {
        sequence = fragment_batch_round_trip(&socket, FRAGMENT_BATCH, sequence, &mut reply)?;
        datagrams = datagrams
            .checked_add(FRAGMENT_BATCH as u64)
            .ok_or_else(|| "fragment datagram count overflow".to_owned())?;
    }
    let elapsed = start.elapsed();
    let bytes = datagrams
        .checked_mul(FRAGMENT_PAYLOAD as u64)
        .ok_or_else(|| "fragment byte count overflow".to_owned())?;
    Ok(json!({
        "measurements": {
            "reassembly_rate": elapsed_rate(bytes, elapsed, "fragment reassembly")?
        },
        "checked_units": datagrams,
        "checks": {
            "payload_exact": true,
            "no_gso": true
        }
    }))
}

fn ring_full(address: SocketAddr) -> Result<Value, String> {
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

fn write_observation(path: &Path, scenario: Scenario, observation: Value) -> Result<(), String> {
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

pub(super) fn run_workload(arguments: &[OsString]) -> Result<String, String> {
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
        Scenario::UdpAssociations => udp_associations(address)?,
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

fn probe(arguments: &ProbeArgs) -> Result<(), String> {
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

pub(super) fn run_probe(arguments: &[OsString]) -> Result<String, String> {
    let arguments = parse_probe(arguments)?;
    probe(&arguments)?;
    Ok("windows_tun_probe status=PASS protocols=tcp,udp".to_owned())
}

fn serve_tcp(mut stream: TcpStream) -> Result<(), String> {
    configure_tcp(&stream)?;
    let mut buffer = vec![0_u8; 65_536];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|error| format!("support TCP read failed: {error}"))?;
        if read == 0 {
            return Ok(());
        }
        stream
            .write_all(&buffer[..read])
            .map_err(|error| format!("support TCP write failed: {error}"))?;
    }
}

pub(super) fn run_support(arguments: &[OsString]) -> Result<String, String> {
    let arguments = parse_support(arguments)?;
    let tcp_address = SocketAddr::new(arguments.listen_ip, arguments.tcp_port);
    let udp_addresses = route_target_addresses(arguments.listen_ip, arguments.udp_port)?;
    let tcp = TcpListener::bind(tcp_address)
        .map_err(|error| format!("bind Windows TUN support TCP failed: {error}"))?;
    let udp_sockets = udp_addresses
        .iter()
        .map(|address| {
            UdpSocket::bind(address)
                .map_err(|error| format!("bind Windows TUN support UDP failed: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let active = Arc::new(AtomicUsize::new(0));
    let udp_workers = udp_sockets
        .into_iter()
        .enumerate()
        .map(|(slot, udp)| {
            thread::Builder::new()
                .name(format!("tun-support-udp-{slot}"))
                .spawn(move || -> Result<(), String> {
                    let mut buffer = vec![0_u8; 65_507];
                    loop {
                        let (read, peer) = udp
                            .recv_from(&mut buffer)
                            .map_err(|error| format!("support UDP receive failed: {error}"))?;
                        let request = &buffer[..read];
                        let (sent, response_len) = match fragment_ack_for_request(request) {
                            Ok(Some(ack)) => udp.send_to(&ack, peer).map(|sent| (sent, ack.len())),
                            Ok(None) => {
                                udp.send_to(request, peer).map(|sent| (sent, request.len()))
                            }
                            Err(_) => continue,
                        }
                        .map_err(|error| format!("support UDP send failed: {error}"))?;
                        if sent != response_len {
                            return Err("support UDP sent a partial datagram".to_owned());
                        }
                    }
                })
                .map_err(|error| format!("spawn support UDP worker failed: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    println!(
        "windows_tun_support status=READY tcp={} udp={}..={}",
        tcp.local_addr()
            .map_err(|error| format!("read support TCP address failed: {error}"))?,
        udp_addresses[0],
        udp_addresses[ROUTE_TARGET_SLOTS - 1],
    );
    std::io::stdout()
        .flush()
        .map_err(|error| format!("flush support readiness failed: {error}"))?;
    for accepted in tcp.incoming() {
        let stream = accepted.map_err(|error| format!("support TCP accept failed: {error}"))?;
        if active.fetch_add(1, Ordering::AcqRel) >= SUPPORT_MAX_TCP_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            drop(stream);
            continue;
        }
        let active = Arc::clone(&active);
        thread::Builder::new()
            .name("tun-support-tcp".to_owned())
            .spawn(move || {
                let result = serve_tcp(stream);
                active.fetch_sub(1, Ordering::AcqRel);
                result
            })
            .map_err(|error| format!("spawn support TCP worker failed: {error}"))?;
    }
    for worker in udp_workers {
        let _ = worker.join();
    }
    Err("Windows TUN support listener stopped unexpectedly".to_owned())
}

pub(super) fn self_check() -> Result<(), String> {
    let directory = tempfile::tempdir()
        .map_err(|error| format!("create Windows TUN self-check directory failed: {error}"))?;
    let output = directory.path().join("observation.json");
    let arguments: Vec<OsString> = [
        "--scenario".to_owned(),
        "tcp-single-flow".to_owned(),
        "--target-ip".to_owned(),
        "192.0.2.10".to_owned(),
        "--tcp-port".to_owned(),
        "443".to_owned(),
        "--udp-port".to_owned(),
        "53".to_owned(),
        "--output".to_owned(),
        output.to_string_lossy().into_owned(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let parsed = parse_workload(&arguments)?;
    if parsed.scenario != Scenario::TcpSingle
        || parsed.target_ip != "192.0.2.10".parse::<IpAddr>().expect("literal")
        || parsed.tcp_port != 443
        || parsed.udp_port != 53
        || parsed.output != output
    {
        return Err("Windows TUN workload arguments were not preserved".to_owned());
    }
    let mut duplicate = arguments.clone();
    duplicate.extend([
        OsString::from("--scenario"),
        OsString::from("udp-packets-per-second"),
    ]);
    if parse_workload(&duplicate).is_ok() {
        return Err("Windows TUN duplicate option was accepted".to_owned());
    }
    let mut loopback = arguments.clone();
    loopback[3] = OsString::from("127.0.0.1");
    if parse_workload(&loopback).is_ok() {
        return Err("Windows TUN loopback target was accepted".to_owned());
    }
    if elapsed_rate(10, Duration::from_secs(2), "self-check")? != 5 {
        return Err("Windows TUN integer rate calculation is invalid".to_owned());
    }
    let payload = sequenced_payload(32, 0x0102_0304_0506_0708)?;
    if payload[..8] != 0x0102_0304_0506_0708_u64.to_be_bytes()
        || payload == sequenced_payload(32, 0x0102_0304_0506_0709)?
    {
        return Err("Windows TUN sequenced UDP payload is invalid".to_owned());
    }
    let fragment_sequence = 0x1112_1314_1516_1718_u64;
    let fragment_request = fragment_request(fragment_sequence);
    let expected_ack = fragment_ack(fragment_sequence);
    let support_ack = fragment_ack_for_request(&fragment_request)?
        .ok_or_else(|| "fragment request was classified as an ordinary echo".to_owned())?;
    if fragment_request.len() != FRAGMENT_PAYLOAD
        || fragment_request_sequence(&fragment_request)? != fragment_sequence
        || support_ack != expected_ack
        || fragment_ack_sequence(&support_ack)? != fragment_sequence
    {
        return Err("Windows TUN fragment request/ACK round trip is invalid".to_owned());
    }
    if fragment_ack_for_request(&payload)?.is_some() {
        return Err("ordinary UDP echo payload was classified as a fragment request".to_owned());
    }
    if FRAGMENT_ACK_LEN != 24
        || FRAGMENT_REPLY_BUFFER != FRAGMENT_ACK_LEN + 1
        || FRAGMENT_ACK_LEN > FRAGMENT_IPV4_RESPONSE_BOUND
    {
        return Err("Windows TUN fragment ACK bound is invalid".to_owned());
    }
    let fragment_data_capacity = ((PERFORMANCE_TUN_MTU - IPV4_HEADER_LEN) / 8) * 8;
    let fragment_count = (FRAGMENT_PAYLOAD + UDP_HEADER_LEN).div_ceil(fragment_data_capacity);
    let fragment_ipv4_len = FRAGMENT_PAYLOAD + UDP_HEADER_LEN + IPV4_HEADER_LEN;
    if fragment_count != 2
        || fragment_ipv4_len <= PERFORMANCE_TUN_MTU
        || fragment_ipv4_len > SUPPORT_UNDERLAY_IPV4_MTU
    {
        return Err(
            "Windows TUN fragment request must split at the TUN MTU without fragmenting the support underlay"
                .to_owned(),
        );
    }
    if fragment_ack_for_request(&fragment_request[..FRAGMENT_PAYLOAD - 1]).is_ok() {
        return Err("truncated fragment request was accepted".to_owned());
    }
    let mut extended_request = fragment_request.clone();
    extended_request.push(0);
    if fragment_ack_for_request(&extended_request).is_ok() {
        return Err("extended fragment request was accepted".to_owned());
    }
    let mut corrupted_request = fragment_request.clone();
    corrupted_request[FRAGMENT_PAYLOAD - 1] ^= 1;
    if fragment_ack_for_request(&corrupted_request).is_ok() {
        return Err("corrupted fragment request was accepted".to_owned());
    }
    if fragment_ack_sequence(&expected_ack[..FRAGMENT_ACK_LEN - 1]).is_ok() {
        return Err("truncated fragment ACK was accepted".to_owned());
    }
    let mut extended_ack = expected_ack.to_vec();
    extended_ack.push(0);
    if fragment_ack_sequence(&extended_ack).is_ok() {
        return Err("extended fragment ACK was accepted".to_owned());
    }
    let mut invalid_ack_tag = expected_ack;
    invalid_ack_tag[0] ^= 1;
    if fragment_ack_sequence(&invalid_ack_tag).is_ok() {
        return Err("fragment ACK with an invalid tag was accepted".to_owned());
    }
    let mut invalid_ack_request_len = expected_ack;
    invalid_ack_request_len[16..24].copy_from_slice(&((FRAGMENT_PAYLOAD - 1) as u64).to_be_bytes());
    if fragment_ack_sequence(&invalid_ack_request_len).is_ok() {
        return Err("fragment ACK with an invalid request length was accepted".to_owned());
    }
    let labels = [
        "tcp-single-flow",
        "tcp-256-flow-fairness",
        "udp-packets-per-second",
        "udp-8192-association-lookup-expiry",
        "udp-route-once",
        "fragment-reassembly-throughput",
        "wintun-ring-full-drop-rate",
    ];
    for label in labels {
        if Scenario::parse(label)?.label() != label {
            return Err("Windows TUN scenario label did not round-trip".to_owned());
        }
    }
    Ok(())
}
