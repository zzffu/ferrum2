#![forbid(unsafe_code)]

use std::env;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use ferrum2_core::{Datagram, TargetAddr};
use ferrum2_crypto::{
    Clock, MethodProfile, MethodPsk, MethodSinglePskProvider, SystemClock, SystemRandom,
};
use ferrum2_shadowsocks::{MAX_UDP_WIRE_LEN, UdpClientSession, UdpPacketScratch};

const SESSION_DATAGRAMS: usize = 3;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
const EXAMPLE_TIMEOUT: Duration = Duration::from_secs(40);

fn main() -> ExitCode {
    match run() {
        Ok(()) => {
            println!("udp_protocol_client status=PASS datagrams=3");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("udp_protocol_client status=FAIL reason={error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), &'static str> {
    let mut arguments = env::args();
    let _program = arguments.next();
    let method = parse_method(&arguments.next().ok_or("method-missing")?)?;
    let server: SocketAddr = arguments
        .next()
        .ok_or("server-missing")?
        .parse()
        .map_err(|_| "server-invalid")?;
    let target_socket: SocketAddr = arguments
        .next()
        .ok_or("target-missing")?
        .parse()
        .map_err(|_| "target-invalid")?;
    if arguments.next().is_some() {
        return Err("unexpected-argument");
    }
    if !server.is_ipv4() || target_socket.port() == 0 {
        return Err("address-unsupported");
    }

    let key_bytes: Vec<u8> = (0..method.key_bytes()).map(|value| value as u8).collect();
    let psk = MethodPsk::try_from_slice(method, &key_bytes).map_err(|_| "key-invalid")?;
    let keys = MethodSinglePskProvider::new(psk);
    let clock = SystemClock::new();
    let random = SystemRandom;
    let mut session =
        UdpClientSession::new(&keys, &random, |_| false).map_err(|_| "session-create")?;
    let target = TargetAddr::ip(target_socket).map_err(|_| "target-invalid")?;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| "socket-bind")?;
    socket.connect(server).map_err(|_| "socket-connect")?;

    let end = Instant::now()
        .checked_add(EXAMPLE_TIMEOUT)
        .ok_or("deadline-invalid")?;
    let mut scratch = UdpPacketScratch::new();
    let mut wire = vec![0_u8; MAX_UDP_WIRE_LEN];
    let mut response = vec![0_u8; MAX_UDP_WIRE_LEN];

    for sequence in 0..SESSION_DATAGRAMS {
        let payload = payload(method, sequence);
        let datagram = Datagram::new(
            target.clone(),
            BytesMut::from(payload.as_slice()),
            payload.len(),
        )
        .map_err(|_| "payload-bounds")?;
        let wire_len = session
            .encode_request(
                &clock,
                &random,
                &datagram,
                sequence,
                &mut wire,
                &mut scratch,
            )
            .map_err(|_| "request-encode")?;
        socket
            .set_write_timeout(Some(remaining(end)?))
            .map_err(|_| "write-timeout-config")?;
        let sent = socket.send(&wire[..wire_len]).map_err(|_| "request-send")?;
        if sent != wire_len {
            return Err("request-short-send");
        }

        socket
            .set_read_timeout(Some(remaining(end)?))
            .map_err(|_| "read-timeout-config")?;
        let received = socket.recv(&mut response).map_err(|_| "response-receive")?;
        let pending = session
            .prepare_response(&clock, &response[..received], &mut scratch)
            .map_err(|_| "response-open")?;
        if pending.datagram().payload() != payload {
            return Err("payload-mismatch");
        }
        if pending.datagram().target().as_socket_addr() != Some(target_socket) {
            return Err("source-address-mismatch");
        }
        let (_datagram, commit) = pending.into_parts();
        session
            .commit_response(commit, clock.monotonic_now())
            .map_err(|_| "response-commit")?;
    }
    Ok(())
}

fn parse_method(value: &str) -> Result<MethodProfile, &'static str> {
    match value {
        "2022-blake3-aes-128-gcm" => Ok(MethodProfile::Blake3Aes128Gcm2022),
        "2022-blake3-aes-256-gcm" => Ok(MethodProfile::Blake3Aes256Gcm2022),
        "2022-blake3-chacha20-poly1305" => Ok(MethodProfile::Blake3ChaCha20Poly13052022),
        _ => Err("method-unsupported"),
    }
}

fn payload(method: MethodProfile, sequence: usize) -> Vec<u8> {
    format!(
        "m2-udp-{}-datagram-{sequence}",
        match method {
            MethodProfile::Blake3Aes128Gcm2022 => "aes128",
            MethodProfile::Blake3Aes256Gcm2022 => "aes256",
            MethodProfile::Blake3ChaCha20Poly13052022 => "chacha",
        }
    )
    .into_bytes()
}

fn remaining(end: Instant) -> Result<Duration, &'static str> {
    end.checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| remaining.min(OPERATION_TIMEOUT))
        .ok_or("deadline-exceeded")
}
