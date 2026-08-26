use std::io::{self, Read, Write};
use std::net::{SocketAddrV4, TcpStream, UdpSocket};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use super::loopback::bind_loopback_listener;
use super::process::{ChildGuard, MetricsReadinessFailure};
use super::{
    ACTIVE_CHILDREN, METRICS_HEADER_CAP, METRICS_RESPONSE_CAP, READINESS_CONFIRMATIONS,
    READINESS_IO_CAP, READINESS_POLL, READINESS_TIMEOUT, contains_bytes,
};

pub fn wait_for_listener(child: &mut ChildGuard, address: SocketAddrV4) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        child.assert_running();
        if std::net::TcpStream::connect(address).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "listener readiness timed out");
        thread::sleep(Duration::from_millis(20));
    }
}

pub fn wait_for_bound(child: &mut ChildGuard, address: SocketAddrV4) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut occupied_confirmations = 0_usize;
    loop {
        child.assert_running();
        match bind_loopback_listener(address) {
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                occupied_confirmations += 1;
                if occupied_confirmations >= READINESS_CONFIRMATIONS {
                    thread::sleep(READINESS_POLL);
                    child.assert_running();
                    match bind_loopback_listener(address) {
                        Err(error) if error.kind() == io::ErrorKind::AddrInUse => return,
                        Ok(listener) => {
                            drop(listener);
                            occupied_confirmations = 0;
                        }
                        Err(error) => {
                            panic!("listener readiness confirmation failed: {error}");
                        }
                    }
                }
            }
            Ok(listener) => {
                drop(listener);
                occupied_confirmations = 0;
            }
            Err(error) => panic!("listener readiness bind probe failed: {error}"),
        }
        assert!(Instant::now() < deadline, "listener readiness timed out");
        thread::sleep(READINESS_POLL);
    }
}

pub fn wait_for_tcp_udp_bound(child: &mut ChildGuard, address: SocketAddrV4) {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    let mut occupied_confirmations = 0_usize;
    loop {
        child.assert_running();
        let tcp = bind_loopback_listener(address);
        let udp = UdpSocket::bind(address);
        match (tcp, udp) {
            (Err(tcp_error), Err(udp_error))
                if tcp_error.kind() == io::ErrorKind::AddrInUse
                    && udp_error.kind() == io::ErrorKind::AddrInUse =>
            {
                occupied_confirmations += 1;
                if occupied_confirmations >= READINESS_CONFIRMATIONS {
                    thread::sleep(READINESS_POLL);
                    child.assert_running();
                    let tcp_error =
                        bind_loopback_listener(address).expect_err("TCP readiness confirmation");
                    let udp_error =
                        UdpSocket::bind(address).expect_err("UDP readiness confirmation");
                    if tcp_error.kind() == io::ErrorKind::AddrInUse
                        && udp_error.kind() == io::ErrorKind::AddrInUse
                    {
                        return;
                    }
                    occupied_confirmations = 0;
                }
            }
            (Ok(tcp), Ok(udp)) => {
                drop((tcp, udp));
                occupied_confirmations = 0;
            }
            (Ok(tcp), Err(udp_error)) => {
                drop(tcp);
                assert_eq!(
                    udp_error.kind(),
                    io::ErrorKind::AddrInUse,
                    "UDP readiness bind probe failed: {udp_error}"
                );
                occupied_confirmations = 0;
            }
            (Err(tcp_error), Ok(udp)) => {
                drop(udp);
                assert_eq!(
                    tcp_error.kind(),
                    io::ErrorKind::AddrInUse,
                    "TCP readiness bind probe failed: {tcp_error}"
                );
                occupied_confirmations = 0;
            }
            (Err(tcp_error), Err(udp_error)) => {
                panic!("dual readiness bind probe failed: TCP={tcp_error}; UDP={udp_error}");
            }
        }
        assert!(Instant::now() < deadline, "listener readiness timed out");
        thread::sleep(READINESS_POLL);
    }
}

pub fn wait_for_metrics_ready(
    child: &mut ChildGuard,
    proxy: SocketAddrV4,
    metrics: SocketAddrV4,
) -> Result<(), MetricsReadinessFailure> {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    let identity = match child.binary.as_str() {
        "ferrum2-client" => ReadinessIdentity::Client,
        "ferrum2-server" => ReadinessIdentity::Server,
        binary => panic!("unsupported readiness binary: {binary}"),
    };
    let initial = loop {
        child
            .check_running()
            .map_err(MetricsReadinessFailure::ChildExited)?;
        if let Some(body) = fetch_ferrum_metrics(metrics, deadline) {
            break metric_value(&body, identity.failure_metric()).unwrap_or(0);
        }
        let Some(sleep) = remaining_capped(deadline, READINESS_POLL) else {
            return Err(MetricsReadinessFailure::Deadline);
        };
        thread::sleep(sleep);
    };
    if initial != 0 || !send_identity_probe(proxy, identity, deadline) {
        return Err(MetricsReadinessFailure::Deadline);
    }

    loop {
        child
            .check_running()
            .map_err(MetricsReadinessFailure::ChildExited)?;
        if fetch_ferrum_metrics(metrics, deadline)
            .and_then(|body| metric_value(&body, identity.failure_metric()))
            == Some(1)
        {
            child
                .check_running()
                .map_err(MetricsReadinessFailure::ChildExited)?;
            return Ok(());
        }
        child
            .check_running()
            .map_err(MetricsReadinessFailure::ChildExited)?;
        let Some(sleep) = remaining_capped(deadline, READINESS_POLL) else {
            return Err(MetricsReadinessFailure::Deadline);
        };
        thread::sleep(sleep);
    }
}

#[derive(Clone, Copy)]
enum ReadinessIdentity {
    Client,
    Server,
}

impl ReadinessIdentity {
    fn probe(self) -> &'static [u8] {
        match self {
            Self::Client => &[4, 1, 0],
            Self::Server => &[0xa5; 43],
        }
    }

    fn failure_metric(self) -> &'static str {
        match self {
            Self::Client => {
                "ferrum2_tcp_failures_total{role=\"client\",stage=\"socks5\",reason=\"socks_protocol\"}"
            }
            Self::Server => {
                "ferrum2_tcp_failures_total{role=\"server\",stage=\"shadowsocks\",reason=\"authentication\"}"
            }
        }
    }
}

fn send_identity_probe(
    proxy: SocketAddrV4,
    identity: ReadinessIdentity,
    deadline: Instant,
) -> bool {
    let Some(connect_timeout) = remaining_capped(deadline, READINESS_IO_CAP) else {
        return false;
    };
    let Ok(mut stream) =
        TcpStream::connect_timeout(&std::net::SocketAddr::V4(proxy), connect_timeout)
    else {
        return false;
    };
    write_before_deadline(&mut stream, identity.probe(), deadline).is_ok()
        && stream.shutdown(std::net::Shutdown::Write).is_ok()
}

fn remaining_capped(deadline: Instant, cap: Duration) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| remaining.min(cap))
}

fn fetch_ferrum_metrics(address: SocketAddrV4, deadline: Instant) -> Option<Vec<u8>> {
    let connect_timeout = remaining_capped(deadline, READINESS_IO_CAP)?;
    let mut stream =
        TcpStream::connect_timeout(&std::net::SocketAddr::V4(address), connect_timeout).ok()?;
    if write_before_deadline(
        &mut stream,
        b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n",
        deadline,
    )
    .is_err()
    {
        return None;
    }

    let mut response = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        if let Some(position) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        if response.len() >= METRICS_HEADER_CAP {
            return None;
        }
        let timeout = remaining_capped(deadline, READINESS_IO_CAP)?;
        if stream.set_read_timeout(Some(timeout)).is_err() {
            return None;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
        }
    };

    let content_length = metrics_content_length(&response[..header_end])?;
    let response_length = header_end.checked_add(content_length)?;
    if response_length > METRICS_RESPONSE_CAP {
        return None;
    }
    while response.len() < response_length {
        let timeout = remaining_capped(deadline, READINESS_IO_CAP)?;
        if stream.set_read_timeout(Some(timeout)).is_err() {
            return None;
        }
        let remaining = response_length - response.len();
        let read_length = remaining.min(chunk.len());
        match stream.read(&mut chunk[..read_length]) {
            Ok(0) | Err(_) => return None,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
        }
    }

    let body = &response[header_end..response_length];
    (contains_bytes(body, b"# HELP ferrum2_tcp_replay_entries ")
        && contains_bytes(body, b"# TYPE ferrum2_tcp_replay_entries gauge"))
    .then(|| body.to_vec())
}

pub fn wait_for_metrics(address: SocketAddrV4) -> Vec<u8> {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        if let Some(body) = fetch_ferrum_metrics(address, deadline) {
            return body;
        }
        assert!(Instant::now() < deadline, "metrics readiness timed out");
        thread::sleep(READINESS_POLL);
    }
}

pub fn wait_for_metrics_sample(address: SocketAddrV4, sample: &str) -> Vec<u8> {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        if let Some(body) = fetch_ferrum_metrics(address, deadline)
            && contains_bytes(&body, sample.as_bytes())
        {
            return body;
        }
        assert!(Instant::now() < deadline, "metrics sample timed out");
        thread::sleep(READINESS_POLL);
    }
}

fn write_before_deadline(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let timeout = remaining_capped(deadline, READINESS_IO_CAP)
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "readiness deadline"))?;
        stream.set_write_timeout(Some(timeout))?;
        match stream.write(bytes)? {
            0 => return Err(io::Error::new(io::ErrorKind::WriteZero, "metrics request")),
            written => bytes = &bytes[written..],
        }
    }
    Ok(())
}

fn metrics_content_length(header: &[u8]) -> Option<usize> {
    let header = std::str::from_utf8(header).ok()?;
    let mut lines = header.split("\r\n");
    if lines.next()? != "HTTP/1.1 200 OK" {
        return None;
    }
    let mut content_type = false;
    let mut connection_close = false;
    let mut content_length = None;
    for line in lines {
        if line == "Content-Type: text/plain; version=0.0.4" {
            content_type = true;
        } else if line == "Connection: close" {
            connection_close = true;
        } else if let Some(value) = line.strip_prefix("Content-Length: ") {
            content_length = value.parse().ok();
        }
    }
    (content_type && connection_close)
        .then_some(content_length)
        .flatten()
}

pub(crate) fn metric_value(body: &[u8], metric: &str) -> Option<u64> {
    let body = std::str::from_utf8(body).ok()?;
    body.lines().find_map(|line| {
        let (name, value) = line.rsplit_once(' ')?;
        (name == metric).then(|| value.parse().ok()).flatten()
    })
}

pub fn active_child_count() -> usize {
    ACTIVE_CHILDREN.load(Ordering::SeqCst)
}
