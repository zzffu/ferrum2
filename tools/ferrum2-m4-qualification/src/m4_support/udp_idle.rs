use super::*;

use ferrum2_crypto::{
    Clock, MethodProfile, MethodPsk, MethodSinglePskProvider, SystemClock, SystemRandom,
};
use ferrum2_shadowsocks::{MAX_UDP_WIRE_LEN, UdpClientSession, UdpPacketScratch};
use serde::Serialize;

pub(super) const PAYLOAD_BYTES: usize = 128;
const SESSIONS: usize = 4_096;
const SETUP_DEADLINE: Duration = Duration::from_secs(20);
const SETUP_SCHEDULE_LEAD: Duration = Duration::from_millis(500);
const SETUP_SEND_SPACING: Duration = Duration::from_millis(2);
const ACTIVE_ELAPSED_SLACK: Duration = Duration::from_millis(250);
const IDLE_TIMEOUT_MILLISECONDS: u64 = 60_000;
const SERVER_MAX_BUFFERED_BYTES: usize = 256 * 1024 * 1024;
const UDP_IDLE_SCHEMA_VERSION: u8 = 1;
const FRAME_MAGIC: [u8; 8] = *b"F2IDLE01";
const METRICS_STABLE_OBSERVATIONS: usize = 3;

#[derive(Serialize)]
struct UdpIdleEvidence {
    schema_version: u8,
    recipe: UdpIdleRecipe,
    correctness: UdpIdleCorrectness,
    cpu: UdpIdleCpu,
    resource: UdpIdleResource,
}

#[derive(Serialize)]
struct UdpIdleRecipe {
    sessions: u64,
    setup_workers: u64,
    payload_bytes: u64,
    setup_deadline_seconds: u64,
    setup_schedule_lead_milliseconds: u64,
    setup_send_spacing_microseconds: u64,
    warmup_seconds: u64,
    active_seconds: u64,
    active_elapsed_maximum_slack_milliseconds: u64,
    idle_timeout_milliseconds: u64,
    drain_timeout_seconds: u64,
    server_max_buffered_bytes: u64,
    measurement_process: &'static str,
    traffic_path: &'static str,
}

#[derive(Serialize)]
struct UdpIdleCorrectness {
    requests_sent: u64,
    target_echoed: u64,
    responses_validated: u64,
    generator_workers_joined: u64,
    retained_sessions: u64,
    server_active_before: u64,
    server_active_after: u64,
    server_active_drained: u64,
    server_buffered_before: u64,
    server_buffered_after: u64,
    server_buffered_drained: u64,
    accepted_client_to_target: u64,
    completed_target_to_client: u64,
    drain: &'static str,
    rebind: &'static str,
    cleanup: &'static str,
}

#[derive(Serialize)]
struct UdpIdleCpu {
    process_start_time_ticks: u64,
    start_ticks: u64,
    end_ticks: u64,
    delta_ticks: u64,
    clock_ticks_per_second: u64,
    elapsed_nanoseconds: u64,
}

#[derive(Serialize)]
struct UdpIdleResource {
    setup_elapsed_nanoseconds: u64,
    pre_load: UdpIdleSample,
    established: UdpIdleSample,
    after_idle_window: UdpIdleSample,
    drained: UdpIdleSample,
}

#[derive(Clone, Copy, Serialize)]
struct UdpIdleSample {
    active_sessions: u64,
    buffered_bytes: u64,
    fds: u64,
    tasks: u64,
    rss_kib: u64,
    smaps_rss_kib: u64,
    anonymous_kib: u64,
    anon_huge_pages_kib: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UdpMetrics {
    active_sessions: u64,
    buffered_bytes: u64,
    accepted_client_to_target: u64,
    completed_target_to_client: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CpuSnapshot {
    ticks: u64,
    process_start_time_ticks: u64,
}

struct HeldSession {
    _socket: UdpSocket,
    _protocol: UdpClientSession,
}

struct EchoTarget {
    address: SocketAddrV4,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<u64, String>>>,
}

impl EchoTarget {
    fn start(deadline: Instant) -> Result<Self, String> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
        let address = v4(socket.local_addr().map_err(clean_io)?)?;
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(clean_io)?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = spawn_worker(move || {
            let mut seen = vec![false; SESSIONS];
            let mut payload = [0_u8; MAX_UDP_WIRE_LEN];
            let mut echoed = 0_usize;
            while echoed < SESSIONS {
                if worker_stop.load(Ordering::SeqCst) {
                    return Err("UDP idle echo target was cancelled".to_owned());
                }
                if Instant::now() >= deadline {
                    return Err("UDP idle echo target exceeded the setup deadline".to_owned());
                }
                let (length, peer) = match socket.recv_from(&mut payload) {
                    Ok(received) => received,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => return Err(clean_io(error)),
                };
                let index = validate_payload(&payload[..length])?;
                if std::mem::replace(&mut seen[index], true) {
                    return Err("UDP idle echo target observed a duplicate session".to_owned());
                }
                let sent = socket.send_to(&payload[..length], peer).map_err(clean_io)?;
                if sent != length {
                    return Err("UDP idle echo target short-sent a response".to_owned());
                }
                echoed += 1;
            }
            u64::try_from(echoed).map_err(|_| "UDP idle echo count overflow".to_owned())
        })?;
        Ok(Self {
            address,
            stop,
            worker: Some(worker),
        })
    }

    fn finish(mut self) -> Result<u64, String> {
        let worker = self
            .worker
            .take()
            .ok_or_else(|| "UDP idle echo target was already joined".to_owned())?;
        join_worker(worker)?
    }
}

impl Drop for EchoTarget {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct Completed {
    target_echoed: u64,
    setup_elapsed: Duration,
    pre_load: UdpIdleSample,
    established: UdpIdleSample,
    after_idle: UdpIdleSample,
    drained: UdpIdleSample,
    after_metrics: UdpMetrics,
    cpu_start: CpuSnapshot,
    cpu_end: CpuSnapshot,
    cpu_elapsed: Duration,
    clock_ticks_per_second: u64,
}

fn payload(index: usize) -> [u8; PAYLOAD_BYTES] {
    let mut value = [0_u8; PAYLOAD_BYTES];
    value[..FRAME_MAGIC.len()].copy_from_slice(&FRAME_MAGIC);
    value[8..12].copy_from_slice(&(index as u32).to_be_bytes());
    value[12..16].copy_from_slice((!(index as u32)).to_be_bytes().as_slice());
    for (offset, byte) in value[16..].iter_mut().enumerate() {
        *byte = ((index.wrapping_mul(31).wrapping_add(offset)) % 251) as u8;
    }
    value
}

fn validate_payload(value: &[u8]) -> Result<usize, String> {
    if value.len() != PAYLOAD_BYTES || value[..8] != FRAME_MAGIC {
        return Err("UDP idle target received a malformed payload".to_owned());
    }
    let index = u32::from_be_bytes(
        value[8..12]
            .try_into()
            .map_err(|_| "UDP idle payload index is malformed".to_owned())?,
    ) as usize;
    let inverse = u32::from_be_bytes(
        value[12..16]
            .try_into()
            .map_err(|_| "UDP idle payload inverse is malformed".to_owned())?,
    );
    if index >= SESSIONS || inverse != !(index as u32) || value != payload(index) {
        return Err("UDP idle target received the wrong payload".to_owned());
    }
    Ok(index)
}

fn establish_one(
    index: usize,
    keys: &MethodSinglePskProvider,
    server: SocketAddrV4,
    target_address: SocketAddrV4,
    target: &TargetAddr,
    send_not_before: Instant,
    deadline: Instant,
) -> Result<HeldSession, String> {
    let random = SystemRandom;
    let clock = SystemClock::new();
    let mut protocol = UdpClientSession::new(keys, &random, |_| false)
        .map_err(|_| "UDP idle protocol session creation failed".to_owned())?;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
    socket.connect(server).map_err(clean_io)?;
    let mut scratch = UdpPacketScratch::new();
    let mut request = [0_u8; MAX_UDP_WIRE_LEN];
    let expected = payload(index);
    sleep_until(send_not_before);
    let request_length = protocol
        .encode_request_parts(
            &clock,
            &random,
            target,
            &expected,
            0,
            &mut request,
            &mut scratch,
        )
        .map_err(|_| "UDP idle request encoding failed".to_owned())?;
    socket
        .set_write_timeout(Some(remaining(deadline)?.min(IO_TIMEOUT)))
        .map_err(clean_io)?;
    if socket.send(&request[..request_length]).map_err(clean_io)? != request_length {
        return Err("UDP idle request was short-sent".to_owned());
    }
    let mut response = [0_u8; MAX_UDP_WIRE_LEN];
    socket
        .set_read_timeout(Some(remaining(deadline)?.min(IO_TIMEOUT)))
        .map_err(clean_io)?;
    let response_length = socket.recv(&mut response).map_err(clean_io)?;
    let pending = protocol
        .prepare_response(&clock, &response[..response_length], &mut scratch)
        .map_err(|_| "UDP idle response authentication failed".to_owned())?;
    if pending.datagram().payload() != expected
        || pending.datagram().target().as_socket_addr() != Some(SocketAddr::V4(target_address))
    {
        return Err("UDP idle response validation failed".to_owned());
    }
    let (_datagram, commit) = pending.into_parts();
    protocol
        .commit_response(commit, clock.monotonic_now())
        .map_err(|_| "UDP idle response commit failed".to_owned())?;
    Ok(HeldSession {
        _socket: socket,
        _protocol: protocol,
    })
}

fn establish_sessions(
    server: SocketAddrV4,
    target_address: SocketAddrV4,
    deadline: Instant,
) -> Result<(Vec<HeldSession>, u64), String> {
    let method = MethodProfile::Blake3Aes128Gcm2022;
    let key_bytes: Vec<u8> = (0..method.key_bytes()).map(|value| value as u8).collect();
    let psk = MethodPsk::try_from_slice(method, &key_bytes)
        .map_err(|_| "UDP idle test PSK is invalid".to_owned())?;
    let keys = Arc::new(MethodSinglePskProvider::new(psk));
    let target = Arc::new(
        TargetAddr::ip(SocketAddr::V4(target_address))
            .map_err(|_| "UDP idle target address is invalid".to_owned())?,
    );
    let cancelled = Arc::new(AtomicBool::new(false));
    let setup_schedule_start = Arc::new(OnceLock::new());
    let mut workers = Vec::with_capacity(SETUP_WORKERS);
    for worker_index in 0..SETUP_WORKERS {
        let keys = Arc::clone(&keys);
        let target = Arc::clone(&target);
        let worker_cancelled = Arc::clone(&cancelled);
        let worker_schedule_start = Arc::clone(&setup_schedule_start);
        let worker = spawn_worker(move || {
            let mut sessions = Vec::with_capacity(SESSIONS.div_ceil(SETUP_WORKERS));
            let schedule_start = loop {
                if worker_cancelled.load(Ordering::SeqCst) {
                    return Err("UDP idle setup was cancelled".to_owned());
                }
                if let Some(start) = worker_schedule_start.get() {
                    break *start;
                }
                thread::sleep(Duration::from_millis(1));
            };
            for index in (worker_index..SESSIONS).step_by(SETUP_WORKERS) {
                if worker_cancelled.load(Ordering::SeqCst) {
                    return Err("UDP idle setup was cancelled".to_owned());
                }
                let send_not_before = schedule_start
                    + SETUP_SEND_SPACING
                        .checked_mul(index as u32)
                        .ok_or_else(|| "UDP idle setup schedule overflow".to_owned())?;
                match establish_one(
                    index,
                    &keys,
                    server,
                    target_address,
                    &target,
                    send_not_before,
                    deadline,
                ) {
                    Ok(session) => sessions.push(session),
                    Err(error) => {
                        worker_cancelled.store(true, Ordering::SeqCst);
                        return Err(format!("UDP idle session {index} failed: {error}"));
                    }
                }
            }
            Ok(sessions)
        });
        match worker {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                cancelled.store(true, Ordering::SeqCst);
                let _ = setup_schedule_start.set(Instant::now());
                for worker in workers {
                    let _ = join_worker(worker);
                }
                return Err(error);
            }
        }
    }
    // Release all workers onto one global schedule. Each session still sends exactly
    // once: pacing avoids loopback UDP burst loss without hiding it behind retries.
    setup_schedule_start
        .set(Instant::now() + SETUP_SCHEDULE_LEAD)
        .map_err(|_| "UDP idle setup schedule was already released".to_owned())?;
    let mut sessions = Vec::with_capacity(SESSIONS);
    let mut joined = 0_u64;
    let mut first_error = None;
    for worker in workers {
        match join_worker(worker).and_then(|result| result) {
            Ok(mut owned) => {
                sessions.append(&mut owned);
                joined += 1;
            }
            Err(error) => {
                cancelled.store(true, Ordering::SeqCst);
                first_error.get_or_insert(error);
            }
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    if sessions.len() != SESSIONS || joined != SETUP_WORKERS as u64 {
        return Err("UDP idle setup ownership accounting is incomplete".to_owned());
    }
    remaining(deadline)?;
    Ok((sessions, joined))
}

fn server_config(listen: SocketAddrV4, metrics: SocketAddrV4) -> String {
    format!(
        "schema_version = 1\n[server]\nlisten = \"{listen}\"\n\
         [shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{PSK}\"\n\
         [runtime]\nmax_connections = 128\nidle_timeout_ms = {IDLE_TIMEOUT_MILLISECONDS}\n\
         [udp]\nenabled = true\nmax_sessions = {SESSIONS}\n\
         max_buffered_bytes = {SERVER_MAX_BUFFERED_BYTES}\n\
         idle_timeout_ms = {IDLE_TIMEOUT_MILLISECONDS}\n\
         [logging]\nlevel = \"error\"\n[metrics]\nlisten = \"{metrics}\"\n"
    )
}

fn metrics_snapshot(address: SocketAddrV4, deadline: Instant) -> Result<UdpMetrics, String> {
    let timeout = remaining(deadline)?.min(IO_TIMEOUT);
    let mut stream = TcpStream::connect_timeout(&SocketAddr::V4(address), timeout)
        .map_err(|_| "UDP idle metrics connection failed".to_owned())?;
    stream
        .set_write_timeout(Some(remaining(deadline)?.min(IO_TIMEOUT)))
        .map_err(clean_io)?;
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .map_err(clean_io)?;
    let mut response = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    loop {
        if response.len() >= 256 * 1024 {
            return Err("UDP idle metrics response exceeded its bound".to_owned());
        }
        stream
            .set_read_timeout(Some(remaining(deadline)?.min(IO_TIMEOUT)))
            .map_err(clean_io)?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(error) => return Err(clean_io(error)),
        }
    }
    let value = parse_metrics_response(&response)?;
    remaining(deadline)?;
    Ok(value)
}

fn parse_metrics_response(response: &[u8]) -> Result<UdpMetrics, String> {
    const ACTIVE: &str = "ferrum2_udp_sessions_active{role=\"server\"}";
    const BUFFERED: &str = "ferrum2_udp_buffered_bytes{role=\"server\"}";
    const CLIENT_TO_TARGET: &str = "ferrum2_udp_datagrams_total{role=\"server\",direction=\"client_to_target\",outcome=\"accepted\"}";
    const TARGET_TO_CLIENT: &str = "ferrum2_udp_datagrams_total{role=\"server\",direction=\"target_to_client\",outcome=\"completed\"}";

    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "UDP idle metrics response is malformed".to_owned())?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| "UDP idle metrics response is malformed".to_owned())?;
    let mut status = headers
        .lines()
        .next()
        .ok_or_else(|| "UDP idle metrics response is malformed".to_owned())?
        .split_whitespace();
    if !status
        .next()
        .is_some_and(|value| value.starts_with("HTTP/"))
        || status.next() != Some("200")
    {
        return Err("UDP idle metrics response status is not 200".to_owned());
    }
    let body = std::str::from_utf8(&response[header_end + 4..])
        .map_err(|_| "UDP idle metrics body is not UTF-8".to_owned())?;
    if !body.ends_with("# EOF\n") || body.lines().filter(|line| *line == "# EOF").count() != 1 {
        return Err("UDP idle metrics exposition is incomplete".to_owned());
    }
    let mut active = None;
    let mut buffered = None;
    let mut client_to_target = None;
    let mut target_to_client = None;
    for line in body.lines().filter(|line| !line.starts_with('#')) {
        let Some((name, raw_value)) = line.split_once(' ') else {
            continue;
        };
        let slot = match name {
            ACTIVE => Some(&mut active),
            BUFFERED => Some(&mut buffered),
            CLIENT_TO_TARGET => Some(&mut client_to_target),
            TARGET_TO_CLIENT => Some(&mut target_to_client),
            _ => None,
        };
        if let Some(slot) = slot {
            if slot.is_some() {
                return Err("UDP idle metrics sample is duplicated".to_owned());
            }
            *slot = Some(
                raw_value
                    .parse::<u64>()
                    .map_err(|_| "UDP idle metrics sample is malformed".to_owned())?,
            );
        }
    }
    Ok(UdpMetrics {
        active_sessions: active
            .ok_or_else(|| "UDP idle active-session metric is absent".to_owned())?,
        buffered_bytes: buffered
            .ok_or_else(|| "UDP idle buffered-byte metric is absent".to_owned())?,
        accepted_client_to_target: client_to_target.unwrap_or(0),
        completed_target_to_client: target_to_client.unwrap_or(0),
    })
}

fn metrics_match(
    actual: UdpMetrics,
    expected_active: u64,
    expected_buffered: Option<u64>,
    expect_traffic: bool,
) -> bool {
    actual.active_sessions == expected_active
        && expected_buffered.map_or(actual.buffered_bytes > 0, |expected| {
            actual.buffered_bytes == expected
        })
        && actual.accepted_client_to_target == if expect_traffic { SESSIONS as u64 } else { 0 }
        && actual.completed_target_to_client == if expect_traffic { SESSIONS as u64 } else { 0 }
}

fn wait_metrics(
    process: &mut ProcessGuard,
    address: SocketAddrV4,
    expected_active: u64,
    expected_buffered: Option<u64>,
    expect_traffic: bool,
    deadline: Instant,
) -> Result<UdpMetrics, String> {
    let mut stable = 0;
    let mut previous = None;
    loop {
        process.ensure_running()?;
        let last = metrics_snapshot(address, deadline)?;
        if metrics_match(last, expected_active, expected_buffered, expect_traffic) {
            if previous == Some(last) {
                stable += 1;
            } else {
                stable = 1;
                previous = Some(last);
            }
            if stable == METRICS_STABLE_OBSERVATIONS {
                return Ok(last);
            }
        } else {
            stable = 0;
            previous = None;
        }
        thread::sleep(remaining(deadline)?.min(Duration::from_millis(100)));
    }
}

fn observe(pid: u32, metrics: UdpMetrics) -> Result<UdpIdleSample, String> {
    let process = proc_sample(pid)?;
    Ok(UdpIdleSample {
        active_sessions: metrics.active_sessions,
        buffered_bytes: metrics.buffered_bytes,
        fds: process.fds,
        tasks: process.tasks,
        rss_kib: process.rss_kib,
        smaps_rss_kib: process.smaps_rss_kib,
        anonymous_kib: process.anonymous_kib,
        anon_huge_pages_kib: process.anon_huge_pages_kib,
    })
}

fn parse_proc_stat(value: &str) -> Result<CpuSnapshot, String> {
    let end = value
        .rfind(") ")
        .ok_or_else(|| "UDP idle process CPU state is malformed".to_owned())?;
    let fields: Vec<_> = value[end + 2..].split_whitespace().collect();
    if fields.len() < 20 {
        return Err("UDP idle process CPU state is incomplete".to_owned());
    }
    let parse = |index: usize| {
        fields[index]
            .parse::<u64>()
            .map_err(|_| "UDP idle process CPU state is malformed".to_owned())
    };
    Ok(CpuSnapshot {
        ticks: parse(11)?
            .checked_add(parse(12)?)
            .ok_or_else(|| "UDP idle process CPU ticks overflow".to_owned())?,
        process_start_time_ticks: parse(19)?,
    })
}

fn process_cpu(pid: u32) -> Result<CpuSnapshot, String> {
    let value = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| "UDP idle process CPU state is unavailable".to_owned())?;
    parse_proc_stat(&value)
}

fn clock_ticks_per_second() -> Result<u64, String> {
    let value = first_line(&probe_text(
        "UDP idle clock-tick probe",
        "getconf",
        ["CLK_TCK"],
        PROBE_TIMEOUT,
    )?);
    value
        .parse::<u64>()
        .ok()
        .filter(|ticks| *ticks > 0)
        .ok_or_else(|| "UDP idle clock-tick probe is malformed".to_owned())
}

fn sleep_until(deadline: Instant) {
    while let Some(delay) = deadline.checked_duration_since(Instant::now()) {
        if delay.is_zero() {
            break;
        }
        thread::sleep(delay);
    }
}

fn build_outcome(arguments: &ProfileArgs, completed: Completed) -> Result<ProfileOutcome, String> {
    if completed.cpu_start.process_start_time_ticks != completed.cpu_end.process_start_time_ticks {
        return Err("UDP idle measured process identity changed".to_owned());
    }
    let delta_ticks = completed
        .cpu_end
        .ticks
        .checked_sub(completed.cpu_start.ticks)
        .ok_or_else(|| "UDP idle process CPU ticks moved backwards".to_owned())?;
    let elapsed_nanoseconds = u64::try_from(completed.cpu_elapsed.as_nanos())
        .map_err(|_| "UDP idle elapsed time exceeds u64".to_owned())?;
    let minimum_elapsed = Duration::from_secs(arguments.active_seconds);
    if completed.cpu_elapsed < minimum_elapsed
        || completed.cpu_elapsed > minimum_elapsed + ACTIVE_ELAPSED_SLACK
    {
        return Err("UDP idle CPU window elapsed time is outside its strict bound".to_owned());
    }
    let setup_elapsed_nanoseconds = u64::try_from(completed.setup_elapsed.as_nanos())
        .map_err(|_| "UDP idle setup elapsed time exceeds u64".to_owned())?;
    let evidence = UdpIdleEvidence {
        schema_version: UDP_IDLE_SCHEMA_VERSION,
        recipe: UdpIdleRecipe {
            sessions: SESSIONS as u64,
            setup_workers: SETUP_WORKERS as u64,
            payload_bytes: PAYLOAD_BYTES as u64,
            setup_deadline_seconds: SETUP_DEADLINE.as_secs(),
            setup_schedule_lead_milliseconds: SETUP_SCHEDULE_LEAD.as_millis() as u64,
            setup_send_spacing_microseconds: SETUP_SEND_SPACING.as_micros() as u64,
            warmup_seconds: arguments.warmup_seconds,
            active_seconds: arguments.active_seconds,
            active_elapsed_maximum_slack_milliseconds: ACTIVE_ELAPSED_SLACK.as_millis() as u64,
            idle_timeout_milliseconds: IDLE_TIMEOUT_MILLISECONDS,
            drain_timeout_seconds: DRAIN_TIMEOUT.as_secs(),
            server_max_buffered_bytes: SERVER_MAX_BUFFERED_BYTES as u64,
            measurement_process: "ferrum2-server",
            traffic_path: "loopback-direct-sip022-server",
        },
        correctness: UdpIdleCorrectness {
            requests_sent: SESSIONS as u64,
            target_echoed: completed.target_echoed,
            responses_validated: SESSIONS as u64,
            generator_workers_joined: SETUP_WORKERS as u64,
            retained_sessions: SESSIONS as u64,
            server_active_before: completed.pre_load.active_sessions,
            server_active_after: completed.after_metrics.active_sessions,
            server_active_drained: completed.drained.active_sessions,
            server_buffered_before: completed.pre_load.buffered_bytes,
            server_buffered_after: completed.after_metrics.buffered_bytes,
            server_buffered_drained: completed.drained.buffered_bytes,
            accepted_client_to_target: completed.after_metrics.accepted_client_to_target,
            completed_target_to_client: completed.after_metrics.completed_target_to_client,
            drain: "PASS",
            rebind: "PASS",
            cleanup: "PASS",
        },
        cpu: UdpIdleCpu {
            process_start_time_ticks: completed.cpu_start.process_start_time_ticks,
            start_ticks: completed.cpu_start.ticks,
            end_ticks: completed.cpu_end.ticks,
            delta_ticks,
            clock_ticks_per_second: completed.clock_ticks_per_second,
            elapsed_nanoseconds,
        },
        resource: UdpIdleResource {
            setup_elapsed_nanoseconds,
            pre_load: completed.pre_load,
            established: completed.established,
            after_idle_window: completed.after_idle,
            drained: completed.drained,
        },
    };
    let udp_idle_json = serde_json::to_string(&evidence)
        .map_err(|_| "UDP idle evidence could not be encoded".to_owned())?;
    if udp_idle_json.len() + 4_096 > EVIDENCE_LINE_MAX_BYTES {
        return Err("UDP idle evidence exceeds its bounded trial envelope".to_owned());
    }
    Ok(ProfileOutcome {
        summary: format!(
            "m18_profile_workload_completion status=PASS scenario=udp-idle-4096 \
             sessions={SESSIONS} cpu_ticks={delta_ticks} elapsed_nanoseconds={elapsed_nanoseconds} \
             drain=PASS rebind=PASS"
        ),
        metric: "server_cpu_ticks",
        value: delta_ticks,
        checked_units: SESSIONS as u64,
        p99_nanoseconds: None,
        io_completions: (SESSIONS as u64) * 2,
        scale_json: None,
        udp_idle_json: Some(udp_idle_json),
    })
}

pub(super) fn run(arguments: &ProfileArgs, ready_file: &Path) -> Result<ProfileOutcome, String> {
    if arguments.warmup_seconds != 3 || arguments.active_seconds != 30 {
        return Err("udp-idle-4096 requires the fixed 3/30 second recipe".to_owned());
    }
    let clock_ticks = clock_ticks_per_second()?;
    let mut directory = Some(
        tempfile::Builder::new()
            .prefix("profile-udp-idle-")
            .tempdir()
            .map_err(clean_io)?,
    );
    let mut server_reservation = Some(TcpUdpReservation::new()?);
    let mut metrics_reservation = Some(PortReservation::new()?);
    let server_address = server_reservation
        .as_ref()
        .expect("UDP idle server reservation")
        .address;
    let metrics_address = metrics_reservation
        .as_ref()
        .expect("UDP idle metrics reservation")
        .address;
    let server_config_path = directory
        .as_ref()
        .expect("UDP idle directory")
        .path()
        .join("server.toml");
    let echo_deadline = Instant::now() + STARTUP_TIMEOUT + SETUP_DEADLINE + IO_TIMEOUT;
    let mut echo_target = Some(EchoTarget::start(echo_deadline)?);
    let target_address = echo_target.as_ref().expect("UDP idle target").address;
    let mut server_process = None;
    let mut ready = None;
    let mut held_sessions = None;
    let mut completed = None;
    let mut errors = Vec::new();

    let execution = (|| -> Result<(), String> {
        fs::write(
            &server_config_path,
            server_config(server_address, metrics_address),
        )
        .map_err(clean_io)?;
        server_reservation
            .take()
            .expect("UDP idle server reservation")
            .release();
        metrics_reservation
            .take()
            .expect("UDP idle metrics reservation")
            .release();
        server_process = Some(spawn_proxy(
            Topology::Ferrum,
            "UDP idle server",
            &profile_binary(&arguments.binary_dir, "ferrum2-server")?,
            &server_config_path,
        )?);
        wait_for_metrics(
            server_process.as_mut().expect("UDP idle server"),
            metrics_address,
        )?;
        let pre_metrics = wait_metrics(
            server_process.as_mut().expect("UDP idle server"),
            metrics_address,
            0,
            None,
            false,
            Instant::now() + IO_TIMEOUT,
        )?;
        let pre_load = observe(
            server_process.as_ref().expect("UDP idle server").id(),
            pre_metrics,
        )?;

        let setup_started = Instant::now();
        let setup_deadline = setup_started + SETUP_DEADLINE;
        let (sessions, joined) =
            establish_sessions(server_address, target_address, setup_deadline)?;
        if joined != SETUP_WORKERS as u64 {
            return Err("UDP idle generator worker accounting is incomplete".to_owned());
        }
        held_sessions = Some(sessions);
        let target_echoed = echo_target.take().expect("UDP idle echo target").finish()?;
        if target_echoed != SESSIONS as u64 {
            return Err("UDP idle echo target count is incomplete".to_owned());
        }
        // The bound pre-event counterfactual already allocates receive storage only
        // after readiness. Requiring the root buffer baseline here keeps this CPU
        // qualification isolated to the 50 ms full reconcile removal.
        let established_metrics = wait_metrics(
            server_process.as_mut().expect("UDP idle server"),
            metrics_address,
            SESSIONS as u64,
            Some(pre_metrics.buffered_bytes),
            true,
            setup_deadline,
        )?;
        let setup_elapsed = setup_started.elapsed();
        if setup_elapsed > SETUP_DEADLINE {
            return Err("UDP idle session setup exceeded 20 seconds".to_owned());
        }
        let established = observe(
            server_process.as_ref().expect("UDP idle server").id(),
            established_metrics,
        )?;
        let expected_established_fds = pre_load
            .fds
            .checked_add(SESSIONS as u64)
            .ok_or_else(|| "UDP idle established descriptor count overflow".to_owned())?;
        if established.fds != expected_established_fds {
            return Err("UDP idle established descriptor count is incomplete".to_owned());
        }
        ready = Some(ReadyFile::publish(
            ready_file,
            arguments.scenario,
            None,
            Some(server_process.as_ref().expect("UDP idle server").id()),
            arguments.warmup_seconds,
            arguments.active_seconds,
        )?);

        let warmup_deadline = Instant::now() + Duration::from_secs(arguments.warmup_seconds);
        sleep_until(warmup_deadline);
        server_process
            .as_mut()
            .expect("UDP idle server")
            .ensure_running()?;
        let cpu_start = process_cpu(server_process.as_ref().expect("UDP idle server").id())?;
        let cpu_started = Instant::now();
        sleep_until(cpu_started + Duration::from_secs(arguments.active_seconds));
        let cpu_end = process_cpu(server_process.as_ref().expect("UDP idle server").id())?;
        let cpu_elapsed = cpu_started.elapsed();
        server_process
            .as_mut()
            .expect("UDP idle server")
            .ensure_running()?;
        let after_metrics = wait_metrics(
            server_process.as_mut().expect("UDP idle server"),
            metrics_address,
            SESSIONS as u64,
            Some(established_metrics.buffered_bytes),
            true,
            Instant::now() + IO_TIMEOUT,
        )?;
        let after_idle = observe(
            server_process.as_ref().expect("UDP idle server").id(),
            after_metrics,
        )?;
        if after_idle.fds != established.fds || after_idle.tasks != established.tasks {
            return Err("UDP idle resources changed during the CPU window".to_owned());
        }
        ready.take().expect("UDP idle ready owner").remove()?;
        drop(held_sessions.take());

        let drain_deadline = Instant::now() + DRAIN_TIMEOUT;
        let mut stable = 0_usize;
        let drained = loop {
            server_process
                .as_mut()
                .expect("UDP idle server")
                .ensure_running()?;
            let metrics = metrics_snapshot(metrics_address, drain_deadline)?;
            let sample = observe(
                server_process.as_ref().expect("UDP idle server").id(),
                metrics,
            )?;
            let complete = metrics_match(metrics, 0, Some(pre_metrics.buffered_bytes), true)
                && sample.fds == pre_load.fds
                && sample.tasks == pre_load.tasks;
            if complete {
                stable += 1;
                if stable == METRICS_STABLE_OBSERVATIONS {
                    break sample;
                }
            } else {
                stable = 0;
            }
            thread::sleep(remaining(drain_deadline)?.min(Duration::from_millis(100)));
        };
        completed = Some(Completed {
            target_echoed,
            setup_elapsed,
            pre_load,
            established,
            after_idle,
            drained,
            after_metrics,
            cpu_start,
            cpu_end,
            cpu_elapsed,
            clock_ticks_per_second: clock_ticks,
        });
        Ok(())
    })();
    if let Err(error) = execution {
        errors.push(error);
    }

    drop(ready.take());
    drop(held_sessions.take());
    drop(echo_target.take());
    drop(server_reservation.take());
    drop(metrics_reservation.take());
    if let Some(process) = server_process.as_mut()
        && let Err(error) = process.terminate()
    {
        errors.push(format!("UDP idle server cleanup failed: {error}"));
    }
    if let Some(directory) = directory.take()
        && let Err(error) = directory.close().map_err(clean_io)
    {
        errors.push(format!("UDP idle directory cleanup failed: {error}"));
    }
    for result in [
        prove_tcp_udp_rebind(server_address, "UDP idle server"),
        prove_tcp_rebind(metrics_address, "UDP idle metrics"),
        prove_udp_rebind(target_address, "UDP idle echo target"),
    ] {
        if let Err(error) = result {
            errors.push(error);
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    assert_no_owners()?;
    build_outcome(
        arguments,
        completed.ok_or_else(|| "UDP idle execution produced no completed evidence".to_owned())?,
    )
}

pub(super) fn self_check() -> Result<(), String> {
    let final_send_offset = SETUP_SCHEDULE_LEAD
        + SETUP_SEND_SPACING
            .checked_mul((SESSIONS - 1) as u32)
            .ok_or_else(|| "UDP idle setup schedule self-check overflow".to_owned())?;
    if final_send_offset >= SETUP_DEADLINE {
        return Err("UDP idle paced setup does not fit its deadline".to_owned());
    }
    let sample = parse_proc_stat(
        "123 (worker ) name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20",
    )?;
    if sample
        != (CpuSnapshot {
            ticks: 23,
            process_start_time_ticks: 19,
        })
    {
        return Err("UDP idle proc-stat parser self-check failed".to_owned());
    }
    for index in [0, SESSIONS / 2, SESSIONS - 1] {
        if validate_payload(&payload(index))? != index {
            return Err("UDP idle payload self-check failed".to_owned());
        }
    }
    let response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n\
# TYPE ferrum2_udp_sessions_active gauge\n\
ferrum2_udp_sessions_active{role=\"server\"} 4096\n\
# TYPE ferrum2_udp_buffered_bytes gauge\n\
ferrum2_udp_buffered_bytes{role=\"server\"} 131014\n\
ferrum2_udp_datagrams_total{role=\"server\",direction=\"client_to_target\",outcome=\"accepted\"} 4096\n\
ferrum2_udp_datagrams_total{role=\"server\",direction=\"target_to_client\",outcome=\"completed\"} 4096\n\
# EOF\n";
    let metrics = parse_metrics_response(response)?;
    if metrics.active_sessions != SESSIONS as u64
        || metrics.buffered_bytes != 131_014
        || !metrics_match(metrics, SESSIONS as u64, Some(131_014), true)
    {
        return Err("UDP idle metrics parser self-check failed".to_owned());
    }
    let config = server_config(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10001),
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10002),
    );
    if !config.contains("max_sessions = 4096\n")
        || !config.contains("max_buffered_bytes = 268435456\n")
        || !config.contains("idle_timeout_ms = 60000\n")
        || !config.contains("[metrics]\nlisten = \"127.0.0.1:10002\"\n")
    {
        return Err("UDP idle fixed recipe self-check failed".to_owned());
    }
    let maximum_sample = UdpIdleSample {
        active_sessions: u64::MAX,
        buffered_bytes: u64::MAX,
        fds: u64::MAX,
        tasks: u64::MAX,
        rss_kib: u64::MAX,
        smaps_rss_kib: u64::MAX,
        anonymous_kib: u64::MAX,
        anon_huge_pages_kib: u64::MAX,
    };
    let maximum = UdpIdleEvidence {
        schema_version: UDP_IDLE_SCHEMA_VERSION,
        recipe: UdpIdleRecipe {
            sessions: SESSIONS as u64,
            setup_workers: SETUP_WORKERS as u64,
            payload_bytes: PAYLOAD_BYTES as u64,
            setup_deadline_seconds: SETUP_DEADLINE.as_secs(),
            setup_schedule_lead_milliseconds: SETUP_SCHEDULE_LEAD.as_millis() as u64,
            setup_send_spacing_microseconds: SETUP_SEND_SPACING.as_micros() as u64,
            warmup_seconds: 3,
            active_seconds: 30,
            active_elapsed_maximum_slack_milliseconds: 250,
            idle_timeout_milliseconds: IDLE_TIMEOUT_MILLISECONDS,
            drain_timeout_seconds: DRAIN_TIMEOUT.as_secs(),
            server_max_buffered_bytes: SERVER_MAX_BUFFERED_BYTES as u64,
            measurement_process: "ferrum2-server",
            traffic_path: "loopback-direct-sip022-server",
        },
        correctness: UdpIdleCorrectness {
            requests_sent: u64::MAX,
            target_echoed: u64::MAX,
            responses_validated: u64::MAX,
            generator_workers_joined: u64::MAX,
            retained_sessions: u64::MAX,
            server_active_before: u64::MAX,
            server_active_after: u64::MAX,
            server_active_drained: u64::MAX,
            server_buffered_before: u64::MAX,
            server_buffered_after: u64::MAX,
            server_buffered_drained: u64::MAX,
            accepted_client_to_target: u64::MAX,
            completed_target_to_client: u64::MAX,
            drain: "PASS",
            rebind: "PASS",
            cleanup: "PASS",
        },
        cpu: UdpIdleCpu {
            process_start_time_ticks: u64::MAX,
            start_ticks: u64::MAX,
            end_ticks: u64::MAX,
            delta_ticks: u64::MAX,
            clock_ticks_per_second: u64::MAX,
            elapsed_nanoseconds: u64::MAX,
        },
        resource: UdpIdleResource {
            setup_elapsed_nanoseconds: u64::MAX,
            pre_load: maximum_sample,
            established: maximum_sample,
            after_idle_window: maximum_sample,
            drained: maximum_sample,
        },
    };
    let maximum_json = serde_json::to_string(&maximum)
        .map_err(|_| "UDP idle maximum evidence fixture did not encode".to_owned())?;
    if maximum_json.contains('\n') || maximum_json.len() + 4_096 > EVIDENCE_LINE_MAX_BYTES {
        return Err("UDP idle maximum evidence fixture violates its envelope".to_owned());
    }
    Ok(())
}
