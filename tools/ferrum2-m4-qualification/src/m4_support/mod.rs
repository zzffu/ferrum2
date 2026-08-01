#![allow(dead_code)]

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const PROFILE: &str = "M4-GHA-01";
const PSK: &str = "AAECAwQFBgcICQoLDA0ODw==";
const REFERENCE_VERSION: &str = "shadowsocks 1.24.0";
const REFERENCE_SHA256: &str = "5f528efb4e51e732352f5c69538dcc76e8cf8f6d1a240dfb5b748a67f0b05f65";
const STREAMS: usize = 8;
const PAYLOAD_BYTES: usize = 64 * 1024;
const WARMUP: Duration = Duration::from_secs(10);
const MEASURE: Duration = Duration::from_secs(30);
const TRIALS: [Topology; 10] = [
    Topology::Ferrum,
    Topology::Reference,
    Topology::Reference,
    Topology::Ferrum,
    Topology::Ferrum,
    Topology::Reference,
    Topology::Reference,
    Topology::Ferrum,
    Topology::Ferrum,
    Topology::Reference,
];
const RESOURCE_SESSIONS: usize = 10_000;
const SETUP_WORKERS: usize = 256;
const STABILIZATION_SAMPLES: usize = 30;
const RESOURCE_SAMPLES: usize = 180;
const SAMPLE_INTERVAL: Duration = Duration::from_secs(10);
const RSS_WINDOW: usize = 30;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(120);
const PROCESS_OUTPUT_CAP: usize = 64 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const REAP_TIMEOUT: Duration = Duration::from_secs(5);

static ACTIVE_PROCESSES: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_WORKERS: AtomicUsize = AtomicUsize::new(0);

pub fn run(arguments: impl Iterator<Item = OsString>) -> Result<String, String> {
    let mut arguments = arguments;
    let mode = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| "expected mode: throughput, resource, or self-check".to_owned())?;
    let rest: Vec<_> = arguments.collect();
    match mode.as_str() {
        "throughput" => run_throughput(parse_hosted_args(&rest, true)?),
        "resource" => run_resource(parse_hosted_args(&rest, false)?),
        "self-check" if rest.is_empty() => run_self_check(),
        "self-check" => Err("self-check accepts no arguments".to_owned()),
        _ => Err("expected mode: throughput, resource, or self-check".to_owned()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Topology {
    Ferrum,
    Reference,
}

impl Topology {
    const fn label(self) -> &'static str {
        match self {
            Self::Ferrum => "ferrum",
            Self::Reference => "reference",
        }
    }
}

struct HostedArgs {
    sha: String,
    output: PathBuf,
    sslocal: Option<PathBuf>,
    ssserver: Option<PathBuf>,
}

fn parse_hosted_args(arguments: &[OsString], reference: bool) -> Result<HostedArgs, String> {
    let mut sha = None;
    let mut output = None;
    let mut sslocal = None;
    let mut ssserver = None;
    let mut chunks = arguments.chunks_exact(2);
    for pair in &mut chunks {
        let flag = pair[0]
            .to_str()
            .ok_or_else(|| "option name is not UTF-8".to_owned())?;
        let value = pair[1].clone();
        let slot = match flag {
            "--sha" => &mut sha,
            "--output" => &mut output,
            "--sslocal" if reference => &mut sslocal,
            "--ssserver" if reference => &mut ssserver,
            _ => return Err(format!("unsupported option: {flag}")),
        };
        if slot.replace(value).is_some() {
            return Err(format!("duplicate option: {flag}"));
        }
    }
    if !chunks.remainder().is_empty() {
        return Err("every option requires one value".to_owned());
    }
    let utf8 = |value: OsString, name: &str| {
        value
            .into_string()
            .map_err(|_| format!("{name} is not UTF-8"))
    };
    let sha = utf8(sha.ok_or_else(|| "missing --sha".to_owned())?, "SHA")?;
    let output = PathBuf::from(output.ok_or_else(|| "missing --output".to_owned())?);
    let sslocal = sslocal.map(PathBuf::from);
    let ssserver = ssserver.map(PathBuf::from);
    if reference && (sslocal.is_none() || ssserver.is_none()) {
        return Err("throughput requires --sslocal and --ssserver".to_owned());
    }
    Ok(HostedArgs {
        sha,
        output,
        sslocal,
        ssserver,
    })
}

struct HostedIdentity {
    sha: String,
    run_id: String,
    run_attempt: String,
    event: String,
    image_version: String,
    kernel: String,
    cpu_model: String,
    cpu_count: usize,
    memory_kib: u64,
    runner_temp_free_kib: u64,
    nofile_soft: u64,
    rustc: String,
    cc: String,
    linker: String,
}

impl HostedIdentity {
    fn load(requested_sha: &str, output: &Path) -> Result<Self, String> {
        let environment = EnvironmentIdentity {
            github_actions: env("GITHUB_ACTIONS")?,
            runner_os: env("RUNNER_OS")?,
            runner_arch: env("RUNNER_ARCH")?,
            image_os: env("ImageOS")?,
            github_sha: env("GITHUB_SHA")?,
        };
        validate_environment(requested_sha, &environment)?;
        let head = probe_text(
            "checkout HEAD probe",
            "git",
            ["rev-parse", "HEAD"],
            PROBE_TIMEOUT,
        )?;
        if head.trim() != requested_sha {
            return Err("checkout HEAD does not match requested SHA".to_owned());
        }
        if !probe_text(
            "checkout status probe",
            "git",
            ["status", "--porcelain=v1"],
            PROBE_TIMEOUT,
        )?
        .is_empty()
        {
            return Err("checkout is dirty before generated writes".to_owned());
        }
        validate_output_path(output)?;
        let runner_temp_free_kib = validate_temp_free(output)?;
        let cpu_count = thread::available_parallelism()
            .map_err(|_| "logical CPU count is unavailable".to_owned())?
            .get();
        let (memory_kib, cpu_model) = linux_capacity()?;
        if cpu_count < 4 || memory_kib < 15_000_000 {
            return Err("host capacity is below M4-GHA-01".to_owned());
        }
        let nofile_soft = validate_nofile()?;
        let rustc = first_line(&probe_text(
            "Rust version probe",
            "rustc",
            ["--version"],
            PROBE_TIMEOUT,
        )?);
        if !rustc.starts_with("rustc 1.97.1 ") {
            return Err("Rust toolchain is not 1.97.1".to_owned());
        }
        let event = env("GITHUB_EVENT_NAME")?;
        if event != "push" && event != "workflow_dispatch" {
            return Err("hosted event is outside the performance profile".to_owned());
        }
        let run_id = env("GITHUB_RUN_ID")?;
        let run_attempt = env("GITHUB_RUN_ATTEMPT")?;
        if run_id.parse::<u64>().is_err() || run_attempt.parse::<u64>().is_err() {
            return Err("hosted run identity is malformed".to_owned());
        }
        Ok(Self {
            sha: requested_sha.to_owned(),
            run_id,
            run_attempt,
            event,
            image_version: env("ImageVersion")?,
            kernel: first_line(&probe_text(
                "kernel identity probe",
                "uname",
                ["-srvmo"],
                PROBE_TIMEOUT,
            )?),
            cpu_model,
            cpu_count,
            memory_kib,
            runner_temp_free_kib,
            nofile_soft,
            rustc,
            cc: first_line(&probe_text(
                "C compiler identity probe",
                "cc",
                ["--version"],
                PROBE_TIMEOUT,
            )?),
            linker: first_line(&probe_text(
                "linker identity probe",
                "ld",
                ["--version"],
                PROBE_TIMEOUT,
            )?),
        })
    }

    fn json_fields(&self) -> String {
        format!(
            "\"profile\":{},\"sha\":{},\"run_id\":{},\"run_attempt\":{},\
             \"image_version\":{},\"kernel\":{},\"cpu_model\":{},\"cpu_count\":{},\
             \"memory_kib\":{},\"runner_temp_free_kib\":{},\"nofile_soft\":{},\
             \"event\":{},\"rustc\":{},\"cc\":{},\"linker\":{},\
             \"reference_sha256\":{}",
            json(PROFILE),
            json(&self.sha),
            json(&self.run_id),
            json(&self.run_attempt),
            json(&self.image_version),
            json(&self.kernel),
            json(&self.cpu_model),
            self.cpu_count,
            self.memory_kib,
            self.runner_temp_free_kib,
            self.nofile_soft,
            json(&self.event),
            json(&self.rustc),
            json(&self.cc),
            json(&self.linker),
            json(REFERENCE_SHA256),
        )
    }
}

struct EnvironmentIdentity {
    github_actions: String,
    runner_os: String,
    runner_arch: String,
    image_os: String,
    github_sha: String,
}

fn validate_environment(requested_sha: &str, identity: &EnvironmentIdentity) -> Result<(), String> {
    if requested_sha.len() != 40
        || !requested_sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || identity.github_sha != requested_sha
    {
        return Err("SHA identity mismatch".to_owned());
    }
    if identity.github_actions != "true"
        || identity.runner_os != "Linux"
        || identity.runner_arch != "X64"
        || identity.image_os != "ubuntu24"
    {
        return Err("host identity mismatch".to_owned());
    }
    Ok(())
}

fn validate_output_path(output: &Path) -> Result<(), String> {
    if output.exists() {
        return Err("output already exists".to_owned());
    }
    let runner_temp = PathBuf::from(env("RUNNER_TEMP")?);
    let root = runner_temp.join("m4");
    let root = root
        .canonicalize()
        .map_err(|_| "RUNNER_TEMP/m4 must exist".to_owned())?;
    let parent = output
        .parent()
        .ok_or_else(|| "output has no parent".to_owned())?
        .canonicalize()
        .map_err(|_| "output parent does not exist".to_owned())?;
    if !parent.starts_with(&root) || output.extension() != Some(OsStr::new("jsonl")) {
        return Err("output must be a new JSONL file below RUNNER_TEMP/m4".to_owned());
    }
    Ok(())
}

fn validate_temp_free(output: &Path) -> Result<u64, String> {
    let parent = output.parent().expect("validated output parent");
    let result = probe_text(
        "runner-temp capacity probe",
        "df",
        [OsString::from("-Pk"), parent.as_os_str().to_owned()],
        PROBE_TIMEOUT,
    )?;
    let available = result
        .lines()
        .last()
        .and_then(|line| line.split_whitespace().nth(3))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| "runner-temp free capacity is malformed".to_owned())?;
    if available < 6_000_000 {
        return Err("runner-temp free capacity is below M4-GHA-01".to_owned());
    }
    Ok(available)
}

fn linux_capacity() -> Result<(u64, String), String> {
    let meminfo = fs::read_to_string("/proc/meminfo")
        .map_err(|_| "Linux memory identity is unavailable".to_owned())?;
    let memory_kib = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:")?.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| "Linux memory identity is malformed".to_owned())?;
    let cpuinfo = fs::read_to_string("/proc/cpuinfo")
        .map_err(|_| "Linux CPU identity is unavailable".to_owned())?;
    let cpu_model = cpuinfo
        .lines()
        .find_map(|line| line.strip_prefix("model name\t: "))
        .ok_or_else(|| "Linux CPU model is unavailable".to_owned())?
        .to_owned();
    Ok((memory_kib, cpu_model))
}

fn validate_nofile() -> Result<u64, String> {
    let limits = fs::read_to_string("/proc/self/limits")
        .map_err(|_| "process limits are unavailable".to_owned())?;
    let soft = limits
        .lines()
        .find(|line| line.starts_with("Max open files"))
        .and_then(|line| line.split_whitespace().nth(3))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| "nofile soft limit is malformed".to_owned())?;
    if soft != 65_536 {
        return Err("nofile soft limit is not 65536".to_owned());
    }
    Ok(soft)
}

fn run_throughput(arguments: HostedArgs) -> Result<String, String> {
    let identity = HostedIdentity::load(&arguments.sha, &arguments.output)?;
    let sslocal = arguments.sslocal.expect("parsed reference client");
    let ssserver = arguments.ssserver.expect("parsed reference server");
    verify_reference(&sslocal, &ssserver, &arguments.output)?;
    let mut output = Evidence::create(&arguments.output)?;
    output.line(format!(
        "{{\"kind\":\"identity\",{}}}",
        identity.json_fields()
    ))?;
    let mut trials = Vec::with_capacity(TRIALS.len());
    for (index, topology) in TRIALS.into_iter().enumerate() {
        let trial = throughput_trial(index + 1, topology, &sslocal, &ssserver, output.parent())?;
        output.line(format!(
            "{{\"kind\":\"throughput_trial\",\"trial\":{},\"topology\":{},\
             \"streams\":{},\"payload_bytes\":{},\"warmup_seconds\":10,\
             \"measure_seconds\":30,\"bytes\":{},\"elapsed_ns\":{},\
             \"bytes_per_second\":{},\"client_config_sha256\":{},\
             \"server_config_sha256\":{}}}",
            trial.index,
            json(trial.topology.label()),
            STREAMS,
            PAYLOAD_BYTES,
            trial.bytes,
            trial.elapsed.as_nanos(),
            trial.bytes_per_second,
            json(&trial.client_config_hash),
            json(&trial.server_config_hash),
        ))?;
        trials.push(trial);
    }
    let ferrum = median(
        trials
            .iter()
            .filter(|trial| trial.topology == Topology::Ferrum)
            .map(|trial| trial.bytes_per_second),
    )?;
    let reference = median(
        trials
            .iter()
            .filter(|trial| trial.topology == Topology::Reference)
            .map(|trial| trial.bytes_per_second),
    )?;
    if ferrum == 0 || reference == 0 {
        return Err("throughput medians must be positive".to_owned());
    }
    let ratio = ferrum as f64 / reference as f64;
    let difference = (ferrum as f64 - reference as f64) * 100.0 / reference as f64;
    if !ratio.is_finite() || ratio.is_sign_negative() || !difference.is_finite() {
        return Err("throughput summary is not finite".to_owned());
    }
    output.line(format!(
        "{{\"kind\":\"throughput_summary\",\"ferrum_median_bytes_per_second\":{ferrum},\
         \"reference_median_bytes_per_second\":{reference},\"ratio\":{ratio:.9},\
         \"signed_difference_percent\":{difference:.9},\"trials\":10}}"
    ))?;
    output.finish()?;
    assert_no_owners()?;
    Ok(format!(
        "m4_throughput_completion status=PASS ferrum_median={ferrum} reference_median={reference} \
         ratio={ratio:.9} trials=10 sha={} run_id={} run_attempt={}",
        identity.sha, identity.run_id, identity.run_attempt
    ))
}

struct TrialResult {
    index: usize,
    topology: Topology,
    bytes: u64,
    elapsed: Duration,
    bytes_per_second: u64,
    client_config_hash: String,
    server_config_hash: String,
}

fn throughput_trial(
    index: usize,
    topology: Topology,
    sslocal: &Path,
    ssserver: &Path,
    work: &Path,
) -> Result<TrialResult, String> {
    let directory = tempfile::Builder::new()
        .prefix("throughput-")
        .tempdir_in(work)
        .map_err(clean_io)?;
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
    let target = v4(target_listener.local_addr().map_err(clean_io)?)?;
    let server_reservation = PortReservation::new()?;
    let proxy_reservation = PortReservation::new()?;
    let server = server_reservation.address;
    let proxy = proxy_reservation.address;
    let client_config = directory.path().join("client.json");
    let server_config = directory.path().join("server.json");
    let (client_binary, server_binary, client_text, server_text) = match topology {
        Topology::Ferrum => (
            ferrum_binary("ferrum2-client")?,
            ferrum_binary("ferrum2-server")?,
            ferrum_client_config(proxy, server, None),
            ferrum_server_config(server, None),
        ),
        Topology::Reference => (
            sslocal.to_path_buf(),
            ssserver.to_path_buf(),
            reference_client_config(proxy, server),
            reference_server_config(server),
        ),
    };
    fs::write(&client_config, client_text).map_err(clean_io)?;
    fs::write(&server_config, server_text).map_err(clean_io)?;
    let client_hash = sha256("throughput client config SHA-256 probe", &client_config)?;
    let server_hash = sha256("throughput server config SHA-256 probe", &server_config)?;
    let target_worker = TargetWorker::echo(target_listener, STREAMS)?;
    server_reservation.release();
    let mut server_process = spawn_proxy(topology, "server", &server_binary, &server_config)?;
    wait_for_listener(&mut server_process, server)?;
    proxy_reservation.release();
    let mut client_process = spawn_proxy(topology, "client", &client_binary, &client_config)?;
    wait_for_listener(&mut client_process, proxy)?;
    let gate = Arc::new(StartGate::default());
    let mut workers = Vec::with_capacity(STREAMS);
    for _ in 0..STREAMS {
        let worker_gate = Arc::clone(&gate);
        match spawn_worker(move || load_stream(proxy, target, worker_gate)) {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                gate.cancel();
                for worker in workers {
                    let _ = join_worker(worker);
                }
                return Err(error);
            }
        }
    }
    if let Err(error) = gate.start_when_ready(STREAMS, Instant::now() + STARTUP_TIMEOUT) {
        for worker in workers {
            let _ = join_worker(worker);
        }
        return Err(error);
    }
    let mut bytes = 0_u64;
    let mut worker_error = None;
    for worker in workers {
        match join_worker(worker).and_then(|result| result) {
            Ok(worker_bytes) => {
                bytes = bytes
                    .checked_add(worker_bytes)
                    .ok_or_else(|| "throughput byte count overflow".to_owned())?;
            }
            Err(error) => {
                worker_error.get_or_insert(error);
            }
        }
    }
    if let Some(error) = worker_error {
        return Err(error);
    }
    let elapsed = MEASURE;
    target_worker.finish()?;
    client_process.ensure_running()?;
    server_process.ensure_running()?;
    client_process.terminate()?;
    server_process.terminate()?;
    directory.close().map_err(clean_io)?;
    let bytes_per_second = u64::try_from(u128::from(bytes) * 1_000_000_000 / elapsed.as_nanos())
        .map_err(|_| "throughput value overflow".to_owned())?;
    Ok(TrialResult {
        index,
        topology,
        bytes,
        elapsed,
        bytes_per_second,
        client_config_hash: client_hash,
        server_config_hash: server_hash,
    })
}

fn load_stream(
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    gate: Arc<StartGate>,
) -> Result<u64, String> {
    let prepared = (|| {
        let stream = socks_connect(proxy, target, Instant::now() + STARTUP_TIMEOUT)?;
        stream.set_nodelay(true).map_err(clean_io)?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(clean_io)?;
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(clean_io)?;
        Ok::<_, String>(stream)
    })();
    let started = gate.ready_and_wait()?;
    let mut stream = prepared?;
    let payload = [0x5a; PAYLOAD_BYTES];
    let mut echoed = [0_u8; PAYLOAD_BYTES];
    let warm_end = started + WARMUP;
    let measure_end = warm_end + MEASURE;
    let mut measured = 0_u64;
    while Instant::now() < measure_end {
        let transfer_start = Instant::now();
        stream.write_all(&payload).map_err(clean_io)?;
        stream.read_exact(&mut echoed).map_err(clean_io)?;
        if echoed != payload {
            return Err("echo payload mismatch".to_owned());
        }
        let completion = Instant::now();
        if transfer_is_measured(transfer_start, completion, warm_end, measure_end) {
            measured += PAYLOAD_BYTES as u64;
        }
    }
    stream.shutdown(Shutdown::Both).map_err(clean_io)?;
    Ok(measured)
}

fn transfer_is_measured(
    transfer_start: Instant,
    completion: Instant,
    warm_end: Instant,
    measure_end: Instant,
) -> bool {
    transfer_start >= warm_end && completion <= measure_end
}

fn median(values: impl Iterator<Item = u64>) -> Result<u64, String> {
    let mut values: Vec<_> = values.collect();
    if values.len() != 5 {
        return Err("throughput topology must have five trials".to_owned());
    }
    values.sort_unstable();
    Ok(values[2])
}

fn verify_reference(sslocal: &Path, ssserver: &Path, output: &Path) -> Result<(), String> {
    let local = sslocal
        .canonicalize()
        .map_err(|_| "sslocal is unavailable".to_owned())?;
    let server = ssserver
        .canonicalize()
        .map_err(|_| "ssserver is unavailable".to_owned())?;
    if local.parent() != server.parent() {
        return Err("reference binaries do not share one verified extraction root".to_owned());
    }
    let work = output
        .parent()
        .expect("validated output parent")
        .canonicalize()
        .map_err(clean_io)?;
    if !local.starts_with(&work) || !server.starts_with(&work) {
        return Err("reference binaries escaped RUNNER_TEMP/m4".to_owned());
    }
    let archive = work.join("shadowsocks-v1.24.0.x86_64-unknown-linux-gnu.tar.xz");
    if fs::metadata(&archive).map_err(clean_io)?.len() != 11_635_096
        || sha256("reference archive SHA-256 probe", &archive)? != REFERENCE_SHA256
    {
        return Err("reference archive identity mismatch".to_owned());
    }
    for (identity, binary) in [
        ("reference sslocal version probe", &local),
        ("reference ssserver version probe", &server),
    ] {
        let version = probe_text(identity, binary, ["--version"], PROBE_TIMEOUT)?;
        validate_reference_identity(&version, REFERENCE_SHA256)?;
    }
    Ok(())
}

fn run_resource(arguments: HostedArgs) -> Result<String, String> {
    let identity = HostedIdentity::load(&arguments.sha, &arguments.output)?;
    let mut output = Evidence::create(&arguments.output)?;
    output.line(format!(
        "{{\"kind\":\"identity\",{}}}",
        identity.json_fields()
    ))?;
    let directory = tempfile::Builder::new()
        .prefix("resource-")
        .tempdir_in(output.parent())
        .map_err(clean_io)?;
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
    let target = v4(target_listener.local_addr().map_err(clean_io)?)?;
    let server_reservation = PortReservation::new()?;
    let proxy_reservation = PortReservation::new()?;
    let client_metrics_reservation = PortReservation::new()?;
    let server_metrics_reservation = PortReservation::new()?;
    let server = server_reservation.address;
    let proxy = proxy_reservation.address;
    let client_metrics = client_metrics_reservation.address;
    let server_metrics = server_metrics_reservation.address;
    let client_config = directory.path().join("client.toml");
    let server_config = directory.path().join("server.toml");
    fs::write(
        &client_config,
        ferrum_client_config(proxy, server, Some(client_metrics)),
    )
    .map_err(clean_io)?;
    fs::write(
        &server_config,
        ferrum_server_config(server, Some(server_metrics)),
    )
    .map_err(clean_io)?;
    let client_hash = sha256("resource client config SHA-256 probe", &client_config)?;
    let server_hash = sha256("resource server config SHA-256 probe", &server_config)?;
    output.line(format!(
        "{{\"kind\":\"resource_profile\",\"sessions\":10000,\"setup_concurrency\":256,\
         \"stabilization_samples\":30,\"samples\":180,\"interval_seconds\":10,\
         \"client_config_sha256\":{},\"server_config_sha256\":{}}}",
        json(&client_hash),
        json(&server_hash),
    ))?;
    let mut target_worker = HoldingTarget::start(target_listener, RESOURCE_SESSIONS)?;
    server_reservation.release();
    server_metrics_reservation.release();
    let mut server_process = spawn_proxy(
        Topology::Ferrum,
        "server",
        &ferrum_binary("ferrum2-server")?,
        &server_config,
    )?;
    wait_for_metrics(&mut server_process, server_metrics)?;
    proxy_reservation.release();
    client_metrics_reservation.release();
    let mut client_process = spawn_proxy(
        Topology::Ferrum,
        "client",
        &ferrum_binary("ferrum2-client")?,
        &client_config,
    )?;
    wait_for_metrics(&mut client_process, client_metrics)?;
    let pre_load = sample_pair(
        &mut client_process,
        &mut server_process,
        client_metrics,
        server_metrics,
        Instant::now() + SAMPLE_INTERVAL,
    )?;
    if pre_load.client.active != 0 || pre_load.server.active != 0 {
        return Err("pre-load active gauges are not zero".to_owned());
    }
    let applications = establish_sessions(proxy, target)?;
    target_worker.wait_accepted(Instant::now() + DRAIN_TIMEOUT)?;
    let first_stable = wait_for_sessions(
        &mut client_process,
        &mut server_process,
        client_metrics,
        server_metrics,
    )?;
    let stabilization_started = Instant::now();
    for index in 1..=STABILIZATION_SAMPLES {
        let slot =
            stabilization_started + SAMPLE_INTERVAL * u32::try_from(index).expect("sample index");
        let next_slot = slot + SAMPLE_INTERVAL;
        wait_for_sample_slot(slot, next_slot)?;
        let sample = sample_pair(
            &mut client_process,
            &mut server_process,
            client_metrics,
            server_metrics,
            next_slot,
        )?;
        validate_owner_tuple(&sample, &first_stable, RESOURCE_SESSIONS as u64)
            .map_err(|error| format!("stabilization sample {index}: {error}"))?;
    }
    let mut samples = Vec::with_capacity(RESOURCE_SAMPLES);
    let started = Instant::now();
    for index in 0..RESOURCE_SAMPLES {
        let slot = started + SAMPLE_INTERVAL * u32::try_from(index + 1).expect("sample index");
        let next_slot = slot + SAMPLE_INTERVAL;
        wait_for_sample_slot(slot, next_slot)?;
        let sample = sample_pair(
            &mut client_process,
            &mut server_process,
            client_metrics,
            server_metrics,
            next_slot,
        )?;
        validate_owner_tuple(&sample, &first_stable, RESOURCE_SESSIONS as u64)?;
        output.line(sample.json(index + 1))?;
        samples.push(sample);
    }
    let rss = validate_samples(
        &samples,
        RESOURCE_SAMPLES,
        RSS_WINDOW,
        RESOURCE_SESSIONS as u64,
    )?;
    for verdict in &rss {
        output.line(verdict.json())?;
    }
    drop(applications);
    let drain_deadline = Instant::now() + DRAIN_TIMEOUT;
    target_worker.wait_closed(drain_deadline)?;
    loop {
        let drained = sample_pair(
            &mut client_process,
            &mut server_process,
            client_metrics,
            server_metrics,
            drain_deadline,
        )?;
        if Instant::now() >= drain_deadline {
            return Err("resource drain did not return to exact baseline".to_owned());
        }
        if validate_drain(&drained, &pre_load).is_ok() {
            break;
        }
        thread::sleep(remaining(drain_deadline)?.min(Duration::from_millis(100)));
    }
    client_process.ensure_running()?;
    server_process.ensure_running()?;
    client_process.terminate()?;
    server_process.terminate()?;
    directory.close().map_err(clean_io)?;
    output.line(
        "{\"kind\":\"resource_summary\",\"sessions\":10000,\"samples\":180,\
         \"rss_windows\":6,\"drain\":\"PASS\"}"
            .to_owned(),
    )?;
    output.finish()?;
    assert_no_owners()?;
    Ok(format!(
        "m4_resource_completion status=PASS sessions=10000 samples=180 rss_windows=6/6 \
         drain=PASS sha={} run_id={} run_attempt={}",
        identity.sha, identity.run_id, identity.run_attempt
    ))
}

fn establish_sessions(proxy: SocketAddrV4, target: SocketAddrV4) -> Result<Vec<TcpStream>, String> {
    let next = Arc::new(AtomicUsize::new(0));
    let (sender, receiver) = mpsc::sync_channel(SETUP_WORKERS);
    let mut workers = Vec::with_capacity(SETUP_WORKERS);
    for _ in 0..SETUP_WORKERS {
        let worker_next = Arc::clone(&next);
        let worker_sender = sender.clone();
        let worker = spawn_worker(move || {
            loop {
                let index = worker_next.fetch_add(1, Ordering::Relaxed);
                if index >= RESOURCE_SESSIONS {
                    break;
                }
                let result = socks_connect(proxy, target, Instant::now() + STARTUP_TIMEOUT);
                if worker_sender.send((index, result)).is_err() {
                    break;
                }
            }
            Ok::<(), String>(())
        });
        match worker {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                next.store(RESOURCE_SESSIONS, Ordering::Relaxed);
                drop(sender);
                let _ = join_unit_workers(workers);
                return Err(error);
            }
        }
    }
    drop(sender);
    let mut streams: Vec<Option<TcpStream>> = (0..RESOURCE_SESSIONS).map(|_| None).collect();
    let mut first_error = None;
    for _ in 0..RESOURCE_SESSIONS {
        let Ok((index, result)) = receiver.recv() else {
            first_error
                .get_or_insert_with(|| "setup workers ended before 10000 results".to_owned());
            break;
        };
        match result {
            Ok(stream) => streams[index] = Some(stream),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        };
    }
    join_unit_workers(workers)?;
    if let Some(error) = first_error {
        return Err(error);
    }
    streams
        .into_iter()
        .map(|stream| stream.ok_or_else(|| "session setup result is missing".to_owned()))
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessSample {
    active: u64,
    fds: u64,
    tasks: u64,
    rss_kib: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PairSample {
    client: ProcessSample,
    server: ProcessSample,
}

impl PairSample {
    fn json(self, index: usize) -> String {
        format!(
            "{{\"kind\":\"resource_sample\",\"sample\":{index},\
             \"client_active\":{},\"server_active\":{},\"client_fds\":{},\
             \"server_fds\":{},\"client_tasks\":{},\"server_tasks\":{},\
             \"client_rss_kib\":{},\"server_rss_kib\":{}}}",
            self.client.active,
            self.server.active,
            self.client.fds,
            self.server.fds,
            self.client.tasks,
            self.server.tasks,
            self.client.rss_kib,
            self.server.rss_kib,
        )
    }
}

fn sample_pair(
    client: &mut ProcessGuard,
    server: &mut ProcessGuard,
    client_metrics: SocketAddrV4,
    server_metrics: SocketAddrV4,
    deadline: Instant,
) -> Result<PairSample, String> {
    client.ensure_running()?;
    server.ensure_running()?;
    let client_proc = proc_sample(client.id())?;
    let server_proc = proc_sample(server.id())?;
    let client_active = active_metric(client_metrics, deadline)?;
    let server_active = active_metric(server_metrics, deadline)?;
    let sample = PairSample {
        client: ProcessSample {
            active: client_active,
            ..client_proc
        },
        server: ProcessSample {
            active: server_active,
            ..server_proc
        },
    };
    remaining(deadline)?;
    Ok(sample)
}

fn proc_sample(pid: u32) -> Result<ProcessSample, String> {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let fds = fs::read_dir(root.join("fd"))
        .map_err(|_| "process fd state is unavailable".to_owned())?
        .count() as u64;
    let tasks = fs::read_dir(root.join("task"))
        .map_err(|_| "process task state is unavailable".to_owned())?
        .count() as u64;
    let status = fs::read_to_string(root.join("status"))
        .map_err(|_| "process RSS state is unavailable".to_owned())?;
    let rss_kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:")?.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| "process RSS state is malformed".to_owned())?;
    Ok(ProcessSample {
        active: 0,
        fds,
        tasks,
        rss_kib,
    })
}

fn wait_for_sessions(
    client: &mut ProcessGuard,
    server: &mut ProcessGuard,
    client_metrics: SocketAddrV4,
    server_metrics: SocketAddrV4,
) -> Result<PairSample, String> {
    let deadline = Instant::now() + DRAIN_TIMEOUT;
    loop {
        let sample = sample_pair(client, server, client_metrics, server_metrics, deadline)?;
        if sample.client.active == RESOURCE_SESSIONS as u64
            && sample.server.active == RESOURCE_SESSIONS as u64
        {
            return Ok(sample);
        }
        thread::sleep(remaining(deadline)?.min(Duration::from_millis(100)));
    }
}

fn validate_owner_tuple(
    sample: &PairSample,
    first: &PairSample,
    sessions: u64,
) -> Result<(), String> {
    let tuple = |sample: &PairSample| {
        (
            sample.client.active,
            sample.server.active,
            sample.client.fds,
            sample.server.fds,
            sample.client.tasks,
            sample.server.tasks,
        )
    };
    if sample.client.active != sessions
        || sample.server.active != sessions
        || tuple(sample) != tuple(first)
    {
        return Err("owner/task tuple changed".to_owned());
    }
    Ok(())
}

struct RssVerdict {
    window: usize,
    client_median_twice: u64,
    server_median_twice: u64,
}

impl RssVerdict {
    fn json(&self) -> String {
        format!(
            "{{\"kind\":\"rss_window\",\"window\":{},\"client_median_twice_kib\":{},\
             \"server_median_twice_kib\":{},\"limit_percent\":105,\"status\":\"PASS\"}}",
            self.window, self.client_median_twice, self.server_median_twice
        )
    }
}

fn validate_samples(
    samples: &[PairSample],
    expected: usize,
    window_size: usize,
    sessions: u64,
) -> Result<Vec<RssVerdict>, String> {
    if samples.len() != expected || expected != window_size * 6 {
        return Err("sample set is incomplete".to_owned());
    }
    let first = samples[0];
    for sample in samples {
        validate_owner_tuple(sample, &first, sessions)?;
    }
    let mut verdicts = Vec::with_capacity(6);
    let mut first_client = 0;
    let mut first_server = 0;
    for (index, window) in samples.chunks_exact(window_size).enumerate() {
        let client = median_twice(window.iter().map(|sample| sample.client.rss_kib))?;
        let server = median_twice(window.iter().map(|sample| sample.server.rss_kib))?;
        if index == 0 {
            first_client = client;
            first_server = server;
        }
        if u128::from(client) * 100 > u128::from(first_client) * 105
            || u128::from(server) * 100 > u128::from(first_server) * 105
        {
            return Err(format!("RSS window {} exceeds 105 percent", index + 1));
        }
        verdicts.push(RssVerdict {
            window: index + 1,
            client_median_twice: client,
            server_median_twice: server,
        });
    }
    Ok(verdicts)
}

fn median_twice(values: impl Iterator<Item = u64>) -> Result<u64, String> {
    let mut values: Vec<_> = values.collect();
    if values.is_empty() || values.len() % 2 != 0 {
        return Err("RSS window must contain a positive even sample count".to_owned());
    }
    values.sort_unstable();
    let middle = values.len() / 2;
    values[middle - 1]
        .checked_add(values[middle])
        .ok_or_else(|| "RSS median overflow".to_owned())
}

fn validate_drain(sample: &PairSample, baseline: &PairSample) -> Result<(), String> {
    if sample.client.active != 0
        || sample.server.active != 0
        || sample.client.fds != baseline.client.fds
        || sample.server.fds != baseline.server.fds
        || sample.client.tasks != baseline.client.tasks
        || sample.server.tasks != baseline.server.tasks
    {
        return Err("drain is incomplete".to_owned());
    }
    Ok(())
}

fn run_self_check() -> Result<String, String> {
    let sha = "0123456789abcdef0123456789abcdef01234567";
    let good = EnvironmentIdentity {
        github_actions: "true".to_owned(),
        runner_os: "Linux".to_owned(),
        runner_arch: "X64".to_owned(),
        image_os: "ubuntu24".to_owned(),
        github_sha: sha.to_owned(),
    };
    validate_environment(sha, &good)?;
    let transfer_start = Instant::now();
    let warm_end = transfer_start + WARMUP;
    let measure_end = warm_end + MEASURE;
    if !transfer_is_measured(warm_end, measure_end, warm_end, measure_end)
        || transfer_is_measured(
            warm_end - Duration::from_nanos(1),
            measure_end,
            warm_end,
            measure_end,
        )
        || transfer_is_measured(
            warm_end,
            measure_end + Duration::from_nanos(1),
            warm_end,
            measure_end,
        )
    {
        return Err("throughput measurement boundary is invalid".to_owned());
    }
    let past_slot = Instant::now();
    let admission_now = past_slot + Duration::from_nanos(1);
    if sample_slot_delay(admission_now, past_slot, admission_now + SAMPLE_INTERVAL).is_ok() {
        return Err("past resource sample slot was admitted".to_owned());
    }
    let executable = std::env::current_exe().map_err(clean_io)?;
    let probe_error = probe_text(
        "self-check nonzero probe",
        &executable,
        ["self-check-probe-nonzero"],
        PROBE_TIMEOUT,
    )
    .expect_err("self-check probe must exit nonzero");
    ensure_redacted(&probe_error)?;
    if probe_error != "self-check nonzero probe exited nonzero" {
        return Err(format!("probe diagnostic mismatch: {probe_error}"));
    }
    let lazy_absent = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n\
# TYPE ferrum2_tcp_replay_entries gauge\n\
ferrum2_tcp_replay_entries 0\n\
# EOF\n";
    if parse_active_metric_response(lazy_absent) != Ok(0) {
        return Err("valid lazy active metric absence was rejected".to_owned());
    }
    expect_rejected("unidentified active metric absence", || {
        parse_active_metric_response(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n# EOF\n")
    })?;
    expect_rejected("wrong SHA", || {
        validate_environment("1123456789abcdef0123456789abcdef01234567", &good)
    })?;
    let wrong_host = EnvironmentIdentity {
        runner_os: "Windows".to_owned(),
        ..good
    };
    expect_rejected("wrong host", || validate_environment(sha, &wrong_host))?;
    expect_rejected("wrong reference", || {
        validate_reference_identity("shadowsocks 1.23.0", REFERENCE_SHA256)
    })?;
    let process = ProcessSample {
        active: 4,
        fds: 20,
        tasks: 3,
        rss_kib: 100,
    };
    let sample = PairSample {
        client: process,
        server: process,
    };
    let samples = vec![sample; 12];
    validate_samples(&samples, 12, 2, 4)?;
    expect_rejected("missing sample", || {
        validate_samples(&samples[..11], 12, 2, 4)
    })?;
    let mut changing = samples.clone();
    changing[3].client.tasks += 1;
    expect_rejected("changing owner tuple", || {
        validate_samples(&changing, 12, 2, 4)
    })?;
    let mut rss = samples.clone();
    rss[10].client.rss_kib = 106;
    rss[11].client.rss_kib = 106;
    expect_rejected("RSS regression", || validate_samples(&rss, 12, 2, 4))?;
    let baseline = PairSample {
        client: ProcessSample {
            active: 0,
            fds: 7,
            tasks: 2,
            rss_kib: 80,
        },
        server: ProcessSample {
            active: 0,
            fds: 8,
            tasks: 2,
            rss_kib: 80,
        },
    };
    let mut incomplete = baseline;
    incomplete.server.fds += 1;
    expect_rejected("incomplete drain", || {
        validate_drain(&incomplete, &baseline)
    })?;
    expect_rejected("leaked owner", || validate_owner_counts(1, 0))?;
    expect_rejected("secret output", || ensure_redacted(PSK))?;
    let root = repository_root()?.join("target/m4");
    fs::create_dir_all(&root).map_err(clean_io)?;
    let path = root.join("self-check.jsonl");
    let mut file = BufWriter::new(File::create(&path).map_err(clean_io)?);
    let line = "{\"kind\":\"self_check\",\"mutations\":11,\"status\":\"PASS\"}\n";
    ensure_redacted(line)?;
    file.write_all(line.as_bytes()).map_err(clean_io)?;
    file.flush().map_err(clean_io)?;
    assert_no_owners()?;
    Ok("m4_self_check status=PASS mutations=11".to_owned())
}

fn expect_rejected<T>(
    name: &str,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<(), String> {
    if operation().is_ok() {
        return Err(format!("self-check mutation survived: {name}"));
    }
    Ok(())
}

fn validate_reference_identity(version: &str, sha256: &str) -> Result<(), String> {
    if version.trim() != REFERENCE_VERSION || sha256 != REFERENCE_SHA256 {
        return Err("reference identity mismatch".to_owned());
    }
    Ok(())
}

fn ensure_redacted(text: &str) -> Result<(), String> {
    if text.contains(PSK) {
        return Err("secret-bearing output".to_owned());
    }
    Ok(())
}

fn assert_no_owners() -> Result<(), String> {
    validate_owner_counts(
        ACTIVE_PROCESSES.load(Ordering::SeqCst),
        ACTIVE_WORKERS.load(Ordering::SeqCst),
    )
}

fn validate_owner_counts(processes: usize, workers: usize) -> Result<(), String> {
    if processes != 0 || workers != 0 {
        return Err("owned process or worker leaked".to_owned());
    }
    Ok(())
}

struct Evidence {
    writer: BufWriter<File>,
    parent: PathBuf,
    finished: bool,
}

impl Evidence {
    fn create(path: &Path) -> Result<Self, String> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(clean_io)?;
        Ok(Self {
            writer: BufWriter::new(file),
            parent: path
                .parent()
                .expect("validated output parent")
                .to_path_buf(),
            finished: false,
        })
    }

    fn parent(&self) -> &Path {
        &self.parent
    }

    fn line(&mut self, line: String) -> Result<(), String> {
        if line.len() > 16 * 1024 {
            return Err("evidence line exceeds bound".to_owned());
        }
        ensure_redacted(&line)?;
        self.writer.write_all(line.as_bytes()).map_err(clean_io)?;
        self.writer.write_all(b"\n").map_err(clean_io)
    }

    fn finish(mut self) -> Result<(), String> {
        self.writer.flush().map_err(clean_io)?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for Evidence {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.writer.flush();
        }
    }
}

fn ferrum_client_config(
    listen: SocketAddrV4,
    server: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
) -> String {
    let metrics = metrics
        .map(|address| format!("\n[metrics]\nlisten = \"{address}\"\n"))
        .unwrap_or_default();
    format!(
        "schema_version = 1\n\n[client]\nlisten = \"{listen}\"\nserver = \"{server}\"\n\n\
         [shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{PSK}\"\n\n\
         [runtime]\nmax_connections = 12000\nlisten_backlog = 65535\n\
         idle_timeout_ms = 3600000\n\n[logging]\nlevel = \"error\"\n{metrics}"
    )
}

fn ferrum_server_config(listen: SocketAddrV4, metrics: Option<SocketAddrV4>) -> String {
    let metrics = metrics
        .map(|address| format!("\n[metrics]\nlisten = \"{address}\"\n"))
        .unwrap_or_default();
    format!(
        "schema_version = 1\n\n[server]\nlisten = \"{listen}\"\n\n\
         [shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{PSK}\"\n\n\
         [runtime]\nmax_connections = 12000\nlisten_backlog = 65535\n\
         idle_timeout_ms = 3600000\n\n[udp]\nenabled = false\n\n\
         [logging]\nlevel = \"error\"\n{metrics}"
    )
}

fn reference_client_config(listen: SocketAddrV4, server: SocketAddrV4) -> String {
    format!(
        "{{\"local_address\":\"127.0.0.1\",\"local_port\":{},\
         \"server\":\"127.0.0.1\",\"server_port\":{},\"password\":\"{PSK}\",\
         \"method\":\"2022-blake3-aes-128-gcm\",\"mode\":\"tcp_only\"}}",
        listen.port(),
        server.port()
    )
}

fn reference_server_config(listen: SocketAddrV4) -> String {
    format!(
        "{{\"server\":\"127.0.0.1\",\"server_port\":{},\"password\":\"{PSK}\",\
         \"method\":\"2022-blake3-aes-128-gcm\",\"mode\":\"tcp_only\"}}",
        listen.port()
    )
}

fn spawn_proxy(
    topology: Topology,
    role: &str,
    binary: &Path,
    config: &Path,
) -> Result<ProcessGuard, String> {
    let mut command = Command::new(binary);
    match topology {
        Topology::Ferrum => {
            command.args([OsStr::new("--config"), config.as_os_str()]);
        }
        Topology::Reference => {
            command.args([OsStr::new("-c"), config.as_os_str()]);
        }
    }
    ProcessGuard::spawn(&format!("{} {role}", topology.label()), &mut command)
}

fn ferrum_binary(name: &str) -> Result<PathBuf, String> {
    let path = std::env::current_exe()
        .map_err(clean_io)?
        .parent()
        .expect("qualification profile directory")
        .join(name);
    if !path.is_file() {
        return Err(format!("required release binary is missing: {name}"));
    }
    Ok(path)
}

struct PortReservation {
    listener: TcpListener,
    address: SocketAddrV4,
}

impl PortReservation {
    fn new() -> Result<Self, String> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
        let address = v4(listener.local_addr().map_err(clean_io)?)?;
        Ok(Self { listener, address })
    }

    fn release(self) {
        drop(self.listener);
    }
}

fn v4(address: SocketAddr) -> Result<SocketAddrV4, String> {
    match address {
        SocketAddr::V4(address) => Ok(address),
        SocketAddr::V6(_) => Err("IPv4 loopback returned IPv6".to_owned()),
    }
}

fn wait_for_listener(child: &mut ProcessGuard, address: SocketAddrV4) -> Result<(), String> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        child.ensure_running()?;
        if TcpStream::connect_timeout(&SocketAddr::V4(address), Duration::from_millis(200)).is_ok()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("listener readiness timed out".to_owned());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_metrics(child: &mut ProcessGuard, address: SocketAddrV4) -> Result<(), String> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        child.ensure_running()?;
        if active_metric(address, deadline).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("metrics readiness timed out".to_owned());
        }
        thread::sleep(remaining(deadline)?.min(Duration::from_millis(20)));
    }
}

fn active_metric(address: SocketAddrV4, deadline: Instant) -> Result<u64, String> {
    let timeout = remaining(deadline)?.min(IO_TIMEOUT);
    let mut stream = TcpStream::connect_timeout(&SocketAddr::V4(address), timeout)
        .map_err(|_| "metrics connection failed".to_owned())?;
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
            return Err("metrics response exceeded bound".to_owned());
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
    let active = parse_active_metric_response(&response)?;
    remaining(deadline)?;
    Ok(active)
}

fn parse_active_metric_response(response: &[u8]) -> Result<u64, String> {
    const ACTIVE: &str = "ferrum2_tcp_connections_active";
    const CLIENT_ACTIVE: &str =
        "ferrum2_tcp_connections_active{role=\"client\",inbound=\"socks5\"}";
    const SERVER_ACTIVE: &str =
        "ferrum2_tcp_connections_active{role=\"server\",inbound=\"shadowsocks\"}";
    const REPLAY: &str = "ferrum2_tcp_replay_entries";
    const REPLAY_TYPE: &str = "# TYPE ferrum2_tcp_replay_entries gauge";

    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "metrics response is malformed".to_owned())?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| "metrics response is malformed".to_owned())?;
    let mut status = headers
        .lines()
        .next()
        .ok_or_else(|| "metrics response is malformed".to_owned())?
        .split_whitespace();
    if !status
        .next()
        .is_some_and(|value| value.starts_with("HTTP/"))
        || status.next() != Some("200")
    {
        return Err("metrics response status is not 200".to_owned());
    }
    let body = &response[header_end + 4..];
    let body = std::str::from_utf8(body).map_err(|_| "metrics body is not UTF-8".to_owned())?;
    if !body.ends_with("# EOF\n") || body.lines().filter(|line| *line == "# EOF").count() != 1 {
        return Err("metrics exposition is incomplete".to_owned());
    }

    let mut active = None;
    let mut replay_type = 0;
    let mut replay_sample = false;
    for line in body.lines() {
        if line == REPLAY_TYPE {
            replay_type += 1;
        } else if !line.starts_with('#') && line.starts_with(ACTIVE) {
            let (name, value) = line
                .split_once(' ')
                .ok_or_else(|| "active metric is malformed".to_owned())?;
            if (name != CLIENT_ACTIVE && name != SERVER_ACTIVE) || active.is_some() {
                return Err("active metric is malformed or duplicated".to_owned());
            }
            active = Some(
                value
                    .parse()
                    .map_err(|_| "active metric is malformed".to_owned())?,
            );
        } else if !line.starts_with('#') && line.starts_with(REPLAY) {
            let (name, value) = line
                .split_once(' ')
                .ok_or_else(|| "metrics exposition identity is malformed".to_owned())?;
            if name != REPLAY || replay_sample || value.parse::<i64>().is_err() {
                return Err("metrics exposition identity is malformed".to_owned());
            }
            replay_sample = true;
        }
    }
    if replay_type > 1 {
        return Err("metrics exposition identity is malformed".to_owned());
    }
    active
        .or_else(|| (replay_type == 1 && replay_sample).then_some(0))
        .ok_or_else(|| "active metric is absent from an unidentified exposition".to_owned())
}

fn socks_connect(
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    deadline: Instant,
) -> Result<TcpStream, String> {
    let timeout = remaining(deadline)?;
    let mut stream =
        TcpStream::connect_timeout(&SocketAddr::V4(proxy), timeout).map_err(clean_io)?;
    stream.set_read_timeout(Some(timeout)).map_err(clean_io)?;
    stream.set_write_timeout(Some(timeout)).map_err(clean_io)?;
    stream.write_all(&[5, 1, 0]).map_err(clean_io)?;
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).map_err(clean_io)?;
    if method != [5, 0] {
        return Err("SOCKS authentication negotiation failed".to_owned());
    }
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).map_err(clean_io)?;
    let mut reply = [0_u8; 10];
    stream.read_exact(&mut reply).map_err(clean_io)?;
    if reply[..4] != [5, 0, 0, 1] {
        return Err("SOCKS CONNECT failed".to_owned());
    }
    stream.set_read_timeout(None).map_err(clean_io)?;
    stream.set_write_timeout(None).map_err(clean_io)?;
    Ok(stream)
}

fn remaining(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| "operation deadline expired".to_owned())
}

#[derive(Default)]
struct StartGate {
    state: Mutex<StartState>,
    changed: Condvar,
}

#[derive(Default)]
struct StartState {
    ready: usize,
    start: Option<Instant>,
    cancelled: bool,
}

impl StartGate {
    fn ready_and_wait(&self) -> Result<Instant, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "load start gate is poisoned".to_owned())?;
        state.ready += 1;
        self.changed.notify_all();
        while state.start.is_none() && !state.cancelled {
            state = self
                .changed
                .wait(state)
                .map_err(|_| "load start gate is poisoned".to_owned())?;
        }
        state
            .start
            .ok_or_else(|| "load start was cancelled".to_owned())
    }

    fn start_when_ready(&self, expected: usize, deadline: Instant) -> Result<Instant, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "load start gate is poisoned".to_owned())?;
        while state.ready != expected && !state.cancelled {
            let timeout = remaining(deadline)?;
            let (next, result) = self
                .changed
                .wait_timeout(state, timeout)
                .map_err(|_| "load start gate is poisoned".to_owned())?;
            state = next;
            if result.timed_out() && state.ready != expected {
                state.cancelled = true;
                self.changed.notify_all();
                return Err("load workers did not become ready".to_owned());
            }
        }
        if state.cancelled {
            return Err("load start was cancelled".to_owned());
        }
        let start = Instant::now();
        state.start = Some(start);
        self.changed.notify_all();
        Ok(start)
    }

    fn cancel(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.cancelled = true;
            self.changed.notify_all();
        }
    }
}

struct TargetWorker {
    cancel: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<(), String>>>,
}

impl TargetWorker {
    fn echo(listener: TcpListener, streams: usize) -> Result<Self, String> {
        listener.set_nonblocking(true).map_err(clean_io)?;
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker = spawn_worker(move || {
            let mut workers = Vec::with_capacity(streams);
            let accepted = (|| {
                for _ in 0..streams {
                    let mut stream = loop {
                        match listener.accept() {
                            Ok((stream, _)) => break stream,
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                if worker_cancel.load(Ordering::SeqCst) {
                                    return Err("target accept cancelled".to_owned());
                                }
                                thread::sleep(Duration::from_millis(10));
                            }
                            Err(error) => return Err(clean_io(error)),
                        }
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_millis(200)))
                        .map_err(clean_io)?;
                    stream
                        .set_write_timeout(Some(Duration::from_millis(200)))
                        .map_err(clean_io)?;
                    let stream_cancel = Arc::clone(&worker_cancel);
                    workers.push(spawn_worker(move || {
                        let mut buffer = [0_u8; PAYLOAD_BYTES];
                        loop {
                            match stream.read(&mut buffer) {
                                Ok(0) => break,
                                Ok(read) => stream.write_all(&buffer[..read]).map_err(clean_io)?,
                                Err(error)
                                    if error.kind() == io::ErrorKind::WouldBlock
                                        || error.kind() == io::ErrorKind::TimedOut =>
                                {
                                    if stream_cancel.load(Ordering::SeqCst) {
                                        break;
                                    }
                                }
                                Err(error)
                                    if error.kind() == io::ErrorKind::ConnectionReset
                                        || error.kind() == io::ErrorKind::ConnectionAborted =>
                                {
                                    break;
                                }
                                Err(error) => return Err(clean_io(error)),
                            }
                        }
                        Ok(())
                    })?);
                }
                Ok::<(), String>(())
            })();
            if let Err(error) = accepted {
                worker_cancel.store(true, Ordering::SeqCst);
                return match join_unit_workers(workers) {
                    Ok(()) => Err(error),
                    Err(_) => Err(format!("{error}; target worker cleanup failed")),
                };
            }
            join_unit_workers(workers)
        })?;
        Ok(Self {
            cancel,
            worker: Some(worker),
        })
    }

    fn finish(mut self) -> Result<(), String> {
        join_worker(self.worker.take().expect("target worker owner"))?
    }
}

impl Drop for TargetWorker {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct HoldingTarget {
    accepted: mpsc::Receiver<Result<(), String>>,
    close: mpsc::Sender<Instant>,
    cancel: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<(), String>>>,
}

impl HoldingTarget {
    fn start(listener: TcpListener, sessions: usize) -> Result<Self, String> {
        listener.set_nonblocking(true).map_err(clean_io)?;
        let (accepted_sender, accepted) = mpsc::sync_channel(1);
        let (close, close_receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker = spawn_worker(move || {
            let mut streams = Vec::with_capacity(sessions);
            for _ in 0..sessions {
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            streams.push(stream);
                            break;
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            if worker_cancel.load(Ordering::SeqCst) {
                                return Ok(());
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => {
                            let message = clean_io(error);
                            let _ = accepted_sender.send(Err(message.clone()));
                            return Err(message);
                        }
                    }
                }
            }
            accepted_sender
                .send(Ok(()))
                .map_err(|_| "accepted signal lost".to_owned())?;
            let deadline = loop {
                match close_receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(deadline) => break deadline,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if worker_cancel.load(Ordering::SeqCst) {
                            return Ok(());
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                }
            };
            for stream in &streams {
                stream.set_nonblocking(true).map_err(clean_io)?;
            }
            while !streams.is_empty() {
                streams.retain_mut(|stream| {
                    let mut byte = [0_u8; 1];
                    match stream.read(&mut byte) {
                        Ok(0) => false,
                        Err(error)
                            if error.kind() == io::ErrorKind::ConnectionReset
                                || error.kind() == io::ErrorKind::ConnectionAborted =>
                        {
                            false
                        }
                        Ok(_) => true,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => true,
                        Err(_) => true,
                    }
                });
                if Instant::now() >= deadline {
                    return Err("target did not observe every closure".to_owned());
                }
                thread::sleep(Duration::from_millis(20));
            }
            Ok(())
        })?;
        Ok(Self {
            accepted,
            close,
            cancel,
            worker: Some(worker),
        })
    }

    fn wait_accepted(&self, deadline: Instant) -> Result<(), String> {
        self.accepted
            .recv_timeout(remaining(deadline)?)
            .map_err(|_| "target did not accept 10000 streams".to_owned())?
    }

    fn wait_closed(&mut self, deadline: Instant) -> Result<(), String> {
        self.close
            .send(deadline)
            .map_err(|_| "target close owner ended early".to_owned())?;
        let worker = self
            .worker
            .take()
            .ok_or_else(|| "target worker already joined".to_owned())?;
        join_worker(worker)?
    }
}

impl Drop for HoldingTarget {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
        let _ = self.close.send(Instant::now());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct ProcessGuard {
    child: Child,
    label: String,
    stdout: Option<JoinHandle<Capture>>,
    stderr: Option<JoinHandle<Capture>>,
    reaped: bool,
}

struct Capture {
    bytes: Vec<u8>,
    truncated: bool,
    secret: bool,
}

impl ProcessGuard {
    fn spawn(label: &str, command: &mut Command) -> Result<Self, String> {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|_| format!("{label} did not start"))?;
        let stdout = capture(child.stdout.take().expect("stdout owner"));
        let stderr = capture(child.stderr.take().expect("stderr owner"));
        ACTIVE_PROCESSES.fetch_add(1, Ordering::SeqCst);
        Ok(Self {
            child,
            label: label.to_owned(),
            stdout: Some(stdout),
            stderr: Some(stderr),
            reaped: false,
        })
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn ensure_running(&mut self) -> Result<(), String> {
        if let Some(status) = self.child.try_wait().map_err(clean_io)? {
            let error = format!("{} exited early with {status}", self.label);
            self.reap()?;
            return Err(error);
        }
        Ok(())
    }

    fn terminate(&mut self) -> Result<(), String> {
        if self.reaped {
            return Ok(());
        }
        if self.child.try_wait().map_err(clean_io)?.is_none() {
            self.child.kill().map_err(clean_io)?;
        }
        let _exit = wait_child(&mut self.child, Instant::now() + REAP_TIMEOUT)?;
        self.reap()
    }

    fn reap(&mut self) -> Result<(), String> {
        let _ = self.child.wait().map_err(clean_io)?;
        let stdout = join_capture(self.stdout.take().expect("stdout capture"))?;
        let stderr = join_capture(self.stderr.take().expect("stderr capture"))?;
        self.reaped = true;
        ACTIVE_PROCESSES.fetch_sub(1, Ordering::SeqCst);
        if stdout.truncated || stderr.truncated {
            return Err(format!("{} output exceeded bound", self.label));
        }
        if stdout.secret || stderr.secret {
            return Err(format!("{} emitted secret-bearing output", self.label));
        }
        Ok(())
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(stdout) = self.stdout.take() {
            let _ = stdout.join();
        }
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.join();
        }
        self.reaped = true;
        ACTIVE_PROCESSES.fetch_sub(1, Ordering::SeqCst);
    }
}

fn capture(mut reader: impl Read + Send + 'static) -> JoinHandle<Capture> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut scan = Vec::new();
        let mut truncated = false;
        let mut secret = false;
        let mut chunk = [0_u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    scan.extend_from_slice(&chunk[..read]);
                    secret |= scan
                        .windows(PSK.len())
                        .any(|window| window == PSK.as_bytes());
                    if scan.len() > PSK.len() {
                        scan.drain(..scan.len() - PSK.len());
                    }
                    let remaining = PROCESS_OUTPUT_CAP.saturating_sub(bytes.len());
                    let keep = remaining.min(read);
                    bytes.extend_from_slice(&chunk[..keep]);
                    truncated |= keep < read;
                }
            }
        }
        Capture {
            bytes,
            truncated,
            secret,
        }
    })
}

fn join_capture(worker: JoinHandle<Capture>) -> Result<Capture, String> {
    worker
        .join()
        .map_err(|_| "capture worker panicked".to_owned())
}

fn wait_child(child: &mut Child, deadline: Instant) -> Result<(ExitStatus, bool), String> {
    loop {
        if let Some(status) = child.try_wait().map_err(clean_io)? {
            return Ok((status, false));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return child.wait().map(|status| (status, true)).map_err(clean_io);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn probe_text<P, I, S>(
    identity: &'static str,
    program: P,
    arguments: I,
    timeout: Duration,
) -> Result<String, String>
where
    P: AsRef<OsStr>,
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new(program);
    command.args(arguments);
    let mut process = ProcessGuard::spawn(identity, &mut command)?;
    let (status, timed_out) = wait_child(&mut process.child, Instant::now() + timeout)
        .map_err(|_| format!("{identity} wait failed"))?;
    let stdout = join_capture(process.stdout.take().expect("probe stdout"))
        .map_err(|_| format!("{identity} stdout capture failed"))?;
    let stderr = join_capture(process.stderr.take().expect("probe stderr"))
        .map_err(|_| format!("{identity} stderr capture failed"))?;
    process.reaped = true;
    ACTIVE_PROCESSES.fetch_sub(1, Ordering::SeqCst);
    if timed_out {
        return Err(format!("{identity} timed out"));
    }
    if stdout.truncated || stderr.truncated {
        return Err(format!("{identity} output exceeded bound"));
    }
    if stdout.secret || stderr.secret {
        return Err(format!("{identity} emitted secret-bearing output"));
    }
    if !status.success() {
        return Err(format!("{identity} exited nonzero"));
    }
    let output =
        String::from_utf8(stdout.bytes).map_err(|_| format!("{identity} stdout is not UTF-8"))?;
    String::from_utf8(stderr.bytes).map_err(|_| format!("{identity} stderr is not UTF-8"))?;
    Ok(output)
}

fn sha256(identity: &'static str, path: &Path) -> Result<String, String> {
    let output = probe_text(identity, "sha256sum", [path.as_os_str()], PROBE_TIMEOUT)?;
    let digest = output
        .split_whitespace()
        .next()
        .ok_or_else(|| format!("{identity} output is empty"))?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{identity} output is malformed"));
    }
    Ok(digest.to_ascii_lowercase())
}

fn spawn_worker<T: Send + 'static>(
    operation: impl FnOnce() -> T + Send + 'static,
) -> Result<JoinHandle<T>, String> {
    ACTIVE_WORKERS.fetch_add(1, Ordering::SeqCst);
    thread::Builder::new()
        .spawn(move || {
            let _owner = WorkerOwner;
            operation()
        })
        .map_err(|error| {
            ACTIVE_WORKERS.fetch_sub(1, Ordering::SeqCst);
            clean_io(error)
        })
}

struct WorkerOwner;

impl Drop for WorkerOwner {
    fn drop(&mut self) {
        ACTIVE_WORKERS.fetch_sub(1, Ordering::SeqCst);
    }
}

fn join_worker<T>(worker: JoinHandle<T>) -> Result<T, String> {
    worker
        .join()
        .map_err(|_| "owned worker panicked".to_owned())
}

fn join_unit_workers(workers: Vec<JoinHandle<Result<(), String>>>) -> Result<(), String> {
    let mut first_error = None;
    for worker in workers {
        if let Err(error) = join_worker(worker).and_then(|result| result) {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn wait_for_sample_slot(slot: Instant, next_slot: Instant) -> Result<(), String> {
    let delay = sample_slot_delay(Instant::now(), slot, next_slot)?;
    thread::sleep(delay);
    remaining(next_slot).map(|_| ())
}

fn sample_slot_delay(now: Instant, slot: Instant, next_slot: Instant) -> Result<Duration, String> {
    if slot < now || slot >= next_slot {
        return Err("resource sample slot was missed".to_owned());
    }
    Ok(slot.duration_since(now))
}

fn repository_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "repository root is unavailable".to_owned())
}

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("required hosted identity is missing: {name}"))
}

fn first_line(text: &str) -> String {
    text.lines()
        .next()
        .unwrap_or("missing")
        .chars()
        .take(512)
        .collect()
}

fn json(text: &str) -> String {
    let mut output = String::with_capacity(text.len() + 2);
    output.push('"');
    for character in text.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => output.push('?'),
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn clean_io(error: impl std::fmt::Display) -> String {
    format!("I/O operation failed: {error}")
}
