use std::ffi::{OsStr, OsString};
use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::json;

use super::STREAMS;
use super::dns_resource::prove_tcp_rebind;
use super::evidence_support::{Evidence, PortReservation, profile_binary, spawn_proxy};
use super::process_support::{
    IO_TIMEOUT, PROBE_TIMEOUT, ProcessGuard, STARTUP_TIMEOUT, StartGate, TargetWorker,
    active_metric, clean_io, first_line, is_repository_root, join_worker, probe_text, sha256,
    spawn_worker, v4, wait_for_listener, wait_for_metrics,
};
use super::profile_contract::Topology;
use super::profile_output::wait_for_profile_phase_optional_server;
use super::proxy_config::{ferrum_client_config, ferrum_server_config};
use super::self_check::assert_no_owners;
use super::structural_contract::{
    STRUCTURAL_KIND, STRUCTURAL_SCENARIO, STRUCTURAL_SCHEMA_VERSION, StructuralMeasurement,
    StructuralSnapshot, capture, counter_schema_json, measure,
};
use super::throughput::load_tcp_stream;

const STRUCTURAL_EVIDENCE_MAX_BYTES: usize = 256 * 1024;
const STRUCTURAL_WARMUP_SECONDS: std::ops::RangeInclusive<u64> = 1..=10;
const STRUCTURAL_ACTIVE_SECONDS: std::ops::RangeInclusive<u64> = 1..=60;

pub(super) struct StructuralArgs {
    repository_root: PathBuf,
    binary_dir: PathBuf,
    output: PathBuf,
    candidate_sha: String,
    warmup_seconds: u64,
    active_seconds: u64,
}

struct StructuralIdentity {
    candidate_sha: String,
    tree_sha: String,
    runner_sha256: String,
    client_sha256: String,
    server_sha256: String,
}

struct StructuralRun {
    measurement: StructuralMeasurement,
    checked_bytes: u64,
}

pub(super) fn run(arguments: &[OsString]) -> Result<String, String> {
    let arguments = StructuralArgs::parse(arguments)?;
    let identity = StructuralIdentity::load(&arguments)?;
    let mut evidence = Evidence::create(&arguments.output)?;
    let result = run_workload(&arguments);
    let owners = assert_no_owners();
    let result = match (result, owners) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(owner_error)) => Err(owner_error),
        (Err(error), Err(owner_error)) => Err(format!("{error}; cleanup: {owner_error}")),
    }?;
    validate_tcp_fused_evidence(&result.measurement)?;
    let line = evidence_json(&arguments, &identity, &result)?;
    evidence.line_with_limit(line, STRUCTURAL_EVIDENCE_MAX_BYTES)?;
    evidence.finish()?;
    Ok(format!(
        "m18_structural_diagnostic status=PASS schema_version={} scenario={} checked_bytes={} performance_authoritative=false performance_adoption_allowed=false",
        STRUCTURAL_SCHEMA_VERSION, STRUCTURAL_SCENARIO, result.checked_bytes,
    ))
}

impl StructuralArgs {
    fn parse(arguments: &[OsString]) -> Result<Self, String> {
        let mut repository_root = None;
        let mut binary_dir = None;
        let mut output = None;
        let mut candidate_sha = None;
        let mut warmup_seconds = None;
        let mut active_seconds = None;
        let mut chunks = arguments.chunks_exact(2);
        for pair in &mut chunks {
            let flag = pair[0]
                .to_str()
                .ok_or_else(|| "structural option name is not UTF-8".to_owned())?;
            let slot = match flag {
                "--repository-root" => &mut repository_root,
                "--binary-dir" => &mut binary_dir,
                "--output" => &mut output,
                "--candidate-sha" => &mut candidate_sha,
                "--warmup-seconds" => &mut warmup_seconds,
                "--active-seconds" => &mut active_seconds,
                _ => return Err(format!("unsupported structural option: {flag}")),
            };
            if slot.replace(pair[1].clone()).is_some() {
                return Err(format!("duplicate structural option: {flag}"));
            }
        }
        if !chunks.remainder().is_empty() {
            return Err("every structural option requires one value".to_owned());
        }

        let repository_root = required_path(repository_root, "--repository-root")?;
        let binary_dir = required_path(binary_dir, "--binary-dir")?;
        if !repository_root.is_absolute() || !binary_dir.is_absolute() {
            return Err("structural repository and binary paths must be absolute".to_owned());
        }
        let repository_root = repository_root
            .canonicalize()
            .map_err(|_| "structural repository root is unavailable".to_owned())?;
        let binary_dir = binary_dir
            .canonicalize()
            .map_err(|_| "structural binary directory is unavailable".to_owned())?;
        if !is_repository_root(&repository_root) {
            return Err("structural repository root is invalid".to_owned());
        }
        let expected_binary_dir = repository_root
            .join("target/structural-diagnostic/profiling")
            .canonicalize()
            .map_err(|_| "independent structural target directory is unavailable".to_owned())?;
        if binary_dir != expected_binary_dir {
            return Err("--binary-dir must use target/structural-diagnostic/profiling".to_owned());
        }

        let output = required_path(output, "--output")?;
        if !output.is_absolute() || output.extension() != Some(OsStr::new("json")) {
            return Err("structural --output must be an absolute JSON path".to_owned());
        }
        if fs::symlink_metadata(&output).is_ok() {
            return Err("structural output already exists".to_owned());
        }
        let output_parent = output
            .parent()
            .ok_or_else(|| "structural output has no parent".to_owned())?
            .canonicalize()
            .map_err(|_| "structural output parent is unavailable".to_owned())?;
        let output = output_parent.join(
            output
                .file_name()
                .ok_or_else(|| "structural output has no file name".to_owned())?,
        );

        let candidate_sha = required_text(candidate_sha, "--candidate-sha")?;
        if candidate_sha.len() != 40
            || !candidate_sha
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("--candidate-sha must be a lowercase 40-character SHA".to_owned());
        }
        let warmup_seconds = bounded_seconds(
            warmup_seconds,
            "--warmup-seconds",
            &STRUCTURAL_WARMUP_SECONDS,
        )?;
        let active_seconds = bounded_seconds(
            active_seconds,
            "--active-seconds",
            &STRUCTURAL_ACTIVE_SECONDS,
        )?;
        Ok(Self {
            repository_root,
            binary_dir,
            output,
            candidate_sha,
            warmup_seconds,
            active_seconds,
        })
    }
}

fn required_path(value: Option<OsString>, name: &str) -> Result<PathBuf, String> {
    value
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {name}"))
}

fn required_text(value: Option<OsString>, name: &str) -> Result<String, String> {
    value
        .ok_or_else(|| format!("missing {name}"))?
        .into_string()
        .map_err(|_| format!("{name} is not UTF-8"))
}

fn bounded_seconds(
    value: Option<OsString>,
    name: &str,
    bounds: &std::ops::RangeInclusive<u64>,
) -> Result<u64, String> {
    let value = required_text(value, name)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{name} must be an integer"));
    }
    value
        .parse()
        .ok()
        .filter(|value| bounds.contains(value))
        .ok_or_else(|| format!("{name} is outside its finite bound"))
}

impl StructuralIdentity {
    fn load(arguments: &StructuralArgs) -> Result<Self, String> {
        let root = arguments
            .repository_root
            .to_str()
            .ok_or_else(|| "structural repository root is not UTF-8".to_owned())?;
        let git = |identity, command: &str| {
            probe_text(
                identity,
                "git",
                ["-C", root, "rev-parse", command],
                PROBE_TIMEOUT,
            )
        };
        let candidate_sha = first_line(&git("structural HEAD probe", "HEAD")?);
        if candidate_sha != arguments.candidate_sha {
            return Err("structural checkout HEAD does not match candidate SHA".to_owned());
        }
        let status = probe_text(
            "structural checkout status probe",
            "git",
            ["-C", root, "status", "--porcelain=v1"],
            PROBE_TIMEOUT,
        )?;
        if !status.is_empty() {
            return Err("structural checkout is dirty before evidence collection".to_owned());
        }
        let tree_sha = first_line(&git("structural tree probe", "HEAD^{tree}")?);
        let runner = std::env::current_exe()
            .and_then(|path| path.canonicalize())
            .map_err(clean_io)?;
        let expected_runner = profile_binary(&arguments.binary_dir, "m4-qualification")?
            .canonicalize()
            .map_err(clean_io)?;
        if runner != expected_runner {
            return Err("structural runner is outside the independent target directory".to_owned());
        }
        let client = profile_binary(&arguments.binary_dir, "ferrum2-client")?;
        let server = profile_binary(&arguments.binary_dir, "ferrum2-server")?;
        Ok(Self {
            candidate_sha,
            tree_sha,
            runner_sha256: sha256("structural runner SHA-256 probe", &runner)?,
            client_sha256: sha256("structural client SHA-256 probe", &client)?,
            server_sha256: sha256("structural server SHA-256 probe", &server)?,
        })
    }
}

fn run_workload(arguments: &StructuralArgs) -> Result<StructuralRun, String> {
    let mut directory = Some(
        tempfile::Builder::new()
            .prefix("structural-diagnostic-")
            .tempdir()
            .map_err(clean_io)?,
    );
    let (target_listener, target) = bind_target()?;
    let mut target_listener = Some(target_listener);
    let mut server_reservation = Some(PortReservation::new()?);
    let mut proxy_reservation = Some(PortReservation::new()?);
    let mut server_metrics_reservation = Some(PortReservation::new()?);
    let mut client_metrics_reservation = Some(PortReservation::new()?);
    let server = server_reservation
        .as_ref()
        .expect("server reservation")
        .address;
    let proxy = proxy_reservation
        .as_ref()
        .expect("proxy reservation")
        .address;
    let server_metrics = server_metrics_reservation
        .as_ref()
        .expect("server metrics reservation")
        .address;
    let client_metrics = client_metrics_reservation
        .as_ref()
        .expect("client metrics reservation")
        .address;
    let client_config = directory
        .as_ref()
        .expect("structural config owner")
        .path()
        .join("client.toml");
    let server_config = directory
        .as_ref()
        .expect("structural config owner")
        .path()
        .join("server.toml");
    let gate = Arc::new(StartGate::default());
    let stop = Arc::new(AtomicBool::new(false));
    let warmup = Duration::from_secs(arguments.warmup_seconds);
    let active = Duration::from_secs(arguments.active_seconds);
    let mut target_worker = None;
    let mut server_process = None;
    let mut client_process = None;
    let mut workers = Vec::with_capacity(STREAMS);
    let mut errors = Vec::new();
    let mut started = false;
    let mut before: Option<(StructuralSnapshot, StructuralSnapshot)> = None;
    let mut after: Option<(StructuralSnapshot, StructuralSnapshot)> = None;
    let execution = (|| -> Result<(), String> {
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
        let client_binary = profile_binary(&arguments.binary_dir, "ferrum2-client")?;
        let server_binary = profile_binary(&arguments.binary_dir, "ferrum2-server")?;
        target_worker = Some(TargetWorker::echo(
            target_listener.take().expect("target listener"),
            STREAMS,
        )?);

        server_reservation
            .take()
            .expect("server reservation")
            .release();
        server_metrics_reservation
            .take()
            .expect("server metrics reservation")
            .release();
        server_process = Some(spawn_proxy(
            Topology::Ferrum,
            "structural diagnostic server",
            &server_binary,
            &server_config,
        )?);
        wait_for_listener(server_process.as_mut().expect("server process"), server)?;
        wait_for_metrics(
            server_process.as_mut().expect("server process"),
            server_metrics,
        )?;

        proxy_reservation
            .take()
            .expect("proxy reservation")
            .release();
        client_metrics_reservation
            .take()
            .expect("client metrics reservation")
            .release();
        client_process = Some(spawn_proxy(
            Topology::Ferrum,
            "structural diagnostic client",
            &client_binary,
            &client_config,
        )?);
        wait_for_listener(client_process.as_mut().expect("client process"), proxy)?;
        wait_for_metrics(
            client_process.as_mut().expect("client process"),
            client_metrics,
        )?;

        let baseline_deadline = Instant::now() + IO_TIMEOUT;
        let client_before = capture(client_metrics, baseline_deadline)?;
        let server_before = capture(server_metrics, baseline_deadline)?;
        if client_before.overflowed || server_before.overflowed {
            return Err("structural baseline overflow invalidates the diagnostic".to_owned());
        }
        before = Some((client_before, server_before));
        for _ in 0..STREAMS {
            let worker_gate = Arc::clone(&gate);
            let failure_gate = Arc::clone(&gate);
            let worker_stop = Arc::clone(&stop);
            let failure_stop = Arc::clone(&stop);
            workers.push(spawn_worker(move || {
                let result =
                    load_tcp_stream(proxy, target, worker_gate, worker_stop, warmup, active);
                if result.is_err() {
                    failure_stop.store(true, Ordering::SeqCst);
                    failure_gate.cancel();
                }
                result
            })?);
        }
        let start = gate.start_when_ready(STREAMS, Instant::now() + STARTUP_TIMEOUT)?;
        started = true;
        let warm_end = start + warmup;
        let active_end = warm_end + active;
        wait_for_profile_phase_optional_server(
            client_process.as_mut().expect("client process"),
            server_process.as_mut(),
            &gate,
            &workers,
            warm_end,
            true,
        )?;
        gate.require_validated(STREAMS)?;
        wait_for_profile_phase_optional_server(
            client_process.as_mut().expect("client process"),
            server_process.as_mut(),
            &gate,
            &workers,
            active_end,
            false,
        )
    })();
    let execution_succeeded = execution.is_ok();
    if let Err(error) = execution {
        errors.push(error);
    }
    stop.store(true, Ordering::SeqCst);
    gate.cancel();
    let mut checked_bytes = 0_u64;
    for worker in workers {
        match join_worker(worker).and_then(|result| result) {
            Ok(bytes) => match checked_bytes.checked_add(bytes) {
                Some(total) => checked_bytes = total,
                None => errors.push("structural checked byte count overflow".to_owned()),
            },
            Err(error) => errors.push(error),
        }
    }
    if execution_succeeded && checked_bytes == 0 {
        errors.push("structural workload completed no validated bytes".to_owned());
    }
    if execution_succeeded {
        let drain_deadline = Instant::now() + STARTUP_TIMEOUT;
        for (process, metrics, label) in [
            (
                client_process.as_mut().expect("client process"),
                client_metrics,
                "client",
            ),
            (
                server_process.as_mut().expect("server process"),
                server_metrics,
                "server",
            ),
        ] {
            if let Err(error) = wait_for_zero_active(process, metrics, drain_deadline, label) {
                errors.push(error);
            }
        }
        if errors.is_empty() {
            let snapshot_deadline = Instant::now() + IO_TIMEOUT;
            match (
                capture(client_metrics, snapshot_deadline),
                capture(server_metrics, snapshot_deadline),
            ) {
                (Ok(client), Ok(server)) => after = Some((client, server)),
                (Err(error), _) | (_, Err(error)) => errors.push(error),
            }
        }
    }
    if started {
        if let Some(worker) = target_worker.take()
            && let Err(error) = worker.finish()
        {
            errors.push(format!("structural target cleanup failed: {error}"));
        }
    } else {
        drop(target_worker.take());
    }
    for process in [&mut client_process, &mut server_process] {
        if let Some(process) = process.as_mut()
            && let Err(error) = process.terminate()
        {
            errors.push(format!("structural process cleanup failed: {error}"));
        }
    }
    drop((client_process.take(), server_process.take()));
    drop((
        proxy_reservation.take(),
        server_reservation.take(),
        client_metrics_reservation.take(),
        server_metrics_reservation.take(),
    ));
    drop(target_listener.take());
    if let Some(directory) = directory.take()
        && let Err(error) = directory.close().map_err(clean_io)
    {
        errors.push(format!("structural config cleanup failed: {error}"));
    }
    for (address, label) in [
        (proxy, "structural client"),
        (server, "structural server"),
        (target, "structural target"),
        (client_metrics, "structural client metrics"),
        (server_metrics, "structural server metrics"),
    ] {
        if let Err(error) = prove_tcp_rebind(address, label) {
            errors.push(format!("structural rebind failed: {error}"));
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    let (client_before, server_before) = before.expect("successful structural baseline");
    let (client_after, server_after) = after.expect("successful structural final snapshot");
    Ok(StructuralRun {
        measurement: measure(client_before, client_after, server_before, server_after)?,
        checked_bytes,
    })
}

fn bind_target() -> Result<(TcpListener, SocketAddrV4), String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
    let address = v4(listener.local_addr().map_err(clean_io)?)?;
    Ok((listener, address))
}

fn wait_for_zero_active(
    process: &mut ProcessGuard,
    metrics: SocketAddrV4,
    deadline: Instant,
    label: &str,
) -> Result<(), String> {
    loop {
        process.ensure_running()?;
        if active_metric(metrics, deadline)? == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("structural {label} connection drain timed out"));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn validate_tcp_fused_evidence(measurement: &StructuralMeasurement) -> Result<(), String> {
    let merged = &measurement.merged_delta;
    for name in [
        "tcp_plain_to_encrypt_copy_bytes",
        "tcp_decrypt_to_plain_copy_bytes",
    ] {
        if merged[name] != 0 {
            return Err(format!("structural zero-copy assertion failed: {name}"));
        }
    }
    for name in [
        "tcp_fused_fast_path_connections",
        "tcp_fused_owned_upload_frames",
        "tcp_fused_borrowed_download_frames",
        "tcp_fused_frames",
        "tcp_fused_encrypt_buffer_capacity_bytes",
        "tcp_fused_decrypt_buffer_capacity_bytes",
        "tcp_fused_relay_buffer_capacity_removed_bytes",
    ] {
        if merged[name] == 0 {
            return Err(format!("structural fused-path evidence is absent: {name}"));
        }
    }
    for name in [
        "tcp_fused_fallback_direct_connections",
        "tcp_fused_fallback_multi_hop_connections",
        "tcp_fused_fallback_tun_connections",
        "tcp_fused_fallback_dns_connections",
        "tcp_fused_fallback_rule_set_connections",
        "tcp_fused_fallback_server_non_direct_connections",
        "tcp_fused_fallback_unsupported_flow_connections",
    ] {
        if merged[name] != 0 {
            return Err(format!(
                "structural fused-path fallback was observed: {name}"
            ));
        }
    }
    Ok(())
}

fn evidence_json(
    arguments: &StructuralArgs,
    identity: &StructuralIdentity,
    result: &StructuralRun,
) -> Result<String, String> {
    let measurement = &result.measurement;
    serde_json::to_string(&json!({
        "schema_version": STRUCTURAL_SCHEMA_VERSION,
        "kind": STRUCTURAL_KIND,
        "candidate_sha": identity.candidate_sha,
        "tree_sha": identity.tree_sha,
        "runner_sha256": identity.runner_sha256,
        "client_sha256": identity.client_sha256,
        "server_sha256": identity.server_sha256,
        "scenario": STRUCTURAL_SCENARIO,
        "warmup_seconds": arguments.warmup_seconds,
        "active_seconds": arguments.active_seconds,
        "build_profile": "profiling-structural-metrics",
        "performance_authoritative": false,
        "performance_adoption_allowed": false,
        "counter_schema": counter_schema_json(),
        "snapshots": {
            "client": {
                "before": measurement.client_before.values,
                "after": measurement.client_after.values,
            },
            "server": {
                "before": measurement.server_before.values,
                "after": measurement.server_after.values,
            },
        },
        "overflow": {
            "client_before": measurement.client_before.overflowed,
            "client_after": measurement.client_after.overflowed,
            "server_before": measurement.server_before.overflowed,
            "server_after": measurement.server_after.overflowed,
            "any": measurement.client_before.overflowed
                || measurement.client_after.overflowed
                || measurement.server_before.overflowed
                || measurement.server_after.overflowed,
        },
        "deltas": {
            "client": measurement.client_delta,
            "server": measurement.server_delta,
            "merged": measurement.merged_delta,
        },
        "workload": {"checked_bytes": result.checked_bytes, "workers": STREAMS},
        "cleanup": {
            "active_processes": 0,
            "active_workers": 0,
            "rebind_status": "PASS",
            "status": "PASS",
        },
        "correctness": "PASS",
        "status": "PASS",
    }))
    .map_err(|_| "structural evidence could not be encoded".to_owned())
}

pub(super) fn run_self_check() -> Result<(), String> {
    let root = tempfile::tempdir().map_err(clean_io)?;
    fs::write(root.path().join("Cargo.toml"), "[workspace]\n").map_err(clean_io)?;
    fs::write(root.path().join("Cargo.lock"), "").map_err(clean_io)?;
    fs::create_dir_all(root.path().join("tools/ferrum2-m4-qualification")).map_err(clean_io)?;
    fs::write(
        root.path()
            .join("tools/ferrum2-m4-qualification/Cargo.toml"),
        "[package]\nname='fixture'\nversion='0.0.0'\n",
    )
    .map_err(clean_io)?;
    let binary_dir = root.path().join("target/structural-diagnostic/profiling");
    fs::create_dir_all(&binary_dir).map_err(clean_io)?;
    let output_dir = tempfile::tempdir().map_err(clean_io)?;
    let arguments: Vec<OsString> = [
        OsString::from("--repository-root"),
        root.path().as_os_str().to_owned(),
        OsString::from("--binary-dir"),
        binary_dir.as_os_str().to_owned(),
        OsString::from("--output"),
        output_dir.path().join("evidence.json").into_os_string(),
        OsString::from("--candidate-sha"),
        OsString::from("0123456789abcdef0123456789abcdef01234567"),
        OsString::from("--warmup-seconds"),
        OsString::from("1"),
        OsString::from("--active-seconds"),
        OsString::from("15"),
    ]
    .into_iter()
    .collect();
    let parsed = StructuralArgs::parse(&arguments)?;
    if parsed.warmup_seconds != 1 || parsed.active_seconds != 15 {
        return Err("structural arguments did not preserve bounded timing".to_owned());
    }
    expect_rejected("shared target directory", || {
        let mut mutated = arguments.clone();
        let index = mutated
            .iter()
            .position(|value| value == "--binary-dir")
            .expect("binary directory option");
        mutated[index + 1] = root.path().into();
        StructuralArgs::parse(&mutated)
    })?;
    expect_rejected("non-JSON output", || {
        let mut mutated = arguments.clone();
        let index = mutated
            .iter()
            .position(|value| value == "--output")
            .expect("output option");
        mutated[index + 1] = output_dir.path().join("evidence.jsonl").into_os_string();
        StructuralArgs::parse(&mutated)
    })?;
    Ok(())
}

fn expect_rejected<T>(
    name: &str,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<(), String> {
    if operation().is_ok() {
        return Err(format!("structural diagnostic mutation survived: {name}"));
    }
    Ok(())
}
