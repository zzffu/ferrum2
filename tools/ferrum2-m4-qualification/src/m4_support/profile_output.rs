use std::ffi::OsStr;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::evidence_support::Evidence;
use super::process_support::{ProcessGuard, StartGate, json};
use super::profile_contract::{
    EVIDENCE_LINE_MAX_BYTES, ProfileArgs, ProfileOutcome, ProfileRawIdentity, ProfileScenario,
    TCP_SCALE_EVIDENCE_LINE_MAX_BYTES, profile_raw_prefix, resolve_profile_ready_file,
};
use super::profile_dns::run_profile_dns;
use super::profile_tcp::run_profile_tcp;
use super::profile_udp::run_profile_udp;
use super::self_check::assert_no_owners;
use super::tcp_scale;

pub(super) fn run_profile_scenario(arguments: &ProfileArgs) -> Result<ProfileOutcome, String> {
    let ready_file = resolve_profile_ready_file(&arguments.repository_root, &arguments.ready_file)?;
    match arguments.scenario {
        ProfileScenario::TcpBulk
        | ProfileScenario::TcpStream64k
        | ProfileScenario::TcpRequest1k
        | ProfileScenario::TcpRequest4k
        | ProfileScenario::TcpRequest16k => run_profile_tcp(arguments, &ready_file),
        ProfileScenario::DnsUdpConcurrency => run_profile_dns(arguments, &ready_file),
        ProfileScenario::TcpScale10k => tcp_scale::run_scale(arguments, &ready_file),
        ProfileScenario::UdpSmallHigh
        | ProfileScenario::UdpMtu1200
        | ProfileScenario::UdpPayload1472
        | ProfileScenario::UdpPayload1500
        | ProfileScenario::UdpPayload8192
        | ProfileScenario::UdpMaxWire65507
        | ProfileScenario::UdpDirectSmall128
        | ProfileScenario::UdpDirectMax65497 => run_profile_udp(arguments, &ready_file),
    }
}

pub(super) fn run_profile_workload(mut arguments: ProfileArgs) -> Result<String, String> {
    let raw = arguments.raw.take();
    let raw_identity = raw.as_ref().map(|raw| {
        ProfileRawIdentity::load(raw, &arguments.repository_root, &arguments.binary_dir)
    });
    let mut evidence = if let Some(raw) = &raw {
        let output = resolve_profile_ready_file(&arguments.repository_root, &raw.output)?;
        if output.extension() != Some(OsStr::new("jsonl")) {
            return Err("profile --output must name a JSONL file below profiles/".to_owned());
        }
        Some(Evidence::create(&output)?)
    } else {
        None
    };
    let raw_identity = match (raw.as_ref(), raw_identity) {
        (Some(_), Some(Ok(identity))) => Some(identity),
        (Some(raw), Some(Err(error))) => {
            evidence
                .as_mut()
                .expect("raw evidence owner")
                .line(format!(
                    "{{{},\"correctness\":\"FAIL\",\"status\":\"FAIL\",\"error\":{}}}",
                    profile_raw_prefix(&arguments, raw),
                    json(&error),
                ))?;
            evidence.take().expect("raw evidence owner").finish()?;
            return Err(error);
        }
        (None, None) => None,
        _ => unreachable!("raw identity follows raw arguments"),
    };
    let result = run_profile_scenario(&arguments);
    let owners = assert_no_owners();
    let result = match (result, owners) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(owner_error)) => Err(owner_error),
        (Err(error), Err(owner_error)) => Err(format!("{error}; cleanup: {owner_error}")),
    };
    if let (Some(raw), Some(mut evidence), Some(identity)) =
        (raw.as_ref(), evidence.take(), raw_identity.as_ref())
    {
        let prefix = profile_raw_prefix(&arguments, raw);
        match &result {
            Ok(outcome) => {
                let scale = outcome.scale_json.as_deref().unwrap_or("null");
                let line = format!(
                    "{{{prefix},\"sha\":{},\"tree\":{},\"runner_sha256\":{},\
                 \"client_sha256\":{},\"server_sha256\":{},\"rustc\":{},\"kernel\":{},\
                 \"cpu_model\":{},\"cpu_count\":{},\"memory_kib\":{},\"metric\":{},\
                 \"value\":{},\"checked_units\":{},\"p99_nanoseconds\":{},\
                 \"io_completions\":{},\"scale\":{scale},\
                 \"environment_identity\":{{\"runner_image\":{},\"rustc\":{},\"kernel\":{},\
                 \"cpu_model\":{},\"cpu_count\":{},\"memory_kib\":{},\"build_profile\":{}}},\
                 \"cleanup\":{{\"active_processes\":0,\"active_workers\":0,\
                 \"ready_file_removed\":true,\"status\":\"PASS\"}},\"correctness\":\"PASS\",\
                 \"status\":\"PASS\"}}",
                    json(&identity.sha),
                    json(&identity.tree),
                    json(&identity.runner_sha256),
                    json(&identity.client_sha256),
                    json(&identity.server_sha256),
                    json(&identity.rustc),
                    json(&identity.kernel),
                    json(&identity.cpu_model),
                    identity.cpu_count,
                    identity.memory_kib,
                    json(outcome.metric),
                    outcome.value,
                    outcome.checked_units,
                    outcome
                        .p99_nanoseconds
                        .map_or_else(|| "null".to_owned(), |value| value.to_string()),
                    outcome.io_completions,
                    json(&raw.runner_image),
                    json(&identity.rustc),
                    json(&identity.kernel),
                    json(&identity.cpu_model),
                    identity.cpu_count,
                    identity.memory_kib,
                    json(&raw.build_profile),
                );
                let limit = if arguments.scenario == ProfileScenario::TcpScale10k {
                    TCP_SCALE_EVIDENCE_LINE_MAX_BYTES
                } else {
                    EVIDENCE_LINE_MAX_BYTES
                };
                evidence.line_with_limit(line, limit)?;
            }
            Err(error) => evidence.line(format!(
                "{{{prefix},\"sha\":{},\"tree\":{},\"runner_sha256\":{},\
                 \"client_sha256\":{},\"server_sha256\":{},\"rustc\":{},\"kernel\":{},\
                 \"cpu_model\":{},\"cpu_count\":{},\"memory_kib\":{},\
                 \"correctness\":\"FAIL\",\"status\":\"FAIL\",\"error\":{}}}",
                json(&identity.sha),
                json(&identity.tree),
                json(&identity.runner_sha256),
                json(&identity.client_sha256),
                json(&identity.server_sha256),
                json(&identity.rustc),
                json(&identity.kernel),
                json(&identity.cpu_model),
                identity.cpu_count,
                identity.memory_kib,
                json(error),
            ))?,
        }
        evidence.finish()?;
    }
    result.map(|outcome| outcome.summary)
}

pub(super) fn wait_for_profile_phase<T>(
    client: &mut ProcessGuard,
    server: &mut ProcessGuard,
    gate: &StartGate,
    workers: &[JoinHandle<Result<T, String>>],
    deadline: Instant,
    require_running_at_deadline: bool,
) -> Result<(), String> {
    loop {
        client.ensure_running()?;
        server.ensure_running()?;
        let workers_running = ensure_profile_workers_running(gate, workers);
        let now = Instant::now();
        if now >= deadline && !require_running_at_deadline {
            gate.require_active()?;
            return Ok(());
        }
        workers_running?;
        if now >= deadline {
            return Ok(());
        }
        thread::sleep((deadline - now).min(Duration::from_millis(20)));
    }
}

pub(super) fn wait_for_profile_phase_optional_server<T>(
    client: &mut ProcessGuard,
    mut server: Option<&mut ProcessGuard>,
    gate: &StartGate,
    workers: &[JoinHandle<Result<T, String>>],
    deadline: Instant,
    require_running_at_deadline: bool,
) -> Result<(), String> {
    loop {
        client.ensure_running()?;
        if let Some(process) = server.as_deref_mut() {
            process.ensure_running()?;
        }
        let workers_running = ensure_profile_workers_running(gate, workers);
        let now = Instant::now();
        if now >= deadline && !require_running_at_deadline {
            gate.require_active()?;
            return Ok(());
        }
        workers_running?;
        if now >= deadline {
            return Ok(());
        }
        thread::sleep((deadline - now).min(Duration::from_millis(20)));
    }
}

pub(super) fn ensure_profile_workers_running<T>(
    gate: &StartGate,
    workers: &[JoinHandle<Result<T, String>>],
) -> Result<(), String> {
    gate.require_active()?;
    if workers.iter().any(JoinHandle::is_finished) {
        return Err("profile load worker ended early".to_owned());
    }
    Ok(())
}

pub(super) enum ProfileTcpWorkerResult {
    Bytes(u64),
    Latencies(Vec<u64>),
}
