use std::ffi::OsString;
use std::fs;
use std::path::{Component, PathBuf};
use std::time::Duration;

use ferrum2_structural::StructuralCounter;
use serde_json::{Map, Value, json};

use super::evidence_support::Evidence;
use super::process_support::json as json_string;
use super::profile_contract::{
    ProfileArgs, ProfileMember, ProfileRawArgs, ProfileRawIdentity, ProfileScenario,
    resolve_profile_ready_file,
};
use super::profile_udp::{ProcessDiagnosticDelta, UdpWorkerProfileRun, run_udp_worker_profile};
use super::self_check::assert_no_owners;
use super::structural_contract::{
    STRUCTURAL_AGGREGATION, STRUCTURAL_SCHEMA_VERSION, StructuralMeasurement, counter_schema_json,
};

const UDP_WORKER_SCHEMA_VERSION: u8 = 1;
const UDP_WORKER_KIND: &str = "ferrum2_udp_worker_trial";
const UDP_WORKER_SCENARIO: &str = "udp-small-high";
const UDP_WORKER_WARMUP_SECONDS: u64 = 3;
const UDP_WORKER_ACTIVE_SECONDS: u64 = 15;
const UDP_WORKER_BUILD_PROFILE: &str = "profiling-structural-metrics";
const UDP_WORKER_RUNNER_IMAGE: &str = "ubuntu-24.04";
const UDP_WORKER_EVIDENCE_MAX_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionTopology {
    SameSession,
    MultiSession,
}

impl SessionTopology {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "same-session" => Ok(Self::SameSession),
            "multi-session" => Ok(Self::MultiSession),
            _ => Err("--session-topology must be same-session or multi-session".to_owned()),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::SameSession => "same-session",
            Self::MultiSession => "multi-session",
        }
    }

    const fn logical_sessions(self) -> usize {
        match self {
            Self::SameSession => 1,
            Self::MultiSession => 32,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrialPhase {
    CalibrationAa,
    Comparison,
}

impl TrialPhase {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "calibration-aa" => Ok(Self::CalibrationAa),
            "comparison" => Ok(Self::Comparison),
            _ => Err("--phase must be calibration-aa or comparison".to_owned()),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::CalibrationAa => "calibration-aa",
            Self::Comparison => "comparison",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AxisMember {
    Baseline,
    Variant,
}

impl AxisMember {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "baseline" => Ok(Self::Baseline),
            "variant" => Ok(Self::Variant),
            _ => Err("--member must be baseline or variant".to_owned()),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Variant => "variant",
        }
    }
}

struct UdpWorkerArgs {
    server_receive_workers: usize,
    comparison_receive_workers: usize,
    session_topology: SessionTopology,
    phase: TrialPhase,
    member: AxisMember,
    round: u8,
    pair: u8,
    order: u8,
    output: PathBuf,
    ready_file: PathBuf,
    repository_root: PathBuf,
    binary_dir: PathBuf,
    candidate_sha: String,
    runner_image: String,
    producer_source_sha256: String,
    controller_source_sha256: String,
    semantic_recipe_sha256: String,
    evidence_bundle_sha256: String,
}

pub(super) fn run(arguments: &[OsString]) -> Result<String, String> {
    let arguments = parse_args(arguments)?;
    let output = resolve_profile_ready_file(&arguments.repository_root, &arguments.output)?;
    if output.extension().and_then(|value| value.to_str()) != Some("json") {
        return Err("UDP worker --output must name a JSON file below profiles/".to_owned());
    }
    let ready = resolve_profile_ready_file(&arguments.repository_root, &arguments.ready_file)?;
    let raw_identity = profile_raw_identity(&arguments);
    let mut evidence = Evidence::create(&output)?;
    let identity = match ProfileRawIdentity::load(
        &raw_identity,
        &arguments.repository_root,
        &arguments.binary_dir,
    ) {
        Ok(identity) => identity,
        Err(error) => {
            evidence.line_with_limit(
                failure_json(&arguments, None, &error),
                UDP_WORKER_EVIDENCE_MAX_BYTES,
            )?;
            evidence.finish()?;
            return Err(error);
        }
    };
    let runner_parent = std::env::current_exe()
        .map_err(super::process_support::clean_io)?
        .parent()
        .expect("qualification binary parent")
        .canonicalize()
        .map_err(|_| "UDP worker runner directory is unavailable".to_owned())?;
    if runner_parent != arguments.binary_dir {
        let error = "UDP worker runner is outside the exact binary directory".to_owned();
        evidence.line_with_limit(
            failure_json(&arguments, Some(&identity), &error),
            UDP_WORKER_EVIDENCE_MAX_BYTES,
        )?;
        evidence.finish()?;
        return Err(error);
    }
    let cpu_vendor = match linux_cpu_vendor() {
        Ok(vendor) if vendor == "AuthenticAMD" => vendor,
        Ok(_) => {
            let error = "UDP worker qualification requires an AuthenticAMD host".to_owned();
            evidence.line_with_limit(
                failure_json(&arguments, Some(&identity), &error),
                UDP_WORKER_EVIDENCE_MAX_BYTES,
            )?;
            evidence.finish()?;
            return Err(error);
        }
        Err(error) => {
            evidence.line_with_limit(
                failure_json(&arguments, Some(&identity), &error),
                UDP_WORKER_EVIDENCE_MAX_BYTES,
            )?;
            evidence.finish()?;
            return Err(error);
        }
    };

    let profile = ProfileArgs {
        scenario: ProfileScenario::UdpSmallHigh,
        warmup_seconds: UDP_WORKER_WARMUP_SECONDS,
        active_seconds: UDP_WORKER_ACTIVE_SECONDS,
        ready_file: arguments.ready_file.clone(),
        repository_root: arguments.repository_root.clone(),
        binary_dir: arguments.binary_dir.clone(),
        raw: None,
    };
    let workload = run_udp_worker_profile(
        &profile,
        &ready,
        arguments.server_receive_workers,
        arguments.session_topology.logical_sessions(),
    );
    let owners = assert_no_owners();
    let workload = match (workload, owners) {
        (Ok(workload), Ok(())) => Ok(workload),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; cleanup: {cleanup}")),
    };
    match workload {
        Ok(workload) => {
            let record = match success_record(&arguments, &identity, &cpu_vendor, &workload) {
                Ok(record) => record,
                Err(error) => {
                    evidence.line_with_limit(
                        failure_json(&arguments, Some(&identity), &error),
                        UDP_WORKER_EVIDENCE_MAX_BYTES,
                    )?;
                    evidence.finish()?;
                    return Err(error);
                }
            };
            evidence.line_with_limit(
                serde_json::to_string(&record)
                    .map_err(|_| "UDP worker evidence could not be encoded".to_owned())?,
                UDP_WORKER_EVIDENCE_MAX_BYTES,
            )?;
            evidence.finish()?;
            Ok(format!(
                "udp_worker_workload status=PASS schema_version={} receive_workers={} session_topology={} datagrams={} performance_authoritative=false adoption_claim=false",
                UDP_WORKER_SCHEMA_VERSION,
                arguments.server_receive_workers,
                arguments.session_topology.label(),
                workload.outcome.checked_units,
            ))
        }
        Err(error) => {
            evidence.line_with_limit(
                failure_json(&arguments, Some(&identity), &error),
                UDP_WORKER_EVIDENCE_MAX_BYTES,
            )?;
            evidence.finish()?;
            Err(error)
        }
    }
}

fn parse_args(arguments: &[OsString]) -> Result<UdpWorkerArgs, String> {
    let mut values = std::collections::BTreeMap::new();
    let mut chunks = arguments.chunks_exact(2);
    for pair in &mut chunks {
        let flag = pair[0]
            .to_str()
            .ok_or_else(|| "UDP worker option name is not UTF-8".to_owned())?;
        if !matches!(
            flag,
            "--server-receive-workers"
                | "--comparison-receive-workers"
                | "--session-topology"
                | "--phase"
                | "--member"
                | "--round"
                | "--pair"
                | "--order"
                | "--output"
                | "--ready-file"
                | "--repository-root"
                | "--binary-dir"
                | "--candidate-sha"
                | "--runner-image"
                | "--producer-source-sha256"
                | "--controller-source-sha256"
                | "--semantic-recipe-sha256"
                | "--evidence-bundle-sha256"
        ) {
            return Err(format!("unsupported UDP worker option: {flag}"));
        }
        let value = pair[1]
            .to_str()
            .ok_or_else(|| format!("{flag} is not UTF-8"))?
            .to_owned();
        if values.insert(flag, value).is_some() {
            return Err(format!("duplicate UDP worker option: {flag}"));
        }
    }
    if !chunks.remainder().is_empty() {
        return Err("every UDP worker option requires one value".to_owned());
    }
    let required = |name: &'static str| {
        values
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("missing {name}"))
    };
    let bounded = |name: &'static str, allowed: &[usize]| {
        let value = required(name)?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!("{name} must be an integer"));
        }
        value
            .parse::<usize>()
            .ok()
            .filter(|value| allowed.contains(value))
            .ok_or_else(|| format!("{name} is outside its closed set"))
    };
    let server_receive_workers = bounded("--server-receive-workers", &[1, 2, 4, 8])?;
    let comparison_receive_workers = bounded("--comparison-receive-workers", &[1, 2, 4, 8])?;
    let phase = TrialPhase::parse(required("--phase")?)?;
    let member = AxisMember::parse(required("--member")?)?;
    let round = u8::try_from(bounded("--round", &[1, 2])?)
        .map_err(|_| "--round is outside its finite bound".to_owned())?;
    let pair = u8::try_from(bounded("--pair", &[1, 2, 3, 4, 5, 6])?)
        .map_err(|_| "--pair is outside its finite bound".to_owned())?;
    let order = u8::try_from(bounded("--order", &[1, 2])?)
        .map_err(|_| "--order is outside its finite bound".to_owned())?;
    if expected_member(pair, order) != member {
        return Err("UDP worker member does not match the fixed ABBA schedule".to_owned());
    }
    match phase {
        TrialPhase::CalibrationAa
            if comparison_receive_workers == 1
                && matches!(round, 1 | 2)
                && server_receive_workers == 1 => {}
        TrialPhase::Comparison
            if matches!(comparison_receive_workers, 2 | 4 | 8)
                && round == 1
                && server_receive_workers
                    == match member {
                        AxisMember::Baseline => 1,
                        AxisMember::Variant => comparison_receive_workers,
                    } => {}
        TrialPhase::CalibrationAa => {
            return Err("A/A requires two rounds of exact receive_workers=1".to_owned());
        }
        TrialPhase::Comparison => {
            return Err("comparison axis does not match baseline=1 and variant=2/4/8".to_owned());
        }
    }
    let repository_root = canonical_directory(required("--repository-root")?, "repository root")?;
    let binary_dir = canonical_directory(required("--binary-dir")?, "binary directory")?;
    let expected_binary_dir = repository_root
        .join("target/udp-worker/profiling")
        .canonicalize()
        .map_err(|_| "UDP worker exact target directory is unavailable".to_owned())?;
    if binary_dir != expected_binary_dir {
        return Err("--binary-dir must use target/udp-worker/profiling".to_owned());
    }
    let relative = |name: &'static str| -> Result<PathBuf, String> {
        let value = PathBuf::from(required(name)?);
        if value.is_absolute()
            || !value.starts_with("profiles")
            || value.components().count() < 2
            || value
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(format!("{name} must be a relative child of profiles/"));
        }
        Ok(value)
    };
    let candidate_sha = required("--candidate-sha")?.to_owned();
    validate_digest(&candidate_sha, 40, "--candidate-sha")?;
    let runner_image = required("--runner-image")?.to_owned();
    if runner_image != UDP_WORKER_RUNNER_IMAGE {
        return Err("--runner-image is outside the registered environment".to_owned());
    }
    let digest = |name: &'static str| {
        let value = required(name)?.to_owned();
        validate_digest(&value, 64, name)?;
        Ok::<String, String>(value)
    };
    let output = relative("--output")?;
    let ready_file = relative("--ready-file")?;
    if output == ready_file
        || output.extension().and_then(|value| value.to_str()) != Some("json")
        || ready_file.extension().and_then(|value| value.to_str()) != Some("ready")
    {
        return Err(
            "UDP worker output and ready-file paths are not distinct typed files".to_owned(),
        );
    }
    Ok(UdpWorkerArgs {
        server_receive_workers,
        comparison_receive_workers,
        session_topology: SessionTopology::parse(required("--session-topology")?)?,
        phase,
        member,
        round,
        pair,
        order,
        output,
        ready_file,
        repository_root,
        binary_dir,
        candidate_sha,
        runner_image,
        producer_source_sha256: digest("--producer-source-sha256")?,
        controller_source_sha256: digest("--controller-source-sha256")?,
        semantic_recipe_sha256: digest("--semantic-recipe-sha256")?,
        evidence_bundle_sha256: digest("--evidence-bundle-sha256")?,
    })
}

fn expected_member(pair: u8, order: u8) -> AxisMember {
    if (pair % 2 == 1) == (order == 1) {
        AxisMember::Baseline
    } else {
        AxisMember::Variant
    }
}

fn canonical_directory(value: &str, label: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("UDP worker {label} must be absolute"));
    }
    let path = path
        .canonicalize()
        .map_err(|_| format!("UDP worker {label} is unavailable"))?;
    if !path.is_dir() {
        return Err(format!("UDP worker {label} is not a directory"));
    }
    Ok(path)
}

fn validate_digest(value: &str, length: usize, name: &str) -> Result<(), String> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must be a lowercase hexadecimal digest"));
    }
    Ok(())
}

fn profile_raw_identity(arguments: &UdpWorkerArgs) -> ProfileRawArgs {
    ProfileRawArgs {
        output: arguments.output.clone(),
        parent_sha: arguments.candidate_sha.clone(),
        candidate_sha: arguments.candidate_sha.clone(),
        member: ProfileMember::Candidate,
        pair: arguments.pair,
        order: arguments.order,
        build_profile: UDP_WORKER_BUILD_PROFILE.to_owned(),
        unit: "datagrams_per_second".to_owned(),
        runner_image: arguments.runner_image.clone(),
        producer_source_sha256: arguments.producer_source_sha256.clone(),
        controller_source_sha256: arguments.controller_source_sha256.clone(),
        semantic_recipe_sha256: arguments.semantic_recipe_sha256.clone(),
        evidence_bundle_sha256: arguments.evidence_bundle_sha256.clone(),
    }
}

fn common_record(arguments: &UdpWorkerArgs) -> Map<String, Value> {
    let mut record = Map::new();
    record.insert(
        "schema_version".to_owned(),
        json!(UDP_WORKER_SCHEMA_VERSION),
    );
    record.insert("kind".to_owned(), json!(UDP_WORKER_KIND));
    record.insert("candidate_sha".to_owned(), json!(arguments.candidate_sha));
    record.insert("phase".to_owned(), json!(arguments.phase.label()));
    record.insert("round".to_owned(), json!(arguments.round));
    record.insert("pair".to_owned(), json!(arguments.pair));
    record.insert("order".to_owned(), json!(arguments.order));
    record.insert("member".to_owned(), json!(arguments.member.label()));
    record.insert(
        "comparison_receive_workers".to_owned(),
        json!(arguments.comparison_receive_workers),
    );
    record.insert(
        "axis".to_owned(),
        json!({
            "scenario": UDP_WORKER_SCENARIO,
            "topology": "shadowsocks",
            "server_receive_workers": arguments.server_receive_workers,
            "session_topology": arguments.session_topology.label(),
            "logical_sessions": arguments.session_topology.logical_sessions(),
            "application_payload_bytes": 128,
            "warmup_seconds": UDP_WORKER_WARMUP_SECONDS,
            "active_seconds": UDP_WORKER_ACTIVE_SECONDS,
            "unit": "datagrams_per_second",
            "config_axis": "server.udp.receive_workers",
        }),
    );
    record.insert(
        "source_identity".to_owned(),
        json!({
            "producer_source_sha256": arguments.producer_source_sha256,
            "controller_source_sha256": arguments.controller_source_sha256,
            "semantic_recipe_sha256": arguments.semantic_recipe_sha256,
            "evidence_bundle_sha256": arguments.evidence_bundle_sha256,
        }),
    );
    record.insert(
        "authority".to_owned(),
        json!({
            "scope": "github-hosted-amd-provisional",
            "performance_authoritative": false,
            "bare_metal_gate": false,
            "adoption_claim": false,
        }),
    );
    record
}

fn identity_json(identity: &ProfileRawIdentity, cpu_vendor: &str) -> Value {
    json!({
        "sha": identity.sha,
        "tree": identity.tree,
        "runner_sha256": identity.runner_sha256,
        "client_sha256": identity.client_sha256,
        "server_sha256": identity.server_sha256,
        "environment": {
            "runner_image": UDP_WORKER_RUNNER_IMAGE,
            "rustc": identity.rustc,
            "kernel": identity.kernel,
            "cpu_vendor": cpu_vendor,
            "cpu_model": identity.cpu_model,
            "cpu_count": identity.cpu_count,
            "memory_kib": identity.memory_kib,
            "build_profile": UDP_WORKER_BUILD_PROFILE,
        },
    })
}

fn success_record(
    arguments: &UdpWorkerArgs,
    identity: &ProfileRawIdentity,
    cpu_vendor: &str,
    workload: &UdpWorkerProfileRun,
) -> Result<Value, String> {
    let active_nanoseconds = Duration::from_secs(UDP_WORKER_ACTIVE_SECONDS).as_nanos();
    let combined_cpu = workload
        .diagnostics
        .client_process
        .cpu_nanoseconds
        .checked_add(workload.diagnostics.server_process.cpu_nanoseconds)
        .ok_or_else(|| "UDP worker combined CPU time overflow".to_owned())?;
    let cpu_core_millis = u128::from(combined_cpu)
        .checked_mul(1_000)
        .map(|value| value / active_nanoseconds)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| "UDP worker CPU/core observation overflow".to_owned())?;
    let p99 = workload
        .outcome
        .p99_nanoseconds
        .ok_or_else(|| "UDP worker p99 evidence is missing".to_owned())?;
    let mut record = common_record(arguments);
    record.insert("identity".to_owned(), identity_json(identity, cpu_vendor));
    record.insert(
        "metrics".to_owned(),
        json!({
            "datagrams_per_second": workload.outcome.value,
            "validated_datagrams": workload.outcome.checked_units,
            "p99_nanoseconds": p99,
            "p99_sample_count": workload.diagnostics.latency_sample_count,
            "combined_cpu_nanoseconds": combined_cpu,
            "combined_cpu_core_millis": cpu_core_millis,
            "client": process_delta_json(workload.diagnostics.client_process),
            "server": process_delta_json(workload.diagnostics.server_process),
        }),
    );
    record.insert(
        "hot_locks".to_owned(),
        hot_lock_json(&workload.diagnostics.structural)?,
    );
    record.insert(
        "structural".to_owned(),
        structural_json(&workload.diagnostics.structural),
    );
    record.insert(
        "cleanup".to_owned(),
        json!({
            "active_processes": 0,
            "active_workers": 0,
            "ready_file_removed": true,
            "status": "PASS",
        }),
    );
    record.insert("decision".to_owned(), json!("OBSERVATION_ONLY"));
    record.insert("correctness".to_owned(), json!("PASS"));
    record.insert("status".to_owned(), json!("PASS"));
    Ok(Value::Object(record))
}

fn process_delta_json(delta: ProcessDiagnosticDelta) -> Value {
    json!({
        "cpu_nanoseconds": delta.cpu_nanoseconds,
        "voluntary_context_switches": delta.voluntary_context_switches,
        "involuntary_context_switches": delta.involuntary_context_switches,
    })
}

fn hot_lock_json(measurement: &StructuralMeasurement) -> Result<Value, String> {
    let lock = |prefix: &str| -> Result<Value, String> {
        let value = |suffix: &str| {
            let name = format!("{prefix}_{suffix}");
            measurement
                .server_delta
                .get(&name)
                .copied()
                .ok_or_else(|| format!("UDP worker structural evidence is missing {name}"))
        };
        Ok(json!({
            "wait_nanoseconds": value("lock_wait_nanoseconds")?,
            "hold_nanoseconds": value("lock_hold_nanoseconds")?,
            "samples": value("lock_samples")?,
        }))
    };
    Ok(json!({
        "aggregation": "server_checked_delta",
        "admission": lock("admission")?,
        "udp_server_state": lock("udp_server")?,
        "udp_mappings_state": lock("udp_mappings")?,
    }))
}

fn structural_json(measurement: &StructuralMeasurement) -> Value {
    json!({
        "schema_version": STRUCTURAL_SCHEMA_VERSION,
        "aggregation": STRUCTURAL_AGGREGATION,
        "counter_schema": counter_schema_json(),
        "counter_count": StructuralCounter::COUNT,
        "client_before": snapshot_json(&measurement.client_before),
        "client_after": snapshot_json(&measurement.client_after),
        "server_before": snapshot_json(&measurement.server_before),
        "server_after": snapshot_json(&measurement.server_after),
        "client_delta": measurement.client_delta,
        "server_delta": measurement.server_delta,
        "merged_delta": measurement.merged_delta,
    })
}

fn snapshot_json(snapshot: &super::structural_contract::StructuralSnapshot) -> Value {
    json!({"values": snapshot.values, "overflowed": snapshot.overflowed})
}

fn linux_cpu_vendor() -> Result<String, String> {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo")
        .map_err(|_| "UDP worker CPU vendor identity is unavailable".to_owned())?;
    let mut vendors = cpuinfo.lines().filter_map(|line| {
        line.strip_prefix("vendor_id")
            .and_then(|rest| rest.split_once(':'))
            .map(|(_, value)| value.trim())
            .filter(|value| !value.is_empty())
    });
    let vendor = vendors
        .next()
        .ok_or_else(|| "UDP worker CPU vendor identity is unavailable".to_owned())?;
    if vendors.any(|next| next != vendor) {
        return Err("UDP worker CPU vendor identity is inconsistent".to_owned());
    }
    Ok(vendor.to_owned())
}

fn failure_json(
    arguments: &UdpWorkerArgs,
    identity: Option<&ProfileRawIdentity>,
    error: &str,
) -> String {
    let mut record = common_record(arguments);
    record.insert(
        "identity".to_owned(),
        identity.map_or(Value::Null, |identity| identity_json(identity, "unknown")),
    );
    record.insert("correctness".to_owned(), json!("FAIL"));
    record.insert("status".to_owned(), json!("FAIL"));
    record.insert("error".to_owned(), Value::String(error.to_owned()));
    serde_json::to_string(&Value::Object(record)).unwrap_or_else(|_| {
        format!(
            "{{\"schema_version\":{UDP_WORKER_SCHEMA_VERSION},\"kind\":{},\"status\":\"FAIL\",\"error\":{}}}",
            json_string(UDP_WORKER_KIND),
            json_string("UDP worker failure evidence encoding failed"),
        )
    })
}

pub(super) fn run_self_check() -> Result<(), String> {
    if !parse_args(&[]).is_err_and(|error| error == "missing --server-receive-workers") {
        return Err("UDP worker missing-option mutation survived".to_owned());
    }
    let duplicate = [
        OsString::from("--server-receive-workers"),
        OsString::from("1"),
        OsString::from("--server-receive-workers"),
        OsString::from("2"),
    ];
    if !parse_args(&duplicate)
        .is_err_and(|error| error == "duplicate UDP worker option: --server-receive-workers")
    {
        return Err("UDP worker duplicate-option mutation survived".to_owned());
    }
    if SessionTopology::parse("single").is_ok() || TrialPhase::parse("adoption").is_ok() {
        return Err("UDP worker closed-enum mutation survived".to_owned());
    }
    for pair in 1..=6 {
        let expected = if pair % 2 == 1 {
            [AxisMember::Baseline, AxisMember::Variant]
        } else {
            [AxisMember::Variant, AxisMember::Baseline]
        };
        if [expected_member(pair, 1), expected_member(pair, 2)] != expected {
            return Err("UDP worker ABBA schedule self-check failed".to_owned());
        }
    }
    validate_digest(&"a".repeat(40), 40, "SHA")?;
    if validate_digest(&"A".repeat(40), 40, "SHA").is_ok()
        || validate_digest(&"a".repeat(39), 40, "SHA").is_ok()
    {
        return Err("UDP worker digest mutation survived".to_owned());
    }
    let mut p99 = (1..=100).collect::<Vec<u64>>();
    if super::profile_udp::nearest_rank_p99(&mut p99)? != 99 {
        return Err("UDP worker nearest-rank p99 self-check failed".to_owned());
    }
    Ok(())
}
