use std::fs;
use std::io::Read;
use std::num::NonZeroUsize;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::cli::{Args, QualificationError, Result};
use crate::cli::{MAX_BASE_ITERATIONS, MAX_SAMPLES, MIN_SAMPLES};
use crate::dns_policy::run_dns_policy;
use crate::match_set::benchmark::run_generated_match_sets;
use crate::match_set::srs::{run_generated_binary_srs, run_real_srs};
use crate::measurement::statistics::{
    LOCAL_PARITY_TARGET_PERCENT, NOISY_GATE_CEILING_PERCENT, P99_PARITY_TARGET_PERCENT,
    collect_parity_observations, ensure_unique_measurement_ids,
};
use crate::measurement::timing::{MIN_SAMPLE_WINDOW_NANOSECONDS, WARMUP_BATCHES};
use crate::report::{
    CandidateEvidence, EnvironmentFingerprint, MeasurementPolicy, REPORT_SCHEMA, Report,
    RepositoryFingerprint, RunConfiguration, RunnerFingerprint,
};
use crate::route_program::run_route_programs;

pub fn execute(args: Args) -> Result<()> {
    let samples = args.samples.unwrap_or(args.profile.default_samples());
    if !(MIN_SAMPLES..=MAX_SAMPLES).contains(&samples) {
        return Err(QualificationError::new(format!(
            "--samples must be in {MIN_SAMPLES}..={MAX_SAMPLES}"
        )));
    }
    let base_iterations = args
        .iterations_per_sample
        .unwrap_or(args.profile.default_base_iterations());
    if !(1..=MAX_BASE_ITERATIONS).contains(&base_iterations) {
        return Err(QualificationError::new(format!(
            "--iterations-per-sample must be in 1..={MAX_BASE_ITERATIONS}"
        )));
    }

    let workspace_root = fs::canonicalize(&args.workspace_root).map_err(|error| {
        QualificationError::new(format!("workspace root is unavailable: {error}"))
    })?;
    validate_workspace_root(&workspace_root)?;

    let mut match_sizes = args.profile.match_sizes();
    if args.include_100k && !match_sizes.contains(&100_000) {
        match_sizes.push(100_000);
    }
    let route_sizes = args.profile.route_sizes();
    let dns_rule_sizes = args.profile.dns_rule_sizes();

    let environment = environment_fingerprint();
    let repository = repository_fingerprint(&workspace_root);
    let runner = runner_fingerprint()?;
    let mut measurements = Vec::new();
    run_generated_match_sets(&match_sizes, samples, base_iterations, &mut measurements)?;
    let mut fixtures = Vec::new();
    if args.profile.includes_generated_binary_srs() {
        fixtures.extend(run_generated_binary_srs(
            &match_sizes,
            samples,
            base_iterations,
            &mut measurements,
        )?);
    }
    fixtures.extend(run_real_srs(
        &workspace_root,
        samples,
        base_iterations,
        &mut measurements,
    )?);
    run_route_programs(&route_sizes, samples, base_iterations, &mut measurements)?;
    run_dns_policy(&dns_rule_sizes, samples, base_iterations, &mut measurements)?;
    ensure_unique_measurement_ids(&measurements)?;
    let parity_observations = collect_parity_observations(&measurements)?;
    let parity_gate_passed = parity_observations.iter().all(|observation| {
        !observation.performance_gate_applicable || observation.decision == "passed"
    });
    let allocation_gate_passed = measurements
        .iter()
        .all(|row| !row.allocation_gate_applicable || row.allocation_gate_passed == Some(true));

    let report = Report {
        schema: REPORT_SCHEMA,
        generated_unix_millis: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| QualificationError::new("system clock precedes the Unix epoch"))?
            .as_millis(),
        profile: args.profile,
        environment,
        repository,
        runner,
        candidate: candidate_evidence(),
        configuration: RunConfiguration {
            match_sizes,
            route_sizes,
            dns_rule_sizes,
            samples,
            base_iterations_per_sample: base_iterations,
            includes_100k: args.include_100k,
        },
        measurement_policy: MeasurementPolicy {
            latency_source: "std::time::Instant self-calibrating wall-clock batches",
            minimum_reported_batch_nanoseconds: MIN_SAMPLE_WINDOW_NANOSECONDS,
            calibration: "each retained sample runs enough operations to reach the minimum window; paired rows share the same operation count",
            warmup_batches: WARMUP_BATCHES,
            paired_order: "each paired MatchSet sample contains 32 strictly alternating rounds (16 in each order); a deterministic scenario hash randomizes the first role",
            retained_samples: true,
            allocation_measurement: "stats_alloc 0.1.10 instrumented system allocator; five separate one-operation regions outside latency timing",
            compiled_memory_measurement: "net retained bytes in the instrumented build region",
            local_parity_target_percent: LOCAL_PARITY_TARGET_PERCENT,
            noisy_gate_ceiling_percent: NOISY_GATE_CEILING_PERCENT,
            p99_parity_target_percent: P99_PARITY_TARGET_PERCENT,
            thresholds_enforced_by_runner: true,
            parity_gate_scope: "CompiledMatchSet ordinary-inline/synthetic and synthetic/binary-SRS rows only",
            paired_observation_scope: "Route and DNS program ordinary/RuleSet rows retain paired latency and correctness but are not subject to the MatchSet 5%/15% gate",
            allocation_gate_scope: "CompiledMatchSet matches and Route evaluation with reusable scratch",
            note: "DNS end-to-end rows include query construction and report allocations without applying the matcher hot-path gate",
        },
        scenario_count: measurements.len(),
        fixtures,
        measurements,
        parity_observations,
        correctness_passed: true,
        allocation_gate_passed,
        parity_gate_passed,
        thresholds_passed: allocation_gate_passed && parity_gate_passed,
    };
    let mut encoded = serde_json::to_vec_pretty(&report)
        .map_err(|error| QualificationError::new(format!("JSON encoding failed: {error}")))?;
    encoded.push(b'\n');
    if let Some(output) = args.output.as_deref() {
        write_report(output, &encoded)?;
    }
    print!("{}", String::from_utf8_lossy(&encoded));
    if allocation_gate_passed && parity_gate_passed {
        Ok(())
    } else if !parity_gate_passed {
        Err(QualificationError::new(
            "ordinary/RuleSet local 5% median or 15% p99 parity gate failed; JSON evidence was emitted",
        ))
    } else {
        Err(QualificationError::new(
            "allocation-free MatchSet/Route hot-path gate failed; JSON evidence was emitted",
        ))
    }
}

fn candidate_evidence() -> CandidateEvidence {
    let enabled_features = [
        cfg!(feature = "candidate-atomic-snapshot").then_some("candidate-atomic-snapshot"),
        cfg!(feature = "candidate-cidr-radix").then_some("candidate-cidr-radix"),
        cfg!(feature = "candidate-domain-suffix-trie").then_some("candidate-domain-suffix-trie"),
    ]
    .into_iter()
    .flatten()
    .collect();
    CandidateEvidence {
        adoption_claim: false,
        enabled_features,
    }
}

fn validate_workspace_root(root: &Path) -> Result<()> {
    if !root.join("Cargo.toml").is_file() || !root.join("tests/fixtures/srs").is_dir() {
        return Err(QualificationError::new(
            "workspace root must contain Cargo.toml and tests/fixtures/srs",
        ));
    }
    Ok(())
}

fn write_report(path: &Path, encoded: &[u8]) -> Result<()> {
    if path.extension().and_then(|value| value.to_str()) != Some("json") {
        return Err(QualificationError::new(
            "--output must have a .json extension",
        ));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(QualificationError::new(
            "--output parent directory does not exist",
        ));
    }
    fs::write(path, encoded)
        .map_err(|error| QualificationError::new(format!("report write failed: {error}")))
}

fn environment_fingerprint() -> EnvironmentFingerprint {
    EnvironmentFingerprint {
        os: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        family: std::env::consts::FAMILY,
        logical_cpus: std::thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(1),
        cpu_model: std::env::var("PROCESSOR_IDENTIFIER")
            .ok()
            .filter(|value| !value.trim().is_empty()),
        rustc_version: command_text(Path::new("."), "rustc", &["--version"]),
        timer: "std::time::Instant",
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
    }
}

fn repository_fingerprint(root: &Path) -> RepositoryFingerprint {
    let git_head = command_text(root, "git", &["rev-parse", "HEAD"]);
    let git_tree = command_text(root, "git", &["rev-parse", "HEAD^{tree}"]);
    let status = Command::new("git")
        .current_dir(root)
        .args(["status", "--porcelain=v1", "--untracked-files=normal"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| output.stdout);
    let changed_entries = status.as_ref().map(|bytes| {
        bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .count()
    });
    let status_sha256 = status.as_ref().map(|bytes| sha256_bytes(bytes));
    let tree_state = match changed_entries {
        Some(0) => "clean",
        Some(_) => "dirty",
        None => "unknown",
    };
    RepositoryFingerprint {
        git_head,
        git_tree,
        tree_state,
        changed_entries,
        status_sha256,
    }
}

fn runner_fingerprint() -> Result<RunnerFingerprint> {
    let executable = std::env::current_exe()
        .map_err(|error| QualificationError::new(format!("runner path unavailable: {error}")))?;
    let bytes = fs::metadata(&executable)
        .map_err(|error| QualificationError::new(format!("runner metadata unavailable: {error}")))?
        .len();
    Ok(RunnerFingerprint {
        sha256: sha256_file(&executable)?,
        bytes,
    })
}

fn command_text(root: &Path, program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program)
        .current_dir(root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)
        .map_err(|error| QualificationError::new(format!("hash input unavailable: {error}")))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| QualificationError::new(format!("hash input read failed: {error}")))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_evidence_is_sorted_explicit_and_never_claims_adoption() {
        let evidence = candidate_evidence();
        let expected = [
            cfg!(feature = "candidate-atomic-snapshot").then_some("candidate-atomic-snapshot"),
            cfg!(feature = "candidate-cidr-radix").then_some("candidate-cidr-radix"),
            cfg!(feature = "candidate-domain-suffix-trie")
                .then_some("candidate-domain-suffix-trie"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        assert!(!evidence.adoption_claim);
        assert_eq!(evidence.enabled_features, expected);
        assert!(
            evidence
                .enabled_features
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
    }
}
