use std::collections::{BTreeMap, BTreeSet};

use super::{
    commands_equivalent, contains_early_control_flow, continuation_statements,
    workflow_child_mapping, workflow_child_sequence, workflow_jobs, workflow_mapping,
};

pub(crate) fn validate_fuzz_workflow_execution(source: &str) -> Result<(), String> {
    let triggers = workflow_mapping(source, "on")?;
    let expected_triggers = BTreeMap::from([
        ("pull_request".to_owned(), String::new()),
        ("push".to_owned(), String::new()),
        ("workflow_dispatch".to_owned(), String::new()),
    ]);
    if triggers != expected_triggers {
        return Err(format!("fuzz workflow trigger set drifted: {triggers:?}"));
    }
    if !workflow_child_mapping(source, "on", "pull_request")?.is_empty()
        || !workflow_child_mapping(source, "on", "workflow_dispatch")?.is_empty()
    {
        return Err("fuzz pull request and manual triggers must remain unfiltered".to_owned());
    }
    let push = workflow_child_mapping(source, "on", "push")?;
    if push.keys().map(String::as_str).collect::<Vec<_>>() != ["branches"] {
        return Err(format!(
            "fuzz push trigger may only declare the reviewed branch set: {push:?}"
        ));
    }
    let branches = workflow_child_sequence(source, "on", "push", "branches")?;
    if branches != ["master", "codex/integration/**"] {
        return Err(format!(
            "fuzz push branch sequence is not the exact reviewed set: {branches:?}"
        ));
    }
    let concurrency = workflow_mapping(source, "concurrency")?;
    let expected_concurrency = BTreeMap::from([
        (
            "group".to_owned(),
            "${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}"
                .to_owned(),
        ),
        ("cancel-in-progress".to_owned(), "false".to_owned()),
        ("queue".to_owned(), "max".to_owned()),
    ]);
    if concurrency != expected_concurrency {
        return Err(format!(
            "fuzz workflow concurrency contract drifted: {concurrency:?}"
        ));
    }

    let jobs = workflow_jobs(source)?;
    if jobs
        .values()
        .flat_map(|job| &job.steps)
        .any(contains_early_control_flow)
    {
        return Err("fuzz workflow contains unreviewed exit or return control flow".to_owned());
    }
    for job_name in [
        "impact",
        "deterministic-build",
        "libfuzzer-build",
        "fuzz-campaign",
        "required",
    ] {
        let job = jobs
            .get(job_name)
            .ok_or_else(|| format!("fuzz workflow {job_name} job is missing"))?;
        if job.properties.contains_key("continue-on-error") {
            return Err(format!(
                "fuzz workflow {job_name} job must not suppress failures"
            ));
        }
    }

    let impact = jobs
        .get("impact")
        .ok_or_else(|| "fuzz impact job is missing".to_owned())?;
    if impact
        .properties
        .get("outputs.seconds_per_target")
        .map(String::as_str)
        != Some("${{ steps.classify.outputs.seconds_per_target }}")
    {
        return Err("fuzz impact job does not publish the controller budget".to_owned());
    }
    if impact
        .properties
        .get("outputs.targets_json")
        .map(String::as_str)
        != Some("${{ steps.classify.outputs.targets_json }}")
    {
        return Err("fuzz impact job does not publish the controller target set".to_owned());
    }
    let expected_classifier = "python3 -B -m tools.ci.fuzz_contract --policy tests/m0-harness/tests/workspace_policy/architecture.toml --repository . --event-name \"$EVENT_NAME\" --base-sha \"$BASE_SHA\" --head-sha \"$HEAD_SHA\" --github-output \"$GITHUB_OUTPUT\" --github-summary \"$GITHUB_STEP_SUMMARY\"";
    let classify_steps: Vec<_> = impact
        .steps
        .iter()
        .filter(|step| {
            let statements = executable_statements(step);
            step.properties.get("id").map(String::as_str) == Some("classify")
                && !step.properties.contains_key("if")
                && !step.properties.contains_key("continue-on-error")
                && step.properties.get("shell").map(String::as_str) == Some("bash")
                && matches!(
                    statements.as_slice(),
                    [strict, command]
                        if strict == "set -euo pipefail"
                            && commands_equivalent(command, expected_classifier)
                )
        })
        .collect();
    let classifier_invocations = jobs
        .values()
        .flat_map(|job| &job.steps)
        .flat_map(|step| continuation_statements(step, '\\'))
        .filter(|statement| statement.contains("tools.ci.fuzz_contract"))
        .count();
    if classify_steps.len() != 1 || classifier_invocations != 1 {
        return Err(
            "fuzz impact controller surface is not one exact unconditional call".to_owned(),
        );
    }

    let deterministic = jobs
        .get("deterministic-build")
        .ok_or_else(|| "deterministic fuzz job is missing".to_owned())?;
    let smoke_steps: Vec<_> = deterministic
        .steps
        .iter()
        .filter(|step| {
            step.properties.get("shell").map(String::as_str) == Some("bash")
                && !step.properties.contains_key("if")
                && !step.properties.contains_key("continue-on-error")
                && step.environment.is_empty()
                && step.inputs.is_empty()
                && executable_statements(step) == ["set -euo pipefail", "./target/debug/smoke"]
        })
        .collect();
    let smoke_invocations = jobs
        .values()
        .flat_map(|job| &job.steps)
        .flat_map(|step| &step.run_lines)
        .filter(|line| line.contains("./target/debug/smoke"))
        .count();
    if smoke_steps.len() != 1 || smoke_invocations != 1 {
        return Err("deterministic smoke execution surface is not one exact step".to_owned());
    }

    let campaign = jobs
        .get("fuzz-campaign")
        .ok_or_else(|| "fuzz campaign job is missing".to_owned())?;
    let campaign_matrix_properties: BTreeSet<_> = campaign
        .properties
        .keys()
        .filter(|key| key.starts_with("strategy.matrix."))
        .map(String::as_str)
        .collect();
    if campaign_matrix_properties != BTreeSet::from(["strategy.matrix.target"]) {
        return Err(format!(
            "fuzz campaign matrix contains an unreviewed selector: {campaign_matrix_properties:?}"
        ));
    }
    for (property, expected) in [
        (
            "strategy.matrix.target",
            "${{ fromJSON(needs.impact.outputs.targets_json) }}",
        ),
        ("env.FUZZ_TARGET", "${{ matrix.target }}"),
        (
            "env.FUZZ_SECONDS_PER_TARGET",
            "${{ needs.impact.outputs.seconds_per_target }}",
        ),
    ] {
        if campaign.properties.get(property).map(String::as_str) != Some(expected) {
            return Err(format!(
                "fuzz campaign property {property} is not closed over impact output"
            ));
        }
    }

    let expected_campaign = "timeout --signal=TERM --kill-after=30s \"${outer_timeout_seconds}s\" \"$RUNNER_TEMP/tun-fuzz-binaries/$FUZZ_TARGET\" \"$campaign_root/corpus/$FUZZ_TARGET\" -artifact_prefix=\"$campaign_root/artifacts/$FUZZ_TARGET/\" -max_total_time=\"$FUZZ_SECONDS_PER_TARGET\" -timeout=15 -rss_limit_mb=4096 -print_final_stats=1 2>&1 | tee \"$campaign_root/logs/$FUZZ_TARGET.log\"";
    let campaign_steps: Vec<_> = campaign
        .steps
        .iter()
        .filter(|step| {
            step.properties.get("shell").map(String::as_str) == Some("bash")
                && step.properties.get("timeout-minutes").map(String::as_str) == Some("17")
                && !step.properties.contains_key("if")
                && !step.properties.contains_key("continue-on-error")
                && step.environment.is_empty()
                && step.inputs.is_empty()
                && campaign_sequence_matches(step, expected_campaign)
        })
        .collect();
    let runs_bounded_target = campaign_steps.len() == 1;
    let all_statements: Vec<_> = jobs
        .values()
        .flat_map(|job| &job.steps)
        .flat_map(|step| continuation_statements(step, '\\'))
        .collect();
    let target_path_mentions = all_statements
        .iter()
        .filter(|statement| statement.contains("$RUNNER_TEMP/tun-fuzz-binaries/$FUZZ_TARGET"))
        .count();
    let budget_mentions = all_statements
        .iter()
        .filter(|statement| statement.contains("-max_total_time="))
        .count();
    if !runs_bounded_target || target_path_mentions != 2 || budget_mentions != 1 {
        return Err(
            "fuzz target execution is duplicated, unbounded, or detached from the controller budget"
                .to_owned(),
        );
    }
    let fuzz_commands: Vec<_> = all_statements
        .iter()
        .filter(|statement| statement.contains("cargo ") && statement.contains(" fuzz "))
        .map(String::as_str)
        .collect();
    let expected_fuzz_commands = [
        "test \"$(cargo +nightly-2026-07-10 fuzz --version)\" = \"cargo-fuzz 0.13.2\"",
        "CARGO_NET_OFFLINE=true cargo +nightly-2026-07-10 fuzz build --features libfuzzer \"$target\"",
    ];
    if fuzz_commands.len() != expected_fuzz_commands.len()
        || fuzz_commands
            .iter()
            .zip(expected_fuzz_commands)
            .any(|(actual, expected)| {
                if let Some(expected) = expected.strip_prefix("CARGO_NET_OFFLINE=true ") {
                    !actual
                        .strip_prefix("CARGO_NET_OFFLINE=true ")
                        .is_some_and(|actual| commands_equivalent(actual, expected))
                } else {
                    actual
                        .strip_prefix("test \"$(")
                        .and_then(|command| command.strip_suffix(")\" = \"cargo-fuzz 0.13.2\""))
                        .is_none_or(|command| {
                            !commands_equivalent(
                                command,
                                "cargo +nightly-2026-07-10 fuzz --version",
                            )
                        })
                }
            })
    {
        return Err(format!(
            "cargo-fuzz command surface drifted: {fuzz_commands:?}"
        ));
    }
    Ok(())
}

// The assignments and pipeline form the reviewed budget/dataflow envelope.
// Only the inner invocation has freely reorderable arguments: accepting arbitrary
// shell syntax here could hide an unbounded run or mask the fuzzer's exit status.
fn campaign_sequence_matches(step: &super::WorkflowStep, expected_command: &str) -> bool {
    let statements = executable_statements(step);
    let [strict, root, budget, command] = statements.as_slice() else {
        return false;
    };
    let pipeline = " 2>&1 | tee \"$campaign_root/logs/$FUZZ_TARGET.log\"";
    strict == "set -euo pipefail"
        && root == "campaign_root=\"$RUNNER_TEMP/tun-fuzz-campaign\""
        && budget == "outer_timeout_seconds=$((FUZZ_SECONDS_PER_TARGET + 60))"
        && command
            .strip_suffix(pipeline)
            .zip(expected_command.strip_suffix(pipeline))
            .is_some_and(|(actual, expected)| commands_equivalent(actual, expected))
}

fn executable_statements(step: &super::WorkflowStep) -> Vec<String> {
    continuation_statements(step, '\\')
        .into_iter()
        .filter(|statement| !statement.is_empty() && !statement.starts_with('#'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn campaign_role_allows_renaming_and_argument_order_not_unbounded_execution() {
        let source = std::fs::read_to_string(
            crate::workspace_root().join(".github/workflows/tun-fuzz-deterministic.yml"),
        )
        .expect("fuzz workflow");
        let renamed = source
            .replace(
                "Run deterministic TUN smoke corpus",
                "Exercise deterministic corpus",
            )
            .replace(
                "Run target sanitizer fuzz campaign",
                "Exercise bounded target",
            )
            .replace(
                "--signal=TERM --kill-after=30s",
                "--kill-after 30s --signal TERM",
            )
            .replace(
                "-timeout=15 -rss_limit_mb=4096",
                "-rss_limit_mb=4096 -timeout=15",
            );
        validate_fuzz_workflow_execution(&renamed).expect("equivalent bounded campaign");
        for (from, to) in [
            (
                "-max_total_time=\"$FUZZ_SECONDS_PER_TARGET\"",
                "-max_total_time=0",
            ),
            (
                "\"$campaign_root/corpus/$FUZZ_TARGET\"",
                "\"$campaign_root/corpus/other\"",
            ),
            ("--kill-after 30s", "--kill-after 300s"),
            ("set -euo pipefail", "set -eu"),
            ("tools.ci.fuzz_contract", "tools.ci.other_contract"),
        ] {
            assert!(renamed.contains(from), "mutation source {from}");
            assert!(validate_fuzz_workflow_execution(&renamed.replace(from, to)).is_err());
        }
    }
}
