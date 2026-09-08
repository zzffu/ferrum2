use std::collections::{BTreeMap, BTreeSet};

use super::{commands_equivalent, validate_read_only_permissions, workflow_jobs};

fn controller_contract(
    expected_dependencies: &BTreeSet<String>,
) -> Result<(BTreeMap<String, String>, &'static str), String> {
    let ordinary = BTreeSet::from([
        "changes".to_owned(),
        "quality".to_owned(),
        "platform".to_owned(),
        "interop".to_owned(),
    ]);
    let fuzz = BTreeSet::from([
        "impact".to_owned(),
        "deterministic-build".to_owned(),
        "libfuzzer-build".to_owned(),
        "fuzz-campaign".to_owned(),
    ]);
    if expected_dependencies == &ordinary {
        Ok((
            BTreeMap::from([
                (
                    "CHANGE_RESULT".to_owned(),
                    "${{ needs.changes.result }}".to_owned(),
                ),
                (
                    "RUN_EXPENSIVE".to_owned(),
                    "${{ needs.changes.outputs.run_expensive }}".to_owned(),
                ),
                (
                    "QUALITY_RESULT".to_owned(),
                    "${{ needs.quality.result }}".to_owned(),
                ),
                (
                    "PLATFORM_RESULT".to_owned(),
                    "${{ needs.platform.result }}".to_owned(),
                ),
                (
                    "INTEROP_RESULT".to_owned(),
                    "${{ needs.interop.result }}".to_owned(),
                ),
            ]),
            "python3 -B -m tools.ci.required_gate --mode ordinary --decision \"$RUN_EXPENSIVE\" --dependency \"changes=$CHANGE_RESULT\" --dependency \"quality=$QUALITY_RESULT\" --dependency \"platform=$PLATFORM_RESULT\" --dependency \"interop=$INTEROP_RESULT\"",
        ))
    } else if expected_dependencies == &fuzz {
        Ok((
            BTreeMap::from([
                (
                    "IMPACT_RESULT".to_owned(),
                    "${{ needs.impact.result }}".to_owned(),
                ),
                (
                    "FUZZ_AFFECTED".to_owned(),
                    "${{ needs.impact.outputs.affected }}".to_owned(),
                ),
                (
                    "DETERMINISTIC_RESULT".to_owned(),
                    "${{ needs.deterministic-build.result }}".to_owned(),
                ),
                (
                    "LIBFUZZER_RESULT".to_owned(),
                    "${{ needs.libfuzzer-build.result }}".to_owned(),
                ),
                (
                    "CAMPAIGN_RESULT".to_owned(),
                    "${{ needs.fuzz-campaign.result }}".to_owned(),
                ),
            ]),
            "python3 -B -m tools.ci.required_gate --mode fuzz --decision \"$FUZZ_AFFECTED\" --dependency \"impact=$IMPACT_RESULT\" --dependency \"deterministic-build=$DETERMINISTIC_RESULT\" --dependency \"libfuzzer-build=$LIBFUZZER_RESULT\" --dependency \"fuzz-campaign=$CAMPAIGN_RESULT\"",
        ))
    } else {
        Err(format!(
            "required controller has no typed policy for {expected_dependencies:?}"
        ))
    }
}

pub(crate) fn validate_required_job(
    source: &str,
    expected_dependencies: &BTreeSet<String>,
) -> Result<(), String> {
    validate_read_only_permissions(source)?;
    let jobs = workflow_jobs(source)?;
    let required = jobs
        .get("required")
        .ok_or_else(|| "workflow required job is missing".to_owned())?;
    if !required.properties.get("if").is_some_and(|condition| {
        let condition = condition.trim();
        condition
            .strip_prefix("${{")
            .and_then(|inner| inner.strip_suffix("}}"))
            .unwrap_or(condition)
            .trim()
            == "always()"
    }) {
        return Err("required job must run unconditionally with always()".to_owned());
    }
    if required.properties.contains_key("continue-on-error") {
        return Err("required job must not suppress failures".to_owned());
    }
    let actual_dependencies: BTreeSet<_> = required.needs.iter().cloned().collect();
    if required.needs.len() != actual_dependencies.len()
        || actual_dependencies != *expected_dependencies
    {
        return Err(format!(
            "required job dependency set drifted: {actual_dependencies:?}"
        ));
    }
    if required.properties.get("runs-on").map(String::as_str) != Some("ubuntu-24.04")
        || required
            .properties
            .get("timeout-minutes")
            .map(String::as_str)
            != Some("5")
    {
        return Err("required job runner or timeout drifted".to_owned());
    }
    if required.steps.len() != 2 {
        return Err(
            "required job must contain exactly checkout and typed controller steps".to_owned(),
        );
    }

    let checkout = &required.steps[0];
    if checkout.properties.get("uses").map(String::as_str)
        != Some("actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd")
        || checkout.properties.contains_key("if")
        || checkout.properties.contains_key("continue-on-error")
        || checkout.inputs
            != BTreeMap::from([
                ("ref".to_owned(), "${{ github.sha }}".to_owned()),
                ("fetch-depth".to_owned(), "1".to_owned()),
                ("clean".to_owned(), "true".to_owned()),
                ("persist-credentials".to_owned(), "false".to_owned()),
            ])
        || !checkout.run_lines.is_empty()
    {
        return Err("required job checkout step drifted".to_owned());
    }

    let (expected_environment, expected_command) = controller_contract(expected_dependencies)?;
    let controller = &required.steps[1];
    if controller.properties.get("shell").map(String::as_str) != Some("bash")
        || controller.properties.contains_key("if")
        || controller.properties.contains_key("continue-on-error")
        || controller.environment != expected_environment
        || !controller.inputs.is_empty()
        || !commands_equivalent(&controller.run_lines.join("\n"), expected_command)
    {
        return Err(
            "required job must invoke the exact typed controller with the closed dependency inputs"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_role_allows_presentation_changes_but_preserves_failure_inputs() {
        let source =
            std::fs::read_to_string(crate::workspace_root().join(".github/workflows/m0.yml"))
                .expect("ordinary workflow");
        let dependencies = ["changes", "quality", "platform", "interop"]
            .map(str::to_owned)
            .into_iter()
            .collect();
        let (_, command) = controller_contract(&dependencies).expect("ordinary controller");
        let reordered = "python3 -B -m tools.ci.required_gate --dependency \"interop=$INTEROP_RESULT\" --decision \"$RUN_EXPENSIVE\" --dependency \"platform=$PLATFORM_RESULT\" --mode=ordinary --dependency \"changes=$CHANGE_RESULT\" --dependency \"quality=$QUALITY_RESULT\"";
        assert!(source.contains(command));
        let renamed = source
            .replace("Checkout exact current SHA", "Checkout reviewed revision")
            .replace(
                "Require every ordinary main gate",
                "Evaluate dependency outcomes",
            )
            .replace("${{ always() }}", "${{always()}}")
            .replace(command, reordered);
        validate_required_job(&renamed, &dependencies).expect("equivalent controller");
        for replacement in [
            reordered.replace("interop=$INTEROP_RESULT", "interop=success"),
            reordered.replace("tools.ci.required_gate", "tools.ci.other_gate"),
            reordered.replace("\"$RUN_EXPENSIVE\"", "'$RUN_EXPENSIVE'"),
            format!("{reordered} || true"),
        ] {
            assert!(
                validate_required_job(&renamed.replace(reordered, &replacement), &dependencies)
                    .is_err()
            );
        }
        assert!(
            validate_required_job(
                &renamed.replace("${{always()}}", "${{ success() }}"),
                &dependencies,
            )
            .is_err()
        );
        assert!(
            validate_required_job(
                &renamed.replace("contents: read", "contents: write"),
                &dependencies,
            )
            .is_err()
        );
    }
}
