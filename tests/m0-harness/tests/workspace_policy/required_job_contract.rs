use std::collections::{BTreeMap, BTreeSet};

use super::workflow_jobs;

fn controller_contract(
    expected_dependencies: &BTreeSet<String>,
) -> Result<(&'static str, BTreeMap<String, String>, &'static str), String> {
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
            "Require every ordinary main gate",
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
            "Require impact decision and applicable fuzz gates",
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
    let jobs = workflow_jobs(source)?;
    let required = jobs
        .get("required")
        .ok_or_else(|| "workflow required job is missing".to_owned())?;
    if required.properties.get("if").map(String::as_str) != Some("${{ always() }}") {
        return Err("required job must use the exact always condition".to_owned());
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
    if checkout.properties.get("name").map(String::as_str) != Some("Checkout exact current SHA")
        || checkout.properties.get("uses").map(String::as_str)
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

    let (expected_name, expected_environment, expected_command) =
        controller_contract(expected_dependencies)?;
    let controller = &required.steps[1];
    if controller.properties.get("name").map(String::as_str) != Some(expected_name)
        || controller.properties.get("shell").map(String::as_str) != Some("bash")
        || controller.properties.contains_key("if")
        || controller.properties.contains_key("continue-on-error")
        || controller.environment != expected_environment
        || !controller.inputs.is_empty()
        || controller.run_lines != [expected_command]
    {
        return Err(
            "required job must invoke the exact typed controller with the closed dependency inputs"
                .to_owned(),
        );
    }
    Ok(())
}
