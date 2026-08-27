use std::collections::{BTreeMap, BTreeSet};

fn workflow_mapping(source: &str, key: &str) -> Result<BTreeMap<String, String>, String> {
    let header = format!("{key}:");
    let lines: Vec<_> = source.lines().collect();
    let matches: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == header)
        .map(|(index, _)| index)
        .collect();
    if matches.len() != 1 {
        return Err(format!("workflow must contain one top-level {header}"));
    }
    let mut values = BTreeMap::new();
    for line in &lines[matches[0] + 1..] {
        if line.is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            break;
        }
        if line.starts_with("    ") || !line.starts_with("  ") || line.starts_with('\t') {
            continue;
        }
        let entry = &line[2..];
        let (name, value) = entry
            .split_once(':')
            .ok_or_else(|| format!("workflow {key} entry is not a mapping: {entry}"))?;
        if name.is_empty()
            || values
                .insert(name.to_owned(), value.trim().to_owned())
                .is_some()
        {
            return Err(format!("workflow {key} entry is empty or duplicated"));
        }
    }
    if values.is_empty() {
        return Err(format!("workflow {key} mapping is empty"));
    }
    Ok(values)
}

fn workflow_child_mapping(
    source: &str,
    parent: &str,
    child: &str,
) -> Result<BTreeMap<String, String>, String> {
    let parent_header = format!("{parent}:");
    let child_header = format!("  {child}:");
    let lines: Vec<_> = source.lines().collect();
    let parent_index = lines
        .iter()
        .position(|line| **line == parent_header)
        .ok_or_else(|| format!("workflow {parent} mapping is missing"))?;
    let parent_end = lines[parent_index + 1..]
        .iter()
        .position(|line| !line.is_empty() && !line.starts_with(' '))
        .map_or(lines.len(), |offset| parent_index + 1 + offset);
    let matches: Vec<_> = lines[parent_index + 1..parent_end]
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == child_header)
        .map(|(offset, _)| parent_index + 1 + offset)
        .collect();
    if matches.len() != 1 {
        return Err(format!(
            "workflow {parent} must contain one direct {child} mapping"
        ));
    }
    let mut values = BTreeMap::new();
    for line in &lines[matches[0] + 1..parent_end] {
        if line.is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with("    ") {
            break;
        }
        if line.starts_with("      ") {
            continue;
        }
        let entry = &line[4..];
        let (name, value) = entry
            .split_once(':')
            .ok_or_else(|| format!("workflow {parent}.{child} entry is malformed"))?;
        if name.is_empty()
            || values
                .insert(name.to_owned(), value.trim().to_owned())
                .is_some()
        {
            return Err(format!(
                "workflow {parent}.{child} entry is empty or duplicated"
            ));
        }
    }
    Ok(values)
}

fn unquote_scalar(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value[1..value.len() - 1].to_owned()
    } else {
        value.to_owned()
    }
}

fn indented_sequence(
    lines: &[&str],
    header: &str,
    item_prefix: &str,
) -> Result<Vec<String>, String> {
    let matches: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == header)
        .map(|(index, _)| index)
        .collect();
    if matches.len() > 1 {
        return Err(format!("workflow sequence {header:?} is duplicated"));
    }
    let Some(start) = matches.first().copied() else {
        return Ok(Vec::new());
    };
    let header_indentation = header.len() - header.trim_start_matches(' ').len();
    let mut values = Vec::new();
    for line in &lines[start + 1..] {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indentation = line.len() - line.trim_start_matches(' ').len();
        if indentation <= header_indentation {
            break;
        }
        let value = line
            .strip_prefix(item_prefix)
            .ok_or_else(|| format!("workflow sequence {header:?} contains a malformed item"))?;
        if value.is_empty() {
            return Err(format!(
                "workflow sequence {header:?} contains an empty item"
            ));
        }
        values.push(unquote_scalar(value));
    }
    if values.is_empty() {
        return Err(format!("workflow sequence {header:?} is empty"));
    }
    Ok(values)
}

fn workflow_child_sequence(
    source: &str,
    parent: &str,
    child: &str,
    sequence: &str,
) -> Result<Vec<String>, String> {
    let parent_header = format!("{parent}:");
    let child_header = format!("  {child}:");
    let sequence_header = format!("    {sequence}:");
    let lines: Vec<_> = source.lines().collect();
    let parent_index = lines
        .iter()
        .position(|line| **line == parent_header)
        .ok_or_else(|| format!("workflow {parent} mapping is missing"))?;
    let child_index = lines[parent_index + 1..]
        .iter()
        .position(|line| **line == child_header)
        .map(|offset| parent_index + 1 + offset)
        .ok_or_else(|| format!("workflow {parent}.{child} mapping is missing"))?;
    let child_end = lines[child_index + 1..]
        .iter()
        .position(|line| !line.is_empty() && !line.starts_with("    "))
        .map_or(lines.len(), |offset| child_index + 1 + offset);
    indented_sequence(
        &lines[child_index + 1..child_end],
        &sequence_header,
        "      - ",
    )
}

#[derive(Debug)]
struct WorkflowStep {
    properties: BTreeMap<String, String>,
    environment: BTreeMap<String, String>,
    inputs: BTreeMap<String, String>,
    run_lines: Vec<String>,
}

#[derive(Debug)]
struct WorkflowJob {
    properties: BTreeMap<String, String>,
    needs: Vec<String>,
    matrix_include: Vec<BTreeMap<String, String>>,
    steps: Vec<WorkflowStep>,
}

#[path = "hosted_pe_contract.rs"]
mod hosted_pe_contract;

#[path = "required_job_contract.rs"]
mod required_job_contract;
pub(super) use required_job_contract::validate_required_job;

#[path = "fuzz_workflow_contract.rs"]
mod fuzz_workflow_contract;
pub(super) use fuzz_workflow_contract::validate_fuzz_workflow_execution;

fn workflow_jobs(source: &str) -> Result<BTreeMap<String, WorkflowJob>, String> {
    if source.lines().any(|line| line.contains('\t')) {
        return Err("workflow contains a tab and cannot be parsed safely".to_owned());
    }
    let lines: Vec<_> = source.lines().collect();
    let jobs_matches: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == "jobs:")
        .map(|(index, _)| index)
        .collect();
    if jobs_matches.len() != 1 {
        return Err("workflow must contain exactly one jobs mapping".to_owned());
    }
    let jobs_index = jobs_matches[0];
    let mut ranges = Vec::new();
    for (index, line) in lines.iter().enumerate().skip(jobs_index + 1) {
        if !line.is_empty() && !line.starts_with(' ') {
            break;
        }
        let Some(entry) = line.strip_prefix("  ") else {
            continue;
        };
        if entry.starts_with(' ') || entry.starts_with('-') {
            continue;
        }
        let Some((name, value)) = entry.split_once(':') else {
            continue;
        };
        if !name.is_empty() && value.trim().is_empty() {
            ranges.push((name.to_owned(), index));
        }
    }
    if ranges.is_empty() {
        return Err("workflow jobs mapping is empty".to_owned());
    }

    let workflow_end = lines[jobs_index + 1..]
        .iter()
        .position(|line| !line.is_empty() && !line.starts_with(' '))
        .map_or(lines.len(), |offset| jobs_index + 1 + offset);
    let mut jobs = BTreeMap::new();
    for (position, (name, start)) in ranges.iter().enumerate() {
        let end = ranges
            .get(position + 1)
            .map_or(workflow_end, |(_, next)| *next);
        let job = parse_workflow_job(&lines[start + 1..end])?;
        if jobs.insert(name.clone(), job).is_some() {
            return Err(format!("workflow job {name} is duplicated"));
        }
    }
    Ok(jobs)
}

fn parse_matrix_include(lines: &[&str]) -> Result<Vec<BTreeMap<String, String>>, String> {
    let matches: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == "        include:")
        .map(|(index, _)| index)
        .collect();
    if matches.len() > 1 {
        return Err("workflow matrix include mapping is duplicated".to_owned());
    }
    let Some(start) = matches.first().copied() else {
        return Ok(Vec::new());
    };
    let mut rows = Vec::new();
    let mut current = None;
    for line in &lines[start + 1..] {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indentation = line.len() - line.trim_start_matches(' ').len();
        if indentation <= 8 {
            break;
        }
        let entry = if let Some(entry) = line.strip_prefix("          - ") {
            if let Some(row) = current.replace(BTreeMap::new()) {
                rows.push(row);
            }
            entry
        } else {
            line.strip_prefix("            ")
                .ok_or_else(|| "workflow matrix include row is malformed".to_owned())?
        };
        let (key, value) = entry
            .split_once(':')
            .ok_or_else(|| "workflow matrix include property is malformed".to_owned())?;
        if key.is_empty() || value.trim().is_empty() {
            return Err("workflow matrix include property is empty".to_owned());
        }
        let row = current
            .as_mut()
            .ok_or_else(|| "workflow matrix include property precedes its row".to_owned())?;
        if row.insert(key.to_owned(), unquote_scalar(value)).is_some() {
            return Err(format!(
                "workflow matrix include property {key} is duplicated"
            ));
        }
    }
    if let Some(row) = current {
        rows.push(row);
    }
    if rows.is_empty() {
        return Err("workflow matrix include mapping is empty".to_owned());
    }
    Ok(rows)
}

fn parse_workflow_job(lines: &[&str]) -> Result<WorkflowJob, String> {
    let steps_index = lines.iter().position(|line| *line == "    steps:");
    let preamble = steps_index.map_or(lines, |index| &lines[..index]);
    let mut properties = BTreeMap::new();
    let mut parents: Vec<(usize, String)> = Vec::new();
    let mut sequence_indentation = None;
    for line in preamble {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indentation = line.len() - line.trim_start_matches(' ').len();
        if sequence_indentation.is_some_and(|sequence| indentation > sequence) {
            continue;
        }
        sequence_indentation = None;
        if line.trim_start().starts_with('-') {
            sequence_indentation = Some(indentation);
            continue;
        }
        if indentation < 4 {
            continue;
        }
        let entry = line.trim_start();
        let Some((key, value)) = entry.split_once(':') else {
            continue;
        };
        if key.is_empty() {
            return Err("workflow job contains an empty mapping key".to_owned());
        }
        while parents
            .last()
            .is_some_and(|(parent_indentation, _)| *parent_indentation >= indentation)
        {
            parents.pop();
        }
        let path = parents
            .iter()
            .map(|(_, parent)| parent.as_str())
            .chain([key])
            .collect::<Vec<_>>()
            .join(".");
        if properties
            .insert(path.clone(), value.trim().to_owned())
            .is_some()
        {
            return Err(format!("workflow job property {path} is duplicated"));
        }
        if value.trim().is_empty() {
            parents.push((indentation, key.to_owned()));
        }
    }

    let mut steps = Vec::new();
    if let Some(steps_index) = steps_index {
        let step_lines = &lines[steps_index + 1..];
        let starts: Vec<_> = step_lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.starts_with("      - "))
            .map(|(index, _)| index)
            .collect();
        for (position, start) in starts.iter().enumerate() {
            let end = starts
                .get(position + 1)
                .copied()
                .unwrap_or(step_lines.len());
            steps.push(parse_workflow_step(&step_lines[*start..end])?);
        }
    }
    let needs = indented_sequence(preamble, "    needs:", "      - ")?;
    let matrix_include = parse_matrix_include(preamble)?;
    Ok(WorkflowJob {
        properties,
        needs,
        matrix_include,
        steps,
    })
}

fn parse_workflow_step(lines: &[&str]) -> Result<WorkflowStep, String> {
    let mut properties = BTreeMap::new();
    let mut environment = BTreeMap::new();
    let mut inputs = BTreeMap::new();
    let mut run_lines = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        let entry = if index == 0 {
            line.strip_prefix("      - ")
        } else {
            line.strip_prefix("        ")
                .filter(|entry| !entry.starts_with(' '))
        };
        let Some(entry) = entry else {
            index += 1;
            continue;
        };
        let Some((key, value)) = entry.split_once(':') else {
            index += 1;
            continue;
        };
        if key == "run" {
            if value.trim() == "|" || value.trim() == ">" {
                index += 1;
                while index < lines.len() {
                    if lines[index].is_empty() {
                        run_lines.push(String::new());
                        index += 1;
                        continue;
                    }
                    let Some(script_line) = lines[index].strip_prefix("          ") else {
                        break;
                    };
                    run_lines.push(script_line.to_owned());
                    index += 1;
                }
                continue;
            }
            if !value.trim().is_empty() {
                run_lines.push(value.trim().to_owned());
            }
        }
        if properties
            .insert(key.to_owned(), value.trim().to_owned())
            .is_some()
        {
            return Err(format!("workflow step property {key} is duplicated"));
        }
        index += 1;
    }
    if let Some(environment_index) = lines.iter().position(|line| *line == "        env:") {
        for line in &lines[environment_index + 1..] {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let Some(entry) = line.strip_prefix("          ") else {
                break;
            };
            if entry.starts_with(' ') {
                return Err("workflow step environment entry is malformed".to_owned());
            }
            let (key, value) = entry
                .split_once(':')
                .ok_or_else(|| "workflow step environment entry is malformed".to_owned())?;
            if key.is_empty()
                || value.trim().is_empty()
                || environment
                    .insert(key.to_owned(), value.trim().to_owned())
                    .is_some()
            {
                return Err("workflow step environment entry is empty or duplicated".to_owned());
            }
        }
    }
    if let Some(inputs_index) = lines.iter().position(|line| *line == "        with:") {
        for line in &lines[inputs_index + 1..] {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let Some(entry) = line.strip_prefix("          ") else {
                break;
            };
            if entry.starts_with(' ') {
                continue;
            }
            let (key, value) = entry
                .split_once(':')
                .ok_or_else(|| "workflow step input entry is malformed".to_owned())?;
            if key.is_empty()
                || value.trim().is_empty()
                || inputs
                    .insert(key.to_owned(), value.trim().to_owned())
                    .is_some()
            {
                return Err("workflow step input entry is empty or duplicated".to_owned());
            }
        }
    }
    Ok(WorkflowStep {
        properties,
        environment,
        inputs,
        run_lines,
    })
}

fn command_words(line: &str) -> Vec<&str> {
    line.trim()
        .split_ascii_whitespace()
        .filter(|word| *word != "\\")
        .collect()
}

fn continuation_statements(step: &WorkflowStep, continuation: char) -> Vec<String> {
    let mut statements = Vec::new();
    let mut current = String::new();
    for line in &step.run_lines {
        let trimmed = line.trim();
        let continued = trimmed.ends_with(continuation);
        let part = trimmed.trim_end_matches(continuation).trim_end();
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(part);
        if !continued {
            statements.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        statements.push(current);
    }
    statements
}

fn contains_early_control_flow(step: &WorkflowStep) -> bool {
    step.run_lines.iter().any(|line| {
        line.split_ascii_whitespace().any(|word| {
            matches!(
                word.trim_matches(|character: char| {
                    matches!(character, ';' | '(' | ')' | '{' | '}')
                }),
                "exit" | "return"
            )
        })
    })
}

fn is_cargo_test_statement(statement: &str) -> bool {
    let words = command_words(statement);
    let Some(cargo) = words.iter().position(|word| *word == "cargo") else {
        return false;
    };
    let command = if words
        .get(cargo + 1)
        .is_some_and(|word| word.starts_with('+'))
    {
        cargo + 2
    } else {
        cargo + 1
    };
    words.get(command) == Some(&"test")
}

fn selects_package(statement: &str, package: &str) -> bool {
    command_words(statement)
        .windows(2)
        .any(|pair| pair[0] == "-p" && pair[1] == package)
}

fn is_cargo_library_test(line: &str, package: &str, target_required: bool) -> bool {
    let words = command_words(line);
    let actual: Vec<_> = words
        .iter()
        .map(|word| word.trim_matches(|character| matches!(character, '"' | '\'')))
        .collect();
    let expected = if target_required {
        vec![
            "cargo",
            "+1.97.1",
            "test",
            "-p",
            package,
            "--lib",
            "--no-default-features",
            "--features",
            "fuzzing",
            "--locked",
            "--target",
            "${{",
            "matrix.target",
            "}}",
        ]
    } else {
        vec![
            "cargo",
            "test",
            "-p",
            package,
            "--lib",
            "--no-default-features",
            "--features",
            "fuzzing",
            "--locked",
        ]
    };
    actual == expected
}

fn job_runs_library_test(
    job: &WorkflowJob,
    package: &str,
    target_required: bool,
    required_step_condition: Option<&str>,
) -> bool {
    job.steps.iter().any(|step| {
        step.properties.get("if").map(String::as_str) == required_step_condition
            && !step.properties.contains_key("continue-on-error")
            && step
                .run_lines
                .iter()
                .any(|line| is_cargo_library_test(line, package, target_required))
    })
}

pub(super) fn validate_read_only_permissions(source: &str) -> Result<(), String> {
    let permissions = workflow_mapping(source, "permissions")?;
    if permissions == BTreeMap::from([("contents".to_owned(), "read".to_owned())]) {
        Ok(())
    } else {
        Err(format!(
            "workflow permissions are not exactly read-only: {permissions:?}"
        ))
    }
}

pub(super) fn validate_lifecycle_triggers(source: &str) -> Result<(), String> {
    let triggers = workflow_mapping(source, "on")?;
    let expected = BTreeMap::from([
        ("push".to_owned(), String::new()),
        ("workflow_dispatch".to_owned(), String::new()),
    ]);
    if triggers != expected {
        return Err(format!("lifecycle trigger set drifted: {triggers:?}"));
    }
    for trigger in expected.keys() {
        if !workflow_child_mapping(source, "on", trigger)?.is_empty() {
            return Err(format!(
                "lifecycle {trigger} trigger must not be narrowed by filters"
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_hosted_library_execution(source: &str) -> Result<(), String> {
    let jobs = workflow_jobs(source)?;
    let linux = jobs
        .get("quality")
        .ok_or_else(|| "main workflow quality job is missing".to_owned())?;
    if linux.properties.contains_key("continue-on-error") {
        return Err("main workflow quality job must not suppress failures".to_owned());
    }
    if linux.properties.get("runs-on").map(String::as_str) != Some("ubuntu-24.04") {
        return Err("main workflow quality job is not pinned to the Linux host".to_owned());
    }
    for package in ["ferrum2-tun", "ferrum2-platform-windows"] {
        if !job_runs_library_test(linux, package, false, None) {
            return Err(format!(
                "Linux quality job does not execute {package} --lib with the reviewed hosted features"
            ));
        }
    }
    let linux_hosted_steps: Vec<_> = linux
        .steps
        .iter()
        .filter(|step| {
            ["ferrum2-tun", "ferrum2-platform-windows"]
                .iter()
                .any(|package| {
                    step.run_lines
                        .iter()
                        .any(|line| is_cargo_library_test(line, package, false))
                })
        })
        .collect();
    let expected_linux_sequence = [
        "set -euo pipefail",
        "cargo test -p ferrum2-client --all-features --no-run --locked",
        "cargo test -p ferrum2-tun --lib --no-default-features --features fuzzing --locked",
        "cargo test -p ferrum2-platform-windows --lib --no-default-features --features fuzzing --locked",
    ];
    if linux_hosted_steps.len() != 1
        || linux_hosted_steps[0]
            .properties
            .get("name")
            .map(String::as_str)
            != Some("Run portable TUN and Windows platform unit tests")
        || linux_hosted_steps[0]
            .properties
            .get("shell")
            .map(String::as_str)
            != Some("bash")
        || linux_hosted_steps[0].properties.contains_key("if")
        || linux_hosted_steps[0]
            .properties
            .contains_key("continue-on-error")
        || !linux_hosted_steps[0].environment.is_empty()
        || !linux_hosted_steps[0].inputs.is_empty()
        || linux_hosted_steps[0].run_lines != expected_linux_sequence
    {
        return Err(
            "Linux hosted tests must be the exact unconditional execution sequence".to_owned(),
        );
    }

    let platform = jobs
        .get("platform")
        .ok_or_else(|| "main workflow platform job is missing".to_owned())?;
    if platform.properties.contains_key("continue-on-error") {
        return Err("main workflow platform job must not suppress failures".to_owned());
    }
    let windows_rows: Vec<_> = platform
        .matrix_include
        .iter()
        .filter(|row| row.get("profile").map(String::as_str) == Some("windows-msvc"))
        .collect();
    let matrix_properties: BTreeSet<_> = platform
        .properties
        .keys()
        .filter(|key| key.starts_with("strategy.matrix."))
        .map(String::as_str)
        .collect();
    let expected_windows_row = BTreeMap::from([
        ("profile".to_owned(), "windows-msvc".to_owned()),
        ("runner".to_owned(), "windows-2022".to_owned()),
        ("target".to_owned(), "x86_64-pc-windows-msvc".to_owned()),
    ]);
    if matrix_properties != BTreeSet::from(["strategy.matrix.include"])
        || windows_rows.len() != 1
        || windows_rows[0] != &expected_windows_row
    {
        return Err(
            "Windows platform matrix row is not the exact reviewed profile/target".to_owned(),
        );
    }
    for package in ["ferrum2-tun", "ferrum2-platform-windows"] {
        let expected_name = if package == "ferrum2-tun" {
            "Run hosted-safe Windows TUN unit tests"
        } else {
            "Run hosted-safe Windows platform unit tests"
        };
        let expected_command = format!(
            "cargo +1.97.1 test -p {package} --lib --no-default-features --features fuzzing --locked --target ${{{{ matrix.target }}}}"
        );
        let execution_steps: Vec<_> = platform
            .steps
            .iter()
            .filter(|step| {
                step.run_lines
                    .iter()
                    .any(|line| is_cargo_library_test(line, package, true))
            })
            .collect();
        if execution_steps.len() != 1
            || execution_steps[0]
                .properties
                .get("name")
                .map(String::as_str)
                != Some(expected_name)
            || execution_steps[0].properties.get("if").map(String::as_str)
                != Some("matrix.profile == 'windows-msvc'")
            || execution_steps[0]
                .properties
                .get("shell")
                .map(String::as_str)
                != Some("pwsh")
            || execution_steps[0]
                .properties
                .contains_key("continue-on-error")
            || !execution_steps[0].environment.is_empty()
            || !execution_steps[0].inputs.is_empty()
            || execution_steps[0].run_lines
                != [
                    "$ErrorActionPreference = \"Stop\"",
                    "$PSNativeCommandUseErrorActionPreference = $true",
                    expected_command.as_str(),
                ]
        {
            return Err(format!(
                "Windows platform job does not execute {package} in one exact unconditional step"
            ));
        }
    }
    let hosted_pe_steps: Vec<_> = platform
        .steps
        .iter()
        .filter(|step| {
            step.properties.get("if").map(String::as_str)
                == Some("matrix.profile == 'windows-msvc'")
                && step.properties.get("shell").map(String::as_str) == Some("pwsh")
                && step.properties.get("name").map(String::as_str)
                    == Some("Prove hosted-safe Windows test imports")
                && step
                    .run_lines
                    .iter()
                    .any(|line| line.contains("hosted_test_pe_imports status=PASS"))
        })
        .collect();
    if hosted_pe_steps.len() != 1 {
        return Err("Windows hosted tests are not owned by one exact execution step".to_owned());
    }
    hosted_pe_contract::validate_hosted_pe_imports(hosted_pe_steps[0])?;

    let all_statements: Vec<_> = jobs
        .values()
        .flat_map(|job| &job.steps)
        .flat_map(|step| {
            continuation_statements(
                step,
                if step.properties.get("shell").map(String::as_str) == Some("pwsh") {
                    '`'
                } else {
                    '\\'
                },
            )
        })
        .filter(|statement| is_cargo_test_statement(statement))
        .collect();
    for package in ["ferrum2-tun", "ferrum2-platform-windows"] {
        let count = all_statements
            .iter()
            .filter(|statement| selects_package(statement, package))
            .count();
        if count != 2 {
            return Err(format!(
                "hosted test command surface for {package} is not exactly Linux plus Windows: {count}"
            ));
        }
    }
    let generic_resolvers = all_statements
        .iter()
        .filter(|statement| selects_package(statement, "$Package"))
        .count();
    let other_hosted_selectors = all_statements
        .iter()
        .filter(|statement| {
            ["ferrum2-tun", "ferrum2-platform-windows", "$Package"]
                .iter()
                .any(|package| selects_package(statement, package))
        })
        .count();
    if generic_resolvers != 1 || other_hosted_selectors != 5 {
        return Err(format!(
            "hosted cargo-test surface is not closed: generic={generic_resolvers}, total={other_hosted_selectors}"
        ));
    }
    let exact_workspace_test = "cargo test --workspace --exclude ferrum2-client --exclude ferrum2-tun --exclude ferrum2-platform-windows --locked";
    let workspace_tests: Vec<_> = all_statements
        .iter()
        .filter(|statement| command_words(statement).contains(&"--workspace"))
        .map(String::as_str)
        .collect();
    if workspace_tests != [exact_workspace_test] {
        return Err(format!(
            "workspace cargo-test exclusion surface drifted: {workspace_tests:?}"
        ));
    }
    let implicit_or_manifest_tests: Vec<_> = all_statements
        .iter()
        .filter(|statement| {
            let words = command_words(statement);
            statement.as_str() != exact_workspace_test
                && (!words.contains(&"-p")
                    || words.contains(&"--manifest-path")
                    || words.contains(&"--all"))
        })
        .collect();
    if !implicit_or_manifest_tests.is_empty() {
        return Err(format!(
            "workflow contains implicit or manifest-selected cargo tests: {implicit_or_manifest_tests:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "workflow_contract_tests.rs"]
mod tests;
