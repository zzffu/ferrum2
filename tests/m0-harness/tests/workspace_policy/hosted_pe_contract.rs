use std::collections::BTreeSet;

use super::{WorkflowStep, command_words, commands_equivalent, continuation_statements};

fn has_comparison(step: &WorkflowStep, left: &str, operator: &str, right: &str) -> bool {
    step.run_lines.iter().any(|line| {
        let words = command_words(line);
        words.windows(3).any(|window| {
            window[0].trim_matches(|character| matches!(character, '(' | ')' | '"' | '\'')) == left
                && window[1] == operator
                && window[2].trim_matches(|character| matches!(character, '(' | ')' | '"' | '\''))
                    == right
        })
    })
}

fn trimmed_line_count(step: &WorkflowStep, expected: &str) -> usize {
    step.run_lines
        .iter()
        .filter(|line| line.trim() == expected)
        .count()
}

fn unique_line_index(step: &WorkflowStep, expected: &str) -> Result<usize, String> {
    let matches: Vec<_> = step
        .run_lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.trim() == expected)
        .map(|(index, _)| index)
        .collect();
    if matches.len() == 1 {
        Ok(matches[0])
    } else {
        Err(format!(
            "hosted PE proof line is missing or duplicated: {expected}"
        ))
    }
}

fn powershell_array(step: &WorkflowStep, variable: &str) -> Result<Vec<String>, String> {
    let header = format!("{variable} = @(");
    let matches: Vec<_> = step
        .run_lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.trim() == header)
        .map(|(index, _)| index)
        .collect();
    if matches.len() != 1 {
        return Err(format!(
            "PowerShell array {variable} is missing or duplicated"
        ));
    }
    let mut values = Vec::new();
    for line in &step.run_lines[matches[0] + 1..] {
        let value = line.trim();
        if value == ")" {
            break;
        }
        let value = value.trim_end_matches(',').trim_end();
        if value.len() < 2 || !value.starts_with('\'') || !value.ends_with('\'') {
            return Err(format!(
                "PowerShell array {variable} contains a non-literal item"
            ));
        }
        values.push(value[1..value.len() - 1].to_owned());
    }
    if values.is_empty() {
        return Err(format!("PowerShell array {variable} is empty"));
    }
    Ok(values)
}

fn resolves_exact_hosted_test(step: &WorkflowStep) -> bool {
    continuation_statements(step, '`').iter().any(|statement| {
        statement
            .strip_prefix("$events = & ")
            .and_then(|command| command.strip_suffix(" 2>&1"))
            .is_some_and(|command| {
                commands_equivalent(
                    command,
                    "cargo +1.97.1 test -p $Package --lib --no-default-features --features fuzzing --locked --no-run --message-format=json --target ${{ matrix.target }}",
                )
            })
    })
}

pub(super) fn validate_hosted_pe_imports(step: &WorkflowStep) -> Result<(), String> {
    if !resolves_exact_hosted_test(step) {
        let candidates: Vec<_> = continuation_statements(step, '`')
            .into_iter()
            .filter(|statement| statement.contains("$events = & cargo"))
            .collect();
        return Err(format!(
            "hosted PE resolver does not rebuild the exact safe test graph: {candidates:?}"
        ));
    }
    for (package, target_name) in [
        ("ferrum2-tun", "ferrum2_tun"),
        ("ferrum2-platform-windows", "ferrum2_platform_windows"),
    ] {
        let call = format!(
            "Resolve-HostedTestExecutable -Package '{package}' -TargetName '{target_name}'"
        );
        let matches = continuation_statements(step, '`')
            .iter()
            .filter(|statement| {
                statement
                    .strip_prefix("Path = ")
                    .is_some_and(|command| commands_equivalent(command, &call))
            })
            .count();
        if matches != 1 {
            return Err(format!("hosted PE resolver call drifted for {package}"));
        }
    }
    let resolver_calls = step
        .run_lines
        .iter()
        .filter(|line| {
            line.contains("Resolve-HostedTestExecutable")
                && !line.trim_start().starts_with("function ")
        })
        .count();
    let resolver_builds = continuation_statements(step, '`')
        .iter()
        .filter(|statement| statement.contains("$events = & cargo"))
        .count();
    if resolver_calls != 2 || resolver_builds != 1 {
        return Err(format!(
            "hosted PE resolver surface is not closed: calls={resolver_calls}, builds={resolver_builds}"
        ));
    }
    for (left, operator, right) in [
        ("$event.reason", "-eq", "compiler-artifact"),
        ("$event.target.name", "-eq", "$TargetName"),
        ("$event.profile.test", "-eq", "$true"),
        ("$executables.Count", "-ne", "1"),
    ] {
        if !has_comparison(step, left, operator, right) {
            return Err(format!(
                "hosted PE artifact selection lost {left} {operator} {right}"
            ));
        }
    }
    for exact in [
        "$event.executable) {",
        "$depsRoot = [IO.Path]::GetFullPath(\"target\\${{ matrix.target }}\\debug\\deps\")",
        "$depsRoot + [IO.Path]::DirectorySeparatorChar,",
        "[StringComparison]::OrdinalIgnoreCase",
        "if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {",
        "foreach ($entry in $hostedTests) {",
        "$imports = & $dumpbin /imports $entry.Path 2>&1 | Out-String",
        "if ($violations.Count -ne 0) {",
    ] {
        if trimmed_line_count(step, exact) != 1 {
            return Err(format!(
                "hosted PE import readback lost exact guard: {exact}"
            ));
        }
    }

    // Exit status must be consumed before artifact parsing/import filtering.
    // Keep this ordered PowerShell envelope narrow rather than accepting
    // arbitrary expressions that merely mention the expected status variable.
    let statements: Vec<_> = continuation_statements(step, '`')
        .into_iter()
        .filter(|statement| !statement.is_empty() && !statement.starts_with('#'))
        .collect();
    for (invocation, guard) in [
        (
            "$events = & ",
            &[
                "$status = $LASTEXITCODE",
                "if ($status -ne 0) {",
                "$events | ForEach-Object { Write-Output ([string] $_) }",
            ][..],
        ),
        (
            "$imports = & $dumpbin /imports ",
            &["if ($LASTEXITCODE -ne 0 -or $imports -notmatch 'Dump of file') {"][..],
        ),
    ] {
        let Some(index) = statements
            .iter()
            .position(|line| line.starts_with(invocation))
        else {
            return Err("hosted PE invocation is missing".to_owned());
        };
        if !statements[index + 1..]
            .iter()
            .map(String::as_str)
            .take(guard.len())
            .eq(guard.iter().copied())
            || !statements
                .get(index + 1 + guard.len())
                .is_some_and(|line| line.starts_with("throw "))
        {
            return Err("hosted PE command failure is not immediately propagated".to_owned());
        }
    }

    let returns: Vec<_> = step
        .run_lines
        .iter()
        .map(|line| line.trim())
        .filter(|line| line.starts_with("return") || line.starts_with("exit"))
        .collect();
    if returns != ["return $executable"] {
        return Err(format!(
            "hosted PE step contains unreviewed early control flow: {returns:?}"
        ));
    }
    let unreviewed_control_flow: Vec<_> = step
        .run_lines
        .iter()
        .map(|line| line.trim())
        .filter(|line| *line != "return $executable")
        .filter(|line| {
            line.split_ascii_whitespace().any(|word| {
                matches!(
                    word.trim_matches(|character: char| {
                        matches!(character, ';' | '(' | ')' | '{' | '}')
                    }),
                    "exit" | "return"
                )
            })
        })
        .collect();
    if !unreviewed_control_flow.is_empty() {
        return Err(format!(
            "hosted PE step contains inline early control flow: {unreviewed_control_flow:?}"
        ));
    }
    let path_guard = unique_line_index(
        step,
        "if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {",
    )?;
    let return_index = unique_line_index(step, "return $executable")?;
    if return_index <= path_guard {
        return Err("hosted PE resolver returns before path validation".to_owned());
    }
    let imports = unique_line_index(
        step,
        "$imports = & $dumpbin /imports $entry.Path 2>&1 | Out-String",
    )?;
    let violation_guard = unique_line_index(step, "if ($violations.Count -ne 0) {")?;
    let pass = unique_line_index(
        step,
        "Write-Output \"hosted_test_pe_imports status=PASS package=$($entry.Name) live_backend_imports=0\"",
    )?;
    if !(imports < violation_guard && violation_guard < pass) {
        return Err("hosted PE proof can report success before import validation".to_owned());
    }
    let import_invocations = step
        .run_lines
        .iter()
        .filter(|line| line.contains("$dumpbin /imports"))
        .count();
    let proof_outputs = step
        .run_lines
        .iter()
        .filter(|line| line.contains("hosted_test_pe_imports status=PASS"))
        .count();
    if import_invocations != 1 || proof_outputs != 1 {
        return Err(format!(
            "hosted PE proof surface is not closed: imports={import_invocations}, pass={proof_outputs}"
        ));
    }

    let actual: BTreeSet<_> = powershell_array(step, "$forbiddenHostedImports")?
        .into_iter()
        .collect();
    let expected = BTreeSet::from([
        "(?i)\\biphlpapi\\.dll\\b".to_owned(),
        "(?i)\\bfwpuclnt\\.dll\\b".to_owned(),
        "(?i)\\bwintun\\.dll\\b".to_owned(),
        "(?i)\\b(?:Create|Delete|Set)IpForwardEntry2\\b".to_owned(),
        "(?i)\\b(?:Create|Delete|Set)UnicastIpAddressEntry\\b".to_owned(),
        "(?i)\\bSetInterfaceDnsSettings\\b".to_owned(),
        "(?i)\\bSetIpInterfaceEntry\\b".to_owned(),
        "(?i)\\bFwpm[A-Za-z0-9_]*\\b".to_owned(),
        "(?i)\\bWintun[A-Za-z0-9_]*\\b".to_owned(),
    ]);
    if actual != expected {
        return Err(format!("hosted PE import denylist drifted: {actual:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_resolver_accepts_argument_order_but_preserves_identity_and_failures() {
        let source =
            std::fs::read_to_string(crate::workspace_root().join(".github/workflows/m0.yml"))
                .expect("ordinary workflow");
        let jobs = super::super::workflow_jobs(&source).expect("workflow jobs");
        let mut step = jobs
            .into_values()
            .flat_map(|job| job.steps)
            .find(|step| {
                step.run_lines
                    .iter()
                    .any(|line| line.contains("function Resolve-HostedTestExecutable"))
            })
            .expect("hosted resolver role");
        step.properties.insert(
            "name".to_owned(),
            "Inspect safe executable imports".to_owned(),
        );
        for line in &mut step.run_lines {
            *line = line
                .replace(
                    "-Package 'ferrum2-tun' -TargetName 'ferrum2_tun'",
                    "-TargetName 'ferrum2_tun' -Package 'ferrum2-tun'",
                )
                .replace("--features fuzzing --locked", "--locked --features=fuzzing");
        }
        validate_hosted_pe_imports(&step).expect("equivalent resolver");
        for (from, to) in [
            ("--features=fuzzing", "--features=system"),
            ("-TargetName 'ferrum2_tun'", "-TargetName 'ferrum2_client'"),
            ("if ($status -ne 0)", "if ($status -eq 0)"),
            (
                "if ($LASTEXITCODE -ne 0 -or $imports",
                "if ($LASTEXITCODE -eq 0 -or $imports",
            ),
        ] {
            let mut mutated = WorkflowStep {
                properties: step.properties.clone(),
                environment: step.environment.clone(),
                inputs: step.inputs.clone(),
                run_lines: step.run_lines.clone(),
            };
            assert!(mutated.run_lines.iter().any(|line| line.contains(from)));
            for line in &mut mutated.run_lines {
                *line = line.replace(from, to);
            }
            assert!(validate_hosted_pe_imports(&mutated).is_err());
        }
    }
}
