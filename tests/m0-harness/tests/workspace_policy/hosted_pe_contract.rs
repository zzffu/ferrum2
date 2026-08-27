use std::collections::BTreeSet;

use super::{WorkflowStep, command_words, continuation_statements};

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
        let words = command_words(statement);
        let actual: Vec<_> = words
            .iter()
            .map(|word| word.trim_matches(|character| matches!(character, '"' | '\'')))
            .collect();
        actual
            == [
                "$events",
                "=",
                "&",
                "cargo",
                "+1.97.1",
                "test",
                "-p",
                "$Package",
                "--lib",
                "--no-default-features",
                "--features",
                "fuzzing",
                "--locked",
                "--no-run",
                "--message-format=json",
                "--target",
                "${{",
                "matrix.target",
                "}}",
                "2>&1",
            ]
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
            "Path = Resolve-HostedTestExecutable -Package '{package}' -TargetName '{target_name}'"
        );
        if trimmed_line_count(step, &call) != 1 {
            return Err(format!("hosted PE resolver call drifted for {package}"));
        }
    }
    let resolver_calls = step
        .run_lines
        .iter()
        .filter(|line| {
            line.contains("Resolve-HostedTestExecutable -Package")
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
