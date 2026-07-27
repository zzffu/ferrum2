use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SYNTHETIC_PSK: &str = "AAECAwQFBgcICQoLDA0ODw==";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("harness is nested under tests/")
        .to_path_buf()
}

#[test]
fn reference_pin_policy() {
    let pins = fs::read_to_string(repository_root().join("tests/interop/versions.toml"))
        .expect("read required reference pins");

    for required in [
        "version = \"1.13.14\"",
        "source_commit = \"25a600db24f7680ad9806ce5427bd0ab8afe1114\"",
        "linux_sha256 = \"aae9172317c61760aae3dafcde889b2e51b7ea590c40d2b3c7ccdeae14b361b6\"",
        "windows_sha256 = \"f580782c6dd10f7691c66cea1d7c421813c5fbf7e305d1ee7ce0c3a40d196341\"",
        "version = \"1.24.0\"",
        "source_commit = \"7ee1aa9223ed8f4d34734aac919036c8ad4502c2\"",
        "linux_sha256 = \"5f528efb4e51e732352f5c69538dcc76e8cf8f6d1a240dfb5b748a67f0b05f65\"",
        "windows_sha256 = \"8f4bdd02cf3b42976f6b48e01239bc0ae61f9da7a3c260505a7880de615291d0\"",
        "license_review",
        "expected_version",
        "linux_size",
        "windows_size",
    ] {
        assert!(
            pins.contains(required),
            "missing pin field/value: {required}"
        );
    }
    assert!(!pins.to_ascii_lowercase().contains("latest"));
}

#[test]
fn platform_config_fixture_policy() {
    let root = repository_root();
    for (path, role, psk) in [
        (
            "tests/platform/config/client-valid.toml",
            "[client]",
            SYNTHETIC_PSK,
        ),
        (
            "tests/platform/config/client-invalid-key-length.toml",
            "[client]",
            "AAECAwQFBgcICQoLDA0O",
        ),
        (
            "tests/platform/config/server-valid.toml",
            "[server]",
            SYNTHETIC_PSK,
        ),
        (
            "tests/platform/config/server-invalid-key-length.toml",
            "[server]",
            "AAECAwQFBgcICQoLDA0O",
        ),
    ] {
        let fixture =
            fs::read_to_string(root.join(path)).unwrap_or_else(|error| panic!("{path}: {error}"));
        assert!(fixture.contains("schema_version = 1"));
        assert!(fixture.contains(role));
        assert!(fixture.contains("method = \"2022-blake3-aes-128-gcm\""));
        assert!(fixture.contains(&format!("psk = \"{psk}\"")));
        assert!(fixture.contains("[metrics]"));
        assert!(fixture.contains("listen = \"127.0.0.1:9090\""));
    }
    let helper = fs::read_to_string(root.join("tests/platform/check_config_no_side_effects.rs"))
        .expect("std-only platform helper");
    assert!(helper.contains("#![forbid(unsafe_code)]"));
    assert_eq!(
        helper.matches("Case {").count(),
        4,
        "exact four platform cases"
    );
    for required in [
        "--self-test",
        "forbidden connector side effect",
        "--mutation-listen-exit2",
        "TcpListener::bind",
        "try_wait()",
        "configuration valid\\n",
        "error[config.semantic] shadowsocks.psk: configuration value is invalid\\n",
        "expected_exit: 0",
        "expected_exit: 2",
        "4/4 exact outputs/exits and no listener was created",
    ] {
        assert!(
            helper.contains(required),
            "platform helper omits {required}"
        );
    }
    assert!(
        !helper.contains("zero socket side effects"),
        "platform helper must not overclaim that no bind was attempted"
    );
    assert_offline_entrypoint(&root.join("bins/ferrum2-client/src/main.rs"), "load_client");
    assert_offline_entrypoint(&root.join("bins/ferrum2-server/src/main.rs"), "load_server");
}

fn assert_offline_entrypoint(path: &Path, loader: &str) {
    let source = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .replace("\r\n", "\n");
    assert_eq!(
        source.matches(&format!("{loader}(&cli.config)")).count(),
        1,
        "{} must call the pure config loader exactly once",
        path.display()
    );
    assert_eq!(
        source.matches("run::run(").count(),
        1,
        "{} must have exactly one runtime entrypoint",
        path.display()
    );
    let load = source
        .find(&format!("{loader}(&cli.config)"))
        .expect("loader");
    let check = source[load..]
        .find("if cli.check_config {")
        .map(|offset| load + offset)
        .expect("offline check branch");
    let success = source[check..]
        .find("return ExitCode::SUCCESS;")
        .map(|offset| check + offset)
        .expect("offline success return");
    let runtime = source.find("run::run(config)").expect("runtime entrypoint");
    assert!(
        load < check && check < success && success < runtime,
        "{} must load config, return from --check-config, then and only then enter runtime",
        path.display()
    );
}

#[test]
fn workflow_policy() {
    let root = repository_root();
    let workflow_dir = root.join(".github/workflows");
    let workflows = fs::read_dir(&workflow_dir)
        .expect("read sole workflow directory")
        .map(|entry| entry.expect("workflow entry").path())
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    assert_eq!(
        workflows,
        [workflow_dir.join("m0.yml")],
        "M0 permits exactly one workflow"
    );
    let workflow = fs::read_to_string(&workflows[0]).expect("read M0 workflow");
    validate_workflow(&workflow).expect("strict workflow contract");

    for (label, mutation) in [
        (
            "unknown trigger",
            workflow.replacen(
                "  workflow_dispatch:",
                "  schedule:\n  workflow_dispatch:",
                1,
            ),
        ),
        (
            "double-quoted unknown trigger",
            workflow.replacen(
                "  workflow_dispatch:",
                "  \"schedule\":\n  workflow_dispatch:",
                1,
            ),
        ),
        (
            "single-quoted job permission elevation",
            workflow.replacen(
                "    timeout-minutes: 60",
                "    'permissions': write\n    timeout-minutes: 60",
                1,
            ),
        ),
        (
            "double-quoted job permission elevation",
            workflow.replacen(
                "    timeout-minutes: 60",
                "    \"permissions\": write\n    timeout-minutes: 60",
                1,
            ),
        ),
        (
            "mapping anchor and merge alias",
            workflow
                .replacen("permissions:\n", "permissions: &elevated\n", 1)
                .replacen(
                    "    timeout-minutes: 60",
                    "    <<: *elevated\n    timeout-minutes: 60",
                    1,
                ),
        ),
        (
            "unsupported alias value",
            workflow.replacen(
                "  workflow_dispatch:",
                "  workflow_dispatch: *dispatch",
                1,
            ),
        ),
        (
            "underscore job ID",
            workflow.replacen(
                "  m0-host-quick:",
                "  evil_job:\n    name: evil_job\n    runs-on: ubuntu-24.04\n    timeout-minutes: 60\n    steps: []\n  m0-host-quick:",
                1,
            ),
        ),
        (
            "uppercase job ID",
            workflow.replacen(
                "  m0-host-quick:",
                "  EVIL-JOB:\n    name: EVIL-JOB\n    runs-on: ubuntu-24.04\n    timeout-minutes: 60\n    steps: []\n  m0-host-quick:",
                1,
            ),
        ),
        (
            "nameless run step",
            workflow.replacen(
                "      - name: Verify clean current SHA",
                "      - run: echo bypass\n      - name: Verify clean current SHA",
                1,
            ),
        ),
        (
            "arbitrary extra shell",
            workflow.replacen(
                "          set -euo pipefail",
                "          set -euo pipefail\n          echo unallowlisted-command",
                1,
            ),
        ),
        (
            "duplicate trigger",
            workflow.replacen(
                "  workflow_dispatch:",
                "  workflow_dispatch:\n  workflow_dispatch:",
                1,
            ),
        ),
        (
            "per-job command relocation",
            workflow.replacen(
                "          cargo +1.85.0 build --workspace --bins --locked",
                "          cargo build --workspace --bins --locked",
                1,
            ),
        ),
        (
            "zero exact filter",
            workflow.replacen(
                "            test \"$count\" -eq 1",
                "            test \"$count\" -eq 0",
                1,
            ),
        ),
        (
            "wrong build-script JSON field",
            workflow.replacen(".cfgs", ".cfg", 1),
        ),
        (
            "unknown job field",
            workflow.replacen(
                "    timeout-minutes: 60",
                "    timeout-minutes: 60\n    unexpected-field: true",
                1,
            ),
        ),
    ] {
        assert!(
            validate_workflow(&mutation).is_err(),
            "workflow mutation escaped strict validator: {label}"
        );
    }
}

#[test]
fn fixed_baseline_scope_and_provenance_audit() {
    const BASELINE: &str = "b41c6127b1834ebd97246451fd92bafea50cb205";
    let root = repository_root();
    let ancestor = Command::new("git")
        .args(["merge-base", "--is-ancestor", BASELINE, "HEAD"])
        .current_dir(&root)
        .status()
        .expect("git merge-base");
    assert!(ancestor.success(), "fixed baseline must be an ancestor");
    let output = Command::new("git")
        .args([
            "diff",
            "--name-status",
            "--find-renames",
            &format!("{BASELINE}...HEAD"),
        ])
        .current_dir(&root)
        .output()
        .expect("fixed-baseline diff");
    assert!(output.status.success(), "fixed-baseline diff failed");
    let changed = String::from_utf8(output.stdout).expect("UTF-8 changed paths");
    for path in changed_paths(&changed) {
        assert!(
            is_immutable_owned(path) || is_control_document(path),
            "path is outside immutable M0 ownership/control allowlist: {path}"
        );
        assert_safe_changed_path(path);
        scan_changed_text(&root, path);
    }
    let mutable_ticket = fs::read_to_string(
        root.join("docs/tickets/M0-T08-interop-platform-and-integration-gates.md"),
    )
    .expect("T08 ticket");
    let expanded = mutable_ticket.replacen(
        "owns = [",
        "owns = [\n  \"unapproved/mutable-expansion/**\",",
        1,
    );
    assert!(expanded.contains("unapproved/mutable-expansion/**"));
    assert!(
        !is_immutable_owned("unapproved/mutable-expansion/payload.bin"),
        "mutable current ticket text must never authorize baseline scope"
    );

    for group in ["tests/fixtures/crypto", "tests/fixtures/sip022"] {
        let provenance_path = root.join(group).join("PROVENANCE.toml");
        let provenance = fs::read_to_string(&provenance_path)
            .unwrap_or_else(|error| panic!("{}: {error}", provenance_path.display()));
        for required in ["source =", "fixture_sha256 =", "expected_interpretation ="] {
            assert!(
                provenance.contains(required),
                "{} lacks {required}",
                provenance_path.display()
            );
        }
        assert!(
            provenance.contains("source_license =") || provenance.contains("rights_review ="),
            "{} lacks license-or-rights review",
            provenance_path.display()
        );
    }

    let production_scan = Command::new("rg")
        .args([
            "-n",
            "-i",
            "fixture.only|scripted.*random|bypass",
            "bins",
            "crates",
            "--glob",
            "!**/tests/**",
        ])
        .current_dir(&root)
        .output()
        .expect("production bypass scan");
    assert!(
        production_scan.status.code() == Some(1) && production_scan.stdout.is_empty(),
        "production tree contains fixture-only key, scripted RNG, or bypass marker"
    );
}

fn validate_workflow(workflow: &str) -> Result<(), String> {
    if workflow.contains('\r') {
        let normalized = workflow.replace("\r\n", "\n");
        if normalized.contains('\r') {
            return Err("bare carriage return is unsupported".into());
        }
        return validate_workflow(&normalized);
    }
    validate_yaml_lexical_subset(workflow)?;
    assert_exact_keys(workflow, 0, &["name", "on", "permissions", "jobs"])?;
    let header = workflow
        .split_once("jobs:\n")
        .ok_or_else(|| "missing jobs mapping".to_owned())?
        .0;
    let triggers = section(header, "on:", "permissions:")?;
    assert_exact_keys(triggers, 2, &["pull_request", "push", "workflow_dispatch"])?;
    let push = section(triggers, "  push:", "  workflow_dispatch:")?;
    assert_exact_keys(push, 4, &["branches"])?;
    let branches = push
        .lines()
        .filter(|line| line.starts_with("      - "))
        .map(str::trim)
        .collect::<Vec<_>>();
    if branches != ["- master", "- \"codex/integration/**\""] {
        return Err(format!(
            "exact push branch allowlist mismatch: {branches:?}"
        ));
    }
    let permissions = section(header, "permissions:", "jobs:").unwrap_or_else(|_| {
        header
            .split_once("permissions:")
            .map(|(_, tail)| tail)
            .unwrap_or("")
    });
    assert_exact_keys(permissions, 2, &["contents"])?;
    if !permissions.lines().any(|line| line == "  contents: read") {
        return Err("top-level contents: read permission missing".into());
    }

    let expected = [
        ("m0-host-quick", "ubuntu-24.04"),
        ("m0-security", "ubuntu-24.04"),
        ("m0-lifecycle", "ubuntu-24.04"),
        ("m0-local-e2e", "ubuntu-24.04"),
        ("m0-integration-full", "ubuntu-24.04"),
        ("m0-msrv", "ubuntu-24.04"),
        ("m0-windows-msvc", "windows-2022"),
        ("m0-linux-gnu", "ubuntu-24.04"),
        ("m0-linux-musl", "ubuntu-24.04"),
        ("m0-interop-sing-box", "ubuntu-24.04"),
        ("m0-interop-shadowsocks-rust", "ubuntu-24.04"),
    ];
    let jobs = job_blocks(workflow)?;
    let actual_ids = jobs.keys().map(String::as_str).collect::<Vec<_>>();
    let mut expected_ids = expected.iter().map(|(job, _)| *job).collect::<Vec<_>>();
    expected_ids.sort_unstable();
    if actual_ids != expected_ids {
        return Err(format!("exact required job IDs mismatch: {actual_ids:?}"));
    }
    for (job, runner) in expected {
        let block = jobs.get(job).ok_or_else(|| format!("missing job {job}"))?;
        assert_exact_keys(block, 4, &["name", "runs-on", "timeout-minutes", "steps"])?;
        require_once(block, &format!("    name: {job}\n"), job)?;
        require_once(block, &format!("    runs-on: {runner}\n"), job)?;
        require_once(block, "    timeout-minutes: 60\n", job)?;
        validate_steps(job, block)?;
        for evidence in [
            "GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT",
            "GITHUB_SHA",
            "RUNNER_OS",
            "RUNNER_ARCH",
            "ImageOS",
            "ImageVersion",
            "git status --porcelain",
        ] {
            require_once_or_more(block, evidence, job)?;
        }
    }

    for forbidden in [
        "secrets.",
        "continue-on-error",
        "ubuntu-latest",
        "windows-latest",
        "pull_request_target",
        "workflow_run",
        "repository_dispatch",
    ] {
        if workflow.to_ascii_lowercase().contains(forbidden) {
            return Err(format!("forbidden workflow value: {forbidden}"));
        }
    }
    validate_command_allocation(&jobs)?;
    validate_closed_workflow_snapshot(workflow)?;
    Ok(())
}

fn validate_yaml_lexical_subset(workflow: &str) -> Result<(), String> {
    let mut scalar_indent = None;
    for (index, line) in workflow.lines().enumerate() {
        if line.contains('\t') {
            return Err(format!(
                "line {} contains unsupported tab indentation",
                index + 1
            ));
        }
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        if let Some(owner_indent) = scalar_indent {
            if trimmed.is_empty() || indent > owner_indent {
                continue;
            }
            scalar_indent = None;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed == "---"
            || trimmed == "..."
            || trimmed.starts_with("%YAML")
            || trimmed.starts_with("? ")
        {
            return Err(format!(
                "line {} uses unsupported YAML document/key syntax",
                index + 1
            ));
        }
        let candidate = trimmed.strip_prefix("- ").unwrap_or(trimmed);
        if quoted_mapping_key(candidate) {
            return Err(format!(
                "line {} uses an unsupported quoted mapping key",
                index + 1
            ));
        }
        if candidate.starts_with("<<:") {
            return Err(format!(
                "line {} uses an unsupported YAML merge key",
                index + 1
            ));
        }
        if contains_unquoted_yaml_control(candidate) {
            return Err(format!(
                "line {} uses unsupported YAML anchor, alias, or tag syntax",
                index + 1
            ));
        }
        if let Some((_, value)) = candidate.split_once(':') {
            let value = value.trim_start();
            if value.starts_with('|') || value.starts_with('>') {
                scalar_indent = Some(indent);
            }
        }
    }
    Ok(())
}

fn quoted_mapping_key(text: &str) -> bool {
    let Some(quote) = text.as_bytes().first().copied() else {
        return false;
    };
    if quote != b'\'' && quote != b'"' {
        return false;
    }
    let mut escaped = false;
    for (index, byte) in text.bytes().enumerate().skip(1) {
        if quote == b'"' && byte == b'\\' && !escaped {
            escaped = true;
            continue;
        }
        if byte == quote && !escaped {
            return text[index + 1..].trim_start().starts_with(':');
        }
        escaped = false;
    }
    false
}

fn contains_unquoted_yaml_control(text: &str) -> bool {
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    let bytes = text.as_bytes();
    for (index, byte) in bytes.iter().copied().enumerate() {
        if double && byte == b'\\' && !escaped {
            escaped = true;
            continue;
        }
        if byte == b'\'' && !double {
            single = !single;
        } else if byte == b'"' && !single && !escaped {
            double = !double;
        } else if !single
            && !double
            && matches!(byte, b'&' | b'*' | b'!')
            && (index == 0
                || bytes[index - 1].is_ascii_whitespace()
                || matches!(bytes[index - 1], b':' | b'[' | b'{' | b','))
        {
            return true;
        }
        escaped = false;
    }
    single || double
}

fn validate_closed_workflow_snapshot(workflow: &str) -> Result<(), String> {
    const EXPECTED_BLOB_ID: &str = "4fed74274af633884c9ffb486e936283558d6558";
    let mut child = Command::new("git")
        .args(["hash-object", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn workflow snapshot hash: {error}"))?;
    use std::io::Write as _;
    child
        .stdin
        .take()
        .ok_or_else(|| "workflow snapshot stdin unavailable".to_owned())?
        .write_all(workflow.as_bytes())
        .map_err(|error| format!("write workflow snapshot: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait workflow snapshot hash: {error}"))?;
    if !output.status.success() {
        return Err("workflow snapshot hash command failed".into());
    }
    let actual = String::from_utf8(output.stdout)
        .map_err(|error| format!("workflow snapshot hash is not UTF-8: {error}"))?;
    if actual.trim() != EXPECTED_BLOB_ID {
        return Err(format!(
            "workflow contains an unallowlisted structural or command line: {}",
            actual.trim()
        ));
    }
    Ok(())
}

fn section<'a>(text: &'a str, start: &str, end: &str) -> Result<&'a str, String> {
    let tail = text
        .split_once(start)
        .ok_or_else(|| format!("missing section {start}"))?
        .1;
    Ok(tail
        .split_once(end)
        .ok_or_else(|| format!("missing section terminator {end}"))?
        .0)
}

fn assert_exact_keys(text: &str, indent: usize, expected: &[&str]) -> Result<(), String> {
    let mut keys = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let spaces = line.len() - line.trim_start().len();
        if spaces != indent || line.trim_start().starts_with("- ") {
            continue;
        }
        let Some((key, _)) = line.trim().split_once(':') else {
            return Err(format!(
                "unsupported mapping syntax at indent {indent}: {}",
                line.trim()
            ));
        };
        if !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(format!("unsupported mapping key at indent {indent}: {key}"));
        }
        if keys.contains(&key) {
            return Err(format!("duplicate mapping key at indent {indent}: {key}"));
        }
        keys.push(key);
    }
    if keys != expected {
        return Err(format!(
            "mapping keys at indent {indent} mismatch: actual={keys:?}, expected={expected:?}"
        ));
    }
    Ok(())
}

fn job_blocks(workflow: &str) -> Result<std::collections::BTreeMap<String, String>, String> {
    let jobs = workflow
        .split_once("jobs:\n")
        .ok_or_else(|| "jobs mapping missing".to_owned())?
        .1;
    let mut blocks = std::collections::BTreeMap::new();
    let mut current: Option<String> = None;
    for line in jobs.lines() {
        if line.starts_with("  ") && !line.starts_with("    ") && !line.trim().is_empty() {
            let candidate = line
                .trim()
                .strip_suffix(':')
                .ok_or_else(|| format!("unsupported job mapping line: {}", line.trim()))?;
            if !candidate
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(format!("unsupported job ID: {candidate}"));
            }
            current = Some(candidate.to_owned());
            if blocks
                .insert(current.clone().expect("job"), String::new())
                .is_some()
            {
                return Err(format!("duplicate job ID: {candidate}"));
            }
        }
        if let Some(job) = &current {
            let block: &mut String = blocks.get_mut(job).expect("current block");
            block.push_str(line);
            block.push('\n');
        }
    }
    Ok(blocks)
}

fn validate_steps(job: &str, block: &str) -> Result<(), String> {
    let mut steps = Vec::<(String, String)>::new();
    let mut current: Option<usize> = None;
    for line in block.lines() {
        if line.starts_with("      ") && !line.starts_with("        ") {
            let name = line
                .strip_prefix("      - name: ")
                .ok_or_else(|| format!("{job} contains an unsupported or nameless step"))?;
            steps.push((name.to_owned(), format!("{line}\n")));
            current = Some(steps.len() - 1);
        } else if let Some(index) = current {
            steps[index].1.push_str(line);
            steps[index].1.push('\n');
        }
    }
    let expected_names: &[&str] = match job {
        "m0-linux-musl" => &[
            "Checkout exact current SHA",
            "Verify clean current SHA",
            "Record provider and native toolchain evidence",
            "Install exact musl packages",
            "Build run and assert static musl artifacts",
        ],
        "m0-interop-sing-box" => &[
            "Checkout exact current SHA",
            "Verify clean current SHA",
            "Record provider and toolchain evidence",
            "Build current ferrum binaries",
            "Download verify and safely extract pinned sing-box",
            "Run both required sing-box directions",
        ],
        "m0-interop-shadowsocks-rust" => &[
            "Checkout exact current SHA",
            "Verify clean current SHA",
            "Record provider and toolchain evidence",
            "Build current ferrum binaries",
            "Download verify and safely extract pinned shadowsocks-rust",
            "Run both required shadowsocks-rust directions",
        ],
        "m0-msrv" => &[
            "Checkout exact current SHA",
            "Verify clean current SHA",
            "Record provider evidence",
            "Install and prove MSRV",
        ],
        "m0-windows-msvc" | "m0-linux-gnu" => &[
            "Checkout exact current SHA",
            "Verify clean current SHA",
            "Record provider and native toolchain evidence",
            if job == "m0-windows-msvc" {
                "Build and run native MSVC artifacts"
            } else {
                "Build and run native GNU artifacts"
            },
        ],
        "m0-local-e2e" => &[
            "Checkout exact current SHA",
            "Verify clean current SHA",
            "Record provider and toolchain evidence",
            "Build current binaries and run local product evidence",
        ],
        "m0-host-quick" => &[
            "Checkout exact current SHA",
            "Verify clean current SHA",
            "Record provider and toolchain evidence",
            "Run authoritative quick gate",
        ],
        "m0-security" => &[
            "Checkout exact current SHA",
            "Verify clean current SHA",
            "Record provider and toolchain evidence",
            "Run security and static evidence",
        ],
        "m0-lifecycle" => &[
            "Checkout exact current SHA",
            "Verify clean current SHA",
            "Record provider and toolchain evidence",
            "Run lifecycle evidence",
        ],
        "m0-integration-full" => &[
            "Checkout exact current SHA",
            "Verify clean current SHA",
            "Record provider and toolchain evidence",
            "Run authoritative full and repository gates",
        ],
        _ => return Err(format!("unknown required job {job}")),
    };
    let actual_names = steps
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>();
    if actual_names != expected_names {
        return Err(format!("{job} exact step names mismatch: {actual_names:?}"));
    }
    for (index, (_, step)) in steps.iter().enumerate() {
        let mut keys = vec!["name"];
        for line in step.lines() {
            if !line.starts_with("        ") || line.starts_with("          ") {
                continue;
            }
            let Some((key, _)) = line.trim().split_once(':') else {
                continue;
            };
            if keys.contains(&key) {
                return Err(format!("{job} duplicate step field: {key}"));
            }
            keys.push(key);
        }
        let expected_fields: &[&str] = if index == 0 {
            &["name", "uses", "with"]
        } else if step.contains("\n        env:\n") {
            &["name", "shell", "env", "run"]
        } else {
            &["name", "shell", "run"]
        };
        if keys != expected_fields {
            return Err(format!(
                "{job} step field mismatch: actual={keys:?}, expected={expected_fields:?}"
            ));
        }
        if index == 0 {
            require_once(
                step,
                "uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
                job,
            )?;
            assert_exact_keys(
                step,
                10,
                &["ref", "fetch-depth", "clean", "persist-credentials"],
            )?;
            for option in [
                "ref: ${{ github.sha }}",
                "fetch-depth: 0",
                "clean: true",
                "persist-credentials: false",
            ] {
                require_once(step, option, job)?;
            }
        } else if step.contains("uses:") || !step.contains("shell:") || !step.contains("run: |") {
            return Err(format!("{job} non-checkout step structure is invalid"));
        }
    }
    Ok(())
}

fn validate_command_allocation(
    jobs: &std::collections::BTreeMap<String, String>,
) -> Result<(), String> {
    let required: &[(&str, &[&str])] = &[
        (
            "m0-host-quick",
            &[
                "cargo build --workspace --bins --locked",
                "cargo fmt --all -- --check",
                "cargo check --workspace --all-targets --locked",
                "cargo test --workspace --locked",
            ],
        ),
        (
            "m0-security",
            &[
                "cargo build --workspace --bins --locked",
                "run_filtered 2 cargo test -p ferrum2-crypto --lib --locked tcp_owner_nonce_exhaustion",
                "run_filtered 4 cargo test -p ferrum2-shadowsocks --lib --locked flow_internal_contract",
                "cargo test -p ferrum2-shadowsocks --test detection_prevention --locked",
                "cargo test -p ferrum2-shadowsocks --test response_binding --locked",
            ],
        ),
        (
            "m0-lifecycle",
            &[
                "cargo build --workspace --bins --locked",
                "cargo test -p ferrum2-runtime --test half_close --locked",
                "run_filtered 5 cargo test -p ferrum2-client --locked phase_deadline_contract",
                "run_filtered 6 cargo test -p ferrum2-server --locked lifecycle_composition_contract",
                "cargo test -p ferrum2-m0-harness --test lifecycle_cycles --locked",
            ],
        ),
        (
            "m0-local-e2e",
            &[
                "cargo build --workspace --bins --locked",
                "run_filtered 3 cargo test -p ferrum2-m0-harness --test local_e2e --locked success",
                "run_filtered 2 cargo test -p ferrum2-m0-harness --test local_e2e --locked failures",
            ],
        ),
        (
            "m0-integration-full",
            &[
                "cargo build --workspace --bins --locked",
                "cargo clippy --workspace --all-targets --all-features --locked -- -D warnings",
                "run_all 4 cargo test -p ferrum2-m0-harness --test scope_audit --locked",
                "run_filtered 1 cargo test -p ferrum2-m0-harness --test scope_audit --locked workflow_policy",
                "b41c6127b1834ebd97246451fd92bafea50cb205...HEAD",
            ],
        ),
        (
            "m0-msrv",
            &[
                "cargo +1.85.0 build --workspace --bins --locked",
                "cargo +1.85.0 check --workspace --all-targets --locked",
                "cargo +1.85.0 test --workspace --locked",
            ],
        ),
        (
            "m0-windows-msvc",
            &[
                "$env:CC_x86_64_pc_windows_msvc = Join-Path",
                "$env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = Join-Path",
                "$LASTEXITCODE -ne 1100",
                "$buildScripts[0].cfgs",
                "tests\\platform\\check_config_no_side_effects.rs",
                "platform-no-side-effect.exe --self-test",
                "cargo +1.97.1 build --workspace --bins --locked",
                "$detectionCount -ne 2",
                "cargo test -p ferrum2-m0-harness --test detection_probe --locked",
            ],
        ),
        (
            "m0-linux-gnu",
            &[
                "CC_x86_64_unknown_linux_gnu: /usr/bin/gcc",
                "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER: /usr/bin/gcc",
                "underlying_linker_path=",
                "rows[0][\"cfgs\"]",
                "$RUNNER_TEMP/gnu-build.json",
                "tests/platform/check_config_no_side_effects.rs",
                "platform-no-side-effect --self-test",
                "cargo +1.97.1 build --workspace --bins --locked",
                "grep -c ': test$')\" -eq 2",
                "cargo test -p ferrum2-m0-harness --test detection_probe --locked",
            ],
        ),
        (
            "m0-linux-musl",
            &[
                "musl=1.2.4-2 musl-dev=1.2.4-2 musl-tools=1.2.4-2",
                "CC_x86_64_unknown_linux_musl: /usr/bin/musl-gcc",
                "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER: /usr/bin/musl-gcc",
                "musl_linker_driver_path=",
                "rows[0][\"cfgs\"]",
                "$RUNNER_TEMP/musl-build.json",
                "platform-no-side-effect --self-test",
                "PT_INTERP is forbidden",
                "DT_NEEDED is forbidden",
            ],
        ),
        (
            "m0-interop-sing-box",
            &[
                "cargo build --workspace --bins --locked",
                "sha256sum -c -",
                "test \"$count\" -eq 1",
                "run_ignored_exact client_sing_box",
                "run_ignored_exact sing_box_client",
            ],
        ),
        (
            "m0-interop-shadowsocks-rust",
            &[
                "cargo build --workspace --bins --locked",
                "sha256sum -c -",
                "test \"$count\" -eq 1",
                "run_ignored_exact client_shadowsocks_rust",
                "run_ignored_exact shadowsocks_rust_client",
            ],
        ),
    ];
    for (job, commands) in required {
        let block = jobs.get(*job).ok_or_else(|| format!("missing job {job}"))?;
        validate_exact_cargo_lines(job, block)?;
        for command in *commands {
            require_once_or_more(block, command, job)?;
        }
        let build = if *job == "m0-msrv" {
            "cargo +1.85.0 build --workspace --bins --locked"
        } else {
            "build --workspace --bins --locked"
        };
        if let Some(first_test) = block.find("cargo test") {
            let build_position = block
                .find(build)
                .ok_or_else(|| format!("{job} lacks clean-job binary prerequisite"))?;
            if build_position > first_test {
                return Err(format!("{job} binary build occurs after process tests"));
            }
        }
    }
    for job in ["m0-interop-sing-box", "m0-interop-shadowsocks-rust"] {
        let block = jobs.get(job).expect("interop job");
        if block.find("sha256sum -c -").expect("checksum")
            > block.find("run_ignored_exact ").expect("interop run")
        {
            return Err(format!(
                "{job} executes reference before checksum verification"
            ));
        }
    }
    Ok(())
}

fn validate_exact_cargo_lines(job: &str, block: &str) -> Result<(), String> {
    let actual = block
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.contains("cargo build")
                || line.contains("cargo +1.85.0 build")
                || line.contains("cargo +1.85.0 check")
                || line.contains("cargo +1.85.0 test")
                || line.contains("cargo +1.97.1 build")
                || line.starts_with("cargo fmt")
                || line.starts_with("cargo check")
                || line.starts_with("cargo test")
                || line.starts_with("cargo clippy")
                || line.starts_with("cargo doc")
                || line.starts_with("cargo metadata")
                || line.starts_with("cargo tree")
                || line.starts_with("run_filtered ")
                || line.starts_with("run_all ")
                || line.contains("count=\"$(cargo test")
                || line.contains("$detectionList = cargo test")
                || line.contains("test \"$(cargo test")
        })
        .collect::<Vec<_>>();
    let expected: &[&str] = match job {
        "m0-host-quick" => &[
            "cargo build --workspace --bins --locked",
            "cargo fmt --all -- --check",
            "cargo check --workspace --all-targets --locked",
            "cargo test --workspace --locked",
        ],
        "m0-security" => &[
            "cargo build --workspace --bins --locked",
            "cargo metadata --locked --format-version 1",
            "cargo test -p ferrum2-m0-harness --test architecture --locked",
            "cargo test -p ferrum2-m0-harness --test workspace_policy --locked",
            "cargo tree --workspace --locked",
            "cargo tree -p ferrum2-client --locked -e normal,build",
            "cargo tree -p ferrum2-client --locked -e all",
            "cargo tree -p ferrum2-server --locked -e normal,build",
            "cargo tree -p ferrum2-server --locked -e all",
            "cargo tree -p ferrum2-crypto --locked -e features -i aes",
            "cargo tree -p ferrum2-crypto --locked -e features -i ghash",
            "cargo tree -p ferrum2-crypto --locked -e features -i polyval",
            "cargo tree -p ferrum2-crypto --locked -e features -i zeroize",
            "run_filtered 1 cargo test -p ferrum2-m0-harness --test config_cli --locked invalid_matrix",
            "run_filtered 1 cargo test -p ferrum2-crypto --test primitive_vectors --locked blake3",
            "run_filtered 1 cargo test -p ferrum2-crypto --test primitive_vectors --locked aes128_gcm",
            "cargo test -p ferrum2-crypto --test sip022_vectors --locked",
            "cargo test -p ferrum2-crypto --test secret_entropy --locked",
            "run_filtered 2 cargo test -p ferrum2-crypto --lib --locked tcp_owner_nonce_exhaustion",
            "run_filtered 1 cargo test -p ferrum2-shadowsocks --test tcp_negative --locked bounds",
            "run_filtered 2 cargo test -p ferrum2-shadowsocks --test tcp_negative --locked auth",
            "run_filtered 1 cargo test -p ferrum2-shadowsocks --test tcp_replay --locked timestamp",
            "cargo test -p ferrum2-shadowsocks --test tcp_ordering --locked",
            "cargo test -p ferrum2-shadowsocks --test tcp_allocation_bounds --locked",
            "run_filtered 4 cargo test -p ferrum2-shadowsocks --lib --locked flow_internal_contract",
            "cargo test -p ferrum2-shadowsocks --test tcp_vectors --locked",
            "cargo test -p ferrum2-shadowsocks --test tcp_duplex --locked",
            "cargo test -p ferrum2-shadowsocks --test tcp_fragmentation --locked",
            "cargo test -p ferrum2-shadowsocks --test tcp_flow_contract --locked",
            "run_filtered 1 cargo test -p ferrum2-shadowsocks --test tcp_replay --locked exact",
            "run_filtered 1 cargo test -p ferrum2-shadowsocks --test tcp_replay --locked concurrent",
            "run_filtered 1 cargo test -p ferrum2-shadowsocks --test tcp_replay --locked retention",
            "run_filtered 1 cargo test -p ferrum2-shadowsocks --test tcp_replay --locked capacity",
            "cargo test -p ferrum2-shadowsocks --test detection_prevention --locked",
            "cargo test -p ferrum2-shadowsocks --test response_binding --locked",
            "cargo test -p ferrum2-observability --test tracing_contract --locked",
            "cargo test -p ferrum2-observability --test metrics_contract --locked",
        ],
        "m0-lifecycle" => &[
            "cargo build --workspace --bins --locked",
            "cargo test -p ferrum2-runtime --test abortive_close --locked",
            "cargo test -p ferrum2-runtime --test backpressure --locked",
            "cargo test -p ferrum2-runtime --test lifecycle --locked",
            "cargo test -p ferrum2-runtime --test half_close --locked",
            "cargo test -p ferrum2-runtime --test shutdown --locked",
            "cargo test -p ferrum2-runtime --test metrics_endpoint --locked",
            "run_filtered 5 cargo test -p ferrum2-client --locked phase_deadline_contract",
            "run_filtered 1 cargo test -p ferrum2-client --locked lifecycle_composition_contract",
            "run_filtered 6 cargo test -p ferrum2-server --locked lifecycle_composition_contract",
            "cargo test -p ferrum2-m0-harness --test lifecycle_cycles --locked",
        ],
        "m0-local-e2e" => &[
            "cargo build --workspace --bins --locked",
            "run_filtered 1 cargo test -p ferrum2-m0-harness --test config_cli --locked valid",
            "run_filtered 1 cargo test -p ferrum2-m0-harness --test config_cli --locked no_side_effects",
            "cargo test -p ferrum2-m0-harness --test cli_contract --locked",
            "cargo test -p ferrum2-socks5 --locked",
            "cargo test -p ferrum2-socks5 --test negative --locked",
            "cargo test -p ferrum2-runtime --test local_endpoint --locked",
            "run_filtered 1 cargo test -p ferrum2-shadowsocks --test tcp_ordering --locked connector_target_and_request_target",
            "run_filtered 1 cargo test -p ferrum2-shadowsocks --test tcp_ordering --locked connector_error_before_write",
            "run_filtered 1 cargo test -p ferrum2-shadowsocks --test tcp_ordering --locked client_open_phase_contract",
            "run_filtered 1 cargo test -p ferrum2-socks5 --test negative --locked general_failure",
            "run_filtered 1 cargo test -p ferrum2-client --locked local_endpoint_failure",
            "run_filtered 5 cargo test -p ferrum2-client --locked adapter_contract",
            "run_filtered 5 cargo test -p ferrum2-client --locked phase_deadline_contract",
            "run_filtered 6 cargo test -p ferrum2-server --locked adapter_contract",
            "run_filtered 6 cargo test -p ferrum2-server --locked lifecycle_composition_contract",
            "run_filtered 3 cargo test -p ferrum2-m0-harness --test local_e2e --locked success",
            "run_filtered 2 cargo test -p ferrum2-m0-harness --test local_e2e --locked failures",
        ],
        "m0-integration-full" => &[
            "cargo build --workspace --bins --locked",
            "cargo fmt --all -- --check",
            "cargo clippy --workspace --all-targets --all-features --locked -- -D warnings",
            "cargo test --workspace --all-features --locked",
            "cargo doc --workspace --all-features --no-deps --locked",
            "run_all 4 cargo test -p ferrum2-m0-harness --test scope_audit --locked",
            "run_filtered 1 cargo test -p ferrum2-m0-harness --test scope_audit --locked workflow_policy",
            "cargo tree --workspace --locked",
        ],
        "m0-msrv" => &[
            "cargo +1.85.0 build --workspace --bins --locked",
            "cargo +1.85.0 check --workspace --all-targets --locked",
            "cargo +1.85.0 test --workspace --locked",
        ],
        "m0-windows-msvc" => &[
            "$messages = cargo +1.97.1 build --workspace --bins --release --locked --target x86_64-pc-windows-msvc --message-format=json",
            "cargo +1.97.1 build --workspace --bins --locked",
            "$detectionList = cargo test -p ferrum2-m0-harness --test detection_probe --locked -- --list",
            "cargo test -p ferrum2-m0-harness --test detection_probe --locked",
        ],
        "m0-linux-gnu" => &[
            "cargo +1.97.1 build --workspace --bins --release --locked --target x86_64-unknown-linux-gnu --message-format=json > \"$RUNNER_TEMP/gnu-build.json\"",
            "cargo +1.97.1 build --workspace --bins --locked",
            "test \"$(cargo test -p ferrum2-m0-harness --test detection_probe --locked -- --list | grep -c ': test$')\" -eq 2",
            "cargo test -p ferrum2-m0-harness --test detection_probe --locked",
        ],
        "m0-linux-musl" => &[
            "cargo +1.97.1 build --workspace --bins --release --locked --target x86_64-unknown-linux-musl --message-format=json > \"$RUNNER_TEMP/musl-build.json\"",
        ],
        "m0-interop-sing-box" | "m0-interop-shadowsocks-rust" => &[
            "cargo build --workspace --bins --locked",
            "count=\"$(cargo test -p ferrum2-m0-harness --test external_interop --locked -- --ignored --exact \"$name\" --list | grep -c ': test$')\"",
            "cargo test -p ferrum2-m0-harness --test external_interop --locked -- --ignored --exact \"$name\"",
        ],
        _ => return Err(format!("no exact command allocation for {job}")),
    };
    if actual != expected {
        return Err(format!(
            "{job} exact Cargo command allocation mismatch:\nactual={actual:#?}\nexpected={expected:#?}"
        ));
    }
    Ok(())
}

fn require_once(text: &str, needle: &str, context: &str) -> Result<(), String> {
    let count = text.matches(needle).count();
    if count != 1 {
        return Err(format!(
            "{context}: expected exactly one `{needle}`, got {count}"
        ));
    }
    Ok(())
}

fn require_once_or_more(text: &str, needle: &str, context: &str) -> Result<(), String> {
    if !text.contains(needle) {
        return Err(format!("{context}: missing `{needle}`"));
    }
    Ok(())
}

fn changed_paths(diff: &str) -> Vec<&str> {
    let mut paths = Vec::new();
    for line in diff.lines() {
        let fields = line.split('\t').collect::<Vec<_>>();
        assert!(fields.len() >= 2, "malformed name-status row: {line}");
        if fields[0].starts_with('R') || fields[0].starts_with('C') {
            assert_eq!(fields.len(), 3, "rename/copy row must name both paths");
            paths.push(fields[1]);
            paths.push(fields[2]);
        } else {
            assert_eq!(fields.len(), 2, "ordinary diff row must name one path");
            paths.push(fields[1]);
        }
    }
    paths
}

fn is_immutable_owned(path: &str) -> bool {
    const OWNERSHIP: &[&str] = &[
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        ".cargo/config.toml",
        "LICENSE",
        "bins/ferrum2-client/Cargo.toml",
        "bins/ferrum2-server/Cargo.toml",
        "crates/ferrum2-core/**",
        "crates/ferrum2-crypto/Cargo.toml",
        "crates/ferrum2-crypto/src/**",
        "crates/ferrum2-crypto/tests/**",
        "crates/ferrum2-shadowsocks/Cargo.toml",
        "crates/ferrum2-shadowsocks/src/**",
        "crates/ferrum2-shadowsocks/tests/**",
        "crates/ferrum2-socks5/Cargo.toml",
        "crates/ferrum2-socks5/src/**",
        "crates/ferrum2-socks5/tests/**",
        "crates/ferrum2-runtime/Cargo.toml",
        "crates/ferrum2-runtime/src/**",
        "crates/ferrum2-runtime/tests/**",
        "crates/ferrum2-config/Cargo.toml",
        "crates/ferrum2-config/src/**",
        "crates/ferrum2-config/tests/**",
        "crates/ferrum2-observability/Cargo.toml",
        "crates/ferrum2-observability/src/**",
        "crates/ferrum2-observability/tests/**",
        "bins/ferrum2-client/src/cli.rs",
        "bins/ferrum2-client/src/main.rs",
        "bins/ferrum2-client/src/run.rs",
        "bins/ferrum2-server/src/cli.rs",
        "bins/ferrum2-server/src/main.rs",
        "bins/ferrum2-server/src/run.rs",
        "tests/fixtures/crypto/**",
        "tests/fixtures/sip022/**",
        "tests/fixtures/config/**",
        "tests/m0-harness/Cargo.toml",
        "tests/m0-harness/src/local_support/**",
        "tests/m0-harness/src/external_support/**",
        "tests/m0-harness/tests/architecture.rs",
        "tests/m0-harness/tests/workspace_policy.rs",
        "tests/m0-harness/tests/config_cli.rs",
        "tests/m0-harness/tests/cli_contract.rs",
        "tests/m0-harness/tests/local_e2e.rs",
        "tests/m0-harness/tests/lifecycle_cycles.rs",
        "tests/m0-harness/tests/detection_probe.rs",
        "tests/m0-harness/tests/external_interop.rs",
        "tests/m0-harness/tests/scope_audit.rs",
        "tests/interop/**",
        "tests/platform/**",
        ".github/workflows/m0.yml",
    ];
    OWNERSHIP.iter().any(|owned| {
        owned
            .strip_suffix("/**")
            .is_some_and(|prefix| path == prefix || path.starts_with(&format!("{prefix}/")))
            || path == *owned
    })
}

fn is_control_document(path: &str) -> bool {
    const CONTROL_DOCUMENTS: &[&str] = &[
        ".codex/agents/qa.toml",
        "docs/ci-status.md",
        "docs/gap-analysis.md",
        "docs/roadmap.md",
        "docs/vision.md",
        "docs/research/M0-upstream-baseline.md",
        "docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md",
        "docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md",
        "docs/tickets/M0-T01-workspace-and-core-contracts.md",
        "docs/tickets/M0-T02-crypto-secret-and-kat.md",
        "docs/tickets/M0-T03-sip022-tcp-security-state.md",
        "docs/tickets/M0-T04-config-and-observability.md",
        "docs/tickets/M0-T05-socks5-connect-inbound.md",
        "docs/tickets/M0-T06-runtime-direct-relay-and-lifecycle.md",
        "docs/tickets/M0-T07-compose-binaries-and-local-e2e.md",
        "docs/tickets/M0-T08-interop-platform-and-integration-gates.md",
        "docs/adr/ADR-0001-m0-workspace-toolchain-and-module-topology.md",
        "docs/adr/ADR-0002-m0-secret-key-clock-and-entropy-boundaries.md",
        "docs/adr/ADR-0003-m0-configuration-and-cli-contract.md",
        "docs/adr/ADR-0004-m0-sip022-tcp-security-state.md",
        "docs/adr/ADR-0005-m0-runtime-lifecycle-and-observability.md",
        "docs/adr/ADR-0006-m0-interoperability-provenance-and-platform-evidence.md",
        "docs/adr/ADR-0007-m0-github-actions-ci-provider.md",
        "docs/adr/ADR-0008-m0-aes-gcm-kat-provenance-correction.md",
        "docs/adr/ADR-0009-m0-aead-state-zeroize-feature-unification.md",
        "docs/adr/ADR-0010-m0-opaque-sip022-duplex-flow.md",
        "docs/adr/ADR-0011-m0-evidence-boundaries-and-native-detection-probes.md",
        "docs/adr/ADR-0012-m0-phase-deadlines-and-partial-relay-accounting.md",
        "docs/adr/ADR-0013-m0-binary-paused-time-test-boundary.md",
        "docs/adr/ADR-0014-m0-external-half-close-evidence-boundary.md",
    ];
    CONTROL_DOCUMENTS.contains(&path)
}

fn assert_safe_changed_path(path: &str) {
    let lower = path.to_ascii_lowercase();
    for generated in [
        "target/",
        "coverage/",
        "profile/",
        "results/",
        ".pcap",
        ".log",
    ] {
        assert!(
            !lower.contains(generated),
            "generated artifact in diff: {path}"
        );
    }
    for external in [".exe", ".dll", ".zip", ".tar", ".tar.gz", ".tar.xz", ".7z"] {
        assert!(
            !lower.ends_with(external),
            "external artifact in diff: {path}"
        );
    }
    if lower.starts_with(".github/") {
        assert_eq!(path, ".github/workflows/m0.yml");
    }
}

fn scan_changed_text(root: &Path, path: &str) {
    let candidate = root.join(path);
    if !candidate.is_file() {
        return;
    }
    let Ok(bytes) = fs::read(&candidate) else {
        panic!("cannot read changed file: {path}");
    };
    let Ok(text) = String::from_utf8(bytes) else {
        panic!("non-text changed artifact is not allowed: {path}");
    };
    for secret_marker in [
        concat!("-----BEGIN PRIVATE ", "KEY-----"),
        concat!("-----BEGIN RSA PRIVATE ", "KEY-----"),
        concat!("AKIAIOSFODNN7", "EXAMPLE"),
        concat!("gh", "p_"),
    ] {
        assert!(
            !text.contains(secret_marker),
            "real-secret marker found in {path}"
        );
    }
}
