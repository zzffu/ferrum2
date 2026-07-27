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
        assert!(!fixture.contains("[metrics]"));
    }
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
    let lower = workflow.to_ascii_lowercase();

    let header = workflow
        .split_once("jobs:")
        .expect("workflow jobs section")
        .0;
    assert!(header.contains(
        "on:\n  pull_request:\n  push:\n    branches:\n      - master\n      - \"codex/integration/**\"\n  workflow_dispatch:"
    ));
    for forbidden in [
        "pull_request_target",
        "workflow_run",
        "schedule:",
        "repository_dispatch",
        "tags:",
    ] {
        assert!(
            !header.contains(forbidden),
            "forbidden trigger: {forbidden}"
        );
    }
    assert!(header.contains("permissions:\n  contents: read"));
    assert_eq!(workflow.matches("\npermissions:").count(), 1);
    assert!(!lower.contains("secrets."));
    assert!(!lower.contains("continue-on-error"));
    assert!(!lower.contains("environment:"));
    assert!(!lower.contains("ubuntu-latest"));
    assert!(!lower.contains("windows-latest"));
    assert!(!lower.contains("cache"));

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
    let jobs = job_blocks(&workflow);
    assert_eq!(jobs.len(), expected.len(), "exact required job count");
    for (job, runner) in expected {
        let block = jobs.get(job).unwrap_or_else(|| panic!("missing job {job}"));
        assert!(block.contains(&format!("name: {job}\n")));
        assert!(block.contains(&format!("runs-on: {runner}\n")));
        assert!(block.contains("timeout-minutes: 60\n"));
        assert!(!block.contains("\n    permissions:"));
        assert!(block.contains("git status --porcelain"));
        assert!(block.contains("GITHUB_SHA"));
        for evidence in [
            "GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT",
            "RUNNER_OS",
            "RUNNER_ARCH",
            "ImageOS",
            "ImageVersion",
        ] {
            assert!(block.contains(evidence), "{job} lacks {evidence} evidence");
        }
    }

    let uses = workflow
        .lines()
        .filter_map(|line| line.trim().strip_prefix("uses: "))
        .collect::<Vec<_>>();
    assert_eq!(uses.len(), 11, "checkout is the only action");
    for action in uses {
        let (name, revision) = action.split_once('@').expect("action revision");
        assert_eq!(name, "actions/checkout");
        assert_eq!(revision, "de0fac2e4500dabe0009e67214ff5f5447ce83dd");
        assert!(revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
    for checkout_option in [
        "ref: ${{ github.sha }}",
        "fetch-depth: 0",
        "clean: true",
        "persist-credentials: false",
    ] {
        assert_eq!(workflow.matches(checkout_option).count(), 11);
    }

    for required in [
        "cargo fmt --all -- --check",
        "cargo check --workspace --all-targets --locked",
        "cargo test --workspace --locked",
        "cargo clippy --workspace --all-targets --all-features --locked -- -D warnings",
        "cargo test --workspace --all-features --locked",
        "cargo doc --workspace --all-features --no-deps --locked",
        "cargo +1.85.0 check --workspace --all-targets --locked",
        "cargo +1.85.0 test --workspace --locked",
        "cargo build --workspace --bins --locked",
        "--ignored --exact client_sing_box",
        "--ignored --exact client_shadowsocks_rust",
        "--ignored --exact sing_box_client",
        "--ignored --exact shadowsocks_rust_client",
        "musl=1.2.4-2 musl-dev=1.2.4-2 musl-tools=1.2.4-2",
        "x86_64-pc-windows-msvc",
        "x86_64-unknown-linux-gnu",
        "x86_64-unknown-linux-musl",
        "readelf -lW",
        "readelf -dW",
        "PT_INTERP",
        "DT_NEEDED",
        "cargo test -p ferrum2-m0-harness --test detection_probe --locked",
        "cargo test -p ferrum2-m0-harness --test scope_audit --locked workflow_policy",
        "b41c6127b1834ebd97246451fd92bafea50cb205...HEAD",
        "close-evidence-candidate",
    ] {
        assert!(workflow.contains(required), "workflow omits: {required}");
    }
    assert!(
        workflow.find("sha256sum -c").expect("reference checksum")
            < workflow
                .find("--ignored --exact client_sing_box")
                .expect("first reference execution")
    );
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
        .args(["diff", "--name-only", &format!("{BASELINE}...HEAD")])
        .current_dir(&root)
        .output()
        .expect("fixed-baseline diff");
    assert!(output.status.success(), "fixed-baseline diff failed");
    let changed = String::from_utf8(output.stdout).expect("UTF-8 changed paths");
    let ownership = ticket_ownership(&root);
    for path in changed.lines() {
        assert!(
            is_owned(path, &ownership) || is_control_document(path),
            "path is outside M0 ticket/control ownership: {path}"
        );
        assert_safe_changed_path(path);
        scan_changed_text(&root, path);
    }

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

fn job_blocks(workflow: &str) -> std::collections::BTreeMap<String, String> {
    let jobs = workflow.split_once("jobs:\n").expect("jobs").1;
    let mut blocks = std::collections::BTreeMap::new();
    let mut current: Option<String> = None;
    for line in jobs.lines() {
        let candidate = line.trim().trim_end_matches(':');
        if line.starts_with("  ")
            && !line.starts_with("    ")
            && line.ends_with(':')
            && candidate
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            current = Some(candidate.to_owned());
            blocks.entry(current.clone().expect("job")).or_default();
        }
        if let Some(job) = &current {
            let block: &mut String = blocks.get_mut(job).expect("current block");
            block.push_str(line);
            block.push('\n');
        }
    }
    blocks
}

fn ticket_ownership(root: &Path) -> Vec<String> {
    let mut ownership = Vec::new();
    for entry in fs::read_dir(root.join("docs/tickets")).expect("ticket directory") {
        let path = entry.expect("ticket entry").path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if !name.starts_with("M0-T") || name == "M0-T00-template.md" {
            continue;
        }
        let text = fs::read_to_string(&path).expect("ticket text");
        let mut in_owns = false;
        for line in text.lines() {
            if line == "owns = [" {
                in_owns = true;
                continue;
            }
            if in_owns && line == "]" {
                break;
            }
            if in_owns {
                let owned = line.trim().trim_matches(',').trim_matches('"');
                if !owned.is_empty() {
                    ownership.push(owned.to_owned());
                }
            }
        }
    }
    ownership
}

fn is_owned(path: &str, ownership: &[String]) -> bool {
    ownership.iter().any(|owned| {
        owned
            .strip_suffix("/**")
            .is_some_and(|prefix| path == prefix || path.starts_with(&format!("{prefix}/")))
            || path == owned
    })
}

fn is_control_document(path: &str) -> bool {
    path == ".codex/agents/qa.toml"
        || path == "docs/ci-status.md"
        || path == "docs/gap-analysis.md"
        || path == "docs/roadmap.md"
        || path == "docs/vision.md"
        || path.starts_with("docs/adr/")
        || path.starts_with("docs/specs/")
        || path.starts_with("docs/test-plans/")
        || path.starts_with("docs/tickets/")
        || path == "docs/research/M0-upstream-baseline.md"
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
