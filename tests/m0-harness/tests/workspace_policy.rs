use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("harness must be two levels below the workspace root")
        .to_path_buf()
}

fn metadata() -> Value {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--locked", "--format-version", "1"])
        .current_dir(workspace_root())
        .output()
        .expect("cargo metadata must start");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata JSON")
}

#[test]
fn toolchain_and_msrv_are_pinned() {
    let root = workspace_root();
    let toolchain = fs::read_to_string(root.join("rust-toolchain.toml")).expect("toolchain file");
    for required in [
        "channel = \"1.97.1\"",
        "profile = \"minimal\"",
        "components = [\"rustfmt\", \"clippy\"]",
        "\"x86_64-pc-windows-msvc\"",
        "\"x86_64-unknown-linux-gnu\"",
        "\"x86_64-unknown-linux-musl\"",
    ] {
        assert!(
            toolchain.contains(required),
            "missing toolchain policy: {required}"
        );
    }

    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("root manifest");
    assert!(manifest.contains("edition = \"2024\""));
    assert!(manifest.contains("rust-version = \"1.85.0\""));
    assert!(manifest.contains("resolver = \"3\""));

    let cargo_config =
        fs::read_to_string(root.join(".cargo/config.toml")).expect("Cargo configuration");
    assert!(cargo_config.contains("incompatible-rust-versions = \"fallback\""));
}

#[test]
fn direct_dependency_versions_and_features_match_the_approved_baseline() {
    let manifest = fs::read_to_string(workspace_root().join("Cargo.toml")).expect("root manifest");
    let required = [
        "tokio = { version = \"=1.53.1\", default-features = false, features = [\"rt-multi-thread\", \"macros\", \"net\", \"io-util\", \"sync\", \"time\", \"signal\"] }",
        "bytes = \"=1.12.1\"",
        "socket2 = \"=0.6.5\"",
        "serde = { version = \"=1.0.229\", default-features = false, features = [\"std\", \"derive\"] }",
        "toml = { version = \"=1.1.3\", default-features = false, features = [\"std\", \"serde\", \"parse\"] }",
        "tracing = { version = \"=0.1.44\", default-features = false, features = [\"std\"] }",
        "tracing-subscriber = { version = \"=0.3.23\", default-features = false, features = [\"fmt\", \"json\", \"env-filter\"] }",
        "prometheus-client = { version = \"=0.25.0\", default-features = false }",
        "aes-gcm = { version = \"=0.11.0\", default-features = false, features = [\"aes\", \"bytes\", \"zeroize\"] }",
        "blake3 = { version = \"=1.8.5\", default-features = false, features = [\"std\", \"zeroize\"] }",
        "base64 = { version = \"=0.23.0\", default-features = false, features = [\"std\"] }",
        "zeroize = { version = \"=1.9.0\", default-features = false, features = [\"alloc\", \"derive\"] }",
        "getrandom = { version = \"=0.4.3\", default-features = false, features = [\"std\"] }",
        "clap = { version = \"=4.6.4\", default-features = false, features = [\"std\", \"derive\", \"help\", \"usage\", \"error-context\"] }",
        "thiserror = \"=2.0.19\"",
        "hex = \"=0.4.3\"",
        "serde_json = \"=1.0.151\"",
        "tempfile = \"=3.27.0\"",
    ];

    for dependency in required {
        assert!(
            manifest.contains(dependency),
            "missing exact dependency contract: {dependency}"
        );
    }

    let dependency_table = manifest
        .split("[workspace.dependencies]")
        .nth(1)
        .expect("workspace dependencies")
        .split("[workspace.lints.rust]")
        .next()
        .expect("workspace dependency table end");
    let actual_names: BTreeSet<_> = dependency_table
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name.trim()))
        .filter(|name| !name.is_empty())
        .collect();
    let expected_names = BTreeSet::from([
        "aes-gcm",
        "base64",
        "blake3",
        "bytes",
        "clap",
        "ferrum2-config",
        "ferrum2-core",
        "ferrum2-crypto",
        "ferrum2-observability",
        "ferrum2-runtime",
        "ferrum2-shadowsocks",
        "ferrum2-socks5",
        "getrandom",
        "hex",
        "prometheus-client",
        "serde",
        "serde_json",
        "socket2",
        "tempfile",
        "thiserror",
        "tokio",
        "toml",
        "tracing",
        "tracing-subscriber",
        "zeroize",
    ]);
    assert_eq!(
        actual_names, expected_names,
        "workspace dependencies must be exactly the approved baseline"
    );

    for forbidden in [
        "features = [\"full\"]",
        "async-trait",
        "openssl",
        "io-uring",
        "secrecy",
        "subtle =",
        "rand =",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "forbidden dependency or feature: {forbidden}"
        );
    }
}

#[test]
fn every_project_package_inherits_repository_policy() {
    let metadata = metadata();
    let root = workspace_root();

    for member_id in metadata["workspace_members"]
        .as_array()
        .expect("workspace members")
    {
        let package = metadata["packages"]
            .as_array()
            .expect("packages")
            .iter()
            .find(|package| package["id"] == *member_id)
            .expect("member package");
        assert_eq!(package["version"], "0.1.0");
        assert_eq!(package["edition"], "2024");
        assert_eq!(package["rust_version"], "1.85.0");
        assert_eq!(package["license"], "GPL-3.0-only");
        assert_eq!(
            package["publish"],
            serde_json::json!([]),
            "publish=false is represented by an empty registry allowlist"
        );

        let manifest_path =
            PathBuf::from(package["manifest_path"].as_str().expect("manifest path"));
        let manifest = fs::read_to_string(&manifest_path).expect("member manifest");
        assert!(
            manifest.contains("[lints]\nworkspace = true"),
            "{} must inherit workspace lints",
            manifest_path
                .strip_prefix(&root)
                .unwrap_or(&manifest_path)
                .display()
        );
    }

    let root_manifest = fs::read_to_string(root.join("Cargo.toml")).expect("root manifest");
    assert!(root_manifest.contains("[workspace.lints.rust]\nunsafe_code = \"forbid\""));
}

#[test]
fn config_predeclares_zeroizing_storage_dependency() {
    let metadata = metadata();
    let config = metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|package| package["name"] == "ferrum2-config")
        .expect("config package");
    let zeroize = config["dependencies"]
        .as_array()
        .expect("config dependencies")
        .iter()
        .find(|dependency| dependency["name"] == "zeroize")
        .expect("config must predeclare zeroize for raw config and PSK strings");

    assert_eq!(zeroize["req"], "=1.9.0");
    assert_eq!(zeroize["uses_default_features"], false);
    assert_eq!(zeroize["features"], serde_json::json!(["alloc", "derive"]));
}

#[test]
fn lockfile_and_gplv3_license_are_committed_policy_inputs() {
    let root = workspace_root();
    let lock = root.join("Cargo.lock");
    assert!(lock.is_file(), "Cargo.lock must exist");

    let output = Command::new("git")
        .args(["ls-files", "--error-unmatch", "Cargo.lock"])
        .current_dir(&root)
        .output()
        .expect("git ls-files must start");
    assert!(
        output.status.success(),
        "Cargo.lock must be tracked: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let license = fs::read_to_string(root.join("LICENSE")).expect("LICENSE");
    assert!(license.contains("GNU GENERAL PUBLIC LICENSE"));
    assert!(license.contains("Version 3, 29 June 2007"));
}

#[test]
fn harness_has_no_concrete_ferrum2_cargo_dependency() {
    let manifest = fs::read_to_string(workspace_root().join("tests/m0-harness/Cargo.toml"))
        .expect("harness manifest");
    let dependency_section = manifest
        .split("[dev-dependencies]")
        .nth(1)
        .expect("dev dependencies");
    assert!(
        !dependency_section.contains("ferrum2-"),
        "the black-box harness must not link a concrete ferrum2 package"
    );
}
