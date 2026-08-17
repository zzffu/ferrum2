use proc_macro2::{TokenStream, TokenTree};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn metadata() -> &'static Value {
    static METADATA: OnceLock<Value> = OnceLock::new();
    METADATA.get_or_init(|| {
        let output = Command::new(env!("CARGO"))
            .current_dir(workspace_root())
            .args(["metadata", "--locked", "--format-version", "1"])
            .output()
            .expect("cargo metadata must start");
        assert!(
            output.status.success(),
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("cargo metadata JSON")
    })
}

fn package<'a>(metadata: &'a Value, name: &str) -> &'a Value {
    metadata["packages"]
        .as_array()
        .expect("metadata packages")
        .iter()
        .find(|package| package["name"] == name)
        .unwrap_or_else(|| panic!("missing package {name}"))
}

fn dependency<'a>(package: &'a Value, name: &str, kind: Option<&str>) -> &'a Value {
    package["dependencies"]
        .as_array()
        .expect("package dependencies")
        .iter()
        .find(|dependency| {
            dependency["name"] == name
                && match kind {
                    Some(kind) => dependency["kind"] == kind,
                    None => dependency["kind"].is_null(),
                }
        })
        .unwrap_or_else(|| panic!("missing {kind:?} dependency {name}"))
}

fn features(dependency: &Value) -> BTreeSet<&str> {
    dependency["features"]
        .as_array()
        .expect("dependency features")
        .iter()
        .map(|feature| feature.as_str().expect("feature name"))
        .collect()
}

#[test]
fn workspace_members_share_the_declared_release_policy() {
    let metadata = metadata();
    let member_ids: BTreeSet<_> = metadata["workspace_members"]
        .as_array()
        .expect("workspace members")
        .iter()
        .map(|member| member.as_str().expect("member id"))
        .collect();
    let members: Vec<_> = metadata["packages"]
        .as_array()
        .expect("metadata packages")
        .iter()
        .filter(|package| member_ids.contains(package["id"].as_str().expect("package id")))
        .collect();
    assert_eq!(members.len(), member_ids.len());

    let root_source = fs::read_to_string(workspace_root().join("Cargo.toml"))
        .expect("workspace Cargo.toml")
        .replace("\r\n", "\n");
    let root: toml::Value = toml::from_str(&root_source).expect("structured workspace TOML");
    let expected_msrv = root["workspace"]["package"]["rust-version"]
        .as_str()
        .expect("workspace rust-version");
    assert_eq!(root["workspace"]["resolver"].as_str(), Some("3"));
    assert_eq!(
        root["workspace"]["lints"]["rust"]["unsafe_code"].as_str(),
        Some("forbid")
    );
    for package in members {
        assert_eq!(package["edition"], "2024", "{} edition", package["name"]);
        assert_eq!(
            package["rust_version"], expected_msrv,
            "{} rust-version",
            package["name"]
        );
        assert_eq!(
            package["license"], "GPL-3.0-only",
            "{} license",
            package["name"]
        );
        assert_eq!(
            package["publish"],
            serde_json::json!([]),
            "{} publish policy",
            package["name"]
        );

        let manifest_source = fs::read_to_string(
            package["manifest_path"]
                .as_str()
                .expect("package manifest path"),
        )
        .expect("package manifest")
        .replace("\r\n", "\n");
        let manifest: toml::Value =
            toml::from_str(&manifest_source).expect("structured package manifest");
        if package["name"] == "ferrum2-wintun" {
            assert_eq!(
                manifest["lints"]["rust"]["unsafe_code"].as_str(),
                Some("deny"),
                "the native ABI owner must retain its narrow unsafe exception"
            );
        } else {
            assert_eq!(
                manifest["lints"]["workspace"].as_bool(),
                Some(true),
                "{} must inherit workspace lints",
                package["name"]
            );
        }
    }

    let toolchain_source = fs::read_to_string(workspace_root().join("rust-toolchain.toml"))
        .expect("rust-toolchain.toml")
        .replace("\r\n", "\n");
    let toolchain: toml::Value =
        toml::from_str(&toolchain_source).expect("structured toolchain TOML");
    assert_eq!(
        toolchain["toolchain"]["channel"].as_str(),
        Some(expected_msrv),
        "the default toolchain is also the tested MSRV"
    );

    for package in metadata["packages"].as_array().expect("metadata packages") {
        if !member_ids.contains(package["id"].as_str().expect("package id")) {
            continue;
        }
        for dependency in package["dependencies"]
            .as_array()
            .expect("package dependencies")
        {
            if let Some(source) = dependency["source"].as_str() {
                let requirement = dependency["req"]
                    .as_str()
                    .expect("registry dependency requirement");
                assert!(
                    requirement.starts_with('='),
                    "{} dependency {} is not exactly pinned: {requirement}",
                    package["name"],
                    dependency["name"]
                );
                assert!(
                    source.starts_with("registry+"),
                    "{} dependency {} has a non-registry source",
                    package["name"],
                    dependency["name"]
                );
            }
        }
    }
}

#[test]
fn workspace_boundaries_are_expressed_by_cargo_metadata() {
    let metadata = metadata();
    let core = package(&metadata, "ferrum2-core");
    let core_dependencies: BTreeSet<_> = core["dependencies"]
        .as_array()
        .expect("core dependencies")
        .iter()
        .filter(|dependency| dependency["kind"].is_null())
        .map(|dependency| dependency["name"].as_str().expect("dependency name"))
        .collect();
    for forbidden in [
        "tokio",
        "socket2",
        "hickory-proto",
        "hickory-resolver",
        "rustls",
        "ferrum2-runtime",
        "ferrum2-crypto",
        "ferrum2-shadowsocks",
        "ferrum2-socks5",
        "ferrum2-dns",
        "ferrum2-tun",
        "ferrum2-wintun",
    ] {
        assert!(
            !core_dependencies.contains(forbidden),
            "core acquired runtime or protocol dependency {forbidden}"
        );
    }

    let harness = package(metadata, "ferrum2-m0-harness");
    let harness_node = metadata["resolve"]["nodes"]
        .as_array()
        .expect("resolve nodes")
        .iter()
        .find(|node| node["id"] == harness["id"])
        .expect("harness resolve node");
    assert!(
        harness_node["dependencies"]
            .as_array()
            .expect("harness resolved dependencies")
            .iter()
            .all(|dependency_id| !metadata["workspace_members"]
                .as_array()
                .expect("workspace members")
                .contains(dependency_id)),
        "the external qualification harness must stay black-box"
    );

    let wintun_edges: Vec<_> = metadata["packages"]
        .as_array()
        .expect("metadata packages")
        .iter()
        .flat_map(|package| {
            package["dependencies"]
                .as_array()
                .expect("package dependencies")
                .iter()
                .filter(|dependency| dependency["name"] == "ferrum2-wintun")
                .map(move |dependency| {
                    (
                        package["name"].as_str().expect("package name"),
                        dependency["target"].as_str().expect("dependency target"),
                    )
                })
        })
        .collect();
    assert_eq!(
        wintun_edges,
        vec![("ferrum2-tun", "cfg(all(windows, target_arch = \"x86_64\"))")]
    );

    let mut qualification_targets = 0;
    for package in metadata["packages"].as_array().expect("metadata packages") {
        for target in package["targets"].as_array().expect("package targets") {
            let name = target["name"].as_str().expect("target name");
            if name.ends_with("qualification") {
                qualification_targets += 1;
                assert_eq!(target["kind"], serde_json::json!(["bin"]));
                assert_eq!(target["test"], false, "{name} must not run in cargo test");
            }
        }
    }
    assert_eq!(qualification_targets, 2);
}

#[test]
fn production_features_preserve_security_and_resource_boundaries() {
    let metadata = metadata();
    let workspace_members = metadata["workspace_members"]
        .as_array()
        .expect("workspace members");
    for package in metadata["packages"].as_array().expect("metadata packages") {
        if !workspace_members.contains(&package["id"]) {
            continue;
        }
        for dependency in package["dependencies"]
            .as_array()
            .expect("package dependencies")
            .iter()
            .filter(|dependency| dependency["kind"].is_null() && dependency["name"] == "tokio")
        {
            assert!(
                !features(dependency).contains("test-util"),
                "{} enables tokio test-util in production",
                package["name"]
            );
        }
    }
    for binary in ["ferrum2-client", "ferrum2-server"] {
        assert!(
            features(dependency(package(metadata, binary), "tokio", Some("dev")))
                .contains("test-util"),
            "{binary} tests need deterministic paused time"
        );
    }

    for target in ["x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu"] {
        let output = Command::new(env!("CARGO"))
            .current_dir(workspace_root())
            .args([
                "tree",
                "--workspace",
                "--locked",
                "--edges",
                "normal,build,features",
                "--target",
                target,
                "--prefix",
                "none",
            ])
            .output()
            .expect("cargo tree must start");
        assert!(
            output.status.success(),
            "cargo tree failed for {target}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let tree = String::from_utf8(output.stdout).expect("cargo tree UTF-8");
        assert!(
            !tree
                .lines()
                .any(|line| line == "tokio feature \"test-util\""),
            "{target} production graph enables tokio test-util"
        );
    }

    let resolver = dependency(package(metadata, "ferrum2-dns"), "hickory-resolver", None);
    assert_eq!(resolver["uses_default_features"], false);
    let resolver_features = features(resolver);
    for required in ["tokio", "tls-ring", "https-ring", "webpki-roots"] {
        assert!(
            resolver_features.contains(required),
            "missing DNS feature {required}"
        );
    }
    for forbidden in ["tls-aws-lc-rs", "https-aws-lc-rs", "system-config"] {
        assert!(
            !resolver_features.contains(forbidden),
            "unexpected DNS provider feature {forbidden}"
        );
    }

    let smoltcp = dependency(package(metadata, "ferrum2-tun"), "smoltcp", None);
    assert_eq!(smoltcp["uses_default_features"], false);
    let smoltcp_features = features(smoltcp);
    for required in [
        "std",
        "medium-ip",
        "proto-ipv4",
        "proto-ipv6",
        "socket-tcp",
        "socket-udp",
        "iface-max-addr-count-2",
        "iface-max-route-count-2",
        "assembler-max-segment-count-4",
    ] {
        assert!(
            smoltcp_features.contains(required),
            "missing bounded smoltcp feature {required}"
        );
    }
    assert!(!smoltcp_features.contains("socket-icmp"));
}

fn has_unsafe_token(tokens: TokenStream) -> bool {
    tokens.into_iter().any(|token| match token {
        TokenTree::Ident(identifier) => identifier.to_string() == "unsafe",
        TokenTree::Group(group) => has_unsafe_token(group.stream()),
        TokenTree::Punct(_) | TokenTree::Literal(_) => false,
    })
}

fn rust_sources(directory: &Path, sources: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("read Rust source directory") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            rust_sources(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
}

#[test]
fn vendored_crypto_is_v2_only_and_contains_no_unsafe_tokens() {
    let metadata = metadata();
    let crypto = package(metadata, "ferrum2-crypto");
    let backend = dependency(crypto, "shadowsocks-crypto", None);
    assert_eq!(backend["uses_default_features"], false);
    assert_eq!(features(backend), BTreeSet::from(["v2"]));

    let resolved = package(metadata, "shadowsocks-crypto");
    assert_eq!(resolved["version"], "0.7.0");
    assert_eq!(resolved["license"], "MIT");
    assert!(
        resolved["source"].is_null(),
        "backend must resolve from the local patch"
    );
    let vendor = workspace_root()
        .join("vendor/shadowsocks-crypto")
        .canonicalize()
        .expect("vendored backend");
    let manifest = PathBuf::from(
        resolved["manifest_path"]
            .as_str()
            .expect("backend manifest path"),
    );
    assert_eq!(
        manifest
            .parent()
            .expect("backend manifest parent")
            .canonicalize()
            .expect("backend parent"),
        vendor
    );

    let node = metadata["resolve"]["nodes"]
        .as_array()
        .expect("resolve nodes")
        .iter()
        .find(|node| node["id"] == resolved["id"])
        .expect("resolved backend node");
    let resolved_features: BTreeSet<_> = node["features"]
        .as_array()
        .expect("resolved features")
        .iter()
        .map(|feature| feature.as_str().expect("resolved feature"))
        .collect();
    assert_eq!(resolved_features, BTreeSet::from(["v2"]));
    let resolved_dependencies: BTreeSet<_> = node["deps"]
        .as_array()
        .expect("backend resolved dependencies")
        .iter()
        .map(|dependency| {
            package(
                metadata,
                metadata["packages"]
                    .as_array()
                    .expect("metadata packages")
                    .iter()
                    .find(|package| package["id"] == dependency["pkg"])
                    .expect("resolved dependency package")["name"]
                    .as_str()
                    .expect("resolved dependency name"),
            )["name"]
                .as_str()
                .expect("resolved package name")
        })
        .collect();
    assert!(resolved_dependencies.contains("zeroize"));
    assert!(!resolved_dependencies.contains("aws-lc-rs"));
    let workspace_members = metadata["workspace_members"]
        .as_array()
        .expect("workspace members");
    for package in metadata["packages"].as_array().expect("metadata packages") {
        if !workspace_members.contains(&package["id"]) {
            continue;
        }
        for dependency in package["dependencies"]
            .as_array()
            .expect("package dependencies")
            .iter()
            .filter(|dependency| dependency["kind"].is_null())
        {
            let name = dependency["name"].as_str().expect("dependency name");
            if ["aes", "aes-gcm", "blake3", "chacha20poly1305", "ghash"].contains(&name) {
                panic!(
                    "workspace package {} uses production crypto oracle {name}",
                    package["name"]
                );
            }
            if name == "shadowsocks-crypto" {
                assert_eq!(package["name"], "ferrum2-crypto");
            }
        }
    }
    assert!(
        resolved["targets"]
            .as_array()
            .expect("backend targets")
            .iter()
            .all(|target| !target["kind"]
                .as_array()
                .expect("target kinds")
                .contains(&serde_json::json!("custom-build"))),
        "vendored backend must not execute a build script"
    );
    let vcs: Value = serde_json::from_str(
        &fs::read_to_string(vendor.join(".cargo_vcs_info.json")).expect("backend VCS identity"),
    )
    .expect("structured backend VCS identity");
    assert_eq!(
        vcs["git"]["sha1"],
        "2affa6c39b30f7626137a1792c533610cf133ade"
    );

    let mut sources = Vec::new();
    rust_sources(&vendor.join("src"), &mut sources);
    assert!(!sources.is_empty());
    for source in sources {
        let text = fs::read_to_string(&source).expect("vendored Rust source");
        let tokens = text.parse::<TokenStream>().expect("valid Rust tokens");
        assert!(
            !has_unsafe_token(tokens),
            "vendored backend contains unsafe Rust in {}",
            source.display()
        );
    }

    for harmless in [
        "fn TcpStream64k() {}",
        "const unsafe_code: bool = false;",
        "const MESSAGE: &str = \"unsafe\";",
        "// unsafe\nfn safe() {}",
    ] {
        assert!(!has_unsafe_token(
            harmless.parse().expect("harmless Rust tokens")
        ));
    }
    for actual in ["unsafe {}", "unsafe fn operation() {}"] {
        assert!(has_unsafe_token(
            actual.parse().expect("unsafe Rust tokens")
        ));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn profiling_wrapper_enforces_bounds_and_records_stage_results() {
    use std::os::unix::fs::PermissionsExt;

    let root = workspace_root();
    let fake = tempfile::tempdir().expect("fake tool directory");
    let log = fake.path().join("calls.log");
    let tool = r#"#!/usr/bin/env bash
set -u
tool=${0##*/}
case "$tool:$1" in
  perf:--version) printf '%s\n' 'perf version fake' ;;
  perf:list) printf '  %s\n' "$2" ;;
  perf:stat)
    output=
    while (($#)); do
      if [[ $1 == -o ]]; then output=$2; shift 2; else shift; fi
    done
    if [[ -n $output ]]; then
      printf '%s\n' perf_stat >>"$PROFILE_FAKE_LOG"
      if [[ ${PROFILE_FAKE_UNSUPPORTED:-0} == 1 ]]; then printf '%s\n' '<not supported>;cycles:u' >"$output"; else printf '%s\n' '1;task-clock' >"$output"; fi
    else
      printf '%s\n' perf_preflight >>"$PROFILE_FAKE_LOG"
    fi ;;
  samply:--version) printf '%s\n' 'samply 0.13.1' ;;
  samply:record)
    if [[ ${2:-} == --help ]]; then printf '%s\n' '--pid --duration --rate --save-only --output'; exit 0; fi
    output=
    while (($#)); do
      if [[ $1 == --output ]]; then output=$2; shift 2; else shift; fi
    done
    printf '%s\n' samply >>"$PROFILE_FAKE_LOG"
    trap 'printf "%s\n" fake-profile >"$output"; printf "%s\n" samply_int >>"$PROFILE_FAKE_LOG"; exit 0' INT
    while true; do sleep 0.05; done ;;
  readlink:*) printf '%s\n' /fake/ferrum2-client ;;
  readelf:*) printf '%s\n' '    Build ID: 0123456789abcdef' ;;
  git:-C)
    if [[ $3 == status ]]; then exit 0; fi
    if [[ ${5:-} == 'HEAD^{tree}' || ${4:-} == 'HEAD^{tree}' ]]; then printf '%040d\n' 2; else printf '%040d\n' 1; fi ;;
  *) exit 97 ;;
esac
"#;
    for name in ["perf", "samply", "readlink", "readelf", "git"] {
        let path = fake.path().join(name);
        fs::write(&path, tool).expect("fake tool");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("fake tool mode");
    }
    let mut path = vec![fake.path().to_path_buf()];
    path.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let path = std::env::join_paths(path).expect("test PATH");
    let profiles = root.join("profiles");
    fs::create_dir_all(&profiles).expect("profiles directory");
    let reserve = tempfile::NamedTempFile::new_in(&profiles).expect("output reservation");
    let output = reserve.path().to_path_buf();
    reserve.close().expect("remove output reservation");
    let run = |output: &Path, unsupported: bool, duration: &str, frequency: &str| {
        let mut command = Command::new(root.join("tools/profile-cpu.sh"));
        command
            .args([
                "--scenario",
                "tcp-bulk",
                "--role",
                "client",
                "--pid",
                &std::process::id().to_string(),
                "--duration",
                duration,
                "--frequency",
                frequency,
                "--output",
            ])
            .arg(output)
            .env("PATH", &path)
            .env("PROFILE_FAKE_LOG", &log);
        if unsupported {
            command.env("PROFILE_FAKE_UNSUPPORTED", "1");
        }
        command.output().expect("profiling wrapper must start")
    };

    let success = run(&output, false, "1", "1");
    assert!(
        success.status.success(),
        "{}",
        String::from_utf8_lossy(&success.stderr)
    );
    let calls: Vec<_> = fs::read_to_string(&log)
        .expect("fake call log")
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(calls.len(), 4);
    assert_eq!(
        calls.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "perf_preflight".to_owned(),
            "perf_stat".to_owned(),
            "samply".to_owned(),
            "samply_int".to_owned(),
        ])
    );
    let stages = fs::read_to_string(output.join("stage-status.txt")).expect("stage results");
    assert!(
        stages
            .lines()
            .any(|line| line == "stage=samply status=PASS")
    );
    assert!(stages.lines().any(|line| line == "result=PASS exit_code=0"));

    let calls_before_overflow = fs::read(&log).expect("fake call log");
    for (duration, frequency) in [("18446744073709551616", "1"), ("1", "18446744073709551616")] {
        let reserve = tempfile::NamedTempFile::new_in(&profiles).expect("overflow reservation");
        let overflow_output = reserve.path().to_path_buf();
        reserve.close().expect("remove overflow reservation");
        let overflow = run(&overflow_output, false, duration, frequency);
        assert_eq!(overflow.status.code(), Some(2));
        assert!(!overflow_output.exists());
    }
    assert_eq!(
        fs::read(&log).expect("fake call log"),
        calls_before_overflow
    );

    for artifact in [
        "metadata.txt",
        "perf-stat.txt",
        "samply.json.gz",
        "stage-status.txt",
    ] {
        assert!(output.join(artifact).is_file(), "missing {artifact}");
    }
    assert_eq!(
        fs::metadata(&output)
            .expect("output mode")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(output.join("metadata.txt"))
            .expect("metadata mode")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let metadata_before = fs::read(output.join("metadata.txt")).expect("metadata");
    assert!(!run(&output, false, "1", "1").status.success());
    assert_eq!(
        fs::read(output.join("metadata.txt")).expect("metadata"),
        metadata_before
    );

    let reserve = tempfile::NamedTempFile::new_in(&profiles).expect("failed output reservation");
    let failed = reserve.path().to_path_buf();
    reserve.close().expect("remove failed output reservation");
    let failure = run(&failed, true, "1", "1");
    assert!(!failure.status.success());
    assert!(
        fs::read_to_string(failed.join("perf-stat.txt"))
            .expect("partial perf evidence")
            .contains("<not supported>")
    );
    assert!(!failed.join("samply.json.gz").exists());
    assert!(
        fs::read_to_string(failed.join("stage-status.txt"))
            .expect("failed stages")
            .lines()
            .any(|line| line == "stage=perf_stat status=FAIL")
    );

    let outside = fake.path().join("outside-profiles");
    assert!(!run(&outside, false, "1", "1").status.success());
    assert!(!outside.exists());
    fs::remove_dir_all(output).expect("remove successful evidence");
    fs::remove_dir_all(failed).expect("remove failed evidence");
}
