use proc_macro2::{TokenStream, TokenTree};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

#[path = "workspace_policy/r0_policy.rs"]
mod r0_policy;

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
    let member_names: BTreeSet<_> = members
        .iter()
        .map(|package| package["name"].as_str().expect("package name"))
        .collect();
    for required in [
        "ferrum2-client",
        "ferrum2-server",
        "ferrum2-core",
        "ferrum2-rule",
        "ferrum2-crypto",
        "ferrum2-dns",
        "ferrum2-runtime",
        "ferrum2-shadowsocks",
        "ferrum2-socks5",
        "ferrum2-tun",
        "ferrum2-platform-windows",
        "ferrum2-m0-harness",
        "ferrum2-m4-qualification",
    ] {
        assert!(
            member_names.contains(required),
            "missing required member {required}"
        );
    }

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
        assert!(
            package["targets"]
                .as_array()
                .expect("package targets")
                .iter()
                .all(|target| !target["kind"]
                    .as_array()
                    .expect("target kinds")
                    .contains(&serde_json::json!("custom-build"))),
            "{} must not execute a workspace build script",
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
        if package["name"] == "ferrum2-platform-windows" {
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
                assert_eq!(
                    source, "registry+https://github.com/rust-lang/crates.io-index",
                    "{} dependency {} has a non-registry source",
                    package["name"], dependency["name"]
                );
            }
        }
    }
}

#[test]
fn workspace_boundaries_are_expressed_by_cargo_metadata() {
    let metadata = metadata();
    let core = package(metadata, "ferrum2-core");
    let core_dependencies: BTreeSet<_> = core["dependencies"]
        .as_array()
        .expect("core dependencies")
        .iter()
        .filter(|dependency| dependency["kind"].is_null())
        .map(|dependency| dependency["name"].as_str().expect("dependency name"))
        .collect();
    assert_eq!(core_dependencies, BTreeSet::from(["bytes"]));

    let rule = package(metadata, "ferrum2-rule");
    let rule_dependencies: BTreeSet<_> = rule["dependencies"]
        .as_array()
        .expect("rule dependencies")
        .iter()
        .filter(|dependency| dependency["kind"].is_null())
        .map(|dependency| dependency["name"].as_str().expect("dependency name"))
        .collect();
    assert_eq!(
        rule_dependencies,
        BTreeSet::from(["aho-corasick", "ferrum2-core", "flate2", "ipnet"])
    );
    assert!(
        core_dependencies
            .iter()
            .all(|dependency| *dependency != "ferrum2-rule"),
        "ferrum2-core must not depend on the policy compiler"
    );

    let config = package(metadata, "ferrum2-config");
    let config_dependencies: BTreeSet<_> = config["dependencies"]
        .as_array()
        .expect("config dependencies")
        .iter()
        .map(|dependency| dependency["name"].as_str().expect("dependency name"))
        .collect();
    assert!(
        !config_dependencies.contains("ferrum2-dns")
            && !config_dependencies.contains("hickory-proto"),
        "configuration must expose a runtime-neutral DNS blueprint without DNS/Hickory edges"
    );
    let dns = package(metadata, "ferrum2-dns");
    assert!(
        dns["dependencies"]
            .as_array()
            .expect("DNS dependencies")
            .iter()
            .all(|dependency| dependency["name"] != "ferrum2-config"),
        "DNS execution must consume the rule blueprint without a config back-edge"
    );

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

    let platform_windows_edges: Vec<_> = metadata["packages"]
        .as_array()
        .expect("metadata packages")
        .iter()
        .flat_map(|package| {
            package["dependencies"]
                .as_array()
                .expect("package dependencies")
                .iter()
                .filter(|dependency| dependency["name"] == "ferrum2-platform-windows")
                .map(move |dependency| {
                    (
                        package["name"].as_str().expect("package name"),
                        dependency["target"].as_str(),
                    )
                })
        })
        .collect();
    assert_eq!(
        platform_windows_edges,
        vec![
            ("ferrum2-client", None),
            ("ferrum2-server", None),
            ("ferrum2-tun", None),
        ]
    );
    let platform_windows_src = PathBuf::from(
        package(metadata, "ferrum2-platform-windows")["manifest_path"]
            .as_str()
            .expect("Windows platform manifest path"),
    )
    .parent()
    .expect("Windows platform package directory")
    .join("src")
    .canonicalize()
    .expect("Windows platform source directory");
    let unsafe_root = platform_windows_src
        .join("windows/ffi")
        .canonicalize()
        .expect("Windows FFI subtree");
    let mut platform_windows_sources = Vec::new();
    rust_sources(&platform_windows_src, &mut platform_windows_sources);
    let mut unsafe_source_count = 0;
    for source in platform_windows_sources {
        let source = source
            .canonicalize()
            .expect("canonical Windows platform source");
        let tokens = fs::read_to_string(&source)
            .expect("Windows platform Rust source")
            .parse::<TokenStream>()
            .expect("valid Windows platform Rust tokens");
        if source.starts_with(&unsafe_root) {
            if has_unsafe_token(tokens) {
                unsafe_source_count += 1;
            }
        } else {
            assert!(
                !has_unsafe_token(tokens),
                "unsafe Rust escaped the Windows FFI subtree into {}",
                source.display()
            );
        }
    }
    assert!(
        unsafe_source_count > 0,
        "the declared Windows FFI boundary disappeared"
    );

    for (package_name, target_name) in [
        ("ferrum2-m0-harness", "m0-qualification"),
        ("ferrum2-m4-qualification", "m4-qualification"),
    ] {
        let target = package(metadata, package_name)["targets"]
            .as_array()
            .expect("package targets")
            .iter()
            .find(|target| target["name"] == target_name)
            .unwrap_or_else(|| panic!("missing qualification target {target_name}"));
        assert_eq!(target["kind"], serde_json::json!(["bin"]));
        assert_eq!(
            target["test"], false,
            "{target_name} must not run in cargo test"
        );
    }
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

    for target in [
        "x86_64-pc-windows-msvc",
        "x86_64-unknown-linux-gnu",
        "x86_64-unknown-linux-musl",
    ] {
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
        for forbidden in [
            "aws-lc-rs ",
            "aws-lc-sys ",
            "quinn ",
            "h3 ",
            "ipconfig ",
            "resolv-conf ",
            "system-configuration ",
        ] {
            assert!(
                !tree.lines().any(|line| line.starts_with(forbidden)),
                "{target} production graph contains forbidden package {}",
                forbidden.trim()
            );
        }
    }

    let resolver = dependency(package(metadata, "ferrum2-dns"), "hickory-resolver", None);
    assert_eq!(resolver["uses_default_features"], false);
    assert_eq!(
        features(resolver),
        BTreeSet::from(["https-ring", "tls-ring", "tokio", "webpki-roots"])
    );

    let smoltcp = dependency(package(metadata, "ferrum2-tun"), "smoltcp", None);
    assert_eq!(smoltcp["uses_default_features"], false);
    assert_eq!(
        features(smoltcp),
        BTreeSet::from([
            "assembler-max-segment-count-4",
            "iface-max-addr-count-2",
            "iface-max-route-count-2",
            "medium-ip",
            "proto-ipv4",
            "proto-ipv6",
            "socket-tcp",
            "socket-tcp-reno",
            "socket-udp",
            "std",
        ])
    );
    let smoltcp_package = package(metadata, "smoltcp");
    let resolved_smoltcp = metadata["resolve"]["nodes"]
        .as_array()
        .expect("resolve nodes")
        .iter()
        .find(|node| node["id"] == smoltcp_package["id"])
        .expect("resolved smoltcp node");
    assert!(
        !features(resolved_smoltcp).contains("auto-icmp-echo-reply"),
        "the resolved packet stack must not synthesize ICMP replies"
    );
}

fn has_unsafe_token(tokens: TokenStream) -> bool {
    tokens.into_iter().any(|token| match token {
        TokenTree::Ident(identifier) => identifier == "unsafe",
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
    let vendor_manifest_source =
        fs::read_to_string(vendor.join("Cargo.toml")).expect("vendored backend manifest");
    let vendor_manifest: toml::Value =
        toml::from_str(&vendor_manifest_source).expect("structured backend manifest");
    assert_eq!(vendor_manifest["package"]["build"].as_bool(), Some(false));
    let v2_features: BTreeSet<_> = vendor_manifest["features"]["v2"]
        .as_array()
        .expect("v2 feature mapping")
        .iter()
        .map(|feature| feature.as_str().expect("v2 feature"))
        .collect();
    assert_eq!(
        v2_features,
        BTreeSet::from([
            "dep:aes-v2",
            "dep:aes-gcm-v2",
            "dep:blake3-v2",
            "dep:chacha20poly1305-v2",
            "dep:ghash-v2",
            "dep:zeroize",
        ])
    );
    for (dependency, package_name, version, expected_features) in [
        ("aes-v2", "aes", "=0.9.1", &["zeroize"][..]),
        (
            "aes-gcm-v2",
            "aes-gcm",
            "=0.11.0",
            &["aes", "bytes", "zeroize"][..],
        ),
        ("blake3-v2", "blake3", "=1.8.5", &["std", "zeroize"][..]),
        (
            "chacha20poly1305-v2",
            "chacha20poly1305",
            "=0.11.0",
            &["bytes", "zeroize"][..],
        ),
        ("ghash-v2", "ghash", "=0.6.0", &["zeroize"][..]),
    ] {
        let specification = &vendor_manifest["dependencies"][dependency];
        assert_eq!(
            specification["package"].as_str(),
            Some(package_name),
            "{dependency} package identity"
        );
        assert_eq!(
            specification["version"].as_str(),
            Some(version),
            "{dependency} version"
        );
        for alternative_source in ["git", "path", "registry"] {
            assert!(
                specification.get(alternative_source).is_none(),
                "{dependency} changed source via {alternative_source}"
            );
        }
        assert_eq!(
            specification["optional"].as_bool(),
            Some(true),
            "{dependency} selection"
        );
        assert_eq!(
            specification["default-features"].as_bool(),
            Some(false),
            "{dependency} default features"
        );
        let selected_features: BTreeSet<_> = specification["features"]
            .as_array()
            .expect("backend dependency features")
            .iter()
            .map(|feature| feature.as_str().expect("backend dependency feature"))
            .collect();
        assert_eq!(
            selected_features,
            expected_features.iter().copied().collect(),
            "{dependency} feature identity"
        );
    }
    let zeroize = &vendor_manifest["dependencies"]["zeroize"];
    assert_eq!(zeroize["version"].as_str(), Some("=1.9.0"));
    assert_eq!(zeroize["optional"].as_bool(), Some(true));
    assert_eq!(zeroize["default-features"].as_bool(), Some(false));
    assert_eq!(
        zeroize["features"]
            .as_array()
            .expect("zeroize features")
            .iter()
            .map(|feature| feature.as_str().expect("zeroize feature"))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["alloc"])
    );
    for alternative_source in ["git", "path", "registry"] {
        assert!(zeroize.get(alternative_source).is_none());
    }
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
