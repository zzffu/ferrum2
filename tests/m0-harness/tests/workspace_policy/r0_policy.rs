use proc_macro2::{TokenStream, TokenTree};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use super::{metadata, workspace_root};

fn policy() -> toml::Value {
    toml::from_str(include_str!("architecture.toml")).expect("structured architecture policy")
}

fn strings(value: &toml::Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("policy string array")
        .iter()
        .map(|value| value.as_str().expect("policy string").to_owned())
        .collect()
}

fn workspace_member_names(metadata: &Value) -> BTreeSet<String> {
    let member_ids: BTreeSet<_> = metadata["workspace_members"]
        .as_array()
        .expect("workspace members")
        .iter()
        .map(|member| member.as_str().expect("workspace member id"))
        .collect();
    metadata["packages"]
        .as_array()
        .expect("metadata packages")
        .iter()
        .filter(|package| member_ids.contains(package["id"].as_str().expect("package id")))
        .map(|package| package["name"].as_str().expect("package name").to_owned())
        .collect()
}

fn validate_member_set(
    actual: &BTreeSet<String>,
    expected: &BTreeSet<String>,
) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "workspace member drift: actual={actual:?} expected={expected:?}"
        ))
    }
}

fn workspace_adjacency(metadata: &Value) -> BTreeMap<String, BTreeSet<String>> {
    let id_to_name: BTreeMap<_, _> = metadata["packages"]
        .as_array()
        .expect("metadata packages")
        .iter()
        .map(|package| {
            (
                package["id"].as_str().expect("package id").to_owned(),
                package["name"].as_str().expect("package name").to_owned(),
            )
        })
        .collect();
    let workspace_names = workspace_member_names(metadata);
    metadata["resolve"]["nodes"]
        .as_array()
        .expect("resolve nodes")
        .iter()
        .filter_map(|node| {
            let name = id_to_name.get(node["id"].as_str().expect("node id"))?;
            if !workspace_names.contains(name) {
                return None;
            }
            let dependencies = node["dependencies"]
                .as_array()
                .expect("resolved dependencies")
                .iter()
                .filter_map(|dependency| {
                    id_to_name.get(dependency.as_str().expect("dependency id"))
                })
                .filter(|dependency| workspace_names.contains(*dependency))
                .cloned()
                .collect();
            Some((name.clone(), dependencies))
        })
        .collect()
}

fn has_path(adjacency: &BTreeMap<String, BTreeSet<String>>, from: &str, to: &str) -> bool {
    let mut queue = VecDeque::from([from.to_owned()]);
    let mut visited = BTreeSet::new();
    while let Some(current) = queue.pop_front() {
        if !visited.insert(current.clone()) {
            continue;
        }
        for dependency in adjacency.get(&current).into_iter().flatten() {
            if dependency == to {
                return true;
            }
            queue.push_back(dependency.clone());
        }
    }
    false
}

fn validate_forbidden_path(
    adjacency: &BTreeMap<String, BTreeSet<String>>,
    from: &str,
    to: &str,
) -> Result<(), String> {
    if has_path(adjacency, from, to) {
        Err(format!("forbidden dependency path {from} -> {to}"))
    } else {
        Ok(())
    }
}

fn has_unsafe_token(tokens: TokenStream) -> bool {
    tokens.into_iter().any(|token| match token {
        TokenTree::Ident(identifier) => identifier == "unsafe",
        TokenTree::Group(group) => has_unsafe_token(group.stream()),
        _ => false,
    })
}

fn rust_sources(directory: &Path, sources: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("Rust source directory") {
        let entry = entry.expect("Rust source entry");
        let file_type = entry.file_type().expect("Rust source entry type");
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            if entry.file_name() == "target" {
                continue;
            }
            rust_sources(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
}

fn managed_rust_sources(root: &Path, source_roots: &BTreeSet<String>) -> BTreeMap<String, String> {
    let mut paths = Vec::new();
    for source_root in source_roots {
        rust_sources(&root.join(source_root), &mut paths);
    }
    paths
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(root)
                .expect("managed Rust source stays under workspace root")
                .to_string_lossy()
                .replace('\\', "/");
            let source = fs::read_to_string(&path).expect("managed Rust source");
            (relative, source)
        })
        .collect()
}

fn validate_fixture_consumer_policy(
    sources: &BTreeMap<String, String>,
    declared: &BTreeSet<String>,
    canonical_path: &str,
    forbidden_paths: &BTreeSet<String>,
) -> Result<(), String> {
    let forbidden_consumers: BTreeSet<_> = sources
        .iter()
        .filter(|(_, source)| {
            forbidden_paths
                .iter()
                .any(|forbidden| source.contains(forbidden))
        })
        .map(|(path, _)| path.clone())
        .collect();
    if !forbidden_consumers.is_empty() {
        return Err(format!(
            "shared DNS TLS consumers retain forbidden fixture paths: {forbidden_consumers:?}"
        ));
    }

    let actual: BTreeSet<_> = sources
        .iter()
        .filter(|(_, source)| source.contains(canonical_path))
        .map(|(path, _)| path.clone())
        .collect();
    if actual == *declared {
        return Ok(());
    }
    let undeclared: BTreeSet<_> = actual.difference(declared).cloned().collect();
    let stale: BTreeSet<_> = declared.difference(&actual).cloned().collect();
    Err(format!(
        "shared DNS TLS consumer drift: undeclared={undeclared:?} stale={stale:?}"
    ))
}

fn count_unsafe_allowances(source: &str) -> usize {
    let compact: String = source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    compact.match_indices("#[allow(unsafe_code)]").count()
        + compact.match_indices("#![allow(unsafe_code)]").count()
}

fn validate_unsafe_sources(
    sources: &[(PathBuf, String)],
    legacy: Option<&Path>,
    ffi_root: &Path,
    expected_allowances: usize,
) -> Result<(), String> {
    let allowance_count: usize = sources
        .iter()
        .map(|(_, source)| count_unsafe_allowances(source))
        .sum();
    if allowance_count != expected_allowances {
        return Err(format!(
            "unsafe allowance count {allowance_count}, expected {expected_allowances}"
        ));
    }
    for (path, source) in sources {
        let tokens = source
            .parse::<TokenStream>()
            .map_err(|error| format!("invalid Rust source {}: {error}", path.display()))?;
        if has_unsafe_token(tokens)
            && !legacy.is_some_and(|legacy| path == legacy)
            && !path.starts_with(ffi_root)
        {
            return Err(format!(
                "unsafe token escaped declared boundary: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn local_crypto_package(lock: &toml::Value) -> Result<&toml::Value, String> {
    let matches: Vec<_> = lock["package"]
        .as_array()
        .ok_or_else(|| "lock package array missing".to_owned())?
        .iter()
        .filter(|package| package["name"].as_str() == Some("shadowsocks-crypto"))
        .collect();
    if matches.len() != 1 {
        return Err(format!(
            "lock contains {} shadowsocks-crypto packages",
            matches.len()
        ));
    }
    let package = matches[0];
    if package["version"].as_str() != Some("0.7.0")
        || package.get("source").is_some()
        || package.get("checksum").is_some()
    {
        return Err("lock does not resolve the reviewed local crypto patch".to_owned());
    }
    Ok(package)
}

fn validate_vendor_manifest(manifest: &toml::Value) -> Result<(), String> {
    if manifest["package"]["version"].as_str() != Some("0.7.0")
        || manifest["package"]["build"].as_bool() != Some(false)
        || manifest["dependencies"]["zeroize"]["version"].as_str() != Some("=1.9.0")
    {
        return Err("vendored crypto identity drift".to_owned());
    }
    Ok(())
}

fn validate_action_reference(reference: &str) -> Result<(), String> {
    if reference.starts_with("./") {
        return Ok(());
    }
    let Some((_, revision)) = reference.rsplit_once('@') else {
        return Err(format!("Action reference lacks revision: {reference}"));
    };
    if revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!(
            "Action reference is not an immutable SHA: {reference}"
        ))
    }
}

#[test]
fn shared_dns_tls_fixtures_match_provenance_and_consumers() {
    let root = workspace_root();
    let policy = policy();
    let contract = &policy["shared_dns_tls"];
    let fixture_root = root.join(contract["root"].as_str().expect("fixture root"));
    let readme =
        fs::read_to_string(root.join(contract["readme"].as_str().expect("fixture provenance")))
            .expect("shared DNS TLS provenance");

    for fixture in contract["files"]
        .as_array()
        .expect("shared DNS TLS fixture rows")
    {
        let name = fixture["name"].as_str().expect("fixture name");
        let bytes = fs::read(fixture_root.join(name)).expect("shared DNS TLS fixture");
        assert_eq!(
            bytes.len(),
            fixture["bytes"].as_integer().expect("fixture byte length") as usize,
            "{name} byte length drift"
        );
        let digest = hex::encode(Sha256::digest(&bytes));
        let expected = fixture["sha256"].as_str().expect("fixture SHA-256");
        assert_eq!(digest, expected, "{name} digest drift");
        assert!(
            readme.contains(name) && readme.contains(expected),
            "{name} is absent from shared fixture provenance"
        );
    }

    let source_roots = strings(&contract["consumer_source_roots"]);
    let sources = managed_rust_sources(&root, &source_roots);
    let forbidden_paths = strings(&contract["forbidden_consumer_paths"]);
    validate_fixture_consumer_policy(
        &sources,
        &strings(&contract["consumers"]),
        contract["root"].as_str().expect("canonical fixture path"),
        &forbidden_paths,
    )
    .expect("shared DNS TLS consumer allowlist");
    for forbidden_path in forbidden_paths {
        assert!(
            !root.join(&forbidden_path).exists(),
            "forbidden shared DNS TLS fixture owner still exists: {forbidden_path}"
        );
    }
    for package in ["crates/ferrum2-dns", "crates/ferrum2-ruleset"] {
        assert!(
            !fixture_root.starts_with(root.join(package)),
            "shared TLS credentials must remain outside the {package} package payload"
        );
    }
}

#[test]
fn declarative_architecture_policy_matches_the_workspace() {
    let policy = policy();
    assert_eq!(policy["schema"].as_integer(), Some(1));
    let expected_members = strings(&policy["workspace_members"]);
    validate_member_set(&workspace_member_names(metadata()), &expected_members)
        .expect("declared workspace members");

    let adjacency = workspace_adjacency(metadata());
    for edge in policy["transitive_forbidden_edges"]
        .as_array()
        .expect("transitive forbidden edges")
        .iter()
        .filter(|edge| edge["enforced"].as_bool() == Some(true))
    {
        validate_forbidden_path(
            &adjacency,
            edge["from"].as_str().expect("edge source"),
            edge["to"].as_str().expect("edge target"),
        )
        .expect("forbidden transitive edge");
    }
    for edge in policy["direct_forbidden_edges"]
        .as_array()
        .expect("direct forbidden edges")
        .iter()
        .filter(|edge| edge["enforced"].as_bool() == Some(true))
    {
        let from = edge["from"].as_str().expect("edge source");
        let to = edge["to"].as_str().expect("edge target");
        assert!(
            !adjacency
                .get(from)
                .is_some_and(|dependencies| dependencies.contains(to)),
            "forbidden direct dependency {from} -> {to}"
        );
    }

    for boundary in policy["internal_dependency_allowlists"]
        .as_array()
        .expect("internal dependency allowlists")
    {
        let package = boundary["package"].as_str().expect("allowlist package");
        let allowed = strings(&boundary["allowed"]);
        let actual = adjacency.get(package).cloned().unwrap_or_default();
        assert_eq!(actual, allowed, "{package} internal dependency drift");
    }

    let declared_runtime_targets: BTreeSet<_> = policy["direct_forbidden_edges"]
        .as_array()
        .expect("direct forbidden edges")
        .iter()
        .filter(|edge| edge["from"].as_str() == Some("ferrum2-runtime"))
        .map(|edge| edge["to"].as_str().expect("runtime target").to_owned())
        .collect();
    assert_eq!(
        declared_runtime_targets,
        BTreeSet::from([
            "ferrum2-config".to_owned(),
            "ferrum2-dns".to_owned(),
            "ferrum2-rule".to_owned(),
            "ferrum2-tun".to_owned(),
            "ferrum2-platform-windows".to_owned(),
        ]),
        "runtime final-state forbidden edges must remain explicit"
    );
}

#[test]
fn unsafe_boundary_honors_the_declared_legacy_phase_and_ffi_subtree() {
    let root = workspace_root();
    let policy = policy();
    let boundary = &policy["unsafe_boundary"];
    let legacy = root.join(boundary["legacy_file"].as_str().expect("legacy file"));
    let ffi_root = root.join(boundary["ffi_subtree"].as_str().expect("FFI subtree"));
    let mut paths = Vec::new();
    rust_sources(&root.join("bins"), &mut paths);
    rust_sources(&root.join("crates"), &mut paths);
    let sources: Vec<_> = paths
        .into_iter()
        .map(|path| {
            let source = fs::read_to_string(&path).expect("workspace Rust source");
            (path, source)
        })
        .collect();
    validate_unsafe_sources(
        &sources,
        boundary["legacy_allowed"]
            .as_bool()
            .expect("legacy phase flag")
            .then_some(legacy.as_path()),
        &ffi_root,
        boundary["allow_declarations"]
            .as_integer()
            .expect("allow declaration count") as usize,
    )
    .expect("unsafe boundary");
}

#[test]
fn root_and_fuzz_locks_resolve_the_reviewed_local_crypto_patch() {
    let root = workspace_root();
    for relative in ["Cargo.lock", "crates/ferrum2-tun/fuzz/Cargo.lock"] {
        let source = fs::read_to_string(root.join(relative)).expect("lock file");
        let lock: toml::Value = toml::from_str(&source).expect("structured lock file");
        let package =
            local_crypto_package(&lock).unwrap_or_else(|error| panic!("{relative}: {error}"));
        let dependencies: BTreeSet<_> = package["dependencies"]
            .as_array()
            .expect("crypto lock dependencies")
            .iter()
            .map(|dependency| dependency.as_str().expect("lock dependency"))
            .collect();
        assert_eq!(
            dependencies,
            BTreeSet::from([
                "aes",
                "aes-gcm",
                "blake3",
                "chacha20poly1305",
                "ghash",
                "zeroize"
            ]),
            "{relative} crypto dependency drift"
        );
    }
}

#[test]
fn root_workflows_pin_actions_and_required_contexts_are_stable() {
    let root = workspace_root();
    let workflow_root = root.join(".github/workflows");
    for entry in fs::read_dir(&workflow_root).expect("workflow directory") {
        let path = entry.expect("workflow entry").path();
        if !path
            .extension()
            .is_some_and(|extension| extension == "yml" || extension == "yaml")
        {
            continue;
        }
        let source = fs::read_to_string(&path).expect("workflow source");
        assert!(
            source.contains("permissions:\n  contents: read"),
            "{} lacks read-only permissions",
            path.display()
        );
        for line in source.lines().map(str::trim) {
            if let Some(reference) = line.strip_prefix("uses:") {
                validate_action_reference(reference.trim())
                    .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            }
        }
    }

    let fuzz = fs::read_to_string(workflow_root.join("tun-fuzz-deterministic.yml"))
        .expect("fuzz workflow");
    let trigger = fuzz
        .split_once("\npermissions:\n")
        .expect("fuzz workflow trigger boundary")
        .0;
    assert!(
        trigger.contains("\n  pull_request:\n") && trigger.contains("\n  push:\n"),
        "the independently required fuzz workflow must cover pull requests and protected pushes"
    );
    assert!(
        !trigger
            .lines()
            .any(|line| matches!(line.trim(), "paths:" | "paths-ignore:")),
        "the independently required fuzz workflow must run on every PR and protected push"
    );
    let owner_paths = strings(&policy()["fuzz_impact"]["owner_paths"]);
    for required in [
        "crates/ferrum2-tun/fuzz/**",
        "crates/ferrum2-platform-windows/src/**",
        "tests/platform/**",
        "tools/powershell/**",
        ".github/workflows/tun-fuzz-deterministic.yml",
        "vendor/shadowsocks-crypto/**",
    ] {
        assert!(
            owner_paths.contains(required),
            "fuzz owner-impact ledger is missing {required}"
        );
    }

    let policy = policy();
    let required = &policy["ci_required"];
    for (workflow_key, needs_key) in [
        ("main_workflow", "main_needs"),
        ("fuzz_workflow", "fuzz_needs"),
    ] {
        let relative = required[workflow_key]
            .as_str()
            .expect("required workflow path");
        let source = fs::read_to_string(root.join(relative)).expect("required workflow");
        assert_eq!(
            source.matches("\n  required:\n").count(),
            1,
            "{relative} must expose one stable required job"
        );
        let required_job = source
            .split_once("\n  required:\n")
            .expect("required job block")
            .1;
        assert!(
            required_job.contains("    if: ${{ always() }}"),
            "{relative} required job must run after failed dependencies"
        );
        let expected_dependencies = strings(&required[needs_key]);
        let mut actual_dependencies = BTreeSet::new();
        let mut in_needs = false;
        for line in required_job.lines() {
            if line == "    needs:" {
                in_needs = true;
                continue;
            }
            if !in_needs {
                continue;
            }
            let Some(dependency) = line.strip_prefix("      - ") else {
                break;
            };
            actual_dependencies.insert(dependency.to_owned());
        }
        assert_eq!(
            actual_dependencies, expected_dependencies,
            "{relative} required job dependency set drift"
        );
        for dependency in expected_dependencies {
            assert!(
                required_job.contains(&format!("needs.{dependency}.result")),
                "{relative} required job does not explicitly enforce {dependency}"
            );
        }
    }

    let main = fs::read_to_string(root.join(".github/workflows/m0.yml")).expect("main workflow");
    for command in [
        "cargo test --workspace --exclude ferrum2-client --exclude ferrum2-tun --exclude ferrum2-platform-windows --locked",
        "cargo test -p ferrum2-client --all-features --no-run --locked",
        "cargo test -p ferrum2-tun --all-features --no-run --locked",
        "cargo test -p ferrum2-platform-windows --all-features --no-run --locked",
        "cargo +1.97.1 test -p ferrum2-client --all-features --no-run --locked --target ${{ matrix.target }}",
        "cargo +1.97.1 test -p ferrum2-tun --all-features --no-run --locked --target ${{ matrix.target }}",
        "cargo +1.97.1 test -p ferrum2-platform-windows --all-features --no-run --locked --target ${{ matrix.target }}",
        "python3 -B -m unittest discover -s tests/performance_candidate -p 'test_*.py' -v",
        "python3 -B -m unittest discover -s tests/performance_rule -p 'test_*.py' -v",
    ] {
        assert!(
            main.contains(command),
            "main workflow lost safe command: {command}"
        );
    }
}

#[test]
fn policy_mutations_fail_closed() {
    let expected = strings(&policy()["workspace_members"]);
    let mut unexpected_member = expected.clone();
    unexpected_member.insert("untracked-workspace-member".to_owned());
    assert!(validate_member_set(&unexpected_member, &expected).is_err());

    let graph = BTreeMap::from([
        (
            "ferrum2-server".to_owned(),
            BTreeSet::from(["platform".to_owned()]),
        ),
        (
            "platform".to_owned(),
            BTreeSet::from(["ferrum2-tun".to_owned()]),
        ),
    ]);
    assert!(validate_forbidden_path(&graph, "ferrum2-server", "ferrum2-tun").is_err());

    let legacy = PathBuf::from("legacy.rs");
    let ffi = PathBuf::from("ffi");
    let second_allowance = vec![
        (
            legacy.clone(),
            "#[allow(unsafe_code)] fn first() { unsafe {} }".to_owned(),
        ),
        (
            ffi.join("raw.rs"),
            "#[allow(unsafe_code)] fn second() { unsafe {} }".to_owned(),
        ),
    ];
    assert!(validate_unsafe_sources(&second_allowance, Some(&legacy), &ffi, 1).is_err());

    let vendor_source =
        fs::read_to_string(workspace_root().join("vendor/shadowsocks-crypto/Cargo.toml"))
            .expect("vendor manifest");
    let vendor: toml::Value = toml::from_str(&vendor_source).expect("structured vendor manifest");
    validate_vendor_manifest(&vendor).expect("current vendor identity");
    let mut drifted = vendor;
    drifted["dependencies"]["zeroize"]["version"] = toml::Value::String("=9.9.9".to_owned());
    assert!(validate_vendor_manifest(&drifted).is_err());

    assert!(validate_action_reference("actions/checkout@v5").is_err());
}

#[test]
fn fixture_consumer_policy_rejects_undeclared_and_stale_consumers() {
    let canonical = format!("{}/{}", "tests/fixtures", "dns-tls");
    let sources = BTreeMap::from([
        (
            "crates/declared.rs".to_owned(),
            format!("include_bytes!(\"../../../{canonical}/root.der\");"),
        ),
        (
            "crates/undeclared.rs".to_owned(),
            format!("include_bytes!(\"../../../{canonical}/leaf.der\");"),
        ),
    ]);
    let forbidden = BTreeSet::new();

    let missing_declaration = validate_fixture_consumer_policy(
        &sources,
        &BTreeSet::from(["crates/declared.rs".to_owned()]),
        &canonical,
        &forbidden,
    )
    .expect_err("undeclared fixture consumer must fail closed");
    assert!(missing_declaration.contains("crates/undeclared.rs"));

    let stale_declaration = validate_fixture_consumer_policy(
        &sources,
        &BTreeSet::from([
            "crates/declared.rs".to_owned(),
            "crates/undeclared.rs".to_owned(),
            "crates/stale.rs".to_owned(),
        ]),
        &canonical,
        &forbidden,
    )
    .expect_err("stale fixture consumer must fail closed");
    assert!(stale_declaration.contains("crates/stale.rs"));
}

#[test]
fn fixture_consumer_policy_rejects_forbidden_private_fixture_paths() {
    let canonical = format!("{}/{}", "tests/fixtures", "dns-tls");
    let forbidden = format!("{}/{}", "crates/ferrum2-dns/tests", "fixtures");
    let sources = BTreeMap::from([(
        "crates/legacy.rs".to_owned(),
        format!("include_bytes!(\"../../../{forbidden}/root.der\");"),
    )]);
    let error = validate_fixture_consumer_policy(
        &sources,
        &BTreeSet::new(),
        &canonical,
        &BTreeSet::from([forbidden]),
    )
    .expect_err("private fixture path must fail closed");
    assert!(error.contains("crates/legacy.rs"));
}
