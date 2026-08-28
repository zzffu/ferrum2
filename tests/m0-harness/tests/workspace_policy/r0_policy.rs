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

fn workspace_declared_adjacency(metadata: &Value) -> BTreeMap<String, BTreeSet<String>> {
    let member_ids: BTreeSet<_> = metadata["workspace_members"]
        .as_array()
        .expect("workspace members")
        .iter()
        .map(|member| member.as_str().expect("workspace member id"))
        .collect();
    let member_roots: BTreeMap<_, _> = metadata["packages"]
        .as_array()
        .expect("metadata packages")
        .iter()
        .filter(|package| member_ids.contains(package["id"].as_str().expect("package id")))
        .map(|package| {
            (
                Path::new(
                    package["manifest_path"]
                        .as_str()
                        .expect("package manifest path"),
                )
                .parent()
                .expect("package manifest parent")
                .to_path_buf(),
                package["name"].as_str().expect("package name").to_owned(),
            )
        })
        .collect();
    metadata["packages"]
        .as_array()
        .expect("metadata packages")
        .iter()
        .filter(|package| member_ids.contains(package["id"].as_str().expect("package id")))
        .map(|package| {
            let dependencies = package["dependencies"]
                .as_array()
                .expect("package dependencies")
                .iter()
                .filter_map(|dependency| {
                    dependency["path"]
                        .as_str()
                        .and_then(|path| member_roots.get(Path::new(path)))
                })
                .cloned()
                .collect();
            (
                package["name"].as_str().expect("package name").to_owned(),
                dependencies,
            )
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
        let path = root.join(source_root);
        if path.is_file() {
            paths.push(path);
        } else {
            rust_sources(&path, &mut paths);
        }
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
    allowed_paths: &[PathBuf],
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
            && !allowed_paths
                .iter()
                .any(|allowed| path == allowed || path.starts_with(allowed))
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

#[path = "workflow_contract.rs"]
mod workflow_contract;

use workflow_contract::{
    validate_fuzz_workflow_execution, validate_hosted_library_execution,
    validate_lifecycle_triggers, validate_read_only_permissions, validate_required_job,
};
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

    // Manifest declarations are the security boundary: optional, renamed,
    // target-specific, build, and development edges require review even when
    // the default feature resolution does not activate them.
    let adjacency = workspace_declared_adjacency(metadata());
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
fn declared_adjacency_reviews_optional_renamed_and_target_specific_edges() {
    let metadata = serde_json::json!({
        "workspace_members": ["app-id", "structural-id", "runtime-id", "core-id"],
        "packages": [
            {
                "id": "app-id",
                "name": "app",
                "manifest_path": "C:/workspace/app/Cargo.toml",
                "dependencies": [
                    {
                        "name": "ferrum2-structural",
                        "rename": "evidence",
                        "kind": null,
                        "optional": true,
                        "target": "cfg(windows)",
                        "path": "C:/workspace/structural"
                    },
                    {
                        "name": "ferrum2-runtime",
                        "rename": "runtime_build",
                        "kind": "build",
                        "optional": false,
                        "target": null,
                        "path": "C:/workspace/runtime"
                    },
                    {
                        "name": "ferrum2-core",
                        "rename": null,
                        "kind": "dev",
                        "optional": false,
                        "target": "cfg(unix)",
                        "path": "C:/workspace/core"
                    },
                    {
                        "name": "ferrum2-core",
                        "rename": "external_lookalike",
                        "kind": null,
                        "optional": false,
                        "target": null,
                        "path": "C:/outside/core"
                    }
                ]
            },
            {
                "id": "structural-id",
                "name": "ferrum2-structural",
                "manifest_path": "C:/workspace/structural/Cargo.toml",
                "dependencies": []
            },
            {
                "id": "runtime-id",
                "name": "ferrum2-runtime",
                "manifest_path": "C:/workspace/runtime/Cargo.toml",
                "dependencies": []
            },
            {
                "id": "core-id",
                "name": "ferrum2-core",
                "manifest_path": "C:/workspace/core/Cargo.toml",
                "dependencies": []
            }
        ]
    });

    let adjacency = workspace_declared_adjacency(&metadata);
    assert_eq!(
        adjacency["app"],
        BTreeSet::from([
            "ferrum2-core".to_owned(),
            "ferrum2-runtime".to_owned(),
            "ferrum2-structural".to_owned(),
        ])
    );
}

#[test]
fn unsafe_boundary_honors_the_declared_reviewed_paths() {
    let root = workspace_root();
    let policy = policy();
    let boundary = &policy["unsafe_boundary"];
    let legacy = root.join(boundary["legacy_file"].as_str().expect("legacy file"));
    let allowed_paths: Vec<_> = boundary["allowed_paths"]
        .as_array()
        .expect("unsafe allowed paths")
        .iter()
        .map(|path| root.join(path.as_str().expect("unsafe allowed path")))
        .collect();
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
        &allowed_paths,
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
        validate_read_only_permissions(&source)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        for line in source.lines().map(str::trim) {
            if let Some(reference) = line.strip_prefix("uses:") {
                validate_action_reference(reference.trim())
                    .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            }
        }
    }

    let fuzz = fs::read_to_string(workflow_root.join("tun-fuzz-deterministic.yml"))
        .expect("fuzz workflow");
    validate_fuzz_workflow_execution(&fuzz).expect("fuzz workflow execution contract");
    let fuzz_policy = policy();
    let owner_paths = strings(&fuzz_policy["fuzz_impact"]["owner_paths"]);
    assert_eq!(
        owner_paths,
        BTreeSet::from([
            ".gitattributes".to_owned(),
            ".cargo/config.toml".to_owned(),
            ".github/workflows/tun-fuzz-deterministic.yml".to_owned(),
            "Cargo.lock".to_owned(),
            "Cargo.toml".to_owned(),
            "crates/ferrum2-config/Cargo.toml".to_owned(),
            "crates/ferrum2-config/src/**".to_owned(),
            "crates/ferrum2-core/Cargo.toml".to_owned(),
            "crates/ferrum2-core/src/**".to_owned(),
            "crates/ferrum2-crypto/Cargo.toml".to_owned(),
            "crates/ferrum2-crypto/src/**".to_owned(),
            "crates/ferrum2-net/Cargo.toml".to_owned(),
            "crates/ferrum2-net/src/**".to_owned(),
            "crates/ferrum2-platform-windows/Cargo.toml".to_owned(),
            "crates/ferrum2-platform-windows/src/**".to_owned(),
            "crates/ferrum2-rule/Cargo.toml".to_owned(),
            "crates/ferrum2-rule/src/**".to_owned(),
            "crates/ferrum2-runtime/Cargo.toml".to_owned(),
            "crates/ferrum2-runtime/src/**".to_owned(),
            "crates/ferrum2-tun/Cargo.toml".to_owned(),
            "crates/ferrum2-tun/fuzz/**".to_owned(),
            "crates/ferrum2-tun/src/**".to_owned(),
            "crates/ferrum2-tun/tests/fixtures/packets/**".to_owned(),
            "rust-toolchain.toml".to_owned(),
            "tests/m0-harness/tests/workspace_policy/architecture.toml".to_owned(),
            "tools/ci/__init__.py".to_owned(),
            "tools/ci/fuzz_contract.py".to_owned(),
            "tools/ci/git_changes.py".to_owned(),
            "vendor/shadowsocks-crypto/Cargo.toml".to_owned(),
            "vendor/shadowsocks-crypto/src/**".to_owned(),
        ]),
        "the fuzz owner-impact ledger drifted"
    );
    let documentation_exclusions = fuzz_policy["fuzz_impact"]["documentation_exclusions"]
        .as_array()
        .expect("typed fuzz documentation exclusions");
    let actual_exclusions: BTreeSet<_> = documentation_exclusions
        .iter()
        .map(|entry| {
            (
                entry["pattern"]
                    .as_str()
                    .expect("documentation exclusion pattern"),
                entry["kind"]
                    .as_str()
                    .expect("documentation exclusion kind"),
            )
        })
        .collect();
    assert_eq!(
        actual_exclusions,
        BTreeSet::from([
            ("crates/ferrum2-tun/fuzz/*.md", "markdown"),
            ("crates/ferrum2-tun/fuzz/**/*.md", "markdown"),
        ]),
        "fuzz documentation exclusions must remain explicit and typed"
    );
    let campaign = &policy()["fuzz_campaign"];
    let campaign_targets = strings(&campaign["targets"]);
    assert_eq!(
        campaign_targets,
        BTreeSet::from([
            "config_legacy_fields".to_owned(),
            "packet_reassembly".to_owned(),
            "strict_route_rules".to_owned(),
            "udp_reset_races".to_owned(),
        ]),
        "the hosted fuzz campaign target set drifted"
    );
    let seconds_per_target = campaign["seconds_per_target"]
        .as_integer()
        .expect("fuzz seconds per target");
    let total_seconds = campaign["total_seconds"]
        .as_integer()
        .expect("total fuzz seconds");
    assert_eq!(
        seconds_per_target * campaign_targets.len() as i64,
        total_seconds,
        "the declared fuzz target budgets do not add up to the total campaign budget"
    );
    assert_eq!(
        total_seconds, 3_600,
        "the required fuzz campaign is one hour"
    );
    let main = fs::read_to_string(workflow_root.join("m0.yml")).expect("main workflow source");
    validate_hosted_library_execution(&main).expect("hosted-safe library execution contract");
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
        let expected_dependencies = strings(&required[needs_key]);
        validate_required_job(&source, &expected_dependencies)
            .unwrap_or_else(|error| panic!("{relative}: {error}"));
    }

    let lifecycle =
        fs::read_to_string(workflow_root.join("lifecycle-stress.yml")).expect("lifecycle workflow");
    validate_lifecycle_triggers(&lifecycle).expect("lifecycle workflow trigger contract");
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
    assert!(
        validate_unsafe_sources(
            &second_allowance,
            Some(&legacy),
            std::slice::from_ref(&ffi),
            1
        )
        .is_err()
    );

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
