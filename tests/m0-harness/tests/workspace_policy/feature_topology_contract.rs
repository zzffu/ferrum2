use std::collections::BTreeSet;
use std::fs;
use std::process::Command;

use toml::Value;

use super::workspace_root;

#[derive(Clone)]
struct FeatureTopology {
    workspace: Value,
    platform: Value,
    tun: Value,
    fuzz: Value,
    client: Value,
    server: Value,
}

type TopologyMutation = (&'static str, Box<dyn Fn(&mut FeatureTopology)>);

impl FeatureTopology {
    fn load() -> Self {
        let root = workspace_root();
        Self {
            workspace: parse_manifest(&root.join("Cargo.toml")),
            platform: parse_manifest(&root.join("crates/ferrum2-platform-windows/Cargo.toml")),
            tun: parse_manifest(&root.join("crates/ferrum2-tun/Cargo.toml")),
            fuzz: parse_manifest(&root.join("crates/ferrum2-tun/fuzz/Cargo.toml")),
            client: parse_manifest(&root.join("bins/ferrum2-client/Cargo.toml")),
            server: parse_manifest(&root.join("bins/ferrum2-server/Cargo.toml")),
        }
    }

    fn validate(&self) -> Result<(), String> {
        exact_feature_map(
            &self.platform,
            "platform",
            &[
                ("default", &["live-backend"]),
                ("fuzzing", &[]),
                ("live-backend", &[]),
            ],
        )?;
        exact_feature_map(
            &self.tun,
            "tun",
            &[
                ("default", &["live-backend"]),
                ("fuzzing", &[]),
                ("live-backend", &["ferrum2-platform-windows/live-backend"]),
            ],
        )?;

        exact_dependency(
            &self.workspace,
            &["workspace", "dependencies"],
            "ferrum2-platform-windows",
            false,
            &[],
            "workspace platform dependency",
        )?;
        exact_dependency(
            &self.workspace,
            &["workspace", "dependencies"],
            "ferrum2-tun",
            false,
            &[],
            "workspace TUN dependency",
        )?;
        exact_dependency(
            &self.tun,
            &["dependencies"],
            "ferrum2-platform-windows",
            false,
            &[],
            "TUN platform dependency",
        )?;
        exact_dependency(
            &self.fuzz,
            &["dependencies"],
            "ferrum2-platform-windows",
            false,
            &["fuzzing"],
            "fuzz platform dependency",
        )?;
        exact_dependency(
            &self.fuzz,
            &["dependencies"],
            "ferrum2-tun",
            false,
            &["fuzzing"],
            "fuzz TUN dependency",
        )?;

        explicit_live_dependency(
            &self.client,
            "ferrum2-platform-windows",
            "client platform dependency",
        )?;
        explicit_live_dependency(&self.client, "ferrum2-tun", "client TUN dependency")?;
        explicit_live_dependency(
            &self.server,
            "ferrum2-platform-windows",
            "server platform dependency",
        )?;
        Ok(())
    }
}

fn parse_manifest(path: &std::path::Path) -> Value {
    let source =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    toml::from_str(&source).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn table_at<'a>(
    manifest: &'a Value,
    path: &[&str],
    owner: &str,
) -> Result<&'a toml::Table, String> {
    let mut current = manifest;
    for component in path {
        current = current
            .get(*component)
            .ok_or_else(|| format!("{owner} is missing table component {component}"))?;
    }
    current
        .as_table()
        .ok_or_else(|| format!("{owner} must be a TOML table"))
}

fn exact_feature_map(
    manifest: &Value,
    owner: &str,
    expected: &[(&str, &[&str])],
) -> Result<(), String> {
    let features = table_at(manifest, &["features"], owner)?;
    let actual_names: BTreeSet<_> = features.keys().map(String::as_str).collect();
    let expected_names: BTreeSet<_> = expected.iter().map(|(name, _)| *name).collect();
    if actual_names != expected_names {
        return Err(format!(
            "{owner} feature names changed: expected {expected_names:?}, got {actual_names:?}"
        ));
    }
    for (name, members) in expected {
        exact_string_array(
            features
                .get(*name)
                .ok_or_else(|| format!("{owner} feature {name} is missing"))?,
            members,
            &format!("{owner} feature {name}"),
        )?;
    }
    Ok(())
}

fn exact_dependency(
    manifest: &Value,
    table_path: &[&str],
    dependency: &str,
    expected_default_features: bool,
    expected_features: &[&str],
    owner: &str,
) -> Result<(), String> {
    let specification = unique_dependency_at(manifest, table_path, dependency, owner)?;
    if specification
        .get("default-features")
        .and_then(Value::as_bool)
        != Some(expected_default_features)
    {
        return Err(format!(
            "{owner} must set default-features = {expected_default_features}"
        ));
    }
    exact_optional_features(specification, expected_features, owner)
}

fn explicit_live_dependency(manifest: &Value, dependency: &str, owner: &str) -> Result<(), String> {
    let specification = unique_dependency_at(manifest, &["dependencies"], dependency, owner)?;
    if specification.get("workspace").and_then(Value::as_bool) != Some(true) {
        return Err(format!("{owner} must inherit the workspace dependency"));
    }
    if specification
        .get("default-features")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return Err(format!("{owner} must not re-enable default features"));
    }
    exact_optional_features(specification, &["live-backend"], owner)
}

fn unique_dependency_at<'a>(
    manifest: &'a Value,
    expected_table_path: &[&str],
    dependency: &str,
    owner: &str,
) -> Result<&'a toml::Table, String> {
    let mut occurrences = Vec::new();
    collect_dependency_occurrences(manifest, dependency, &mut Vec::new(), &mut occurrences)?;
    let expected_path = expected_table_path.join(".");
    if occurrences.len() != 1 || occurrences[0].0 != expected_path || occurrences[0].1 != dependency
    {
        let actual_paths: Vec<_> = occurrences
            .iter()
            .map(|(path, alias, _)| format!("{path}.{alias}"))
            .collect();
        return Err(format!(
            "{owner} must occur only in {expected_path}; got {actual_paths:?}"
        ));
    }
    Ok(occurrences.remove(0).2)
}

fn collect_dependency_occurrences<'a>(
    value: &'a Value,
    dependency: &str,
    path: &mut Vec<String>,
    occurrences: &mut Vec<(String, String, &'a toml::Table)>,
) -> Result<(), String> {
    let Some(table) = value.as_table() else {
        return Ok(());
    };
    for (name, child) in table {
        path.push(name.clone());
        if matches!(
            name.as_str(),
            "dependencies" | "dev-dependencies" | "build-dependencies"
        ) {
            let dependencies = child
                .as_table()
                .ok_or_else(|| format!("{} must be a dependency table", path.join(".")))?;
            for (alias, specification) in dependencies {
                let package = specification
                    .as_table()
                    .and_then(|table| table.get("package"))
                    .map(|package| {
                        package.as_str().ok_or_else(|| {
                            format!(
                                "{}.{} package identity must be a string",
                                path.join("."),
                                alias
                            )
                        })
                    })
                    .transpose()?
                    .unwrap_or(alias);
                if package == dependency {
                    let specification = specification.as_table().ok_or_else(|| {
                        format!(
                            "{}.{} must use an explicit dependency table",
                            path.join("."),
                            alias
                        )
                    })?;
                    occurrences.push((path.join("."), alias.clone(), specification));
                }
            }
        }
        collect_dependency_occurrences(child, dependency, path, occurrences)?;
        path.pop();
    }
    Ok(())
}

fn exact_optional_features(
    specification: &toml::Table,
    expected: &[&str],
    owner: &str,
) -> Result<(), String> {
    match specification.get("features") {
        Some(features) => exact_string_array(features, expected, &format!("{owner} features")),
        None if expected.is_empty() => Ok(()),
        None => Err(format!("{owner} is missing explicit features {expected:?}")),
    }
}

fn exact_string_array(value: &Value, expected: &[&str], owner: &str) -> Result<(), String> {
    let values = value
        .as_array()
        .ok_or_else(|| format!("{owner} must be an array"))?;
    let mut actual = BTreeSet::new();
    for value in values {
        let member = value
            .as_str()
            .ok_or_else(|| format!("{owner} members must be strings"))?;
        if !actual.insert(member) {
            return Err(format!("{owner} contains duplicate member {member}"));
        }
    }
    let expected: BTreeSet<_> = expected.iter().copied().collect();
    if actual != expected {
        return Err(format!(
            "{owner} changed: expected {expected:?}, got {actual:?}"
        ));
    }
    Ok(())
}

#[test]
fn hosted_feature_topology_is_fail_closed() {
    FeatureTopology::load()
        .validate()
        .expect("hosted feature topology");
}

#[test]
fn hosted_resolved_feature_graph_excludes_live_backend() {
    let root = workspace_root();
    for target in ["x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"] {
        let output = Command::new(env!("CARGO"))
            .current_dir(&root)
            .args([
                "metadata",
                "--manifest-path",
                "crates/ferrum2-tun/fuzz/Cargo.toml",
                "--no-default-features",
                "--locked",
                "--filter-platform",
                target,
                "--format-version",
                "1",
            ])
            .output()
            .expect("hosted cargo metadata must start");
        assert!(
            output.status.success(),
            "hosted cargo metadata failed for {target}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let metadata: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("structured cargo metadata");
        for package_name in ["ferrum2-tun", "ferrum2-platform-windows"] {
            let package = metadata["packages"]
                .as_array()
                .expect("metadata packages")
                .iter()
                .find(|package| package["name"] == package_name)
                .unwrap_or_else(|| panic!("missing {package_name} package for {target}"));
            let node = metadata["resolve"]["nodes"]
                .as_array()
                .expect("metadata resolve nodes")
                .iter()
                .find(|node| node["id"] == package["id"])
                .unwrap_or_else(|| panic!("missing {package_name} node for {target}"));
            let features: BTreeSet<_> = node["features"]
                .as_array()
                .expect("resolved package features")
                .iter()
                .map(|feature| feature.as_str().expect("resolved feature"))
                .collect();
            assert_eq!(
                features,
                BTreeSet::from(["fuzzing"]),
                "{package_name} hosted features changed for {target}"
            );
        }
    }
}

#[test]
fn hosted_feature_topology_mutations_fail_closed() {
    let baseline = FeatureTopology::load();
    let mutations: Vec<TopologyMutation> = vec![
        (
            "workspace platform defaults",
            Box::new(|topology| {
                topology.workspace["workspace"]["dependencies"]["ferrum2-platform-windows"]["default-features"] =
                    Value::Boolean(true);
            }),
        ),
        (
            "workspace TUN defaults",
            Box::new(|topology| {
                topology.workspace["workspace"]["dependencies"]["ferrum2-tun"]["default-features"] =
                    Value::Boolean(true);
            }),
        ),
        (
            "platform default omits live",
            Box::new(|topology| {
                topology.platform["features"]["default"] = Value::Array(Vec::new());
            }),
        ),
        (
            "TUN forwarding disappears",
            Box::new(|topology| {
                topology.tun["features"]["live-backend"] = Value::Array(Vec::new());
            }),
        ),
        (
            "TUN platform defaults",
            Box::new(|topology| {
                topology.tun["dependencies"]["ferrum2-platform-windows"]["default-features"] =
                    Value::Boolean(true);
            }),
        ),
        (
            "TUN dev dependency enables platform live",
            Box::new(|topology| {
                insert_dependency(
                    &mut topology.tun,
                    "dev-dependencies",
                    "ferrum2-platform-windows",
                    &["live-backend"],
                );
            }),
        ),
        (
            "fuzz enables platform live",
            Box::new(|topology| {
                topology.fuzz["dependencies"]["ferrum2-platform-windows"]["features"] =
                    Value::Array(vec![Value::String("live-backend".to_owned())]);
            }),
        ),
        (
            "fuzz enables TUN defaults",
            Box::new(|topology| {
                topology.fuzz["dependencies"]["ferrum2-tun"]["default-features"] =
                    Value::Boolean(true);
            }),
        ),
        (
            "fuzz target dependency enables platform live",
            Box::new(|topology| {
                let root = topology.fuzz.as_table_mut().expect("fuzz manifest table");
                let target = root
                    .entry("target")
                    .or_insert_with(|| Value::Table(toml::Table::new()))
                    .as_table_mut()
                    .expect("target table");
                let windows = target
                    .entry("cfg(windows)")
                    .or_insert_with(|| Value::Table(toml::Table::new()));
                insert_dependency(windows, "dependencies", "platform_live", &["live-backend"]);
                windows["dependencies"]["platform_live"]
                    .as_table_mut()
                    .expect("renamed dependency specification")
                    .insert(
                        "package".to_owned(),
                        Value::String("ferrum2-platform-windows".to_owned()),
                    );
            }),
        ),
        (
            "client omits TUN live",
            Box::new(|topology| {
                topology.client["dependencies"]["ferrum2-tun"] = Value::Boolean(true);
            }),
        ),
        (
            "server omits platform live",
            Box::new(|topology| {
                topology.server["dependencies"]["ferrum2-platform-windows"]["features"] =
                    Value::Array(Vec::new());
            }),
        ),
    ];

    for (name, mutate) in mutations {
        let mut topology = baseline.clone();
        mutate(&mut topology);
        assert!(
            topology.validate().is_err(),
            "feature-topology mutation passed: {name}"
        );
    }
}

fn insert_dependency(manifest: &mut Value, table_name: &str, dependency: &str, features: &[&str]) {
    let root = manifest.as_table_mut().expect("manifest table");
    let dependencies = root
        .entry(table_name)
        .or_insert_with(|| Value::Table(toml::Table::new()))
        .as_table_mut()
        .expect("dependency table");
    let mut specification = toml::Table::new();
    specification.insert("workspace".to_owned(), Value::Boolean(true));
    specification.insert(
        "features".to_owned(),
        Value::Array(
            features
                .iter()
                .map(|feature| Value::String((*feature).to_owned()))
                .collect(),
        ),
    );
    dependencies.insert(dependency.to_owned(), Value::Table(specification));
}
