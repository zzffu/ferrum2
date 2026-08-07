use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const CURRENT_COMPATIBILITY_MEMBERS: [&str; 10] = [
    "bins/ferrum2-client",
    "bins/ferrum2-server",
    "crates/ferrum2-config",
    "crates/ferrum2-core",
    "crates/ferrum2-crypto",
    "crates/ferrum2-observability",
    "crates/ferrum2-runtime",
    "crates/ferrum2-shadowsocks",
    "crates/ferrum2-socks5",
    "tests/m0-harness",
];

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
    serde_json::from_slice(&output.stdout).expect("cargo metadata must emit JSON")
}

fn package_names_by_id(metadata: &Value) -> BTreeMap<String, String> {
    metadata["packages"]
        .as_array()
        .expect("packages array")
        .iter()
        .map(|package| {
            (
                package["id"].as_str().expect("package id").to_owned(),
                package["name"].as_str().expect("package name").to_owned(),
            )
        })
        .collect()
}

fn contains_explicit_target_declaration(manifest: &str, declaration: &str) -> bool {
    manifest.replace("\r\n", "\n").contains(declaration)
}

fn rust_sources(directory: &Path) -> Vec<PathBuf> {
    let mut pending = vec![directory.to_path_buf()];
    let mut sources = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).expect("source directory") {
            let path = entry.expect("source entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                sources.push(path);
            }
        }
    }
    sources.sort();
    sources
}

fn rust_tokens(source: &str) -> Vec<String> {
    fn raw_string_end(bytes: &[u8], start: usize) -> Option<usize> {
        let mut cursor = start;
        if bytes.get(cursor) == Some(&b'b') {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'r') {
            return None;
        }
        cursor += 1;
        let hashes = bytes[cursor..]
            .iter()
            .take_while(|byte| **byte == b'#')
            .count();
        cursor += hashes;
        if bytes.get(cursor) != Some(&b'"') {
            return None;
        }
        cursor += 1;
        while cursor < bytes.len() {
            if bytes[cursor] == b'"'
                && bytes
                    .get(cursor + 1..cursor + 1 + hashes)
                    .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
            {
                return Some(cursor + 1 + hashes);
            }
            cursor += 1;
        }
        Some(bytes.len())
    }

    fn quoted_end(bytes: &[u8], quote: usize) -> usize {
        let mut cursor = quote + 1;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'\\' => cursor = (cursor + 2).min(bytes.len()),
                b'"' => return cursor + 1,
                _ => cursor += 1,
            }
        }
        bytes.len()
    }

    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes.get(cursor..cursor + 2) == Some(b"//") {
            cursor += 2;
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor += 1;
            }
            continue;
        }
        if bytes.get(cursor..cursor + 2) == Some(b"/*") {
            cursor += 2;
            let mut depth = 1;
            while cursor < bytes.len() && depth > 0 {
                if bytes.get(cursor..cursor + 2) == Some(b"/*") {
                    depth += 1;
                    cursor += 2;
                } else if bytes.get(cursor..cursor + 2) == Some(b"*/") {
                    depth -= 1;
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            continue;
        }
        if matches!(bytes[cursor], b'r' | b'b')
            && let Some(end) = raw_string_end(bytes, cursor)
        {
            cursor = end;
            continue;
        }
        if bytes[cursor] == b'"' {
            cursor = quoted_end(bytes, cursor);
            continue;
        }
        if bytes.get(cursor..cursor + 2) == Some(b"b\"") {
            cursor = quoted_end(bytes, cursor + 1);
            continue;
        }
        if bytes[cursor] == b'\''
            && (bytes.get(cursor + 2) == Some(&b'\'') || bytes.get(cursor + 1) == Some(&b'\\'))
        {
            cursor += 1;
            while cursor < bytes.len() {
                if bytes[cursor] == b'\\' {
                    cursor = (cursor + 2).min(bytes.len());
                } else if bytes[cursor] == b'\'' {
                    cursor += 1;
                    break;
                } else {
                    cursor += 1;
                }
            }
            continue;
        }
        if bytes.get(cursor..cursor + 2) == Some(b"b'") {
            cursor += 2;
            while cursor < bytes.len() {
                if bytes[cursor] == b'\\' {
                    cursor = (cursor + 2).min(bytes.len());
                } else if bytes[cursor] == b'\'' {
                    cursor += 1;
                    break;
                } else {
                    cursor += 1;
                }
            }
            continue;
        }
        if bytes[cursor].is_ascii_alphabetic() || bytes[cursor] == b'_' {
            let start = cursor;
            cursor += 1;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
            {
                cursor += 1;
            }
            tokens.push(source[start..cursor].to_owned());
            continue;
        }
        if bytes[cursor].is_ascii_digit() {
            let start = cursor;
            cursor += 1;
            while cursor < bytes.len() && bytes[cursor].is_ascii_alphanumeric() {
                cursor += 1;
            }
            tokens.push(source[start..cursor].to_owned());
            continue;
        }
        if !bytes[cursor].is_ascii_whitespace() {
            tokens.push((bytes[cursor] as char).to_string());
        }
        cursor += 1;
    }
    tokens
}

fn has_tokens(tokens: &[String], expected: &[&str]) -> bool {
    tokens.windows(expected.len()).any(|window| {
        window
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
    })
}

struct TokenSource {
    path: String,
    tokens: Vec<String>,
}

impl TokenSource {
    fn new(path: impl Into<String>, source: &str) -> Self {
        Self {
            path: path.into(),
            tokens: rust_tokens(source),
        }
    }

    fn production_tokens(&self) -> &[String] {
        let test_module = (0..self.tokens.len().saturating_sub(7)).find(|&index| {
            has_tokens(
                &self.tokens[index..index + 7],
                &["#", "[", "cfg", "(", "test", ")", "]"],
            ) && self.tokens[index + 7..]
                .iter()
                .take_while(|token| token.as_str() != "{")
                .any(|token| token == "mod")
        });
        &self.tokens[..test_module.unwrap_or(self.tokens.len())]
    }
}

fn token_sources(root: &Path, paths: &[&str]) -> Vec<TokenSource> {
    paths
        .iter()
        .map(|path| {
            TokenSource::new(
                *path,
                &fs::read_to_string(root.join(path)).expect("token source"),
            )
        })
        .collect()
}

fn token_sources_under(root: &Path, directories: &[&str]) -> Vec<TokenSource> {
    let mut sources = Vec::new();
    for directory in directories {
        for path in rust_sources(&root.join(directory)) {
            let relative = path
                .strip_prefix(root)
                .expect("product source under workspace")
                .to_string_lossy()
                .replace('\\', "/");
            sources.push(TokenSource::new(
                relative,
                &fs::read_to_string(path).expect("product source"),
            ));
        }
    }
    sources
}

type DefinitionRule = (&'static str, &'static str, &'static str);

fn ownership_scope(owner: &str) -> &str {
    owner.find("src/").map_or_else(
        || owner.rsplit_once('/').map_or("", |(scope, _)| scope),
        |end| &owner[..end + 4],
    )
}

fn check_definition_ownership(
    sources: &[TokenSource],
    rules: &[DefinitionRule],
    roots: &[&str],
) -> Result<(), String> {
    for &(keyword, name, owner) in rules {
        let scope = ownership_scope(owner);
        let locations: Vec<_> = sources
            .iter()
            .filter(|source| {
                source.path.starts_with(scope) && has_tokens(&source.tokens, &[keyword, name])
            })
            .map(|source| source.path.as_str())
            .collect();
        if locations != [owner] {
            return Err(format!(
                "{keyword} {name} must have one owner {owner}, found {locations:?}"
            ));
        }
        if locations.iter().any(|location| roots.contains(location)) {
            return Err(format!("composition root restores {keyword} {name}"));
        }
    }
    Ok(())
}

fn check_no_identifiers<'a>(
    sources: impl IntoIterator<Item = &'a TokenSource>,
    forbidden: &[&str],
) -> Result<(), String> {
    for source in sources {
        if let Some(identifier) = source
            .production_tokens()
            .iter()
            .find(|token| forbidden.contains(&token.as_str()))
        {
            return Err(format!("{} contains forbidden {identifier}", source.path));
        }
    }
    Ok(())
}

fn check_no_sequences<'a>(
    sources: impl IntoIterator<Item = &'a TokenSource>,
    forbidden: &[&[&str]],
) -> Result<(), String> {
    for source in sources {
        if let Some(sequence) = forbidden
            .iter()
            .find(|sequence| has_tokens(source.production_tokens(), sequence))
        {
            return Err(format!("{} contains forbidden {sequence:?}", source.path));
        }
    }
    Ok(())
}

fn check_no_glob_facades(
    sources: &[TokenSource],
    owners: &[&str],
    roots: &[(&str, &[&str])],
) -> Result<(), String> {
    for owner in owners {
        let source = sources
            .iter()
            .find(|source| source.path == *owner)
            .ok_or_else(|| format!("missing owner {owner}"))?;
        if has_tokens(source.production_tokens(), &["use", "super", ":", ":", "*"]) {
            return Err(format!("production owner remains a glob facade: {owner}"));
        }
    }
    for (root, children) in roots {
        let source = sources
            .iter()
            .find(|source| source.path == *root)
            .ok_or_else(|| format!("missing composition root {root}"))?;
        for child in *children {
            if has_tokens(source.production_tokens(), &["use", child, ":", ":", "*"]) {
                return Err(format!("composition root glob-imports {child}: {root}"));
            }
        }
    }
    Ok(())
}

fn restricted_items(tokens: &[String]) -> BTreeSet<String> {
    let mut items = BTreeSet::new();
    for (index, window) in tokens.windows(4).enumerate() {
        if window[0] != "pub"
            || window[1] != "("
            || !matches!(window[2].as_str(), "super" | "crate")
            || window[3] != ")"
        {
            continue;
        }
        let declaration = tokens[index + 4..]
            .iter()
            .take_while(|token| !matches!(token.as_str(), "," | ";" | "{" | "}"));
        let declaration: Vec<_> = declaration.map(String::as_str).collect();
        for keyword in ["struct", "enum", "fn", "trait", "type", "const"] {
            if let Some(keyword) = declaration.iter().position(|token| *token == keyword) {
                if let Some(name) = declaration.get(keyword + 1) {
                    items.insert((*name).to_owned());
                }
                break;
            }
        }
    }
    items
}

fn check_restricted_interfaces(
    sources: &[TokenSource],
    expected: &[(&str, &[&str])],
) -> Result<(), String> {
    for (path, names) in expected {
        let source = sources
            .iter()
            .find(|source| source.path == *path)
            .ok_or_else(|| format!("missing interface owner {path}"))?;
        let actual = restricted_items(source.production_tokens());
        let expected: BTreeSet<_> = names.iter().map(|name| (*name).to_owned()).collect();
        if actual != expected {
            return Err(format!(
                "restricted interface mismatch for {path}: expected {expected:?}, found {actual:?}"
            ));
        }
    }
    Ok(())
}

fn check_test_placement(
    sources: &[TokenSource],
    rules: &[DefinitionRule],
    composition_tests: &[&str],
    support_modules: &[&str],
) -> Result<(), String> {
    check_definition_ownership(sources, rules, composition_tests)?;
    for source in sources {
        let imports_composition_tests = has_tokens(
            &source.tokens,
            &["crate", ":", ":", "run", ":", ":", "tests"],
        );
        if imports_composition_tests && !composition_tests.contains(&source.path.as_str()) {
            return Err(format!(
                "owner tests import composition tests: {}",
                source.path
            ));
        }
        let imports_owner_tests = source
            .tokens
            .windows(3)
            .any(|window| window[0] == "tests" && window[1] == ":" && window[2] == ":");
        if composition_tests.contains(&source.path.as_str()) && imports_owner_tests {
            return Err(format!(
                "composition tests import owner test module: {}",
                source.path
            ));
        }
        if support_modules.contains(&source.path.as_str()) && imports_owner_tests {
            return Err(format!("test support imports owner tests: {}", source.path));
        }
    }
    Ok(())
}

#[test]
fn workspace_contains_current_compatibility_members_without_exhausting_future_topology() {
    let metadata = metadata();
    let root = PathBuf::from(metadata["workspace_root"].as_str().expect("workspace root"));
    let actual: BTreeSet<_> = metadata["workspace_members"]
        .as_array()
        .expect("workspace members")
        .iter()
        .map(|id| {
            let id = id.as_str().expect("workspace member id");
            let package = metadata["packages"]
                .as_array()
                .expect("packages")
                .iter()
                .find(|package| package["id"].as_str() == Some(id))
                .expect("workspace member package");
            let manifest = PathBuf::from(package["manifest_path"].as_str().expect("manifest path"));
            manifest
                .parent()
                .expect("manifest parent")
                .strip_prefix(&root)
                .expect("member under workspace")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();

    for required in CURRENT_COMPATIBILITY_MEMBERS {
        assert!(
            actual.contains(required),
            "current compatibility member is missing: {required}"
        );
    }
}

#[test]
fn current_deep_modules_keep_one_way_internal_dependencies() {
    let exposes_standalone_plan_snapshot = |source: &str| {
        source.split(';').any(|statement| {
            let mut tokens = statement
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .filter(|token| !token.is_empty());
            let mut saw_public = false;
            tokens.any(|token| {
                saw_public |= token == "pub";
                saw_public && token == "PlanSnapshot"
            })
        })
    };
    for mutation in [
        "pub use runtime_provider::{SystemDnsEgress, PlanSnapshot, DnsTcpIo};",
        "#[derive(Clone)]\npub struct PlanSnapshot(std::sync::Arc<[usize]>);",
    ] {
        assert!(exposes_standalone_plan_snapshot(mutation));
    }
    assert!(!exposes_standalone_plan_snapshot(
        "pub use ferrum2_core::route::EgressPlanSnapshot;"
    ));

    let metadata = metadata();
    let names = package_names_by_id(&metadata);
    let workspace_ids: BTreeSet<_> = metadata["workspace_members"]
        .as_array()
        .expect("workspace members")
        .iter()
        .map(|id| id.as_str().expect("member id").to_owned())
        .collect();
    let allowed: BTreeMap<&str, BTreeSet<&str>> = [
        (
            "ferrum2-config",
            BTreeSet::from(["ferrum2-core", "ferrum2-crypto"]),
        ),
        ("ferrum2-core", BTreeSet::new()),
        ("ferrum2-crypto", BTreeSet::new()),
        ("ferrum2-dns", BTreeSet::from(["ferrum2-core"])),
        ("ferrum2-observability", BTreeSet::new()),
        ("ferrum2-runtime", BTreeSet::from(["ferrum2-core"])),
        (
            "ferrum2-shadowsocks",
            BTreeSet::from(["ferrum2-core", "ferrum2-crypto"]),
        ),
        ("ferrum2-socks5", BTreeSet::from(["ferrum2-core"])),
    ]
    .into_iter()
    .collect();
    let workspace_names: BTreeSet<_> = workspace_ids
        .iter()
        .map(|id| names.get(id).expect("workspace package name").as_str())
        .collect();

    for package in metadata["packages"].as_array().expect("packages") {
        let package_id = package["id"].as_str().expect("package id");
        if !workspace_ids.contains(package_id) {
            continue;
        }
        let package_name = names.get(package_id).expect("package name");
        let actual: BTreeSet<_> = package["dependencies"]
            .as_array()
            .expect("dependencies")
            .iter()
            .filter_map(|dependency| {
                let dependency_name = dependency["name"].as_str().expect("dependency name");
                workspace_names
                    .contains(dependency_name)
                    .then_some(dependency_name)
            })
            .collect();
        assert!(
            actual.is_disjoint(&BTreeSet::from(["ferrum2-client", "ferrum2-server"])),
            "internal package must not depend on a composition root: {package_name}"
        );
        if let Some(permitted) = allowed.get(package_name.as_str()) {
            assert!(
                actual.is_subset(permitted),
                "deep module has an upward or cross-layer dependency: {package_name}"
            );
        }
    }

    let root = workspace_root();
    for path in rust_sources(&root.join("crates/ferrum2-dns/src")) {
        let source = fs::read_to_string(&path).expect("DNS source");
        for forbidden in ["ferrum2_config", "DnsServerConfig", "DnsTransport"] {
            assert!(
                !source.contains(forbidden),
                "DNS runtime source imports config ownership: {} contains {forbidden}",
                path.display()
            );
        }
        assert!(
            !exposes_standalone_plan_snapshot(&source),
            "DNS source exposes a standalone PlanSnapshot: {}",
            path.display()
        );
    }
    let public =
        fs::read_to_string(root.join("crates/ferrum2-dns/src/lib.rs")).expect("DNS public module");
    assert!(public.contains("DnsUpstreamSpec"));
}

#[test]
fn core_is_runtime_and_protocol_neutral() {
    let metadata = metadata();
    let core = metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|package| package["name"] == "ferrum2-core")
        .expect("core package");
    let dependencies: BTreeSet<_> = core["dependencies"]
        .as_array()
        .expect("dependencies")
        .iter()
        .map(|dependency| dependency["name"].as_str().expect("dependency name"))
        .collect();

    assert_eq!(dependencies, BTreeSet::from(["bytes"]));
}

#[test]
fn core_source_preserves_endpoint_ownership_without_freezing_address_family() {
    let source = fs::read_to_string(workspace_root().join("crates/ferrum2-core/src/lib.rs"))
        .expect("core source");

    for required in [
        "type Stream: LocalEndpoint;",
        "fn local_socket_addr(&self) -> SocketAddr",
        "fn succeeded_socket(",
        "bound: SocketAddr",
    ] {
        assert!(
            source.contains(required),
            "core contract must contain `{required}`"
        );
    }
}

#[test]
fn crypto_profiles_keep_cipher_dispatch_inside_one_deep_module() {
    let root = workspace_root();
    let metadata = metadata();
    let crypto =
        fs::read_to_string(root.join("crates/ferrum2-crypto/src/lib.rs")).expect("crypto source");
    for required in [
        "pub enum MethodProfile",
        "pub type TcpMethodProfile = MethodProfile",
        "pub struct MethodPsk",
        "pub trait MethodKeyProvider",
        "ShadowsocksTcpCipher::try_new",
        "ShadowsocksTcpCipher::try_from_subkey",
        "pub struct TcpSealer",
        "pub struct TcpOpener",
        "enum UdpCryptoInner",
        "ShadowsocksUdpCipher::try_new",
        "ShadowsocksAesHeaderCipher::try_new",
        "pub struct UdpCrypto",
        "pub struct UdpSessionId",
        "pub struct UdpOutboundSession",
        "outbound: &mut UdpOutboundSession",
    ] {
        assert!(
            crypto.contains(required),
            "crypto deep module must contain `{required}`"
        );
    }
    for separable_udp_state in [
        "pub struct UdpPacketCounter",
        "pub fn generate_udp_session_id",
        "pub fn generate_distinct_udp_session_id",
    ] {
        assert!(
            !crypto.contains(separable_udp_state),
            "outbound UDP identity and packet lineage must remain inseparable: {separable_udp_state}"
        );
    }
    for duplicated_owner in [
        "Aes256TcpSealer",
        "Aes256TcpOpener",
        "ChaChaTcpSealer",
        "ChaChaTcpOpener",
        "Aes128UdpCrypto",
        "Aes256UdpCrypto",
        "ChaChaUdpCrypto",
    ] {
        assert!(
            !crypto.contains(duplicated_owner),
            "method-specific public flow owner is forbidden: {duplicated_owner}"
        );
    }
    for replaced_implementation in [
        "enum TcpCipher",
        "enum AesUdpBodyCipher",
        "fn cipher_from_subkey",
        "fn derive_subkey_16",
        "fn derive_subkey_32",
        "fn derive_udp_subkey_16",
        "fn derive_udp_subkey_32",
        "SIP022_KDF_CONTEXT",
        "Aes128Gcm::new_from_slice",
        "Aes256Gcm::new_from_slice",
        "XChaCha20Poly1305::new_from_slice",
    ] {
        assert!(
            !crypto.contains(replaced_implementation),
            "replaced local crypto implementation is forbidden: {replaced_implementation}"
        );
    }

    let workspace_ids: BTreeSet<_> = metadata["workspace_members"]
        .as_array()
        .expect("workspace members")
        .iter()
        .map(|id| id.as_str().expect("workspace member id"))
        .collect();
    for package in metadata["packages"].as_array().expect("packages") {
        let package_id = package["id"].as_str().expect("package id");
        if !workspace_ids.contains(package_id) || package["name"] == "ferrum2-crypto" {
            continue;
        }
        let manifest_path = package["manifest_path"].as_str().expect("manifest path");
        let manifest = fs::read_to_string(manifest_path).expect("member manifest");
        assert!(
            !manifest.contains("chacha20poly1305"),
            "ChaCha primitive dependency must stay inside ferrum2-crypto: {}",
            package["name"]
        );
    }
}

#[test]
fn current_product_targets_are_explicit_without_exhausting_future_targets() {
    let root = workspace_root();
    for (manifest, declaration) in [
        (
            "bins/ferrum2-client/Cargo.toml",
            "[[bin]]\nname = \"ferrum2-client\"\npath = \"src/main.rs\"",
        ),
        (
            "bins/ferrum2-server/Cargo.toml",
            "[[bin]]\nname = \"ferrum2-server\"\npath = \"src/main.rs\"",
        ),
        (
            "crates/ferrum2-crypto/Cargo.toml",
            "[lib]\npath = \"src/lib.rs\"",
        ),
        (
            "crates/ferrum2-shadowsocks/Cargo.toml",
            "[lib]\npath = \"src/lib.rs\"",
        ),
        (
            "crates/ferrum2-socks5/Cargo.toml",
            "[lib]\npath = \"src/lib.rs\"",
        ),
        (
            "crates/ferrum2-runtime/Cargo.toml",
            "[lib]\npath = \"src/lib.rs\"",
        ),
        (
            "crates/ferrum2-config/Cargo.toml",
            "[lib]\npath = \"src/lib.rs\"",
        ),
        (
            "crates/ferrum2-observability/Cargo.toml",
            "[lib]\npath = \"src/lib.rs\"",
        ),
    ] {
        let contents = fs::read_to_string(root.join(manifest)).expect("member manifest");
        assert!(
            contains_explicit_target_declaration(&contents, declaration),
            "{manifest} must explicitly declare `{declaration}`"
        );
    }
}

#[test]
fn current_target_declaration_matching_accepts_crlf() {
    let manifest = "[[bin]]\r\nname = \"ferrum2-client\"\r\npath = \"src/main.rs\"\r\n";
    let declaration = "[[bin]]\nname = \"ferrum2-client\"\npath = \"src/main.rs\"";

    assert!(contains_explicit_target_declaration(manifest, declaration));
}

#[test]
fn tagged_composition_stays_out_of_core_and_protocol_modules() {
    let root = workspace_root();
    let core = fs::read_to_string(root.join("crates/ferrum2-core/src/lib.rs")).expect("core");
    assert_eq!(core.matches("pub mod route").count(), 1);
    let native = fs::read_to_string(root.join("tests/platform/qualify_native.py")).expect("native");
    for required in "def bounded_accept(|listener.settimeout(timeout)|peer.settimeout(timeout)|except (TimeoutError, OSError)|bounded_accept(tcp, 9)".split('|') {
        assert!(native.contains(required), "native lacks {required}");
    }
    for (members, forbidden) in [
        (
            "crates/ferrum2-shadowsocks,crates/ferrum2-socks5,crates/ferrum2-runtime",
            "RouteRule,RouteTable,route::,pub trait Route",
        ),
        (
            "crates/ferrum2-core,crates/ferrum2-shadowsocks,crates/ferrum2-socks5",
            "pub trait Endpoint,RouteFactory,RouteRegistry,AdapterRegistry,ServiceRegistry,adapter_registry,endpoint_registry",
        ),
    ] {
        for member in members.split(',') {
            let sources = rust_sources(&root.join(member));
            assert!(!sources.is_empty(), "{member} has no sources");
            for path in sources {
                let source = fs::read_to_string(&path).expect("source");
                assert!(
                    forbidden.split(',').all(|item| !source.contains(item)),
                    "{} violates architecture",
                    path.display()
                );
            }
        }
    }
    for member in "bins/ferrum2-client,bins/ferrum2-server,crates/ferrum2-observability".split(',')
    {
        for path in rust_sources(&root.join(member)) {
            let source = fs::read_to_string(path).expect("observable source");
            assert!(
                "tag,target,destination,route"
                    .split(',')
                    .all(|field| !source.contains(&format!("{field} = %"))
                        && !source.contains(&format!("{field} = ?"))),
                "{member} exposes route identity"
            );
        }
    }
    for member in "crates/ferrum2-core,crates/ferrum2-shadowsocks,crates/ferrum2-socks5".split(',')
    {
        let manifest =
            fs::read_to_string(root.join(member).join("Cargo.toml")).expect("deep-module manifest");
        for forbidden in ["ferrum2-config", "ferrum2-runtime"] {
            assert!(
                !manifest.contains(forbidden),
                "{member} must not depend on {forbidden}"
            );
        }
    }
}

#[test]
fn recursive_rust_source_discovery_excludes_non_rust_files() {
    let directory = tempfile::tempdir().expect("source discovery tempdir");
    let nested = directory.path().join("nested");
    fs::create_dir(&nested).expect("nested source directory");
    fs::write(directory.path().join("root.rs"), "root").expect("root source");
    fs::write(nested.join("nested.rs"), "nested").expect("nested source");
    fs::write(nested.join("ignored.txt"), "ignored").expect("non-source");

    let sources = rust_sources(directory.path());
    assert_eq!(sources.len(), 2);
    assert!(sources.iter().any(|path| path.ends_with("nested.rs")));
    assert!(sources.iter().any(|path| path.ends_with("root.rs")));
}

#[test]
fn lexical_ownership_scanner_rejects_decoys_and_owner_mutations() {
    let definition = ("struct", "Owned", "sample/owner.rs");
    let reformatted = [TokenSource::new(
        "sample/owner.rs",
        "pub\nstruct\nOwned; // pub struct CommentDecoy\n\
         const TEXT: &str = \"pub struct StringDecoy\";",
    )];
    assert!(
        check_definition_ownership(&reformatted, &[definition], &["sample/root.rs"]).is_ok(),
        "whitespace and comment/string decoys must preserve the real owner"
    );
    for (mutation, sources) in [
        (
            "duplicate",
            vec![
                TokenSource::new("sample/owner.rs", "struct Owned;"),
                TokenSource::new("sample/duplicate.rs", "struct Owned;"),
            ],
        ),
        (
            "wrong owner/move",
            vec![TokenSource::new("sample/wrong.rs", "struct Owned;")],
        ),
        (
            "root restoration",
            vec![TokenSource::new("sample/root.rs", "struct Owned;")],
        ),
    ] {
        assert!(
            check_definition_ownership(&sources, &[definition], &["sample/root.rs"]).is_err(),
            "ownership checker accepted {mutation}"
        );
    }

    let globbed = [TokenSource::new("sample/owner.rs", "use super :: *;")];
    assert!(
        check_no_glob_facades(&globbed, &["sample/owner.rs"], &[]).is_err(),
        "ownership checker accepted a glob facade"
    );

    let test_rule = ("fn", "owned_case", "sample/owner.rs");
    let wrong_test_owner = [TokenSource::new(
        "sample/tests.rs",
        "#[test] fn owned_case() {}",
    )];
    assert!(
        check_test_placement(&wrong_test_owner, &[test_rule], &["sample/tests.rs"], &[]).is_err(),
        "test placement checker accepted the wrong owner"
    );
    let cycle = [
        TokenSource::new(
            "sample/owner.rs",
            "use crate::run::tests::fixture; #[test] fn owned_case() {}",
        ),
        TokenSource::new("sample/tests.rs", ""),
    ];
    assert!(
        check_test_placement(&cycle, &[test_rule], &["sample/tests.rs"], &[]).is_err(),
        "test placement checker accepted an owner/composition cycle"
    );
}

#[test]
fn production_owner_dependencies_are_explicit_and_narrow() {
    let root = workspace_root();
    let owners = [
        "bins/ferrum2-client/src/run/context.rs",
        "bins/ferrum2-client/src/run/dns.rs",
        "bins/ferrum2-client/src/run/io.rs",
        "bins/ferrum2-client/src/run/observation.rs",
        "bins/ferrum2-client/src/run/socks.rs",
        "bins/ferrum2-server/src/run/dns.rs",
        "bins/ferrum2-server/src/run/io.rs",
        "bins/ferrum2-server/src/run/observation.rs",
        "bins/ferrum2-server/src/run/tcp.rs",
        "bins/ferrum2-server/src/run/udp.rs",
        "crates/ferrum2-config/src/error.rs",
        "crates/ferrum2-config/src/load.rs",
        "crates/ferrum2-config/src/model.rs",
        "crates/ferrum2-config/src/raw.rs",
        "crates/ferrum2-config/src/validation.rs",
    ];
    let roots = [
        "bins/ferrum2-client/src/run.rs",
        "bins/ferrum2-server/src/run.rs",
    ];
    let mut paths = owners.to_vec();
    paths.extend(roots);
    let sources = token_sources(&root, &paths);
    check_no_glob_facades(
        &sources,
        &owners,
        &[
            (
                roots[0],
                &["context", "dns", "observation", "socks", "tokio_io"][..],
            ),
            (
                roots[1],
                &["dns", "observation", "tcp", "tokio_io", "udp"][..],
            ),
        ],
    )
    .unwrap_or_else(|error| panic!("{error}"));

    check_restricted_interfaces(
        &sources,
        &[
            (owners[0], &["ClientContext", "ClientRouting"]),
            (owners[1], &["ClientDnsRoot"]),
            (
                owners[2],
                &[
                    "TokioConnector",
                    "TokioFramed",
                    "TokioTransport",
                    "bind_listener",
                    "new",
                    "shutdown_signal",
                    "terminal",
                ],
            ),
            (
                owners[3],
                &[
                    "ClientMetricsRoot",
                    "UdpPacketPhase",
                    "finish_relay",
                    "log_level",
                    "observation_for_error",
                    "record_failure",
                    "record_forced_udp_sessions",
                    "record_udp_drop",
                    "record_udp_packet_error",
                    "record_udp_runtime_error",
                    "record_udp_terminal",
                    "run_error_for_supervisor",
                ],
            ),
            (owners[4], &["ClientTcpListeners", "ClientTcpRoot"]),
            (owners[5], &["ServerDnsRoot"]),
            (
                owners[6],
                &[
                    "TokioFramed",
                    "TokioTransport",
                    "bind_listener",
                    "new",
                    "shutdown_signal",
                    "terminal",
                ],
            ),
            (
                owners[7],
                &[
                    "ServerMetricsRoot",
                    "finish_relay",
                    "log_level",
                    "observation_for_direct_connect",
                    "observation_for_error",
                    "record_failure",
                    "record_udp_failure",
                    "record_udp_protocol_failure",
                    "record_udp_request_accepted",
                    "record_udp_runtime_failure",
                    "run_error_for_supervisor",
                    "update_replay_metric",
                    "update_udp_resource_metrics",
                ],
            ),
            (
                owners[8],
                &[
                    "ServerContext",
                    "ServerRouting",
                    "ServerTcpListeners",
                    "ServerTcpRoot",
                ],
            ),
            (
                owners[9],
                &[
                    "PreparedUdpServer",
                    "ServerUdpListener",
                    "ServerUdpShared",
                    "UdpMappings",
                    "new",
                    "prepare_udp_server",
                    "udp_runtime_limits",
                ],
            ),
            (owners[10], &["new", "semantic"]),
            (owners[11], &[]),
            (owners[12], &[]),
            (
                owners[13],
                &[
                    "RawChain",
                    "RawClient",
                    "RawClientInbound",
                    "RawClientOutbound",
                    "RawClientRoot",
                    "RawDns",
                    "RawDnsInbound",
                    "RawDnsRoute",
                    "RawDnsRouteRule",
                    "RawDnsServer",
                    "RawLogging",
                    "RawMetrics",
                    "RawReplay",
                    "RawRoute",
                    "RawRouteRule",
                    "RawRouteTarget",
                    "RawRuntime",
                    "RawSelector",
                    "RawServer",
                    "RawServerInbound",
                    "RawServerOutbound",
                    "RawServerRoot",
                    "RawShadowsocks",
                    "RawUdp",
                    "SecretString",
                    "as_str",
                ],
            ),
            (owners[14], &["validate_client", "validate_server"]),
        ],
    )
    .unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn owner_specific_tests_leave_composition_roots_and_form_no_cycles() {
    let root = workspace_root();
    let sources = token_sources_under(
        &root,
        &["bins/ferrum2-client/src", "bins/ferrum2-server/src"],
    );
    let rules = [
        (
            "fn",
            "phase_deadline_contract_table_preserves_defaults_overrides_and_first_write",
            "bins/ferrum2-client/src/run/egress/tcp.rs",
        ),
        (
            "fn",
            "routed_tcp_selects_after_target_and_never_falls_back",
            "bins/ferrum2-client/src/run/egress/tcp.rs",
        ),
        (
            "fn",
            "udp_send_lifecycle_covers_socket_io_session_idle_and_process_cancel",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "routed_udp_uses_lazy_endpoint_legs_and_rejects_cross_leg_responses",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "concrete_udp_socket_faults_release_every_owner_and_endpoint",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "composed_udp_boundaries_are_real_and_sequential_for_every_method_and_target",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "udp_chain_layers_mixed_credentials_bounds_and_response_binding",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "udp_chain_selector_snapshots_and_cross_plan_binding",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "udp_chain_invalid_inner_state_and_shutdown_are_atomic",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "dns_proxy_prepare_cancellation_awaits_owner_and_rebinds",
            "bins/ferrum2-client/src/run/dns.rs",
        ),
        (
            "fn",
            "dns_proxy_selector_snapshot_and_no_fallback",
            "bins/ferrum2-client/src/dns_egress.rs",
        ),
        (
            "fn",
            "dns_proxy_first_match_direct_and_detoured_transports",
            "bins/ferrum2-client/src/dns_egress.rs",
        ),
        (
            "fn",
            "dns_proxy_detoured_udp_with_public_associate_off",
            "bins/ferrum2-client/src/dns_egress.rs",
        ),
        (
            "fn",
            "dns_proxy_detour_saturation_shutdown_and_exact_rebind",
            "bins/ferrum2-client/src/dns_egress.rs",
        ),
        (
            "fn",
            "tagged_dns_selection_uses_authenticated_original_context_and_final",
            "bins/ferrum2-server/src/dns_egress.rs",
        ),
        (
            "fn",
            "udp_composition_three_methods_echo_and_deferred_client_commit_table",
            "bins/ferrum2-server/src/run/udp.rs",
        ),
        (
            "fn",
            "udp_real_socket_session_saturation_never_reaches_second_target",
            "bins/ferrum2-server/src/run/udp.rs",
        ),
    ];
    check_test_placement(
        &sources,
        &rules,
        &[
            "bins/ferrum2-client/src/run/tests.rs",
            "bins/ferrum2-server/src/run/tests.rs",
        ],
        &[
            "bins/ferrum2-client/src/run/test_support.rs",
            "bins/ferrum2-server/src/run/test_support.rs",
        ],
    )
    .unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn binary_composition_roots_delegate_protocol_execution_to_owned_modules() {
    let root = workspace_root();
    let sources = token_sources(
        &root,
        &[
            "bins/ferrum2-client/src/run.rs",
            "bins/ferrum2-server/src/run.rs",
        ],
    );
    check_no_sequences(
        &sources,
        &[
            &["fn", "client_connection"],
            &["fn", "run_udp_association"],
            &["fn", "relay_udp_association"],
            &["fn", "server_connection"],
            &["struct", "UdpMappings"],
            &["fn", "prepare_udp_server"],
            &["struct", "TokioTransport"],
            &["fn", "observation_for_error"],
            &["fn", "framed_error"],
        ],
    )
    .unwrap_or_else(|error| panic!("composition root owns protocol execution: {error}"));
}

#[test]
fn runtime_and_library_owners_are_unique_and_composition_only() {
    let root = workspace_root();
    let sources = token_sources_under(&root, &["bins", "crates"]);
    let rules = [
        (
            "struct",
            "ClientRouting",
            "bins/ferrum2-client/src/run/context.rs",
        ),
        (
            "struct",
            "ClientContext",
            "bins/ferrum2-client/src/run/context.rs",
        ),
        (
            "struct",
            "ClientDnsRoot",
            "bins/ferrum2-client/src/run/dns.rs",
        ),
        (
            "struct",
            "ClientDnsEgress",
            "bins/ferrum2-client/src/dns_egress.rs",
        ),
        (
            "struct",
            "ClientEgressEngine",
            "bins/ferrum2-client/src/run/egress/mod.rs",
        ),
        (
            "struct",
            "TokioTransport",
            "bins/ferrum2-client/src/run/io.rs",
        ),
        (
            "struct",
            "ClientMetricsRoot",
            "bins/ferrum2-client/src/run/observation.rs",
        ),
        (
            "fn",
            "observation_for_error",
            "bins/ferrum2-client/src/run/observation.rs",
        ),
        (
            "fn",
            "client_connection",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "run_udp_association",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "fn",
            "relay_udp_association",
            "bins/ferrum2-client/src/run/socks.rs",
        ),
        (
            "struct",
            "ServerDnsRoot",
            "bins/ferrum2-server/src/run/dns.rs",
        ),
        (
            "struct",
            "ServerDnsEgress",
            "bins/ferrum2-server/src/dns_egress.rs",
        ),
        (
            "struct",
            "TokioTransport",
            "bins/ferrum2-server/src/run/io.rs",
        ),
        (
            "struct",
            "ServerMetricsRoot",
            "bins/ferrum2-server/src/run/observation.rs",
        ),
        (
            "fn",
            "observation_for_error",
            "bins/ferrum2-server/src/run/observation.rs",
        ),
        (
            "fn",
            "server_connection",
            "bins/ferrum2-server/src/run/tcp.rs",
        ),
        (
            "struct",
            "UdpMappings",
            "bins/ferrum2-server/src/run/udp.rs",
        ),
        (
            "fn",
            "prepare_udp_server",
            "bins/ferrum2-server/src/run/udp.rs",
        ),
        (
            "struct",
            "EgressPlanSnapshot",
            "crates/ferrum2-core/src/route.rs",
        ),
        (
            "struct",
            "SelectorControl",
            "crates/ferrum2-core/src/selector.rs",
        ),
        (
            "struct",
            "ValidatedClientConfig",
            "crates/ferrum2-config/src/model.rs",
        ),
        (
            "struct",
            "ValidatedServerConfig",
            "crates/ferrum2-config/src/model.rs",
        ),
        (
            "struct",
            "ConfigError",
            "crates/ferrum2-config/src/error.rs",
        ),
        (
            "enum",
            "ConfigErrorKind",
            "crates/ferrum2-config/src/error.rs",
        ),
        ("fn", "load_client", "crates/ferrum2-config/src/load.rs"),
        ("fn", "load_server", "crates/ferrum2-config/src/load.rs"),
        (
            "struct",
            "RawClientRoot",
            "crates/ferrum2-config/src/raw.rs",
        ),
        (
            "struct",
            "RawServerRoot",
            "crates/ferrum2-config/src/raw.rs",
        ),
        (
            "fn",
            "validate_client",
            "crates/ferrum2-config/src/validation.rs",
        ),
        (
            "fn",
            "validate_server",
            "crates/ferrum2-config/src/validation.rs",
        ),
        ("struct", "DnsProxy", "crates/ferrum2-dns/src/proxy.rs"),
        (
            "struct",
            "SystemDnsEgress",
            "crates/ferrum2-dns/src/runtime_provider.rs",
        ),
        (
            "struct",
            "TaggedResolver",
            "crates/ferrum2-dns/src/runtime_owner.rs",
        ),
        (
            "struct",
            "ClientTcpOutbound",
            "crates/ferrum2-shadowsocks/src/lib.rs",
        ),
        (
            "struct",
            "ShadowsocksTcpInbound",
            "crates/ferrum2-shadowsocks/src/lib.rs",
        ),
        (
            "struct",
            "UdpClientSession",
            "crates/ferrum2-shadowsocks/src/udp.rs",
        ),
        (
            "struct",
            "UdpServer",
            "crates/ferrum2-shadowsocks/src/udp.rs",
        ),
        (
            "fn",
            "encode_request_first_write",
            "crates/ferrum2-shadowsocks/src/lib.rs",
        ),
    ];
    let roots = [
        "bins/ferrum2-client/src/run.rs",
        "bins/ferrum2-server/src/run.rs",
        "crates/ferrum2-config/src/lib.rs",
        "crates/ferrum2-core/src/lib.rs",
    ];
    check_definition_ownership(&sources, &rules, &roots).unwrap_or_else(|error| panic!("{error}"));

    check_no_identifiers(&sources, &["unsafe", "PlanSnapshot"])
        .unwrap_or_else(|error| panic!("product source changes unsafe/plan ownership: {error}"));
    let dns_adapters = [
        "bins/ferrum2-client/src/dns_egress.rs",
        "bins/ferrum2-client/src/run/dns.rs",
        "bins/ferrum2-server/src/dns_egress.rs",
        "bins/ferrum2-server/src/run/dns.rs",
    ];
    check_no_identifiers(
        sources
            .iter()
            .filter(|source| dns_adapters.contains(&source.path.as_str())),
        &["hickory_proto", "DnsParser"],
    )
    .unwrap_or_else(|error| panic!("DNS adapter duplicates protocol behavior: {error}"));
    for adapter in dns_adapters {
        let source = sources
            .iter()
            .find(|source| source.path == adapter)
            .unwrap();
        check_no_sequences([source], &[&["Message", ":", ":", "from_vec"]])
            .unwrap_or_else(|error| panic!("DNS adapter parses wire: {error}"));
    }
}
#[test]
fn server_dns_composition_reuses_the_tagged_resolver_and_connector_seams() {
    let root = workspace_root();
    let run = fs::read_to_string(root.join("bins/ferrum2-server/src/run.rs"))
        .expect("server composition");
    let egress = fs::read_to_string(root.join("bins/ferrum2-server/src/dns_egress.rs"))
        .expect("server DNS egress adapter");
    let dns = fs::read_to_string(root.join("bins/ferrum2-server/src/run/dns.rs"))
        .expect("server DNS process owner");
    let support = fs::read_to_string(root.join("tests/m0-harness/src/local_support/mod.rs"))
        .expect("shared process support");

    for required in [
        "mod dns_egress;",
        "ServerDnsRoot",
        "TaggedResolver::new",
        "ServerDnsResolver::new",
    ] {
        assert!(
            run.contains(required),
            "missing server DNS composition: {required}"
        );
    }
    assert!(dns.contains("PreparedProcessRoot<RunError> for ServerDnsRoot"));
    for required in [
        "ActionTable<usize>",
        "SystemTcpResolver",
        "SystemUdpResolver",
        "impl TcpResolver for ServerDnsResolver",
        "impl UdpResolver for ServerDnsResolver",
        "MAX_RESOLVED_CANDIDATES",
    ] {
        assert!(
            egress.contains(required),
            "missing reused DNS seam: {required}"
        );
    }
    for forbidden in ["Message::from_vec", "hickory_proto", "struct DnsParser"] {
        assert!(
            !run.contains(forbidden) && !dns.contains(forbidden) && !egress.contains(forbidden),
            "server composition duplicated DNS protocol behavior: {forbidden}"
        );
    }
    for required in [
        "Message::from_vec",
        "Record::from_rdata",
        "RData::A",
        ".to_vec().expect(\"DNS answer encode\")",
    ] {
        assert!(
            support.contains(required),
            "shared DNS fixture must use Hickory: {required}"
        );
    }
    for forbidden in [
        "let mut end = 12",
        "u16::from_be_bytes([request[end]",
        "response.extend_from_slice(&[0x81, 0x80",
        "0xc0,\n                    0x0c",
    ] {
        assert!(
            !support.contains(forbidden),
            "shared DNS fixture copied DNS wire behavior: {forbidden}"
        );
    }
}
