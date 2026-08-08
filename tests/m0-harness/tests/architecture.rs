use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const CURRENT_COMPATIBILITY_MEMBERS: [&str; 11] = [
    "bins/ferrum2-client",
    "bins/ferrum2-server",
    "crates/ferrum2-config",
    "crates/ferrum2-core",
    "crates/ferrum2-crypto",
    "crates/ferrum2-observability",
    "crates/ferrum2-runtime",
    "crates/ferrum2-shadowsocks",
    "crates/ferrum2-sniff",
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

fn balanced_end(tokens: &[String], start: usize, open: &str, close: &str) -> Option<usize> {
    (tokens.get(start)? == open).then_some(())?;
    let mut depth = 0;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        if token == open {
            depth += 1;
        } else if token == close {
            depth -= 1;
            if depth == 0 {
                return Some(index + 1);
            }
        }
    }
    None
}

fn is_identifier(token: &str) -> bool {
    token
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
}

fn test_module_end(tokens: &[String], start: usize) -> Option<usize> {
    if !has_tokens(
        tokens.get(start..start + 7)?,
        &["#", "[", "cfg", "(", "test", ")", "]"],
    ) {
        return None;
    }
    let mut cursor = start + 7;
    if tokens.get(cursor).is_some_and(|token| token == "pub") {
        cursor = balanced_end(tokens, cursor + 1, "(", ")")?;
    }
    if tokens.get(cursor).map(String::as_str) != Some("mod")
        || tokens
            .get(cursor + 1)
            .is_none_or(|name| !is_identifier(name))
    {
        return None;
    }
    match tokens.get(cursor + 2)?.as_str() {
        ";" => Some(cursor + 3),
        "{" => balanced_end(tokens, cursor + 2, "{", "}"),
        _ => None,
    }
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

    fn production_tokens(&self) -> Result<&[String], String> {
        let mut delimiters = Vec::new();
        let mut cursor = 0;
        while cursor < self.tokens.len() {
            if delimiters.is_empty()
                && let Some(end) = test_module_end(&self.tokens, cursor)
            {
                let production_end = cursor;
                cursor = end;
                while cursor < self.tokens.len() {
                    cursor = test_module_end(&self.tokens, cursor).ok_or_else(|| {
                        format!("{} has production after a test module", self.path)
                    })?;
                }
                return Ok(&self.tokens[..production_end]);
            }
            match self.tokens[cursor].as_str() {
                "(" => delimiters.push(")"),
                "[" => delimiters.push("]"),
                "{" => delimiters.push("}"),
                token if delimiters.last().is_some_and(|close| *close == token) => {
                    delimiters.pop();
                }
                _ => {}
            }
            cursor += 1;
        }
        Ok(&self.tokens)
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
            .production_tokens()?
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
        let tokens = source.production_tokens()?;
        if let Some(sequence) = forbidden
            .iter()
            .find(|sequence| has_tokens(tokens, sequence))
        {
            return Err(format!("{} contains forbidden {sequence:?}", source.path));
        }
    }
    Ok(())
}

fn check_composition_roots(
    sources: &[TokenSource],
    expected: &[(&str, &[&str])],
) -> Result<(), String> {
    for (path, names) in expected {
        let source = sources
            .iter()
            .find(|source| source.path == *path)
            .ok_or_else(|| format!("missing composition root {path}"))?;
        let tokens = source.production_tokens()?;
        let actual = name_counts(tokens.windows(2).filter_map(|window| {
            (window[0] == "fn" && is_identifier(&window[1])).then_some(window[1].as_str())
        }));
        let expected = name_counts(names.iter().copied());
        if actual != expected {
            return Err(format!(
                "composition root function mismatch for {path}: expected {expected:?}, found {actual:?}"
            ));
        }
        check_no_identifiers([source], &["accept_response", "commit_request"])?;
    }
    Ok(())
}

fn has_glob_use(tokens: &[String]) -> bool {
    tokens.iter().enumerate().any(|(index, token)| {
        token == "use"
            && tokens[index + 1..]
                .iter()
                .take_while(|token| token.as_str() != ";")
                .any(|token| token == "*")
    })
}

fn check_no_glob_facades(
    sources: &[TokenSource],
    owners: &[&str],
    roots: &[&str],
) -> Result<(), String> {
    for owner in owners {
        let source = sources
            .iter()
            .find(|source| source.path == *owner)
            .ok_or_else(|| format!("missing owner {owner}"))?;
        if has_glob_use(source.production_tokens()?) {
            return Err(format!("production owner remains a glob facade: {owner}"));
        }
    }
    for root in roots {
        let source = sources
            .iter()
            .find(|source| source.path == *root)
            .ok_or_else(|| format!("missing composition root {root}"))?;
        if has_glob_use(source.production_tokens()?) {
            return Err(format!("composition root has a glob import: {root}"));
        }
    }
    Ok(())
}

fn name_counts<'a>(names: impl IntoIterator<Item = &'a str>) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for name in names {
        *counts.entry(name.to_owned()).or_default() += 1;
    }
    counts
}

fn restricted_items(tokens: &[String]) -> BTreeMap<String, usize> {
    let mut items = BTreeMap::new();
    for index in 0..tokens.len() {
        if tokens.get(index).map(String::as_str) != Some("pub")
            || tokens.get(index + 1).map(String::as_str) != Some("(")
        {
            continue;
        }
        let Some(declaration_start) = balanced_end(tokens, index + 1, "(", ")") else {
            continue;
        };
        let declaration = tokens[declaration_start..]
            .iter()
            .take_while(|token| !matches!(token.as_str(), "," | ";" | "{" | "}"));
        let declaration: Vec<_> = declaration.map(String::as_str).collect();
        for keyword in ["struct", "enum", "fn", "trait", "type", "const"] {
            if let Some(keyword) = declaration.iter().position(|token| *token == keyword) {
                if let Some(name) = declaration.get(keyword + 1) {
                    *items.entry((*name).to_owned()).or_default() += 1;
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
        let actual = restricted_items(source.production_tokens()?);
        let expected = name_counts(names.iter().copied());
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
        let references_tests = source
            .tokens
            .windows(3)
            .any(|window| window[0] == "tests" && window[1] == ":" && window[2] == ":");
        if references_tests {
            let role = if composition_tests.contains(&source.path.as_str()) {
                "composition"
            } else if support_modules.contains(&source.path.as_str()) {
                "support"
            } else {
                "owner"
            };
            return Err(format!(
                "{role} source references a test module: {}",
                source.path
            ));
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
        ("ferrum2-sniff", BTreeSet::new()),
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

    let sniff = token_sources_under(&root, &["crates/ferrum2-sniff/src"]);
    check_no_identifiers(
        &sniff,
        &[
            "unsafe",
            "async",
            "spawn",
            "TcpListener",
            "TcpStream",
            "UdpSocket",
            "ToSocketAddrs",
            "ServerConfig",
            "ClientConnection",
            "HashMap",
            "dyn",
            "trait",
            "ferrum2_config",
            "ferrum2_runtime",
            "tracing",
            "metrics",
        ],
    )
    .unwrap_or_else(|error| panic!("pure sniff module gained runtime/registry ownership: {error}"));
    for required in [
        &["Header", ":", ":", "read"][..],
        &["Message", ":", ":", "read"][..],
        &["Acceptor", ":", ":", "default"],
        &["httparse", ":", ":", "Request", ":", ":", "new"],
    ] {
        assert_eq!(
            sniff
                .iter()
                .map(|source| {
                    source
                        .production_tokens()
                        .expect("sniff production tokens")
                        .windows(required.len())
                        .filter(|window| {
                            window
                                .iter()
                                .map(String::as_str)
                                .eq(required.iter().copied())
                        })
                        .count()
                })
                .sum::<usize>(),
            1,
            "sniff module must have exactly one owner/use of reviewed parser {required:?}"
        );
    }

    let mut decode_dns_bodies = Vec::new();
    for source in &sniff {
        let tokens = source.production_tokens().expect("sniff production tokens");
        for definition in tokens
            .windows(2)
            .enumerate()
            .filter_map(|(index, window)| (window == ["fn", "decode_dns"]).then_some(index))
        {
            let body_start = (definition + 2..tokens.len())
                .find(|index| tokens[*index] == "{")
                .expect("decode_dns body start");
            let body_end =
                balanced_end(tokens, body_start, "{", "}").expect("balanced decode_dns definition");
            decode_dns_bodies.push(&tokens[body_start..body_end]);
        }
    }
    assert_eq!(
        decode_dns_bodies.len(),
        1,
        "DNS decoding must have one semantic production owner"
    );
    let decode_dns = decode_dns_bodies[0];
    let parser_position = |parser: &[&str]| {
        decode_dns
            .windows(parser.len())
            .position(|window| window.iter().map(String::as_str).eq(parser.iter().copied()))
            .unwrap_or_else(|| panic!("decode_dns must call {parser:?}"))
    };
    let header_read = parser_position(&["Header", ":", ":", "read"]);
    let checked_multiply = parser_position(&[".", "checked_mul"]);
    let checked_add = parser_position(&[".", "checked_add"]);
    let message_read = parser_position(&["Message", ":", ":", "read"]);
    assert!(
        header_read < checked_multiply
            && checked_multiply < checked_add
            && checked_add < message_read,
        "bounded Hickory Header preflight must precede allocating Message decode"
    );
    for required in [
        &["header", ".", "metadata", ".", "message_type"][..],
        &["header", ".", "metadata", ".", "op_code"],
        &["header", ".", "counts", ".", "queries"],
        &["header", ".", "counts", ".", "answers"],
        &["header", ".", "counts", ".", "authorities"],
        &["header", ".", "counts", ".", "additionals"],
    ] {
        assert!(
            has_tokens(decode_dns, required),
            "DNS Header preflight must constrain {required:?}"
        );
    }

    assert_eq!(
        name_counts(sniff.iter().flat_map(|source| {
            source
                .production_tokens()
                .expect("sniff production tokens")
                .windows(3)
                .filter_map(|window| {
                    (window[0] == "pub" && window[1] == "fn").then_some(window[2].as_str())
                })
        })),
        BTreeMap::from([("sniff".to_owned(), 1)]),
        "sniff module exposes exactly one byte-slice function"
    );
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

    assert_eq!(dependencies, BTreeSet::from(["bytes", "ipnet"]));
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
fn ordered_route_program_is_protocol_neutral_and_the_only_ordinary_engine() {
    let root = workspace_root();
    let sources = [TokenSource::new(
        "crates/ferrum2-core/src/route.rs",
        &fs::read_to_string(root.join("crates/ferrum2-core/src/route.rs"))
            .expect("core route module"),
    )];
    check_definition_ownership(
        &sources,
        &[
            (
                "struct",
                "OrderedRouteProgram",
                "crates/ferrum2-core/src/route.rs",
            ),
            (
                "struct",
                "RouteProgramEvaluation",
                "crates/ferrum2-core/src/route.rs",
            ),
        ],
        &[],
    )
    .unwrap_or_else(|error| panic!("ordered-route ownership changed: {error}"));
    let route = &sources[0];
    let tokens = route.production_tokens().expect("route production tokens");
    assert!(has_tokens(tokens, &["cursor", ":", "usize"]));
    assert!(has_tokens(
        tokens,
        &[
            "program",
            ":",
            "OrderedRouteProgram",
            "<",
            "(",
            ")",
            ",",
            "OutboundAction"
        ]
    ));
    assert!(has_tokens(
        tokens,
        &[
            "assert_eq",
            "!",
            "(",
            "plan",
            ".",
            "hops",
            ".",
            "len",
            "(",
            ")",
            ",",
            "1"
        ]
    ));
    let concrete: Vec<_> =
        "Dns,DNS,Tls,TLS,Http,HTTP,Sniff,sniff,Hijack,hijack,tokio,ferrum2_config,ferrum2_runtime"
            .split(',')
            .collect();
    check_no_identifiers([route], &concrete)
        .unwrap_or_else(|error| panic!("core route owns concrete vocabulary: {error}"));
    check_no_sequences(
        [route],
        &[
            &["actions", ":", "ActionTable", "<", "OutboundAction", ">"],
            &["pub", "cursor"],
            &["pub", "(", "crate", ")", "cursor"],
        ],
    )
    .unwrap_or_else(|error| panic!("ordered-route ownership changed: {error}"));

    let validation = TokenSource::new(
        "crates/ferrum2-config/src/validation.rs",
        &fs::read_to_string(root.join("crates/ferrum2-config/src/validation.rs"))
            .expect("config validation"),
    );
    assert!(
        has_tokens(
            validation
                .production_tokens()
                .expect("config production tokens"),
            &[
                "selectors",
                ".",
                "as_deref",
                "(",
                ")",
                ",",
                "&",
                "[",
                "]",
                ",",
                "detour_tags",
                ",",
                "source",
            ],
        ),
        "server scalar route compilation must receive no multi-hop plans"
    );
}

#[test]
fn server_consumes_typed_routes_through_one_runtime_prefix_collector() {
    let root = workspace_root();
    let runtime = token_sources_under(&root, &["crates/ferrum2-runtime/src"]);
    check_definition_ownership(
        &runtime,
        &[(
            "fn",
            "collect_sniff_prefix",
            "crates/ferrum2-runtime/src/sniff.rs",
        )],
        &[],
    )
    .unwrap_or_else(|error| panic!("prefix collector ownership changed: {error}"));

    let server = token_sources(
        &root,
        &[
            "bins/ferrum2-server/src/run.rs",
            "bins/ferrum2-server/src/run/tcp.rs",
            "bins/ferrum2-server/src/run/udp.rs",
        ],
    );
    let run = server[0]
        .production_tokens()
        .expect("server root production tokens");
    assert!(has_tokens(
        run,
        &["program", ":", "config", ".", "route_program"]
    ));
    assert!(
        !run.iter().any(|token| token == "schema_version"),
        "server root restored a schema-v2 startup latch"
    );
    let tcp = server[1]
        .production_tokens()
        .expect("server TCP production tokens");
    assert!(has_tokens(
        tcp,
        &["program", ":", "Option", "<", "CompiledRoute", ">"]
    ));
    assert!(has_tokens(tcp, &["collect_sniff_prefix", "("]));
    assert!(has_tokens(tcp, &["poll_read_plain", "("]));
    let udp = server[2]
        .production_tokens()
        .expect("server UDP production tokens");
    for required in [
        &["prepare_request", "("][..],
        &["select_udp_route", "("][..],
        &["reserve_udp_direct", "("][..],
        &["commit_request", "("][..],
    ] {
        assert!(
            has_tokens(udp, required),
            "missing UDP composition {required:?}"
        );
    }
    check_no_sequences(server.iter(), &[&["fn", "collect_sniff_prefix"]])
        .unwrap_or_else(|error| panic!("server restored a second prefix collector: {error}"));

    let runtime_manifest = fs::read_to_string(root.join("crates/ferrum2-runtime/Cargo.toml"))
        .expect("runtime manifest");
    assert!(!runtime_manifest.contains("ferrum2-sniff"));
    let server_manifest =
        fs::read_to_string(root.join("bins/ferrum2-server/Cargo.toml")).expect("server manifest");
    assert!(server_manifest.contains("ferrum2-sniff.workspace = true"));

    let position = |tokens: &[String], sequence: &[&str], start: usize| {
        tokens[start..]
            .windows(sequence.len())
            .position(|window| {
                window
                    .iter()
                    .map(String::as_str)
                    .eq(sequence.iter().copied())
            })
            .map(|offset| start + offset)
    };
    let check_udp_order = |tokens: &[String]| -> Result<(), String> {
        let prepare = position(tokens, &["prepare_request", "("], 0)
            .ok_or("missing authenticated UDP prepare")?;
        let select = position(tokens, &["select_udp_route", "("], prepare + 1)
            .ok_or("UDP policy precedes prepare")?;
        let reject = position(
            tokens,
            &[
                "if",
                "terminal",
                "=",
                "=",
                "ServerTerminalRoute",
                ":",
                ":",
                "Reject",
            ],
            select + 1,
        )
        .ok_or("missing immediate UDP terminal split")?;
        let legacy = position(
            tokens,
            &["routing", ".", "program", "(", ")", ".", "is_none"],
            reject + 1,
        )
        .ok_or("legacy reject no-mutation gate moved")?;
        let commits: Vec<_> = tokens
            .windows(2)
            .enumerate()
            .filter_map(|(index, window)| {
                (index > select && window[0] == "commit_request" && window[1] == "(")
                    .then_some(index)
            })
            .collect();
        let reserves: Vec<_> = tokens
            .windows(2)
            .enumerate()
            .filter_map(|(index, window)| {
                (index > select && window[0] == "reserve_udp_direct" && window[1] == "(")
                    .then_some(index)
            })
            .collect();
        if has_tokens(tokens, &["orphan_count", "("]) {
            return Err("UDP restored a split orphan-only admission ceiling".to_owned());
        }
        let reconcile = position(tokens, &["reconcile_udp_generations", "("], legacy + 1)
            .ok_or("missing retained-orphan reconciliation before admission")?;
        let prune = position(
            tokens,
            &["mappings", ".", "prune_protocol", "("],
            reconcile + 1,
        )
        .ok_or("missing retained-orphan prune before admission")?;
        let session_cap = position(tokens, &["protocol", ".", "session_count", "("], prune + 1)
            .ok_or("missing shared protocol session ceiling")?;
        if commits.len() != 3
            || reserves.len() != 2
            || !(select < reject
                && reject < legacy
                && legacy < reconcile
                && reconcile < prune
                && prune < session_cap
                && session_cap < commits[0]
                && session_cap < reserves[0]
                && commits[0] < reserves[0]
                && reserves[0] < commits[1]
                && commits[1] < reserves[1]
                && reserves[1] < commits[2])
        {
            return Err(format!(
                "UDP prepare/select/shared-cap/reject/direct reservation order changed: select={select} reject={reject} legacy={legacy} reconcile={reconcile} prune={prune} session_cap={session_cap} commits={commits:?} reserves={reserves:?}"
            ));
        }
        Ok(())
    };
    check_udp_order(udp).unwrap_or_else(|error| panic!("{error}"));

    let check_tcp_boundary = |tokens: &[String]| -> Result<(), String> {
        if tokens
            .iter()
            .filter(|token| token.as_str() == "poll_read_plain")
            .count()
            != 1
            || tokens
                .windows(2)
                .filter(|window| window[0] == "collect_sniff_prefix" && window[1] == "(")
                .count()
                != 1
        {
            return Err("TCP restored an alias read loop or second collector".to_owned());
        }
        let function = position(tokens, &["async", "fn", "server_connection"], 0)
            .ok_or("missing server connection")?;
        let body_start = tokens[function..]
            .iter()
            .position(|token| token == "{")
            .map(|offset| function + offset)
            .ok_or("missing server connection body")?;
        let body_end = balanced_end(tokens, body_start, "{", "}")
            .ok_or("unbalanced server connection body")?;
        let body = &tokens[body_start..body_end];
        let authenticate = position(body, &["inbound", ".", "accept", "("], 0)
            .ok_or("missing SIP022 authentication")?;
        let select = position(body, &["select_tcp_route", "("], 0)
            .ok_or("missing post-auth route selection")?;
        if authenticate >= select
            || has_tokens(body, &["ferrum2_sniff", "::", "sniff", "("])
            || has_tokens(body, &["collect_sniff_prefix", "("])
        {
            return Err("TCP sniff moved before authentication or escaped its selector".to_owned());
        }
        Ok(())
    };
    check_tcp_boundary(tcp).unwrap_or_else(|error| panic!("{error}"));
    let observation = TokenSource::new(
        "bins/ferrum2-server/src/run/observation.rs",
        &fs::read_to_string(root.join("bins/ferrum2-server/src/run/observation.rs"))
            .expect("server observation"),
    );
    let observation = observation
        .production_tokens()
        .expect("server observation production tokens");
    assert_eq!(
        observation
            .windows(2)
            .filter(|window| window[0] == "fn" && window[1] == "record_sniff")
            .count(),
        1,
        "sniff telemetry must keep one server mapping seam"
    );
    assert_eq!(
        observation
            .windows(4)
            .filter(|window| {
                window[0] == "metrics"
                    && window[1] == "."
                    && window[2] == "sniff"
                    && window[3] == "("
            })
            .count(),
        1,
        "server observation must emit one closed sniff tuple"
    );
    assert_eq!(
        tcp.windows(2)
            .filter(|window| window[0] == "record_sniff" && window[1] == "(")
            .count(),
        2,
        "TCP must cover fatal and continuing sniff terminals"
    );
    assert_eq!(
        udp.windows(2)
            .filter(|window| window[0] == "record_sniff" && window[1] == "(")
            .count(),
        1,
        "UDP must emit once after authenticated borrow-sniff"
    );

    let mut reordered_udp = udp.to_vec();
    let prepare = position(&reordered_udp, &["prepare_request", "("], 0).expect("prepare token");
    let select = position(&reordered_udp, &["select_udp_route", "("], 0).expect("select token");
    reordered_udp.swap(prepare, select);
    assert!(
        check_udp_order(&reordered_udp).is_err(),
        "UDP prepare/select reorder mutation survived"
    );
    let mut split_udp_cap = udp.to_vec();
    let session_cap = position(&split_udp_cap, &["protocol", ".", "session_count", "("], 0)
        .expect("shared session ceiling token");
    split_udp_cap[session_cap] = "mappings".to_owned();
    split_udp_cap[session_cap + 2] = "orphan_count".to_owned();
    assert!(
        check_udp_order(&split_udp_cap).is_err(),
        "orphan-only admission mutation survived"
    );
    let mut aliased_tcp = tcp.to_vec();
    aliased_tcp.extend(["poll_read_plain".to_owned(), "(".to_owned()]);
    assert!(
        check_tcp_boundary(&aliased_tcp).is_err(),
        "second plaintext read-loop mutation survived"
    );
    let mut preauth_tcp = tcp.to_vec();
    let function = position(&preauth_tcp, &["async", "fn", "server_connection"], 0)
        .expect("server connection token");
    let authenticate = position(&preauth_tcp, &["accept", "("], function).expect("accept token");
    let select = position(&preauth_tcp, &["select_tcp_route", "("], function)
        .expect("route selection token");
    preauth_tcp.swap(authenticate, select);
    assert!(
        check_tcp_boundary(&preauth_tcp).is_err(),
        "pre-auth TCP sniff mutation survived"
    );
    let check_run_latch = |tokens: &[String]| {
        (!tokens.iter().any(|token| token == "schema_version"))
            .then_some(())
            .ok_or("server schema latch restored")
    };
    check_run_latch(run).unwrap_or_else(|error| panic!("{error}"));
    let mut latched_run = run.to_vec();
    latched_run.push("schema_version".to_owned());
    assert!(
        check_run_latch(&latched_run).is_err(),
        "schema latch mutation survived"
    );
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

    let mut accepted = Vec::new();
    for (mutation, source) in [
        (
            "cfg(test) use followed by mod and production",
            "#[cfg(test)] use crate::fixture; mod tests; fn production() {}",
        ),
        (
            "non-terminal cfg(test) module",
            "#[cfg(test)] mod tests; fn production() {}",
        ),
    ] {
        let source = TokenSource::new("sample/owner.rs", source);
        if check_no_identifiers([&source], &["production"]).is_ok() {
            accepted.push(mutation);
        }
    }
    for (mutation, source, expected) in [
        (
            "pub(in path) restricted item",
            "pub(in crate::run) fn extra() {}",
            &[][..],
        ),
        (
            "duplicate restricted item name",
            "struct A; impl A { pub(super) fn new() {} } \
             struct B; impl B { pub(super) fn new() {} }",
            &["new"][..],
        ),
    ] {
        let sources = [TokenSource::new("sample/owner.rs", source)];
        if check_restricted_interfaces(&sources, &[("sample/owner.rs", expected)]).is_ok() {
            accepted.push(mutation);
        }
    }
    for (mutation, source, owners, roots) in [
        (
            "crate root glob import",
            "use crate::run::*;",
            &["sample/owner.rs"][..],
            &[][..],
        ),
        (
            "self child root glob import",
            "use self::child::*;",
            &[][..],
            &["sample/root.rs"][..],
        ),
    ] {
        let sources = [TokenSource::new(
            if owners.is_empty() {
                "sample/root.rs"
            } else {
                "sample/owner.rs"
            },
            source,
        )];
        if check_no_glob_facades(&sources, owners, roots).is_ok() {
            accepted.push(mutation);
        }
    }
    let relative_cycle = [
        TokenSource::new(
            "sample/owner.rs",
            "use super::super::tests::fixture; #[test] fn owned_case() {}",
        ),
        TokenSource::new("sample/tests.rs", ""),
    ];
    if check_test_placement(&relative_cycle, &[test_rule], &["sample/tests.rs"], &[]).is_ok() {
        accepted.push("relative owner/test cycle");
    }

    for (mutation, source) in [
        (
            "renamed root executor",
            "fn run() {} fn renamed_executor() {}",
        ),
        (
            "allowed root function with protocol operation",
            "fn run() { association.accept_response(); }",
        ),
    ] {
        let sources = [TokenSource::new("sample/root.rs", source)];
        if check_composition_roots(&sources, &[("sample/root.rs", &["run"])]).is_ok() {
            accepted.push(mutation);
        }
    }
    assert!(
        accepted.is_empty(),
        "ownership scanner accepted mutations: {accepted:?}"
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
    check_no_glob_facades(&sources, &owners, &roots).unwrap_or_else(|error| panic!("{error}"));

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
                    "new",
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
                    "record_sniff",
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
                    "ServerTerminalRoute",
                    "ServerTcpListeners",
                    "ServerTcpRoot",
                    "legacy",
                    "program",
                    "route_metadata",
                    "sniff_order",
                    "terminal",
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
    check_composition_roots(
        &sources,
        &[
            (
                "bins/ferrum2-client/src/run.rs",
                &[
                    "fmt",
                    "run",
                    "run_async",
                    "run_with_registry",
                    "run_with_registry_and_metrics",
                    "run_with_registry_and_metrics_inner",
                    "report_result",
                ],
            ),
            (
                "bins/ferrum2-server/src/run.rs",
                &[
                    "fmt",
                    "run",
                    "run_async",
                    "run_with_registry",
                    "run_with_registry_prepared",
                    "report_result",
                ],
            ),
        ],
    )
    .unwrap_or_else(|error| panic!("composition root owns protocol execution: {error}"));
    check_no_sequences(
        &sources,
        &[&["struct", "UdpMappings"], &["struct", "TokioTransport"]],
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
        ("enum", "ProxyIngress", "crates/ferrum2-dns/src/proxy.rs"),
        ("fn", "answer", "crates/ferrum2-dns/src/proxy.rs"),
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
    let dns_sources: Vec<_> = sources
        .iter()
        .filter(|source| source.path.starts_with("crates/ferrum2-dns/src/"))
        .collect();
    check_no_identifiers(
        dns_sources.iter().copied(),
        &["DnsService", "DnsFramer", "DnsParser", "DnsQueryEngine"],
    )
    .unwrap_or_else(|error| panic!("DNS crate restored a delegating/duplicate module: {error}"));
    let parser_owners: Vec<_> = dns_sources
        .iter()
        .filter(|source| {
            has_tokens(
                source.production_tokens().expect("DNS production tokens"),
                &["Message", ":", ":", "from_vec"],
            )
        })
        .map(|source| source.path.as_str())
        .collect();
    assert_eq!(
        parser_owners,
        ["crates/ferrum2-dns/src/proxy.rs"],
        "DnsProxy::answer must remain the only DNS wire decoder"
    );
    let proxy = dns_sources
        .iter()
        .find(|source| source.path == "crates/ferrum2-dns/src/proxy.rs")
        .expect("DNS proxy owner")
        .production_tokens()
        .expect("DNS proxy production tokens");
    assert_eq!(
        proxy
            .windows(4)
            .filter(|window| *window == ["HickoryTcpStream", ":", ":", "from_stream"])
            .count(),
        1,
        "DnsProxy listeners must retain one Hickory TCP framer"
    );
    let server_dns = sources
        .iter()
        .find(|source| source.path == "bins/ferrum2-server/src/dns_egress.rs")
        .expect("server DNS policy adapter");
    check_no_identifiers([server_dns], &["DnsQueryType", "RecordType", "qtype"])
        .unwrap_or_else(|error| panic!("server application DNS policy gained qtype: {error}"));
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
