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
fn binary_composition_roots_delegate_protocol_execution_to_owned_modules() {
    let root = workspace_root();
    for (binary, forbidden) in [
        (
            "ferrum2-client",
            &[
                "async fn client_connection(",
                "async fn run_udp_association<",
                "async fn relay_udp_association<",
                "struct TokioTransport<",
                "fn observation_for_error(",
            ][..],
        ),
        (
            "ferrum2-server",
            &[
                "async fn server_connection(",
                "struct UdpMappings",
                "fn prepare_udp_server<",
                "struct TokioTransport<",
                "fn observation_for_error(",
            ][..],
        ),
    ] {
        let run = fs::read_to_string(root.join("bins").join(binary).join("src/run.rs"))
            .expect("binary composition root");
        for implementation in forbidden {
            assert!(
                !run.contains(implementation),
                "{binary} run.rs still owns protocol execution: {implementation}"
            );
        }
    }
}

#[test]
fn runtime_and_library_owners_are_unique_and_composition_only() {
    let root = workspace_root();
    let owners = [
        (
            "bins/ferrum2-client/src/run/context.rs",
            &["struct ClientRouting", "struct ClientContext"][..],
        ),
        (
            "bins/ferrum2-client/src/run/dns.rs",
            &["struct ClientDnsRoot"][..],
        ),
        (
            "bins/ferrum2-client/src/run/io.rs",
            &["struct TokioTransport<"][..],
        ),
        (
            "bins/ferrum2-client/src/run/observation.rs",
            &["struct ClientMetricsRoot", "fn observation_for_error("][..],
        ),
        (
            "bins/ferrum2-client/src/run/socks.rs",
            &[
                "struct ClientTcpListeners",
                "async fn client_connection(",
                "async fn run_udp_association<",
                "async fn relay_udp_association<",
            ][..],
        ),
        (
            "bins/ferrum2-server/src/run/dns.rs",
            &["struct ServerDnsRoot"][..],
        ),
        (
            "bins/ferrum2-server/src/run/io.rs",
            &["struct TokioTransport<"][..],
        ),
        (
            "bins/ferrum2-server/src/run/observation.rs",
            &["struct ServerMetricsRoot", "fn observation_for_error("][..],
        ),
        (
            "bins/ferrum2-server/src/run/tcp.rs",
            &["struct ServerTcpListeners", "async fn server_connection("][..],
        ),
        (
            "bins/ferrum2-server/src/run/udp.rs",
            &["struct UdpMappings", "fn prepare_udp_server<"][..],
        ),
        (
            "crates/ferrum2-core/src/route.rs",
            &["pub struct EgressPlanSnapshot"][..],
        ),
        (
            "crates/ferrum2-core/src/selector.rs",
            &["pub struct SelectorControl"][..],
        ),
        (
            "crates/ferrum2-config/src/error.rs",
            &["pub enum ConfigErrorKind", "pub struct ConfigError"][..],
        ),
        (
            "crates/ferrum2-config/src/load.rs",
            &["pub fn load_client(", "pub fn load_server("][..],
        ),
        (
            "crates/ferrum2-config/src/model.rs",
            &["pub struct ValidatedClientConfig"][..],
        ),
        (
            "crates/ferrum2-config/src/raw.rs",
            &["struct RawClientRoot", "struct RawServerRoot"][..],
        ),
        (
            "crates/ferrum2-config/src/validation.rs",
            &["fn validate_client(", "fn validate_server("][..],
        ),
    ];
    for (owner, required) in owners {
        let source = fs::read_to_string(root.join(owner)).expect("owned module");
        for anchor in required {
            assert!(
                source.contains(anchor),
                "{owner} does not own required implementation: {anchor}"
            );
        }
    }

    let core = fs::read_to_string(root.join("crates/ferrum2-core/src/lib.rs"))
        .expect("core composition module");
    assert!(core.contains("pub mod route;"));
    assert!(core.contains("pub mod selector;"));
    assert!(!core.contains("pub mod route {"));
    assert!(!core.contains("pub mod selector {"));
    let config = fs::read_to_string(root.join("crates/ferrum2-config/src/lib.rs"))
        .expect("config composition module");
    for reexport in [
        "pub use error::{ConfigError, ConfigErrorKind, ConfigField};",
        "pub use load::{load_client, load_server};",
        "pub use model::{",
    ] {
        assert!(
            config.contains(reexport),
            "missing config re-export: {reexport}"
        );
    }
    for implementation in [
        "pub struct ValidatedClientConfig",
        "pub enum ConfigErrorKind",
        "pub fn load_client(",
        "struct RawClientRoot",
        "fn validate_client(",
    ] {
        assert!(
            !config.contains(implementation),
            "config lib.rs still owns implementation: {implementation}"
        );
    }

    let mut product_sources = Vec::new();
    for directory in ["bins", "crates"] {
        product_sources.extend(rust_sources(&root.join(directory)));
    }
    for forbidden in [
        "unsafe {",
        "unsafe fn ",
        "unsafe impl ",
        "unsafe trait ",
        "#![allow(unsafe_code)]",
    ] {
        for path in &product_sources {
            let source = fs::read_to_string(path).expect("product source");
            assert!(
                !source.contains(forbidden),
                "{} changes the workspace unsafe state: {forbidden}",
                path.display()
            );
        }
    }

    for (definition, expected_owner) in [
        (
            "pub struct EgressPlanSnapshot",
            "crates/ferrum2-core/src/route.rs",
        ),
        (
            "pub struct ClientTcpOutbound",
            "crates/ferrum2-shadowsocks/src/lib.rs",
        ),
        (
            "pub struct ShadowsocksTcpInbound",
            "crates/ferrum2-shadowsocks/src/lib.rs",
        ),
        (
            "pub struct UdpClientSession",
            "crates/ferrum2-shadowsocks/src/udp.rs",
        ),
        (
            "pub struct UdpServer",
            "crates/ferrum2-shadowsocks/src/udp.rs",
        ),
        (
            "pub fn encode_request_first_write",
            "crates/ferrum2-shadowsocks/src/lib.rs",
        ),
    ] {
        let locations: Vec<_> = product_sources
            .iter()
            .filter(|path| {
                fs::read_to_string(path)
                    .expect("product source")
                    .contains(definition)
            })
            .collect();
        assert_eq!(locations.len(), 1, "duplicate implementation: {definition}");
        assert!(
            locations[0].ends_with(expected_owner),
            "wrong owner for {definition}: {}",
            locations[0].display()
        );
    }
    for path in &product_sources {
        let source = fs::read_to_string(path).expect("product source");
        assert!(
            !source.contains("struct PlanSnapshot"),
            "{} duplicates the owned route snapshot",
            path.display()
        );
    }

    for binary in ["ferrum2-client", "ferrum2-server"] {
        for adapter in ["src/dns_egress.rs", "src/run/dns.rs"] {
            let path = root.join("bins").join(binary).join(adapter);
            let source = fs::read_to_string(&path).expect("DNS adapter source");
            for forbidden in ["Message::from_vec", "hickory_proto", "struct DnsParser"] {
                assert!(
                    !source.contains(forbidden),
                    "{} duplicated DNS protocol behavior: {forbidden}",
                    path.display()
                );
            }
        }
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
