use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::qualification::{DnsReference, Method, Reference, Transport};

use super::config::{
    Pin, ReferencePaths, ReservedPorts, dns_reference_paths, path_text, reference_client_config,
    reference_paths, reference_server_config, verify_binary_location, write_config,
};
use super::dns_case::run_dns_probe;
use super::pin_hash::{sha256_bytes, sha256_file_with_deadline};
use super::process_guard::{CaseDeadline, ProcessGuard, redact_synthetic_psks, sanitize_capture};
use super::udp_case::wait_for_stable_child;

pub(super) fn provision_reference(reference: Reference) {
    let deadline = CaseDeadline::start();
    let pin = load_pin(reference);
    verify_pin(reference, &pin);
    let paths = reference_paths(reference, &pin);
    verify_archive(&paths.archive, &pin, deadline);
    verify_archive_members(reference, &paths.archive, &pin, deadline);
    verify_binary_location(&paths.server, &paths.extraction_root);
    verify_version(reference, &paths.server, &pin, deadline);
    if let Some(client) = &paths.client {
        verify_binary_location(client, &paths.extraction_root);
        if reference == Reference::ShadowsocksRust {
            verify_version(reference, client, &pin, deadline);
        }
    }
    if let Some(license) = &paths.license {
        verify_reviewed_license(license);
    }
    verify_transport_configs(reference, &paths, deadline);
    deadline.check("final reference provision verification");
}

pub(super) fn provision_dns_reference(reference: DnsReference) {
    let deadline = CaseDeadline::start();
    let pin = load_dns_pin(reference);
    verify_dns_pin(reference, &pin);
    let paths = dns_reference_paths(reference, &pin);
    verify_archive(&paths.archive, &pin, deadline);
    verify_binary_location(&paths.binary, &paths.extraction_root);
    verify_reviewed_license(&paths.license);
    if reference == DnsReference::CoreDns {
        let values = load_pin_values("coredns");
        let license = fs::read(&paths.license).expect("read CoreDNS license");
        assert_eq!(
            license.len(),
            value(&values, "license_size")
                .parse::<usize>()
                .expect("numeric CoreDNS license size")
        );
        assert_eq!(
            sha256_bytes(&license),
            value(&values, "license_sha256"),
            "CoreDNS license hash mismatch"
        );
    }
    let mut command = Command::new(&paths.binary);
    match reference {
        DnsReference::CoreDns => {
            command.arg("-version");
        }
        DnsReference::Bind => {
            command.arg("-v");
        }
    }
    let rendered = run_dns_probe(&mut command, deadline, "DNS provider version");
    assert!(
        rendered
            .lines()
            .any(|line| line.contains(&pin.expected_version)),
        "DNS provider version mismatch"
    );
}

pub(super) fn verify_dns_pin(reference: DnsReference, pin: &Pin) {
    let (version, commit, asset, url, license) = match reference {
        DnsReference::CoreDns => (
            "1.14.6",
            "424d125775cd70fa90dfc80bf0e52cc9a9aeb574",
            "coredns_1.14.6_linux_amd64.tgz",
            "https://github.com/coredns/coredns/releases/download/v1.14.6/",
            "Apache-2.0",
        ),
        DnsReference::Bind => (
            "9.20.26",
            "7e228e3ba7c2ca945b1c2a22ed2ef0aa9d7cab10",
            "bind-9.20.26.tar.xz",
            "https://downloads.isc.org/isc/bind9/9.20.26/",
            "MPL-2.0",
        ),
    };
    assert_eq!(pin.version, version, "DNS release pin changed");
    assert_eq!(pin.source_commit, commit, "DNS source pin changed");
    assert_eq!(pin.asset, asset, "DNS asset pin changed");
    assert_eq!(pin.url, format!("{url}{asset}"), "DNS provenance changed");
    assert!(
        pin.license_review.contains(license)
            && pin.license_review.contains("independent test process"),
        "DNS license boundary changed"
    );
}

pub(super) fn verify_pin(reference: Reference, pin: &Pin) {
    let (version, commit, asset, url_prefix, license_marker) = match reference {
        Reference::SingBox => (
            "1.13.14",
            "25a600db24f7680ad9806ce5427bd0ab8afe1114",
            "sing-box-1.13.14-linux-amd64-glibc.tar.gz",
            "https://github.com/SagerNet/sing-box/releases/download/v1.13.14/",
            "NOASSERTION",
        ),
        Reference::ShadowsocksRust => (
            "1.24.0",
            "7ee1aa9223ed8f4d34734aac919036c8ad4502c2",
            "shadowsocks-v1.24.0.x86_64-unknown-linux-gnu.tar.xz",
            "https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.24.0/",
            "MIT",
        ),
    };
    assert_eq!(pin.version, version, "reference release pin changed");
    assert_eq!(pin.source_commit, commit, "reference source pin changed");
    assert_eq!(pin.asset, asset, "reference host asset pin changed");
    assert!(
        pin.url.starts_with(url_prefix) && pin.url.ends_with(asset),
        "reference release provenance URL changed"
    );
    assert!(
        pin.license_review.contains(license_marker)
            && pin.license_review.contains("independent test process"),
        "reference license boundary changed"
    );
    assert!(
        pin.sha256.len() == 64
            && pin
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "reference SHA-256 pin is malformed"
    );
}

pub(super) fn verify_reviewed_license(path: &Path) {
    let metadata = fs::metadata(path).expect("reviewed license metadata");
    assert!(
        metadata.is_file() && (1..=256 * 1024).contains(&metadata.len()),
        "reviewed license file bounds invalid"
    );
    let contents = fs::read(path).expect("read reviewed license file");
    assert!(!contents.is_empty(), "reviewed license file is empty");
}

pub(super) fn verify_transport_configs(
    reference: Reference,
    paths: &ReferencePaths,
    deadline: CaseDeadline,
) {
    let directory = tempfile::tempdir().expect("isolated transport config verification directory");
    for transport in [Transport::Tcp, Transport::Udp] {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::ChaCha20Poly1305,
        ] {
            let mut ports = ReservedPorts::new();
            let server = ports.shadowsocks_address();
            let proxy = ports.proxy_address();
            let server_config = reference_server_config(method, reference, server, transport);
            assert_transport_config(&server_config, reference, transport);
            let server_path = write_config(directory.path(), "server.json", &server_config);
            ports.release_shadowsocks();
            run_config_check(reference, &paths.server, &server_path, deadline);

            let client_config =
                reference_client_config(method, reference, server, proxy, transport);
            assert_transport_config(&client_config, reference, transport);
            let client_path = write_config(directory.path(), "client.json", &client_config);
            ports.release_proxy();
            run_config_check(
                reference,
                paths.client.as_ref().unwrap_or(&paths.server),
                &client_path,
                deadline,
            );
        }
    }
    directory
        .close()
        .expect("close isolated transport config verification directory");
}

pub(super) fn assert_transport_config(config: &str, reference: Reference, transport: Transport) {
    let marker = match (reference, transport) {
        (Reference::SingBox, Transport::Tcp) => "\"network\":\"tcp\"",
        (Reference::SingBox, Transport::Udp) => "\"network\":\"udp\"",
        (Reference::ShadowsocksRust, Transport::Tcp) => "\"mode\":\"tcp_only\"",
        (Reference::ShadowsocksRust, Transport::Udp) => "\"mode\":\"udp_only\"",
    };
    assert!(
        config.contains(marker)
            || (reference == Reference::ShadowsocksRust
                && transport == Transport::Udp
                && config.contains("\"mode\":\"tcp_and_udp\"")),
        "reference configuration is not explicitly transport-enabled"
    );
}

pub(super) fn run_config_check(
    reference: Reference,
    binary: &Path,
    config: &Path,
    deadline: CaseDeadline,
) {
    let mut command = Command::new(binary);
    match reference {
        Reference::SingBox => {
            command.args(["check", "-c", path_text(config)]);
        }
        Reference::ShadowsocksRust => {
            command.args(["-c", path_text(config)]);
        }
    }
    let mut process = ProcessGuard::spawn("reference config check", &mut command, deadline);
    match reference {
        Reference::SingBox => {
            let status = process.wait_for_exit(deadline, "bounded reference config check");
            let (stdout, stderr) = process.finish_captures(deadline);
            assert!(
                status.success() && !stdout.truncated && !stderr.truncated,
                "reference config check failed: status={status}, stdout={}, stderr={}",
                sanitize_capture(stdout),
                sanitize_capture(stderr)
            );
        }
        Reference::ShadowsocksRust => {
            wait_for_stable_child(&mut process, deadline, "reference config check");
            let _ = process.terminate(deadline);
        }
    }
}

pub(super) fn verify_archive_members(
    reference: Reference,
    archive: &Path,
    pin: &Pin,
    deadline: CaseDeadline,
) {
    let mut command = Command::new("tar");
    match reference {
        Reference::SingBox => {
            command.args(["-tzf", path_text(archive)]);
        }
        Reference::ShadowsocksRust => {
            command.args(["-tJf", path_text(archive)]);
        }
    }
    let mut process = ProcessGuard::spawn("reviewed archive member probe", &mut command, deadline);
    let status = process.wait_for_exit(deadline, "bounded archive member probe");
    let (stdout, stderr) = process.finish_captures(deadline);
    assert!(
        status.success() && !stdout.truncated && !stderr.truncated && stderr.bytes.is_empty(),
        "reviewed archive member probe failed: status={status}, stdout={}, stderr={}",
        sanitize_capture(stdout),
        sanitize_capture(stderr)
    );
    let members = String::from_utf8(stdout.bytes).expect("archive member list must be UTF-8 text");
    let actual: Vec<_> = members.lines().collect();
    let sing_root = format!("sing-box-{}-linux-amd64-glibc", pin.version);
    let expected = match reference {
        Reference::SingBox => vec![
            format!("{sing_root}/"),
            format!("{sing_root}/LICENSE"),
            format!("{sing_root}/sing-box"),
        ],
        Reference::ShadowsocksRust => ["sslocal", "ssserver", "ssurl", "ssmanager", "ssservice"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    };
    assert_eq!(actual, expected, "archive member allowlist mismatch");
    assert!(
        actual.iter().all(|member| {
            let normalized = member.trim_end_matches('/');
            !normalized.starts_with('/')
                && !normalized.split('/').any(|component| component == "..")
                && !normalized.contains('\\')
        }),
        "archive member escaped the safe extraction allowlist"
    );
}

pub(super) fn load_pin(reference: Reference) -> Pin {
    let section = match reference {
        Reference::SingBox => "sing_box",
        Reference::ShadowsocksRust => "shadowsocks_rust",
    };
    pin_from_values(load_pin_values(section))
}

pub(super) fn load_dns_pin(reference: DnsReference) -> Pin {
    pin_from_values(load_pin_values(match reference {
        DnsReference::CoreDns => "coredns",
        DnsReference::Bind => "bind",
    }))
}

pub(super) fn load_pin_values(section: &str) -> HashMap<String, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root");
    let text = fs::read_to_string(root.join("tests/interop/versions.toml"))
        .expect("read interop version pins");
    parse_section(&text, section)
}

pub(super) fn pin_from_values(values: HashMap<String, String>) -> Pin {
    Pin {
        version: value(&values, "version").to_owned(),
        source_commit: value(&values, "source_commit").to_owned(),
        expected_version: value(&values, "expected_version").to_owned(),
        asset: value(&values, "linux_asset").to_owned(),
        url: value(&values, "linux_url").to_owned(),
        size: value(&values, "linux_size")
            .parse()
            .expect("numeric asset size"),
        sha256: value(&values, "linux_sha256").to_owned(),
        license_review: value(&values, "license_review").to_owned(),
    }
}

pub(super) fn panic_diagnostic(payload: Box<dyn std::any::Any + Send>) -> String {
    let text = if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_owned()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "non-text panic".to_owned()
    };
    redact_synthetic_psks(&text)
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .chars()
        .take(4096)
        .collect()
}

pub(super) fn parse_section(text: &str, wanted: &str) -> HashMap<String, String> {
    let mut current = "";
    let mut values = HashMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            current = &line[1..line.len() - 1];
            continue;
        }
        if current != wanted || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, raw_value) = line.split_once('=').expect("pin key/value");
        values.insert(
            key.trim().to_owned(),
            raw_value.trim().trim_matches('"').to_owned(),
        );
    }
    values
}

pub(super) fn value<'a>(values: &'a HashMap<String, String>, key: &str) -> &'a str {
    values
        .get(key)
        .unwrap_or_else(|| panic!("required pin field missing: {key}"))
}

pub(super) fn verify_archive(path: &Path, pin: &Pin, deadline: CaseDeadline) {
    deadline.check("reference archive verification");
    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some(pin.asset.as_str()),
        "reference archive asset name mismatch"
    );
    let metadata = fs::metadata(path).expect("reference archive metadata");
    assert_eq!(metadata.len(), pin.size, "reference archive size mismatch");
    assert_eq!(
        sha256_file_with_deadline(path, deadline),
        pin.sha256,
        "reference archive SHA-256 mismatch"
    );
}

pub(super) fn verify_version(
    reference: Reference,
    binary: &Path,
    pin: &Pin,
    deadline: CaseDeadline,
) {
    let mut command = Command::new(binary);
    match reference {
        Reference::SingBox => {
            command.arg("version");
        }
        Reference::ShadowsocksRust => {
            command.arg("--version");
        }
    }
    let mut process = ProcessGuard::spawn("reference version probe", &mut command, deadline);
    let status = process.wait_for_exit(deadline, "bounded reference version probe");
    let (stdout, stderr) = process.finish_captures(deadline);
    assert!(
        status.success() && !stdout.truncated && !stderr.truncated && stderr.bytes.is_empty(),
        "reference version probe failed: status={status}, stdout={}, stderr={}",
        sanitize_capture(stdout),
        sanitize_capture(stderr)
    );
    let rendered = String::from_utf8(stdout.bytes).expect("reference version output must be UTF-8");
    match reference {
        Reference::SingBox => {
            assert!(
                rendered.lines().any(|line| line == pin.expected_version),
                "sing-box version line mismatch"
            );
            assert!(
                rendered
                    .lines()
                    .any(|line| line == format!("Revision: {}", pin.source_commit)),
                "sing-box source revision mismatch"
            );
        }
        Reference::ShadowsocksRust => assert_eq!(
            rendered.trim_end_matches(['\r', '\n']),
            pin.expected_version,
            "shadowsocks-rust version output mismatch"
        ),
    }
}
