use std::fmt::Write as _;

use ferrum2_config::{ConfigErrorKind, ConfigField, fuzz_parse_client, fuzz_parse_server};

/// Hard input bound for legacy configuration-field rejection cases.
pub const MAX_CONFIG_LEGACY_FUZZ_INPUT_BYTES: usize = 4 * 1024;

const CLIENT_BASE: &str = "schema_version = 2\n\
[[inbounds]]\n\
tag = \"in\"\n\
listen = \"127.0.0.1:1080\"\n\
outbound = \"exit\"\n\
[[outbounds]]\n\
tag = \"exit\"\n\
type = \"direct\"\n";

const SERVER_BASE: &str = "schema_version = 2\n\
[[inbounds]]\n\
tag = \"in\"\n\
listen = \"127.0.0.1:8388\"\n\
outbound = \"exit\"\n\
[[outbounds]]\n\
tag = \"exit\"\n\
type = \"direct\"\n";

/// Injects removed schema shapes and unsupported schema versions, then requires the production
/// parser and validator to reject them with their exact closed error category and field.
pub fn fuzz_config_legacy_fields(input: &[u8]) {
    if input.len() > MAX_CONFIG_LEGACY_FUZZ_INPUT_BYTES {
        return;
    }
    let selector = input.first().copied().unwrap_or_default() % 8;
    let value = hex_string(input.get(1..).unwrap_or_default());
    let port = input
        .get(1..3)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_le_bytes)
        .map_or(1, |port| port.max(1));
    let source = match selector {
        0 => format!(
            "{CLIENT_BASE}[route]\nfinal = \"exit\"\n[[route.rules]]\n\
             target = {{ host = \"{value}\", port = {port} }}\naction = \"reject\"\n"
        ),
        1 => format!(
            "{SERVER_BASE}[route]\nfinal = \"exit\"\n[[route.rules]]\n\
             action = \"reject\"\n[route.rules.target]\nhost = \"{value}\"\nport = {port}\n"
        ),
        2 => format!(
            "{CLIENT_BASE}[dns]\n[[dns.servers]]\ntag = \"dns\"\ntransport = \"udp\"\n\
             address = \"192.0.2.53:53\"\n[dns.route]\nfinal = \"dns\"\n\
             [[dns.route.rules]]\ntarget = {{ host = \"{value}\", port = {port} }}\n\
             server = \"dns\"\n"
        ),
        3 => format!(
            "{SERVER_BASE}[dns]\n[[dns.servers]]\ntag = \"dns\"\ntransport = \"udp\"\n\
             address = \"192.0.2.53:53\"\n[dns.route]\nfinal = \"dns\"\n\
             [[dns.route.rules]]\ntarget = {{ host = \"{value}\", port = {port} }}\n\
             server = \"dns\"\n"
        ),
        4 => format!(
            "schema_version = 2\n[tun]\ntag = \"tun-in\"\nadapter_name = \"Ferrum2\"\n\
             ipv4_address = \"198.18.0.2/30\"\nmax_udp_buffered_bytes = {}\n\
             outbound = \"proxy\"\n[[outbounds]]\ntag = \"proxy\"\n\
             server = \"192.0.2.10:8388\"\n[shadowsocks]\n\
             method = \"2022-blake3-aes-128-gcm\"\n\
             psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n",
            u32::from(port)
        ),
        5 => format!(
            "schema_version = 1\n[client]\nlisten = \"127.0.0.1:{port}\"\n\
             server = \"{value}\"\n[rule_set_loader]\ncache_dir = \"./legacy-cache\"\n"
        ),
        6 => format!(
            "[client]\nlisten = \"127.0.0.1:{port}\"\nserver = \"{value}\"\n\
             [rule_set_loader]\ncache_dir = \"./legacy-cache\"\n"
        ),
        _ => format!(
            "schema_version = 3\n[client]\nlisten = \"127.0.0.1:{port}\"\n\
             server = \"{value}\"\n[rule_set_loader]\ncache_dir = \"./legacy-cache\"\n"
        ),
    };
    let result = if matches!(selector, 1 | 3) {
        fuzz_parse_server(source.as_bytes())
    } else {
        fuzz_parse_client(source.as_bytes())
    };
    let error = result.expect_err("legacy or unsupported configuration was accepted");
    let expected = if selector <= 4 {
        (ConfigErrorKind::Syntax, ConfigField::Config)
    } else {
        (ConfigErrorKind::Semantic, ConfigField::SchemaVersion)
    };
    assert_eq!((error.kind(), error.field()), expected);
}

fn hex_string(input: &[u8]) -> String {
    let mut encoded = String::with_capacity(input.len().saturating_mul(2));
    for byte in input {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String is infallible");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_removed_shape_reaches_the_production_rejection_path() {
        for selector in 0..8_u8 {
            fuzz_config_legacy_fields(&[selector, 0, 53, 0xff]);
        }
    }
}
