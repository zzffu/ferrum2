use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{Read, Write};
use std::path::PathBuf;

use ferrum2_config::{ConfigErrorKind, MAX_CONFIG_BYTES, PreparedClientV2, prepare_client_source};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize)]
pub struct ConfigDocument {
    pub source: String,
    pub revision: String,
}

impl fmt::Debug for ConfigDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigDocument")
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl Drop for ConfigDocument {
    fn drop(&mut self) {
        self.source.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigStoreError {
    Io,
    TooLarge,
    Invalid,
    Conflict,
    UnsafePath,
}

impl ConfigStoreError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Io => "config.io",
            Self::TooLarge => "config.too_large",
            Self::Invalid => "config.invalid",
            Self::Conflict => "config.conflict",
            Self::UnsafePath => "config.unsafe_path",
        }
    }
}

impl fmt::Display for ConfigStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ConfigStoreError {}

/// Owns one startup-selected path. No operation accepts a replacement path.
pub struct ConfigStore {
    path: PathBuf,
}

impl ConfigStore {
    pub fn open(path: PathBuf) -> Result<Self, ConfigStoreError> {
        let path = std::path::absolute(path).map_err(|_| ConfigStoreError::Io)?;
        let store = Self { path };
        store.read()?;
        Ok(store)
    }

    fn metadata(&self) -> Result<Metadata, ConfigStoreError> {
        let metadata = fs::symlink_metadata(&self.path).map_err(|_| ConfigStoreError::Io)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(ConfigStoreError::UnsafePath);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(ConfigStoreError::UnsafePath);
            }
        }
        if metadata.len() > MAX_CONFIG_BYTES as u64 {
            return Err(ConfigStoreError::TooLarge);
        }
        Ok(metadata)
    }

    pub fn read(&self) -> Result<ConfigDocument, ConfigStoreError> {
        self.metadata()?;
        let file = File::open(&self.path).map_err(|_| ConfigStoreError::Io)?;
        if file.metadata().map_err(|_| ConfigStoreError::Io)?.len() > MAX_CONFIG_BYTES as u64 {
            return Err(ConfigStoreError::TooLarge);
        }
        let mut source = Zeroizing::new(String::new());
        file.take((MAX_CONFIG_BYTES + 1) as u64)
            .read_to_string(&mut source)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::InvalidData {
                    ConfigStoreError::Invalid
                } else {
                    ConfigStoreError::Io
                }
            })?;
        if source.len() > MAX_CONFIG_BYTES {
            return Err(ConfigStoreError::TooLarge);
        }
        let revision = revision(&source);
        Ok(ConfigDocument {
            source: std::mem::take(&mut *source),
            revision,
        })
    }

    pub fn validate(&self, source: &str) -> Result<PreparedClientV2, ConfigStoreError> {
        validate(source)
    }

    pub fn save(
        &mut self,
        source: &str,
        expected_revision: &str,
    ) -> Result<ConfigDocument, ConfigStoreError> {
        self.validate(source)?;
        if self.read()?.revision != expected_revision {
            return Err(ConfigStoreError::Conflict);
        }
        let metadata = self.metadata()?;
        let permissions = metadata.permissions();
        let parent = self.path.parent().ok_or(ConfigStoreError::UnsafePath)?;
        #[cfg(windows)]
        let mut temporary = tempfile::Builder::new()
            .make_in(parent, |path| {
                ferrum2_platform_windows::create_config_temporary(&self.path, path)
            })
            .map_err(|_| ConfigStoreError::Io)?;
        #[cfg(not(windows))]
        let mut temporary =
            tempfile::NamedTempFile::new_in(parent).map_err(|_| ConfigStoreError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            // Supporting group ACL migration would require a different security contract.
            // Reject it rather than copying group bits onto a new inherited group/ACL.
            if permissions.mode() & 0o077 != 0
                || temporary
                    .as_file()
                    .metadata()
                    .map_err(|_| ConfigStoreError::Io)?
                    .uid()
                    != metadata.uid()
            {
                return Err(ConfigStoreError::UnsafePath);
            }
        }
        temporary
            .as_file()
            .set_permissions(permissions)
            .map_err(|_| ConfigStoreError::Io)?;
        temporary
            .write_all(source.as_bytes())
            .map_err(|_| ConfigStoreError::Io)?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|_| ConfigStoreError::Io)?;
        // Re-read immediately before replacement: external edits made while preparing are conflicts.
        if self.read()?.revision != expected_revision {
            return Err(ConfigStoreError::Conflict);
        }
        #[cfg(windows)]
        {
            let temporary = temporary.into_temp_path();
            ferrum2_platform_windows::replace_config_file(&self.path, &temporary)
                .map_err(|_| ConfigStoreError::Io)?;
        }
        #[cfg(not(windows))]
        temporary
            .persist(&self.path)
            .map_err(|_| ConfigStoreError::Io)?;
        Ok(ConfigDocument {
            source: source.to_owned(),
            revision: revision(source),
        })
    }
}

fn revision(source: &str) -> String {
    hex::encode(Sha256::digest(source.as_bytes()))
}

fn validate(source: &str) -> Result<PreparedClientV2, ConfigStoreError> {
    prepare_client_source(source).map_err(|error| {
        if error.kind() == ConfigErrorKind::TooLarge {
            ConfigStoreError::TooLarge
        } else {
            ConfigStoreError::Invalid
        }
    })
}

/// A separate, allowlisted projection; never use this value as editable configuration source.
/// Endpoint addresses, URLs, TLS/auth objects, paths and credentials are never copied.
pub fn catalog(source: &str) -> Result<Value, ConfigStoreError> {
    validate(source)?;
    let mut root: toml::Value = toml::from_str(source).map_err(|_| ConfigStoreError::Invalid)?;
    let mut route = project(root.get("route"), &["final", "auto_detect_interface"]);
    route["rules"] = rows(
        root.get("route").and_then(|v| v.get("rules")),
        &[
            "action",
            "outbound",
            "inbound",
            "network",
            "protocol",
            "rule_set",
            "port",
            "port_range",
            "sniffers",
        ],
    );
    route["rule_set"] = rows(
        root.get("route").and_then(|v| v.get("rule_set")),
        &["tag", "type", "format", "update_interval_seconds"],
    );
    let dns = root.get("dns").map(|dns| {
        let mut value = project(Some(dns), &["strategy", "timeout_ms", "max_inflight"]);
        value["servers"] = rows(
            dns.get("servers"),
            &["tag", "transport", "detour", "domain_strategy"],
        );
        value["inbounds"] = rows(dns.get("inbounds"), &["tag"]);
        value["cache"] = project(dns.get("cache"), &["enabled", "max_entries"]);
        let mut route = project(dns.get("route"), &["final"]);
        route["rules"] = rows(
            dns.get("route").and_then(|v| v.get("rules")),
            &[
                "action",
                "server",
                "outbound",
                "strategy",
                "qtype",
                "rule_set",
                "match_response",
            ],
        );
        value["route"] = route;
        value
    });
    let result = json!({
        "inbounds": rows(root.get("inbounds"), &["tag", "outbound"]),
        "outbounds": rows(root.get("outbounds"), &["tag", "type", "method", "domain_strategy"]),
        "selectors": rows(root.get("selectors"), &["tag", "outbounds", "default"]),
        "chains": rows(root.get("chains"), &["tag", "hops"]),
        "route": route,
        "dns": dns,
        "tun": root.get("tun").map(|v| project(Some(v), &["mtu", "auto_route", "strict_route", "max_tcp_flows", "max_udp_mappings"])),
        "rocom": root.get("rocom").map(|v| project(Some(v), &["enabled", "max_bytes"]))
    });
    erase_strings(&mut root);
    Ok(result)
}

fn erase_strings(value: &mut toml::Value) {
    match value {
        toml::Value::String(value) => value.zeroize(),
        toml::Value::Array(values) => values.iter_mut().for_each(erase_strings),
        toml::Value::Table(values) => values
            .iter_mut()
            .for_each(|(_, value)| erase_strings(value)),
        _ => {}
    }
}

fn project(value: Option<&toml::Value>, fields: &[&str]) -> Value {
    let mut result = serde_json::Map::new();
    for field in fields {
        if let Some(value) = value.and_then(|v| v.get(*field)) {
            // Only scalars and scalar arrays are accepted; no new nested schema leaks by accident.
            if let Some(value) = scalar(value) {
                result.insert((*field).to_owned(), value);
            }
        }
    }
    Value::Object(result)
}

fn scalar(value: &toml::Value) -> Option<Value> {
    match value {
        toml::Value::String(value) => Some(json!(value)),
        toml::Value::Integer(value) => Some(json!(value)),
        toml::Value::Boolean(value) => Some(json!(value)),
        toml::Value::Array(values) => values
            .iter()
            .map(|value| match value {
                toml::Value::String(_) | toml::Value::Integer(_) | toml::Value::Boolean(_) => {
                    scalar(value)
                }
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .map(Value::Array),
        _ => None,
    }
}

fn rows(value: Option<&toml::Value>, fields: &[&str]) -> Value {
    Value::Array(
        value
            .and_then(toml::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .map(|value| project(Some(value), fields))
                    .collect()
            })
            .unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "schema_version = 2\n[[inbounds]]\ntag = 'proxy'\nlisten = '127.0.0.1:1080'\n[[outbounds]]\ntag = 'direct'\ntype = 'direct'\n[route]\nfinal = 'direct'\n";

    fn store() -> (tempfile::TempDir, ConfigStore) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        fs::write(&path, VALID).unwrap();
        (directory, ConfigStore::open(path).unwrap())
    }

    #[test]
    fn invalid_source_does_not_replace_original() {
        let (_directory, mut store) = store();
        let before = store.read().unwrap();
        assert_eq!(
            store.save("invalid", &before.revision).unwrap_err(),
            ConfigStoreError::Invalid
        );
        assert_eq!(store.read().unwrap().source, before.source);
    }

    #[test]
    fn external_edit_conflicts_and_remains_on_disk() {
        let (_directory, mut store) = store();
        let before = store.read().unwrap();
        let external = format!("{VALID}\n# external edit\n");
        fs::write(&store.path, &external).unwrap();
        assert_eq!(
            store.save(VALID, &before.revision).unwrap_err(),
            ConfigStoreError::Conflict
        );
        assert_eq!(store.read().unwrap().source, external);
    }

    #[test]
    fn bounded_source_and_disk_reads_reject_excess() {
        let (_directory, mut store) = store();
        let before = store.read().unwrap();
        let excess = " ".repeat(MAX_CONFIG_BYTES + 1);
        assert_eq!(
            store.validate(&excess).unwrap_err(),
            ConfigStoreError::TooLarge
        );
        assert_eq!(
            store.save(&excess, &before.revision).unwrap_err(),
            ConfigStoreError::TooLarge
        );
        assert_eq!(store.read().unwrap().source, VALID);
        fs::write(&store.path, excess).unwrap();
        assert_eq!(store.read().unwrap_err(), ConfigStoreError::TooLarge);
    }

    #[test]
    fn exact_source_limit_is_accepted_by_production_parser() {
        let (_directory, store) = store();
        let mut source = VALID.to_owned();
        source.push('#');
        source.extend(std::iter::repeat_n('x', MAX_CONFIG_BYTES - source.len()));
        store.validate(&source).unwrap();
        source.push('x');
        assert_eq!(
            prepare_client_source(&source).unwrap_err().kind(),
            ConfigErrorKind::TooLarge
        );
    }

    #[cfg(unix)]
    #[test]
    fn replacement_preserves_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let (_directory, mut store) = store();
        fs::set_permissions(&store.path, fs::Permissions::from_mode(0o600)).unwrap();
        let before = store.read().unwrap();
        store
            .save(&format!("{VALID}\n# change\n"), &before.revision)
            .unwrap();
        assert_eq!(
            fs::metadata(&store.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn successful_replacement_preserves_true_source_and_revises() {
        let (_directory, mut store) = store();
        let before = store.read().unwrap();
        let edited = format!("{VALID}\n# retained comment\n");
        let saved = store.save(&edited, &before.revision).unwrap();
        assert_eq!(store.read().unwrap().source, edited);
        assert_ne!(saved.revision, before.revision);
        assert_eq!(saved.revision, store.read().unwrap().revision);
    }

    #[test]
    fn catalog_excludes_credentials_tls_endpoints_and_remote_resource_locations() {
        let source = VALID.replace("type = 'direct'", "type = 'shadowsocks'\nserver = '192.0.2.10:8443'\nmethod = '2022-blake3-aes-128-gcm'\npsk = 'AAECAwQFBgcICQoLDA0ODw=='");
        let source = format!(
            "{source}\n[[route.rule_set]]\ntag = 'rules'\ntype = 'remote'\nformat = 'binary'\nurl = 'https://private-rules.example/rules.srs'\ndownload_resolver = 'secure'\n[dns]\n[[dns.inbounds]]\ntag = 'dns-in'\nlisten = '127.0.0.1:1053'\n[[dns.servers]]\ntag = 'secure'\ntransport = 'doh'\naddress = '192.0.2.53:443'\nserver_name = 'private-endpoint.example'\npath = '/private-dns-query'\n[dns.route]\nfinal = 'secure'\n[rocom]\nrecord_path = 'private-recordings/session.tsf4g'\n"
        );
        let value = catalog(&source).unwrap();
        assert_eq!(
            value["outbounds"][0],
            json!({"tag": "direct", "type": "shadowsocks", "method": "2022-blake3-aes-128-gcm"})
        );
        assert_eq!(
            value["route"]["rule_set"][0],
            json!({"tag": "rules", "type": "remote", "format": "binary"})
        );
        assert_eq!(
            value["dns"]["servers"][0],
            json!({"tag": "secure", "transport": "doh"})
        );
        assert_eq!(value["rocom"], json!({}));
        let rendered = value.to_string();
        for secret in [
            "AAECAwQFBgcICQoLDA0ODw==",
            "private-endpoint",
            "private-rules",
            "192.0.2.10",
            "192.0.2.53",
            "private-dns-query",
            "private-recordings",
            "psk",
            "server_name",
            "record_path",
            "url",
        ] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn catalog_and_debug_exclude_credentials_and_endpoints() {
        let source = VALID.replace("type = 'direct'", "type = 'shadowsocks'\nserver = '192.0.2.19:8388'\nmethod = '2022-blake3-aes-128-gcm'\npsk = 'AAECAwQFBgcICQoLDA0ODw=='");
        let value = catalog(&source).unwrap();
        assert_eq!(
            value["outbounds"][0],
            json!({"tag":"direct", "type":"shadowsocks", "method":"2022-blake3-aes-128-gcm"})
        );
        let rendered = value.to_string();
        for secret in [
            "AAECAwQFBgcICQoLDA0ODw==",
            "192.0.2.19",
            "127.0.0.1",
            "psk",
            "password",
            "token_file",
        ] {
            assert!(!rendered.contains(secret));
        }
        let document = ConfigDocument {
            revision: revision(&source),
            source,
        };
        assert!(!format!("{document:?}").contains("AAECAwQFBgcICQoLDA0ODw=="));
    }
}
