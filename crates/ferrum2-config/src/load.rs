use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::MAX_CONFIG_BYTES;
use crate::error::{ConfigError, ConfigErrorKind, ConfigField};
use crate::model::{ValidatedClientConfig, ValidatedServerConfig};
use crate::prepared::{validate_client_source, validate_server_source};
use crate::validation::validate_version;

#[derive(Deserialize)]
struct RawSchemaRoot {
    schema_version: Option<u32>,
}

/// Reads and fully validates a client configuration without creating runtime resources.
pub fn load_client(path: impl AsRef<Path>) -> Result<ValidatedClientConfig, ConfigError> {
    let source = read_bounded_utf8(path.as_ref())?;
    parse_client_source(&source)
}

/// Reads and fully validates a server configuration without creating runtime resources.
pub fn load_server(path: impl AsRef<Path>) -> Result<ValidatedServerConfig, ConfigError> {
    let source = read_bounded_utf8(path.as_ref())?;
    parse_server_source(&source)
}

fn parse_client_source(source: &str) -> Result<ValidatedClientConfig, ConfigError> {
    validate_client_source(source)
}

fn parse_server_source(source: &str) -> Result<ValidatedServerConfig, ConfigError> {
    validate_server_source(source)
}

#[cfg(feature = "fuzzing")]
fn fuzz_source(input: &[u8]) -> Result<Zeroizing<String>, ConfigError> {
    if input.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::new(
            ConfigErrorKind::TooLarge,
            ConfigField::Config,
        ));
    }
    let source = std::str::from_utf8(input)
        .map_err(|_| ConfigError::new(ConfigErrorKind::Syntax, ConfigField::Config))?;
    Ok(Zeroizing::new(source.to_owned()))
}

/// Runs the production client parser and validator over one bounded in-memory fuzz input.
#[cfg(feature = "fuzzing")]
pub fn fuzz_parse_client(input: &[u8]) -> Result<(), ConfigError> {
    let source = fuzz_source(input)?;
    parse_client_source(&source).map(drop)
}

/// Runs the production server parser and validator over one bounded in-memory fuzz input.
#[cfg(feature = "fuzzing")]
pub fn fuzz_parse_server(input: &[u8]) -> Result<(), ConfigError> {
    let source = fuzz_source(input)?;
    parse_server_source(&source).map(drop)
}

pub(super) fn read_bounded_utf8(path: &Path) -> Result<Zeroizing<String>, ConfigError> {
    let file =
        File::open(path).map_err(|_| ConfigError::new(ConfigErrorKind::Io, ConfigField::Config))?;
    let metadata = file
        .metadata()
        .map_err(|_| ConfigError::new(ConfigErrorKind::Io, ConfigField::Config))?;
    if metadata.len() > MAX_CONFIG_BYTES as u64 {
        return Err(ConfigError::new(
            ConfigErrorKind::TooLarge,
            ConfigField::Config,
        ));
    }

    let mut source = Zeroizing::new(String::new());
    let mut bounded = file.take((MAX_CONFIG_BYTES + 1) as u64);
    match bounded.read_to_string(&mut source) {
        Ok(_) if source.len() > MAX_CONFIG_BYTES => Err(ConfigError::new(
            ConfigErrorKind::TooLarge,
            ConfigField::Config,
        )),
        Ok(_) => Ok(source),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => Err(ConfigError::new(
            ConfigErrorKind::Syntax,
            ConfigField::Config,
        )),
        Err(_) => Err(ConfigError::new(ConfigErrorKind::Io, ConfigField::Config)),
    }
}

pub(super) fn parse_toml<'a, T: Deserialize<'a>>(source: &'a str) -> Result<T, ConfigError> {
    toml::from_str(source)
        .map_err(|_| ConfigError::new(ConfigErrorKind::Syntax, ConfigField::Config))
}

pub(super) fn parse_v2_toml<'a, T: Deserialize<'a>>(source: &'a str) -> Result<T, ConfigError> {
    let root: RawSchemaRoot = parse_toml(source)?;
    let version = root
        .schema_version
        .ok_or_else(|| ConfigError::semantic(ConfigField::SchemaVersion))?;
    validate_version(version)?;
    parse_toml(source)
}
