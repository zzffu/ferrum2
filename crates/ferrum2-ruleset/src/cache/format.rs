use ferrum2_rule::MatchSetCapabilities;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{RuleSetLoadError, RuleSetLoadErrorKind};

pub(super) const HEADER_BYTES: usize = 64;
pub(crate) const MAX_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_METADATA_BYTES: usize = 64 * 1024;
pub(crate) const MAX_URL_BYTES: usize = 8 * 1024;
pub(crate) const MAX_ETAG_BYTES: usize = 1024;
pub(crate) const MAX_LAST_MODIFIED_BYTES: usize = 128;
const MAGIC: &[u8; 8] = b"FRSCache";
const SCHEMA: u32 = 1;

pub(super) struct Header {
    pub(super) payload_bytes: u64,
    pub(super) metadata_bytes: usize,
    pub(super) metadata_digest: [u8; 32],
}

impl Header {
    pub(super) fn decode(bytes: [u8; HEADER_BYTES], total: u64) -> Result<Self, RuleSetLoadError> {
        let invalid = || RuleSetLoadError::new(RuleSetLoadErrorKind::CacheMetadata);
        if &bytes[..8] != MAGIC
            || bytes[8..12] != SCHEMA.to_be_bytes()
            || bytes[12..16] != [0; 4]
            || bytes[28..32] != [0; 4]
        {
            return Err(invalid());
        }
        let payload_bytes = u64::from_be_bytes(bytes[16..24].try_into().map_err(|_| invalid())?);
        let metadata_bytes =
            u32::from_be_bytes(bytes[24..28].try_into().map_err(|_| invalid())?) as usize;
        if payload_bytes == 0
            || payload_bytes > MAX_PAYLOAD_BYTES
            || metadata_bytes == 0
            || metadata_bytes > MAX_METADATA_BYTES
        {
            return Err(RuleSetLoadError::new(RuleSetLoadErrorKind::CacheLimit));
        }
        if total != HEADER_BYTES as u64 + payload_bytes + metadata_bytes as u64 {
            return Err(invalid());
        }
        Ok(Self {
            payload_bytes,
            metadata_bytes,
            metadata_digest: bytes[32..].try_into().map_err(|_| invalid())?,
        })
    }

    pub(super) fn encode(payload_bytes: u64, metadata: &[u8]) -> [u8; HEADER_BYTES] {
        let mut header = [0; HEADER_BYTES];
        header[..8].copy_from_slice(MAGIC);
        header[8..12].copy_from_slice(&SCHEMA.to_be_bytes());
        header[16..24].copy_from_slice(&payload_bytes.to_be_bytes());
        header[24..28].copy_from_slice(&(metadata.len() as u32).to_be_bytes());
        header[32..].copy_from_slice(&Sha256::digest(metadata));
        header
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CacheMetadata {
    pub(super) schema: u32,
    pub(super) url: String,
    pub(super) etag: Option<String>,
    pub(super) last_modified: Option<String>,
    pub(super) downloaded_unix_seconds: u64,
    pub(super) sha256: String,
    pub(super) srs_version: u8,
    pub(super) capabilities: SerializableCapabilities,
    pub(super) generation: u64,
}

impl CacheMetadata {
    pub(super) fn valid(&self, url: &str) -> bool {
        self.schema == SCHEMA
            && self.url == url
            && self.url.len() <= MAX_URL_BYTES
            && validators_valid(self.etag.as_deref(), self.last_modified.as_deref())
            && self.sha256.len() == 64
            && self
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }
}

pub(crate) fn validators_valid(etag: Option<&str>, modified: Option<&str>) -> bool {
    etag.is_none_or(|value| value.len() <= MAX_ETAG_BYTES && !value.chars().any(char::is_control))
        && modified.is_none_or(|value| {
            value.len() <= MAX_LAST_MODIFIED_BYTES && !value.chars().any(char::is_control)
        })
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SerializableCapabilities {
    exact_domain: bool,
    domain_suffix: bool,
    domain_keyword: bool,
    ip_cidr: bool,
}

impl From<MatchSetCapabilities> for SerializableCapabilities {
    fn from(value: MatchSetCapabilities) -> Self {
        Self {
            exact_domain: value.exact_domain,
            domain_suffix: value.domain_suffix,
            domain_keyword: value.domain_keyword,
            ip_cidr: value.ip_cidr,
        }
    }
}
