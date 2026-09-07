use std::net::SocketAddr;

use crate::error::{ConfigError, ConfigField};

/// All declared Ferrum2 listeners include TCP (metrics is TCP-only). Therefore
/// any same-family address overlap conflicts, independently of optional UDP.
/// This does not infer dual-stack binding semantics across address families.
pub(super) fn validate_listener(
    address: SocketAddr,
    existing: impl IntoIterator<Item = SocketAddr>,
    field: ConfigField,
) -> Result<(), ConfigError> {
    if existing
        .into_iter()
        .any(|other| sockets_alias(other, address))
    {
        return Err(ConfigError::semantic(field));
    }
    Ok(())
}

pub(super) fn sockets_alias(left: SocketAddr, right: SocketAddr) -> bool {
    left.port() == right.port()
        && left.is_ipv4() == right.is_ipv4()
        && (left.ip() == right.ip() || left.ip().is_unspecified() || right.ip().is_unspecified())
}
