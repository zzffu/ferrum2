//! AEAD 2022 Ciphers

pub(crate) mod crypto;
pub mod tcp;
pub mod udp;

/// Closed failure for Ferrum's checked v2 primitive boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    InvalidMethod,
    InvalidKeyLength,
    InvalidSaltLength,
    InvalidSessionId,
    InvalidNonceLength,
    OperationFailed,
    AuthenticationFailed,
}

/// AEAD2022 protocol Blake3 KDF context
pub const BLAKE3_KEY_DERIVE_CONTEXT: &str = "shadowsocks 2022 session subkey";
