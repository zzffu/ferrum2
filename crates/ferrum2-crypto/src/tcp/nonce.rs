use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::AeadError;
use crate::method::AEAD_NONCE_BYTES;

fn increment_u96_le(value: &mut [u8; AEAD_NONCE_BYTES]) -> Option<()> {
    for byte in value {
        let (next, carried) = byte.overflowing_add(1);
        *byte = next;
        if !carried {
            return Some(());
        }
    }
    None
}

/// A standalone u96le counter fixture seam.
///
/// TCP AEAD owners use an internal counter of the same shape and never accept
/// one from callers.
pub struct NonceCounter {
    bytes: [u8; AEAD_NONCE_BYTES],
}

impl NonceCounter {
    /// Creates the all-zero initial nonce.
    pub const fn new() -> Self {
        Self {
            bytes: [0; AEAD_NONCE_BYTES],
        }
    }

    /// Creates a standalone counter from little-endian bytes.
    ///
    /// This constructor cannot inject state into a `TcpSealer` or `TcpOpener`.
    pub const fn from_le_bytes(bytes: [u8; AEAD_NONCE_BYTES]) -> Self {
        Self { bytes }
    }

    /// Copies the current little-endian bytes for primitive verification.
    pub const fn current_bytes(&self) -> [u8; AEAD_NONCE_BYTES] {
        self.bytes
    }

    /// Advances once, leaving the counter unchanged on overflow.
    pub fn checked_increment(&mut self) -> Result<(), AeadError> {
        let mut next = self.bytes;
        increment_u96_le(&mut next).ok_or(AeadError::NonceExhausted)?;
        self.bytes = next;
        Ok(())
    }
}

impl Default for NonceCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for NonceCounter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NonceCounter([REDACTED])")
    }
}

impl Zeroize for NonceCounter {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for NonceCounter {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for NonceCounter {}

impl NonceCounter {
    /// Reserves the current nonce and advances atomically.
    ///
    /// Overflow returns no nonce and leaves the state unchanged.
    pub fn checked_take(&mut self) -> Result<[u8; AEAD_NONCE_BYTES], AeadError> {
        let (current, next) = self.reserve()?;
        *self = next;
        Ok(current)
    }

    pub(super) fn reserve(&self) -> Result<([u8; AEAD_NONCE_BYTES], Self), AeadError> {
        let mut next = self.bytes;
        increment_u96_le(&mut next).ok_or(AeadError::NonceExhausted)?;
        Ok((self.bytes, Self { bytes: next }))
    }
}
