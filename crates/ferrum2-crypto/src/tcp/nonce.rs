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

/// Private exhaustion-safe TCP nonce state.
pub(super) struct NonceCounter {
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
    #[cfg(test)]
    pub(super) const fn from_le_bytes(bytes: [u8; AEAD_NONCE_BYTES]) -> Self {
        Self { bytes }
    }

    /// Copies the current little-endian bytes for primitive verification.
    #[cfg(test)]
    pub(super) const fn current_bytes(&self) -> [u8; AEAD_NONCE_BYTES] {
        self.bytes
    }

    /// Advances once, leaving the counter unchanged on overflow.
    #[cfg(test)]
    pub(super) fn checked_increment(&mut self) -> Result<(), AeadError> {
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
    #[cfg(test)]
    pub(super) fn checked_take(&mut self) -> Result<[u8; AEAD_NONCE_BYTES], AeadError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nonce_counter_starts_at_zero_carries_and_checks_overflow() {
        let mut zero = NonceCounter::new();
        assert_eq!(zero.current_bytes(), [0; 12]);
        zero.checked_increment().expect("zero increments");
        assert_eq!(zero.current_bytes(), [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let mut carry = NonceCounter::from_le_bytes([0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        carry.checked_increment().expect("carry increments");
        assert_eq!(carry.current_bytes(), [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let mut exhausted = NonceCounter::from_le_bytes([0xff; 12]);
        assert!(exhausted.checked_increment().is_err());
        assert_eq!(exhausted.current_bytes(), [0xff; 12]);
    }
    #[test]
    fn nonce_overflow_returns_no_nonce_and_preserves_state() {
        let mut counter = NonceCounter::from_le_bytes([0xff; 12]);
        assert_eq!(counter.checked_take(), Err(AeadError::NonceExhausted));
        assert_eq!(counter.current_bytes(), [0xff; 12]);
    }
    #[test]
    fn nonce_counter_has_explicit_clear_and_drop_zeroizing_contract() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<NonceCounter>();

        let mut counter = NonceCounter::from_le_bytes([0x5a; 12]);
        counter.zeroize();
        assert_eq!(counter.current_bytes(), [0; 12]);
    }
}
