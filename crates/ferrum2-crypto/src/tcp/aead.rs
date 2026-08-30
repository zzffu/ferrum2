use std::error::Error;
use std::fmt;

use bytes::BytesMut;
use shadowsocks_crypto::v2::tcp::TcpCipher as ShadowsocksTcpCipher;
use zeroize::{Zeroize, Zeroizing};

use super::{NonceCounter, TcpSubkey};
#[cfg(test)]
use crate::method::AEAD_NONCE_BYTES;
use crate::method::AEAD_TAG_BYTES;

/// A method-bound AEAD owner for one outbound TCP direction.
///
/// Construction always initializes its private nonce counter to zero.
pub struct TcpSealer {
    cipher: ShadowsocksTcpCipher,
    pub(super) nonce: NonceCounter,
}

impl TcpSealer {
    /// Consumes a session subkey and creates a zero-nonce sealer.
    pub fn new(subkey: TcpSubkey) -> Self {
        let TcpSubkey { cipher, .. } = subkey;
        Self {
            cipher,
            nonce: NonceCounter::new(),
        }
    }

    /// Encrypts and appends the tag in place with empty associated data.
    pub fn seal_in_place(&mut self, buffer: &mut BytesMut) -> Result<(), AeadError> {
        let (nonce, next) = self.nonce.reserve()?;
        buffer.reserve(AEAD_TAG_BYTES);
        let tag = self
            .cipher
            .encrypt_packet(&nonce, buffer.as_mut())
            .map_err(|_| AeadError::OperationFailed)?;
        buffer.extend_from_slice(&tag);
        self.nonce = next;
        Ok(())
    }
}

/// A method-bound AEAD owner for one inbound TCP direction.
///
/// Construction always initializes its private nonce counter to zero.
pub struct TcpOpener {
    cipher: ShadowsocksTcpCipher,
    nonce: NonceCounter,
    staging: Zeroizing<Vec<u8>>,
}

impl TcpOpener {
    /// Consumes a session subkey and creates a zero-nonce opener.
    pub fn new(subkey: TcpSubkey) -> Self {
        let TcpSubkey { cipher, .. } = subkey;
        Self {
            cipher,
            nonce: NonceCounter::new(),
            staging: Zeroizing::new(Vec::new()),
        }
    }

    /// Authenticates and decrypts a ciphertext-and-tag slice in place.
    ///
    /// Returns the plaintext length on success. After authentication failure,
    /// the contents of `buffer` are unspecified and callers must discard them.
    /// The nonce is committed only after successful authentication. Nonce
    /// exhaustion is checked before touching `buffer`.
    pub fn open_slice_in_place(&mut self, buffer: &mut [u8]) -> Result<usize, AeadError> {
        let (nonce, next) = self.nonce.reserve()?;
        let tag_start = buffer
            .len()
            .checked_sub(AEAD_TAG_BYTES)
            .ok_or(AeadError::AuthenticationFailed)?;
        let tag: [u8; AEAD_TAG_BYTES] = buffer[tag_start..]
            .try_into()
            .unwrap_or_else(|_| unreachable!("validated TCP tag width"));
        self.staging.resize(tag_start, 0);
        self.staging.copy_from_slice(&buffer[..tag_start]);
        if self
            .cipher
            .decrypt_packet(&nonce, self.staging.as_mut(), &tag)
            .is_err()
        {
            self.staging[..tag_start].zeroize();
            return Err(AeadError::AuthenticationFailed);
        }
        buffer[..tag_start].copy_from_slice(self.staging.as_ref());
        self.staging[..tag_start].zeroize();
        self.nonce = next;
        Ok(tag_start)
    }

    /// Authenticates and decrypts in place with empty associated data.
    ///
    /// After authentication failure, the contents of `buffer` are unspecified
    /// and callers must discard them. Nonce exhaustion leaves both the buffer
    /// and counter unchanged.
    pub fn open_in_place(&mut self, buffer: &mut BytesMut) -> Result<(), AeadError> {
        let plaintext_len = self.open_slice_in_place(buffer.as_mut())?;
        buffer.truncate(plaintext_len);
        Ok(())
    }
}

/// A closed AES operation error which contains no key, nonce, or source error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AeadError {
    /// Authentication failed and no plaintext was accepted.
    AuthenticationFailed,
    /// The primitive rejected the in-place operation.
    OperationFailed,
    /// No unused nonce remains for this owner.
    NonceExhausted,
}

impl fmt::Display for AeadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::AuthenticationFailed => "authentication failed",
            Self::OperationFailed => "encryption failed",
            Self::NonceExhausted => "nonce exhausted",
        };
        formatter.write_str(message)
    }
}

impl Error for AeadError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method::{AES_128_KEY_BYTES, MethodProfile, WIDE_KEY_BYTES};

    const EXHAUSTED_NONCE: [u8; AEAD_NONCE_BYTES] = [u8::MAX; AEAD_NONCE_BYTES];

    #[test]
    fn tcp_owner_nonce_exhaustion_sealer_fails_closed() {
        for subkey in [
            TcpSubkey::from_bytes([0x11; AES_128_KEY_BYTES]),
            TcpSubkey::from_subkey(MethodProfile::Blake3Aes256Gcm2022, [0x22; WIDE_KEY_BYTES]),
            TcpSubkey::from_subkey(
                MethodProfile::Blake3ChaCha20Poly13052022,
                [0x33; WIDE_KEY_BYTES],
            ),
        ] {
            let mut sealer = TcpSealer::new(subkey);
            sealer.nonce = NonceCounter::from_le_bytes(EXHAUSTED_NONCE);
            let mut plaintext = BytesMut::from(&b"plaintext remains unchanged"[..]);
            let original_plaintext = plaintext.clone();

            assert_eq!(
                sealer.seal_in_place(&mut plaintext),
                Err(AeadError::NonceExhausted)
            );
            assert_eq!(plaintext, original_plaintext);
            assert_eq!(sealer.nonce.current_bytes(), EXHAUSTED_NONCE);

            assert_eq!(
                sealer.seal_in_place(&mut plaintext),
                Err(AeadError::NonceExhausted)
            );
            assert_eq!(plaintext, original_plaintext);
            assert_eq!(sealer.nonce.current_bytes(), EXHAUSTED_NONCE);
        }
    }

    #[test]
    fn tcp_owner_nonce_exhaustion_opener_fails_closed() {
        for subkey in [
            TcpSubkey::from_bytes([0x44; AES_128_KEY_BYTES]),
            TcpSubkey::from_subkey(MethodProfile::Blake3Aes256Gcm2022, [0x55; WIDE_KEY_BYTES]),
            TcpSubkey::from_subkey(
                MethodProfile::Blake3ChaCha20Poly13052022,
                [0x66; WIDE_KEY_BYTES],
            ),
        ] {
            let mut opener = TcpOpener::new(subkey);
            opener.nonce = NonceCounter::from_le_bytes(EXHAUSTED_NONCE);
            let mut ciphertext = BytesMut::from(&b"ciphertext and tag remain unchanged"[..]);
            let original_ciphertext = ciphertext.clone();

            assert_eq!(
                opener.open_slice_in_place(ciphertext.as_mut()),
                Err(AeadError::NonceExhausted)
            );
            assert_eq!(ciphertext, original_ciphertext);
            assert_eq!(opener.nonce.current_bytes(), EXHAUSTED_NONCE);

            assert_eq!(
                opener.open_slice_in_place(ciphertext.as_mut()),
                Err(AeadError::NonceExhausted)
            );
            assert_eq!(ciphertext, original_ciphertext);
            assert_eq!(opener.nonce.current_bytes(), EXHAUSTED_NONCE);
        }
    }

    #[test]
    fn tcp_opener_slice_decrypts_without_replacing_storage() {
        let subkey = TcpSubkey::from_bytes([0x77; AES_128_KEY_BYTES]);
        let mut sealer = TcpSealer::new(TcpSubkey::from_bytes([0x77; AES_128_KEY_BYTES]));
        let mut wire = BytesMut::from(&b"caller-owned fixed backing"[..]);
        sealer.seal_in_place(&mut wire).expect("fixture seals");

        let storage = wire.as_ptr();
        let wire_len = wire.len();
        let mut opener = TcpOpener::new(subkey);
        let plaintext_len = opener
            .open_slice_in_place(&mut wire[..wire_len])
            .expect("fixture authenticates");

        assert_eq!(wire.as_ptr(), storage);
        assert_eq!(&wire[..plaintext_len], b"caller-owned fixed backing");
        assert_eq!(plaintext_len + AEAD_TAG_BYTES, wire_len);
    }

    #[test]
    fn tcp_opener_slice_short_tag_does_not_consume_nonce() {
        let subkey = TcpSubkey::from_bytes([0x78; AES_128_KEY_BYTES]);
        let mut sealer = TcpSealer::new(TcpSubkey::from_bytes([0x78; AES_128_KEY_BYTES]));
        let mut valid = BytesMut::from(&b"nonce zero remains available"[..]);
        sealer.seal_in_place(&mut valid).expect("fixture seals");
        let mut opener = TcpOpener::new(subkey);
        let mut short = [0xa5; AEAD_TAG_BYTES - 1];

        assert_eq!(
            opener.open_slice_in_place(&mut short),
            Err(AeadError::AuthenticationFailed)
        );
        let plaintext_len = opener
            .open_slice_in_place(valid.as_mut())
            .expect("short input did not consume nonce zero");
        assert_eq!(&valid[..plaintext_len], b"nonce zero remains available");
    }
}
