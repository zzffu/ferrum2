use std::error::Error;
use std::fmt;

use bytes::BytesMut;
use shadowsocks_crypto::v2::tcp::TcpCipher as ShadowsocksTcpCipher;

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
        self.seal_suffix_in_place(buffer, 0)
    }

    /// Encrypts the bytes starting at `plaintext_start` and appends their tag.
    ///
    /// Bytes before `plaintext_start` remain unchanged. An invalid start or nonce
    /// exhaustion leaves the buffer and counter unchanged.
    pub fn seal_suffix_in_place(
        &mut self,
        buffer: &mut BytesMut,
        plaintext_start: usize,
    ) -> Result<(), AeadError> {
        if plaintext_start > buffer.len() {
            return Err(AeadError::OperationFailed);
        }
        let (nonce, next) = self.nonce.reserve()?;
        buffer.reserve(AEAD_TAG_BYTES);
        let tag = self
            .cipher
            .encrypt_packet(&nonce, &mut buffer[plaintext_start..])
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
}

impl TcpOpener {
    /// Consumes a session subkey and creates a zero-nonce opener.
    pub fn new(subkey: TcpSubkey) -> Self {
        let TcpSubkey { cipher, .. } = subkey;
        Self {
            cipher,
            nonce: NonceCounter::new(),
        }
    }

    /// Authenticates and decrypts in place with empty associated data.
    ///
    /// Primitive authentication failure zeroizes the encrypted body without
    /// advancing the nonce. Nonce exhaustion leaves the buffer and counter unchanged.
    pub fn open_in_place(&mut self, buffer: &mut BytesMut) -> Result<(), AeadError> {
        let (nonce, next) = self.nonce.reserve()?;
        let tag_start = buffer
            .len()
            .checked_sub(AEAD_TAG_BYTES)
            .ok_or(AeadError::AuthenticationFailed)?;
        let tag: [u8; AEAD_TAG_BYTES] = buffer[tag_start..]
            .try_into()
            .unwrap_or_else(|_| unreachable!("validated TCP tag width"));
        self.cipher
            .decrypt_packet(&nonce, &mut buffer[..tag_start], &tag)
            .map_err(|_| AeadError::AuthenticationFailed)?;
        buffer.truncate(tag_start);
        self.nonce = next;
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
    fn tcp_sealer_encrypts_only_the_selected_suffix() {
        for profile in MethodProfile::ALL {
            let (seal_subkey, open_subkey) = paired_subkeys(profile);
            let prefix = b"framing prefix";
            let plaintext = b"payload";
            let mut framed = BytesMut::from(&prefix[..]);
            framed.extend_from_slice(plaintext);

            TcpSealer::new(seal_subkey)
                .seal_suffix_in_place(&mut framed, prefix.len())
                .expect("seal suffix");

            assert_eq!(&framed[..prefix.len()], prefix);
            let mut encrypted_suffix = framed.split_off(prefix.len());
            TcpOpener::new(open_subkey)
                .open_in_place(&mut encrypted_suffix)
                .expect("open suffix");
            assert_eq!(encrypted_suffix.as_ref(), plaintext);
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
                opener.open_in_place(&mut ciphertext),
                Err(AeadError::NonceExhausted)
            );
            assert_eq!(ciphertext, original_ciphertext);
            assert_eq!(opener.nonce.current_bytes(), EXHAUSTED_NONCE);

            assert_eq!(
                opener.open_in_place(&mut ciphertext),
                Err(AeadError::NonceExhausted)
            );
            assert_eq!(ciphertext, original_ciphertext);
            assert_eq!(opener.nonce.current_bytes(), EXHAUSTED_NONCE);
        }
    }

    fn paired_subkeys(profile: MethodProfile) -> (TcpSubkey, TcpSubkey) {
        match profile {
            MethodProfile::Blake3Aes128Gcm2022 => (
                TcpSubkey::from_bytes([0x71; AES_128_KEY_BYTES]),
                TcpSubkey::from_bytes([0x71; AES_128_KEY_BYTES]),
            ),
            MethodProfile::Blake3Aes256Gcm2022 | MethodProfile::Blake3ChaCha20Poly13052022 => (
                TcpSubkey::from_subkey(profile, [0x72; WIDE_KEY_BYTES]),
                TcpSubkey::from_subkey(profile, [0x72; WIDE_KEY_BYTES]),
            ),
        }
    }

    #[test]
    fn tcp_opener_zeroizes_failed_body_and_retries_nonce_with_fresh_wire() {
        let plaintext = b"unauthenticated plaintext is never retained";

        for profile in MethodProfile::ALL {
            let (seal_subkey, open_subkey) = paired_subkeys(profile);
            let mut sealer = TcpSealer::new(seal_subkey);
            let mut opener = TcpOpener::new(open_subkey);
            let mut valid = BytesMut::with_capacity(plaintext.len() + AEAD_TAG_BYTES);
            valid.extend_from_slice(plaintext);
            sealer.seal_in_place(&mut valid).expect("seal fixture");

            let tag_start = valid.len() - AEAD_TAG_BYTES;
            assert!(valid[..tag_start].iter().any(|byte| *byte != 0));
            let mut invalid = valid.clone();
            *invalid.last_mut().expect("tag byte") ^= 0x80;
            assert_eq!(
                opener.open_in_place(&mut invalid),
                Err(AeadError::AuthenticationFailed)
            );
            assert!(invalid[..tag_start].iter().all(|byte| *byte == 0));
            assert_eq!(opener.nonce.current_bytes(), [0; AEAD_NONCE_BYTES]);

            opener
                .open_in_place(&mut valid)
                .expect("fresh valid wire reuses failed nonce");
            assert_eq!(valid.as_ref(), plaintext);
            let mut expected_nonce = [0; AEAD_NONCE_BYTES];
            expected_nonce[0] = 1;
            assert_eq!(opener.nonce.current_bytes(), expected_nonce);
        }
    }
}
