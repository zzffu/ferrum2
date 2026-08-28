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

    /// Encrypts one body in its final location and writes its detached tag.
    ///
    /// The nonce is committed only after both encryption and tag publication
    /// succeed. Nonce exhaustion leaves both regions unchanged.
    pub fn seal_in_place_detached(
        &mut self,
        buffer: &mut [u8],
        tag_out: &mut [u8; 16],
    ) -> Result<(), AeadError> {
        let (nonce, next) = self.nonce.reserve()?;
        let tag = self
            .cipher
            .encrypt_packet(&nonce, buffer)
            .map_err(|_| AeadError::OperationFailed)?;
        tag_out.copy_from_slice(&tag);
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
    /// Authentication failure zeroizes the ciphertext body in `buffer` and
    /// leaves the nonce uncommitted. The trailing tag is not part of the
    /// destructive primitive input and remains in place.
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
    const INITIAL_NONCE: [u8; AEAD_NONCE_BYTES] = [0; AEAD_NONCE_BYTES];

    fn matching_subkey_pairs() -> [(TcpSubkey, TcpSubkey); 3] {
        [
            (
                TcpSubkey::from_bytes([0x11; AES_128_KEY_BYTES]),
                TcpSubkey::from_bytes([0x11; AES_128_KEY_BYTES]),
            ),
            (
                TcpSubkey::from_subkey(MethodProfile::Blake3Aes256Gcm2022, [0x22; WIDE_KEY_BYTES]),
                TcpSubkey::from_subkey(MethodProfile::Blake3Aes256Gcm2022, [0x22; WIDE_KEY_BYTES]),
            ),
            (
                TcpSubkey::from_subkey(
                    MethodProfile::Blake3ChaCha20Poly13052022,
                    [0x33; WIDE_KEY_BYTES],
                ),
                TcpSubkey::from_subkey(
                    MethodProfile::Blake3ChaCha20Poly13052022,
                    [0x33; WIDE_KEY_BYTES],
                ),
            ),
        ]
    }

    #[test]
    fn tcp_opener_decrypts_in_place_and_commits_nonce() {
        let plaintext = b"authenticated plaintext";
        let mut next_nonce = INITIAL_NONCE;
        next_nonce[0] = 1;

        for (sealer_subkey, opener_subkey) in matching_subkey_pairs() {
            let mut ciphertext = BytesMut::from(plaintext.as_slice());
            TcpSealer::new(sealer_subkey)
                .seal_in_place(&mut ciphertext)
                .expect("matching subkey seals");
            let mut opener = TcpOpener::new(opener_subkey);

            opener
                .open_in_place(&mut ciphertext)
                .expect("matching subkey authenticates");

            assert_eq!(ciphertext.as_ref(), plaintext);
            assert_eq!(opener.nonce.current_bytes(), next_nonce);
        }
    }

    #[test]
    fn tcp_opener_authentication_failure_clears_body_and_rolls_back_nonce() {
        let plaintext = b"candidate plaintext must not escape";
        let mut next_nonce = INITIAL_NONCE;
        next_nonce[0] = 1;

        for (sealer_subkey, opener_subkey) in matching_subkey_pairs() {
            let mut valid = BytesMut::from(plaintext.as_slice());
            TcpSealer::new(sealer_subkey)
                .seal_in_place(&mut valid)
                .expect("matching subkey seals");
            let mut corrupted = valid.clone();
            *corrupted.last_mut().expect("tag byte") ^= 1;
            let corrupted_tag = corrupted[plaintext.len()..].to_vec();
            let mut opener = TcpOpener::new(opener_subkey);

            assert_eq!(
                opener.open_in_place(&mut corrupted),
                Err(AeadError::AuthenticationFailed)
            );
            assert!(corrupted[..plaintext.len()].iter().all(|byte| *byte == 0));
            assert_eq!(&corrupted[plaintext.len()..], corrupted_tag);
            assert_eq!(opener.nonce.current_bytes(), INITIAL_NONCE);

            opener
                .open_in_place(&mut valid)
                .expect("failed authentication did not commit the nonce");
            assert_eq!(valid.as_ref(), plaintext);
            assert_eq!(opener.nonce.current_bytes(), next_nonce);
        }
    }

    #[test]
    fn tcp_sealer_detached_output_matches_appended_layout_and_commits_nonce() {
        let plaintext = b"plaintext already occupies its final wire range";
        let mut next_nonce = INITIAL_NONCE;
        next_nonce[0] = 1;

        for (appended_subkey, detached_subkey) in matching_subkey_pairs() {
            let mut expected = BytesMut::from(plaintext.as_slice());
            TcpSealer::new(appended_subkey)
                .seal_in_place(&mut expected)
                .expect("appended seal");
            let mut body = plaintext.to_vec();
            let mut tag = [0_u8; AEAD_TAG_BYTES];
            let mut detached = TcpSealer::new(detached_subkey);

            detached
                .seal_in_place_detached(&mut body, &mut tag)
                .expect("detached seal");

            assert_eq!(body, expected[..plaintext.len()]);
            assert_eq!(tag, expected[plaintext.len()..]);
            assert_eq!(detached.nonce.current_bytes(), next_nonce);
        }
    }

    #[test]
    fn tcp_sealer_detached_nonce_exhaustion_preserves_final_layout() {
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
            let mut body = b"final body".to_vec();
            let mut tag = [0xa5; AEAD_TAG_BYTES];
            let original_body = body.clone();
            let original_tag = tag;

            assert_eq!(
                sealer.seal_in_place_detached(&mut body, &mut tag),
                Err(AeadError::NonceExhausted)
            );
            assert_eq!(body, original_body);
            assert_eq!(tag, original_tag);
            assert_eq!(sealer.nonce.current_bytes(), EXHAUSTED_NONCE);
        }
    }

    #[test]
    fn tcp_sealer_detached_commits_only_the_successful_final_layout_region() {
        let mut penultimate_nonce = EXHAUSTED_NONCE;
        penultimate_nonce[0] -= 1;

        for subkey in [
            TcpSubkey::from_bytes([0x11; AES_128_KEY_BYTES]),
            TcpSubkey::from_subkey(MethodProfile::Blake3Aes256Gcm2022, [0x22; WIDE_KEY_BYTES]),
            TcpSubkey::from_subkey(
                MethodProfile::Blake3ChaCha20Poly13052022,
                [0x33; WIDE_KEY_BYTES],
            ),
        ] {
            let mut sealer = TcpSealer::new(subkey);
            sealer.nonce = NonceCounter::from_le_bytes(penultimate_nonce);
            let mut length = 1_u16.to_be_bytes();
            let mut length_tag = [0_u8; AEAD_TAG_BYTES];

            sealer
                .seal_in_place_detached(&mut length, &mut length_tag)
                .expect("penultimate nonce seals the length region");
            assert_eq!(sealer.nonce.current_bytes(), EXHAUSTED_NONCE);

            let mut payload = [0x5a];
            let mut payload_tag = [0xa5; AEAD_TAG_BYTES];
            let original_payload = payload;
            let original_tag = payload_tag;
            assert_eq!(
                sealer.seal_in_place_detached(&mut payload, &mut payload_tag),
                Err(AeadError::NonceExhausted)
            );
            assert_eq!(payload, original_payload);
            assert_eq!(payload_tag, original_tag);
            assert_eq!(sealer.nonce.current_bytes(), EXHAUSTED_NONCE);
        }
    }

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
}
