use std::error::Error;
use std::fmt;

use bytes::BytesMut;
use shadowsocks_crypto::v2::tcp::TcpCipher as ShadowsocksTcpCipher;
use zeroize::Zeroize;

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

    /// Authenticates and decrypts a ciphertext-and-tag slice in place.
    ///
    /// Authentication failure zeroizes the ciphertext body in `buffer` and
    /// leaves the nonce uncommitted. The trailing tag is not part of the
    /// destructive primitive input and remains in place. Nonce exhaustion is
    /// checked before touching or validating `buffer`.
    pub fn open_slice_in_place(&mut self, buffer: &mut [u8]) -> Result<(), AeadError> {
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
        self.nonce = next;
        Ok(())
    }

    /// Authenticates a ciphertext-and-tag slice and decrypts into separate
    /// caller-owned storage without allocating.
    ///
    /// `plaintext` must have exactly the ciphertext length (the input length
    /// minus the tag). Authentication and length failures zeroize the whole
    /// candidate output and leave the nonce uncommitted. Nonce exhaustion is
    /// checked first and leaves the input, output, and nonce unchanged.
    pub fn open_slice_into(
        &mut self,
        buffer: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), AeadError> {
        let (nonce, next) = self.nonce.reserve()?;
        let Some(tag_start) = buffer.len().checked_sub(AEAD_TAG_BYTES) else {
            plaintext.zeroize();
            return Err(AeadError::AuthenticationFailed);
        };
        if plaintext.len() != tag_start {
            plaintext.zeroize();
            return Err(AeadError::OperationFailed);
        }
        let (ciphertext, tag) = buffer.split_at(tag_start);
        let tag: [u8; AEAD_TAG_BYTES] = tag
            .try_into()
            .unwrap_or_else(|_| unreachable!("validated TCP tag width"));
        self.cipher
            .decrypt_packet_into(&nonce, ciphertext, plaintext, &tag)
            .map_err(|error| match error {
                shadowsocks_crypto::v2::CryptoError::AuthenticationFailed => {
                    AeadError::AuthenticationFailed
                }
                _ => AeadError::OperationFailed,
            })?;
        self.nonce = next;
        Ok(())
    }

    /// Authenticates and decrypts in place with empty associated data.
    ///
    /// Authentication failure zeroizes the ciphertext body in `buffer` and
    /// leaves the nonce uncommitted. The trailing tag is not part of the
    /// destructive primitive input and remains in place.
    pub fn open_in_place(&mut self, buffer: &mut BytesMut) -> Result<(), AeadError> {
        let wire_len = buffer.len();
        self.open_slice_in_place(buffer.as_mut())?;
        buffer.truncate(wire_len - AEAD_TAG_BYTES);
        Ok(())
    }
}

/// A closed AES operation error which contains no key, nonce, or source error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AeadError {
    /// Authentication failed and no plaintext was accepted.
    AuthenticationFailed,
    /// The primitive rejected the operation or its output size.
    OperationFailed,
    /// No unused nonce remains for this owner.
    NonceExhausted,
}

impl fmt::Display for AeadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::AuthenticationFailed => "authentication failed",
            Self::OperationFailed => "operation failed",
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
    fn tcp_opener_slice_decrypts_without_replacing_storage() {
        let plaintext = b"caller-owned fixed backing";

        for (sealer_subkey, opener_subkey) in matching_subkey_pairs() {
            let mut wire = BytesMut::from(plaintext.as_slice());
            TcpSealer::new(sealer_subkey)
                .seal_in_place(&mut wire)
                .expect("matching subkey seals");
            let storage = wire.as_ptr();
            let wire_len = wire.len();
            TcpOpener::new(opener_subkey)
                .open_slice_in_place(&mut wire[..wire_len])
                .expect("matching subkey authenticates");

            assert_eq!(wire.as_ptr(), storage);
            assert_eq!(&wire[..wire_len - AEAD_TAG_BYTES], plaintext);
        }
    }

    #[test]
    fn tcp_opener_slice_nonce_exhaustion_precedes_input_validation() {
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
            let mut short = [0xa5; AEAD_TAG_BYTES - 1];
            let original = short;

            assert_eq!(
                opener.open_slice_in_place(&mut short),
                Err(AeadError::NonceExhausted)
            );
            assert_eq!(short, original);
            assert_eq!(opener.nonce.current_bytes(), EXHAUSTED_NONCE);
        }
    }

    #[test]
    fn tcp_opener_into_decrypts_all_methods_without_mutating_input() {
        let plaintext = b"authenticated out-of-place plaintext";
        let mut next_nonce = INITIAL_NONCE;
        next_nonce[0] = 1;

        for (sealer_subkey, opener_subkey) in matching_subkey_pairs() {
            let mut wire = BytesMut::from(plaintext.as_slice());
            TcpSealer::new(sealer_subkey)
                .seal_in_place(&mut wire)
                .expect("matching subkey seals");
            let original_wire = wire.clone();
            let mut output = vec![0xa5; plaintext.len()];
            let mut opener = TcpOpener::new(opener_subkey);

            opener
                .open_slice_into(&wire, &mut output)
                .expect("matching subkey authenticates");

            assert_eq!(output, plaintext);
            assert_eq!(wire, original_wire);
            assert_eq!(opener.nonce.current_bytes(), next_nonce);
        }
    }

    #[test]
    fn tcp_opener_into_authentication_failure_clears_output_and_rolls_back_nonce() {
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
            let original_corrupted = corrupted.clone();
            let mut output = vec![0xa5; plaintext.len()];
            let mut opener = TcpOpener::new(opener_subkey);

            assert_eq!(
                opener.open_slice_into(&corrupted, &mut output),
                Err(AeadError::AuthenticationFailed)
            );
            assert!(output.iter().all(|byte| *byte == 0));
            assert_eq!(corrupted, original_corrupted);
            assert_eq!(opener.nonce.current_bytes(), INITIAL_NONCE);

            opener
                .open_slice_into(&valid, &mut output)
                .expect("failed authentication did not commit the nonce");
            assert_eq!(output, plaintext);
            assert_eq!(opener.nonce.current_bytes(), next_nonce);
        }
    }

    #[test]
    fn tcp_opener_into_length_errors_clear_output_without_committing_nonce() {
        let plaintext = b"output must have the exact plaintext length";

        for (sealer_subkey, opener_subkey) in matching_subkey_pairs() {
            let mut valid = BytesMut::from(plaintext.as_slice());
            TcpSealer::new(sealer_subkey)
                .seal_in_place(&mut valid)
                .expect("matching subkey seals");
            let original_valid = valid.clone();
            let mut opener = TcpOpener::new(opener_subkey);
            let mut short_output = vec![0xa5; plaintext.len() - 1];
            let mut long_output = vec![0x5a; plaintext.len() + 1];
            let short_wire = [0x3c; AEAD_TAG_BYTES - 1];
            let original_short_wire = short_wire;
            let mut malformed_output = [0xc3; 3];

            assert_eq!(
                opener.open_slice_into(&valid, &mut short_output),
                Err(AeadError::OperationFailed)
            );
            assert!(short_output.iter().all(|byte| *byte == 0));
            assert_eq!(opener.nonce.current_bytes(), INITIAL_NONCE);

            assert_eq!(
                opener.open_slice_into(&valid, &mut long_output),
                Err(AeadError::OperationFailed)
            );
            assert!(long_output.iter().all(|byte| *byte == 0));
            assert_eq!(opener.nonce.current_bytes(), INITIAL_NONCE);

            assert_eq!(
                opener.open_slice_into(&short_wire, &mut malformed_output),
                Err(AeadError::AuthenticationFailed)
            );
            assert!(malformed_output.iter().all(|byte| *byte == 0));
            assert_eq!(short_wire, original_short_wire);
            assert_eq!(valid, original_valid);
            assert_eq!(opener.nonce.current_bytes(), INITIAL_NONCE);

            let mut exact_output = vec![0; plaintext.len()];
            opener
                .open_slice_into(&valid, &mut exact_output)
                .expect("length errors did not commit the nonce");
            assert_eq!(exact_output, plaintext);
        }
    }

    #[test]
    fn tcp_opener_into_nonce_exhaustion_preserves_input_output_and_nonce() {
        let plaintext = b"nonce exhaustion fails before output";

        for (sealer_subkey, opener_subkey) in matching_subkey_pairs() {
            let mut wire = BytesMut::from(plaintext.as_slice());
            TcpSealer::new(sealer_subkey)
                .seal_in_place(&mut wire)
                .expect("matching subkey seals");
            let original_wire = wire.clone();
            let mut output = vec![0xa5; plaintext.len()];
            let original_output = output.clone();
            let mut opener = TcpOpener::new(opener_subkey);
            opener.nonce = NonceCounter::from_le_bytes(EXHAUSTED_NONCE);

            assert_eq!(
                opener.open_slice_into(&wire, &mut output),
                Err(AeadError::NonceExhausted)
            );
            assert_eq!(wire, original_wire);
            assert_eq!(output, original_output);
            assert_eq!(opener.nonce.current_bytes(), EXHAUSTED_NONCE);
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
