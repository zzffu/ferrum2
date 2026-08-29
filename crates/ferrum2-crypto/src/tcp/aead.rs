use std::error::Error;
use std::fmt;

use bytes::BytesMut;
use shadowsocks_crypto::v2::tcp::TcpCipher as ShadowsocksTcpCipher;

use super::{NonceCounter, TcpSubkey};
use crate::method::{AEAD_NONCE_BYTES, AEAD_TAG_BYTES};

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

    fn encrypt_detached_with_nonce(
        &self,
        nonce: &[u8; AEAD_NONCE_BYTES],
        plaintext: &mut [u8],
    ) -> Result<[u8; AEAD_TAG_BYTES], AeadError> {
        self.cipher
            .encrypt_packet(nonce, plaintext)
            .map_err(|_| AeadError::OperationFailed)
    }

    /// Encrypts a caller-owned plaintext slice in place with empty associated
    /// data and returns the detached authentication tag.
    ///
    /// The nonce is committed only after the primitive returns a tag. Nonce
    /// exhaustion leaves both the plaintext and counter unchanged. On any
    /// other primitive failure, the plaintext contents are unspecified while
    /// the nonce remains uncommitted.
    pub fn seal_slice_detached(
        &mut self,
        plaintext: &mut [u8],
    ) -> Result<[u8; AEAD_TAG_BYTES], AeadError> {
        let (nonce, next) = self.nonce.reserve()?;
        let tag = self.encrypt_detached_with_nonce(&nonce, plaintext)?;
        self.nonce = next;
        Ok(tag)
    }

    /// Encrypts and appends the tag in place with empty associated data.
    pub fn seal_in_place(&mut self, buffer: &mut BytesMut) -> Result<(), AeadError> {
        let (nonce, next) = self.nonce.reserve()?;
        buffer.reserve(AEAD_TAG_BYTES);
        let tag = self.encrypt_detached_with_nonce(&nonce, buffer.as_mut())?;
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
        let (ciphertext, tag) = buffer.split_at_mut(tag_start);
        let tag: [u8; AEAD_TAG_BYTES] = tag
            .try_into()
            .unwrap_or_else(|_| unreachable!("validated TCP tag width"));
        self.cipher
            .decrypt_packet(&nonce, ciphertext, &tag)
            .map_err(|_| AeadError::AuthenticationFailed)?;
        self.nonce = next;
        Ok(tag_start)
    }

    /// Authenticates a ciphertext-and-tag slice and decrypts into separate
    /// caller-owned storage without allocating.
    ///
    /// `plaintext` must have exactly the ciphertext length (the input length
    /// minus the tag). Authentication, malformed input, output-size failure,
    /// and nonce exhaustion leave `plaintext` and the nonce unchanged.
    pub fn open_slice_into(
        &mut self,
        buffer: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, AeadError> {
        let (nonce, next) = self.nonce.reserve()?;
        let tag_start = buffer
            .len()
            .checked_sub(AEAD_TAG_BYTES)
            .ok_or(AeadError::AuthenticationFailed)?;
        if plaintext.len() != tag_start {
            return Err(AeadError::OperationFailed);
        }
        let (ciphertext, tag) = buffer.split_at(tag_start);
        let tag: [u8; AEAD_TAG_BYTES] = tag
            .try_into()
            .unwrap_or_else(|_| unreachable!("validated TCP tag width"));
        self.cipher
            .decrypt_packet_into(&nonce, ciphertext, plaintext, &tag)
            .map_err(|_| AeadError::AuthenticationFailed)?;
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

    fn test_subkey(profile: MethodProfile, byte: u8) -> TcpSubkey {
        match profile {
            MethodProfile::Blake3Aes128Gcm2022 => {
                TcpSubkey::from_subkey(profile, [byte; AES_128_KEY_BYTES])
            }
            MethodProfile::Blake3Aes256Gcm2022 | MethodProfile::Blake3ChaCha20Poly13052022 => {
                TcpSubkey::from_subkey(profile, [byte; WIDE_KEY_BYTES])
            }
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
                sealer.seal_slice_detached(plaintext.as_mut()),
                Err(AeadError::NonceExhausted)
            );
            assert_eq!(plaintext, original_plaintext);
            assert_eq!(sealer.nonce.current_bytes(), EXHAUSTED_NONCE);

            assert_eq!(
                sealer.seal_slice_detached(plaintext.as_mut()),
                Err(AeadError::NonceExhausted)
            );
            assert_eq!(plaintext, original_plaintext);
            assert_eq!(sealer.nonce.current_bytes(), EXHAUSTED_NONCE);
        }
    }

    #[test]
    fn tcp_sealer_detached_matches_appended_wire_for_all_methods_and_sizes() {
        for profile in MethodProfile::ALL {
            let mut detached = TcpSealer::new(test_subkey(profile, 0x41));
            let mut appended = TcpSealer::new(test_subkey(profile, 0x41));

            for length in [0, 1, 32_768] {
                let source: Vec<u8> = (0..length)
                    .map(|index| u8::try_from(index % 251).expect("bounded pattern"))
                    .collect();
                let mut detached_wire = Vec::with_capacity(length + AEAD_TAG_BYTES);
                detached_wire.extend_from_slice(&source);
                let storage = detached_wire.as_ptr();
                let tag = detached
                    .seal_slice_detached(&mut detached_wire)
                    .expect("detached seal");
                assert_eq!(detached_wire.as_ptr(), storage);
                detached_wire.extend_from_slice(&tag);

                let mut appended_wire = BytesMut::with_capacity(length + AEAD_TAG_BYTES);
                appended_wire.extend_from_slice(&source);
                appended
                    .seal_in_place(&mut appended_wire)
                    .expect("appended seal");

                assert_eq!(detached_wire, appended_wire.as_ref());
            }

            assert_eq!(detached.nonce.current_bytes()[0], 3);
            assert_eq!(appended.nonce.current_bytes()[0], 3);
        }
    }

    #[test]
    fn tcp_sealer_appended_nonce_exhaustion_preserves_storage() {
        for profile in MethodProfile::ALL {
            let mut sealer = TcpSealer::new(test_subkey(profile, 0x42));
            sealer.nonce = NonceCounter::from_le_bytes(EXHAUSTED_NONCE);
            let source = b"exhaustion must precede tag capacity mutation";
            let mut plaintext = BytesMut::with_capacity(source.len());
            plaintext.extend_from_slice(source);
            let original = plaintext.clone();
            let storage = plaintext.as_ptr();
            let capacity = plaintext.capacity();

            assert_eq!(
                sealer.seal_in_place(&mut plaintext),
                Err(AeadError::NonceExhausted)
            );
            assert_eq!(plaintext, original);
            assert_eq!(plaintext.as_ptr(), storage);
            assert_eq!(plaintext.capacity(), capacity);
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

    #[test]
    fn tcp_opener_into_decrypts_all_methods_without_mutating_input() {
        let expected = b"authenticated out-of-place plaintext";

        for profile in MethodProfile::ALL {
            let mut sealer = TcpSealer::new(test_subkey(profile, 0x81));
            let mut wire = BytesMut::from(expected.as_slice());
            sealer.seal_in_place(&mut wire).expect("fixture seals");
            let original_wire = wire.clone();
            let mut plaintext = vec![0xa5; expected.len()];
            let mut opener = TcpOpener::new(test_subkey(profile, 0x81));

            let plaintext_len = opener
                .open_slice_into(&wire, &mut plaintext)
                .expect("fixture authenticates");

            assert_eq!(plaintext_len, expected.len());
            assert_eq!(plaintext, expected);
            assert_eq!(wire, original_wire);
            assert_eq!(opener.nonce.current_bytes()[0], 1);
        }
    }

    #[test]
    fn tcp_opener_into_tamper_leaves_output_and_nonce_unchanged() {
        let expected = b"tampering cannot expose plaintext";

        for profile in MethodProfile::ALL {
            let mut sealer = TcpSealer::new(test_subkey(profile, 0x82));
            let mut valid = BytesMut::from(expected.as_slice());
            sealer.seal_in_place(&mut valid).expect("fixture seals");
            let mut tampered = valid.clone();
            tampered[0] ^= 0x80;
            let mut plaintext = vec![0xa5; expected.len()];
            let original_plaintext = plaintext.clone();
            let mut opener = TcpOpener::new(test_subkey(profile, 0x82));

            assert_eq!(
                opener.open_slice_into(&tampered, &mut plaintext),
                Err(AeadError::AuthenticationFailed)
            );
            assert_eq!(plaintext, original_plaintext);
            assert_eq!(opener.nonce.current_bytes(), [0; AEAD_NONCE_BYTES]);

            let plaintext_len = opener
                .open_slice_into(&valid, &mut plaintext)
                .expect("failed authentication did not consume nonce zero");
            assert_eq!(plaintext_len, expected.len());
            assert_eq!(plaintext, expected);
        }
    }

    #[test]
    fn tcp_opener_into_rejects_output_bounds_and_short_tag_without_nonce_commit() {
        let expected = b"output must have the exact plaintext length";

        for profile in MethodProfile::ALL {
            let mut sealer = TcpSealer::new(test_subkey(profile, 0x83));
            let mut valid = BytesMut::from(expected.as_slice());
            sealer.seal_in_place(&mut valid).expect("fixture seals");
            let mut opener = TcpOpener::new(test_subkey(profile, 0x83));
            let mut short_output = vec![0xa5; expected.len() - 1];
            let original_short = short_output.clone();
            let mut long_output = vec![0x5a; expected.len() + 1];
            let original_long = long_output.clone();
            let mut empty_output = [];

            assert_eq!(
                opener.open_slice_into(&valid, &mut short_output),
                Err(AeadError::OperationFailed)
            );
            assert_eq!(short_output, original_short);
            assert_eq!(
                opener.open_slice_into(&valid, &mut long_output),
                Err(AeadError::OperationFailed)
            );
            assert_eq!(long_output, original_long);
            assert_eq!(
                opener.open_slice_into(&[0xa5; AEAD_TAG_BYTES - 1], &mut empty_output),
                Err(AeadError::AuthenticationFailed)
            );
            assert_eq!(opener.nonce.current_bytes(), [0; AEAD_NONCE_BYTES]);

            let mut exact_output = vec![0; expected.len()];
            opener
                .open_slice_into(&valid, &mut exact_output)
                .expect("invalid sizes did not consume nonce zero");
            assert_eq!(exact_output, expected);
        }
    }

    #[test]
    fn tcp_opener_into_nonce_exhaustion_leaves_input_and_output_unchanged() {
        let expected = b"nonce exhaustion fails before output";

        for profile in MethodProfile::ALL {
            let mut sealer = TcpSealer::new(test_subkey(profile, 0x84));
            let mut wire = BytesMut::from(expected.as_slice());
            sealer.seal_in_place(&mut wire).expect("fixture seals");
            let original_wire = wire.clone();
            let mut plaintext = vec![0xa5; expected.len()];
            let original_plaintext = plaintext.clone();
            let mut opener = TcpOpener::new(test_subkey(profile, 0x84));
            opener.nonce = NonceCounter::from_le_bytes(EXHAUSTED_NONCE);

            assert_eq!(
                opener.open_slice_into(&wire, &mut plaintext),
                Err(AeadError::NonceExhausted)
            );
            assert_eq!(wire, original_wire);
            assert_eq!(plaintext, original_plaintext);
            assert_eq!(opener.nonce.current_bytes(), EXHAUSTED_NONCE);
        }
    }
}
