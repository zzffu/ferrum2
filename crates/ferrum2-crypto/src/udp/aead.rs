use std::error::Error;
use std::fmt;

use shadowsocks_crypto::v2::{
    CryptoError as ShadowsocksCryptoError,
    udp::{AesHeaderCipher as ShadowsocksAesHeaderCipher, UdpCipher as ShadowsocksUdpCipher},
};
use zeroize::{Zeroize, Zeroizing};

use super::session::{
    UdpOutboundSession, UdpSessionId, generate_distinct_udp_session_id, generate_udp_session_id,
};
use super::{UDP_IDENTITY_BYTES, UDP_SESSION_ID_BYTES, XCHACHA_NONCE_BYTES};
use crate::method::{AEAD_NONCE_BYTES, AEAD_TAG_BYTES, MethodProfile, MethodPskBytes};
use crate::random::{RandomError, SecureRandom};

// Keeping fixed-size expanded primitive state inline avoids an allocation in
// the long-lived method capability and all per-packet operations.
#[allow(clippy::large_enum_variant)]
enum UdpCryptoInner {
    Aes {
        profile: MethodProfile,
        psk: Zeroizing<Vec<u8>>,
        header: ShadowsocksAesHeaderCipher,
    },
    ChaCha20Poly1305(ShadowsocksUdpCipher),
}

/// An opaque method-bound SIP022 UDP crypto envelope owner.
///
/// The caller supplies a bounded plaintext body and output storage. AES
/// envelopes protect the separate header with the PSK and authenticate the
/// body under the session-derived key. ChaCha envelopes authenticate the
/// identity with the body under the direct PSK and a fresh CSPRNG nonce.
pub struct UdpCrypto {
    inner: UdpCryptoInner,
}

impl fmt::Debug for UdpCrypto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UdpCrypto([REDACTED])")
    }
}

impl UdpCrypto {
    pub(crate) fn from_method_key(psk: &MethodPskBytes) -> Self {
        let inner = match psk {
            MethodPskBytes::Aes128(psk) => UdpCryptoInner::Aes {
                profile: MethodProfile::Blake3Aes128Gcm2022,
                psk: Zeroizing::new(psk.to_vec()),
                header: ShadowsocksAesHeaderCipher::try_new(
                    MethodProfile::Blake3Aes128Gcm2022.cipher_kind(),
                    psk.as_ref(),
                )
                .unwrap_or_else(|_| unreachable!("AES-128 PSKs have a fixed width")),
            },
            MethodPskBytes::Aes256(psk) => UdpCryptoInner::Aes {
                profile: MethodProfile::Blake3Aes256Gcm2022,
                psk: Zeroizing::new(psk.to_vec()),
                header: ShadowsocksAesHeaderCipher::try_new(
                    MethodProfile::Blake3Aes256Gcm2022.cipher_kind(),
                    psk.as_ref(),
                )
                .unwrap_or_else(|_| unreachable!("AES-256 PSKs have a fixed width")),
            },
            MethodPskBytes::ChaCha20Poly1305(psk) => UdpCryptoInner::ChaCha20Poly1305(
                ShadowsocksUdpCipher::try_new(
                    MethodProfile::Blake3ChaCha20Poly13052022.cipher_kind(),
                    psk.as_ref(),
                    None,
                )
                .unwrap_or_else(|_| unreachable!("XChaCha20 PSKs have a fixed width")),
            ),
        };
        Self { inner }
    }

    /// Returns the immutable method profile bound to this owner.
    pub const fn profile(&self) -> MethodProfile {
        match self.inner {
            UdpCryptoInner::Aes { profile, .. } => profile,
            UdpCryptoInner::ChaCha20Poly1305(_) => MethodProfile::Blake3ChaCha20Poly13052022,
        }
    }

    /// Creates one outbound session with a fresh ID and one private packet-ID lineage.
    ///
    /// The collision predicate is the caller's bounded live-session lookup.
    /// No candidate bytes or independently resettable counter are exposed.
    pub fn generate_outbound_session(
        &self,
        random: &(impl SecureRandom + ?Sized),
        is_live: impl FnMut(&UdpSessionId) -> bool,
    ) -> Result<UdpOutboundSession, RandomError> {
        generate_udp_session_id(random, is_live)
            .map(|session_id| self.new_outbound_session(session_id))
    }

    /// Creates an outbound session distinct from an opposite-direction owner.
    ///
    /// The opposite ID is always treated as a live collision in addition to
    /// the caller's bounded live-session lookup.
    pub fn generate_distinct_outbound_session(
        &self,
        random: &(impl SecureRandom + ?Sized),
        opposite_direction: &UdpSessionId,
        is_live: impl FnMut(&UdpSessionId) -> bool,
    ) -> Result<UdpOutboundSession, RandomError> {
        generate_distinct_udp_session_id(random, opposite_direction, is_live)
            .map(|session_id| self.new_outbound_session(session_id))
    }

    fn new_outbound_session(&self, session_id: UdpSessionId) -> UdpOutboundSession {
        let aes_body_cipher = match &self.inner {
            UdpCryptoInner::Aes { .. } => Some(self.aes_body_cipher(&session_id)),
            UdpCryptoInner::ChaCha20Poly1305(_) => None,
        };
        UdpOutboundSession::new(self.profile(), session_id, aes_body_cipher)
    }

    fn crypt_aes_header(&self, header: &mut [u8; UDP_IDENTITY_BYTES], encrypt: bool) {
        match (&self.inner, encrypt) {
            (UdpCryptoInner::Aes { header: cipher, .. }, true) => cipher.encrypt(header),
            (UdpCryptoInner::Aes { header: cipher, .. }, false) => cipher.decrypt(header),
            (UdpCryptoInner::ChaCha20Poly1305(_), _) => {
                unreachable!("AES header operation requires an AES method")
            }
        }
    }

    fn aes_body_cipher(&self, session_id: &UdpSessionId) -> ShadowsocksUdpCipher {
        match &self.inner {
            UdpCryptoInner::Aes { profile, psk, .. } => ShadowsocksUdpCipher::try_new(
                profile.cipher_kind(),
                psk.as_ref(),
                Some(&session_id.bytes),
            )
            .unwrap_or_else(|_| unreachable!("AES UDP inputs have validated fixed widths")),
            UdpCryptoInner::ChaCha20Poly1305(_) => {
                unreachable!("AES body operation requires an AES method")
            }
        }
    }

    /// Seals one complete method-specific UDP crypto envelope.
    ///
    /// The packet ID advances only after the complete wire result is present
    /// in `output`. Random, capacity, primitive, or counter failure leaves the
    /// counter unchanged and returns no externally ownable length.
    pub fn seal(
        &self,
        outbound: &mut UdpOutboundSession,
        plaintext_body: &[u8],
        output: &mut [u8],
        random: &(impl SecureRandom + ?Sized),
    ) -> Result<UdpSealResult, UdpCryptoError> {
        if outbound.profile != self.profile() {
            return Err(UdpCryptoError::MethodMismatch);
        }
        let packet_id = outbound.counter.current()?;
        let wire_len = plaintext_body
            .len()
            .checked_add(self.profile().udp_wire_overhead_bytes())
            .ok_or(UdpCryptoError::OutputTooSmall)?;
        if output.len() < wire_len {
            return Err(UdpCryptoError::OutputTooSmall);
        }

        let result = match &self.inner {
            UdpCryptoInner::Aes { .. } => seal_aes_udp(
                self,
                outbound.aes_body_cipher(),
                &outbound.session_id,
                packet_id,
                plaintext_body,
                &mut output[..wire_len],
            ),
            UdpCryptoInner::ChaCha20Poly1305(cipher) => seal_xchacha_udp(
                cipher,
                random,
                &outbound.session_id,
                packet_id,
                plaintext_body,
                &mut output[..wire_len],
            ),
        };

        if let Err(error) = result {
            output[..wire_len].zeroize();
            return Err(error);
        }
        outbound.counter.commit(packet_id);
        Ok(UdpSealResult {
            wire_len,
            packet_id,
        })
    }

    /// Authenticates and opens one complete method-specific UDP envelope.
    ///
    /// No identity or plaintext is returned until authentication succeeds.
    /// ChaCha callers provide scratch capacity for the authenticated identity
    /// plus body; on success the identity is removed and only the body remains.
    pub fn open(
        &self,
        wire: &[u8],
        plaintext_output: &mut [u8],
    ) -> Result<UdpOpenResult, UdpCryptoError> {
        match &self.inner {
            UdpCryptoInner::Aes { .. } => open_aes_udp(self, wire, plaintext_output),
            UdpCryptoInner::ChaCha20Poly1305(cipher) => {
                open_xchacha_udp(cipher, wire, plaintext_output)
            }
        }
    }
}

/// Successful UDP seal metadata without exposing key or nonce material.
pub struct UdpSealResult {
    wire_len: usize,
    packet_id: u64,
}

impl UdpSealResult {
    /// Returns the complete externally ownable wire length.
    pub const fn wire_len(&self) -> usize {
        self.wire_len
    }

    /// Returns the committed directional packet ID.
    pub const fn packet_id(&self) -> u64 {
        self.packet_id
    }
}

/// Successful authenticated UDP open metadata.
pub struct UdpOpenResult {
    session_id: UdpSessionId,
    packet_id: u64,
    plaintext_len: usize,
}

impl UdpOpenResult {
    /// Returns the authenticated opaque session ID.
    pub const fn session_id(&self) -> &UdpSessionId {
        &self.session_id
    }

    /// Returns the authenticated packet ID for replay processing.
    pub const fn packet_id(&self) -> u64 {
        self.packet_id
    }

    /// Returns the authenticated plaintext body length in the output buffer.
    pub const fn plaintext_len(&self) -> usize {
        self.plaintext_len
    }
}

/// A closed, redacted UDP cryptographic failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpCryptoError {
    /// Caller-owned output or scratch storage is too small.
    OutputTooSmall,
    /// The wire input cannot contain the selected method's envelope.
    InputTooShort,
    /// Authentication failed and no identity or plaintext was accepted.
    AuthenticationFailed,
    /// The secure-random capability failed without a fallback.
    RandomUnavailable,
    /// The primitive rejected the operation.
    OperationFailed,
    /// Every directional `u64` packet ID has been consumed.
    CounterExhausted,
    /// The outbound session belongs to another cryptographic method.
    MethodMismatch,
}

impl fmt::Display for UdpCryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::OutputTooSmall => "UDP output capacity unavailable",
            Self::InputTooShort => "UDP cryptographic envelope is truncated",
            Self::AuthenticationFailed => "UDP authentication failed",
            Self::RandomUnavailable => "secure random unavailable",
            Self::OperationFailed => "UDP encryption failed",
            Self::CounterExhausted => "UDP packet counter exhausted",
            Self::MethodMismatch => "UDP cryptographic method mismatch",
        };
        formatter.write_str(message)
    }
}

impl Error for UdpCryptoError {}

fn udp_identity(session_id: &UdpSessionId, packet_id: u64) -> [u8; UDP_IDENTITY_BYTES] {
    let mut identity = [0_u8; UDP_IDENTITY_BYTES];
    identity[..UDP_SESSION_ID_BYTES].copy_from_slice(&session_id.bytes);
    identity[UDP_SESSION_ID_BYTES..].copy_from_slice(&packet_id.to_be_bytes());
    identity
}

fn seal_aes_udp(
    crypto: &UdpCrypto,
    cipher: &ShadowsocksUdpCipher,
    session_id: &UdpSessionId,
    packet_id: u64,
    plaintext_body: &[u8],
    output: &mut [u8],
) -> Result<(), UdpCryptoError> {
    let mut identity = Zeroizing::new(udp_identity(session_id, packet_id));
    let mut protected_header = *identity;
    crypto.crypt_aes_header(&mut protected_header, true);
    output[..UDP_IDENTITY_BYTES].copy_from_slice(&protected_header);

    let mut nonce = Zeroizing::new([0_u8; AEAD_NONCE_BYTES]);
    nonce.copy_from_slice(&identity[4..UDP_IDENTITY_BYTES]);
    let body_end = UDP_IDENTITY_BYTES + plaintext_body.len();
    output[UDP_IDENTITY_BYTES..body_end].copy_from_slice(plaintext_body);
    let tag = cipher
        .encrypt_packet(nonce.as_ref(), &mut output[UDP_IDENTITY_BYTES..body_end])
        .map_err(map_udp_operation_error)?;
    output[body_end..body_end + AEAD_TAG_BYTES].copy_from_slice(&tag);

    protected_header.zeroize();
    nonce.zeroize();
    identity.zeroize();
    Ok(())
}

fn seal_xchacha_udp(
    cipher: &ShadowsocksUdpCipher,
    random: &(impl SecureRandom + ?Sized),
    session_id: &UdpSessionId,
    packet_id: u64,
    plaintext_body: &[u8],
    output: &mut [u8],
) -> Result<(), UdpCryptoError> {
    let mut nonce = Zeroizing::new([0_u8; XCHACHA_NONCE_BYTES]);
    random
        .fill(nonce.as_mut())
        .map_err(|_| UdpCryptoError::RandomUnavailable)?;

    let body_start = XCHACHA_NONCE_BYTES;
    let body_end = body_start + UDP_IDENTITY_BYTES + plaintext_body.len();
    output[body_start..body_start + UDP_SESSION_ID_BYTES].copy_from_slice(&session_id.bytes);
    output[body_start + UDP_SESSION_ID_BYTES..body_start + UDP_IDENTITY_BYTES]
        .copy_from_slice(&packet_id.to_be_bytes());
    output[body_start + UDP_IDENTITY_BYTES..body_end].copy_from_slice(plaintext_body);

    let tag = cipher
        .encrypt_packet(nonce.as_ref(), &mut output[body_start..body_end])
        .map_err(map_udp_operation_error)?;
    output[..XCHACHA_NONCE_BYTES].copy_from_slice(nonce.as_ref());
    output[body_end..body_end + AEAD_TAG_BYTES].copy_from_slice(&tag);
    nonce.zeroize();
    Ok(())
}

fn open_aes_udp(
    crypto: &UdpCrypto,
    wire: &[u8],
    plaintext_output: &mut [u8],
) -> Result<UdpOpenResult, UdpCryptoError> {
    let body_len = aes_udp_body_len(wire, plaintext_output)?;
    let mut identity = Zeroizing::new([0_u8; UDP_IDENTITY_BYTES]);
    identity.copy_from_slice(&wire[..UDP_IDENTITY_BYTES]);
    crypto.crypt_aes_header(&mut identity, false);

    let mut session_bytes = [0_u8; UDP_SESSION_ID_BYTES];
    session_bytes.copy_from_slice(&identity[..UDP_SESSION_ID_BYTES]);
    let packet_id = u64::from_be_bytes(
        identity[UDP_SESSION_ID_BYTES..]
            .try_into()
            .unwrap_or_else(|_| unreachable!("UDP packet IDs have a fixed width")),
    );
    let mut nonce = Zeroizing::new([0_u8; AEAD_NONCE_BYTES]);
    nonce.copy_from_slice(&identity[4..UDP_IDENTITY_BYTES]);
    let candidate_session = UdpSessionId::from_bytes(session_bytes);
    let cipher = crypto.aes_body_cipher(&candidate_session);

    plaintext_output[..body_len]
        .copy_from_slice(&wire[UDP_IDENTITY_BYTES..UDP_IDENTITY_BYTES + body_len]);
    let tag_start = UDP_IDENTITY_BYTES + body_len;
    let tag_bytes: [u8; AEAD_TAG_BYTES] = wire[tag_start..]
        .try_into()
        .unwrap_or_else(|_| unreachable!("validated UDP tag width"));
    let result = cipher.decrypt_packet(
        nonce.as_ref(),
        &mut plaintext_output[..body_len],
        &tag_bytes,
    );

    identity.zeroize();
    nonce.zeroize();
    if result.is_err() {
        plaintext_output[..body_len].zeroize();
        return Err(UdpCryptoError::AuthenticationFailed);
    }
    Ok(UdpOpenResult {
        session_id: candidate_session,
        packet_id,
        plaintext_len: body_len,
    })
}

fn aes_udp_body_len(wire: &[u8], plaintext_output: &[u8]) -> Result<usize, UdpCryptoError> {
    let body_len = wire
        .len()
        .checked_sub(UDP_IDENTITY_BYTES + AEAD_TAG_BYTES)
        .ok_or(UdpCryptoError::InputTooShort)?;
    if plaintext_output.len() < body_len {
        return Err(UdpCryptoError::OutputTooSmall);
    }
    Ok(body_len)
}

fn open_xchacha_udp(
    cipher: &ShadowsocksUdpCipher,
    wire: &[u8],
    plaintext_output: &mut [u8],
) -> Result<UdpOpenResult, UdpCryptoError> {
    let encrypted_len = wire
        .len()
        .checked_sub(XCHACHA_NONCE_BYTES + AEAD_TAG_BYTES)
        .filter(|length| *length >= UDP_IDENTITY_BYTES)
        .ok_or(UdpCryptoError::InputTooShort)?;
    if plaintext_output.len() < encrypted_len {
        return Err(UdpCryptoError::OutputTooSmall);
    }

    let mut nonce = Zeroizing::new([0_u8; XCHACHA_NONCE_BYTES]);
    nonce.copy_from_slice(&wire[..XCHACHA_NONCE_BYTES]);
    let ciphertext_start = XCHACHA_NONCE_BYTES;
    let tag_start = ciphertext_start + encrypted_len;
    plaintext_output[..encrypted_len].copy_from_slice(&wire[ciphertext_start..tag_start]);
    let tag_bytes: [u8; AEAD_TAG_BYTES] = wire[tag_start..]
        .try_into()
        .unwrap_or_else(|_| unreachable!("validated UDP tag width"));
    let result = cipher.decrypt_packet(
        nonce.as_ref(),
        &mut plaintext_output[..encrypted_len],
        &tag_bytes,
    );
    nonce.zeroize();
    if result.is_err() {
        plaintext_output[..encrypted_len].zeroize();
        return Err(UdpCryptoError::AuthenticationFailed);
    }

    let mut session_bytes = [0_u8; UDP_SESSION_ID_BYTES];
    session_bytes.copy_from_slice(&plaintext_output[..UDP_SESSION_ID_BYTES]);
    let packet_id = u64::from_be_bytes(
        plaintext_output[UDP_SESSION_ID_BYTES..UDP_IDENTITY_BYTES]
            .try_into()
            .unwrap_or_else(|_| unreachable!("UDP packet IDs have a fixed width")),
    );
    let body_len = encrypted_len - UDP_IDENTITY_BYTES;
    plaintext_output.copy_within(UDP_IDENTITY_BYTES..encrypted_len, 0);
    plaintext_output[body_len..encrypted_len].zeroize();
    Ok(UdpOpenResult {
        session_id: UdpSessionId::from_bytes(session_bytes),
        packet_id,
        plaintext_len: body_len,
    })
}

fn map_udp_operation_error(_: ShadowsocksCryptoError) -> UdpCryptoError {
    UdpCryptoError::OperationFailed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method::{AES_128_KEY_BYTES, WIDE_KEY_BYTES};
    use crate::random::SystemRandom;
    use zeroize::Zeroizing;

    fn aes128_udp_crypto() -> UdpCrypto {
        let psk = MethodPskBytes::Aes128(Zeroizing::new([0x11; AES_128_KEY_BYTES]));
        UdpCrypto::from_method_key(&psk)
    }

    fn aes256_udp_crypto() -> UdpCrypto {
        let psk = MethodPskBytes::Aes256(Zeroizing::new([0x33; WIDE_KEY_BYTES]));
        UdpCrypto::from_method_key(&psk)
    }

    #[test]
    fn udp_outbound_session_commits_zero_terminal_and_exhausted_states_only_on_success() {
        let crypto = aes128_udp_crypto();
        let session_id = UdpSessionId::from_bytes([0x22; UDP_SESSION_ID_BYTES]);
        let mut outbound = crypto.new_outbound_session(session_id);
        let mut output = [0xa5; 64];

        let original = output;
        assert!(matches!(
            aes256_udp_crypto().seal(&mut outbound, b"body", &mut output, &SystemRandom),
            Err(UdpCryptoError::MethodMismatch)
        ));
        assert_eq!(output, original);

        assert!(matches!(
            crypto.seal(&mut outbound, b"body", &mut output[..3], &SystemRandom,),
            Err(UdpCryptoError::OutputTooSmall)
        ));
        let first = crypto
            .seal(&mut outbound, b"body", &mut output, &SystemRandom)
            .expect("first complete packet");
        assert_eq!(first.packet_id(), 0);

        outbound.counter.next = Some(u64::MAX);
        let terminal = crypto
            .seal(&mut outbound, b"body", &mut output, &SystemRandom)
            .expect("terminal packet ID remains usable");
        assert_eq!(terminal.packet_id(), u64::MAX);
        assert!(outbound.is_exhausted());

        let original = output;
        assert!(matches!(
            crypto.seal(&mut outbound, b"body", &mut output, &SystemRandom,),
            Err(UdpCryptoError::CounterExhausted)
        ));
        assert_eq!(output, original);
    }
}
