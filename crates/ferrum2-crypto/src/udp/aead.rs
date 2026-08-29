use std::error::Error;
use std::fmt;
use std::ops::Range;
use std::sync::{Arc, Weak};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

use bytes::BytesMut;
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

#[derive(Default)]
struct UdpCryptoOwner {
    #[cfg(test)]
    aes_body_cipher_derivations: AtomicUsize,
}

/// Opaque AES UDP body-cipher state bound to one crypto owner and session ID.
///
/// The token is intentionally non-cloneable and redacted. Callers may retain it
/// behind an [`Arc`] for bounded session caches, while the underlying primitive
/// is shared without exposing derived key material.
pub struct UdpAesSessionCipher {
    owner: Weak<UdpCryptoOwner>,
    session_id: UdpSessionId,
    cipher: ShadowsocksUdpCipher,
}

impl fmt::Debug for UdpAesSessionCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UdpAesSessionCipher([REDACTED])")
    }
}

/// An opaque method-bound SIP022 UDP crypto envelope owner.
///
/// The caller supplies a bounded plaintext body and output storage. AES
/// envelopes protect the separate header with the PSK and authenticate the
/// body under the session-derived key. ChaCha envelopes authenticate the
/// identity with the body under the direct PSK and a fresh CSPRNG nonce.
pub struct UdpCrypto {
    inner: UdpCryptoInner,
    aes_owner: Option<Arc<UdpCryptoOwner>>,
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
        let aes_owner = matches!(&inner, UdpCryptoInner::Aes { .. })
            .then(|| Arc::new(UdpCryptoOwner::default()));
        Self { inner, aes_owner }
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
        generate_udp_session_id(random, is_live).map(|session_id| {
            let aes_body_cipher = self.derive_aes_session_cipher(&session_id);
            UdpOutboundSession::new(self.profile(), session_id, aes_body_cipher)
        })
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
        generate_distinct_udp_session_id(random, opposite_direction, is_live).map(|session_id| {
            let aes_body_cipher = self.derive_aes_session_cipher(&session_id);
            UdpOutboundSession::new(self.profile(), session_id, aes_body_cipher)
        })
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

    /// Derives one cacheable AES body cipher bound to this owner and session.
    ///
    /// ChaCha methods return `None`; their direct-PSK cipher is already retained
    /// by [`UdpCrypto`] and never consults an AES session resolver.
    pub fn derive_aes_session_cipher(
        &self,
        session_id: &UdpSessionId,
    ) -> Option<UdpAesSessionCipher> {
        match &self.inner {
            UdpCryptoInner::Aes { profile, psk, .. } => {
                #[cfg(test)]
                self.aes_owner
                    .as_ref()
                    .expect("AES crypto owns its cache identity")
                    .aes_body_cipher_derivations
                    .fetch_add(1, AtomicOrdering::Relaxed);
                let owner = self
                    .aes_owner
                    .as_ref()
                    .expect("AES crypto owns its cache identity");
                Some(UdpAesSessionCipher {
                    owner: Arc::downgrade(owner),
                    session_id: session_id.clone(),
                    cipher: ShadowsocksUdpCipher::try_new(
                        profile.cipher_kind(),
                        psk.as_ref(),
                        Some(&session_id.bytes),
                    )
                    .unwrap_or_else(|_| unreachable!("AES UDP inputs have validated fixed widths")),
                })
            }
            UdpCryptoInner::ChaCha20Poly1305(_) => None,
        }
    }

    fn validate_aes_session_cipher<'a>(
        &self,
        cached: &'a UdpAesSessionCipher,
        session_id: &UdpSessionId,
    ) -> Result<&'a ShadowsocksUdpCipher, UdpCryptoError> {
        let owner = self
            .aes_owner
            .as_ref()
            .ok_or(UdpCryptoError::MethodMismatch)?;
        if cached.session_id != *session_id
            || !std::ptr::eq(cached.owner.as_ptr(), Arc::as_ptr(owner))
        {
            return Err(UdpCryptoError::MethodMismatch);
        }
        Ok(&cached.cipher)
    }

    fn outbound_aes_body_cipher<'a>(
        &self,
        outbound: &'a UdpOutboundSession,
    ) -> Result<&'a ShadowsocksUdpCipher, UdpCryptoError> {
        let cached = outbound
            .aes_body_cipher
            .as_ref()
            .ok_or(UdpCryptoError::MethodMismatch)?;
        self.validate_aes_session_cipher(cached, &outbound.session_id)
    }

    #[cfg(test)]
    fn aes_body_cipher_derivation_count(&self) -> usize {
        self.aes_owner.as_ref().map_or(0, |owner| {
            owner
                .aes_body_cipher_derivations
                .load(AtomicOrdering::Relaxed)
        })
    }

    /// Reserves the exact method-specific wire layout for one semantic body.
    ///
    /// The returned reservation lends only the semantic plaintext body range
    /// to the caller. Dropping it before a successful seal clears the complete
    /// reserved wire range and leaves the packet counter uncommitted.
    pub fn reserve_seal<'a>(
        &'a self,
        outbound: &'a mut UdpOutboundSession,
        body_len: usize,
        output: &'a mut [u8],
    ) -> Result<UdpSealReservation<'a>, UdpCryptoError> {
        if outbound.profile != self.profile() {
            return Err(UdpCryptoError::MethodMismatch);
        }
        if matches!(self.inner, UdpCryptoInner::Aes { .. }) {
            let _ = self.outbound_aes_body_cipher(outbound)?;
        } else if outbound.aes_body_cipher.is_some() {
            return Err(UdpCryptoError::MethodMismatch);
        }
        let packet_id = outbound.counter.current()?;
        let wire_len = body_len
            .checked_add(self.profile().udp_wire_overhead_bytes())
            .ok_or(UdpCryptoError::OutputTooSmall)?;
        if output.len() < wire_len {
            return Err(UdpCryptoError::OutputTooSmall);
        }
        let body_start = match self.inner {
            UdpCryptoInner::Aes { .. } => UDP_IDENTITY_BYTES,
            UdpCryptoInner::ChaCha20Poly1305(_) => XCHACHA_NONCE_BYTES + UDP_IDENTITY_BYTES,
        };
        let body_end = body_start
            .checked_add(body_len)
            .ok_or(UdpCryptoError::OutputTooSmall)?;
        debug_assert_eq!(body_end + AEAD_TAG_BYTES, wire_len);
        Ok(UdpSealReservation {
            crypto: self,
            outbound,
            output,
            body_range: body_start..body_end,
            wire_len,
            packet_id,
            sealed: false,
        })
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
        let mut reservation = self.reserve_seal(outbound, plaintext_body.len(), output)?;
        reservation.body_mut().copy_from_slice(plaintext_body);
        reservation.seal(random)
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
        self.open_with_aes_session_cipher(wire, plaintext_output, |_| None)
    }

    /// Opens one copied UDP envelope while consulting an accepted-session AES cache.
    ///
    /// This compatibility path still copies candidate ciphertext into caller output.
    /// Owned production receives should prefer [`Self::open_in_place_with_aes_session_cipher`].
    pub fn open_with_aes_session_cipher(
        &self,
        wire: &[u8],
        plaintext_output: &mut [u8],
        resolve: impl FnOnce(&UdpSessionId) -> Option<Arc<UdpAesSessionCipher>>,
    ) -> Result<UdpOpenResult, UdpCryptoError> {
        match &self.inner {
            UdpCryptoInner::Aes { .. } => open_aes_udp(self, wire, plaintext_output, resolve),
            UdpCryptoInner::ChaCha20Poly1305(cipher) => {
                open_xchacha_udp(cipher, wire, plaintext_output)
            }
        }
    }

    /// Destructively authenticates one exclusively owned wire buffer in place.
    ///
    /// The result names the authenticated semantic body range without moving
    /// it. AES opens its body after the protected identity header; XChaCha
    /// leaves the authenticated identity prefix before the body. Authentication
    /// failure clears the complete candidate-plaintext range.
    pub fn open_in_place(&self, wire: &mut BytesMut) -> Result<UdpOpenResult, UdpCryptoError> {
        self.open_in_place_with_aes_session_cipher(wire, |_| None)
    }

    /// Destructively opens one UDP envelope while consulting an accepted-session AES cache.
    ///
    /// AES invokes `resolve` exactly once with the protected-header session ID. A cache miss
    /// derives temporary state for this packet; a returned token from another owner or session
    /// fails closed. ChaCha never invokes the resolver.
    pub fn open_in_place_with_aes_session_cipher(
        &self,
        wire: &mut BytesMut,
        resolve: impl FnOnce(&UdpSessionId) -> Option<Arc<UdpAesSessionCipher>>,
    ) -> Result<UdpOpenResult, UdpCryptoError> {
        match &self.inner {
            UdpCryptoInner::Aes { .. } => open_aes_udp_in_place(self, wire, resolve),
            UdpCryptoInner::ChaCha20Poly1305(cipher) => open_xchacha_udp_in_place(cipher, wire),
        }
    }
}

/// Exact final-wire reservation for one caller-built UDP semantic body.
///
/// Callers must completely initialize [`Self::body_mut`] before sealing. The
/// reservation owns counter commit and all method-specific layout details.
pub struct UdpSealReservation<'a> {
    crypto: &'a UdpCrypto,
    outbound: &'a mut UdpOutboundSession,
    output: &'a mut [u8],
    body_range: Range<usize>,
    wire_len: usize,
    packet_id: u64,
    sealed: bool,
}

impl UdpSealReservation<'_> {
    /// Returns the exact semantic plaintext body region in the final wire.
    pub fn body_mut(&mut self) -> &mut [u8] {
        &mut self.output[self.body_range.clone()]
    }

    /// Seals the initialized body and commits the reserved packet ID.
    pub fn seal(
        mut self,
        random: &(impl SecureRandom + ?Sized),
    ) -> Result<UdpSealResult, UdpCryptoError> {
        let result = match &self.crypto.inner {
            UdpCryptoInner::Aes { .. } => {
                let cipher = self.crypto.outbound_aes_body_cipher(self.outbound)?;
                seal_aes_udp_in_place(
                    self.crypto,
                    cipher,
                    &self.outbound.session_id,
                    self.packet_id,
                    self.body_range.clone(),
                    &mut self.output[..self.wire_len],
                )
            }
            UdpCryptoInner::ChaCha20Poly1305(cipher) => seal_xchacha_udp_in_place(
                cipher,
                random,
                &self.outbound.session_id,
                self.packet_id,
                self.body_range.clone(),
                &mut self.output[..self.wire_len],
            ),
        };
        result?;
        self.outbound.counter.commit(self.packet_id);
        self.sealed = true;
        Ok(UdpSealResult {
            wire_len: self.wire_len,
            packet_id: self.packet_id,
        })
    }
}

impl Drop for UdpSealReservation<'_> {
    fn drop(&mut self) {
        if !self.sealed {
            self.output[..self.wire_len].zeroize();
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
    authenticated_offset: usize,
    authenticated_len: usize,
    plaintext_offset: usize,
    plaintext_len: usize,
    aes_session_cipher: Option<UdpAesSessionCipher>,
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

    /// Returns the authenticated semantic body range in the opened buffer.
    pub fn plaintext_range(&self) -> Range<usize> {
        self.plaintext_offset..self.plaintext_offset + self.plaintext_len
    }

    /// Returns every authenticated cleartext byte requiring cleanup if a
    /// later semantic or replay check rejects the packet.
    pub fn authenticated_range(&self) -> Range<usize> {
        self.authenticated_offset..self.authenticated_offset + self.authenticated_len
    }

    /// Transfers the authenticated cold-miss AES cipher to protocol commit state.
    ///
    /// Cache hits and ChaCha packets return `None`. The opaque token remains
    /// move-only so rejected or abandoned protocol transitions cannot publish it.
    pub fn into_aes_session_cipher(self) -> Option<UdpAesSessionCipher> {
        self.aes_session_cipher
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
    /// The outbound session or AES cache token belongs to another owner, method, or session.
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
            Self::MethodMismatch => "UDP cryptographic owner mismatch",
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

fn seal_aes_udp_in_place(
    crypto: &UdpCrypto,
    cipher: &ShadowsocksUdpCipher,
    session_id: &UdpSessionId,
    packet_id: u64,
    body_range: Range<usize>,
    output: &mut [u8],
) -> Result<(), UdpCryptoError> {
    let mut identity = Zeroizing::new(udp_identity(session_id, packet_id));
    let mut protected_header = *identity;
    crypto.crypt_aes_header(&mut protected_header, true);
    output[..UDP_IDENTITY_BYTES].copy_from_slice(&protected_header);

    let mut nonce = Zeroizing::new([0_u8; AEAD_NONCE_BYTES]);
    nonce.copy_from_slice(&identity[4..UDP_IDENTITY_BYTES]);
    let tag = cipher
        .encrypt_packet(nonce.as_ref(), &mut output[body_range.clone()])
        .map_err(map_udp_operation_error)?;
    output[body_range.end..body_range.end + AEAD_TAG_BYTES].copy_from_slice(&tag);

    protected_header.zeroize();
    nonce.zeroize();
    identity.zeroize();
    Ok(())
}

fn seal_xchacha_udp_in_place(
    cipher: &ShadowsocksUdpCipher,
    random: &(impl SecureRandom + ?Sized),
    session_id: &UdpSessionId,
    packet_id: u64,
    body_range: Range<usize>,
    output: &mut [u8],
) -> Result<(), UdpCryptoError> {
    let mut nonce = Zeroizing::new([0_u8; XCHACHA_NONCE_BYTES]);
    random
        .fill(nonce.as_mut())
        .map_err(|_| UdpCryptoError::RandomUnavailable)?;

    let encrypted_start = XCHACHA_NONCE_BYTES;
    output[encrypted_start..encrypted_start + UDP_SESSION_ID_BYTES]
        .copy_from_slice(&session_id.bytes);
    output[encrypted_start + UDP_SESSION_ID_BYTES..encrypted_start + UDP_IDENTITY_BYTES]
        .copy_from_slice(&packet_id.to_be_bytes());

    let tag = cipher
        .encrypt_packet(nonce.as_ref(), &mut output[encrypted_start..body_range.end])
        .map_err(map_udp_operation_error)?;
    output[..XCHACHA_NONCE_BYTES].copy_from_slice(nonce.as_ref());
    output[body_range.end..body_range.end + AEAD_TAG_BYTES].copy_from_slice(&tag);
    nonce.zeroize();
    Ok(())
}

fn open_aes_udp(
    crypto: &UdpCrypto,
    wire: &[u8],
    plaintext_output: &mut [u8],
    resolve: impl FnOnce(&UdpSessionId) -> Option<Arc<UdpAesSessionCipher>>,
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
    let cached = resolve(&candidate_session);
    let temporary = cached.is_none().then(|| {
        crypto
            .derive_aes_session_cipher(&candidate_session)
            .unwrap_or_else(|| unreachable!("AES open uses an AES crypto owner"))
    });
    let selected = cached
        .as_deref()
        .or(temporary.as_ref())
        .unwrap_or_else(|| unreachable!("AES resolution always selects one cipher"));
    let cipher = match crypto.validate_aes_session_cipher(selected, &candidate_session) {
        Ok(cipher) => cipher,
        Err(error) => {
            plaintext_output[..body_len].zeroize();
            return Err(error);
        }
    };

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
        authenticated_offset: 0,
        authenticated_len: body_len,
        plaintext_offset: 0,
        plaintext_len: body_len,
        aes_session_cipher: temporary,
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
        authenticated_offset: 0,
        authenticated_len: body_len,
        plaintext_offset: 0,
        plaintext_len: body_len,
        aes_session_cipher: None,
    })
}

fn open_aes_udp_in_place(
    crypto: &UdpCrypto,
    wire: &mut BytesMut,
    resolve: impl FnOnce(&UdpSessionId) -> Option<Arc<UdpAesSessionCipher>>,
) -> Result<UdpOpenResult, UdpCryptoError> {
    let body_len = wire
        .len()
        .checked_sub(UDP_IDENTITY_BYTES + AEAD_TAG_BYTES)
        .ok_or(UdpCryptoError::InputTooShort)?;
    let body_range = UDP_IDENTITY_BYTES..UDP_IDENTITY_BYTES + body_len;
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
    let cached = resolve(&candidate_session);
    let temporary = cached.is_none().then(|| {
        crypto
            .derive_aes_session_cipher(&candidate_session)
            .unwrap_or_else(|| unreachable!("AES open uses an AES crypto owner"))
    });
    let selected = cached
        .as_deref()
        .or(temporary.as_ref())
        .unwrap_or_else(|| unreachable!("AES resolution always selects one cipher"));
    let cipher = match crypto.validate_aes_session_cipher(selected, &candidate_session) {
        Ok(cipher) => cipher,
        Err(error) => {
            wire[body_range.clone()].zeroize();
            return Err(error);
        }
    };
    let tag_bytes: [u8; AEAD_TAG_BYTES] = wire[body_range.end..]
        .try_into()
        .unwrap_or_else(|_| unreachable!("validated UDP tag width"));
    let result = cipher.decrypt_packet(nonce.as_ref(), &mut wire[body_range.clone()], &tag_bytes);

    identity.zeroize();
    nonce.zeroize();
    if result.is_err() {
        return Err(UdpCryptoError::AuthenticationFailed);
    }
    Ok(UdpOpenResult {
        session_id: candidate_session,
        packet_id,
        authenticated_offset: body_range.start,
        authenticated_len: body_len,
        plaintext_offset: body_range.start,
        plaintext_len: body_len,
        aes_session_cipher: temporary,
    })
}

fn open_xchacha_udp_in_place(
    cipher: &ShadowsocksUdpCipher,
    wire: &mut BytesMut,
) -> Result<UdpOpenResult, UdpCryptoError> {
    let encrypted_len = wire
        .len()
        .checked_sub(XCHACHA_NONCE_BYTES + AEAD_TAG_BYTES)
        .filter(|length| *length >= UDP_IDENTITY_BYTES)
        .ok_or(UdpCryptoError::InputTooShort)?;
    let encrypted_range = XCHACHA_NONCE_BYTES..XCHACHA_NONCE_BYTES + encrypted_len;
    let mut nonce = Zeroizing::new([0_u8; XCHACHA_NONCE_BYTES]);
    nonce.copy_from_slice(&wire[..XCHACHA_NONCE_BYTES]);
    let tag_bytes: [u8; AEAD_TAG_BYTES] = wire[encrypted_range.end..]
        .try_into()
        .unwrap_or_else(|_| unreachable!("validated UDP tag width"));
    let result = cipher.decrypt_packet(
        nonce.as_ref(),
        &mut wire[encrypted_range.clone()],
        &tag_bytes,
    );
    nonce.zeroize();
    if result.is_err() {
        return Err(UdpCryptoError::AuthenticationFailed);
    }

    let identity_start = encrypted_range.start;
    let identity_end = identity_start + UDP_IDENTITY_BYTES;
    let mut session_bytes = [0_u8; UDP_SESSION_ID_BYTES];
    session_bytes.copy_from_slice(&wire[identity_start..identity_start + UDP_SESSION_ID_BYTES]);
    let packet_id = u64::from_be_bytes(
        wire[identity_start + UDP_SESSION_ID_BYTES..identity_end]
            .try_into()
            .unwrap_or_else(|_| unreachable!("UDP packet IDs have a fixed width")),
    );
    Ok(UdpOpenResult {
        session_id: UdpSessionId::from_bytes(session_bytes),
        packet_id,
        authenticated_offset: encrypted_range.start,
        authenticated_len: encrypted_len,
        plaintext_offset: identity_end,
        plaintext_len: encrypted_len - UDP_IDENTITY_BYTES,
        aes_session_cipher: None,
    })
}

fn map_udp_operation_error(_: ShadowsocksCryptoError) -> UdpCryptoError {
    UdpCryptoError::OperationFailed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method::{AES_128_KEY_BYTES, WIDE_KEY_BYTES};
    use crate::random::{RandomError, SystemRandom};
    use std::sync::atomic::{AtomicBool, Ordering};
    use zeroize::Zeroizing;

    fn aes128_udp_crypto() -> UdpCrypto {
        let psk = MethodPskBytes::Aes128(Zeroizing::new([0x11; AES_128_KEY_BYTES]));
        UdpCrypto::from_method_key(&psk)
    }

    fn aes256_udp_crypto() -> UdpCrypto {
        let psk = MethodPskBytes::Aes256(Zeroizing::new([0x33; WIDE_KEY_BYTES]));
        UdpCrypto::from_method_key(&psk)
    }

    fn chacha20_udp_crypto() -> UdpCrypto {
        let psk = MethodPskBytes::ChaCha20Poly1305(Zeroizing::new([0x55; WIDE_KEY_BYTES]));
        UdpCrypto::from_method_key(&psk)
    }

    fn udp_cryptos() -> [UdpCrypto; 3] {
        [
            aes128_udp_crypto(),
            aes256_udp_crypto(),
            chacha20_udp_crypto(),
        ]
    }

    struct FailingRandom;

    impl SecureRandom for FailingRandom {
        fn fill(&self, _destination: &mut [u8]) -> Result<(), RandomError> {
            Err(RandomError::Unavailable)
        }
    }

    #[test]
    fn udp_reservation_builds_final_wire_and_owned_open_keeps_body_at_profile_offset() {
        let body = b"semantic body is written once";

        for crypto in udp_cryptos() {
            let session_id = UdpSessionId::from_bytes([0x77; UDP_SESSION_ID_BYTES]);
            let aes_body_cipher = crypto.derive_aes_session_cipher(&session_id);
            let mut outbound =
                UdpOutboundSession::new(crypto.profile(), session_id, aes_body_cipher);
            let wire_len = body.len() + crypto.profile().udp_wire_overhead_bytes();
            let mut wire = BytesMut::from(&vec![0xa5; wire_len][..]);
            let mut reservation = crypto
                .reserve_seal(&mut outbound, body.len(), &mut wire)
                .expect("exact final wire reserves");
            assert_eq!(reservation.body_mut().len(), body.len());
            reservation.body_mut().copy_from_slice(body);
            let sealed = reservation.seal(&SystemRandom).expect("wire seals");
            assert_eq!(sealed.packet_id(), 0);
            assert_eq!(sealed.wire_len(), wire_len);

            let opened = crypto
                .open_in_place(&mut wire)
                .expect("owned wire authenticates");
            let expected_offset = match crypto.profile() {
                MethodProfile::Blake3Aes128Gcm2022 | MethodProfile::Blake3Aes256Gcm2022 => {
                    UDP_IDENTITY_BYTES
                }
                MethodProfile::Blake3ChaCha20Poly13052022 => {
                    XCHACHA_NONCE_BYTES + UDP_IDENTITY_BYTES
                }
            };
            assert_eq!(
                opened.plaintext_range(),
                expected_offset..expected_offset + body.len()
            );
            let authenticated_offset = match crypto.profile() {
                MethodProfile::Blake3Aes128Gcm2022 | MethodProfile::Blake3Aes256Gcm2022 => {
                    UDP_IDENTITY_BYTES
                }
                MethodProfile::Blake3ChaCha20Poly13052022 => XCHACHA_NONCE_BYTES,
            };
            assert_eq!(
                opened.authenticated_range(),
                authenticated_offset..expected_offset + body.len()
            );
            assert_eq!(&wire[opened.plaintext_range()], body);
        }
    }

    #[test]
    fn udp_owned_open_auth_failure_clears_every_candidate_plaintext_byte() {
        let body = b"unauthenticated plaintext must not escape";

        for crypto in udp_cryptos() {
            let session_id = UdpSessionId::from_bytes([0x88; UDP_SESSION_ID_BYTES]);
            let aes_body_cipher = crypto.derive_aes_session_cipher(&session_id);
            let mut outbound =
                UdpOutboundSession::new(crypto.profile(), session_id, aes_body_cipher);
            let mut wire = BytesMut::from(
                &vec![0xa5; body.len() + crypto.profile().udp_wire_overhead_bytes()][..],
            );
            let sealed = crypto
                .seal(&mut outbound, body, &mut wire, &SystemRandom)
                .expect("wire seals");
            *wire
                .get_mut(sealed.wire_len() - 1)
                .expect("authentication tag byte") ^= 1;
            let candidate_range = match crypto.profile() {
                MethodProfile::Blake3Aes128Gcm2022 | MethodProfile::Blake3Aes256Gcm2022 => {
                    UDP_IDENTITY_BYTES..sealed.wire_len() - AEAD_TAG_BYTES
                }
                MethodProfile::Blake3ChaCha20Poly13052022 => {
                    XCHACHA_NONCE_BYTES..sealed.wire_len() - AEAD_TAG_BYTES
                }
            };

            assert!(matches!(
                crypto.open_in_place(&mut wire),
                Err(UdpCryptoError::AuthenticationFailed)
            ));
            assert!(wire[candidate_range].iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn udp_dropped_or_failed_reservation_clears_wire_and_does_not_commit_counter() {
        let body_len = 17;
        let crypto = chacha20_udp_crypto();
        let session_id = UdpSessionId::from_bytes([0x99; UDP_SESSION_ID_BYTES]);
        let aes_body_cipher = crypto.derive_aes_session_cipher(&session_id);
        let mut outbound = UdpOutboundSession::new(crypto.profile(), session_id, aes_body_cipher);
        let wire_len = body_len + crypto.profile().udp_wire_overhead_bytes();
        let mut output = [0xa5; 96];

        {
            let mut reservation = crypto
                .reserve_seal(&mut outbound, body_len, &mut output)
                .expect("reservation");
            reservation.body_mut().fill(0x42);
        }
        assert!(output[..wire_len].iter().all(|byte| *byte == 0));
        assert!(output[wire_len..].iter().all(|byte| *byte == 0xa5));

        output.fill(0xa5);
        let mut reservation = crypto
            .reserve_seal(&mut outbound, body_len, &mut output)
            .expect("retry reservation");
        reservation.body_mut().fill(0x24);
        assert!(matches!(
            reservation.seal(&FailingRandom),
            Err(UdpCryptoError::RandomUnavailable)
        ));
        assert!(output[..wire_len].iter().all(|byte| *byte == 0));

        let sealed = crypto
            .seal(&mut outbound, b"ok", &mut output, &SystemRandom)
            .expect("failed reservations did not commit counter");
        assert_eq!(sealed.packet_id(), 0);
    }

    #[test]
    fn udp_outbound_session_commits_zero_terminal_and_exhausted_states_only_on_success() {
        let crypto = aes128_udp_crypto();
        let session_id = UdpSessionId::from_bytes([0x22; UDP_SESSION_ID_BYTES]);
        let aes_body_cipher = crypto.derive_aes_session_cipher(&session_id);
        let mut outbound = UdpOutboundSession::new(crypto.profile(), session_id, aes_body_cipher);
        let mut output = [0xa5; 64];

        let original = output;
        assert!(matches!(
            aes256_udp_crypto().seal(&mut outbound, b"body", &mut output, &SystemRandom),
            Err(UdpCryptoError::MethodMismatch)
        ));
        assert_eq!(output, original);
        assert!(matches!(
            aes128_udp_crypto().seal(&mut outbound, b"body", &mut output, &SystemRandom),
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

    #[test]
    fn aes_session_cache_derives_once_for_outbound_and_hits_without_rederivation() {
        let crypto = aes128_udp_crypto();
        let mut outbound = crypto
            .generate_outbound_session(&SystemRandom, |_| false)
            .expect("outbound session");
        assert_eq!(crypto.aes_body_cipher_derivation_count(), 1);
        let mut first_wire = BytesMut::from(&vec![0; 96][..]);
        let first = crypto
            .seal(&mut outbound, b"first", &mut first_wire, &SystemRandom)
            .expect("first packet");
        first_wire.truncate(first.wire_len());
        let mut second_wire = BytesMut::from(&vec![0; 96][..]);
        let second = crypto
            .seal(&mut outbound, b"second", &mut second_wire, &SystemRandom)
            .expect("second packet");
        second_wire.truncate(second.wire_len());
        assert_eq!(crypto.aes_body_cipher_derivation_count(), 1);

        let accepted = Arc::new(
            crypto
                .derive_aes_session_cipher(outbound.session_id())
                .expect("AES cache token"),
        );
        assert_eq!(crypto.aes_body_cipher_derivation_count(), 2);
        let opened = crypto
            .open_in_place_with_aes_session_cipher(&mut first_wire, |_| Some(Arc::clone(&accepted)))
            .expect("accepted cache hit");
        assert_eq!(&first_wire[opened.plaintext_range()], b"first");
        assert!(opened.into_aes_session_cipher().is_none());
        assert_eq!(crypto.aes_body_cipher_derivation_count(), 2);
        let mut copied_plaintext = vec![0xa5; second_wire.len()];
        let copied = crypto
            .open_with_aes_session_cipher(&second_wire, &mut copied_plaintext, |_| {
                Some(Arc::clone(&accepted))
            })
            .expect("copied cache hit");
        assert_eq!(&copied_plaintext[copied.plaintext_range()], b"second");
        assert_eq!(crypto.aes_body_cipher_derivation_count(), 2);

        let mut miss_wire = BytesMut::from(&vec![0; 96][..]);
        let miss = crypto
            .seal(&mut outbound, b"miss", &mut miss_wire, &SystemRandom)
            .expect("miss packet");
        miss_wire.truncate(miss.wire_len());
        let cold_miss = crypto
            .open_in_place_with_aes_session_cipher(&mut miss_wire, |_| None)
            .expect("cold miss derives temporary state");
        assert_eq!(crypto.aes_body_cipher_derivation_count(), 3);
        let cold_miss = Arc::new(
            cold_miss
                .into_aes_session_cipher()
                .expect("authenticated miss transfers its derived cipher"),
        );
        let mut established_wire = BytesMut::from(&vec![0; 96][..]);
        let established = crypto
            .seal(
                &mut outbound,
                b"established",
                &mut established_wire,
                &SystemRandom,
            )
            .expect("established packet");
        established_wire.truncate(established.wire_len());
        let established = crypto
            .open_in_place_with_aes_session_cipher(&mut established_wire, |_| {
                Some(Arc::clone(&cold_miss))
            })
            .expect("handoff cache hit");
        assert!(established.into_aes_session_cipher().is_none());
        assert_eq!(crypto.aes_body_cipher_derivation_count(), 3);

        let mut rejected_wire = BytesMut::from(&vec![0; 96][..]);
        let rejected = crypto
            .seal(
                &mut outbound,
                b"authentication failure",
                &mut rejected_wire,
                &SystemRandom,
            )
            .expect("rejected packet");
        rejected_wire.truncate(rejected.wire_len());
        *rejected_wire.last_mut().expect("tag") ^= 1;
        let body_range = UDP_IDENTITY_BYTES..rejected_wire.len() - AEAD_TAG_BYTES;
        assert!(matches!(
            crypto.open_in_place_with_aes_session_cipher(&mut rejected_wire, |_| {
                Some(Arc::clone(&accepted))
            }),
            Err(UdpCryptoError::AuthenticationFailed)
        ));
        assert!(rejected_wire[body_range].iter().all(|byte| *byte == 0));
        assert_eq!(crypto.aes_body_cipher_derivation_count(), 3);
    }

    #[test]
    fn aes_cache_owner_and_session_mismatch_fail_closed_without_fallback_derivation() {
        let old_crypto = aes128_udp_crypto();
        let new_crypto = aes128_udp_crypto();
        let mut outbound = old_crypto
            .generate_outbound_session(&SystemRandom, |_| false)
            .expect("outbound session");
        let old_cache = Arc::new(
            old_crypto
                .derive_aes_session_cipher(outbound.session_id())
                .expect("old owner token"),
        );
        let mut wire = BytesMut::from(&vec![0; 96][..]);
        let sealed = old_crypto
            .seal(&mut outbound, b"owner-bound", &mut wire, &SystemRandom)
            .expect("packet");
        wire.truncate(sealed.wire_len());
        let body_range = UDP_IDENTITY_BYTES..wire.len() - AEAD_TAG_BYTES;
        assert_eq!(new_crypto.aes_body_cipher_derivation_count(), 0);
        assert!(matches!(
            new_crypto.open_in_place_with_aes_session_cipher(&mut wire, |_| {
                Some(Arc::clone(&old_cache))
            }),
            Err(UdpCryptoError::MethodMismatch)
        ));
        assert!(wire[body_range].iter().all(|byte| *byte == 0));
        assert_eq!(new_crypto.aes_body_cipher_derivation_count(), 0);

        let different_session = UdpSessionId::from_bytes([0x7a; UDP_SESSION_ID_BYTES]);
        let wrong_session_cache = Arc::new(
            old_crypto
                .derive_aes_session_cipher(&different_session)
                .expect("different session token"),
        );
        let mut second_wire = BytesMut::from(&vec![0; 96][..]);
        let sealed = old_crypto
            .seal(
                &mut outbound,
                b"session-bound",
                &mut second_wire,
                &SystemRandom,
            )
            .expect("second packet");
        second_wire.truncate(sealed.wire_len());
        let body_range = UDP_IDENTITY_BYTES..second_wire.len() - AEAD_TAG_BYTES;
        let before = old_crypto.aes_body_cipher_derivation_count();
        assert!(matches!(
            old_crypto.open_in_place_with_aes_session_cipher(&mut second_wire, |_| {
                Some(Arc::clone(&wrong_session_cache))
            }),
            Err(UdpCryptoError::MethodMismatch)
        ));
        assert!(second_wire[body_range].iter().all(|byte| *byte == 0));
        assert_eq!(old_crypto.aes_body_cipher_derivation_count(), before);
    }

    #[test]
    fn chacha_open_never_invokes_aes_resolver() {
        let crypto = chacha20_udp_crypto();
        let mut outbound = crypto
            .generate_outbound_session(&SystemRandom, |_| false)
            .expect("outbound session");
        let mut wire = BytesMut::from(&vec![0; 128][..]);
        let sealed = crypto
            .seal(&mut outbound, b"chacha", &mut wire, &SystemRandom)
            .expect("packet");
        wire.truncate(sealed.wire_len());
        let called = AtomicBool::new(false);
        let opened = crypto
            .open_in_place_with_aes_session_cipher(&mut wire, |_| {
                called.store(true, Ordering::SeqCst);
                None
            })
            .expect("ChaCha packet");
        assert!(opened.into_aes_session_cipher().is_none());
        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(crypto.aes_body_cipher_derivation_count(), 0);
    }

    #[test]
    fn aes_cache_is_redacted_send_sync_and_does_not_retain_its_crypto_owner() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<UdpAesSessionCipher>();
        assert_send_sync::<Arc<UdpAesSessionCipher>>();

        let crypto = aes256_udp_crypto();
        let session_id = UdpSessionId::from_bytes([0x91; UDP_SESSION_ID_BYTES]);
        let cached = crypto
            .derive_aes_session_cipher(&session_id)
            .expect("AES cache token");
        assert_eq!(format!("{cached:?}"), "UdpAesSessionCipher([REDACTED])");
        assert!(cached.owner.upgrade().is_some());
        drop(crypto);
        assert!(cached.owner.upgrade().is_none());
    }
}
