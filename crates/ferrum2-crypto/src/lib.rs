#![forbid(unsafe_code)]

use std::collections::hash_map::DefaultHasher;
use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use shadowsocks_crypto::{
    CipherKind,
    v2::{
        CryptoError as ShadowsocksCryptoError,
        tcp::TcpCipher as ShadowsocksTcpCipher,
        udp::{AesHeaderCipher as ShadowsocksAesHeaderCipher, UdpCipher as ShadowsocksUdpCipher},
    },
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const AES_128_KEY_BYTES: usize = 16;
const WIDE_KEY_BYTES: usize = 32;
const AEAD_NONCE_BYTES: usize = 12;
const AEAD_TAG_BYTES: usize = 16;
const UDP_SESSION_ID_BYTES: usize = 8;
const UDP_PACKET_ID_BYTES: usize = 8;
const UDP_IDENTITY_BYTES: usize = UDP_SESSION_ID_BYTES + UDP_PACKET_ID_BYTES;
const XCHACHA_NONCE_BYTES: usize = 24;
const RESPONSE_SALT_ATTEMPTS: usize = 8;
const UDP_SESSION_ID_ATTEMPTS: usize = 8;

/// One of the three immutable SIP022 cryptographic method profiles.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodProfile {
    /// SIP022 `2022-blake3-aes-128-gcm`.
    Blake3Aes128Gcm2022,
    /// SIP022 `2022-blake3-aes-256-gcm`.
    Blake3Aes256Gcm2022,
    /// SIP022-compatible `2022-blake3-chacha20-poly1305`.
    Blake3ChaCha20Poly13052022,
}

impl MethodProfile {
    /// The complete supported profile table.
    pub const ALL: [Self; 3] = [
        Self::Blake3Aes128Gcm2022,
        Self::Blake3Aes256Gcm2022,
        Self::Blake3ChaCha20Poly13052022,
    ];

    /// Returns the canonical configuration method name.
    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Blake3Aes128Gcm2022 => "2022-blake3-aes-128-gcm",
            Self::Blake3Aes256Gcm2022 => "2022-blake3-aes-256-gcm",
            Self::Blake3ChaCha20Poly13052022 => "2022-blake3-chacha20-poly1305",
        }
    }

    /// Returns the exact PSK, salt, and derived-subkey width.
    pub const fn key_bytes(self) -> usize {
        match self {
            Self::Blake3Aes128Gcm2022 => AES_128_KEY_BYTES,
            Self::Blake3Aes256Gcm2022 | Self::Blake3ChaCha20Poly13052022 => WIDE_KEY_BYTES,
        }
    }

    /// Returns the exact TCP salt width.
    pub const fn salt_bytes(self) -> usize {
        self.key_bytes()
    }

    /// Returns the fixed AEAD tag width.
    pub const fn tag_bytes(self) -> usize {
        AEAD_TAG_BYTES
    }

    /// Returns the fixed TCP nonce width.
    pub const fn nonce_bytes(self) -> usize {
        AEAD_NONCE_BYTES
    }

    /// Returns the method-derived initial request read width.
    pub const fn initial_request_read_bytes(self) -> usize {
        self.salt_bytes() + 27
    }

    /// Returns the method-derived initial response read width.
    pub const fn initial_response_read_bytes(self) -> usize {
        self.salt_bytes() * 2 + 27
    }

    /// Returns the complete UDP crypto overhead around a caller's body.
    ///
    /// AES uses a protected 16-byte separate header and a 16-byte tag.
    /// ChaCha authenticates the 16-byte identity inside the body and prefixes
    /// a fresh 24-byte nonce plus a 16-byte tag.
    pub const fn udp_wire_overhead_bytes(self) -> usize {
        match self {
            Self::Blake3Aes128Gcm2022 | Self::Blake3Aes256Gcm2022 => {
                UDP_IDENTITY_BYTES + AEAD_TAG_BYTES
            }
            Self::Blake3ChaCha20Poly13052022 => {
                XCHACHA_NONCE_BYTES + UDP_IDENTITY_BYTES + AEAD_TAG_BYTES
            }
        }
    }

    const fn cipher_kind(self) -> CipherKind {
        match self {
            Self::Blake3Aes128Gcm2022 => CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
            Self::Blake3Aes256Gcm2022 => CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
            Self::Blake3ChaCha20Poly13052022 => CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
        }
    }
}

/// An immutable method-bound pre-shared key.
///
/// Its private variant binds the selected method to the only accepted key
/// width. The owner is intentionally neither `Clone` nor printable.
pub struct MethodPsk {
    bytes: MethodPskBytes,
}

enum MethodPskBytes {
    Aes128(Zeroizing<[u8; AES_128_KEY_BYTES]>),
    Aes256(Zeroizing<[u8; WIDE_KEY_BYTES]>),
    ChaCha20Poly1305(Zeroizing<[u8; WIDE_KEY_BYTES]>),
}

impl MethodPskBytes {
    const fn profile(&self) -> MethodProfile {
        match self {
            Self::Aes128(_) => MethodProfile::Blake3Aes128Gcm2022,
            Self::Aes256(_) => MethodProfile::Blake3Aes256Gcm2022,
            Self::ChaCha20Poly1305(_) => MethodProfile::Blake3ChaCha20Poly13052022,
        }
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Aes128(bytes) => bytes.as_ref(),
            Self::Aes256(bytes) | Self::ChaCha20Poly1305(bytes) => bytes.as_ref(),
        }
    }
}

impl MethodPsk {
    /// Takes ownership of an AES-128 profile PSK.
    pub fn aes128(bytes: [u8; AES_128_KEY_BYTES]) -> Self {
        Self {
            bytes: MethodPskBytes::Aes128(Zeroizing::new(bytes)),
        }
    }

    /// Takes ownership of an AES-256 profile PSK.
    pub fn aes256(bytes: [u8; WIDE_KEY_BYTES]) -> Self {
        Self {
            bytes: MethodPskBytes::Aes256(Zeroizing::new(bytes)),
        }
    }

    /// Takes ownership of a ChaCha20-Poly1305 profile PSK.
    pub fn chacha20_poly1305(bytes: [u8; WIDE_KEY_BYTES]) -> Self {
        Self {
            bytes: MethodPskBytes::ChaCha20Poly1305(Zeroizing::new(bytes)),
        }
    }

    /// Copies a decoded PSK only when its width matches the selected profile.
    pub fn try_from_slice(
        profile: MethodProfile,
        bytes: &[u8],
    ) -> Result<Self, MethodPskLengthError> {
        match profile {
            MethodProfile::Blake3Aes128Gcm2022 => bytes
                .try_into()
                .map(Self::aes128)
                .map_err(|_| MethodPskLengthError),
            MethodProfile::Blake3Aes256Gcm2022 => bytes
                .try_into()
                .map(Self::aes256)
                .map_err(|_| MethodPskLengthError),
            MethodProfile::Blake3ChaCha20Poly13052022 => bytes
                .try_into()
                .map(Self::chacha20_poly1305)
                .map_err(|_| MethodPskLengthError),
        }
    }

    /// Returns the immutable profile bound to this PSK.
    pub const fn profile(&self) -> MethodProfile {
        self.bytes.profile()
    }

    /// Explicitly clears the owned PSK without changing its bound profile.
    pub fn clear(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for MethodPsk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MethodPsk([REDACTED])")
    }
}

impl Zeroize for MethodPsk {
    fn zeroize(&mut self) {
        match &mut self.bytes {
            MethodPskBytes::Aes128(bytes) => bytes.zeroize(),
            MethodPskBytes::Aes256(bytes) | MethodPskBytes::ChaCha20Poly1305(bytes) => {
                bytes.zeroize();
            }
        }
    }
}

impl ZeroizeOnDrop for MethodPsk {}

/// A redacted error for a decoded PSK with the wrong profile width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MethodPskLengthError;

impl fmt::Display for MethodPskLengthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid pre-shared key length for selected method")
    }
}

impl Error for MethodPskLengthError {}

/// An exact-width TCP salt bound to one cryptographic profile.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct MethodTcpSalt {
    bytes: MethodSaltBytes,
}

#[derive(Clone, Eq, Hash, PartialEq)]
enum MethodSaltBytes {
    Aes128([u8; AES_128_KEY_BYTES]),
    Aes256([u8; WIDE_KEY_BYTES]),
    ChaCha20Poly1305([u8; WIDE_KEY_BYTES]),
}

impl MethodTcpSalt {
    /// Copies salt bytes only when their width matches the selected profile.
    pub fn try_from_slice(
        profile: MethodProfile,
        bytes: &[u8],
    ) -> Result<Self, MethodSaltLengthError> {
        let bytes = match profile {
            MethodProfile::Blake3Aes128Gcm2022 => {
                MethodSaltBytes::Aes128(bytes.try_into().map_err(|_| MethodSaltLengthError)?)
            }
            MethodProfile::Blake3Aes256Gcm2022 => {
                MethodSaltBytes::Aes256(bytes.try_into().map_err(|_| MethodSaltLengthError)?)
            }
            MethodProfile::Blake3ChaCha20Poly13052022 => MethodSaltBytes::ChaCha20Poly1305(
                bytes.try_into().map_err(|_| MethodSaltLengthError)?,
            ),
        };
        Ok(Self { bytes })
    }

    /// Returns the immutable profile bound to this salt.
    pub const fn profile(&self) -> MethodProfile {
        match self.bytes {
            MethodSaltBytes::Aes128(_) => MethodProfile::Blake3Aes128Gcm2022,
            MethodSaltBytes::Aes256(_) => MethodProfile::Blake3Aes256Gcm2022,
            MethodSaltBytes::ChaCha20Poly1305(_) => MethodProfile::Blake3ChaCha20Poly13052022,
        }
    }

    /// Returns the complete wire representation.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.bytes {
            MethodSaltBytes::Aes128(bytes) => bytes,
            MethodSaltBytes::Aes256(bytes) | MethodSaltBytes::ChaCha20Poly1305(bytes) => bytes,
        }
    }
}

impl fmt::Debug for MethodTcpSalt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MethodTcpSalt([REDACTED])")
    }
}

impl Zeroize for MethodTcpSalt {
    fn zeroize(&mut self) {
        match &mut self.bytes {
            MethodSaltBytes::Aes128(bytes) => bytes.zeroize(),
            MethodSaltBytes::Aes256(bytes) | MethodSaltBytes::ChaCha20Poly1305(bytes) => {
                bytes.zeroize();
            }
        }
    }
}

impl Drop for MethodTcpSalt {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for MethodTcpSalt {}

/// A redacted error for salt material with the wrong profile width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MethodSaltLengthError;

impl fmt::Display for MethodSaltLengthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid salt length for selected method")
    }
}

impl Error for MethodSaltLengthError {}

/// A method-bound single-PSK owner for M1 composition.
pub struct MethodSinglePskProvider {
    psk: Arc<MethodPsk>,
}

impl MethodSinglePskProvider {
    /// Takes ownership of one validated method-bound PSK.
    pub fn new(psk: MethodPsk) -> Self {
        Self { psk: Arc::new(psk) }
    }

    /// Takes shared ownership of one validated method-bound PSK.
    ///
    /// The secret itself remains a non-cloneable [`MethodPsk`]; cloning the
    /// `Arc` only lets independently owned protocol graphs borrow the same
    /// zeroizing allocation. The allocation is cleared when its last owner is
    /// dropped.
    pub fn from_shared(psk: Arc<MethodPsk>) -> Self {
        Self { psk }
    }

    /// Returns the immutable profile of the configured key.
    pub fn profile(&self) -> MethodProfile {
        self.psk.profile()
    }
}

/// A scoped method-bound key lookup capability.
pub trait MethodKeyProvider: Send + Sync {
    /// Closed provider error.
    type Error;

    /// Returns the profile before a protocol flow allocates wire buffers.
    fn profile(&self) -> MethodProfile;

    /// Runs one operation with a capability borrowed from the selected key.
    fn with_method_key<T>(
        &self,
        selector: KeySelector<'_>,
        use_key: impl FnOnce(MethodSecretKeyRef<'_>) -> T,
    ) -> Result<T, Self::Error>;
}

impl MethodKeyProvider for MethodSinglePskProvider {
    type Error = KeyProviderError;

    fn profile(&self) -> MethodProfile {
        self.profile()
    }

    fn with_method_key<T>(
        &self,
        selector: KeySelector<'_>,
        use_key: impl FnOnce(MethodSecretKeyRef<'_>) -> T,
    ) -> Result<T, Self::Error> {
        match selector {
            KeySelector::Default => Ok(use_key(MethodSecretKeyRef {
                psk: &self.psk.bytes,
            })),
            KeySelector::Identity(_) => Err(KeyProviderError::IdentityUnsupported),
        }
    }
}

/// A scoped method-bound capability that can derive only its own subkey type.
pub struct MethodSecretKeyRef<'a> {
    psk: &'a MethodPskBytes,
}

impl MethodSecretKeyRef<'_> {
    /// Derives a SIP022 TCP subkey when the salt has the same bound profile.
    pub fn derive_tcp_subkey(
        self,
        salt: &MethodTcpSalt,
    ) -> Result<TcpSubkey, MethodProfileMismatchError> {
        let profile = salt.profile();
        if self.psk.profile() != profile {
            return Err(MethodProfileMismatchError);
        }
        Ok(TcpSubkey::derive(
            profile,
            self.psk.as_slice(),
            salt.as_bytes(),
        ))
    }

    /// Creates an opaque method-bound SIP022 UDP cryptographic capability.
    ///
    /// The returned owner contains only private secret and primitive state.
    /// Callers can seal or authenticate complete crypto envelopes but cannot
    /// read or substitute the underlying PSK.
    pub fn udp_crypto(self) -> UdpCrypto {
        let inner = match self.psk {
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
        UdpCrypto { inner }
    }
}

/// An opaque eight-byte SIP022 UDP session identifier.
///
/// The identifier can be compared and hashed for bounded session lookup, but
/// its wire bytes are only consumed and produced by [`UdpCrypto`].
#[derive(Clone, Eq, PartialEq)]
pub struct UdpSessionId {
    bytes: [u8; UDP_SESSION_ID_BYTES],
    lookup_hash: u64,
}

impl UdpSessionId {
    fn from_bytes(bytes: [u8; UDP_SESSION_ID_BYTES]) -> Self {
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        let lookup_hash = hasher.finish();
        Self { bytes, lookup_hash }
    }

    /// Writes the identifier into a bounded SIP022 semantic-header field.
    ///
    /// This is the only encoding seam for response binding; the type exposes
    /// no borrowed or owned raw-byte accessor.
    pub fn write_wire(&self, destination: &mut [u8]) -> Result<(), UdpCryptoError> {
        let field = destination
            .get_mut(..UDP_SESSION_ID_BYTES)
            .ok_or(UdpCryptoError::OutputTooSmall)?;
        field.copy_from_slice(&self.bytes);
        Ok(())
    }

    /// Compares an exact-width SIP022 response-binding field.
    pub fn matches_wire(&self, encoded: &[u8]) -> bool {
        if encoded.len() != UDP_SESSION_ID_BYTES {
            return false;
        }
        let mut difference = 0_u8;
        for (expected, actual) in self.bytes.iter().zip(encoded) {
            difference |= expected ^ actual;
        }
        difference == 0
    }
}

impl Hash for UdpSessionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.lookup_hash);
    }
}

impl fmt::Debug for UdpSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UdpSessionId([REDACTED])")
    }
}

impl Zeroize for UdpSessionId {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
        self.lookup_hash.zeroize();
    }
}

impl Drop for UdpSessionId {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for UdpSessionId {}

fn generate_udp_session_id(
    random: &(impl SecureRandom + ?Sized),
    mut is_live: impl FnMut(&UdpSessionId) -> bool,
) -> Result<UdpSessionId, RandomError> {
    for _ in 0..UDP_SESSION_ID_ATTEMPTS {
        let mut bytes = Zeroizing::new([0_u8; UDP_SESSION_ID_BYTES]);
        random.fill(bytes.as_mut())?;
        let candidate = UdpSessionId::from_bytes(*bytes);
        bytes.zeroize();
        if !is_live(&candidate) {
            return Ok(candidate);
        }
    }
    Err(RandomError::RepeatedSessionId)
}

fn generate_distinct_udp_session_id(
    random: &(impl SecureRandom + ?Sized),
    opposite_direction: &UdpSessionId,
    mut is_live: impl FnMut(&UdpSessionId) -> bool,
) -> Result<UdpSessionId, RandomError> {
    generate_udp_session_id(random, |candidate| {
        candidate == opposite_direction || is_live(candidate)
    })
}

struct UdpPacketCounter {
    next: Option<u64>,
}

impl UdpPacketCounter {
    const fn new() -> Self {
        Self { next: Some(0) }
    }

    fn current(&self) -> Result<u64, UdpCryptoError> {
        self.next.ok_or(UdpCryptoError::CounterExhausted)
    }

    fn commit(&mut self, packet_id: u64) {
        debug_assert_eq!(self.next, Some(packet_id));
        self.next = packet_id.checked_add(1);
    }
}

impl Zeroize for UdpPacketCounter {
    fn zeroize(&mut self) {
        if let Some(next) = &mut self.next {
            next.zeroize();
        }
        self.next = None;
    }
}

impl Drop for UdpPacketCounter {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for UdpPacketCounter {}

/// A move-only, method-bound outbound UDP session owner.
///
/// The opaque session ID and its sole packet-ID lineage are created together.
/// Callers can use the ID for bounded lookup and response binding, but cannot
/// clone, reset, replace, or detach the lineage used by [`UdpCrypto::seal`].
pub struct UdpOutboundSession {
    profile: MethodProfile,
    session_id: UdpSessionId,
    counter: UdpPacketCounter,
}

impl UdpOutboundSession {
    fn new(profile: MethodProfile, session_id: UdpSessionId) -> Self {
        Self {
            profile,
            session_id,
            counter: UdpPacketCounter::new(),
        }
    }

    /// Returns the opaque session ID for bounded lookup and response binding.
    pub const fn session_id(&self) -> &UdpSessionId {
        &self.session_id
    }

    /// Reports whether every `u64` packet ID has been consumed.
    pub const fn is_exhausted(&self) -> bool {
        self.counter.next.is_none()
    }
}

impl fmt::Debug for UdpOutboundSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UdpOutboundSession([REDACTED])")
    }
}

impl Zeroize for UdpOutboundSession {
    fn zeroize(&mut self) {
        self.session_id.zeroize();
        self.counter.zeroize();
    }
}

impl Drop for UdpOutboundSession {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for UdpOutboundSession {}

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
            .map(|session_id| UdpOutboundSession::new(self.profile(), session_id))
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
            .map(|session_id| UdpOutboundSession::new(self.profile(), session_id))
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

/// A redacted failure for crossing two immutable method profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MethodProfileMismatchError;

impl fmt::Display for MethodProfileMismatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("cryptographic method profile mismatch")
    }
}

impl Error for MethodProfileMismatchError {}

/// Key selection before a TCP transport state machine is entered.
pub enum KeySelector<'a> {
    /// Selects the configured default key.
    Default,
    /// Reserves the future identity-selection boundary without implementing SIP023.
    Identity(&'a [u8; AES_128_KEY_BYTES]),
}

/// A closed key lookup error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyProviderError {
    /// Identity selection and SIP023 are not implemented.
    IdentityUnsupported,
}

impl fmt::Display for KeyProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("key identity is unsupported")
    }
}

impl Error for KeyProviderError {}

fn udp_identity(session_id: &UdpSessionId, packet_id: u64) -> [u8; UDP_IDENTITY_BYTES] {
    let mut identity = [0_u8; UDP_IDENTITY_BYTES];
    identity[..UDP_SESSION_ID_BYTES].copy_from_slice(&session_id.bytes);
    identity[UDP_SESSION_ID_BYTES..].copy_from_slice(&packet_id.to_be_bytes());
    identity
}

fn seal_aes_udp(
    crypto: &UdpCrypto,
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
    let cipher = crypto.aes_body_cipher(session_id);
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

    fn reserve(&self) -> Result<([u8; AEAD_NONCE_BYTES], Self), AeadError> {
        let mut next = self.bytes;
        increment_u96_le(&mut next).ok_or(AeadError::NonceExhausted)?;
        Ok((self.bytes, Self { bytes: next }))
    }
}

/// Wall and monotonic time required by the SIP022 protocol path.
pub trait Clock {
    /// Returns Unix wall-clock seconds or a closed failure.
    fn unix_seconds(&self) -> Result<u64, ClockError>;

    /// Returns monotonic time in this clock's epoch.
    fn monotonic_now(&self) -> MonotonicInstant;
}

/// An opaque monotonic instant comparable only within one clock epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicInstant(Duration);

impl MonotonicInstant {
    /// The start of a synthetic or system clock epoch.
    pub const ZERO: Self = Self(Duration::ZERO);

    /// Creates an instant for deterministic clock adapters.
    pub const fn from_duration(since_epoch: Duration) -> Self {
        Self(since_epoch)
    }

    /// Returns elapsed monotonic time, or `None` for reversed instants.
    pub fn duration_since(self, earlier: Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0)
    }
}

/// The production wall/monotonic clock adapter.
pub struct SystemClock {
    monotonic_origin: Instant,
}

impl SystemClock {
    /// Starts a new monotonic epoch.
    pub fn new() -> Self {
        Self {
            monotonic_origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn unix_seconds(&self) -> Result<u64, ClockError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .map_err(|_| ClockError::Unavailable)
    }

    fn monotonic_now(&self) -> MonotonicInstant {
        MonotonicInstant(self.monotonic_origin.elapsed())
    }
}

/// A closed wall-clock failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError {
    /// Wall time could not be represented as Unix seconds.
    Unavailable,
}

impl fmt::Display for ClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("clock unavailable")
    }
}

impl Error for ClockError {}

/// A narrow secure-random capability shared by production and test adapters.
pub trait SecureRandom: Send + Sync {
    /// Fills the complete destination or fails without a weak fallback.
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomError>;
}

/// The production OS CSPRNG adapter.
pub struct SystemRandom;

impl SecureRandom for SystemRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomError> {
        getrandom::fill(destination).map_err(|_| RandomError::Unavailable)
    }
}

/// Generates a request salt with the exact width of the selected profile.
pub fn generate_method_request_salt(
    profile: MethodProfile,
    random: &(impl SecureRandom + ?Sized),
) -> Result<MethodTcpSalt, RandomError> {
    let mut bytes = Zeroizing::new([0_u8; WIDE_KEY_BYTES]);
    random.fill(&mut bytes[..profile.salt_bytes()])?;
    MethodTcpSalt::try_from_slice(profile, &bytes[..profile.salt_bytes()])
        .map_err(|_| RandomError::Unavailable)
}

/// Generates a profile-bound response salt distinct from its request salt.
///
/// Eight consecutive full-width collisions fail closed.
pub fn generate_method_response_salt(
    random: &(impl SecureRandom + ?Sized),
    request: &MethodTcpSalt,
) -> Result<MethodTcpSalt, RandomError> {
    for _ in 0..RESPONSE_SALT_ATTEMPTS {
        let candidate = generate_method_request_salt(request.profile(), random)?;
        if candidate != *request {
            return Ok(candidate);
        }
    }
    Err(RandomError::RepeatedSalt)
}

/// A closed secure-random failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RandomError {
    /// The OS or injected secure-random capability failed.
    Unavailable,
    /// Eight response-salt draws collided with the request salt.
    RepeatedSalt,
    /// Eight UDP session-ID draws collided with live state.
    RepeatedSessionId,
}

impl fmt::Display for RandomError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Unavailable => "secure random unavailable",
            Self::RepeatedSalt => "secure random repeated request salt",
            Self::RepeatedSessionId => "secure random repeated live session ID",
        };
        formatter.write_str(message)
    }
}

impl Error for RandomError {}

/// An owned method-bound TCP session subkey.
///
/// The owner is intentionally neither `Clone` nor printable.
pub struct TcpSubkey {
    profile: MethodProfile,
    cipher: ShadowsocksTcpCipher,
}

impl TcpSubkey {
    /// Takes ownership of an AES-128 primitive key.
    pub fn from_bytes(bytes: [u8; AES_128_KEY_BYTES]) -> Self {
        Self::from_subkey(MethodProfile::Blake3Aes128Gcm2022, bytes)
    }

    fn from_subkey<const N: usize>(profile: MethodProfile, bytes: [u8; N]) -> Self {
        let mut bytes = Zeroizing::new(bytes);
        let cipher = ShadowsocksTcpCipher::try_from_subkey(profile.cipher_kind(), bytes.as_ref())
            .unwrap_or_else(|_| unreachable!("TCP subkeys have a profile-fixed width"));
        bytes.zeroize();
        Self { profile, cipher }
    }

    fn derive(profile: MethodProfile, psk: &[u8], salt: &[u8]) -> Self {
        let cipher = ShadowsocksTcpCipher::try_new(profile.cipher_kind(), psk, salt)
            .unwrap_or_else(|_| unreachable!("TCP KDF inputs have profile-fixed widths"));
        Self { profile, cipher }
    }

    /// Returns the immutable profile bound during KDF selection.
    pub const fn profile(&self) -> MethodProfile {
        self.profile
    }
}

impl Zeroize for TcpSubkey {
    fn zeroize(&mut self) {
        let zero_subkey = Zeroizing::new([0_u8; WIDE_KEY_BYTES]);
        self.cipher = ShadowsocksTcpCipher::try_from_subkey(
            self.profile.cipher_kind(),
            &zero_subkey[..self.profile.key_bytes()],
        )
        .unwrap_or_else(|_| unreachable!("zero TCP subkeys have a profile-fixed width"));
    }
}

impl ZeroizeOnDrop for TcpSubkey {}

/// A method-bound AEAD owner for one outbound TCP direction.
///
/// Construction always initializes its private nonce counter to zero.
pub struct TcpSealer {
    cipher: ShadowsocksTcpCipher,
    nonce: NonceCounter,
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
    pub fn open_in_place(&mut self, buffer: &mut BytesMut) -> Result<(), AeadError> {
        let (nonce, next) = self.nonce.reserve()?;
        let tag_start = buffer
            .len()
            .checked_sub(AEAD_TAG_BYTES)
            .ok_or(AeadError::AuthenticationFailed)?;
        let tag: [u8; AEAD_TAG_BYTES] = buffer[tag_start..]
            .try_into()
            .unwrap_or_else(|_| unreachable!("validated TCP tag width"));
        let mut plaintext = Zeroizing::new(buffer[..tag_start].to_vec());
        self.cipher
            .decrypt_packet(&nonce, plaintext.as_mut(), &tag)
            .map_err(|_| AeadError::AuthenticationFailed)?;
        buffer.truncate(tag_start);
        buffer.copy_from_slice(plaintext.as_ref());
        self.nonce = next;
        Ok(())
    }
}

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

    const EXHAUSTED_NONCE: [u8; AEAD_NONCE_BYTES] = [u8::MAX; AEAD_NONCE_BYTES];

    fn aes128_udp_crypto() -> UdpCrypto {
        let psk = MethodPskBytes::Aes128(Zeroizing::new([0x11; AES_128_KEY_BYTES]));
        MethodSecretKeyRef { psk: &psk }.udp_crypto()
    }

    fn aes256_udp_crypto() -> UdpCrypto {
        let psk = MethodPskBytes::Aes256(Zeroizing::new([0x33; WIDE_KEY_BYTES]));
        MethodSecretKeyRef { psk: &psk }.udp_crypto()
    }

    #[test]
    fn udp_outbound_session_commits_zero_terminal_and_exhausted_states_only_on_success() {
        let crypto = aes128_udp_crypto();
        let session_id = UdpSessionId::from_bytes([0x22; UDP_SESSION_ID_BYTES]);
        let mut outbound = UdpOutboundSession::new(crypto.profile(), session_id);
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
