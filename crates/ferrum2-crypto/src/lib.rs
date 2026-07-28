#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes_gcm::{AeadInOut, Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use bytes::BytesMut;
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const AES_128_KEY_BYTES: usize = 16;
const WIDE_KEY_BYTES: usize = 32;
const AEAD_NONCE_BYTES: usize = 12;
const TCP_SALT_BYTES: usize = 16;
const AEAD_TAG_BYTES: usize = 16;
const SIP022_KDF_CONTEXT: &str = "shadowsocks 2022 session subkey";
const RESPONSE_SALT_ATTEMPTS: usize = 8;

/// An exact-width AES-128 pre-shared key.
///
/// The owner is intentionally neither `Clone` nor printable.
pub struct Aes128Psk {
    bytes: Zeroizing<[u8; AES_128_KEY_BYTES]>,
}

impl Aes128Psk {
    /// Takes ownership of an exact-width decoded PSK buffer.
    pub fn from_bytes(bytes: [u8; AES_128_KEY_BYTES]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Explicitly clears the owned PSK before its eventual drop.
    pub fn clear(&mut self) {
        self.zeroize();
    }
}

impl TryFrom<&[u8]> for Aes128Psk {
    type Error = PskLengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; AES_128_KEY_BYTES] = value.try_into().map_err(|_| PskLengthError)?;
        Ok(Self::from_bytes(bytes))
    }
}

impl fmt::Debug for Aes128Psk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Aes128Psk([REDACTED])")
    }
}

impl Zeroize for Aes128Psk {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for Aes128Psk {}

/// A closed error for a decoded PSK with the wrong width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PskLengthError;

impl fmt::Display for PskLengthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid AES-128 key length")
    }
}

impl Error for PskLengthError {}

/// One of the three immutable SIP022 TCP cryptographic profiles.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TcpMethodProfile {
    /// SIP022 `2022-blake3-aes-128-gcm`.
    Blake3Aes128Gcm2022,
    /// SIP022 `2022-blake3-aes-256-gcm`.
    Blake3Aes256Gcm2022,
    /// SIP022-compatible `2022-blake3-chacha20-poly1305`.
    Blake3ChaCha20Poly13052022,
}

impl TcpMethodProfile {
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
        profile: TcpMethodProfile,
        bytes: &[u8],
    ) -> Result<Self, MethodPskLengthError> {
        match profile {
            TcpMethodProfile::Blake3Aes128Gcm2022 => bytes
                .try_into()
                .map(Self::aes128)
                .map_err(|_| MethodPskLengthError),
            TcpMethodProfile::Blake3Aes256Gcm2022 => bytes
                .try_into()
                .map(Self::aes256)
                .map_err(|_| MethodPskLengthError),
            TcpMethodProfile::Blake3ChaCha20Poly13052022 => bytes
                .try_into()
                .map(Self::chacha20_poly1305)
                .map_err(|_| MethodPskLengthError),
        }
    }

    /// Returns the immutable profile bound to this PSK.
    pub const fn profile(&self) -> TcpMethodProfile {
        match self.bytes {
            MethodPskBytes::Aes128(_) => TcpMethodProfile::Blake3Aes128Gcm2022,
            MethodPskBytes::Aes256(_) => TcpMethodProfile::Blake3Aes256Gcm2022,
            MethodPskBytes::ChaCha20Poly1305(_) => TcpMethodProfile::Blake3ChaCha20Poly13052022,
        }
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
        profile: TcpMethodProfile,
        bytes: &[u8],
    ) -> Result<Self, MethodSaltLengthError> {
        let bytes = match profile {
            TcpMethodProfile::Blake3Aes128Gcm2022 => {
                MethodSaltBytes::Aes128(bytes.try_into().map_err(|_| MethodSaltLengthError)?)
            }
            TcpMethodProfile::Blake3Aes256Gcm2022 => {
                MethodSaltBytes::Aes256(bytes.try_into().map_err(|_| MethodSaltLengthError)?)
            }
            TcpMethodProfile::Blake3ChaCha20Poly13052022 => MethodSaltBytes::ChaCha20Poly1305(
                bytes.try_into().map_err(|_| MethodSaltLengthError)?,
            ),
        };
        Ok(Self { bytes })
    }

    /// Returns the immutable profile bound to this salt.
    pub const fn profile(&self) -> TcpMethodProfile {
        match self.bytes {
            MethodSaltBytes::Aes128(_) => TcpMethodProfile::Blake3Aes128Gcm2022,
            MethodSaltBytes::Aes256(_) => TcpMethodProfile::Blake3Aes256Gcm2022,
            MethodSaltBytes::ChaCha20Poly1305(_) => TcpMethodProfile::Blake3ChaCha20Poly13052022,
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
    psk: MethodPsk,
}

impl MethodSinglePskProvider {
    /// Takes ownership of one validated method-bound PSK.
    pub fn new(psk: MethodPsk) -> Self {
        Self { psk }
    }

    /// Returns the immutable profile of the configured key.
    pub const fn profile(&self) -> TcpMethodProfile {
        self.psk.profile()
    }
}

/// A scoped method-bound key lookup capability.
pub trait MethodKeyProvider: Send + Sync {
    /// Closed provider error.
    type Error;

    /// Returns the profile before a protocol flow allocates wire buffers.
    fn profile(&self) -> TcpMethodProfile;

    /// Runs one operation with a capability borrowed from the selected key.
    fn with_method_key<T>(
        &self,
        selector: KeySelector<'_>,
        use_key: impl FnOnce(MethodSecretKeyRef<'_>) -> T,
    ) -> Result<T, Self::Error>;
}

impl MethodKeyProvider for MethodSinglePskProvider {
    type Error = KeyProviderError;

    fn profile(&self) -> TcpMethodProfile {
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
        match (self.psk, &salt.bytes) {
            (MethodPskBytes::Aes128(psk), MethodSaltBytes::Aes128(salt)) => {
                Ok(TcpSubkey::from_bytes(derive_subkey_16(psk, salt)))
            }
            (MethodPskBytes::Aes256(psk), MethodSaltBytes::Aes256(salt)) => {
                Ok(TcpSubkey::aes256(derive_subkey_32(psk, salt)))
            }
            (MethodPskBytes::ChaCha20Poly1305(psk), MethodSaltBytes::ChaCha20Poly1305(salt)) => {
                Ok(TcpSubkey::chacha20_poly1305(derive_subkey_32(psk, salt)))
            }
            _ => Err(MethodProfileMismatchError),
        }
    }
}

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

/// A scoped key lookup capability that never returns raw PSK bytes.
pub trait KeyProvider: Send + Sync {
    /// Closed provider error.
    type Error;

    /// Runs one operation with a capability borrowed from the selected key.
    fn with_key<T>(
        &self,
        selector: KeySelector<'_>,
        use_key: impl FnOnce(SecretKeyRef<'_>) -> T,
    ) -> Result<T, Self::Error>;
}

/// The M0 process-level owner for one default AES-128 PSK.
pub struct SinglePskProvider {
    psk: Aes128Psk,
}

impl SinglePskProvider {
    /// Takes ownership of the configured process key.
    pub fn new(psk: Aes128Psk) -> Self {
        Self { psk }
    }
}

impl KeyProvider for SinglePskProvider {
    type Error = KeyProviderError;

    fn with_key<T>(
        &self,
        selector: KeySelector<'_>,
        use_key: impl FnOnce(SecretKeyRef<'_>) -> T,
    ) -> Result<T, Self::Error> {
        match selector {
            KeySelector::Default => Ok(use_key(SecretKeyRef {
                psk: &self.psk.bytes,
            })),
            KeySelector::Identity(_) => Err(KeyProviderError::IdentityUnsupported),
        }
    }
}

/// A closed key lookup error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyProviderError {
    /// M0 does not implement identity selection or SIP023.
    IdentityUnsupported,
}

impl fmt::Display for KeyProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("key identity is unsupported")
    }
}

impl Error for KeyProviderError {}

/// A scoped capability for deriving a session key without exposing its PSK.
pub struct SecretKeyRef<'a> {
    psk: &'a [u8; AES_128_KEY_BYTES],
}

impl SecretKeyRef<'_> {
    /// Derives the SIP022 TCP subkey for the selected method and salt.
    pub fn derive_tcp_subkey(self, method: TcpMethod, salt: &TcpSalt) -> TcpSubkey {
        match method {
            TcpMethod::Blake3Aes128Gcm2022 => {
                TcpSubkey::from_bytes(derive_subkey_16(self.psk, &salt.bytes))
            }
        }
    }
}

fn derive_subkey_16(
    psk: &[u8; AES_128_KEY_BYTES],
    salt: &[u8; AES_128_KEY_BYTES],
) -> [u8; AES_128_KEY_BYTES] {
    let mut material = Zeroizing::new([0_u8; AES_128_KEY_BYTES * 2]);
    material[..AES_128_KEY_BYTES].copy_from_slice(psk);
    material[AES_128_KEY_BYTES..].copy_from_slice(salt);
    let mut derived = Zeroizing::new(blake3::derive_key(SIP022_KDF_CONTEXT, material.as_ref()));
    let mut selected = [0_u8; AES_128_KEY_BYTES];
    selected.copy_from_slice(&derived[..AES_128_KEY_BYTES]);
    derived.zeroize();
    material.zeroize();
    selected
}

fn derive_subkey_32(
    psk: &[u8; WIDE_KEY_BYTES],
    salt: &[u8; WIDE_KEY_BYTES],
) -> [u8; WIDE_KEY_BYTES] {
    let mut material = Zeroizing::new([0_u8; WIDE_KEY_BYTES * 2]);
    material[..WIDE_KEY_BYTES].copy_from_slice(psk);
    material[WIDE_KEY_BYTES..].copy_from_slice(salt);
    let mut selected = Zeroizing::new(blake3::derive_key(SIP022_KDF_CONTEXT, material.as_ref()));
    material.zeroize();
    let output = *selected;
    selected.zeroize();
    output
}

/// The only TCP cipher method implemented by M0.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpMethod {
    /// SIP022 `2022-blake3-aes-128-gcm`.
    Blake3Aes128Gcm2022,
}

/// A typed 16-byte TCP salt that redacts its diagnostic representation.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct TcpSalt {
    bytes: [u8; TCP_SALT_BYTES],
}

impl TcpSalt {
    /// Wraps salt bytes received from the wire or a secure random source.
    pub const fn from_bytes(bytes: [u8; TCP_SALT_BYTES]) -> Self {
        Self { bytes }
    }

    /// Returns the wire representation.
    pub const fn as_bytes(&self) -> &[u8; TCP_SALT_BYTES] {
        &self.bytes
    }
}

impl fmt::Debug for TcpSalt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TcpSalt([REDACTED])")
    }
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

/// Generates a fresh request salt from the supplied secure-random capability.
pub fn generate_request_salt(
    random: &(impl SecureRandom + ?Sized),
) -> Result<TcpSalt, RandomError> {
    let mut bytes = [0_u8; TCP_SALT_BYTES];
    random.fill(&mut bytes)?;
    Ok(TcpSalt::from_bytes(bytes))
}

/// Generates a response salt distinct from its request salt.
///
/// Eight consecutive collisions fail closed.
pub fn generate_response_salt(
    random: &(impl SecureRandom + ?Sized),
    request: &TcpSalt,
) -> Result<TcpSalt, RandomError> {
    for _ in 0..RESPONSE_SALT_ATTEMPTS {
        let candidate = generate_request_salt(random)?;
        if candidate != *request {
            return Ok(candidate);
        }
    }
    Err(RandomError::RepeatedSalt)
}

/// Generates a request salt with the exact width of the selected profile.
pub fn generate_method_request_salt(
    profile: TcpMethodProfile,
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
}

impl fmt::Display for RandomError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Unavailable => "secure random unavailable",
            Self::RepeatedSalt => "secure random repeated request salt",
        };
        formatter.write_str(message)
    }
}

impl Error for RandomError {}

/// An owned method-bound TCP session subkey.
///
/// The owner is intentionally neither `Clone` nor printable.
pub struct TcpSubkey {
    bytes: TcpSubkeyBytes,
}

enum TcpSubkeyBytes {
    Aes128(Zeroizing<[u8; AES_128_KEY_BYTES]>),
    Aes256(Zeroizing<[u8; WIDE_KEY_BYTES]>),
    ChaCha20Poly1305(Zeroizing<[u8; WIDE_KEY_BYTES]>),
}

impl TcpSubkey {
    /// Takes ownership of an AES-128 primitive key.
    pub fn from_bytes(bytes: [u8; AES_128_KEY_BYTES]) -> Self {
        Self {
            bytes: TcpSubkeyBytes::Aes128(Zeroizing::new(bytes)),
        }
    }

    fn aes256(bytes: [u8; WIDE_KEY_BYTES]) -> Self {
        Self {
            bytes: TcpSubkeyBytes::Aes256(Zeroizing::new(bytes)),
        }
    }

    fn chacha20_poly1305(bytes: [u8; WIDE_KEY_BYTES]) -> Self {
        Self {
            bytes: TcpSubkeyBytes::ChaCha20Poly1305(Zeroizing::new(bytes)),
        }
    }

    /// Returns the immutable profile bound during KDF selection.
    pub const fn profile(&self) -> TcpMethodProfile {
        match self.bytes {
            TcpSubkeyBytes::Aes128(_) => TcpMethodProfile::Blake3Aes128Gcm2022,
            TcpSubkeyBytes::Aes256(_) => TcpMethodProfile::Blake3Aes256Gcm2022,
            TcpSubkeyBytes::ChaCha20Poly1305(_) => TcpMethodProfile::Blake3ChaCha20Poly13052022,
        }
    }
}

impl Zeroize for TcpSubkey {
    fn zeroize(&mut self) {
        match &mut self.bytes {
            TcpSubkeyBytes::Aes128(bytes) => bytes.zeroize(),
            TcpSubkeyBytes::Aes256(bytes) | TcpSubkeyBytes::ChaCha20Poly1305(bytes) => {
                bytes.zeroize();
            }
        }
    }
}

impl ZeroizeOnDrop for TcpSubkey {}

// Keeping the fixed-size primitive state inline avoids a heap allocation for
// every directional owner; the enum is constructed once and reused per frame.
#[allow(clippy::large_enum_variant)]
enum TcpCipher {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

/// A method-bound AEAD owner for one outbound TCP direction.
///
/// Construction always initializes its private nonce counter to zero.
pub struct TcpSealer {
    cipher: TcpCipher,
    nonce: NonceCounter,
}

impl TcpSealer {
    /// Consumes a session subkey and creates a zero-nonce sealer.
    pub fn new(subkey: TcpSubkey) -> Self {
        Self {
            cipher: cipher_from_subkey(&subkey),
            nonce: NonceCounter::new(),
        }
    }

    /// Encrypts and appends the tag in place with empty associated data.
    pub fn seal_in_place(&mut self, buffer: &mut BytesMut) -> Result<(), AeadError> {
        let (nonce, next) = self.nonce.reserve()?;
        match &self.cipher {
            TcpCipher::Aes128(cipher) => cipher.encrypt_in_place(&Nonce::from(nonce), &[], buffer),
            TcpCipher::Aes256(cipher) => cipher.encrypt_in_place(&Nonce::from(nonce), &[], buffer),
            TcpCipher::ChaCha20Poly1305(cipher) => {
                cipher.encrypt_in_place(&Nonce::from(nonce), &[], buffer)
            }
        }
        .map_err(|_| AeadError::OperationFailed)?;
        self.nonce = next;
        Ok(())
    }
}

/// A method-bound AEAD owner for one inbound TCP direction.
///
/// Construction always initializes its private nonce counter to zero.
pub struct TcpOpener {
    cipher: TcpCipher,
    nonce: NonceCounter,
}

impl TcpOpener {
    /// Consumes a session subkey and creates a zero-nonce opener.
    pub fn new(subkey: TcpSubkey) -> Self {
        Self {
            cipher: cipher_from_subkey(&subkey),
            nonce: NonceCounter::new(),
        }
    }

    /// Authenticates and decrypts in place with empty associated data.
    pub fn open_in_place(&mut self, buffer: &mut BytesMut) -> Result<(), AeadError> {
        let (nonce, next) = self.nonce.reserve()?;
        match &self.cipher {
            TcpCipher::Aes128(cipher) => cipher.decrypt_in_place(&Nonce::from(nonce), &[], buffer),
            TcpCipher::Aes256(cipher) => cipher.decrypt_in_place(&Nonce::from(nonce), &[], buffer),
            TcpCipher::ChaCha20Poly1305(cipher) => {
                cipher.decrypt_in_place(&Nonce::from(nonce), &[], buffer)
            }
        }
        .map_err(|_| AeadError::AuthenticationFailed)?;
        self.nonce = next;
        Ok(())
    }
}

fn cipher_from_subkey(subkey: &TcpSubkey) -> TcpCipher {
    match &subkey.bytes {
        TcpSubkeyBytes::Aes128(bytes) => TcpCipher::Aes128(
            Aes128Gcm::new_from_slice(bytes.as_ref())
                .unwrap_or_else(|_| unreachable!("AES-128 subkeys have a fixed width")),
        ),
        TcpSubkeyBytes::Aes256(bytes) => TcpCipher::Aes256(
            Aes256Gcm::new_from_slice(bytes.as_ref())
                .unwrap_or_else(|_| unreachable!("AES-256 subkeys have a fixed width")),
        ),
        TcpSubkeyBytes::ChaCha20Poly1305(bytes) => TcpCipher::ChaCha20Poly1305(
            ChaCha20Poly1305::new_from_slice(bytes.as_ref())
                .unwrap_or_else(|_| unreachable!("ChaCha20 subkeys have a fixed width")),
        ),
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

    #[test]
    fn tcp_owner_nonce_exhaustion_sealer_fails_closed() {
        for subkey in [
            TcpSubkey::from_bytes([0x11; AES_128_KEY_BYTES]),
            TcpSubkey::aes256([0x22; WIDE_KEY_BYTES]),
            TcpSubkey::chacha20_poly1305([0x33; WIDE_KEY_BYTES]),
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
            TcpSubkey::aes256([0x55; WIDE_KEY_BYTES]),
            TcpSubkey::chacha20_poly1305([0x66; WIDE_KEY_BYTES]),
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
