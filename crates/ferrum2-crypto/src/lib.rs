#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit, Nonce};
use bytes::BytesMut;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const AES_128_KEY_BYTES: usize = 16;
const AEAD_NONCE_BYTES: usize = 12;
const TCP_SALT_BYTES: usize = 16;
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
                let mut material = Zeroizing::new([0_u8; AES_128_KEY_BYTES + TCP_SALT_BYTES]);
                material[..AES_128_KEY_BYTES].copy_from_slice(self.psk);
                material[AES_128_KEY_BYTES..].copy_from_slice(&salt.bytes);
                let mut derived =
                    Zeroizing::new(blake3::derive_key(SIP022_KDF_CONTEXT, material.as_ref()));
                let mut selected = [0_u8; AES_128_KEY_BYTES];
                selected.copy_from_slice(&derived[..AES_128_KEY_BYTES]);
                derived.zeroize();
                material.zeroize();
                TcpSubkey::from_bytes(selected)
            }
        }
    }
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

/// An owned AES-128 TCP session subkey.
///
/// The owner is intentionally neither `Clone` nor printable.
pub struct TcpSubkey {
    bytes: Zeroizing<[u8; AES_128_KEY_BYTES]>,
}

impl TcpSubkey {
    /// Takes ownership of an exact-width primitive key.
    pub fn from_bytes(bytes: [u8; AES_128_KEY_BYTES]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }
}

impl Zeroize for TcpSubkey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for TcpSubkey {}

/// An AES-128-GCM owner for one outbound TCP direction.
///
/// Construction always initializes its private nonce counter to zero.
pub struct TcpSealer {
    cipher: Aes128Gcm,
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
        self.cipher
            .encrypt_in_place(&Nonce::from(nonce), &[], buffer)
            .map_err(|_| AeadError::OperationFailed)?;
        self.nonce = next;
        Ok(())
    }
}

/// An AES-128-GCM owner for one inbound TCP direction.
///
/// Construction always initializes its private nonce counter to zero.
pub struct TcpOpener {
    cipher: Aes128Gcm,
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
        self.cipher
            .decrypt_in_place(&Nonce::from(nonce), &[], buffer)
            .map_err(|_| AeadError::AuthenticationFailed)?;
        self.nonce = next;
        Ok(())
    }
}

fn cipher_from_subkey(subkey: &TcpSubkey) -> Aes128Gcm {
    Aes128Gcm::new_from_slice(subkey.bytes.as_ref())
        .unwrap_or_else(|_| unreachable!("AES-128 subkeys always have the required width"))
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
