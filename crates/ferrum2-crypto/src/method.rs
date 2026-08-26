use std::error::Error;
use std::fmt;
use std::sync::Arc;

use shadowsocks_crypto::CipherKind;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::tcp::TcpSubkey;
use crate::udp::{UDP_IDENTITY_BYTES, UdpCrypto, XCHACHA_NONCE_BYTES};

pub(crate) const AES_128_KEY_BYTES: usize = 16;
pub(crate) const WIDE_KEY_BYTES: usize = 32;
pub(crate) const AEAD_NONCE_BYTES: usize = 12;
pub(crate) const AEAD_TAG_BYTES: usize = 16;

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

    pub(crate) const fn cipher_kind(self) -> CipherKind {
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

pub(crate) enum MethodPskBytes {
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
        UdpCrypto::from_method_key(self.psk)
    }
}
