use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::aead::UdpAesSessionCipher;
use super::{UDP_SESSION_ID_BYTES, UdpCryptoError};
use crate::method::MethodProfile;
use crate::random::{RandomError, SecureRandom};

const UDP_SESSION_ID_ATTEMPTS: usize = 8;

/// An opaque eight-byte SIP022 UDP session identifier.
///
/// The identifier can be compared and hashed for bounded session lookup, but
/// its wire bytes are only consumed and produced by [`crate::UdpCrypto`].
#[derive(Clone, Eq, PartialEq)]
pub struct UdpSessionId {
    pub(super) bytes: [u8; UDP_SESSION_ID_BYTES],
    lookup_hash: u64,
}

impl UdpSessionId {
    pub(super) fn from_bytes(bytes: [u8; UDP_SESSION_ID_BYTES]) -> Self {
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

pub(super) fn generate_udp_session_id(
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

pub(super) fn generate_distinct_udp_session_id(
    random: &(impl SecureRandom + ?Sized),
    opposite_direction: &UdpSessionId,
    mut is_live: impl FnMut(&UdpSessionId) -> bool,
) -> Result<UdpSessionId, RandomError> {
    generate_udp_session_id(random, |candidate| {
        candidate == opposite_direction || is_live(candidate)
    })
}

pub(super) struct UdpPacketCounter {
    pub(super) next: Option<u64>,
}

impl UdpPacketCounter {
    const fn new() -> Self {
        Self { next: Some(0) }
    }

    pub(super) fn current(&self) -> Result<u64, UdpCryptoError> {
        self.next.ok_or(UdpCryptoError::CounterExhausted)
    }

    pub(super) fn commit(&mut self, packet_id: u64) {
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
/// clone, reset, replace, or detach the lineage used by [`crate::UdpCrypto::seal`].
pub struct UdpOutboundSession {
    pub(super) profile: MethodProfile,
    pub(super) session_id: UdpSessionId,
    pub(super) counter: UdpPacketCounter,
    pub(super) aes_body_cipher: Option<UdpAesSessionCipher>,
}

impl UdpOutboundSession {
    pub(super) fn new(
        profile: MethodProfile,
        session_id: UdpSessionId,
        aes_body_cipher: Option<UdpAesSessionCipher>,
    ) -> Self {
        Self {
            profile,
            session_id,
            counter: UdpPacketCounter::new(),
            aes_body_cipher,
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
        self.aes_body_cipher.take();
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
