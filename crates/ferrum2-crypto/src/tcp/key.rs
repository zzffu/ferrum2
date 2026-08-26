use shadowsocks_crypto::v2::tcp::TcpCipher as ShadowsocksTcpCipher;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::method::{AES_128_KEY_BYTES, MethodProfile, WIDE_KEY_BYTES};

/// An owned method-bound TCP session subkey.
///
/// The owner is intentionally neither `Clone` nor printable.
pub struct TcpSubkey {
    profile: MethodProfile,
    pub(super) cipher: ShadowsocksTcpCipher,
}

impl TcpSubkey {
    /// Takes ownership of an AES-128 primitive key.
    pub fn from_bytes(bytes: [u8; AES_128_KEY_BYTES]) -> Self {
        Self::from_subkey(MethodProfile::Blake3Aes128Gcm2022, bytes)
    }

    pub(super) fn from_subkey<const N: usize>(profile: MethodProfile, bytes: [u8; N]) -> Self {
        let mut bytes = Zeroizing::new(bytes);
        let cipher = ShadowsocksTcpCipher::try_from_subkey(profile.cipher_kind(), bytes.as_ref())
            .unwrap_or_else(|_| unreachable!("TCP subkeys have a profile-fixed width"));
        bytes.zeroize();
        Self { profile, cipher }
    }

    pub(crate) fn derive(profile: MethodProfile, psk: &[u8], salt: &[u8]) -> Self {
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
