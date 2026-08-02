use chacha20poly1305_v2::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305 as CryptoXChaCha20Poly1305, XNonce};
use zeroize::ZeroizeOnDrop;

use super::require_zeroize_on_drop;

pub struct XChaCha20Poly1305(CryptoXChaCha20Poly1305);

impl XChaCha20Poly1305 {
    pub fn try_new(key: &[u8]) -> Option<Self> {
        CryptoXChaCha20Poly1305::new_from_slice(key)
            .ok()
            .map(require_zeroize_on_drop)
            .map(Self)
    }

    pub const fn key_size() -> usize {
        32
    }

    pub const fn nonce_size() -> usize {
        24
    }

    pub const fn tag_size() -> usize {
        16
    }

    pub fn encrypt(&self, nonce: &[u8; 24], plaintext: &mut [u8]) -> Result<[u8; 16], ()> {
        let tag = self
            .0
            .encrypt_inout_detached(&XNonce::from(*nonce), &[], plaintext.into())
            .map_err(|_| ())?;
        let mut output = [0; 16];
        output.copy_from_slice(&tag);
        Ok(output)
    }

    pub fn decrypt(&self, nonce: &[u8; 24], ciphertext: &mut [u8], tag: &[u8; 16]) -> bool {
        self.0
            .decrypt_inout_detached(&XNonce::from(*nonce), &[], ciphertext.into(), &Tag::from(*tag))
            .is_ok()
    }
}

impl ZeroizeOnDrop for XChaCha20Poly1305 {}
