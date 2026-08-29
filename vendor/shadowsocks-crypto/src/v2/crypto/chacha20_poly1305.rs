use chacha20poly1305_v2::{
    aead::inout::InOutBuf, AeadInOut, ChaCha20Poly1305 as CryptoChaCha20Poly1305, KeyInit, Nonce, Tag,
};
use zeroize::ZeroizeOnDrop;

use super::require_zeroize_on_drop;

pub struct ChaCha20Poly1305(CryptoChaCha20Poly1305);

impl ChaCha20Poly1305 {
    pub fn try_new(key: &[u8]) -> Option<Self> {
        CryptoChaCha20Poly1305::new_from_slice(key)
            .ok()
            .map(require_zeroize_on_drop)
            .map(Self)
    }

    pub const fn key_size() -> usize {
        32
    }

    pub const fn tag_size() -> usize {
        16
    }

    pub fn encrypt(&self, nonce: &[u8; 12], plaintext: &mut [u8]) -> Result<[u8; 16], ()> {
        let tag = self
            .0
            .encrypt_inout_detached(&Nonce::from(*nonce), &[], plaintext.into())
            .map_err(|_| ())?;
        let mut output = [0; 16];
        output.copy_from_slice(&tag);
        Ok(output)
    }

    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &mut [u8], tag: &[u8; 16]) -> bool {
        self.0
            .decrypt_inout_detached(&Nonce::from(*nonce), &[], ciphertext.into(), &Tag::from(*tag))
            .is_ok()
    }

    pub fn decrypt_into(&self, nonce: &[u8; 12], ciphertext: &[u8], plaintext: &mut [u8], tag: &[u8; 16]) -> bool {
        let Ok(buffer) = InOutBuf::new(ciphertext, plaintext) else {
            return false;
        };
        self.0
            .decrypt_inout_detached(&Nonce::from(*nonce), &[], buffer, &Tag::from(*tag))
            .is_ok()
    }
}

impl ZeroizeOnDrop for ChaCha20Poly1305 {}
