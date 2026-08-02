//! AEAD 2022 UDP XChaCha20-Poly1305 cipher.

use zeroize::ZeroizeOnDrop;

use crate::v2::{crypto::XChaCha20Poly1305, CryptoError};

pub struct Cipher {
    cipher: XChaCha20Poly1305,
}

impl Cipher {
    pub const fn nonce_size() -> usize {
        24
    }

    pub fn try_new(key: &[u8]) -> Result<Self, CryptoError> {
        XChaCha20Poly1305::try_new(key)
            .map(|cipher| Self { cipher })
            .ok_or(CryptoError::InvalidKeyLength)
    }

    pub fn encrypt(&self, nonce: &[u8; 24], plaintext: &mut [u8]) -> Result<[u8; 16], ()> {
        self.cipher.encrypt(nonce, plaintext)
    }

    pub fn decrypt(&self, nonce: &[u8; 24], ciphertext: &mut [u8], tag: &[u8; 16]) -> bool {
        self.cipher.decrypt(nonce, ciphertext, tag)
    }
}

impl ZeroizeOnDrop for Cipher {}
