//! AEAD 2022 UDP AES-GCM body ciphers.

#[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
use zeroize::ZeroizeOnDrop;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    v2::{
        crypto::{Aes128Gcm, Aes256Gcm},
        CryptoError, BLAKE3_KEY_DERIVE_CONTEXT,
    },
    CipherKind,
};

pub enum Cipher {
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
}

impl Cipher {
    pub const fn nonce_size() -> usize {
        12
    }

    pub fn try_new(kind: CipherKind, key: &[u8], session_id: &[u8; 8]) -> Result<Self, CryptoError> {
        if !matches!(
            kind,
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM
        ) {
            return Err(CryptoError::InvalidMethod);
        }
        let key_len = kind.key_len();
        if key.len() != key_len {
            return Err(CryptoError::InvalidKeyLength);
        }

        let mut material = Zeroizing::new(Vec::with_capacity(key_len + session_id.len()));
        material.extend_from_slice(key);
        material.extend_from_slice(session_id);
        let mut derived = Zeroizing::new(blake3_v2::derive_key(BLAKE3_KEY_DERIVE_CONTEXT, material.as_slice()));
        let cipher = match kind {
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM => Aes128Gcm::try_new(&derived[..key_len])
                .map(Self::Aes128Gcm)
                .ok_or(CryptoError::InvalidKeyLength)?,
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM => Aes256Gcm::try_new(&derived[..key_len])
                .map(Self::Aes256Gcm)
                .ok_or(CryptoError::InvalidKeyLength)?,
            _ => return Err(CryptoError::InvalidMethod),
        };
        derived.zeroize();
        material.zeroize();
        Ok(cipher)
    }

    pub fn encrypt(&self, nonce: &[u8; 12], plaintext: &mut [u8]) -> Result<[u8; 16], ()> {
        match self {
            Self::Aes128Gcm(cipher) => cipher.encrypt(nonce, plaintext),
            Self::Aes256Gcm(cipher) => cipher.encrypt(nonce, plaintext),
        }
    }

    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &mut [u8], tag: &[u8; 16]) -> bool {
        match self {
            Self::Aes128Gcm(cipher) => cipher.decrypt(nonce, ciphertext, tag),
            Self::Aes256Gcm(cipher) => cipher.decrypt(nonce, ciphertext, tag),
        }
    }
}

#[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
impl ZeroizeOnDrop for Cipher {}
