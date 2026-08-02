//! AEAD 2022 TCP ciphers with explicit caller-owned nonces.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    kind::{CipherCategory, CipherKind},
    v2::{
        crypto::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305},
        CryptoError, BLAKE3_KEY_DERIVE_CONTEXT,
    },
};

enum CipherVariant {
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl CipherVariant {
    fn try_new(kind: CipherKind, key: &[u8]) -> Result<Self, CryptoError> {
        match kind {
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM => Aes128Gcm::try_new(key)
                .map(Self::Aes128Gcm)
                .ok_or(CryptoError::InvalidKeyLength),
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM => Aes256Gcm::try_new(key)
                .map(Self::Aes256Gcm)
                .ok_or(CryptoError::InvalidKeyLength),
            CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => ChaCha20Poly1305::try_new(key)
                .map(Self::ChaCha20Poly1305)
                .ok_or(CryptoError::InvalidKeyLength),
            _ => Err(CryptoError::InvalidMethod),
        }
    }

    fn kind(&self) -> CipherKind {
        match self {
            Self::Aes128Gcm(_) => CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
            Self::Aes256Gcm(_) => CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
            Self::ChaCha20Poly1305(_) => CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
        }
    }

    fn encrypt(&self, nonce: &[u8; 12], plaintext: &mut [u8]) -> Result<[u8; 16], ()> {
        match self {
            Self::Aes128Gcm(cipher) => cipher.encrypt(nonce, plaintext),
            Self::Aes256Gcm(cipher) => cipher.encrypt(nonce, plaintext),
            Self::ChaCha20Poly1305(cipher) => cipher.encrypt(nonce, plaintext),
        }
    }

    fn decrypt(&self, nonce: &[u8; 12], ciphertext: &mut [u8], tag: &[u8; 16]) -> bool {
        match self {
            Self::Aes128Gcm(cipher) => cipher.decrypt(nonce, ciphertext, tag),
            Self::Aes256Gcm(cipher) => cipher.decrypt(nonce, ciphertext, tag),
            Self::ChaCha20Poly1305(cipher) => cipher.decrypt(nonce, ciphertext, tag),
        }
    }
}

impl ZeroizeOnDrop for CipherVariant {}

/// A checked AEAD2022 TCP primitive owner.
pub struct TcpCipher {
    cipher: CipherVariant,
}

impl TcpCipher {
    /// Derives one directional cipher after validating the method and widths.
    pub fn try_new(kind: CipherKind, key: &[u8], salt: &[u8]) -> Result<Self, CryptoError> {
        if !matches!(
            kind,
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM
                | CipherKind::AEAD2022_BLAKE3_AES_256_GCM
                | CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305
        ) {
            return Err(CryptoError::InvalidMethod);
        }
        let key_len = kind.key_len();
        if key.len() != key_len {
            return Err(CryptoError::InvalidKeyLength);
        }
        if salt.len() != key_len {
            return Err(CryptoError::InvalidSaltLength);
        }

        let mut material = Zeroizing::new(Vec::with_capacity(key_len * 2));
        material.extend_from_slice(key);
        material.extend_from_slice(salt);
        let mut derived = Zeroizing::new(blake3_v2::derive_key(BLAKE3_KEY_DERIVE_CONTEXT, material.as_slice()));
        let cipher = CipherVariant::try_new(kind, &derived[..key_len])?;
        derived.zeroize();
        material.zeroize();
        Ok(Self { cipher })
    }

    /// Cipher's kind.
    pub fn kind(&self) -> CipherKind {
        self.cipher.kind()
    }

    /// Cipher's category, always `Aead2022`.
    pub const fn category(&self) -> CipherCategory {
        CipherCategory::Aead2022
    }

    /// Tag size.
    pub const fn tag_len(&self) -> usize {
        16
    }

    /// Encrypts one body under an explicit, already-reserved u96le nonce.
    pub fn encrypt_packet(&self, nonce: &[u8; 12], plaintext: &mut [u8]) -> Result<[u8; 16], CryptoError> {
        self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::OperationFailed)
    }

    /// Authenticates one body under an explicit u96le nonce.
    pub fn decrypt_packet(&self, nonce: &[u8; 12], ciphertext: &mut [u8], tag: &[u8; 16]) -> Result<(), CryptoError> {
        if self.cipher.decrypt(nonce, ciphertext, tag) {
            Ok(())
        } else {
            ciphertext.zeroize();
            Err(CryptoError::AuthenticationFailed)
        }
    }
}

impl ZeroizeOnDrop for TcpCipher {}
