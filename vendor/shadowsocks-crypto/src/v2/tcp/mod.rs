//! AEAD 2022 TCP ciphers with explicit caller-owned nonces.

#[cfg(not(feature = "v2-ring-rekey-diagnostic"))]
use zeroize::ZeroizeOnDrop;
use zeroize::{Zeroize, Zeroizing};

#[cfg(not(feature = "v2-ring-rekey-diagnostic"))]
use crate::v2::crypto::{Aes128Gcm, Aes256Gcm};
use crate::{
    kind::{CipherCategory, CipherKind},
    v2::{crypto::ChaCha20Poly1305, CryptoError, BLAKE3_KEY_DERIVE_CONTEXT},
};
#[cfg(feature = "v2-ring-rekey-diagnostic")]
use ring_rekey::{Aes128Gcm, Aes256Gcm};

#[cfg(feature = "v2-ring-rekey-diagnostic")]
mod ring_rekey;

/// Stable TCP AES-GCM backend identity for security and performance evidence.
#[cfg(feature = "v2-ring-rekey-diagnostic")]
pub const V2_TCP_AES_GCM_BUILD_SECURITY_IDENTITY: &str =
    "diagnostic-only:ring-0.17.14:per-operation-rekey:raw-subkey-zeroized:transient-expanded-key-not-proven-zeroized";

/// Stable TCP AES-GCM backend identity for security and performance evidence.
#[cfg(not(feature = "v2-ring-rekey-diagnostic"))]
pub const V2_TCP_AES_GCM_BUILD_SECURITY_IDENTITY: &str = "rustcrypto:persistent-expanded-keys-zeroized-on-drop";

/// The diagnostic's complete persistent AES owner is a drop-zeroized raw subkey.
#[cfg(feature = "v2-ring-rekey-diagnostic")]
pub const V2_RING_REKEY_RAW_SUBKEY_ZEROIZE_ON_DROP: bool = true;

/// The diagnostic stores no ring expanded key between synchronous operations.
#[cfg(feature = "v2-ring-rekey-diagnostic")]
pub const V2_RING_REKEY_PERSISTENT_EXPANDED_KEY_BYTES: usize = 0;

/// ring 0.17.14 does not prove erasure of its transient expanded key on drop.
#[cfg(feature = "v2-ring-rekey-diagnostic")]
pub const V2_RING_REKEY_TRANSIENT_EXPANDED_KEYS_ZEROIZE_ON_DROP: bool = false;

/// Whether the complete TCP cipher owner claims the production zeroize-on-drop contract.
pub const V2_TCP_CIPHER_ZEROIZE_ON_DROP_CONTRACT: bool = !cfg!(feature = "v2-ring-rekey-diagnostic");

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

#[cfg(not(feature = "v2-ring-rekey-diagnostic"))]
impl ZeroizeOnDrop for CipherVariant {}

/// A checked AEAD2022 TCP primitive owner.
pub struct TcpCipher {
    cipher: CipherVariant,
}

impl TcpCipher {
    /// Owns an already-derived directional subkey after validating the method and width.
    pub fn try_from_subkey(kind: CipherKind, subkey: &[u8]) -> Result<Self, CryptoError> {
        CipherVariant::try_new(kind, subkey).map(|cipher| Self { cipher })
    }

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
        let cipher = Self::try_from_subkey(kind, &derived[..key_len]);
        derived.zeroize();
        material.zeroize();
        cipher
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

#[cfg(not(feature = "v2-ring-rekey-diagnostic"))]
impl ZeroizeOnDrop for TcpCipher {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_subkey_matches_psk_salt_and_rejects_invalid_inputs() {
        let methods = [
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
            CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
        ];
        let key = [0x11; 32];
        let salt = [0x22; 32];
        let oversized = [0x44; 33];
        let nonce = [0x33; 12];

        for kind in methods {
            let key_len = kind.key_len();
            let mut material = Vec::with_capacity(key_len * 2);
            material.extend_from_slice(&key[..key_len]);
            material.extend_from_slice(&salt[..key_len]);
            let derived = blake3_v2::derive_key(BLAKE3_KEY_DERIVE_CONTEXT, &material);

            let derived_cipher = TcpCipher::try_new(kind, &key[..key_len], &salt[..key_len]).unwrap();
            let raw_cipher = TcpCipher::try_from_subkey(kind, &derived[..key_len]).unwrap();
            let mut derived_plaintext = b"same plaintext".to_vec();
            let mut raw_plaintext = derived_plaintext.clone();

            let derived_tag = derived_cipher.encrypt_packet(&nonce, &mut derived_plaintext).unwrap();
            let raw_tag = raw_cipher.encrypt_packet(&nonce, &mut raw_plaintext).unwrap();
            assert_eq!(derived_plaintext, raw_plaintext);
            assert_eq!(derived_tag, raw_tag);

            assert!(matches!(
                TcpCipher::try_from_subkey(kind, &derived[..key_len - 1]),
                Err(CryptoError::InvalidKeyLength)
            ));
            assert!(matches!(
                TcpCipher::try_from_subkey(kind, &oversized[..key_len + 1]),
                Err(CryptoError::InvalidKeyLength)
            ));
        }

        assert!(matches!(
            TcpCipher::try_from_subkey(CipherKind::NONE, &[]),
            Err(CryptoError::InvalidMethod)
        ));
    }
}
