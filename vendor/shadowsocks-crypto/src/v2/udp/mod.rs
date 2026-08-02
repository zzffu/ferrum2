//! Checked AEAD 2022 UDP primitive owners.

use aes_v2::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes_v2::{Aes128, Aes256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    v2::{crypto::require_zeroize_on_drop, CryptoError},
    CipherCategory, CipherKind,
};

#[cfg(feature = "v2-extra")]
pub use self::chacha8_poly1305::Cipher as ChaCha8Poly1305Cipher;
pub use self::{aes_gcm::Cipher as AesGcmCipher, chacha20_poly1305::Cipher as ChaCha20Poly1305Cipher};

mod aes_gcm;
mod chacha20_poly1305;
#[cfg(feature = "v2-extra")]
mod chacha8_poly1305;

enum CipherVariant {
    AesGcm(AesGcmCipher),
    ChaCha20Poly1305(ChaCha20Poly1305Cipher),
}

impl ZeroizeOnDrop for CipherVariant {}

/// AEAD2022 UDP body cipher with checked method, key, session and nonce inputs.
pub struct UdpCipher {
    cipher: CipherVariant,
    kind: CipherKind,
}

impl UdpCipher {
    /// Creates a method-bound body cipher. AES requires an eight-byte session ID;
    /// ChaCha requires `None` because it uses the PSK directly.
    pub fn try_new(kind: CipherKind, key: &[u8], session_id: Option<&[u8; 8]>) -> Result<Self, CryptoError> {
        let cipher = match kind {
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM => CipherVariant::AesGcm(
                AesGcmCipher::try_new(kind, key, session_id.ok_or(CryptoError::InvalidSessionId)?)?,
            ),
            CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => {
                if session_id.is_some() {
                    return Err(CryptoError::InvalidSessionId);
                }
                CipherVariant::ChaCha20Poly1305(ChaCha20Poly1305Cipher::try_new(key)?)
            }
            _ => return Err(CryptoError::InvalidMethod),
        };
        Ok(Self { cipher, kind })
    }

    /// Cipher's kind.
    pub const fn kind(&self) -> CipherKind {
        self.kind
    }

    /// Cipher's category, always `Aead2022`.
    pub const fn category(&self) -> CipherCategory {
        CipherCategory::Aead2022
    }

    /// Encrypts a body and returns its detached authentication tag.
    pub fn encrypt_packet(&self, nonce: &[u8], plaintext: &mut [u8]) -> Result<[u8; 16], CryptoError> {
        match &self.cipher {
            CipherVariant::AesGcm(cipher) => cipher
                .encrypt(
                    nonce.try_into().map_err(|_| CryptoError::InvalidNonceLength)?,
                    plaintext,
                )
                .map_err(|_| CryptoError::OperationFailed),
            CipherVariant::ChaCha20Poly1305(cipher) => cipher
                .encrypt(
                    nonce.try_into().map_err(|_| CryptoError::InvalidNonceLength)?,
                    plaintext,
                )
                .map_err(|_| CryptoError::OperationFailed),
        }
    }

    /// Authenticates and opens a body, clearing candidate plaintext on failure.
    pub fn decrypt_packet(&self, nonce: &[u8], ciphertext: &mut [u8], tag: &[u8; 16]) -> Result<(), CryptoError> {
        let authenticated = match &self.cipher {
            CipherVariant::AesGcm(cipher) => cipher.decrypt(
                nonce.try_into().map_err(|_| CryptoError::InvalidNonceLength)?,
                ciphertext,
                tag,
            ),
            CipherVariant::ChaCha20Poly1305(cipher) => cipher.decrypt(
                nonce.try_into().map_err(|_| CryptoError::InvalidNonceLength)?,
                ciphertext,
                tag,
            ),
        };
        if authenticated {
            Ok(())
        } else {
            ciphertext.zeroize();
            Err(CryptoError::AuthenticationFailed)
        }
    }
}

impl ZeroizeOnDrop for UdpCipher {}

enum HeaderVariant {
    Aes128(Aes128),
    Aes256(Aes256),
}

impl ZeroizeOnDrop for HeaderVariant {}

/// AES-ECB owner for SIP022's separate 16-byte UDP identity header.
pub struct AesHeaderCipher(HeaderVariant);

impl AesHeaderCipher {
    /// Creates a checked AES header owner from the direct PSK.
    pub fn try_new(kind: CipherKind, key: &[u8]) -> Result<Self, CryptoError> {
        let cipher = match kind {
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM => Aes128::new_from_slice(key)
                .ok()
                .map(require_zeroize_on_drop)
                .map(HeaderVariant::Aes128),
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM => Aes256::new_from_slice(key)
                .ok()
                .map(require_zeroize_on_drop)
                .map(HeaderVariant::Aes256),
            _ => return Err(CryptoError::InvalidMethod),
        }
        .ok_or(CryptoError::InvalidKeyLength)?;
        Ok(Self(cipher))
    }

    /// Protects one exact-width separate header in place.
    pub fn encrypt(&self, header: &mut [u8; 16]) {
        let mut block = Array::from(*header);
        match &self.0 {
            HeaderVariant::Aes128(cipher) => cipher.encrypt_block(&mut block),
            HeaderVariant::Aes256(cipher) => cipher.encrypt_block(&mut block),
        }
        header.copy_from_slice(&block);
        block.as_mut_slice().zeroize();
    }

    /// Opens one exact-width separate header in place.
    pub fn decrypt(&self, header: &mut [u8; 16]) {
        let mut block = Array::from(*header);
        match &self.0 {
            HeaderVariant::Aes128(cipher) => cipher.decrypt_block(&mut block),
            HeaderVariant::Aes256(cipher) => cipher.decrypt_block(&mut block),
        }
        header.copy_from_slice(&block);
        block.as_mut_slice().zeroize();
    }
}

impl ZeroizeOnDrop for AesHeaderCipher {}
