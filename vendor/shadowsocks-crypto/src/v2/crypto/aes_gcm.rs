use aes_gcm_v2::{
    aead::inout::InOutBuf, AeadInOut, Aes128Gcm as CryptoAes128Gcm,
    Aes256Gcm as CryptoAes256Gcm, KeyInit, Nonce, Tag,
};
use zeroize::ZeroizeOnDrop;

use super::require_zeroize_on_drop_type;

const _: () = assert!(core::mem::needs_drop::<CryptoAes128Gcm>());
const _: () = assert!(core::mem::needs_drop::<CryptoAes256Gcm>());

pub struct Aes128Gcm(Box<CryptoAes128Gcm>);

impl Aes128Gcm {
    pub fn try_new(key: &[u8]) -> Option<Self> {
        require_zeroize_on_drop_type::<aes_v2::Aes128>();
        CryptoAes128Gcm::new_from_slice(key).ok().map(Box::new).map(Self)
    }

    pub const fn key_size() -> usize {
        16
    }

    pub const fn nonce_size() -> usize {
        12
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

    pub fn decrypt_into(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        tag: &[u8; 16],
    ) -> bool {
        let Ok(buffer) = InOutBuf::new(ciphertext, plaintext) else {
            return false;
        };
        self.0
            .decrypt_inout_detached(&Nonce::from(*nonce), &[], buffer, &Tag::from(*tag))
            .is_ok()
    }
}

impl ZeroizeOnDrop for Aes128Gcm {}

pub struct Aes256Gcm(Box<CryptoAes256Gcm>);

impl Aes256Gcm {
    pub fn try_new(key: &[u8]) -> Option<Self> {
        require_zeroize_on_drop_type::<aes_v2::Aes256>();
        CryptoAes256Gcm::new_from_slice(key).ok().map(Box::new).map(Self)
    }

    pub const fn key_size() -> usize {
        32
    }

    pub const fn nonce_size() -> usize {
        12
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

    pub fn decrypt_into(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        tag: &[u8; 16],
    ) -> bool {
        let Ok(buffer) = InOutBuf::new(ciphertext, plaintext) else {
            return false;
        };
        self.0
            .decrypt_inout_detached(&Nonce::from(*nonce), &[], buffer, &Tag::from(*tag))
            .is_ok()
    }
}

impl ZeroizeOnDrop for Aes256Gcm {}
