use aes_gcm_v2::{AeadInOut, Aes128Gcm as CryptoAes128Gcm, Aes256Gcm as CryptoAes256Gcm, KeyInit, Nonce, Tag};
#[cfg(feature = "aws-lc")]
use aws_lc_rs::aead::{
    Aad as AwsAad, Algorithm as AwsAlgorithm, LessSafeKey as AwsLessSafeKey, Nonce as AwsNonce,
    UnboundKey as AwsUnboundKey, AES_128_GCM, AES_256_GCM,
};
use zeroize::ZeroizeOnDrop;

use super::require_zeroize_on_drop_type;

const _: () = assert!(core::mem::needs_drop::<CryptoAes128Gcm>());
const _: () = assert!(core::mem::needs_drop::<CryptoAes256Gcm>());
// `AwsLessSafeKey` owns an EVP_AEAD_CTX allocation. The locked aws-lc-sys
// `OPENSSL_free` cleanses that allocation before release.
#[cfg(feature = "aws-lc")]
const _: () = assert!(core::mem::needs_drop::<AwsLessSafeKey>());

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

    #[cfg(not(feature = "aws-lc"))]
    pub(crate) fn decrypt_appended(&self, nonce: &[u8; 12], ciphertext_and_tag: &mut [u8]) -> bool {
        let Some(tag_start) = ciphertext_and_tag.len().checked_sub(Self::tag_size()) else {
            return false;
        };
        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(tag_start);
        let tag: &[u8; 16] = (&*tag)
            .try_into()
            .unwrap_or_else(|_| unreachable!("validated AES-GCM tag width"));
        self.decrypt(nonce, ciphertext, tag)
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

    #[cfg(not(feature = "aws-lc"))]
    pub(crate) fn decrypt_appended(&self, nonce: &[u8; 12], ciphertext_and_tag: &mut [u8]) -> bool {
        let Some(tag_start) = ciphertext_and_tag.len().checked_sub(Self::tag_size()) else {
            return false;
        };
        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(tag_start);
        let tag: &[u8; 16] = (&*tag)
            .try_into()
            .unwrap_or_else(|_| unreachable!("validated AES-GCM tag width"));
        self.decrypt(nonce, ciphertext, tag)
    }
}

impl ZeroizeOnDrop for Aes256Gcm {}

#[cfg(not(feature = "aws-lc"))]
pub(crate) type TcpAes128Gcm = Aes128Gcm;

#[cfg(not(feature = "aws-lc"))]
pub(crate) type TcpAes256Gcm = Aes256Gcm;

#[cfg(feature = "aws-lc")]
fn try_new_aws(algorithm: &'static AwsAlgorithm, key: &[u8]) -> Option<AwsLessSafeKey> {
    AwsUnboundKey::new(algorithm, key).ok().map(AwsLessSafeKey::new)
}

/// AWS-LC-backed AES-128-GCM for contiguous TCP ciphertext and tag buffers.
#[cfg(feature = "aws-lc")]
pub(crate) struct TcpAes128Gcm(AwsLessSafeKey);

#[cfg(feature = "aws-lc")]
impl TcpAes128Gcm {
    pub(crate) fn try_new(key: &[u8]) -> Option<Self> {
        try_new_aws(&AES_128_GCM, key).map(Self)
    }

    pub(crate) fn encrypt(&self, nonce: &[u8; 12], plaintext: &mut [u8]) -> Result<[u8; 16], ()> {
        let tag = self
            .0
            .seal_in_place_separate_tag(AwsNonce::assume_unique_for_key(*nonce), AwsAad::empty(), plaintext)
            .map_err(|_| ())?;
        let mut output = [0; 16];
        output.copy_from_slice(tag.as_ref());
        Ok(output)
    }

    pub(crate) fn decrypt_appended(&self, nonce: &[u8; 12], ciphertext_and_tag: &mut [u8]) -> bool {
        self.0
            .open_in_place(
                AwsNonce::assume_unique_for_key(*nonce),
                AwsAad::empty(),
                ciphertext_and_tag,
            )
            .is_ok()
    }
}

#[cfg(feature = "aws-lc")]
impl ZeroizeOnDrop for TcpAes128Gcm {}

/// AWS-LC-backed AES-256-GCM for contiguous TCP ciphertext and tag buffers.
#[cfg(feature = "aws-lc")]
pub(crate) struct TcpAes256Gcm(AwsLessSafeKey);

#[cfg(feature = "aws-lc")]
impl TcpAes256Gcm {
    pub(crate) fn try_new(key: &[u8]) -> Option<Self> {
        try_new_aws(&AES_256_GCM, key).map(Self)
    }

    pub(crate) fn encrypt(&self, nonce: &[u8; 12], plaintext: &mut [u8]) -> Result<[u8; 16], ()> {
        let tag = self
            .0
            .seal_in_place_separate_tag(AwsNonce::assume_unique_for_key(*nonce), AwsAad::empty(), plaintext)
            .map_err(|_| ())?;
        let mut output = [0; 16];
        output.copy_from_slice(tag.as_ref());
        Ok(output)
    }

    pub(crate) fn decrypt_appended(&self, nonce: &[u8; 12], ciphertext_and_tag: &mut [u8]) -> bool {
        self.0
            .open_in_place(
                AwsNonce::assume_unique_for_key(*nonce),
                AwsAad::empty(),
                ciphertext_and_tag,
            )
            .is_ok()
    }
}

#[cfg(feature = "aws-lc")]
impl ZeroizeOnDrop for TcpAes256Gcm {}
