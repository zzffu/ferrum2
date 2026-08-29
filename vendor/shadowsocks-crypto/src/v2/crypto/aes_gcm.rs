#[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
use aes_gcm_v2::{AeadInOut, Aes128Gcm as CryptoAes128Gcm, Aes256Gcm as CryptoAes256Gcm, KeyInit, Nonce, Tag};
#[cfg(feature = "v2-ring-nonzeroizing-diagnostic")]
use ring::aead::{
    Aad, Algorithm, LessSafeKey, Nonce as RingNonce, Tag as RingTag, UnboundKey, AES_128_GCM, AES_256_GCM,
};
#[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
use zeroize::ZeroizeOnDrop;

#[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
use super::require_zeroize_on_drop_type;

/// Identifies whether this build clears the AEAD2022 AES-GCM expanded keys on drop.
///
/// With `v2-ring-nonzeroizing-diagnostic`, this is deliberately `false`: ring
/// 0.17.14 does not implement `Drop` or `ZeroizeOnDrop` for its expanded key.
/// The diagnostic AES wrappers and their TCP/UDP owners therefore intentionally
/// do not implement `ZeroizeOnDrop` either.
///
#[cfg_attr(
    feature = "v2-ring-nonzeroizing-diagnostic",
    doc = r#"```compile_fail
use shadowsocks_crypto::v2::tcp::TcpCipher;
use zeroize::ZeroizeOnDrop;

fn require_zeroize_on_drop<T: ZeroizeOnDrop>() {}

require_zeroize_on_drop::<TcpCipher>();
```

```compile_fail
use shadowsocks_crypto::v2::udp::UdpCipher;
use zeroize::ZeroizeOnDrop;

fn require_zeroize_on_drop<T: ZeroizeOnDrop>() {}

require_zeroize_on_drop::<UdpCipher>();
```"#
)]
pub const V2_AES_GCM_EXPANDED_KEYS_ZEROIZE_ON_DROP: bool = !cfg!(feature = "v2-ring-nonzeroizing-diagnostic");

/// Stable build identity for security-contract and performance evidence.
#[cfg(feature = "v2-ring-nonzeroizing-diagnostic")]
pub const V2_AES_GCM_BUILD_SECURITY_IDENTITY: &str = "diagnostic-only:ring-0.17.14:expanded-keys-not-zeroized-on-drop";

/// Stable build identity for security-contract and performance evidence.
#[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
pub const V2_AES_GCM_BUILD_SECURITY_IDENTITY: &str = "rustcrypto:expanded-keys-zeroized-on-drop";

#[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
const _: () = assert!(core::mem::needs_drop::<CryptoAes128Gcm>());
#[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
const _: () = assert!(core::mem::needs_drop::<CryptoAes256Gcm>());
#[cfg(feature = "v2-ring-nonzeroizing-diagnostic")]
const _: () = assert!(!core::mem::needs_drop::<LessSafeKey>());

#[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
type Aes128Backend = CryptoAes128Gcm;
#[cfg(feature = "v2-ring-nonzeroizing-diagnostic")]
type Aes128Backend = LessSafeKey;

#[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
type Aes256Backend = CryptoAes256Gcm;
#[cfg(feature = "v2-ring-nonzeroizing-diagnostic")]
type Aes256Backend = LessSafeKey;

#[cfg(feature = "v2-ring-nonzeroizing-diagnostic")]
fn try_new_ring_key(algorithm: &'static Algorithm, key: &[u8]) -> Option<Box<LessSafeKey>> {
    UnboundKey::new(algorithm, key).ok().map(LessSafeKey::new).map(Box::new)
}

#[cfg(feature = "v2-ring-nonzeroizing-diagnostic")]
fn ring_encrypt(key: &LessSafeKey, nonce: &[u8; 12], plaintext: &mut [u8]) -> Result<[u8; 16], ()> {
    let tag = key
        .seal_in_place_separate_tag(RingNonce::assume_unique_for_key(*nonce), Aad::empty(), plaintext)
        .map_err(|_| ())?;
    let mut output = [0; 16];
    output.copy_from_slice(tag.as_ref());
    Ok(output)
}

#[cfg(feature = "v2-ring-nonzeroizing-diagnostic")]
fn ring_decrypt(key: &LessSafeKey, nonce: &[u8; 12], ciphertext: &mut [u8], tag: &[u8; 16]) -> bool {
    key.open_in_place_separate_tag(
        RingNonce::assume_unique_for_key(*nonce),
        Aad::empty(),
        RingTag::from(*tag),
        ciphertext,
        0..,
    )
    .is_ok()
}

pub struct Aes128Gcm(Box<Aes128Backend>);

impl Aes128Gcm {
    pub fn try_new(key: &[u8]) -> Option<Self> {
        #[cfg(feature = "v2-ring-nonzeroizing-diagnostic")]
        {
            try_new_ring_key(&AES_128_GCM, key).map(Self)
        }
        #[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
        {
            require_zeroize_on_drop_type::<aes_v2::Aes128>();
            CryptoAes128Gcm::new_from_slice(key).ok().map(Box::new).map(Self)
        }
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
        #[cfg(feature = "v2-ring-nonzeroizing-diagnostic")]
        {
            ring_encrypt(self.0.as_ref(), nonce, plaintext)
        }
        #[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
        {
            let tag = self
                .0
                .encrypt_inout_detached(&Nonce::from(*nonce), &[], plaintext.into())
                .map_err(|_| ())?;
            let mut output = [0; 16];
            output.copy_from_slice(&tag);
            Ok(output)
        }
    }

    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &mut [u8], tag: &[u8; 16]) -> bool {
        #[cfg(feature = "v2-ring-nonzeroizing-diagnostic")]
        {
            ring_decrypt(self.0.as_ref(), nonce, ciphertext, tag)
        }
        #[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
        {
            self.0
                .decrypt_inout_detached(&Nonce::from(*nonce), &[], ciphertext.into(), &Tag::from(*tag))
                .is_ok()
        }
    }
}

#[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
impl ZeroizeOnDrop for Aes128Gcm {}

pub struct Aes256Gcm(Box<Aes256Backend>);

impl Aes256Gcm {
    pub fn try_new(key: &[u8]) -> Option<Self> {
        #[cfg(feature = "v2-ring-nonzeroizing-diagnostic")]
        {
            try_new_ring_key(&AES_256_GCM, key).map(Self)
        }
        #[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
        {
            require_zeroize_on_drop_type::<aes_v2::Aes256>();
            CryptoAes256Gcm::new_from_slice(key).ok().map(Box::new).map(Self)
        }
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
        #[cfg(feature = "v2-ring-nonzeroizing-diagnostic")]
        {
            ring_encrypt(self.0.as_ref(), nonce, plaintext)
        }
        #[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
        {
            let tag = self
                .0
                .encrypt_inout_detached(&Nonce::from(*nonce), &[], plaintext.into())
                .map_err(|_| ())?;
            let mut output = [0; 16];
            output.copy_from_slice(&tag);
            Ok(output)
        }
    }

    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &mut [u8], tag: &[u8; 16]) -> bool {
        #[cfg(feature = "v2-ring-nonzeroizing-diagnostic")]
        {
            ring_decrypt(self.0.as_ref(), nonce, ciphertext, tag)
        }
        #[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
        {
            self.0
                .decrypt_inout_detached(&Nonce::from(*nonce), &[], ciphertext.into(), &Tag::from(*tag))
                .is_ok()
        }
    }
}

#[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
impl ZeroizeOnDrop for Aes256Gcm {}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode<const N: usize>(value: &str) -> [u8; N] {
        hex::decode(value)
            .expect("valid test vector hex")
            .try_into()
            .expect("exact test vector width")
    }

    #[test]
    fn aes_128_gcm_matches_nist_vector_and_rejects_tampering() {
        let cipher = Aes128Gcm::try_new(&[0; 16]).expect("valid AES-128 key");
        let nonce = [0; 12];
        let plaintext = [0; 16];
        let mut ciphertext = plaintext;

        let tag = cipher.encrypt(&nonce, &mut ciphertext).expect("seal");
        assert_eq!(ciphertext, decode("0388dace60b6a392f328c2b971b2fe78"));
        assert_eq!(tag, decode("ab6e47d42cec13bdf53a67b21257bddf"));

        assert!(cipher.decrypt(&nonce, &mut ciphertext, &tag));
        assert_eq!(ciphertext, plaintext);

        let mut tampered_tag = tag;
        tampered_tag[0] ^= 1;
        let mut rejected = decode::<16>("0388dace60b6a392f328c2b971b2fe78");
        assert!(!cipher.decrypt(&nonce, &mut rejected, &tampered_tag));
        assert!(Aes128Gcm::try_new(&[0; 15]).is_none());
    }

    #[test]
    fn aes_256_gcm_matches_nist_vector_and_rejects_wrong_nonce() {
        let cipher = Aes256Gcm::try_new(&[0; 32]).expect("valid AES-256 key");
        let nonce = [0; 12];
        let plaintext = [0; 16];
        let mut ciphertext = plaintext;

        let tag = cipher.encrypt(&nonce, &mut ciphertext).expect("seal");
        assert_eq!(ciphertext, decode("cea7403d4d606b6e074ec5d3baf39d18"));
        assert_eq!(tag, decode("d0d1c8a799996bf0265b98b5d48ab919"));

        let mut wrong_nonce = nonce;
        wrong_nonce[0] = 1;
        assert!(!cipher.decrypt(&wrong_nonce, &mut ciphertext, &tag));
        assert!(Aes256Gcm::try_new(&[0; 31]).is_none());
    }

    #[test]
    fn build_security_identity_matches_selected_backend() {
        #[cfg(feature = "v2-ring-nonzeroizing-diagnostic")]
        {
            assert_eq!(
                std::hint::black_box(V2_AES_GCM_BUILD_SECURITY_IDENTITY),
                "diagnostic-only:ring-0.17.14:expanded-keys-not-zeroized-on-drop"
            );
            assert!(!std::hint::black_box(V2_AES_GCM_EXPANDED_KEYS_ZEROIZE_ON_DROP));
            assert!(!std::hint::black_box(core::mem::needs_drop::<LessSafeKey>()));
        }
        #[cfg(not(feature = "v2-ring-nonzeroizing-diagnostic"))]
        {
            fn require_zeroize_on_drop<T: ZeroizeOnDrop>() {}

            assert_eq!(
                std::hint::black_box(V2_AES_GCM_BUILD_SECURITY_IDENTITY),
                "rustcrypto:expanded-keys-zeroized-on-drop"
            );
            assert!(std::hint::black_box(V2_AES_GCM_EXPANDED_KEYS_ZEROIZE_ON_DROP));
            require_zeroize_on_drop::<Aes128Gcm>();
            require_zeroize_on_drop::<Aes256Gcm>();
        }
    }
}
