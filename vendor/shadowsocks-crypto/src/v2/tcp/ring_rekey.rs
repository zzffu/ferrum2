//! Diagnostic-only TCP AES-GCM adapter that expands a raw subkey per operation.

use ring::aead::{Aad, Algorithm, LessSafeKey, Nonce, Tag, UnboundKey, AES_128_GCM, AES_256_GCM};
use zeroize::Zeroizing;

struct RingRekey<const N: usize> {
    raw_subkey: Zeroizing<[u8; N]>,
}

// These exact-size assertions make persistent expanded-key ownership impossible
// inside the diagnostic adapter. Its complete long-lived state is the inline,
// drop-zeroized raw subkey.
const _: () = assert!(core::mem::size_of::<RingRekey<16>>() == 16);
const _: () = assert!(core::mem::size_of::<RingRekey<32>>() == 32);

impl<const N: usize> RingRekey<N> {
    fn try_new(key: &[u8]) -> Option<Self> {
        if key.len() != N {
            return None;
        }
        let mut raw_subkey = Zeroizing::new([0_u8; N]);
        raw_subkey.copy_from_slice(key);
        Some(Self { raw_subkey })
    }

    fn key(&self, algorithm: &'static Algorithm) -> Result<LessSafeKey, ()> {
        UnboundKey::new(algorithm, &self.raw_subkey[..])
            .map(LessSafeKey::new)
            .map_err(|_| ())
    }

    fn encrypt(&self, algorithm: &'static Algorithm, nonce: &[u8; 12], plaintext: &mut [u8]) -> Result<[u8; 16], ()> {
        let key = self.key(algorithm)?;
        let tag = key
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(*nonce), Aad::empty(), plaintext)
            .map_err(|_| ())?;
        let mut output = [0_u8; 16];
        output.copy_from_slice(tag.as_ref());
        Ok(output)
    }

    fn decrypt(&self, algorithm: &'static Algorithm, nonce: &[u8; 12], ciphertext: &mut [u8], tag: &[u8; 16]) -> bool {
        let Ok(key) = self.key(algorithm) else {
            return false;
        };
        key.open_in_place_separate_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::empty(),
            Tag::from(*tag),
            ciphertext,
            0..,
        )
        .is_ok()
    }
}

pub(super) struct Aes128Gcm(RingRekey<16>);

impl Aes128Gcm {
    pub(super) fn try_new(key: &[u8]) -> Option<Self> {
        RingRekey::try_new(key).map(Self)
    }

    pub(super) fn encrypt(&self, nonce: &[u8; 12], plaintext: &mut [u8]) -> Result<[u8; 16], ()> {
        self.0.encrypt(&AES_128_GCM, nonce, plaintext)
    }

    pub(super) fn decrypt(&self, nonce: &[u8; 12], ciphertext: &mut [u8], tag: &[u8; 16]) -> bool {
        self.0.decrypt(&AES_128_GCM, nonce, ciphertext, tag)
    }
}

pub(super) struct Aes256Gcm(RingRekey<32>);

impl Aes256Gcm {
    pub(super) fn try_new(key: &[u8]) -> Option<Self> {
        RingRekey::try_new(key).map(Self)
    }

    pub(super) fn encrypt(&self, nonce: &[u8; 12], plaintext: &mut [u8]) -> Result<[u8; 16], ()> {
        self.0.encrypt(&AES_256_GCM, nonce, plaintext)
    }

    pub(super) fn decrypt(&self, nonce: &[u8; 12], ciphertext: &mut [u8], tag: &[u8; 16]) -> bool {
        self.0.decrypt(&AES_256_GCM, nonce, ciphertext, tag)
    }
}

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
    fn aes_128_matches_nist_vector_and_rejects_tampering() {
        let cipher = Aes128Gcm::try_new(&[0_u8; 16]).expect("valid AES-128 key");
        let nonce = [0_u8; 12];
        let plaintext = [0_u8; 16];
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
        assert!(Aes128Gcm::try_new(&[0_u8; 15]).is_none());
    }

    #[test]
    fn aes_256_matches_nist_vector_and_rejects_wrong_nonce() {
        let cipher = Aes256Gcm::try_new(&[0_u8; 32]).expect("valid AES-256 key");
        let nonce = [0_u8; 12];
        let plaintext = [0_u8; 16];
        let mut ciphertext = plaintext;

        let tag = cipher.encrypt(&nonce, &mut ciphertext).expect("seal");
        assert_eq!(ciphertext, decode("cea7403d4d606b6e074ec5d3baf39d18"));
        assert_eq!(tag, decode("d0d1c8a799996bf0265b98b5d48ab919"));

        let mut wrong_nonce = nonce;
        wrong_nonce[0] = 1;
        assert!(!cipher.decrypt(&wrong_nonce, &mut ciphertext, &tag));
        assert!(Aes256Gcm::try_new(&[0_u8; 31]).is_none());
    }
}
