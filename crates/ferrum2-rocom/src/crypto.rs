//! AES method 3 adapted from tsf4g_codec/src/crypto.rs and codec/data_body.rs.
//! Uses the workspace's reviewed AWS-LC provider, without protocol padding removal.
use aws_lc_rs::{
    cipher::{AES_128, DecryptingKey, DecryptionContext, UnboundCipherKey},
    iv::FixedLength,
};
use zeroize::Zeroizing;

pub(crate) struct Plaintext {
    pub bytes: Zeroizing<Vec<u8>>,
    pub payload: Option<std::ops::Range<usize>>,
    pub error: Option<&'static str>,
}

pub(crate) fn decrypt(key: &[u8; 16], input: &[u8]) -> Plaintext {
    let mut output = Plaintext {
        bytes: Zeroizing::new(Vec::new()),
        payload: None,
        error: None,
    };
    if input.is_empty() || !input.len().is_multiple_of(16) {
        output.error = Some("ciphertext_alignment");
        return output;
    }
    let Ok(cipher) = UnboundCipherKey::new(&AES_128, key).and_then(DecryptingKey::cbc) else {
        output.error = Some("crypto_provider");
        return output;
    };
    output.bytes.extend_from_slice(input);
    let iv = DecryptionContext::Iv128(FixedLength::from([0u8; 16]));
    if cipher.decrypt(&mut output.bytes, iv).is_err() {
        output.bytes = Zeroizing::new(Vec::new());
        output.error = Some("crypto_provider");
        return output;
    }
    let n = output.bytes.len();
    if n < 22 {
        output.error = Some("plaintext_too_short");
        return output;
    }
    let trim = usize::from(output.bytes[n - 1]);
    if trim < 6 || trim > n - 16 {
        output.error = Some("invalid_trim");
        return output;
    }
    if &output.bytes[n - 6..n - 1] != b"tsf4g" {
        output.error = Some("missing_trailer");
        return output;
    }
    output.payload = Some(16..n - trim);
    output
}
