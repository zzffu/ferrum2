use bytes::BytesMut;
use ferrum2_crypto::{
    KeySelector, MethodKeyProvider, MethodPsk, MethodSinglePskProvider, MethodTcpSalt,
    NonceCounter, TcpMethodProfile, TcpOpener, TcpSealer,
};
use serde_json::Value;

const AES128_FIXTURE: &str = include_str!("../../../tests/fixtures/crypto/sip022-kdf-v1.json");
const PROFILE_FIXTURE: &str =
    include_str!("../../../tests/fixtures/crypto/sip022-kdf-profiles-v1.json");

fn decode_array<const N: usize>(encoded: &str) -> [u8; N] {
    hex::decode(encoded)
        .expect("fixture contains hexadecimal")
        .try_into()
        .unwrap_or_else(|_| panic!("fixture field has {N} bytes"))
}

fn profile(method: &str) -> TcpMethodProfile {
    match method {
        "2022-blake3-aes-128-gcm" => TcpMethodProfile::Blake3Aes128Gcm2022,
        "2022-blake3-aes-256-gcm" => TcpMethodProfile::Blake3Aes256Gcm2022,
        "2022-blake3-chacha20-poly1305" => TcpMethodProfile::Blake3ChaCha20Poly13052022,
        other => panic!("unexpected fixture method {other}"),
    }
}

#[test]
fn sip022_kdf_aead_nonce_and_authentication_table_covers_every_profile() {
    let fixture: Value = serde_json::from_str(PROFILE_FIXTURE).expect("valid profile fixture");
    let context = fixture["context_string"].as_str().expect("context");
    assert_eq!(context, "shadowsocks 2022 session subkey");
    let plaintext =
        hex::decode(fixture["aead_plaintext"].as_str().expect("plaintext")).expect("plaintext");

    let cases = fixture["cases"].as_array().expect("profile cases");
    assert_eq!(cases.len(), TcpMethodProfile::ALL.len());
    for case in cases {
        let method_name = case["method"].as_str().expect("method");
        let profile = profile(method_name);
        assert_eq!(profile.canonical_name(), method_name);
        let psk = hex::decode(case["psk"].as_str().expect("psk")).expect("PSK");
        let salt = hex::decode(case["salt"].as_str().expect("salt")).expect("salt");
        let mut input = psk.clone();
        input.extend_from_slice(&salt);
        let expected_full = decode_array::<32>(
            case["full_derive_output"]
                .as_str()
                .expect("full derive output"),
        );
        assert_eq!(blake3::derive_key(context, &input), expected_full);
        assert_eq!(
            &expected_full[..profile.key_bytes()],
            hex::decode(case["selected_subkey"].as_str().expect("selected subkey"))
                .expect("selected subkey")
        );

        let provider = MethodSinglePskProvider::new(
            MethodPsk::try_from_slice(profile, &psk).expect("method-width PSK"),
        );
        let salt = MethodTcpSalt::try_from_slice(profile, &salt).expect("method-width salt");
        assert_eq!(provider.profile(), profile);
        let subkey = provider
            .with_method_key(KeySelector::Default, |key| key.derive_tcp_subkey(&salt))
            .expect("default key exists")
            .expect("profile-bound salt");
        assert_eq!(subkey.profile(), profile);

        let mut sealer = TcpSealer::new(subkey);
        for field in ["nonce_0_ciphertext_and_tag", "nonce_1_ciphertext_and_tag"] {
            let mut encrypted = BytesMut::with_capacity(plaintext.len() + 16);
            encrypted.extend_from_slice(&plaintext);
            sealer
                .seal_in_place(&mut encrypted)
                .expect("profile row seals");
            assert_eq!(
                encrypted.as_ref(),
                hex::decode(case[field].as_str().expect("nonce output")).expect("nonce output"),
                "{method_name} {field}"
            );
        }

        let opener_subkey = provider
            .with_method_key(KeySelector::Default, |key| key.derive_tcp_subkey(&salt))
            .expect("default key exists")
            .expect("profile-bound salt");
        let mut opener = TcpOpener::new(opener_subkey);
        let valid = hex::decode(
            case["nonce_0_ciphertext_and_tag"]
                .as_str()
                .expect("nonce zero output"),
        )
        .expect("nonce zero output");
        let mut corrupted = valid.clone();
        *corrupted.last_mut().expect("tag byte") ^= 1;
        let original = corrupted.clone();
        let mut corrupted = BytesMut::from(corrupted.as_slice());
        assert!(opener.open_in_place(&mut corrupted).is_err());
        assert_eq!(corrupted.as_ref(), original);

        let mut valid = BytesMut::from(valid.as_slice());
        opener
            .open_in_place(&mut valid)
            .expect("failed authentication did not advance nonce");
        assert_eq!(valid.as_ref(), plaintext);
    }

    let old: Value = serde_json::from_str(AES128_FIXTURE).expect("valid M0 fixture");
    assert_eq!(old["psk"], cases[0]["psk"]);
    assert_eq!(old["salt"], cases[0]["salt"]);
    assert_eq!(old["full_derive_output"], cases[0]["full_derive_output"]);
    assert_eq!(old["selected_subkey"], cases[0]["selected_subkey"]);
    assert_eq!(
        old["nonce_0_ciphertext_and_tag"],
        cases[0]["nonce_0_ciphertext_and_tag"]
    );
    assert_eq!(
        old["nonce_1_ciphertext_and_tag"],
        cases[0]["nonce_1_ciphertext_and_tag"]
    );
}

#[test]
fn nonce_counter_starts_at_zero_carries_and_checks_overflow() {
    let mut zero = NonceCounter::new();
    assert_eq!(zero.current_bytes(), [0; 12]);
    zero.checked_increment().expect("zero increments");
    assert_eq!(zero.current_bytes(), [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    let mut carry = NonceCounter::from_le_bytes([0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    carry.checked_increment().expect("carry increments");
    assert_eq!(carry.current_bytes(), [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    let mut exhausted = NonceCounter::from_le_bytes([0xff; 12]);
    assert!(exhausted.checked_increment().is_err());
    assert_eq!(exhausted.current_bytes(), [0xff; 12]);
}
