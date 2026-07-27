use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit, Nonce};
use bytes::BytesMut;
use ferrum2_crypto::{
    Aes128Psk, KeyProvider, KeySelector, NonceCounter, SinglePskProvider, TcpMethod, TcpSalt,
    TcpSealer,
};
use serde_json::Value;

const FIXTURE: &str = include_str!("../../../tests/fixtures/crypto/sip022-kdf-v1.json");

fn decode_array<const N: usize>(encoded: &str) -> [u8; N] {
    hex::decode(encoded)
        .expect("fixture contains hexadecimal")
        .try_into()
        .unwrap_or_else(|_| panic!("fixture field has {N} bytes"))
}

#[test]
fn sip022_kdf_selects_the_first_16_bytes() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("valid fixture");
    let context = fixture["context_string"].as_str().expect("context");
    assert_eq!(context, "shadowsocks 2022 session subkey");

    let psk = decode_array::<16>(fixture["psk"].as_str().expect("psk"));
    let salt = decode_array::<16>(fixture["salt"].as_str().expect("salt"));
    let mut input = [0_u8; 32];
    input[..16].copy_from_slice(&psk);
    input[16..].copy_from_slice(&salt);
    let expected_full = decode_array::<32>(
        fixture["full_derive_output"]
            .as_str()
            .expect("full derive output"),
    );
    let actual_full = blake3::derive_key(context, &input);
    assert_eq!(actual_full, expected_full);
    assert_eq!(
        &expected_full[..16],
        &decode_array::<16>(
            fixture["selected_subkey"]
                .as_str()
                .expect("selected subkey")
        )
    );

    let provider = SinglePskProvider::new(Aes128Psk::from_bytes(psk));
    let subkey = provider
        .with_key(KeySelector::Default, |key| {
            key.derive_tcp_subkey(TcpMethod::Blake3Aes128Gcm2022, &TcpSalt::from_bytes(salt))
        })
        .expect("default key exists");
    let plaintext =
        hex::decode(fixture["aead_plaintext"].as_str().expect("plaintext")).expect("plaintext");
    let selected = decode_array::<16>(
        fixture["selected_subkey"]
            .as_str()
            .expect("selected subkey"),
    );
    let primitive = Aes128Gcm::new_from_slice(&selected).expect("AES-128 key width");
    for (nonce_value, field) in [
        (0_u8, "nonce_0_ciphertext_and_tag"),
        (1_u8, "nonce_1_ciphertext_and_tag"),
    ] {
        let mut direct = BytesMut::with_capacity(plaintext.len() + 16);
        direct.extend_from_slice(&plaintext);
        let mut nonce = [0_u8; 12];
        nonce[0] = nonce_value;
        primitive
            .encrypt_in_place(&Nonce::from(nonce), &[], &mut direct)
            .expect("direct primitive fixture verification");
        assert_eq!(
            direct.as_ref(),
            hex::decode(fixture[field].as_str().expect("nonce output")).expect("nonce output")
        );
    }

    let mut first = BytesMut::with_capacity(plaintext.len() + 16);
    first.extend_from_slice(&plaintext);
    let mut sealer = TcpSealer::new(subkey);
    sealer.seal_in_place(&mut first).expect("zero nonce seals");
    assert_eq!(
        first.as_ref(),
        hex::decode(
            fixture["nonce_0_ciphertext_and_tag"]
                .as_str()
                .expect("nonce zero output")
        )
        .expect("nonce zero output")
    );

    let mut second = BytesMut::with_capacity(plaintext.len() + 16);
    second.extend_from_slice(&plaintext);
    sealer.seal_in_place(&mut second).expect("nonce one seals");
    assert_eq!(
        second.as_ref(),
        hex::decode(
            fixture["nonce_1_ciphertext_and_tag"]
                .as_str()
                .expect("nonce one output")
        )
        .expect("nonce one output")
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
