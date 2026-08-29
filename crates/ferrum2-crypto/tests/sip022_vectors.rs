use std::collections::VecDeque;
use std::sync::Mutex;

use bytes::BytesMut;
use ferrum2_crypto::{
    KeySelector, MethodKeyProvider, MethodProfile, MethodPsk, MethodSinglePskProvider,
    MethodTcpSalt, NonceCounter, RandomError, SecureRandom, TcpOpener, TcpSealer, TcpSubkey,
    UdpCryptoError,
};
use serde_json::Value;

const PROFILE_FIXTURE: &str =
    include_str!("../../../tests/fixtures/crypto/sip022-kdf-profiles-v1.json");
const UDP_FIXTURE: &str =
    include_str!("../../../tests/fixtures/crypto/sip022-udp-primitives-v1.json");

fn decode_array<const N: usize>(encoded: &str) -> [u8; N] {
    hex::decode(encoded)
        .expect("fixture contains hexadecimal")
        .try_into()
        .unwrap_or_else(|_| panic!("fixture field has {N} bytes"))
}

fn profile(method: &str) -> MethodProfile {
    match method {
        "2022-blake3-aes-128-gcm" => MethodProfile::Blake3Aes128Gcm2022,
        "2022-blake3-aes-256-gcm" => MethodProfile::Blake3Aes256Gcm2022,
        "2022-blake3-chacha20-poly1305" => MethodProfile::Blake3ChaCha20Poly13052022,
        other => panic!("unexpected fixture method {other}"),
    }
}

struct ScriptedRandom {
    draws: Mutex<VecDeque<Vec<u8>>>,
}

impl ScriptedRandom {
    fn new(draws: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            draws: Mutex::new(draws.into_iter().collect()),
        }
    }
}

impl SecureRandom for ScriptedRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomError> {
        let draw = self
            .draws
            .lock()
            .expect("draw mutex")
            .pop_front()
            .expect("fixture provides every random draw");
        assert_eq!(draw.len(), destination.len());
        destination.copy_from_slice(&draw);
        Ok(())
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
    assert_eq!(cases.len(), MethodProfile::ALL.len());
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

        if profile == MethodProfile::Blake3Aes128Gcm2022 {
            let selected =
                decode_array::<16>(case["selected_subkey"].as_str().expect("selected subkey"));
            let mut raw = BytesMut::from(plaintext.as_slice());
            TcpSealer::new(TcpSubkey::from_bytes(selected))
                .seal_in_place(&mut raw)
                .expect("already-derived public subkey seals");
            assert_eq!(
                raw.as_ref(),
                hex::decode(
                    case["nonce_0_ciphertext_and_tag"]
                        .as_str()
                        .expect("nonce zero output")
                )
                .expect("nonce zero output")
            );
        }

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
        let mut corrupted = BytesMut::from(corrupted.as_slice());
        assert!(opener.open_in_place(&mut corrupted).is_err());

        let mut valid = BytesMut::from(valid.as_slice());
        opener
            .open_in_place(&mut valid)
            .expect("failed authentication did not advance nonce");
        assert_eq!(valid.as_ref(), plaintext);
    }
}

#[test]
fn sip022_udp_capability_table_matches_reviewed_envelopes_and_fails_closed() {
    let fixture: Value = serde_json::from_str(UDP_FIXTURE).expect("valid UDP fixture");
    let plaintext = hex::decode(fixture["body_plaintext"].as_str().expect("body")).expect("body");
    let cases = fixture["cases"].as_array().expect("UDP cases");
    assert_eq!(cases.len(), MethodProfile::ALL.len());

    for case in cases {
        let method_name = case["method"].as_str().expect("method");
        let profile = profile(method_name);
        let psk = hex::decode(case["psk"].as_str().expect("PSK")).expect("PSK");
        let session_bytes =
            hex::decode(case["session_id"].as_str().expect("session ID")).expect("session ID");
        let provider = MethodSinglePskProvider::new(
            MethodPsk::try_from_slice(profile, &psk).expect("method-width PSK"),
        );
        let crypto = provider
            .with_method_key(KeySelector::Default, |key| key.udp_crypto())
            .expect("default key");
        assert_eq!(crypto.profile(), profile);
        assert!(format!("{crypto:?}").contains("[REDACTED]"));
        let session_random = ScriptedRandom::new([session_bytes]);
        let mut outbound = crypto
            .generate_outbound_session(&session_random, |_| false)
            .expect("fixture outbound session");
        assert!(format!("{outbound:?}").contains("[REDACTED]"));
        let mut binding_field = [0_u8; 8];
        outbound
            .session_id()
            .write_wire(&mut binding_field)
            .expect("bounded response binding field");
        assert_eq!(
            binding_field.as_slice(),
            hex::decode(case["session_id"].as_str().expect("session ID")).expect("session ID")
        );
        assert!(outbound.session_id().matches_wire(&binding_field));
        assert!(!outbound.session_id().matches_wire(&binding_field[..7]));

        let target_packet_id = case["packet_id"].as_u64().expect("packet ID");
        let nonce_draws = if profile == MethodProfile::Blake3ChaCha20Poly13052022 {
            let mut draws = (0..target_packet_id)
                .map(|value| vec![value as u8 + 1; 24])
                .collect::<Vec<_>>();
            draws.push(hex::decode(case["nonce"].as_str().expect("nonce")).expect("fixture nonce"));
            draws.push(vec![0xd4; 24]);
            draws
        } else {
            Vec::new()
        };
        let packet_random = ScriptedRandom::new(nonce_draws);
        let mut output = vec![0xa5; plaintext.len() + profile.udp_wire_overhead_bytes()];

        for expected_packet_id in 0..target_packet_id {
            let sealed = crypto
                .seal(&mut outbound, &plaintext, &mut output, &packet_random)
                .expect("preceding packet seals");
            assert_eq!(sealed.packet_id(), expected_packet_id);
        }

        let mut too_small = vec![0xa5; output.len() - 1];
        assert!(matches!(
            crypto.seal(&mut outbound, &plaintext, &mut too_small, &packet_random,),
            Err(UdpCryptoError::OutputTooSmall)
        ));
        assert!(too_small.iter().all(|byte| *byte == 0xa5));

        let sealed = crypto
            .seal(&mut outbound, &plaintext, &mut output, &packet_random)
            .expect("fixture packet seals");
        assert_eq!(sealed.packet_id(), target_packet_id);
        let expected_wire = hex::decode(case["wire"].as_str().expect("wire")).expect("wire");
        assert_eq!(&output[..sealed.wire_len()], expected_wire);

        let mut opened_body = vec![0xa5; expected_wire.len()];
        let opened = crypto
            .open(&expected_wire, &mut opened_body)
            .expect("fixture packet authenticates");
        assert_eq!(opened.session_id(), outbound.session_id());
        assert_eq!(opened.packet_id(), target_packet_id);
        assert_eq!(&opened_body[..opened.plaintext_len()], plaintext);

        let mut corrupted = expected_wire.clone();
        *corrupted.last_mut().expect("tag byte") ^= 1;
        let mut rejected_output = vec![0xa5; expected_wire.len()];
        assert!(matches!(
            crypto.open(&corrupted, &mut rejected_output),
            Err(UdpCryptoError::AuthenticationFailed)
        ));
        assert!(
            rejected_output[..plaintext.len()]
                .iter()
                .all(|byte| *byte == 0)
        );

        if profile == MethodProfile::Blake3ChaCha20Poly13052022 {
            let prior_wire = output.clone();
            let next = crypto
                .seal(&mut outbound, &plaintext, &mut output, &packet_random)
                .expect("next packet draws a fresh nonce");
            assert_eq!(next.packet_id(), target_packet_id + 1);
            assert_eq!(&output[..24], &[0xd4; 24]);
            assert_ne!(&output[..next.wire_len()], &prior_wire[..sealed.wire_len()]);
        }
    }
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
