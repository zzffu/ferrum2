use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt};
use aes::{Aes128, Aes256};
use aes_gcm::{AeadInOut, Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use blake3::Hasher;
use bytes::BytesMut;
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305, XNonce};
use serde_json::Value;
use std::path::Path;

const BLAKE3_FIXTURE: &str = include_str!("../../../tests/fixtures/crypto/blake3-derive-v1.json");
const AES128_GCM_FIXTURE: &str = include_str!("../../../tests/fixtures/crypto/aes128-gcm-v1.json");
const AES256_GCM_FIXTURE: &str = include_str!("../../../tests/fixtures/crypto/aes256-gcm-v1.json");
const CHACHA20_POLY1305_FIXTURE: &str =
    include_str!("../../../tests/fixtures/crypto/chacha20-poly1305-v1.json");
const XCHACHA20_POLY1305_FIXTURE: &str =
    include_str!("../../../tests/fixtures/crypto/xchacha20-poly1305-draft02-v1.json");
const SIP022_UDP_FIXTURE: &str =
    include_str!("../../../tests/fixtures/crypto/sip022-udp-primitives-v1.json");
const SIP022_KDF_FIXTURE: &str = include_str!("../../../tests/fixtures/crypto/sip022-kdf-v1.json");
const SIP022_PROFILE_KDF_FIXTURE: &str =
    include_str!("../../../tests/fixtures/crypto/sip022-kdf-profiles-v1.json");
const PROFILE_GENERATOR: &str =
    include_str!("../../../tests/fixtures/crypto/profile-fixture-generator.rs");
const PROVENANCE: &str = include_str!("../../../tests/fixtures/crypto/PROVENANCE.toml");

fn decode_array<const N: usize>(encoded: &str) -> [u8; N] {
    hex::decode(encoded)
        .expect("fixture contains hexadecimal")
        .try_into()
        .unwrap_or_else(|_| panic!("fixture field has {N} bytes"))
}

#[test]
fn blake3_official_derive_mode_rows_match() {
    let fixture: Value = serde_json::from_str(BLAKE3_FIXTURE).expect("valid fixture");
    let context = fixture["context_string"].as_str().expect("context string");
    let cases = fixture["cases"].as_array().expect("cases");

    assert_eq!(cases.len(), 3);
    for case in cases {
        let input_len = case["input_len"].as_u64().expect("input length") as usize;
        assert!(matches!(input_len, 0 | 1 | 1024));
        let input: Vec<u8> = (0..input_len).map(|index| (index % 251) as u8).collect();
        let expected = hex::decode(case["derive_key"].as_str().expect("derive output"))
            .expect("hexadecimal derive output");

        let mut hasher = Hasher::new_derive_key(context);
        hasher.update(&input);
        let mut actual = vec![0_u8; expected.len()];
        hasher.finalize_xof().fill(&mut actual);

        assert_eq!(
            actual, expected,
            "official BLAKE3 row input_len={input_len}"
        );
        assert_eq!(&actual[..32], blake3::derive_key(context, &input));
    }
}

#[derive(Clone, Copy)]
enum Primitive {
    Aes128,
    Aes256,
    ChaCha20Poly1305,
}

impl Primitive {
    fn encrypt(self, case: &Value, buffer: &mut BytesMut) {
        let nonce = decode_array::<12>(case["iv"].as_str().expect("nonce"));
        let aad = hex::decode(case["aad"].as_str().expect("AAD")).expect("hexadecimal AAD");
        let result = match self {
            Self::Aes128 => Aes128Gcm::new_from_slice(
                &hex::decode(case["key"].as_str().expect("key")).expect("hexadecimal key"),
            )
            .expect("AES-128 key")
            .encrypt_in_place(&Nonce::from(nonce), &aad, buffer),
            Self::Aes256 => Aes256Gcm::new_from_slice(
                &hex::decode(case["key"].as_str().expect("key")).expect("hexadecimal key"),
            )
            .expect("AES-256 key")
            .encrypt_in_place(&Nonce::from(nonce), &aad, buffer),
            Self::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(
                &hex::decode(case["key"].as_str().expect("key")).expect("hexadecimal key"),
            )
            .expect("ChaCha20 key")
            .encrypt_in_place(&Nonce::from(nonce), &aad, buffer),
        };
        result.expect("reviewed primitive row encrypts");
    }

    fn decrypt(self, case: &Value, buffer: &mut BytesMut) -> Result<(), ()> {
        let nonce = decode_array::<12>(case["iv"].as_str().expect("nonce"));
        let aad = hex::decode(case["aad"].as_str().expect("AAD")).expect("hexadecimal AAD");
        let result = match self {
            Self::Aes128 => Aes128Gcm::new_from_slice(
                &hex::decode(case["key"].as_str().expect("key")).expect("hexadecimal key"),
            )
            .expect("AES-128 key")
            .decrypt_in_place(&Nonce::from(nonce), &aad, buffer),
            Self::Aes256 => Aes256Gcm::new_from_slice(
                &hex::decode(case["key"].as_str().expect("key")).expect("hexadecimal key"),
            )
            .expect("AES-256 key")
            .decrypt_in_place(&Nonce::from(nonce), &aad, buffer),
            Self::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(
                &hex::decode(case["key"].as_str().expect("key")).expect("hexadecimal key"),
            )
            .expect("ChaCha20 key")
            .decrypt_in_place(&Nonce::from(nonce), &aad, buffer),
        };
        result.map_err(|_| ())
    }
}

#[test]
fn reviewed_aead_profile_rows_and_corrupted_tags_match() {
    let fixtures = [
        (
            Primitive::Aes128,
            serde_json::from_str::<Value>(AES128_GCM_FIXTURE).expect("valid AES-128 fixture"),
        ),
        (
            Primitive::Aes256,
            serde_json::from_str::<Value>(AES256_GCM_FIXTURE).expect("valid AES-256 fixture"),
        ),
        (
            Primitive::ChaCha20Poly1305,
            serde_json::from_str::<Value>(CHACHA20_POLY1305_FIXTURE).expect("valid ChaCha fixture"),
        ),
    ];

    assert_eq!(
        fixtures[0].1["source_vector_ids"].as_array().unwrap().len(),
        2
    );
    assert_eq!(
        fixtures[1].1["source_vector_ids"].as_array().unwrap().len(),
        2
    );
    assert_eq!(
        fixtures[2].1["source_vector_ids"].as_array().unwrap().len(),
        1
    );

    for (primitive, fixture) in fixtures {
        let cases = fixture["cases"].as_array().expect("primitive cases");
        for case in cases {
            let plaintext = hex::decode(case["plaintext"].as_str().expect("plaintext"))
                .expect("hexadecimal plaintext");
            let mut expected =
                hex::decode(case["ciphertext"].as_str().expect("ciphertext")).expect("ciphertext");
            expected.extend(
                hex::decode(case["tag"].as_str().expect("tag"))
                    .expect("hexadecimal authentication tag"),
            );

            let mut encrypted = BytesMut::with_capacity(plaintext.len() + 16);
            encrypted.extend_from_slice(&plaintext);
            primitive.encrypt(case, &mut encrypted);
            assert_eq!(encrypted.as_ref(), expected, "fixture row {}", case["id"]);

            primitive
                .decrypt(case, &mut encrypted)
                .expect("reviewed primitive row authenticates");
            assert_eq!(encrypted.as_ref(), plaintext, "fixture row {}", case["id"]);
        }

        let negative = cases.last().expect("negative source row");
        let mut corrupted =
            hex::decode(negative["ciphertext"].as_str().expect("ciphertext")).expect("ciphertext");
        let mut tag = hex::decode(negative["tag"].as_str().expect("tag")).expect("tag");
        *tag.last_mut().expect("non-empty tag") ^= 1;
        corrupted.extend(tag);
        let original = corrupted.clone();
        let mut corrupted = BytesMut::from(corrupted.as_slice());

        assert!(primitive.decrypt(negative, &mut corrupted).is_err());
        assert_eq!(corrupted.as_ref(), original);
    }
}

#[test]
fn pinned_xchacha_draft02_row_and_corrupted_tag_match() {
    let fixture: Value =
        serde_json::from_str(XCHACHA20_POLY1305_FIXTURE).expect("valid XChaCha fixture");
    let cases = fixture["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 1);
    let case = &cases[0];
    let key = hex::decode(case["key"].as_str().expect("key")).expect("key");
    let nonce = decode_array::<24>(case["nonce"].as_str().expect("nonce"));
    let aad = hex::decode(case["aad"].as_str().expect("AAD")).expect("AAD");
    let plaintext = hex::decode(case["plaintext"].as_str().expect("plaintext")).expect("plaintext");
    let mut expected =
        hex::decode(case["ciphertext"].as_str().expect("ciphertext")).expect("ciphertext");
    expected.extend(hex::decode(case["tag"].as_str().expect("tag")).expect("tag"));

    let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("XChaCha key");
    let mut encrypted = BytesMut::with_capacity(plaintext.len() + 16);
    encrypted.extend_from_slice(&plaintext);
    cipher
        .encrypt_in_place(&XNonce::from(nonce), &aad, &mut encrypted)
        .expect("draft row encrypts");
    assert_eq!(encrypted.as_ref(), expected);

    cipher
        .decrypt_in_place(&XNonce::from(nonce), &aad, &mut encrypted)
        .expect("draft row authenticates");
    assert_eq!(encrypted.as_ref(), plaintext);

    let mut corrupted = expected;
    *corrupted.last_mut().expect("tag byte") ^= 1;
    let original = corrupted.clone();
    let mut corrupted = BytesMut::from(corrupted.as_slice());
    assert!(
        cipher
            .decrypt_in_place(&XNonce::from(nonce), &aad, &mut corrupted)
            .is_err()
    );
    assert_eq!(corrupted.as_ref(), original);
}

#[test]
fn sip022_udp_aes_header_kdf_nonce_and_tag_rows_match() {
    let fixture: Value = serde_json::from_str(SIP022_UDP_FIXTURE).expect("valid UDP fixture");
    let context = fixture["context_string"].as_str().expect("context");
    let plaintext = hex::decode(fixture["body_plaintext"].as_str().expect("body")).expect("body");
    let cases = fixture["cases"].as_array().expect("cases");

    for case in &cases[..2] {
        let method = case["method"].as_str().expect("method");
        let psk = hex::decode(case["psk"].as_str().expect("PSK")).expect("PSK");
        let session_id =
            hex::decode(case["session_id"].as_str().expect("session ID")).expect("session ID");
        let plaintext_header =
            decode_array::<16>(case["plaintext_header"].as_str().expect("plaintext header"));
        let expected_header =
            decode_array::<16>(case["encrypted_header"].as_str().expect("encrypted header"));
        let expected_full =
            decode_array::<32>(case["full_derive_output"].as_str().expect("derive output"));

        let mut material = psk.clone();
        material.extend_from_slice(&session_id);
        assert_eq!(blake3::derive_key(context, &material), expected_full);
        assert_eq!(
            &expected_full[..psk.len()],
            hex::decode(case["selected_subkey"].as_str().expect("subkey")).expect("subkey")
        );
        assert_eq!(
            &plaintext_header[4..],
            hex::decode(case["body_nonce"].as_str().expect("body nonce")).expect("body nonce")
        );

        let mut block = Array::from(plaintext_header);
        match method {
            "2022-blake3-aes-128-gcm" => {
                let cipher = Aes128::new_from_slice(&psk).expect("AES-128 key");
                cipher.encrypt_block(&mut block);
                assert_eq!(block.as_slice(), expected_header);
                cipher.decrypt_block(&mut block);
            }
            "2022-blake3-aes-256-gcm" => {
                let cipher = Aes256::new_from_slice(&psk).expect("AES-256 key");
                cipher.encrypt_block(&mut block);
                assert_eq!(block.as_slice(), expected_header);
                cipher.decrypt_block(&mut block);
            }
            other => panic!("unexpected AES row {other}"),
        }
        assert_eq!(block.as_slice(), plaintext_header);

        let nonce = decode_array::<12>(case["body_nonce"].as_str().expect("body nonce"));
        let mut encrypted = BytesMut::with_capacity(plaintext.len() + 16);
        encrypted.extend_from_slice(&plaintext);
        match method {
            "2022-blake3-aes-128-gcm" => Aes128Gcm::new_from_slice(&expected_full[..16])
                .expect("AES-128 body key")
                .encrypt_in_place(&Nonce::from(nonce), &[], &mut encrypted)
                .expect("AES-128 body"),
            "2022-blake3-aes-256-gcm" => Aes256Gcm::new_from_slice(&expected_full)
                .expect("AES-256 body key")
                .encrypt_in_place(&Nonce::from(nonce), &[], &mut encrypted)
                .expect("AES-256 body"),
            _ => unreachable!("validated method"),
        }
        assert_eq!(
            encrypted.as_ref(),
            hex::decode(
                case["body_ciphertext_and_tag"]
                    .as_str()
                    .expect("body output")
            )
            .expect("body output")
        );

        *encrypted.last_mut().expect("tag byte") ^= 1;
        let rejected = match method {
            "2022-blake3-aes-128-gcm" => Aes128Gcm::new_from_slice(&expected_full[..16])
                .expect("AES-128 body key")
                .decrypt_in_place(&Nonce::from(nonce), &[], &mut encrypted),
            "2022-blake3-aes-256-gcm" => Aes256Gcm::new_from_slice(&expected_full)
                .expect("AES-256 body key")
                .decrypt_in_place(&Nonce::from(nonce), &[], &mut encrypted),
            _ => unreachable!("validated method"),
        };
        assert!(rejected.is_err(), "{method} corrupted tag");
    }
}

#[test]
fn fixture_hashes_and_source_provenance_are_pinned() {
    for (fixture, expected) in [
        (
            BLAKE3_FIXTURE,
            "13d8f79ae8241af454938149d209c37d1c87512d55a64551c911cac08a88518c",
        ),
        (
            AES128_GCM_FIXTURE,
            "0c524568d8ee98e4b0a3dda7f4c87c36972fc439174e44716cf33f971393fdf1",
        ),
        (
            AES256_GCM_FIXTURE,
            "b3fddcddbbce801620d9147b362be61e6267ee1eea4cfa00bb2a4e722d61b3f1",
        ),
        (
            CHACHA20_POLY1305_FIXTURE,
            "d9799fb4af314e9c0053bc5f261bf68cb807e5ac91d6ef73fef4e00db104589e",
        ),
        (
            SIP022_KDF_FIXTURE,
            "2b74c9ddf95fbf872dfa19bc402e7dd30da56acd25f3ef0ef3f17bd74fed367d",
        ),
        (
            SIP022_PROFILE_KDF_FIXTURE,
            "f6d0047ad1432707b44201da40cfb831e754cbd70008b28d4538aa160d72f428",
        ),
        (
            XCHACHA20_POLY1305_FIXTURE,
            "6791999d70ac966e72fdf4d55afa03f0b8096bf4d14d04b8a96d33cbc2aa77aa",
        ),
        (
            SIP022_UDP_FIXTURE,
            "3db87e963d6d1ae3b784450958021deeeaaf9f5a8b8053724613a74da0becfef",
        ),
        (
            PROFILE_GENERATOR,
            "0c57b6ae188cd2f471ce0cf5b533d503edea6fc01a381fbb13998f066b365df3",
        ),
    ] {
        let normalized = fixture.replace("\r\n", "\n");
        assert!(!normalized.contains('\r'));
        assert_eq!(hex::encode(sha256(normalized.as_bytes())), expected);
        assert!(PROVENANCE.contains(expected));
    }

    for required in [
        "93a431c78a52d7ccf0f366f106467f5070e6075e",
        "dcb91ea8accc77e6d6e632af7cdc1a99a9f3ae78cf648da595c7d064db32f624",
        "CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception",
        "source_archive_size = 5879",
        "http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-test-vectors.tar.gz",
        "https://web.archive.org/web/20170830120738id_/http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-test-vectors.tar.gz",
        "511e4741cee299ad0d1eb72ae2738911758248e2aba9d3db33a1dbcbb62e07f0",
        "gcm-test-vectors/vec-01.txt",
        "4fffe6ba6272443855d24dcb8deb00e23dddad6da510d57201ffa4560e5137f1",
        "gcm-test-vectors/vec-02.txt",
        "6ceba9c631dac0d4fc5015dc002d37c340af174429213c0afb6f51c76088436a",
        "https://web.archive.org/web/20170811123217id_/http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf",
        "327e3c9363c268fae64e285e2f56f882bb6e3e04f81ef8098521f44c8e2b6c37",
        "https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/proposed-modes/gcm/gcm-nist-ipr.pdf",
        "01708680027b2141cc4f976f2c6e854571cc840737c275da2afb42a48b93813d",
        "source_license = \"NOASSERTION\"",
        "submitter-supplied and historically hosted by NIST",
        "does not imply NIST endorsement",
        "Do not commit or redistribute the source archive or PDF evidence",
        "Non-official SIP022 primitive fixture",
        "gcm-test-vectors/vec-13.txt",
        "a7a76fd69b964918daa559ef5301e1ece5545c1fde61d1039d035bf261a5f8ab",
        "gcm-test-vectors/vec-14.txt",
        "9c94ab4c7de60597968cf6131d0d1402be035e66832420da76741ba9a0927305",
        "RFC 8439 section 2.8.2",
        "25bef70fbf7a07ff45c2fe4cb7c6ce954eac687413d8610603268b4e4415324c",
        "e37a978ccf0992d9053fbc039470d6527108e393",
        "profile-fixture-generator.rs",
        "imports no ferrum2 crate or reference implementation",
        "draft-irtf-cfrg-xchacha-02",
        "Appendix A.1 and A.3.1",
        "IETF Trust Legal Provisions",
        "f6b203facf219fe47bfe2913c2e576240d2bf1f9",
        "AES-128 PSK 00..0f/session ID 60..67/packet ID 0",
    ] {
        assert!(PROVENANCE.contains(required), "missing provenance field");
    }

    let sip022 = provenance_section("tests/fixtures/crypto/sip022-kdf-v1.json");
    let source_path = quoted_provenance_value(sip022, "source_path");
    assert_eq!(
        source_path,
        "docs/adr/ADR-0004-m0-sip022-tcp-security-state.md"
    );
    assert_eq!(
        quoted_provenance_value(sip022, "historical_contract_revision"),
        "c658e5dd285923ccf16d4102034c47e9700461a3"
    );
    assert_eq!(
        quoted_provenance_value(sip022, "historical_contract_blob"),
        "77136841f2122809a39cc6fa36c0354c5bf8c3c4"
    );
    assert_eq!(
        quoted_provenance_value(sip022, "historical_contract_lf_sha256"),
        "ac6365de83c3f3548171caba74781b523a7aebba2f79aa5853352481557cc614"
    );
    assert_eq!(
        quoted_provenance_value(sip022, "historical_contract_section"),
        "Decision / Cryptographic wire constants / subkey"
    );
    assert_eq!(
        quoted_provenance_value(sip022, "current_contract_revision"),
        "a389aa9861806a5d7d0d4fa8f8379f6ecef925d2"
    );
    assert_eq!(
        quoted_provenance_value(sip022, "current_contract_blob"),
        "4c2e401eec1d6f21aedf5b69843de17056c02d40"
    );
    let current_contract_hash = quoted_provenance_value(sip022, "current_contract_lf_sha256");
    assert_eq!(
        current_contract_hash,
        "a8c33a8e2ea013d3b94c9ef54a5b1795a71be77a3adfe1b1079957c72fca83a6"
    );
    assert_eq!(
        quoted_provenance_value(sip022, "current_contract_section"),
        "Decision / Cryptographic wire constants / subkey"
    );
    assert_eq!(
        quoted_provenance_value(sip022, "upstream_sip022_revision"),
        "34598d65054dad975d330ff9d7317b0d41cf1efd"
    );
    assert_eq!(
        quoted_provenance_value(sip022, "upstream_sip022_path"),
        "docs/doc/sip022.md"
    );
    assert_eq!(
        quoted_provenance_value(sip022, "adr0008_kdf_effect"),
        "ADR-0008 changes AES-GCM KAT provenance only; SIP022 KDF constants are unchanged."
    );

    let checked_out_source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(source_path),
    )
    .expect("source_path resolves from the repository root");
    let normalized_source = checked_out_source.replace("\r\n", "\n").replace('\r', "\n");
    let checked_out_hash = hex::encode(sha256(normalized_source.as_bytes()));
    assert!(
        [
            quoted_provenance_value(sip022, "historical_contract_lf_sha256"),
            current_contract_hash,
        ]
        .contains(&checked_out_hash.as_str()),
        "checked-out source must be an explicitly pinned historical or current contract"
    );
    assert!(
        normalized_source
            .contains("BLAKE3-DERIVE(\"shadowsocks 2022 session subkey\", PSK || salt)[0..16]")
    );
}

fn provenance_section(path: &str) -> &str {
    let path_field = format!("path = \"{path}\"");
    let path_offset = PROVENANCE
        .find(&path_field)
        .unwrap_or_else(|| panic!("missing provenance section for {path}"));
    let start = PROVENANCE[..path_offset]
        .rfind("[[fixtures]]")
        .expect("fixture path follows a section header");
    let section = &PROVENANCE[start..];
    let after_header = "[[fixtures]]".len();
    let end = section[after_header..]
        .find("[[fixtures]]")
        .map_or(section.len(), |offset| after_header + offset);
    &section[..end]
}

fn quoted_provenance_value<'a>(section: &'a str, key: &str) -> &'a str {
    let prefix = format!("{key} = \"");
    section
        .lines()
        .find_map(|line| line.strip_prefix(&prefix)?.strip_suffix('"'))
        .unwrap_or_else(|| panic!("missing quoted provenance field {key}"))
}

fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, word) in words[..16].iter_mut().enumerate() {
            *word = u32::from_be_bytes(
                chunk[index * 4..index * 4 + 4]
                    .try_into()
                    .expect("four-byte word"),
            );
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let choice = (e & f) ^ (!e & g);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let first = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let second = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(first);
            d = c;
            c = b;
            b = a;
            a = first.wrapping_add(second);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut output = [0_u8; 32];
    for (chunk, word) in output.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    output
}
