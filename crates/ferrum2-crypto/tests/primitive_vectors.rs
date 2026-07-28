use blake3::Hasher;
use bytes::BytesMut;
use ferrum2_crypto::{TcpOpener, TcpSealer, TcpSubkey};
use serde_json::Value;
use std::path::Path;

const BLAKE3_FIXTURE: &str = include_str!("../../../tests/fixtures/crypto/blake3-derive-v1.json");
const AES128_GCM_FIXTURE: &str = include_str!("../../../tests/fixtures/crypto/aes128-gcm-v1.json");
const SIP022_KDF_FIXTURE: &str = include_str!("../../../tests/fixtures/crypto/sip022-kdf-v1.json");
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

#[test]
fn aes128_gcm_mcgrew_viega_proposal_cases_and_corrupted_tag_match() {
    let fixture: Value = serde_json::from_str(AES128_GCM_FIXTURE).expect("valid fixture");
    let cases = fixture["cases"].as_array().expect("cases");

    assert_eq!(
        fixture["classification"].as_str(),
        Some(
            "McGrew/Viega GCM proposal test cases 1 and 2, submitter-supplied and historically hosted by NIST; not NIST CAVP or NIST-authored validation vectors"
        )
    );
    assert_eq!(
        fixture["source_vector_ids"],
        serde_json::json!([
            "McGrew/Viega GCM proposal test case 1",
            "McGrew/Viega GCM proposal test case 2"
        ])
    );
    assert_eq!(cases.len(), 2);
    for case in cases {
        assert_eq!(case["iv"].as_str(), Some("000000000000000000000000"));
        assert_eq!(case["aad"].as_str(), Some(""));

        let key = decode_array::<16>(case["key"].as_str().expect("key"));
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
        TcpSealer::new(TcpSubkey::from_bytes(key))
            .seal_in_place(&mut encrypted)
            .expect("proposal case encryption succeeds");
        assert_eq!(encrypted.as_ref(), expected);

        TcpOpener::new(TcpSubkey::from_bytes(key))
            .open_in_place(&mut encrypted)
            .expect("proposal case decryption succeeds");
        assert_eq!(encrypted.as_ref(), plaintext);
    }

    let case = &cases[1];
    let key = decode_array::<16>(case["key"].as_str().expect("key"));
    let mut corrupted =
        hex::decode(case["ciphertext"].as_str().expect("ciphertext")).expect("ciphertext");
    let mut tag = hex::decode(case["tag"].as_str().expect("tag")).expect("tag");
    *tag.last_mut().expect("non-empty tag") ^= 1;
    corrupted.extend(tag);
    let original = corrupted.clone();
    let mut corrupted = BytesMut::from(corrupted.as_slice());

    assert!(
        TcpOpener::new(TcpSubkey::from_bytes(key))
            .open_in_place(&mut corrupted)
            .is_err()
    );
    assert_eq!(corrupted.as_ref(), original);
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
            SIP022_KDF_FIXTURE,
            "2b74c9ddf95fbf872dfa19bc402e7dd30da56acd25f3ef0ef3f17bd74fed367d",
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
