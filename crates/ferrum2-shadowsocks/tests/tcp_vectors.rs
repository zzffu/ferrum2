use std::net::{Ipv4Addr, SocketAddrV4};

use ferrum2_core::TargetAddr;
use ferrum2_crypto::{Aes128Psk, SinglePskProvider, TcpSalt};
use ferrum2_shadowsocks::{encode_request_first_write, encode_response_first_write};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/sip022/aes128-tcp-v1.json"
    ))
    .expect("reviewed fixture is valid JSON")
}

fn provider() -> SinglePskProvider {
    SinglePskProvider::new(Aes128Psk::from_bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ]))
}

fn request_salt() -> TcpSalt {
    TcpSalt::from_bytes([
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ])
}

#[test]
fn unofficial_composite_request_and_response_match_exact_reviewed_wire() {
    let fixture = fixture();
    assert!(
        fixture["classification"]
            .as_str()
            .expect("classification")
            .contains("unofficial")
    );

    let target =
        TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)).expect("fixture target");
    let request_a = encode_request_first_write(
        &provider(),
        &request_salt(),
        1_700_000_000,
        &target,
        &[0xa1, 0xb2, 0xc3],
        &[],
    )
    .expect("request A encodes");
    assert_eq!(
        hex::encode(&request_a),
        fixture["request_a"]["first_write"].as_str().expect("wire")
    );
    assert_eq!(
        hex::encode(&request_a[16..43]),
        fixture["request_a"]["fixed_ciphertext_and_tag"]
            .as_str()
            .expect("fixed chunk")
    );
    assert_eq!(
        hex::encode(&request_a[43..]),
        fixture["request_a"]["variable_ciphertext_and_tag"]
            .as_str()
            .expect("variable chunk")
    );

    let request_b = encode_request_first_write(
        &provider(),
        &request_salt(),
        1_700_000_000,
        &target,
        &[],
        b"ping",
    )
    .expect("request B encodes");
    assert_eq!(
        hex::encode(&request_b),
        fixture["request_b"]["first_write"].as_str().expect("wire")
    );
    assert_eq!(
        hex::encode(&request_b[16..43]),
        fixture["request_b"]["fixed_ciphertext_and_tag"]
            .as_str()
            .expect("fixed chunk")
    );
    assert_eq!(
        hex::encode(&request_b[43..]),
        fixture["request_b"]["variable_ciphertext_and_tag"]
            .as_str()
            .expect("variable chunk")
    );

    let response_salt = TcpSalt::from_bytes([
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f,
    ]);
    let response = encode_response_first_write(
        &provider(),
        &response_salt,
        1_700_000_000,
        &request_salt(),
        b"pong",
    )
    .expect("response encodes");
    assert_eq!(
        hex::encode(&response),
        fixture["response"]["first_write"].as_str().expect("wire")
    );
    assert_eq!(
        hex::encode(&response[16..59]),
        fixture["response"]["fixed_ciphertext_and_tag"]
            .as_str()
            .expect("fixed chunk")
    );
}

#[test]
fn fixture_and_primitive_only_generator_match_reviewed_provenance_hashes() {
    let fixture = canonical_lf_utf8(
        include_bytes!("../../../tests/fixtures/sip022/aes128-tcp-v1.json"),
        "fixture",
    );
    let generator = canonical_lf_utf8(
        include_bytes!("../../../tests/fixtures/sip022/generator.rs"),
        "generator",
    );
    let provenance = include_str!("../../../tests/fixtures/sip022/PROVENANCE.toml");

    let fixture_hash = sha256_hex(&fixture);
    let generator_hash = sha256_hex(&generator);
    assert_eq!(
        fixture_hash,
        "c7f210d612fd101a05e052dadabd29be12c0f9a82d75c8b394caae3653e611f0"
    );
    assert_eq!(
        generator_hash,
        "ca8d181b41f52b03c8a015dcda87e93df5048c4a775526b629b77feae67faa39"
    );
    assert!(provenance.contains(&format!("fixture_sha256 = \"{fixture_hash}\"")));
    assert!(provenance.contains(&format!("generator_sha256 = \"{generator_hash}\"")));
    assert!(provenance.contains("Unofficial repository-owned SIP022 composite fixture"));
    assert!(provenance.contains("expected_interpretation"));
    assert!(!include_str!("../../../tests/fixtures/sip022/generator.rs").contains("ferrum2_"));
}

fn canonical_lf_utf8(input: &[u8], label: &str) -> Vec<u8> {
    let text = std::str::from_utf8(input)
        .unwrap_or_else(|_| panic!("{label} must contain valid UTF-8 text"));
    let bytes = text.as_bytes();
    let mut canonical = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\r' {
            assert_eq!(
                bytes.get(index + 1),
                Some(&b'\n'),
                "{label} contains an unexpected bare carriage return"
            );
            canonical.push(b'\n');
            index += 2;
        } else {
            canonical.push(bytes[index]);
            index += 1;
        }
    }
    canonical
}

fn sha256_hex(input: &[u8]) -> String {
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
    let bit_len = (input.len() as u64) * 8;
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
            *word = u32::from_be_bytes(chunk[index * 4..index * 4 + 4].try_into().expect("word"));
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
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sum1)
                .wrapping_add(choose)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
    state.iter().map(|word| format!("{word:08x}")).collect()
}
