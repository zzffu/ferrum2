//! Independent generator for the repository-owned unofficial SIP022 fixture.
//!
//! This source intentionally imports only the pinned primitive crates. It does
//! not import any ferrum2 production module.

use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit, Nonce};
use blake3::derive_key;

const PSK: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const REQUEST_SALT: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const RESPONSE_SALT: [u8; 16] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];
const TIMESTAMP: u64 = 1_700_000_000;
const CONTEXT: &str = "shadowsocks 2022 session subkey";

fn subkey(salt: &[u8; 16]) -> [u8; 16] {
    let mut material = [0_u8; 32];
    material[..16].copy_from_slice(&PSK);
    material[16..].copy_from_slice(salt);
    let derived = derive_key(CONTEXT, &material);
    derived[..16].try_into().expect("fixed prefix")
}

fn seal(key: &[u8; 16], nonce: u8, plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes128Gcm::new_from_slice(key).expect("AES-128 key");
    let mut buffer = plaintext.to_vec();
    let mut nonce_bytes = [0_u8; 12];
    nonce_bytes[0] = nonce;
    let tag = cipher
        .encrypt_inout_detached(&Nonce::from(nonce_bytes), &[], buffer.as_mut_slice().into())
        .expect("fixture encryption");
    buffer.extend_from_slice(&tag);
    buffer
}

fn request(padding: &[u8], initial_payload: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut variable = vec![0x01, 127, 0, 0, 1, 0x1f, 0x90];
    variable.extend_from_slice(&(padding.len() as u16).to_be_bytes());
    variable.extend_from_slice(padding);
    variable.extend_from_slice(initial_payload);

    let mut fixed = vec![0x00];
    fixed.extend_from_slice(&TIMESTAMP.to_be_bytes());
    fixed.extend_from_slice(&(variable.len() as u16).to_be_bytes());

    let key = subkey(&REQUEST_SALT);
    let fixed_ciphertext = seal(&key, 0, &fixed);
    let variable_ciphertext = seal(&key, 1, &variable);
    let mut wire = REQUEST_SALT.to_vec();
    wire.extend_from_slice(&fixed_ciphertext);
    wire.extend_from_slice(&variable_ciphertext);
    (fixed_ciphertext, variable_ciphertext, wire)
}

fn response() -> (Vec<u8>, Vec<u8>) {
    let mut fixed = vec![0x01];
    fixed.extend_from_slice(&TIMESTAMP.to_be_bytes());
    fixed.extend_from_slice(&REQUEST_SALT);
    fixed.extend_from_slice(&4_u16.to_be_bytes());

    let key = subkey(&RESPONSE_SALT);
    let fixed_ciphertext = seal(&key, 0, &fixed);
    let payload_ciphertext = seal(&key, 1, b"pong");
    let mut wire = RESPONSE_SALT.to_vec();
    wire.extend_from_slice(&fixed_ciphertext);
    wire.extend_from_slice(&payload_ciphertext);
    (fixed_ciphertext, wire)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let (request_a_fixed, request_a_variable, request_a_wire) = request(&[0xa1, 0xb2, 0xc3], b"");
    let (request_b_fixed, request_b_variable, request_b_wire) = request(&[], b"ping");
    let (response_fixed, response_wire) = response();

    println!("{{");
    println!(
        "  \"classification\": \"unofficial repository-owned SIP022 composite fixture; not an official SIP022 KAT\","
    );
    println!("  \"method\": \"2022-blake3-aes-128-gcm\",");
    println!("  \"psk\": \"{}\",", hex(&PSK));
    println!("  \"request_salt\": \"{}\",", hex(&REQUEST_SALT));
    println!("  \"response_salt\": \"{}\",", hex(&RESPONSE_SALT));
    println!("  \"timestamp\": {TIMESTAMP},");
    println!("  \"target_ipv4\": \"127.0.0.1\",");
    println!("  \"target_port\": 8080,");
    println!("  \"request_subkey\": \"{}\",", hex(&subkey(&REQUEST_SALT)));
    println!(
        "  \"response_subkey\": \"{}\",",
        hex(&subkey(&RESPONSE_SALT))
    );
    println!("  \"request_a\": {{");
    println!("    \"padding\": \"a1b2c3\",");
    println!("    \"initial_payload\": \"\",");
    println!(
        "    \"fixed_ciphertext_and_tag\": \"{}\",",
        hex(&request_a_fixed)
    );
    println!(
        "    \"variable_ciphertext_and_tag\": \"{}\",",
        hex(&request_a_variable)
    );
    println!("    \"first_write\": \"{}\"", hex(&request_a_wire));
    println!("  }},");
    println!("  \"request_b\": {{");
    println!("    \"padding\": \"\",");
    println!("    \"initial_payload\": \"70696e67\",");
    println!(
        "    \"fixed_ciphertext_and_tag\": \"{}\",",
        hex(&request_b_fixed)
    );
    println!(
        "    \"variable_ciphertext_and_tag\": \"{}\",",
        hex(&request_b_variable)
    );
    println!("    \"first_write\": \"{}\"", hex(&request_b_wire));
    println!("  }},");
    println!("  \"response\": {{");
    println!("    \"first_payload\": \"706f6e67\",");
    println!(
        "    \"fixed_ciphertext_and_tag\": \"{}\",",
        hex(&response_fixed)
    );
    println!("    \"first_write\": \"{}\"", hex(&response_wire));
    println!("  }}");
    println!("}}");
}
