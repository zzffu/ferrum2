//! Independent generator for repository-owned unofficial SIP022 UDP fixtures.
//!
//! This source imports only pinned primitive crates and does not link any
//! ferrum2 production module or interoperability reference.

use aes::cipher::{Array, BlockCipherEncrypt, KeyInit as BlockKeyInit};
use aes::{Aes128, Aes256};
use aes_gcm::{AeadInOut, Aes128Gcm, Aes256Gcm, Nonce};
use blake3::derive_key;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

const CONTEXT: &str = "shadowsocks 2022 session subkey";
const TIMESTAMP: u64 = 1_700_000_000;

fn request_body(timestamp: u64, padding: &[u8], target: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut body = vec![0];
    body.extend_from_slice(&timestamp.to_be_bytes());
    body.extend_from_slice(&(padding.len() as u16).to_be_bytes());
    body.extend_from_slice(padding);
    body.extend_from_slice(target);
    body.extend_from_slice(payload);
    body
}

fn response_body(
    timestamp: u64,
    client_session_id: &[u8; 8],
    padding: &[u8],
    target: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut body = vec![1];
    body.extend_from_slice(&timestamp.to_be_bytes());
    body.extend_from_slice(client_session_id);
    body.extend_from_slice(&(padding.len() as u16).to_be_bytes());
    body.extend_from_slice(padding);
    body.extend_from_slice(target);
    body.extend_from_slice(payload);
    body
}

fn identity(session_id: &[u8; 8], packet_id: u64) -> [u8; 16] {
    let mut identity = [0_u8; 16];
    identity[..8].copy_from_slice(session_id);
    identity[8..].copy_from_slice(&packet_id.to_be_bytes());
    identity
}

fn aes128_packet(
    psk: &[u8; 16],
    session_id: &[u8; 8],
    packet_id: u64,
    body: &[u8],
) -> Vec<u8> {
    let identity = identity(session_id, packet_id);
    let mut protected = Array::from(identity);
    Aes128::new_from_slice(psk)
        .expect("AES-128 key")
        .encrypt_block(&mut protected);
    let mut material = [0_u8; 24];
    material[..16].copy_from_slice(psk);
    material[16..].copy_from_slice(session_id);
    let derived = derive_key(CONTEXT, &material);
    let cipher = Aes128Gcm::new_from_slice(&derived[..16]).expect("AES-128 subkey");
    let mut encrypted_body = body.to_vec();
    let nonce: [u8; 12] = identity[4..].try_into().expect("nonce slice");
    let tag = cipher
        .encrypt_inout_detached(
            &Nonce::from(nonce),
            &[],
            encrypted_body.as_mut_slice().into(),
        )
        .expect("AES-128 body");
    let mut wire = protected.to_vec();
    wire.extend_from_slice(&encrypted_body);
    wire.extend_from_slice(&tag);
    wire
}

fn aes256_packet(
    psk: &[u8; 32],
    session_id: &[u8; 8],
    packet_id: u64,
    body: &[u8],
) -> Vec<u8> {
    let identity = identity(session_id, packet_id);
    let mut protected = Array::from(identity);
    Aes256::new_from_slice(psk)
        .expect("AES-256 key")
        .encrypt_block(&mut protected);
    let mut material = [0_u8; 40];
    material[..32].copy_from_slice(psk);
    material[32..].copy_from_slice(session_id);
    let derived = derive_key(CONTEXT, &material);
    let cipher = Aes256Gcm::new_from_slice(&derived).expect("AES-256 subkey");
    let mut encrypted_body = body.to_vec();
    let nonce: [u8; 12] = identity[4..].try_into().expect("nonce slice");
    let tag = cipher
        .encrypt_inout_detached(
            &Nonce::from(nonce),
            &[],
            encrypted_body.as_mut_slice().into(),
        )
        .expect("AES-256 body");
    let mut wire = protected.to_vec();
    wire.extend_from_slice(&encrypted_body);
    wire.extend_from_slice(&tag);
    wire
}

fn chacha_packet(
    psk: &[u8; 32],
    nonce: &[u8; 24],
    session_id: &[u8; 8],
    packet_id: u64,
    body: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new_from_slice(psk).expect("XChaCha key");
    let mut encrypted = identity(session_id, packet_id).to_vec();
    encrypted.extend_from_slice(body);
    let tag = cipher
        .encrypt_inout_detached(
            &XNonce::from(*nonce),
            &[],
            encrypted.as_mut_slice().into(),
        )
        .expect("XChaCha body");
    let mut wire = nonce.to_vec();
    wire.extend_from_slice(&encrypted);
    wire.extend_from_slice(&tag);
    wire
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[allow(clippy::too_many_arguments)]
fn print_case(
    method: &str,
    psk: &[u8],
    client_session_id: &[u8; 8],
    server_session_id: &[u8; 8],
    packet_id: u64,
    request_nonce: Option<&[u8; 24]>,
    response_nonce: Option<&[u8; 24]>,
    target_kind: &str,
    target: &[u8],
    padding: &[u8],
    request_payload: &[u8],
    response_payload: &[u8],
    request_body: &[u8],
    response_body: &[u8],
    request_wire: &[u8],
    response_wire: &[u8],
    comma: bool,
) {
    println!("    {{");
    println!("      \"method\": \"{method}\",");
    println!("      \"psk\": \"{}\",", hex(psk));
    println!(
        "      \"client_session_id\": \"{}\",",
        hex(client_session_id)
    );
    println!(
        "      \"server_session_id\": \"{}\",",
        hex(server_session_id)
    );
    println!("      \"packet_id\": {packet_id},");
    if let Some(nonce) = request_nonce {
        println!("      \"request_nonce\": \"{}\",", hex(nonce));
        println!(
            "      \"response_nonce\": \"{}\",",
            hex(response_nonce.expect("paired nonce"))
        );
    }
    println!("      \"timestamp\": {TIMESTAMP},");
    println!("      \"target_kind\": \"{target_kind}\",");
    println!("      \"target\": \"{}\",", hex(target));
    println!("      \"padding\": \"{}\",", hex(padding));
    println!(
        "      \"request_payload\": \"{}\",",
        hex(request_payload)
    );
    println!(
        "      \"response_payload\": \"{}\",",
        hex(response_payload)
    );
    println!("      \"request_body\": \"{}\",", hex(request_body));
    println!("      \"response_body\": \"{}\",", hex(response_body));
    println!("      \"request_wire\": \"{}\",", hex(request_wire));
    println!("      \"response_wire\": \"{}\"", hex(response_wire));
    println!("    }}{}", if comma { "," } else { "" });
}

fn main() {
    let aes128_psk: [u8; 16] = core::array::from_fn(|index| index as u8);
    let aes256_psk: [u8; 32] = core::array::from_fn(|index| index as u8 + 0x20);
    let chacha_psk: [u8; 32] = core::array::from_fn(|index| index as u8 + 0x40);
    let aes128_client: [u8; 8] = core::array::from_fn(|index| index as u8 + 0x60);
    let aes128_server: [u8; 8] = core::array::from_fn(|index| index as u8 + 0x68);
    let aes256_client: [u8; 8] = core::array::from_fn(|index| index as u8 + 0x70);
    let aes256_server: [u8; 8] = core::array::from_fn(|index| index as u8 + 0x78);
    let chacha_client: [u8; 8] = core::array::from_fn(|index| index as u8 + 0x80);
    let chacha_server: [u8; 8] = core::array::from_fn(|index| index as u8 + 0x88);
    let request_nonce: [u8; 24] = core::array::from_fn(|index| index as u8 + 0x90);
    let response_nonce: [u8; 24] = core::array::from_fn(|index| index as u8 + 0xa8);
    let ipv4 = [1, 192, 0, 2, 1, 0, 53];
    let ipv6 = [
        4, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x14, 0xe9,
    ];
    let domain = [
        3, 12, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b't', b'e', b's', b't',
        0x20, 0xfb,
    ];

    let aes128_request_body =
        request_body(TIMESTAMP, &[0xa1, 0xb2], &ipv4, b"m2-aes128-req");
    let aes128_response_body = response_body(
        TIMESTAMP,
        &aes128_client,
        &[0xa1, 0xb2],
        &ipv4,
        b"m2-aes128-rsp",
    );
    let aes256_request_body =
        request_body(TIMESTAMP, &[0xb1, 0xb2, 0xb3], &ipv6, b"m2-aes256-req");
    let aes256_response_body = response_body(
        TIMESTAMP,
        &aes256_client,
        &[0xb1, 0xb2, 0xb3],
        &ipv6,
        b"m2-aes256-rsp",
    );
    let chacha_request_body = request_body(TIMESTAMP, &[0xc1], &domain, b"m2-chacha-req");
    let chacha_response_body = response_body(
        TIMESTAMP,
        &chacha_client,
        &[0xc1],
        &domain,
        b"m2-chacha-rsp",
    );

    let aes128_request_wire =
        aes128_packet(&aes128_psk, &aes128_client, 0, &aes128_request_body);
    let aes128_response_wire =
        aes128_packet(&aes128_psk, &aes128_server, 0, &aes128_response_body);
    let aes256_request_wire =
        aes256_packet(&aes256_psk, &aes256_client, 1, &aes256_request_body);
    let aes256_response_wire =
        aes256_packet(&aes256_psk, &aes256_server, 1, &aes256_response_body);
    let chacha_request_wire = chacha_packet(
        &chacha_psk,
        &request_nonce,
        &chacha_client,
        2,
        &chacha_request_body,
    );
    let chacha_response_wire = chacha_packet(
        &chacha_psk,
        &response_nonce,
        &chacha_server,
        2,
        &chacha_response_body,
    );

    println!("{{");
    println!(
        "  \"classification\": \"unofficial repository-owned SIP022 UDP composite fixture; not an official SIP022 KAT\","
    );
    println!("  \"cases\": [");
    print_case(
        "2022-blake3-aes-128-gcm",
        &aes128_psk,
        &aes128_client,
        &aes128_server,
        0,
        None,
        None,
        "ipv4",
        &ipv4,
        &[0xa1, 0xb2],
        b"m2-aes128-req",
        b"m2-aes128-rsp",
        &aes128_request_body,
        &aes128_response_body,
        &aes128_request_wire,
        &aes128_response_wire,
        true,
    );
    print_case(
        "2022-blake3-aes-256-gcm",
        &aes256_psk,
        &aes256_client,
        &aes256_server,
        1,
        None,
        None,
        "ipv6",
        &ipv6,
        &[0xb1, 0xb2, 0xb3],
        b"m2-aes256-req",
        b"m2-aes256-rsp",
        &aes256_request_body,
        &aes256_response_body,
        &aes256_request_wire,
        &aes256_response_wire,
        true,
    );
    print_case(
        "2022-blake3-chacha20-poly1305",
        &chacha_psk,
        &chacha_client,
        &chacha_server,
        2,
        Some(&request_nonce),
        Some(&response_nonce),
        "domain",
        &domain,
        &[0xc1],
        b"m2-chacha-req",
        b"m2-chacha-rsp",
        &chacha_request_body,
        &chacha_response_body,
        &chacha_request_wire,
        &chacha_response_wire,
        false,
    );
    println!("  ]");
    println!("}}");
}
