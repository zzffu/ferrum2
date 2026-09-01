// Independent M1/M2 primitive fixture generator. This source intentionally imports no
// ferrum2 crate or reference implementation.
use aes::cipher::{Array, BlockCipherEncrypt};
use aes::{Aes128, Aes256};
use aes_gcm::{AeadInOut, Aes256Gcm, KeyInit, Nonce};
use bytes::BytesMut;
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305, XNonce};

#[derive(Clone, Copy)]
enum Cipher {
    Aes256,
    ChaCha20Poly1305,
}

fn main() {
    print_tcp_profile_rows();
    print_udp_profile_rows();
    print_xchacha_draft_row();
}

fn print_tcp_profile_rows() {
    let rows = [
        (
            "2022-blake3-aes-256-gcm",
            Cipher::Aes256,
            (0_u8..32).collect::<Vec<_>>(),
            (0x20_u8..0x40).collect::<Vec<_>>(),
        ),
        (
            "2022-blake3-chacha20-poly1305",
            Cipher::ChaCha20Poly1305,
            (0xa0_u8..0xc0).collect::<Vec<_>>(),
            (0xc0_u8..0xe0).collect::<Vec<_>>(),
        ),
    ];

    for (method, cipher, psk, salt) in rows {
        let mut material = psk;
        material.extend_from_slice(&salt);
        let subkey = blake3::derive_key("shadowsocks 2022 session subkey", &material);
        println!("{method} full_derive_output={}", hex::encode(subkey));

        for nonce_value in [0_u8, 1] {
            let mut nonce = [0_u8; 12];
            nonce[0] = nonce_value;
            let mut output = BytesMut::with_capacity(22);
            output.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
            match cipher {
                Cipher::Aes256 => Aes256Gcm::new_from_slice(&subkey)
                    .expect("AES-256 key")
                    .encrypt_in_place(&Nonce::from(nonce), &[], &mut output)
                    .expect("AES-256 fixture"),
                Cipher::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(&subkey)
                    .expect("ChaCha20 key")
                    .encrypt_in_place(&Nonce::from(nonce), &[], &mut output)
                    .expect("ChaCha20 fixture"),
            }
            println!(
                "{method} nonce_{nonce_value}_ciphertext_and_tag={}",
                hex::encode(output)
            );
        }
    }
}

fn print_udp_profile_rows() {
    let body = [0, 1, 2, 3, 4, 5];
    for (method, psk, session_id, packet_id) in [
        (
            "2022-blake3-aes-128-gcm",
            (0_u8..16).collect::<Vec<_>>(),
            (0x60_u8..0x68).collect::<Vec<_>>(),
            0_u64,
        ),
        (
            "2022-blake3-aes-256-gcm",
            (0x20_u8..0x40).collect::<Vec<_>>(),
            (0x70_u8..0x78).collect::<Vec<_>>(),
            1_u64,
        ),
    ] {
        let mut identity = session_id.clone();
        identity.extend_from_slice(&packet_id.to_be_bytes());
        let encrypted_header = match psk.len() {
            16 => {
                let cipher = Aes128::new_from_slice(&psk).expect("AES-128 key");
                let mut block = Array::try_from(identity.as_slice()).expect("header block");
                cipher.encrypt_block(&mut block);
                block.to_vec()
            }
            32 => {
                let cipher = Aes256::new_from_slice(&psk).expect("AES-256 key");
                let mut block = Array::try_from(identity.as_slice()).expect("header block");
                cipher.encrypt_block(&mut block);
                block.to_vec()
            }
            _ => unreachable!("fixed AES profile"),
        };

        let mut material = psk.clone();
        material.extend_from_slice(&session_id);
        let subkey = blake3::derive_key("shadowsocks 2022 session subkey", &material);
        let nonce: [u8; 12] = identity[4..16].try_into().expect("nonce slice");
        let mut encrypted_body = BytesMut::with_capacity(body.len() + 16);
        encrypted_body.extend_from_slice(&body);
        match psk.len() {
            16 => aes_gcm::Aes128Gcm::new_from_slice(&subkey[..16])
                .expect("AES-128 body key")
                .encrypt_in_place(&Nonce::from(nonce), &[], &mut encrypted_body)
                .expect("AES-128 UDP body"),
            32 => Aes256Gcm::new_from_slice(&subkey)
                .expect("AES-256 body key")
                .encrypt_in_place(&Nonce::from(nonce), &[], &mut encrypted_body)
                .expect("AES-256 UDP body"),
            _ => unreachable!("fixed AES profile"),
        }
        println!(
            "{method} udp_plaintext_header={} udp_encrypted_header={} udp_full_derive_output={} udp_selected_subkey={} udp_body_nonce={} udp_body_ciphertext_and_tag={}",
            hex::encode(identity),
            hex::encode(encrypted_header),
            hex::encode(subkey),
            hex::encode(&subkey[..psk.len()]),
            hex::encode(nonce),
            hex::encode(encrypted_body),
        );
    }

    let psk = (0x40_u8..0x60).collect::<Vec<_>>();
    let nonce: [u8; 24] = (0x90_u8..0xa8)
        .collect::<Vec<_>>()
        .try_into()
        .expect("XChaCha nonce");
    let mut plaintext = (0x80_u8..0x88).collect::<Vec<_>>();
    plaintext.extend_from_slice(&2_u64.to_be_bytes());
    plaintext.extend_from_slice(&body);
    let mut encrypted = BytesMut::with_capacity(plaintext.len() + 16);
    encrypted.extend_from_slice(&plaintext);
    XChaCha20Poly1305::new_from_slice(&psk)
        .expect("XChaCha key")
        .encrypt_in_place(&XNonce::from(nonce), &[], &mut encrypted)
        .expect("XChaCha UDP body");
    let mut wire = nonce.to_vec();
    wire.extend_from_slice(&encrypted);
    println!(
        "2022-blake3-chacha20-poly1305 udp_plaintext_identity_and_body={} udp_nonce={} udp_ciphertext_and_tag={} udp_wire={}",
        hex::encode(plaintext),
        hex::encode(nonce),
        hex::encode(encrypted),
        hex::encode(wire),
    );
}

fn print_xchacha_draft_row() {
    let key = hex::decode(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    )
    .expect("draft key");
    let nonce: [u8; 24] =
        hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657")
            .expect("draft nonce")
            .try_into()
            .expect("24-byte nonce");
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").expect("draft AAD");
    let mut plaintext = BytesMut::from(
        hex::decode(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
        )
        .expect("draft plaintext")
        .as_slice(),
    );
    XChaCha20Poly1305::new_from_slice(&key)
        .expect("draft key width")
        .encrypt_in_place(&XNonce::from(nonce), &aad, &mut plaintext)
        .expect("draft vector");
    println!("draft02_a_3_1={}", hex::encode(plaintext));
}
