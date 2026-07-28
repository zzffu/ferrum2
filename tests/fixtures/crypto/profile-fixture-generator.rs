// Independent M1 fixture generator. This source intentionally imports no
// ferrum2 crate or reference implementation.
use aes_gcm::{AeadInOut, Aes256Gcm, KeyInit, Nonce};
use bytes::BytesMut;
use chacha20poly1305::ChaCha20Poly1305;

#[derive(Clone, Copy)]
enum Cipher {
    Aes256,
    ChaCha20Poly1305,
}

fn main() {
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
