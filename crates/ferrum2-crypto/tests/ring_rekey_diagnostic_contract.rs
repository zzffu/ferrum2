#![cfg(feature = "__ring-rekey-diagnostic")]

use shadowsocks_crypto::v2::tcp::{
    TcpCipher, V2_RING_REKEY_PERSISTENT_EXPANDED_KEY_BYTES,
    V2_RING_REKEY_RAW_SUBKEY_ZEROIZE_ON_DROP,
    V2_RING_REKEY_TRANSIENT_EXPANDED_KEYS_ZEROIZE_ON_DROP, V2_TCP_AES_GCM_BUILD_SECURITY_IDENTITY,
    V2_TCP_CIPHER_ZEROIZE_ON_DROP_CONTRACT,
};

#[test]
fn ring_rekey_build_has_only_a_zeroized_raw_persistent_key_owner() {
    assert_eq!(
        std::hint::black_box(V2_TCP_AES_GCM_BUILD_SECURITY_IDENTITY),
        "diagnostic-only:ring-0.17.14:per-operation-rekey:raw-subkey-zeroized:transient-expanded-key-not-proven-zeroized"
    );
    assert!(std::hint::black_box(
        V2_RING_REKEY_RAW_SUBKEY_ZEROIZE_ON_DROP
    ));
    assert_eq!(
        std::hint::black_box(V2_RING_REKEY_PERSISTENT_EXPANDED_KEY_BYTES),
        0
    );
    assert!(!std::hint::black_box(
        V2_RING_REKEY_TRANSIENT_EXPANDED_KEYS_ZEROIZE_ON_DROP
    ));
    assert!(!std::hint::black_box(
        V2_TCP_CIPHER_ZEROIZE_ON_DROP_CONTRACT
    ));

    // The largest persistent variant is the inline 32-byte raw subkey plus an
    // enum discriminant/alignment; no expanded-key allocation is retained.
    assert!(core::mem::size_of::<TcpCipher>() <= 40);
}
