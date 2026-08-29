use shadowsocks_crypto::v2::{
    V2_AES_GCM_BUILD_SECURITY_IDENTITY, V2_AES_GCM_EXPANDED_KEYS_ZEROIZE_ON_DROP,
};

#[test]
fn workspace_ring_candidate_is_explicitly_nonzeroizing_and_diagnostic_only() {
    assert_eq!(
        std::hint::black_box(V2_AES_GCM_BUILD_SECURITY_IDENTITY),
        "diagnostic-only:ring-0.17.14:expanded-keys-not-zeroized-on-drop"
    );
    assert!(!std::hint::black_box(
        V2_AES_GCM_EXPANDED_KEYS_ZEROIZE_ON_DROP
    ));
}
