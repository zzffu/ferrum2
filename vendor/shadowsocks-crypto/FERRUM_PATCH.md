# Ferrum patch provenance

- Package: `shadowsocks-crypto 0.7.0`
- crates.io archive SHA-256: `9339588f8aee0810546fd7e4dcc219fc4bda2cfd0066dd277b7104d5113fd0c0`
- Packaged VCS commit: `2affa6c39b30f7626137a1792c533610cf133ade`
- Upstream license: MIT (`LICENSE` is unchanged)

The committed tree is the exact crates.io archive with this bounded delta:

- `Cargo.toml{,.orig}`: isolate the selected `v2` graph on Ferrum's reviewed
  RustCrypto versions, enable zeroization anchors, and remove `rand` from that graph.
- `src/lib.rs` and `src/utils.rs`: compile the random helper only for v1 and remove
  its unsafe all-zero check.
- `src/v2/**`: add checked explicit-nonce TCP/UDP operations, a checked no-KDF owner
  for exact-width pre-derived TCP subkeys, AES-UDP header protection, zeroized KDF
  temporaries, and compile-time `ZeroizeOnDrop` bounds.

## Diagnostic-only exclusion

The optional `v2-ring-nonzeroizing-diagnostic` feature is a deliberately
non-production performance upper-bound experiment. It replaces only the AEAD2022
AES-128/256-GCM body wrappers with direct ring 0.17.14 detached operations. ring's
expanded AES keys implement neither `Drop` nor `ZeroizeOnDrop`, so the AES wrappers
and every vendored TCP/UDP owner that can contain them intentionally do not claim
`ZeroizeOnDrop` in this build. The RustCrypto UDP header cipher is unchanged.

`V2_AES_GCM_BUILD_SECURITY_IDENTITY` identifies the selected backend, and
`V2_AES_GCM_EXPANDED_KEYS_ZEROIZE_ON_DROP` is `false` for this diagnostic. A build
with that identity does **not** satisfy Ferrum's expanded-key zeroization contract
described above and must not be shipped or merged as the production backend. With
the feature disabled, the reviewed RustCrypto implementation and its compile-time
zeroization bounds remain unchanged.

The patch adds no framing, replay, timestamp, binding, session, routing, config, or
runtime behavior. To audit it, verify the archive hash, extract it, and run
`git diff --no-index <extracted>/shadowsocks-crypto-0.7.0 vendor/shadowsocks-crypto`.
