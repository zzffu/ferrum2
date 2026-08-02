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
- `src/v2/**`: add checked explicit-nonce TCP/UDP operations, AES-UDP header
  protection, zeroized KDF temporaries, and compile-time `ZeroizeOnDrop` bounds.

The patch adds no framing, replay, timestamp, binding, session, routing, config, or
runtime behavior. To audit it, verify the archive hash, extract it, and run
`git diff --no-index <extracted>/shadowsocks-crypto-0.7.0 vendor/shadowsocks-crypto`.
