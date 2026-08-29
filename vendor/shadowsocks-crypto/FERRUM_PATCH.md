# Ferrum patch provenance

- Package: `shadowsocks-crypto 0.7.0`
- crates.io archive SHA-256: `9339588f8aee0810546fd7e4dcc219fc4bda2cfd0066dd277b7104d5113fd0c0`
- Packaged VCS commit: `2affa6c39b30f7626137a1792c533610cf133ade`
- Upstream license: MIT (`LICENSE` is unchanged)

The committed tree is the exact crates.io archive with this bounded delta:

- `Cargo.toml{,.orig}` and `Cargo.lock`: isolate and lock the selected `v2` graph
  on Ferrum's reviewed RustCrypto versions, enable zeroization anchors, and remove
  `rand` from that graph.
- `src/lib.rs` and `src/utils.rs`: compile the random helper only for v1 and remove
  its unsafe all-zero check.
- `src/v2/**`: add checked explicit-nonce TCP/UDP operations, a checked no-KDF owner
  for exact-width pre-derived TCP subkeys, AES-UDP header protection, zeroized KDF
  temporaries, and compile-time `ZeroizeOnDrop` bounds.

## Diagnostic-only TCP ring rekey adapter

The optional `v2-ring-rekey-diagnostic` feature is a non-production performance
experiment selected explicitly through the Ferrum client/server composition-root
feature `__ring-rekey-diagnostic`. The default build remains the reviewed
RustCrypto implementation.

For AEAD2022 AES-128/256-GCM TCP bodies only, the diagnostic persistently owns an
inline `Zeroizing` raw directional subkey and constructs ring 0.17.14
`UnboundKey`/`LessSafeKey` state inside each synchronous encrypt/decrypt call.
Compile-time exact-size assertions constrain that adapter's complete persistent
state to the 16- or 32-byte raw subkey; it has no boxed, TLS, global, or cached
expanded-key owner. ChaCha and every UDP primitive remain unchanged.

This does not restore the production expanded-key-erasure contract. ring does not
prove that its transient expanded key is cleared when the synchronous call
returns, so the diagnostic `TcpCipher` and downstream TCP subkey owner
intentionally do not claim `ZeroizeOnDrop`. The exported build identity and
contract constants state that the raw persistent owner is zeroized, persistent
expanded-key bytes are zero, and transient expanded-key erasure is unproven.
This feature must not be shipped or merged as the production backend.

The patch adds no framing, replay, timestamp, binding, session, routing, config, or
runtime behavior. To audit it, verify the archive hash, extract it, and run
`git diff --no-index <extracted>/shadowsocks-crypto-0.7.0 vendor/shadowsocks-crypto`.
