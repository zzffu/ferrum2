#[path = "../src/external_support/mod.rs"]
mod external_support;

use external_support::{Direction, Reference, run_case};

#[test]
#[ignore = "required external binary; run explicitly in m0-interop-sing-box"]
fn client_sing_box() {
    run_case(Reference::SingBox, Direction::FerrumClient);
}

#[test]
#[ignore = "required external binary; run explicitly in m0-interop-shadowsocks-rust"]
fn client_shadowsocks_rust() {
    run_case(Reference::ShadowsocksRust, Direction::FerrumClient);
}

#[test]
#[ignore = "required external binary; run explicitly in m0-interop-sing-box"]
fn sing_box_client() {
    run_case(Reference::SingBox, Direction::ReferenceClient);
}

#[test]
#[ignore = "required external binary; run explicitly in m0-interop-shadowsocks-rust"]
fn shadowsocks_rust_client() {
    run_case(Reference::ShadowsocksRust, Direction::ReferenceClient);
}
