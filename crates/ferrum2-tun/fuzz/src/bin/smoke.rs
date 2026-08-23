#![forbid(unsafe_code)]

use ferrum2_tun_fuzz::{
    MAX_CONFIG_LEGACY_FUZZ_INPUT_BYTES, MAX_FUZZ_INPUT_BYTES, MAX_STRICT_ROUTE_FUZZ_INPUT_BYTES,
    MAX_UDP_RESET_FUZZ_INPUT_BYTES, fuzz_config_legacy_fields, fuzz_packet_reassembly,
    fuzz_strict_route_rule_builder, fuzz_udp_reset_races,
};

fn main() {
    let corpus: &[(&str, &[u8])] = &[
        (
            "ipv4-fragments",
            include_bytes!("../../corpus/packet_reassembly/ipv4-fragments.hex"),
        ),
        (
            "ipv6-fragments",
            include_bytes!("../../corpus/packet_reassembly/ipv6-fragments.hex"),
        ),
        (
            "malformed",
            include_bytes!("../../corpus/packet_reassembly/malformed.hex"),
        ),
        (
            "generation-expiry",
            include_bytes!("../../corpus/packet_reassembly/generation-expiry.hex"),
        ),
    ];

    for (name, input) in corpus {
        assert!(
            input.len() <= MAX_FUZZ_INPUT_BYTES,
            "oversized seed: {name}"
        );
        fuzz_packet_reassembly(input);
    }
    for input in [&[][..], &[0][..], &[0xff, 0, 1, 0][..]] {
        fuzz_packet_reassembly(input);
    }
    fuzz_packet_reassembly(&vec![0; MAX_FUZZ_INPUT_BYTES + 1]);

    let udp_reset_corpus: &[(&str, &[u8])] = &[
        (
            "reset-before-commit",
            include_bytes!("../../corpus/udp_reset_races/reset-before-commit.seed"),
        ),
        (
            "response-after-reset",
            include_bytes!("../../corpus/udp_reset_races/response-after-reset.seed"),
        ),
        (
            "source-reuse",
            include_bytes!("../../corpus/udp_reset_races/source-reuse.seed"),
        ),
    ];
    for (name, input) in udp_reset_corpus {
        assert!(
            input.len() <= MAX_UDP_RESET_FUZZ_INPUT_BYTES,
            "oversized UDP reset seed: {name}"
        );
        fuzz_udp_reset_races(input);
    }
    for input in [&[][..], &[0][..], &[0xff, 0, 1, 0][..]] {
        fuzz_udp_reset_races(input);
    }
    fuzz_udp_reset_races(&vec![0; MAX_UDP_RESET_FUZZ_INPUT_BYTES + 1]);

    let config_legacy_corpus: &[(&str, &[u8])] = &[
        (
            "client-route-target",
            include_bytes!("../../corpus/config_legacy_fields/client-route-target.seed"),
        ),
        (
            "server-route-target",
            include_bytes!("../../corpus/config_legacy_fields/server-route-target.seed"),
        ),
        (
            "client-dns-target",
            include_bytes!("../../corpus/config_legacy_fields/client-dns-target.seed"),
        ),
        (
            "server-dns-target",
            include_bytes!("../../corpus/config_legacy_fields/server-dns-target.seed"),
        ),
        (
            "tun-memory-field",
            include_bytes!("../../corpus/config_legacy_fields/tun-memory-field.seed"),
        ),
        (
            "schema-v1",
            include_bytes!("../../corpus/config_legacy_fields/schema-v1.seed"),
        ),
        (
            "missing-schema",
            include_bytes!("../../corpus/config_legacy_fields/missing-schema.seed"),
        ),
        (
            "future-schema",
            include_bytes!("../../corpus/config_legacy_fields/future-schema.seed"),
        ),
    ];
    for (name, input) in config_legacy_corpus {
        assert!(
            input.len() <= MAX_CONFIG_LEGACY_FUZZ_INPUT_BYTES,
            "oversized config legacy seed: {name}"
        );
        fuzz_config_legacy_fields(input);
    }
    fuzz_config_legacy_fields(&vec![0; MAX_CONFIG_LEGACY_FUZZ_INPUT_BYTES + 1]);

    let strict_route_corpus: &[(&str, &[u8])] = &[
        (
            "empty-app-id",
            include_bytes!("../../corpus/strict_route_rules/empty-app-id.seed"),
        ),
        (
            "one-byte-app-id",
            include_bytes!("../../corpus/strict_route_rules/one-byte-app-id.seed"),
        ),
        (
            "max-minus-one-app-id",
            include_bytes!("../../corpus/strict_route_rules/max-minus-one-app-id.seed"),
        ),
        (
            "max-app-id",
            include_bytes!("../../corpus/strict_route_rules/max-app-id.seed"),
        ),
        (
            "max-plus-one-app-id",
            include_bytes!("../../corpus/strict_route_rules/max-plus-one-app-id.seed"),
        ),
        (
            "no-family",
            include_bytes!("../../corpus/strict_route_rules/no-family.seed"),
        ),
        (
            "zero-luid",
            include_bytes!("../../corpus/strict_route_rules/zero-luid.seed"),
        ),
        (
            "managed-dns",
            include_bytes!("../../corpus/strict_route_rules/managed-dns.seed"),
        ),
    ];
    for (name, input) in strict_route_corpus {
        assert!(
            input.len() <= MAX_STRICT_ROUTE_FUZZ_INPUT_BYTES,
            "oversized strict-route seed: {name}"
        );
        fuzz_strict_route_rule_builder(input);
    }
    fuzz_strict_route_rule_builder(&vec![0; MAX_STRICT_ROUTE_FUZZ_INPUT_BYTES + 1]);

    println!(
        "TUN state smoke corpora: {} packet, {} UDP reset, {} config legacy, and {} strict-route seeds passed",
        corpus.len(),
        udp_reset_corpus.len(),
        config_legacy_corpus.len(),
        strict_route_corpus.len()
    );
}
