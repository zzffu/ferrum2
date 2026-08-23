#![forbid(unsafe_code)]

use ferrum2_tun_fuzz::{
    MAX_FUZZ_INPUT_BYTES, MAX_UDP_RESET_FUZZ_INPUT_BYTES, fuzz_packet_reassembly,
    fuzz_udp_reset_races,
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

    println!(
        "TUN state smoke corpora: {} packet and {} UDP reset seeds passed",
        corpus.len(),
        udp_reset_corpus.len()
    );
}
