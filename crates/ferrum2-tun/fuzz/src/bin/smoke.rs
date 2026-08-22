#![forbid(unsafe_code)]

use ferrum2_tun_fuzz::{MAX_FUZZ_INPUT_BYTES, fuzz_packet_reassembly};

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

    println!(
        "packet_reassembly smoke corpus: {} seeds passed",
        corpus.len()
    );
}
