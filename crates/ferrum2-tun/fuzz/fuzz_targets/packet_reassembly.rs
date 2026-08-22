#![no_main]

#[cfg(target_os = "windows")]
compile_error!(
    "packet_reassembly libFuzzer execution is Linux-CI-only; run the deterministic fuzz crate tests or smoke binary on Windows"
);

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    ferrum2_tun_fuzz::fuzz_packet_reassembly(data);
});
