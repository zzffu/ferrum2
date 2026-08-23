#![no_main]

#[cfg(target_os = "windows")]
compile_error!(
    "config_legacy_fields libFuzzer execution is Linux-only; use the deterministic smoke binary on Windows"
);

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    ferrum2_tun_fuzz::fuzz_config_legacy_fields(data);
});
