#![forbid(unsafe_code)]

mod config_legacy;
mod strict_route;

pub use config_legacy::{MAX_CONFIG_LEGACY_FUZZ_INPUT_BYTES, fuzz_config_legacy_fields};
pub use ferrum2_tun::{
    MAX_FUZZ_INPUT_BYTES, MAX_UDP_RESET_FUZZ_INPUT_BYTES, fuzz_packet_reassembly,
    fuzz_udp_reset_races,
};
pub use strict_route::{MAX_STRICT_ROUTE_FUZZ_INPUT_BYTES, fuzz_strict_route_rule_builder};
