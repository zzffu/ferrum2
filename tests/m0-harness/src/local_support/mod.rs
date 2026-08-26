#![allow(dead_code)]

use std::collections::HashSet;
use std::sync::atomic::AtomicUsize;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

pub const SYNTHETIC_PSK: &str = "AAECAwQFBgcICQoLDA0ODw==";
#[rustfmt::skip]
pub const TCP_METHOD_CONFIGS: [(&str, &str); 3] = [
    ("2022-blake3-aes-128-gcm", SYNTHETIC_PSK),
    ("2022-blake3-aes-256-gcm", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="),
    ("2022-blake3-chacha20-poly1305", "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="),
];
const CHILD_OUTPUT_CAP: usize = 256 * 1024;
const METRICS_HEADER_CAP: usize = 4 * 1024;
const METRICS_RESPONSE_CAP: usize = 256 * 1024;
const READINESS_TIMEOUT: Duration = Duration::from_secs(5);
const READINESS_IO_CAP: Duration = Duration::from_millis(200);
const READINESS_POLL: Duration = Duration::from_millis(20);
const READINESS_CONFIRMATIONS: usize = 3;
const PROCESS_POLL: Duration = Duration::from_millis(10);
const PROCESS_RUN_TIMEOUT: Duration = Duration::from_secs(30);
const FORCED_REAP_TIMEOUT: Duration = Duration::from_secs(2);
const SIGNAL_DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);
static ACTIVE_CHILDREN: AtomicUsize = AtomicUsize::new(0);
static ISSUED_PORTS: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
// A concurrent fork inherits CLOEXEC sockets until exec; exact rebind probes hold this lock.
static PROCESS_SPAWN_LOCK: Mutex<()> = Mutex::new(());

mod config;
mod dns;
mod loopback;
#[cfg(not(test))]
mod process;
#[cfg(test)]
pub(crate) mod process;
mod readiness;

#[allow(unused_imports)]
pub use config::{
    ChainRoot, force_outbound_policy_denial, rewrite_config_method, route_tagged_config,
    write_client_config, write_client_config_with_psk, write_server_config,
    write_server_config_with_psk, write_tagged_client_config, write_tagged_dns_server_config,
    write_tagged_dns_server_matrix_config, write_tagged_server_config,
    write_tcp_only_server_config, write_tcp_only_server_config_with_psk,
    write_two_hop_client_config, write_udp_client_config,
};
#[allow(unused_imports)]
pub use dns::{DnsAnswerServer, DnsReply, DnsStep, start_dns_answer, start_dns_script};
#[allow(unused_imports)]
pub use loopback::{
    LoopbackReservation, bind_loopback_listener, reserve_loopback, reserve_unused_loopback,
    unused_loopback, unused_tcp_udp_loopback,
};
#[allow(unused_imports)]
pub use process::{
    ChildExit, ChildGuard, MetricsReadinessFailure, binary_path, hold_process_spawns,
    hold_process_spawns_at_or_below, run_binary, run_binary_while_holding,
};
#[allow(unused_imports)]
pub(crate) use readiness::metric_value;
#[allow(unused_imports)]
pub use readiness::{
    active_child_count, wait_for_bound, wait_for_listener, wait_for_metrics,
    wait_for_metrics_ready, wait_for_metrics_sample, wait_for_tcp_udp_bound,
};

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
