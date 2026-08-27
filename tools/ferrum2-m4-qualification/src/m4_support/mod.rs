mod tcp_scale;
mod windows_tun;

use std::ffi::OsString;
use std::time::Duration;

const PROFILE: &str = "M4-GHA-01";
const THP_MAX_PTES_NONE_PATH: &str = "/sys/kernel/mm/transparent_hugepage/khugepaged/max_ptes_none";
const PSK: &str = "AAECAwQFBgcICQoLDA0ODw==";
const REFERENCE_VERSION: &str = "shadowsocks 1.24.0";
const REFERENCE_SHA256: &str = "5f528efb4e51e732352f5c69538dcc76e8cf8f6d1a240dfb5b748a67f0b05f65";
const STREAMS: usize = 8;
const PAYLOAD_BYTES: usize = 64 * 1024;
const WARMUP: Duration = Duration::from_secs(10);
const MEASURE: Duration = Duration::from_secs(30);
const TRIALS: [profile_contract::Topology; 10] = [
    profile_contract::Topology::Ferrum,
    profile_contract::Topology::Reference,
    profile_contract::Topology::Reference,
    profile_contract::Topology::Ferrum,
    profile_contract::Topology::Ferrum,
    profile_contract::Topology::Reference,
    profile_contract::Topology::Reference,
    profile_contract::Topology::Ferrum,
    profile_contract::Topology::Ferrum,
    profile_contract::Topology::Reference,
];
const RESOURCE_SESSIONS: usize = 10_000;
const SETUP_WORKERS: usize = 256;
const STABILIZATION_SAMPLES: usize = 30;
const RESOURCE_SAMPLES: usize = 180;
const SAMPLE_INTERVAL: Duration = Duration::from_secs(10);
const RSS_WINDOW: usize = 30;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(120);
pub fn run(arguments: impl Iterator<Item = OsString>) -> Result<String, String> {
    let mut arguments = arguments;
    let mode = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| {
            concat!(
                "expected mode: throughput, resource, dns-resource, profile-workload, ",
                "windows-tun-workload, windows-tun-probe, windows-tun-support, ",
                "windows-tun-udp-diagnostic-finalize, or self-check"
            )
            .to_owned()
        })?;
    let rest: Vec<_> = arguments.collect();
    match mode.as_str() {
        "throughput" => {
            throughput::run_throughput(profile_contract::parse_hosted_args(&rest, true)?)
        }
        "resource" => resource::run_resource(profile_contract::parse_hosted_args(&rest, false)?),
        "dns-resource" => {
            dns_resource::run_dns_resource(profile_contract::parse_hosted_args(&rest, false)?)
        }
        "profile-workload" => {
            profile_output::run_profile_workload(profile_contract::parse_profile_args(&rest)?)
        }
        "windows-tun-workload" => windows_tun::run_workload(&rest),
        "windows-tun-probe" => windows_tun::run_probe(&rest),
        "windows-tun-support" => windows_tun::run_support(&rest),
        "windows-tun-udp-diagnostic-finalize" => windows_tun::run_udp_diagnostic_finalize(&rest),
        "self-check" if rest.is_empty() => self_check::run_self_check(),
        "self-check" => Err("self-check accepts no arguments".to_owned()),
        _ => Err(concat!(
            "expected mode: throughput, resource, dns-resource, profile-workload, ",
            "windows-tun-workload, windows-tun-probe, windows-tun-support, ",
            "windows-tun-udp-diagnostic-finalize, or self-check"
        )
        .to_owned()),
    }
}

mod dns_resource;
mod evidence_support;
mod host_identity;
mod process_support;
mod profile_contract;
mod profile_output;
mod profile_tcp;
mod profile_udp;
mod proxy_config;
mod resource;
mod resource_sampling;
mod self_check;
mod throughput;
