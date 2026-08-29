use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use ferrum2_core::TargetAddr;
use ferrum2_crypto::MethodProfile;
use ferrum2_shadowsocks::{MAX_UDP_WIRE_LEN, max_udp_payload_len};
use ferrum2_socks5::{MAX_SOCKS_UDP_DATAGRAM_BYTES, encode_udp_datagram};

use super::dns_resource::{
    DNS_DIRECT_NAME, DNS_LOAD_WORKERS, DNS_OWNER_DELTA, DNS_RESOURCE_SAMPLES,
    validate_dns_owner_bound,
};
use super::evidence_support::{DnsLoad, DnsResponder, Evidence};
use super::host_identity::{EnvironmentIdentity, validate_environment};
use super::process_support::{
    ACTIVE_PROCESSES, ACTIVE_WORKERS, PROBE_TIMEOUT, STARTUP_TIMEOUT, StartGate, clean_io,
    is_repository_root, parse_active_metric_response, probe_text, sample_slot_delay, v4,
};
use super::profile_contract::{
    PROFILE_SOCKS_IPV4_HEADER_BYTES, PROFILE_SS_AES_RESPONSE_OVERHEAD_BYTES,
    PROFILE_UDP_DIRECT_MAX_APPLICATION_PAYLOAD_BYTES, PROFILE_UDP_PAYLOAD_BYTES,
    PROFILE_UDP_SS_MAX_APPLICATION_PAYLOAD_BYTES, ProfileArgs, ProfileScenario, ReadyFile,
    parse_profile_args, profile_raw_prefix,
};
use super::profile_output::run_profile_scenario;
use super::profile_structural::StructuralMetrics;
use super::resource::{
    M14_MEASUREMENT_PHASES, M14UdpRoundTripBuffers, m14_tls_client_hello,
    validate_m14_measurement_plan,
};
use super::resource_sampling::{
    PairSample, PreciseRss, ProcessSample, parse_smaps_rollup, validate_dns_samples,
    validate_drain, validate_samples, validate_thp_profile,
};
use super::throughput::{percentile_99, transfer_is_measured};
use super::{MEASURE, PSK, REFERENCE_SHA256, REFERENCE_VERSION, SAMPLE_INTERVAL, STREAMS, WARMUP};
use super::{tcp_scale, windows_tun};

pub(super) fn run_self_check() -> Result<String, String> {
    const MUTATION_COUNT: u64 = 57;
    windows_tun::run_self_check()?;
    // BEGIN M18 STRUCTURAL DIAGNOSTIC (excluded from timed v6 source identity)
    #[cfg(feature = "structural-diagnostic")]
    {
        super::structural_contract::run_self_check()?;
        super::structural_diagnostic::run_self_check()?;
        super::udp_worker::run_self_check()?;
    }
    // END M18 STRUCTURAL DIAGNOSTIC
    let structural: serde_json::Value =
        serde_json::from_str(&StructuralMetrics::dns_listener(32, 8, 0, 0).json())
            .map_err(|_| "structural metrics did not encode as JSON".to_owned())?;
    let closed = structural["closed"]
        .as_object()
        .ok_or_else(|| "structural metrics closure map is absent".to_owned())?;
    for field in [
        "request_count",
        "inflight_peak",
        "drop_count",
        "encode_failure_count",
    ] {
        if structural[field].is_null() || closed.contains_key(field) {
            return Err("observed structural metric remained closed".to_owned());
        }
    }
    let sha = "0123456789abcdef0123456789abcdef01234567";
    let good = EnvironmentIdentity {
        github_actions: "true".to_owned(),
        runner_os: "Linux".to_owned(),
        runner_arch: "X64".to_owned(),
        image_os: "ubuntu24".to_owned(),
        github_sha: sha.to_owned(),
    };
    validate_environment(sha, &good)?;
    let profile_arguments: Vec<OsString> = [
        "--scenario",
        "tcp-bulk",
        "--warmup-seconds",
        "1",
        "--active-seconds",
        "10",
        "--ready-file",
        "profiles/self-check/ready.txt",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let profile = parse_profile_args(&profile_arguments)?;
    if profile.scenario != ProfileScenario::TcpBulk
        || profile.warmup_seconds != 1
        || profile.active_seconds != 10
        || profile.ready_file != Path::new("profiles/self-check/ready.txt")
        || profile.raw.is_some()
    {
        return Err("valid profile workload arguments were not preserved".to_owned());
    }
    let mut explicit_profile_arguments = profile_arguments.clone();
    explicit_profile_arguments.push(OsString::from("--repository-root"));
    explicit_profile_arguments.push(profile.repository_root.clone().into_os_string());
    explicit_profile_arguments.push(OsString::from("--binary-dir"));
    explicit_profile_arguments.push(profile.binary_dir.clone().into_os_string());
    let explicit_profile = parse_profile_args(&explicit_profile_arguments)?;
    if explicit_profile.repository_root != profile.repository_root
        || explicit_profile.binary_dir != profile.binary_dir
    {
        return Err("explicit profile checkout paths were not preserved".to_owned());
    }
    expect_rejected("incomplete profile checkout paths", || {
        parse_profile_args(&explicit_profile_arguments[..explicit_profile_arguments.len() - 2])
    })?;
    for scenario in [
        "tcp-stream-64k",
        "tcp-request-1k",
        "tcp-request-4k",
        "tcp-request-16k",
        "socks-direct-request-1k",
        "socks-direct-request-4k",
        "socks-direct-request-16k",
        "udp-small-high",
        "udp-mtu-1200",
        "udp-payload-1472",
        "udp-payload-1500",
        "udp-payload-8192",
        "udp-max-wire-65507",
        "udp-direct-small-128",
        "udp-direct-max-65497",
        "udp-response-concurrency-1",
        "udp-response-concurrency-8",
        "udp-response-concurrency-32",
        "udp-replay-sequential",
        "dns-udp-concurrency",
        "dns-cache-size-64",
        "dns-cache-size-4096",
        "dns-cache-size-65536",
    ] {
        let mut fixed = profile_arguments.clone();
        fixed[1] = OsString::from(scenario);
        if parse_profile_args(&fixed)?.scenario.label() != scenario {
            return Err("fixed M18 profile scenario was not preserved".to_owned());
        }
    }
    if ProfileScenario::DnsUdpConcurrency.application_payload_bytes()
        != Some(super::profile_contract::PROFILE_DNS_QUERY_BYTES)
        || ProfileScenario::DnsUdpConcurrency.workload_scale() != Some(32)
        || ProfileScenario::UdpReplaySequential
            .application_payload_bytes()
            .is_some()
        || ProfileScenario::UdpReplaySequential.workload_scale() != Some(1)
        || ProfileScenario::DnsCacheSize64
            .application_payload_bytes()
            .is_some()
        || ProfileScenario::DnsCacheSize64.workload_scale() != Some(64)
        || ProfileScenario::DnsCacheSize4096.workload_scale() != Some(4_096)
        || ProfileScenario::DnsCacheSize65536.workload_scale() != Some(65_536)
    {
        return Err("profile payload and workload-scale identities are invalid".to_owned());
    }
    let mut scale_arguments = profile_arguments.clone();
    scale_arguments[1] = OsString::from("tcp-scale-10k");
    scale_arguments[3] = OsString::from("10");
    scale_arguments[5] = OsString::from("30");
    let scale_profile = parse_profile_args(&scale_arguments)?;
    if scale_profile.scenario != ProfileScenario::TcpScale10k
        || scale_profile.warmup_seconds != 10
        || scale_profile.active_seconds != 30
    {
        return Err("fixed tcp-scale-10k recipe was not preserved".to_owned());
    }
    for (index, replacement) in [(3, "5"), (5, "15")] {
        let mut malformed = scale_arguments.clone();
        malformed[index] = OsString::from(replacement);
        expect_rejected("tcp-scale-10k recipe mutation", || {
            parse_profile_args(&malformed)
        })?;
    }
    let ipv4_target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53))
        .map_err(|_| "self-check IPv4 UDP target is invalid".to_owned())?;
    let direct_maximum = vec![0x5a; PROFILE_UDP_DIRECT_MAX_APPLICATION_PAYLOAD_BYTES];
    let mut socks_wire = vec![0_u8; MAX_SOCKS_UDP_DATAGRAM_BYTES];
    if encode_udp_datagram(&ipv4_target, &direct_maximum, &mut socks_wire)
        .map_err(|_| "direct maximum SOCKS datagram was rejected".to_owned())?
        != MAX_SOCKS_UDP_DATAGRAM_BYTES
    {
        return Err("direct maximum did not fill the complete SOCKS datagram".to_owned());
    }
    let direct_buffers = M14UdpRoundTripBuffers::new(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53),
        PROFILE_UDP_DIRECT_MAX_APPLICATION_PAYLOAD_BYTES,
    )?;
    if direct_buffers.request.len() != MAX_SOCKS_UDP_DATAGRAM_BYTES
        || direct_buffers.received.len() != MAX_SOCKS_UDP_DATAGRAM_BYTES
        || ProfileScenario::UdpDirectMax65497.socks_datagram_bytes()
            != Some(MAX_SOCKS_UDP_DATAGRAM_BYTES)
    {
        return Err("direct profile buffer does not preserve the exact SOCKS bound".to_owned());
    }
    let loopback = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53);
    let payload = vec![0x5a; PROFILE_UDP_PAYLOAD_BYTES];
    let mut truncation_probe = M14UdpRoundTripBuffers::new(loopback, payload.len())?;
    if truncation_probe.received.len() != truncation_probe.request.len() + 1 {
        return Err("profile receive buffer omitted its truncation sentinel".to_owned());
    }
    truncation_probe.received[..payload.len()].copy_from_slice(&payload);
    truncation_probe.validate_target_payload(payload.len(), &payload)?;
    truncation_probe.received[payload.len()] = 0xa5;
    expect_rejected("oversized correct-prefix UDP target response", || {
        truncation_probe.validate_target_payload(payload.len() + 1, &payload)
    })?;
    truncation_probe.request[PROFILE_SOCKS_IPV4_HEADER_BYTES..].copy_from_slice(&payload);
    let request_len = truncation_probe.request.len();
    truncation_probe.received[..request_len].copy_from_slice(&truncation_probe.request);
    truncation_probe.validate_application_response(
        request_len,
        SocketAddr::V4(loopback),
        loopback,
    )?;
    truncation_probe.received[request_len] = 0xa5;
    expect_rejected("oversized correct-prefix UDP application response", || {
        truncation_probe.validate_application_response(
            request_len + 1,
            SocketAddr::V4(loopback),
            loopback,
        )
    })?;
    let oversized_direct = vec![0x5a; PROFILE_UDP_DIRECT_MAX_APPLICATION_PAYLOAD_BYTES + 1];
    if encode_udp_datagram(&ipv4_target, &oversized_direct, &mut socks_wire).is_ok() {
        return Err("direct payload above the SOCKS IPv4 bound was accepted".to_owned());
    }
    if M14UdpRoundTripBuffers::new(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53),
        PROFILE_UDP_DIRECT_MAX_APPLICATION_PAYLOAD_BYTES + 1,
    )
    .is_ok()
    {
        return Err("profile buffer accepted payload above the SOCKS IPv4 bound".to_owned());
    }
    let impossible_application_payload = vec![0x5a; MAX_SOCKS_UDP_DATAGRAM_BYTES];
    if encode_udp_datagram(
        &ipv4_target,
        &impossible_application_payload,
        &mut socks_wire,
    )
    .is_ok()
    {
        return Err("65,507-byte application payload incorrectly fit SOCKS IPv4".to_owned());
    }
    let ss_response_maximum =
        max_udp_payload_len(MethodProfile::Blake3Aes128Gcm2022, true, &ipv4_target, 0)
            .map_err(|_| "SS response maximum could not be derived".to_owned())?;
    if ss_response_maximum != PROFILE_UDP_SS_MAX_APPLICATION_PAYLOAD_BYTES
        || ss_response_maximum + PROFILE_SS_AES_RESPONSE_OVERHEAD_BYTES != MAX_UDP_WIRE_LEN
        || ProfileScenario::UdpMaxWire65507.upstream_wire_bytes() != Some(MAX_UDP_WIRE_LEN)
    {
        return Err("SS maximum payload does not fill the 65,507-byte response wire".to_owned());
    }
    let raw_arguments: Vec<OsString> = [
        "--scenario",
        "tcp-stream-64k",
        "--warmup-seconds",
        "1",
        "--active-seconds",
        "10",
        "--ready-file",
        "profiles/self-check/raw-ready.txt",
        "--output",
        "profiles/self-check/raw.jsonl",
        "--parent-sha",
        sha,
        "--candidate-sha",
        sha,
        "--member",
        "parent",
        "--pair",
        "6",
        "--order",
        "2",
        "--build-profile",
        "fat-cgu1",
        "--unit",
        "bytes_per_second",
        "--runner-image",
        "ubuntu-24.04",
        "--producer-source-sha256",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--controller-source-sha256",
        "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--semantic-recipe-sha256",
        "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--evidence-bundle-sha256",
        "3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let raw_profile = parse_profile_args(&raw_arguments)?;
    let raw = raw_profile.raw.as_ref().expect("complete raw arguments");
    if raw.output != Path::new("profiles/self-check/raw.jsonl")
        || raw.parent_sha != sha
        || raw.candidate_sha != sha
        || raw.member.label() != "parent"
        || raw.pair != 6
        || raw.order != 2
        || raw.build_profile != "fat-cgu1"
        || raw.unit != "bytes_per_second"
        || raw.runner_image != "ubuntu-24.04"
    {
        return Err("valid raw profile arguments were not preserved".to_owned());
    }
    if !profile_raw_prefix(&raw_profile, raw).starts_with(&format!(
        "\"schema_version\":{},\"kind\":\"m18_profile_trial\"",
        super::profile_contract::PROFILE_TRIAL_SCHEMA_VERSION
    )) {
        return Err("raw profile trial omitted its explicit schema version".to_owned());
    }
    expect_rejected("incomplete raw profile identity", || {
        parse_profile_args(&raw_arguments[..raw_arguments.len() - 2])
    })?;
    for (flag, replacement) in [
        ("--unit", "datagrams_per_second"),
        ("--runner-image", "ubuntu-22.04"),
        ("--producer-source-sha256", "abcd"),
        ("--controller-source-sha256", "ABCDEF0123456789"),
        ("--semantic-recipe-sha256", ""),
        ("--evidence-bundle-sha256", "0123"),
    ] {
        let mut mutated = raw_arguments.clone();
        let index = mutated
            .iter()
            .position(|value| value == OsStr::new(flag))
            .expect("registered raw flag");
        mutated[index + 1] = OsString::from(replacement);
        expect_rejected("profile evidence-contract mutation", || {
            parse_profile_args(&mutated)
        })?;
    }
    let invalid_ready_profile = ProfileArgs {
        scenario: ProfileScenario::TcpStream64k,
        warmup_seconds: 1,
        active_seconds: 10,
        ready_file: PathBuf::from("profiles"),
        repository_root: profile.repository_root.clone(),
        binary_dir: profile.binary_dir.clone(),
        raw: None,
    };
    expect_rejected("profile ready resolution reaches unified result", || {
        run_profile_scenario(&invalid_ready_profile)
    })?;
    if percentile_99((1..=100).collect())? != 99 {
        return Err("profile p99 rank is invalid".to_owned());
    }
    let mut overflowing = profile_arguments.clone();
    overflowing[5] = OsString::from("901");
    expect_rejected("overflowing profile active lifetime", || {
        parse_profile_args(&overflowing)
    })?;
    let cancelled_profile_gate = StartGate::default();
    for _ in 0..STREAMS {
        cancelled_profile_gate.worker_validated()?;
    }
    cancelled_profile_gate.cancel();
    expect_rejected("validated then cancelled profile load", || {
        cancelled_profile_gate.require_validated(STREAMS)
    })?;
    let profile_ready = tempfile::tempdir().map_err(clean_io)?;
    let ready_path = profile_ready.path().join("ready.txt");
    let ready = ReadyFile::publish(&ready_path, ProfileScenario::TcpBulk, 11, Some(12), 1, 10)?;
    if fs::read_to_string(&ready_path).map_err(clean_io)?
        != "scenario=tcp-bulk\nclient_pid=11\nserver_pid=12\nwarmup_seconds=1\nactive_seconds=10\n"
    {
        return Err("profile ready file fields are incomplete".to_owned());
    }
    expect_rejected("profile ready collision", || {
        ReadyFile::publish(&ready_path, ProfileScenario::TcpBulk, 21, Some(22), 1, 10)
    })?;
    if fs::read_to_string(&ready_path).map_err(clean_io)?
        != "scenario=tcp-bulk\nclient_pid=11\nserver_pid=12\nwarmup_seconds=1\nactive_seconds=10\n"
    {
        return Err("profile ready collision overwrote the sentinel".to_owned());
    }
    ready.remove()?;
    if ready_path.exists() {
        return Err("profile ready file survived explicit cleanup".to_owned());
    }
    let direct_ready = ReadyFile::publish(
        &ready_path,
        ProfileScenario::UdpDirectSmall128,
        30,
        None,
        1,
        10,
    )?;
    if fs::read_to_string(&ready_path).map_err(clean_io)?
        != "scenario=udp-direct-small-128\nclient_pid=30\nserver_pid=none\nwarmup_seconds=1\nactive_seconds=10\n"
    {
        return Err("direct profile ready file claimed a server process".to_owned());
    }
    direct_ready.remove()?;
    {
        let _ready = ReadyFile::publish(
            &ready_path,
            ProfileScenario::UdpSmallHigh,
            31,
            Some(32),
            1,
            10,
        )?;
    }
    if ready_path.exists() {
        return Err("profile ready file survived unwind cleanup".to_owned());
    }
    let raw_path = profile_ready.path().join("raw.jsonl");
    let raw_line = "{\"schema_version\":3,\"kind\":\"m18_profile_trial\",\"status\":\"PASS\"}";
    let mut raw_evidence = Evidence::create(&raw_path)?;
    raw_evidence.line(raw_line.to_owned())?;
    raw_evidence.finish()?;
    if fs::read_to_string(&raw_path).map_err(clean_io)? != format!("{raw_line}\n") {
        return Err("M18 raw profile row did not round-trip".to_owned());
    }
    expect_rejected("M18 raw profile overwrite", || Evidence::create(&raw_path))?;
    let thp = tempfile::tempdir().map_err(clean_io)?;
    let thp_profile = thp.path().join("max_ptes_none");
    fs::write(&thp_profile, "0\n").map_err(clean_io)?;
    validate_thp_profile(&thp_profile)
        .map_err(|_| "canonical THP max_ptes_none profile was rejected".to_owned())?;
    for unavailable in [&thp.path().join("missing"), thp.path()] {
        if validate_thp_profile(unavailable)
            != Err("THP max_ptes_none profile is unavailable".to_owned())
        {
            return Err("unavailable THP max_ptes_none profile had wrong failure".to_owned());
        }
    }
    fs::write(&thp_profile, "00\n").map_err(clean_io)?;
    if validate_thp_profile(&thp_profile)
        != Err("THP max_ptes_none profile is malformed".to_owned())
    {
        return Err("malformed THP max_ptes_none profile had wrong failure".to_owned());
    }
    fs::write(&thp_profile, "511\n").map_err(clean_io)?;
    if validate_thp_profile(&thp_profile) != Err("THP max_ptes_none profile is not zero".to_owned())
    {
        return Err("nonzero THP max_ptes_none profile had wrong failure".to_owned());
    }
    let transfer_start = Instant::now();
    let warm_end = transfer_start + WARMUP;
    let measure_end = warm_end + MEASURE;
    if !transfer_is_measured(warm_end, measure_end, warm_end, measure_end)
        || transfer_is_measured(
            warm_end - Duration::from_nanos(1),
            measure_end,
            warm_end,
            measure_end,
        )
        || transfer_is_measured(
            warm_end,
            measure_end + Duration::from_nanos(1),
            warm_end,
            measure_end,
        )
    {
        return Err("throughput measurement boundary is invalid".to_owned());
    }
    let past_slot = Instant::now();
    let admission_now = past_slot + Duration::from_nanos(1);
    if sample_slot_delay(admission_now, past_slot, admission_now + SAMPLE_INTERVAL).is_ok() {
        return Err("past resource sample slot was admitted".to_owned());
    }
    let executable = std::env::current_exe().map_err(clean_io)?;
    let probe_error = probe_text(
        "self-check nonzero probe",
        &executable,
        ["self-check-probe-nonzero"],
        PROBE_TIMEOUT,
    )
    .expect_err("self-check probe must exit nonzero");
    ensure_redacted(&probe_error)?;
    if probe_error != "self-check nonzero probe exited nonzero" {
        return Err(format!("probe diagnostic mismatch: {probe_error}"));
    }
    let lazy_absent = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n\
# TYPE ferrum2_tcp_replay_entries gauge\n\
ferrum2_tcp_replay_entries 0\n\
# EOF\n";
    if parse_active_metric_response(lazy_absent) != Ok(0) {
        return Err("valid lazy active metric absence was rejected".to_owned());
    }
    expect_rejected("unidentified active metric absence", || {
        parse_active_metric_response(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n# EOF\n")
    })?;
    expect_rejected("wrong SHA", || {
        validate_environment("1123456789abcdef0123456789abcdef01234567", &good)
    })?;
    let wrong_host = EnvironmentIdentity {
        runner_os: "Windows".to_owned(),
        ..good
    };
    expect_rejected("wrong host", || validate_environment(sha, &wrong_host))?;
    expect_rejected("wrong reference", || {
        validate_reference_identity("shadowsocks 1.23.0", REFERENCE_SHA256)
    })?;
    let precise_fixture = "Rss: 123 kB\nPss: 99 kB\nAnonymous: 77 kB\nAnonHugePages: 4 kB\n";
    if parse_smaps_rollup(precise_fixture)
        != Ok(PreciseRss {
            rss_kib: 123,
            anonymous_kib: 77,
            anon_huge_pages_kib: 4,
        })
    {
        return Err("valid smaps_rollup fixture was rejected".to_owned());
    }
    if parse_smaps_rollup("Rss: 123 kB\nAnonHugePages: 4 kB\n")
        != Err("process precise RSS state is missing Anonymous".to_owned())
    {
        return Err("missing smaps_rollup field was admitted".to_owned());
    }
    if parse_smaps_rollup("Rss: 123 kB\nAnonymous: 77 kB\nRss: 124 kB\nAnonHugePages: 4 kB\n")
        != Err("process precise RSS state duplicates Rss".to_owned())
    {
        return Err("duplicate smaps_rollup field was admitted".to_owned());
    }
    if parse_smaps_rollup("Rss: many kB\nAnonymous: 77 kB\nAnonHugePages: 4 kB\n")
        != Err("process precise RSS state has malformed Rss".to_owned())
    {
        return Err("malformed smaps_rollup number was admitted".to_owned());
    }
    if parse_smaps_rollup("Rss: 123 MB\nAnonymous: 77 kB\nAnonHugePages: 4 kB\n")
        != Err("process precise RSS state has wrong unit for Rss".to_owned())
    {
        return Err("wrong smaps_rollup unit was admitted".to_owned());
    }
    if parse_smaps_rollup("Rss: 18446744073709551616 kB\nAnonymous: 77 kB\nAnonHugePages: 4 kB\n")
        != Err("process precise RSS state overflows Rss".to_owned())
    {
        return Err("overflowing smaps_rollup number had wrong failure".to_owned());
    }
    let process = ProcessSample {
        active: 4,
        fds: 20,
        tasks: 3,
        rss_kib: 100,
        smaps_rss_kib: 100,
        anonymous_kib: 70,
        anon_huge_pages_kib: 0,
    };
    let sample = PairSample {
        client: process,
        server: process,
    };
    if sample.json(1)
        != "{\"kind\":\"resource_sample\",\"sample\":1,\"client_active\":4,\
            \"server_active\":4,\"client_fds\":20,\"server_fds\":20,\
            \"client_tasks\":3,\"server_tasks\":3,\"client_rss_kib\":100,\
            \"server_rss_kib\":100,\"client_smaps_rss_kib\":100,\
            \"server_smaps_rss_kib\":100,\"client_anonymous_kib\":70,\
            \"server_anonymous_kib\":70,\"client_anon_huge_pages_kib\":0,\
            \"server_anon_huge_pages_kib\":0}"
    {
        return Err("paired resource sample JSON is incomplete".to_owned());
    }
    let samples = vec![sample; 12];
    let verdicts = validate_samples(&samples, 12, 2, 4)?;
    if verdicts[0].json()
        != "{\"kind\":\"rss_window\",\"window\":1,\"client_median_twice_kib\":200,\
            \"server_median_twice_kib\":200,\"client_smaps_rss_median_twice_kib\":200,\
            \"server_smaps_rss_median_twice_kib\":200,\
            \"client_anonymous_median_twice_kib\":140,\
            \"server_anonymous_median_twice_kib\":140,\
            \"client_anon_huge_pages_median_twice_kib\":0,\
            \"server_anon_huge_pages_median_twice_kib\":0,\
            \"limit_percent\":105,\"status\":\"PASS\"}"
    {
        return Err("paired RSS window JSON is incomplete".to_owned());
    }
    expect_rejected("missing sample", || {
        validate_samples(&samples[..11], 12, 2, 4)
    })?;
    let mut changing = samples.clone();
    changing[3].client.tasks += 1;
    expect_rejected("changing owner tuple", || {
        validate_samples(&changing, 12, 2, 4)
    })?;
    let mut boundary = samples.clone();
    boundary[10].client.rss_kib = 105;
    boundary[11].client.rss_kib = 105;
    validate_samples(&boundary, 12, 2, 4)?;
    let mut plateau = samples.clone();
    for sample in &mut plateau[2..] {
        sample.client.rss_kib = 106;
    }
    let plateau_error = match validate_samples(&plateau, 12, 2, 4) {
        Ok(_) => return Err("self-check mutation survived: RSS plateau".to_owned()),
        Err(error) => error,
    };
    let expected_plateau_error = "RSS window 2 exceeds 105 percent: first_failing_window=2 \
                                  client_vmrss_median_twice_kib=[200, 212, 212, 212, 212, 212] \
                                  server_vmrss_median_twice_kib=[200, 200, 200, 200, 200, 200] \
                                  client_smaps_rss_median_twice_kib=[200, 200, 200, 200, 200, 200] \
                                  server_smaps_rss_median_twice_kib=[200, 200, 200, 200, 200, 200] \
                                  client_anonymous_median_twice_kib=[140, 140, 140, 140, 140, 140] \
                                  server_anonymous_median_twice_kib=[140, 140, 140, 140, 140, 140] \
                                  client_anon_huge_pages_median_twice_kib=[0, 0, 0, 0, 0, 0] \
                                  server_anon_huge_pages_median_twice_kib=[0, 0, 0, 0, 0, 0]";
    if plateau_error != expected_plateau_error {
        return Err(format!("RSS plateau diagnostic mismatch: {plateau_error}"));
    }
    let mut rss = samples.clone();
    for (window, (vmrss, smaps_rss, anonymous, huge)) in [
        (100, 100, 70, 0),
        (101, 103, 71, 1),
        (102, 106, 72, 2),
        (103, 109, 73, 3),
        (105, 112, 74, 4),
        (106, 115, 75, 5),
    ]
    .into_iter()
    .enumerate()
    {
        for sample in &mut rss[window * 2..window * 2 + 2] {
            sample.client.rss_kib = vmrss;
            sample.client.smaps_rss_kib = smaps_rss;
            sample.client.anonymous_kib = anonymous;
            sample.client.anon_huge_pages_kib = huge;
        }
    }
    let rss_error = match validate_samples(&rss, 12, 2, 4) {
        Ok(_) => return Err("self-check mutation survived: RSS regression".to_owned()),
        Err(error) => error,
    };
    let expected_rss_error = "RSS window 6 exceeds 105 percent: first_failing_window=6 \
                              client_vmrss_median_twice_kib=[200, 202, 204, 206, 210, 212] \
                              server_vmrss_median_twice_kib=[200, 200, 200, 200, 200, 200] \
                              client_smaps_rss_median_twice_kib=[200, 206, 212, 218, 224, 230] \
                              server_smaps_rss_median_twice_kib=[200, 200, 200, 200, 200, 200] \
                              client_anonymous_median_twice_kib=[140, 142, 144, 146, 148, 150] \
                              server_anonymous_median_twice_kib=[140, 140, 140, 140, 140, 140] \
                              client_anon_huge_pages_median_twice_kib=[0, 2, 4, 6, 8, 10] \
                              server_anon_huge_pages_median_twice_kib=[0, 0, 0, 0, 0, 0]";
    if rss_error != expected_rss_error {
        return Err(format!("RSS diagnostic mismatch: {rss_error}"));
    }
    let baseline = PairSample {
        client: ProcessSample {
            active: 0,
            fds: 7,
            tasks: 2,
            rss_kib: 80,
            smaps_rss_kib: 80,
            anonymous_kib: 60,
            anon_huge_pages_kib: 0,
        },
        server: ProcessSample {
            active: 0,
            fds: 8,
            tasks: 2,
            rss_kib: 80,
            smaps_rss_kib: 80,
            anonymous_kib: 60,
            anon_huge_pages_kib: 0,
        },
    };
    let mut incomplete = baseline;
    incomplete.server.fds += 1;
    expect_rejected("incomplete drain", || {
        validate_drain(&incomplete, &baseline)
    })?;
    let dns_samples = vec![baseline; DNS_RESOURCE_SAMPLES];
    let dns_verdicts = validate_dns_samples(&dns_samples, &baseline)?;
    if dns_verdicts[0].dns_json("direct")
        != "{\"kind\":\"dns_rss_window\",\"phase\":\"direct\",\"window\":1,\
            \"client_median_twice_kib\":160,\"server_median_twice_kib\":160,\
            \"client_smaps_rss_median_twice_kib\":160,\
            \"server_smaps_rss_median_twice_kib\":160,\
            \"client_anonymous_median_twice_kib\":120,\
            \"server_anonymous_median_twice_kib\":120,\
            \"client_anon_huge_pages_median_twice_kib\":0,\
            \"server_anon_huge_pages_median_twice_kib\":0,\
            \"limit_percent\":105,\"status\":\"PASS\"}"
    {
        return Err("DNS RSS window JSON is incomplete".to_owned());
    }
    let mut overbound = baseline;
    overbound.client.tasks += DNS_OWNER_DELTA + 1;
    expect_rejected("DNS owner ceiling", || {
        validate_dns_owner_bound(&overbound, &baseline)
    })?;
    let mut responder = DnsResponder::start(DNS_DIRECT_NAME)?;
    let mut load = DnsLoad::start(responder.address, DNS_DIRECT_NAME)?;
    load.wait_started(Instant::now() + STARTUP_TIMEOUT)?;
    let inflight_peak = load.peak();
    if inflight_peak == 0 || inflight_peak > DNS_LOAD_WORKERS {
        return Err("typed DNS load inflight observation is invalid".to_owned());
    }
    let completed = load.finish()?;
    if load.active() != 0 {
        return Err("typed DNS load inflight accounting did not drain".to_owned());
    }
    let observed = responder.finish()?;
    if completed < DNS_LOAD_WORKERS || observed != completed || load.completed() != completed {
        return Err("typed DNS load self-check is incomplete".to_owned());
    }
    let blackhole = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(clean_io)?;
    let blackhole_address = v4(blackhole.local_addr().map_err(clean_io)?)?;
    let mut dropped_tail =
        DnsLoad::start_with_workers(blackhole_address, DNS_DIRECT_NAME, 1, None)?;
    let tail_deadline = Instant::now() + STARTUP_TIMEOUT;
    while dropped_tail.active() == 0 {
        dropped_tail.ensure_running()?;
        if Instant::now() >= tail_deadline {
            return Err("DNS tail-loss self-check did not send a query".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    expect_rejected("DNS tail response loss", || dropped_tail.finish())?;
    if dropped_tail.active() != 0 || dropped_tail.completed() != 0 || dropped_tail.peak() != 1 {
        return Err("DNS tail-loss accounting did not close".to_owned());
    }
    drop(blackhole);
    expect_rejected("leaked owner", || validate_owner_counts(1, 0))?;
    expect_rejected("secret output", || ensure_redacted(PSK))?;
    let tls = m14_tls_client_hello()?;
    validate_m14_measurement_plan(&M14_MEASUREMENT_PHASES, &tls, true)?;
    let missing_schema_v1_rejection: Vec<_> = M14_MEASUREMENT_PHASES
        .into_iter()
        .filter(|phase| *phase != "schema-v1-routed-udp-rejection")
        .collect();
    expect_rejected("missing M14 schema-v1 rejection phase", || {
        validate_m14_measurement_plan(&missing_schema_v1_rejection, &tls, true)
    })?;
    expect_rejected("invalid M14 TLS ClientHello", || {
        validate_m14_measurement_plan(&M14_MEASUREMENT_PHASES, &[0x16, 0x03, 0x03, 0, 0], true)
    })?;
    expect_rejected("non-distinguishing M14 terminal oracle", || {
        validate_m14_measurement_plan(&M14_MEASUREMENT_PHASES, &tls, false)
    })?;
    let incomplete_root = tempfile::tempdir().map_err(clean_io)?;
    fs::write(incomplete_root.path().join("Cargo.toml"), "[workspace]\n").map_err(clean_io)?;
    fs::write(incomplete_root.path().join("Cargo.lock"), "").map_err(clean_io)?;
    expect_rejected("incomplete repository identity", || {
        is_repository_root(incomplete_root.path())
            .then_some(())
            .ok_or_else(|| "repository identity is incomplete".to_owned())
    })?;
    let root = profile.repository_root.join("target/m4");
    fs::create_dir_all(&root).map_err(clean_io)?;
    let path = root.join("self-check.jsonl");
    let mut file = BufWriter::new(File::create(&path).map_err(clean_io)?);
    tcp_scale::run_scale_self_check()?;
    let line =
        format!("{{\"kind\":\"self_check\",\"mutations\":{MUTATION_COUNT},\"status\":\"PASS\"}}\n");
    ensure_redacted(&line)?;
    file.write_all(line.as_bytes()).map_err(clean_io)?;
    file.flush().map_err(clean_io)?;
    assert_no_owners()?;
    Ok(format!(
        "m4_self_check status=PASS mutations={MUTATION_COUNT}"
    ))
}

pub(super) fn expect_rejected<T>(
    name: &str,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<(), String> {
    if operation().is_ok() {
        return Err(format!("self-check mutation survived: {name}"));
    }
    Ok(())
}

pub(super) fn validate_reference_identity(version: &str, sha256: &str) -> Result<(), String> {
    if version.trim() != REFERENCE_VERSION || sha256 != REFERENCE_SHA256 {
        return Err("reference identity mismatch".to_owned());
    }
    Ok(())
}

pub(super) fn ensure_redacted(text: &str) -> Result<(), String> {
    if text.contains(PSK) {
        return Err("secret-bearing output".to_owned());
    }
    Ok(())
}

pub(super) fn assert_no_owners() -> Result<(), String> {
    validate_owner_counts(
        ACTIVE_PROCESSES.load(Ordering::SeqCst),
        ACTIVE_WORKERS.load(Ordering::SeqCst),
    )
}

pub(super) fn validate_owner_counts(processes: usize, workers: usize) -> Result<(), String> {
    if processes != 0 || workers != 0 {
        return Err("owned process or worker leaked".to_owned());
    }
    Ok(())
}
