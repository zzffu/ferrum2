use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::thread;

use ferrum2_shadowsocks::MAX_UDP_WIRE_LEN;
use ferrum2_socks5::MAX_SOCKS_UDP_DATAGRAM_BYTES;

use super::evidence_support::profile_binary;
use super::host_identity::linux_capacity;
use super::process_support::{
    PROBE_TIMEOUT, clean_io, first_line, json, probe_text, repository_root, sha256,
};
use super::tcp_scale::SCALE_PAYLOAD_BYTES;
use super::{PAYLOAD_BYTES, STREAMS};

pub(super) const PROFILE_WARMUP_SECONDS: std::ops::RangeInclusive<u64> = 1..=60;
pub(super) const PROFILE_ACTIVE_SECONDS: std::ops::RangeInclusive<u64> = 10..=900;
pub(super) const PROFILE_UDP_WORKERS: usize = 4;
pub(super) const PROFILE_UDP_MAX_BUFFERED_BYTES: usize = 8 * 1024 * 1024;
pub(super) const PROFILE_DNS_WORKERS: usize = 16;
pub(super) const PROFILE_UDP_PAYLOAD_BYTES: usize = 128;
pub(super) const PROFILE_UDP_MTU_PAYLOAD_BYTES: usize = 1_200;
pub(super) const PROFILE_UDP_PAYLOAD_1472_BYTES: usize = 1_472;
pub(super) const PROFILE_UDP_PAYLOAD_1500_BYTES: usize = 1_500;
pub(super) const PROFILE_UDP_PAYLOAD_8192_BYTES: usize = 8_192;
pub(super) const PROFILE_SOCKS_IPV4_HEADER_BYTES: usize = 10;
// AES-2022 response wire: 32 crypto + 11 common + 8 response binding + 7 target.
pub(super) const PROFILE_SS_AES_RESPONSE_OVERHEAD_BYTES: usize = 58;
pub(super) const PROFILE_UDP_SS_MAX_APPLICATION_PAYLOAD_BYTES: usize =
    MAX_UDP_WIRE_LEN - PROFILE_SS_AES_RESPONSE_OVERHEAD_BYTES;
pub(super) const PROFILE_UDP_DIRECT_MAX_APPLICATION_PAYLOAD_BYTES: usize =
    MAX_SOCKS_UDP_DATAGRAM_BYTES - PROFILE_SOCKS_IPV4_HEADER_BYTES;
pub(super) const PROFILE_TCP_STREAM_BATCH: usize = 4;
pub(super) const PROFILE_TCP_LATENCY_WORKERS: usize = 1;
pub(super) const PROFILE_TCP_LATENCY_ACTIVE_MAX_SECONDS: u64 = 60;
pub(super) const PROFILE_TCP_LATENCY_SAMPLE_CAP: usize = 2_000_000;
pub(super) const PROFILE_TRIAL_SCHEMA_VERSION: u8 = 4;
pub(super) const EVIDENCE_LINE_MAX_BYTES: usize = 16 * 1024;
pub(super) const TCP_SCALE_EVIDENCE_LINE_MAX_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Topology {
    Ferrum,
    Reference,
}

impl Topology {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Ferrum => "ferrum",
            Self::Reference => "reference",
        }
    }
}

pub(super) struct HostedArgs {
    pub(super) sha: String,
    pub(super) output: PathBuf,
    pub(super) sslocal: Option<PathBuf>,
    pub(super) ssserver: Option<PathBuf>,
}

pub(super) fn parse_hosted_args(
    arguments: &[OsString],
    reference: bool,
) -> Result<HostedArgs, String> {
    let mut sha = None;
    let mut output = None;
    let mut sslocal = None;
    let mut ssserver = None;
    let mut chunks = arguments.chunks_exact(2);
    for pair in &mut chunks {
        let flag = pair[0]
            .to_str()
            .ok_or_else(|| "option name is not UTF-8".to_owned())?;
        let value = pair[1].clone();
        let slot = match flag {
            "--sha" => &mut sha,
            "--output" => &mut output,
            "--sslocal" if reference => &mut sslocal,
            "--ssserver" if reference => &mut ssserver,
            _ => return Err(format!("unsupported option: {flag}")),
        };
        if slot.replace(value).is_some() {
            return Err(format!("duplicate option: {flag}"));
        }
    }
    if !chunks.remainder().is_empty() {
        return Err("every option requires one value".to_owned());
    }
    let utf8 = |value: OsString, name: &str| {
        value
            .into_string()
            .map_err(|_| format!("{name} is not UTF-8"))
    };
    let sha = utf8(sha.ok_or_else(|| "missing --sha".to_owned())?, "SHA")?;
    let output = PathBuf::from(output.ok_or_else(|| "missing --output".to_owned())?);
    let sslocal = sslocal.map(PathBuf::from);
    let ssserver = ssserver.map(PathBuf::from);
    if reference && (sslocal.is_none() || ssserver.is_none()) {
        return Err("throughput requires --sslocal and --ssserver".to_owned());
    }
    Ok(HostedArgs {
        sha,
        output,
        sslocal,
        ssserver,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProfileScenario {
    TcpBulk,
    TcpStream64k,
    TcpScale10k,
    TcpRequest1k,
    TcpRequest4k,
    TcpRequest16k,
    DnsDirect,
    DnsDetoured,
    UdpSmallHigh,
    UdpMtu1200,
    UdpPayload1472,
    UdpPayload1500,
    UdpPayload8192,
    UdpMaxWire65507,
    UdpDirectSmall128,
    UdpDirectMax65497,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProfileUdpTopology {
    Shadowsocks,
    Direct,
}

impl ProfileUdpTopology {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Shadowsocks => "shadowsocks",
            Self::Direct => "direct",
        }
    }
}

impl ProfileScenario {
    pub(super) fn parse(value: OsString) -> Result<Self, String> {
        match value.to_str() {
            Some("tcp-bulk") => Ok(Self::TcpBulk),
            Some("tcp-stream-64k") => Ok(Self::TcpStream64k),
            Some("tcp-scale-10k") => Ok(Self::TcpScale10k),
            Some("tcp-request-1k") => Ok(Self::TcpRequest1k),
            Some("tcp-request-4k") => Ok(Self::TcpRequest4k),
            Some("tcp-request-16k") => Ok(Self::TcpRequest16k),
            Some("dns-direct") => Ok(Self::DnsDirect),
            Some("dns-detoured") => Ok(Self::DnsDetoured),
            Some("udp-small-high") => Ok(Self::UdpSmallHigh),
            Some("udp-mtu-1200") => Ok(Self::UdpMtu1200),
            Some("udp-payload-1472") => Ok(Self::UdpPayload1472),
            Some("udp-payload-1500") => Ok(Self::UdpPayload1500),
            Some("udp-payload-8192") => Ok(Self::UdpPayload8192),
            Some("udp-max-wire-65507") => Ok(Self::UdpMaxWire65507),
            Some("udp-direct-small-128") => Ok(Self::UdpDirectSmall128),
            Some("udp-direct-max-65497") => Ok(Self::UdpDirectMax65497),
            _ => Err(
                "profile scenario must be tcp-bulk, tcp-stream-64k, tcp-scale-10k, \
                 tcp-request-1k, tcp-request-4k, tcp-request-16k, dns-direct, dns-detoured, \
                 udp-small-high, udp-mtu-1200, udp-payload-1472, udp-payload-1500, \
                 udp-payload-8192, udp-max-wire-65507, udp-direct-small-128, or \
                 udp-direct-max-65497"
                    .to_owned(),
            ),
        }
    }

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::TcpBulk => "tcp-bulk",
            Self::TcpStream64k => "tcp-stream-64k",
            Self::TcpScale10k => "tcp-scale-10k",
            Self::TcpRequest1k => "tcp-request-1k",
            Self::TcpRequest4k => "tcp-request-4k",
            Self::TcpRequest16k => "tcp-request-16k",
            Self::DnsDirect => "dns-direct",
            Self::DnsDetoured => "dns-detoured",
            Self::UdpSmallHigh => "udp-small-high",
            Self::UdpMtu1200 => "udp-mtu-1200",
            Self::UdpPayload1472 => "udp-payload-1472",
            Self::UdpPayload1500 => "udp-payload-1500",
            Self::UdpPayload8192 => "udp-payload-8192",
            Self::UdpMaxWire65507 => "udp-max-wire-65507",
            Self::UdpDirectSmall128 => "udp-direct-small-128",
            Self::UdpDirectMax65497 => "udp-direct-max-65497",
        }
    }

    pub(super) const fn tcp_workers(self) -> Option<usize> {
        match self {
            Self::TcpBulk | Self::TcpStream64k => Some(STREAMS),
            Self::TcpScale10k => None,
            Self::TcpRequest1k | Self::TcpRequest4k | Self::TcpRequest16k => {
                Some(PROFILE_TCP_LATENCY_WORKERS)
            }
            Self::DnsDirect
            | Self::DnsDetoured
            | Self::UdpSmallHigh
            | Self::UdpMtu1200
            | Self::UdpPayload1472
            | Self::UdpPayload1500
            | Self::UdpPayload8192
            | Self::UdpMaxWire65507
            | Self::UdpDirectSmall128
            | Self::UdpDirectMax65497 => None,
        }
    }

    pub(super) const fn tcp_request_bytes(self) -> Option<usize> {
        match self {
            Self::TcpRequest1k => Some(1_024),
            Self::TcpRequest4k => Some(4_096),
            Self::TcpRequest16k => Some(16_384),
            _ => None,
        }
    }

    pub(super) const fn udp_payload_bytes(self) -> Option<usize> {
        match self {
            Self::UdpSmallHigh => Some(PROFILE_UDP_PAYLOAD_BYTES),
            Self::UdpMtu1200 => Some(PROFILE_UDP_MTU_PAYLOAD_BYTES),
            Self::UdpPayload1472 => Some(PROFILE_UDP_PAYLOAD_1472_BYTES),
            Self::UdpPayload1500 => Some(PROFILE_UDP_PAYLOAD_1500_BYTES),
            Self::UdpPayload8192 => Some(PROFILE_UDP_PAYLOAD_8192_BYTES),
            Self::UdpMaxWire65507 => Some(PROFILE_UDP_SS_MAX_APPLICATION_PAYLOAD_BYTES),
            Self::UdpDirectSmall128 => Some(PROFILE_UDP_PAYLOAD_BYTES),
            Self::UdpDirectMax65497 => Some(PROFILE_UDP_DIRECT_MAX_APPLICATION_PAYLOAD_BYTES),
            _ => None,
        }
    }

    pub(super) const fn udp_topology(self) -> Option<ProfileUdpTopology> {
        match self {
            Self::UdpSmallHigh
            | Self::UdpMtu1200
            | Self::UdpPayload1472
            | Self::UdpPayload1500
            | Self::UdpPayload8192
            | Self::UdpMaxWire65507 => Some(ProfileUdpTopology::Shadowsocks),
            Self::UdpDirectSmall128 | Self::UdpDirectMax65497 => Some(ProfileUdpTopology::Direct),
            _ => None,
        }
    }

    pub(super) const fn application_payload_bytes(self) -> usize {
        match self {
            Self::TcpBulk | Self::TcpStream64k => PAYLOAD_BYTES,
            Self::TcpScale10k => SCALE_PAYLOAD_BYTES,
            Self::TcpRequest1k => 1_024,
            Self::TcpRequest4k => 4_096,
            Self::TcpRequest16k => 16_384,
            Self::DnsDirect | Self::DnsDetoured => 0,
            _ => self.udp_payload_bytes().expect("UDP scenario payload"),
        }
    }

    pub(super) const fn topology_label(self) -> &'static str {
        match self {
            Self::DnsDirect => "direct",
            Self::DnsDetoured => "detoured",
            _ => match self.udp_topology() {
                Some(topology) => topology.label(),
                None => "shadowsocks",
            },
        }
    }

    pub(super) const fn unit(self) -> &'static str {
        match self {
            Self::TcpRequest1k | Self::TcpRequest4k | Self::TcpRequest16k => "nanoseconds",
            Self::DnsDirect | Self::DnsDetoured => "queries_per_second",
            Self::UdpSmallHigh
            | Self::UdpMtu1200
            | Self::UdpPayload1472
            | Self::UdpPayload1500
            | Self::UdpPayload8192
            | Self::UdpMaxWire65507
            | Self::UdpDirectSmall128
            | Self::UdpDirectMax65497 => "datagrams_per_second",
            _ => "bytes_per_second",
        }
    }

    pub(super) const fn socks_datagram_bytes(self) -> Option<usize> {
        match self.udp_payload_bytes() {
            Some(payload) => Some(payload + PROFILE_SOCKS_IPV4_HEADER_BYTES),
            None => None,
        }
    }

    pub(super) const fn upstream_wire_bytes(self) -> Option<usize> {
        match self.udp_topology() {
            Some(ProfileUdpTopology::Shadowsocks) => {
                Some(self.application_payload_bytes() + PROFILE_SS_AES_RESPONSE_OVERHEAD_BYTES)
            }
            Some(ProfileUdpTopology::Direct) => Some(self.application_payload_bytes()),
            None => None,
        }
    }
}

pub(super) struct ProfileArgs {
    pub(super) scenario: ProfileScenario,
    pub(super) warmup_seconds: u64,
    pub(super) active_seconds: u64,
    pub(super) ready_file: PathBuf,
    pub(super) repository_root: PathBuf,
    pub(super) binary_dir: PathBuf,
    pub(super) raw: Option<ProfileRawArgs>,
}

#[derive(Clone, Copy)]
pub(super) enum ProfileMember {
    Parent,
    Candidate,
}

impl ProfileMember {
    pub(super) fn parse(value: &OsStr) -> Result<Self, String> {
        match value.to_str() {
            Some("parent") => Ok(Self::Parent),
            Some("candidate") => Ok(Self::Candidate),
            _ => Err("--member must be parent or candidate".to_owned()),
        }
    }

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Parent => "parent",
            Self::Candidate => "candidate",
        }
    }
}

pub(super) struct ProfileRawArgs {
    pub(super) output: PathBuf,
    pub(super) parent_sha: String,
    pub(super) candidate_sha: String,
    pub(super) member: ProfileMember,
    pub(super) pair: u8,
    pub(super) order: u8,
    pub(super) build_profile: String,
    pub(super) unit: String,
    pub(super) runner_image: String,
    pub(super) producer_source_sha256: String,
    pub(super) controller_source_sha256: String,
    pub(super) semantic_recipe_sha256: String,
    pub(super) evidence_bundle_sha256: String,
}

pub(super) fn parse_profile_args(arguments: &[OsString]) -> Result<ProfileArgs, String> {
    let mut scenario = None;
    let mut warmup_seconds = None;
    let mut active_seconds = None;
    let mut ready_file = None;
    let mut output = None;
    let mut parent_sha = None;
    let mut candidate_sha = None;
    let mut member = None;
    let mut raw_pair = None;
    let mut order = None;
    let mut build_profile = None;
    let mut unit = None;
    let mut runner_image = None;
    let mut producer_source_sha256 = None;
    let mut controller_source_sha256 = None;
    let mut semantic_recipe_sha256 = None;
    let mut evidence_bundle_sha256 = None;
    let mut selected_repository_root = None;
    let mut binary_dir = None;
    let mut chunks = arguments.chunks_exact(2);
    for pair in &mut chunks {
        let flag = pair[0]
            .to_str()
            .ok_or_else(|| "profile option name is not UTF-8".to_owned())?;
        let slot = match flag {
            "--scenario" => &mut scenario,
            "--warmup-seconds" => &mut warmup_seconds,
            "--active-seconds" => &mut active_seconds,
            "--ready-file" => &mut ready_file,
            "--output" => &mut output,
            "--parent-sha" => &mut parent_sha,
            "--candidate-sha" => &mut candidate_sha,
            "--member" => &mut member,
            "--pair" => &mut raw_pair,
            "--order" => &mut order,
            "--build-profile" => &mut build_profile,
            "--unit" => &mut unit,
            "--runner-image" => &mut runner_image,
            "--producer-source-sha256" => &mut producer_source_sha256,
            "--controller-source-sha256" => &mut controller_source_sha256,
            "--semantic-recipe-sha256" => &mut semantic_recipe_sha256,
            "--evidence-bundle-sha256" => &mut evidence_bundle_sha256,
            "--repository-root" => &mut selected_repository_root,
            "--binary-dir" => &mut binary_dir,
            _ => return Err(format!("unsupported profile option: {flag}")),
        };
        if slot.replace(pair[1].clone()).is_some() {
            return Err(format!("duplicate profile option: {flag}"));
        }
    }
    if !chunks.remainder().is_empty() {
        return Err("every profile option requires one value".to_owned());
    }
    let seconds = |value: Option<OsString>, name: &str, bounds: &std::ops::RangeInclusive<u64>| {
        let value = value
            .ok_or_else(|| format!("missing {name}"))?
            .into_string()
            .map_err(|_| format!("{name} is not UTF-8"))?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!("{name} must be an integer"));
        }
        let value = value
            .parse::<u64>()
            .map_err(|_| format!("{name} is outside its finite bound"))?;
        bounds
            .contains(&value)
            .then_some(value)
            .ok_or_else(|| format!("{name} is outside its finite bound"))
    };
    let ready_file = PathBuf::from(ready_file.ok_or_else(|| "missing --ready-file".to_owned())?);
    if ready_file.is_absolute()
        || !ready_file.starts_with("profiles")
        || ready_file.components().count() < 2
        || ready_file
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("--ready-file must be a relative child of profiles/".to_owned());
    }
    let scenario =
        ProfileScenario::parse(scenario.ok_or_else(|| "missing --scenario".to_owned())?)?;
    let warmup_seconds = seconds(warmup_seconds, "--warmup-seconds", &PROFILE_WARMUP_SECONDS)?;
    let active_seconds = seconds(active_seconds, "--active-seconds", &PROFILE_ACTIVE_SECONDS)?;
    if scenario.tcp_request_bytes().is_some()
        && active_seconds > PROFILE_TCP_LATENCY_ACTIVE_MAX_SECONDS
    {
        return Err("TCP request-response active lifetime exceeds 60 seconds".to_owned());
    }
    if scenario == ProfileScenario::TcpScale10k && (warmup_seconds != 10 || active_seconds != 30) {
        return Err("tcp-scale-10k requires exactly 10 warmup and 30 active seconds".to_owned());
    }
    let (repository_root, binary_dir) = match (selected_repository_root, binary_dir) {
        (None, None) => (
            repository_root()?
                .canonicalize()
                .map_err(|_| "profile repository root is unavailable".to_owned())?,
            std::env::current_exe()
                .map_err(clean_io)?
                .parent()
                .expect("qualification profile directory")
                .canonicalize()
                .map_err(|_| "profile binary directory is unavailable".to_owned())?,
        ),
        (Some(root), Some(binaries)) => {
            let root = PathBuf::from(root);
            let binaries = PathBuf::from(binaries);
            if !root.is_absolute() || !binaries.is_absolute() {
                return Err("--repository-root and --binary-dir must be absolute paths".to_owned());
            }
            let root = root
                .canonicalize()
                .map_err(|_| "--repository-root must name an existing directory".to_owned())?;
            let binaries = binaries
                .canonicalize()
                .map_err(|_| "--binary-dir must name an existing directory".to_owned())?;
            let expected_binaries = ["profiling", "debug"]
                .into_iter()
                .filter_map(|profile| root.join("target").join(profile).canonicalize().ok())
                .any(|expected| expected == binaries);
            if !root.is_dir()
                || !binaries.is_dir()
                || !binaries.starts_with(&root)
                || !expected_binaries
            {
                return Err(
                    "--binary-dir must be --repository-root/target/profiling or target/debug"
                        .to_owned(),
                );
            }
            (root, binaries)
        }
        _ => {
            return Err("--repository-root and --binary-dir must be supplied together".to_owned());
        }
    };
    let raw_values = [
        output.is_some(),
        parent_sha.is_some(),
        candidate_sha.is_some(),
        member.is_some(),
        raw_pair.is_some(),
        order.is_some(),
        build_profile.is_some(),
        unit.is_some(),
        runner_image.is_some(),
        producer_source_sha256.is_some(),
        controller_source_sha256.is_some(),
        semantic_recipe_sha256.is_some(),
        evidence_bundle_sha256.is_some(),
    ];
    let raw = if raw_values.iter().all(|present| !present) {
        None
    } else if raw_values.iter().all(|present| *present) {
        let text = |value: OsString, name: &str| {
            value
                .into_string()
                .map_err(|_| format!("{name} is not UTF-8"))
        };
        let parent_sha = text(parent_sha.expect("complete raw args"), "--parent-sha")?;
        let candidate_sha = text(candidate_sha.expect("complete raw args"), "--candidate-sha")?;
        for (name, sha) in [
            ("--parent-sha", &parent_sha),
            ("--candidate-sha", &candidate_sha),
        ] {
            if sha.len() != 40
                || !sha
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(format!("{name} must be a lowercase 40-character SHA"));
            }
        }
        let bounded_number = |value: OsString, name: &str, maximum: u8| {
            let value = text(value, name)?;
            value
                .parse::<u8>()
                .ok()
                .filter(|value| (1..=maximum).contains(value))
                .ok_or_else(|| format!("{name} is outside its finite bound"))
        };
        let build_profile = text(build_profile.expect("complete raw args"), "--build-profile")?;
        if !matches!(
            build_profile.as_str(),
            "current" | "thin" | "fat" | "fat-cgu1" | "source-normalized"
        ) {
            return Err("--build-profile is outside the registered M18 matrix".to_owned());
        }
        let unit = text(unit.expect("complete raw args"), "--unit")?;
        if unit != scenario.unit() {
            return Err("--unit does not match the selected scenario".to_owned());
        }
        let runner_image = text(runner_image.expect("complete raw args"), "--runner-image")?;
        if runner_image != "ubuntu-24.04" {
            return Err("--runner-image is outside the registered environment".to_owned());
        }
        let digest = |value: OsString, name: &str| {
            let value = text(value, name)?;
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(format!("{name} must be a lowercase SHA-256 digest"));
            }
            Ok(value)
        };
        Some(ProfileRawArgs {
            output: PathBuf::from(output.expect("complete raw args")),
            parent_sha,
            candidate_sha,
            member: ProfileMember::parse(&member.expect("complete raw args"))?,
            pair: bounded_number(raw_pair.expect("complete raw args"), "--pair", 6)?,
            order: bounded_number(order.expect("complete raw args"), "--order", 2)?,
            build_profile,
            unit,
            runner_image,
            producer_source_sha256: digest(
                producer_source_sha256.expect("complete raw args"),
                "--producer-source-sha256",
            )?,
            controller_source_sha256: digest(
                controller_source_sha256.expect("complete raw args"),
                "--controller-source-sha256",
            )?,
            semantic_recipe_sha256: digest(
                semantic_recipe_sha256.expect("complete raw args"),
                "--semantic-recipe-sha256",
            )?,
            evidence_bundle_sha256: digest(
                evidence_bundle_sha256.expect("complete raw args"),
                "--evidence-bundle-sha256",
            )?,
        })
    } else {
        return Err("raw profile options must be supplied as one complete set".to_owned());
    };
    Ok(ProfileArgs {
        scenario,
        warmup_seconds,
        active_seconds,
        ready_file,
        repository_root,
        binary_dir,
        raw,
    })
}

pub(super) struct ReadyFile {
    pub(super) path: Option<PathBuf>,
}

impl ReadyFile {
    pub(super) fn publish(
        path: &Path,
        scenario: ProfileScenario,
        client_pid: u32,
        server_pid: Option<u32>,
        warmup_seconds: u64,
        active_seconds: u64,
    ) -> Result<Self, String> {
        let parent = path
            .parent()
            .ok_or_else(|| "profile ready file has no parent".to_owned())?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(clean_io)?;
        write!(
            temporary,
            "scenario={}\nclient_pid={}\nserver_pid={}\nwarmup_seconds={}\nactive_seconds={}\n",
            scenario.label(),
            client_pid,
            server_pid.map_or_else(|| "none".to_owned(), |pid| pid.to_string()),
            warmup_seconds,
            active_seconds,
        )
        .map_err(clean_io)?;
        temporary.flush().map_err(clean_io)?;
        #[cfg(unix)]
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(clean_io)?;
        temporary.as_file().sync_all().map_err(clean_io)?;
        fs::hard_link(temporary.path(), path).map_err(|_| {
            "profile ready file already exists or could not be published".to_owned()
        })?;
        if let Err(error) = temporary.close() {
            let _ = fs::remove_file(path);
            return Err(clean_io(error));
        }
        Ok(Self {
            path: Some(path.to_path_buf()),
        })
    }

    pub(super) fn remove(mut self) -> Result<(), String> {
        let path = self.path.take().expect("ready file owner");
        fs::remove_file(path).map_err(clean_io)
    }
}

impl Drop for ReadyFile {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

pub(super) fn resolve_profile_ready_file(
    repository: &Path,
    relative: &Path,
) -> Result<PathBuf, String> {
    let root = repository.join("profiles");
    if fs::symlink_metadata(&root).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err("profiles/ must not be a symlink".to_owned());
    }
    fs::create_dir_all(&root).map_err(clean_io)?;
    let root = root.canonicalize().map_err(clean_io)?;
    let requested = repository.join(relative);
    let parent = requested
        .parent()
        .ok_or_else(|| "profile ready file has no parent".to_owned())?;
    fs::create_dir_all(parent).map_err(clean_io)?;
    let parent = parent.canonicalize().map_err(clean_io)?;
    if !parent.starts_with(&root) {
        return Err("profile ready file escaped profiles/".to_owned());
    }
    #[cfg(unix)]
    {
        fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).map_err(clean_io)?;
        fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).map_err(clean_io)?;
    }
    Ok(parent.join(
        requested
            .file_name()
            .ok_or_else(|| "profile ready file has no name".to_owned())?,
    ))
}

pub(super) struct ProfileOutcome {
    pub(super) summary: String,
    pub(super) metric: &'static str,
    pub(super) value: u64,
    pub(super) checked_units: u64,
    pub(super) p99_nanoseconds: Option<u64>,
    pub(super) io_completions: u64,
    pub(super) scale_json: Option<String>,
}

pub(super) struct ProfileRawIdentity {
    pub(super) sha: String,
    pub(super) tree: String,
    pub(super) runner_sha256: String,
    pub(super) client_sha256: String,
    pub(super) server_sha256: String,
    pub(super) rustc: String,
    pub(super) kernel: String,
    pub(super) cpu_model: String,
    pub(super) cpu_count: usize,
    pub(super) memory_kib: u64,
}

impl ProfileRawIdentity {
    pub(super) fn load(
        raw: &ProfileRawArgs,
        root: &Path,
        binary_dir: &Path,
    ) -> Result<Self, String> {
        let git = |identity, args: &[&str]| {
            probe_text(
                identity,
                "git",
                ["-C", root.to_str().ok_or("repository root is not UTF-8")?]
                    .into_iter()
                    .chain(args.iter().copied()),
                PROBE_TIMEOUT,
            )
        };
        let sha = first_line(&git("profile checkout HEAD probe", &["rev-parse", "HEAD"])?);
        let expected = match raw.member {
            ProfileMember::Parent => &raw.parent_sha,
            ProfileMember::Candidate => &raw.candidate_sha,
        };
        if &sha != expected {
            return Err("profile checkout HEAD does not match selected member SHA".to_owned());
        }
        if !git(
            "profile checkout status probe",
            &["status", "--porcelain=v1"],
        )?
        .is_empty()
        {
            return Err("profile checkout is dirty before generated writes".to_owned());
        }
        let tree = first_line(&git(
            "profile checkout tree probe",
            &["rev-parse", "HEAD^{tree}"],
        )?);
        let rustc = first_line(&probe_text(
            "profile Rust version probe",
            "rustc",
            ["--version"],
            PROBE_TIMEOUT,
        )?);
        if !rustc.starts_with("rustc 1.97.1 ") {
            return Err("profile Rust toolchain is not 1.97.1".to_owned());
        }
        let kernel = first_line(&probe_text(
            "profile kernel identity probe",
            "uname",
            ["-srvmo"],
            PROBE_TIMEOUT,
        )?);
        let (memory_kib, cpu_model) = linux_capacity()?;
        let cpu_count = thread::available_parallelism()
            .map_err(|_| "profile logical CPU count is unavailable".to_owned())?
            .get();
        let runner = std::env::current_exe().map_err(clean_io)?;
        let client = profile_binary(binary_dir, "ferrum2-client")?;
        let server = profile_binary(binary_dir, "ferrum2-server")?;
        Ok(Self {
            sha,
            tree,
            runner_sha256: sha256("profile runner SHA-256 probe", &runner)?,
            client_sha256: sha256("profile client SHA-256 probe", &client)?,
            server_sha256: sha256("profile server SHA-256 probe", &server)?,
            rustc,
            kernel,
            cpu_model,
            cpu_count,
            memory_kib,
        })
    }
}

pub(super) fn profile_raw_prefix(arguments: &ProfileArgs, raw: &ProfileRawArgs) -> String {
    format!(
        "\"schema_version\":{PROFILE_TRIAL_SCHEMA_VERSION},\
         \"kind\":\"m18_profile_trial\",\"parent_sha\":{},\"candidate_sha\":{},\
         \"member\":{},\"pair\":{},\"order\":{},\"build_profile\":{},\"scenario\":{},\
         \"warmup_seconds\":{},\"active_seconds\":{},\"topology\":{},\
         \"application_payload_bytes\":{},\"socks_datagram_bytes\":{},\
         \"upstream_wire_bytes\":{},\"unit\":{},\"producer_source_sha256\":{},\
         \"controller_source_sha256\":{},\"semantic_recipe_sha256\":{},\
         \"evidence_bundle_sha256\":{}",
        json(&raw.parent_sha),
        json(&raw.candidate_sha),
        json(raw.member.label()),
        raw.pair,
        raw.order,
        json(&raw.build_profile),
        json(arguments.scenario.label()),
        arguments.warmup_seconds,
        arguments.active_seconds,
        json(arguments.scenario.topology_label()),
        arguments.scenario.application_payload_bytes(),
        arguments
            .scenario
            .socks_datagram_bytes()
            .map_or_else(|| "null".to_owned(), |value| value.to_string()),
        arguments
            .scenario
            .upstream_wire_bytes()
            .map_or_else(|| "null".to_owned(), |value| value.to_string()),
        json(&raw.unit),
        json(&raw.producer_source_sha256),
        json(&raw.controller_source_sha256),
        json(&raw.semantic_recipe_sha256),
        json(&raw.evidence_bundle_sha256),
    )
}
