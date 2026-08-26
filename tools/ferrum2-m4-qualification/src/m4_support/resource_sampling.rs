use std::fs::{self, File};
use std::io::Read;
use std::net::{SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use super::dns_resource::{DNS_RESOURCE_SAMPLES, DNS_RSS_WINDOW, validate_dns_owner_bound};
use super::process_support::{
    ProcessGuard, STARTUP_TIMEOUT, active_metric, join_unit_workers, json, remaining,
    socks_connect, spawn_worker,
};
use super::{DRAIN_TIMEOUT, RESOURCE_SESSIONS, SETUP_WORKERS};

const SMAPS_ROLLUP_CAP: usize = 64 * 1024;

pub(super) fn validate_thp_profile(path: &Path) -> Result<(), String> {
    let profile = fs::read_to_string(path)
        .map_err(|_| "THP max_ptes_none profile is unavailable".to_owned())?;
    let value = profile
        .strip_suffix('\n')
        .ok_or_else(|| "THP max_ptes_none profile is malformed".to_owned())?;
    if value == "0" {
        return Ok(());
    }
    if value
        .as_bytes()
        .first()
        .is_some_and(|byte| matches!(*byte, b'1'..=b'9'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("THP max_ptes_none profile is not zero".to_owned());
    }
    Err("THP max_ptes_none profile is malformed".to_owned())
}

pub(super) fn establish_sessions(
    proxy: SocketAddrV4,
    target: SocketAddrV4,
) -> Result<Vec<TcpStream>, String> {
    let next = Arc::new(AtomicUsize::new(0));
    let (sender, receiver) = mpsc::sync_channel(SETUP_WORKERS);
    let mut workers = Vec::with_capacity(SETUP_WORKERS);
    for _ in 0..SETUP_WORKERS {
        let worker_next = Arc::clone(&next);
        let worker_sender = sender.clone();
        let worker = spawn_worker(move || {
            loop {
                let index = worker_next.fetch_add(1, Ordering::Relaxed);
                if index >= RESOURCE_SESSIONS {
                    break;
                }
                let result = socks_connect(proxy, target, Instant::now() + STARTUP_TIMEOUT);
                if worker_sender.send((index, result)).is_err() {
                    break;
                }
            }
            Ok::<(), String>(())
        });
        match worker {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                next.store(RESOURCE_SESSIONS, Ordering::Relaxed);
                drop(sender);
                let _ = join_unit_workers(workers);
                return Err(error);
            }
        }
    }
    drop(sender);
    let mut streams: Vec<Option<TcpStream>> = (0..RESOURCE_SESSIONS).map(|_| None).collect();
    let mut first_error = None;
    for _ in 0..RESOURCE_SESSIONS {
        let Ok((index, result)) = receiver.recv() else {
            first_error
                .get_or_insert_with(|| "setup workers ended before 10000 results".to_owned());
            break;
        };
        match result {
            Ok(stream) => streams[index] = Some(stream),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        };
    }
    join_unit_workers(workers)?;
    if let Some(error) = first_error {
        return Err(error);
    }
    streams
        .into_iter()
        .map(|stream| stream.ok_or_else(|| "session setup result is missing".to_owned()))
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProcessSample {
    pub(super) active: u64,
    pub(super) fds: u64,
    pub(super) tasks: u64,
    pub(super) rss_kib: u64,
    pub(super) smaps_rss_kib: u64,
    pub(super) anonymous_kib: u64,
    pub(super) anon_huge_pages_kib: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PairSample {
    pub(super) client: ProcessSample,
    pub(super) server: ProcessSample,
}

impl PairSample {
    pub(super) fn json(self, index: usize) -> String {
        format!(
            "{{\"kind\":\"resource_sample\",\"sample\":{index},\
             \"client_active\":{},\"server_active\":{},\"client_fds\":{},\
             \"server_fds\":{},\"client_tasks\":{},\"server_tasks\":{},\
             \"client_rss_kib\":{},\"server_rss_kib\":{},\
             \"client_smaps_rss_kib\":{},\"server_smaps_rss_kib\":{},\
             \"client_anonymous_kib\":{},\"server_anonymous_kib\":{},\
             \"client_anon_huge_pages_kib\":{},\"server_anon_huge_pages_kib\":{}}}",
            self.client.active,
            self.server.active,
            self.client.fds,
            self.server.fds,
            self.client.tasks,
            self.server.tasks,
            self.client.rss_kib,
            self.server.rss_kib,
            self.client.smaps_rss_kib,
            self.server.smaps_rss_kib,
            self.client.anonymous_kib,
            self.server.anonymous_kib,
            self.client.anon_huge_pages_kib,
            self.server.anon_huge_pages_kib,
        )
    }
}

pub(super) fn sample_pair(
    client: &mut ProcessGuard,
    server: &mut ProcessGuard,
    client_metrics: SocketAddrV4,
    server_metrics: SocketAddrV4,
    deadline: Instant,
) -> Result<PairSample, String> {
    client.ensure_running()?;
    server.ensure_running()?;
    let client_proc = proc_sample(client.id())?;
    let server_proc = proc_sample(server.id())?;
    let client_active = active_metric(client_metrics, deadline)?;
    let server_active = active_metric(server_metrics, deadline)?;
    let sample = PairSample {
        client: ProcessSample {
            active: client_active,
            ..client_proc
        },
        server: ProcessSample {
            active: server_active,
            ..server_proc
        },
    };
    remaining(deadline)?;
    Ok(sample)
}

pub(super) fn proc_sample(pid: u32) -> Result<ProcessSample, String> {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let fds = fs::read_dir(root.join("fd"))
        .map_err(|_| "process fd state is unavailable".to_owned())?
        .count() as u64;
    let tasks = fs::read_dir(root.join("task"))
        .map_err(|_| "process task state is unavailable".to_owned())?
        .count() as u64;
    let status = fs::read_to_string(root.join("status"))
        .map_err(|_| "process RSS state is unavailable".to_owned())?;
    let rss_kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:")?.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| "process RSS state is malformed".to_owned())?;
    let precise = read_smaps_rollup(&root.join("smaps_rollup"))?;
    Ok(ProcessSample {
        active: 0,
        fds,
        tasks,
        rss_kib,
        smaps_rss_kib: precise.rss_kib,
        anonymous_kib: precise.anonymous_kib,
        anon_huge_pages_kib: precise.anon_huge_pages_kib,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PreciseRss {
    pub(super) rss_kib: u64,
    pub(super) anonymous_kib: u64,
    pub(super) anon_huge_pages_kib: u64,
}

pub(super) fn read_smaps_rollup(path: &Path) -> Result<PreciseRss, String> {
    let file =
        File::open(path).map_err(|_| "process precise RSS state is unavailable".to_owned())?;
    let mut bytes = Vec::with_capacity(SMAPS_ROLLUP_CAP + 1);
    file.take((SMAPS_ROLLUP_CAP + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "process precise RSS state could not be read".to_owned())?;
    if bytes.len() > SMAPS_ROLLUP_CAP {
        return Err("process precise RSS state exceeds bound".to_owned());
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "process precise RSS state is not UTF-8".to_owned())?;
    parse_smaps_rollup(text)
}

pub(super) fn parse_smaps_rollup(text: &str) -> Result<PreciseRss, String> {
    let value = |label, name| {
        let mut matches = text.lines().filter_map(|line| line.strip_prefix(label));
        let Some(line) = matches.next() else {
            return Err(format!("process precise RSS state is missing {name}"));
        };
        if matches.next().is_some() {
            return Err(format!("process precise RSS state duplicates {name}"));
        }
        let mut fields = line.split_whitespace();
        let value = fields.next().unwrap_or_default();
        let unit = fields.next().unwrap_or_default();
        if value.is_empty() || unit.is_empty() || fields.next().is_some() {
            return Err(format!("process precise RSS state has malformed {name}"));
        }
        if unit != "kB" {
            return Err(format!(
                "process precise RSS state has wrong unit for {name}"
            ));
        }
        if !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!("process precise RSS state has malformed {name}"));
        }
        value
            .parse()
            .map_err(|_| format!("process precise RSS state overflows {name}"))
    };
    Ok(PreciseRss {
        rss_kib: value("Rss:", "Rss")?,
        anonymous_kib: value("Anonymous:", "Anonymous")?,
        anon_huge_pages_kib: value("AnonHugePages:", "AnonHugePages")?,
    })
}

pub(super) fn wait_for_sessions(
    client: &mut ProcessGuard,
    server: &mut ProcessGuard,
    client_metrics: SocketAddrV4,
    server_metrics: SocketAddrV4,
) -> Result<PairSample, String> {
    let deadline = Instant::now() + DRAIN_TIMEOUT;
    loop {
        let sample = sample_pair(client, server, client_metrics, server_metrics, deadline)?;
        if sample.client.active == RESOURCE_SESSIONS as u64
            && sample.server.active == RESOURCE_SESSIONS as u64
        {
            return Ok(sample);
        }
        thread::sleep(remaining(deadline)?.min(Duration::from_millis(100)));
    }
}

pub(super) fn validate_owner_tuple(
    sample: &PairSample,
    first: &PairSample,
    sessions: u64,
) -> Result<(), String> {
    let tuple = |sample: &PairSample| {
        (
            sample.client.active,
            sample.server.active,
            sample.client.fds,
            sample.server.fds,
            sample.client.tasks,
            sample.server.tasks,
        )
    };
    if sample.client.active != sessions
        || sample.server.active != sessions
        || tuple(sample) != tuple(first)
    {
        return Err("owner/task tuple changed".to_owned());
    }
    Ok(())
}

pub(super) struct RssVerdict {
    pub(super) window: usize,
    pub(super) client_median_twice: u64,
    pub(super) server_median_twice: u64,
    pub(super) client_smaps_rss_median_twice: u64,
    pub(super) server_smaps_rss_median_twice: u64,
    pub(super) client_anonymous_median_twice: u64,
    pub(super) server_anonymous_median_twice: u64,
    pub(super) client_anon_huge_pages_median_twice: u64,
    pub(super) server_anon_huge_pages_median_twice: u64,
}

impl RssVerdict {
    pub(super) fn json(&self) -> String {
        self.json_for("rss_window", None)
    }

    pub(super) fn dns_json(&self, phase: &str) -> String {
        self.json_for("dns_rss_window", Some(phase))
    }

    pub(super) fn json_for(&self, kind: &str, phase: Option<&str>) -> String {
        let phase = phase
            .map(|phase| format!("\"phase\":{},", json(phase)))
            .unwrap_or_default();
        format!(
            "{{\"kind\":{},{phase}\"window\":{},\"client_median_twice_kib\":{},\
             \"server_median_twice_kib\":{},\"client_smaps_rss_median_twice_kib\":{},\
             \"server_smaps_rss_median_twice_kib\":{},\
             \"client_anonymous_median_twice_kib\":{},\
             \"server_anonymous_median_twice_kib\":{},\
             \"client_anon_huge_pages_median_twice_kib\":{},\
             \"server_anon_huge_pages_median_twice_kib\":{},\
             \"limit_percent\":105,\"status\":\"PASS\"}}",
            json(kind),
            self.window,
            self.client_median_twice,
            self.server_median_twice,
            self.client_smaps_rss_median_twice,
            self.server_smaps_rss_median_twice,
            self.client_anonymous_median_twice,
            self.server_anonymous_median_twice,
            self.client_anon_huge_pages_median_twice,
            self.server_anon_huge_pages_median_twice,
        )
    }
}

pub(super) fn validate_samples(
    samples: &[PairSample],
    expected: usize,
    window_size: usize,
    sessions: u64,
) -> Result<Vec<RssVerdict>, String> {
    if samples.len() != expected || window_size == 0 || expected != window_size * 6 {
        return Err("sample set is incomplete".to_owned());
    }
    let first = samples[0];
    for sample in samples {
        validate_owner_tuple(sample, &first, sessions)?;
    }
    validate_rss_windows(samples, window_size)
}

pub(super) fn validate_dns_samples(
    samples: &[PairSample],
    idle: &PairSample,
) -> Result<Vec<RssVerdict>, String> {
    if samples.len() != DNS_RESOURCE_SAMPLES
        || DNS_RSS_WINDOW == 0
        || DNS_RESOURCE_SAMPLES != DNS_RSS_WINDOW * 6
    {
        return Err("DNS sample set is incomplete".to_owned());
    }
    for sample in samples {
        validate_dns_owner_bound(sample, idle)?;
    }
    validate_rss_windows(samples, DNS_RSS_WINDOW)
}

pub(super) fn validate_rss_windows(
    samples: &[PairSample],
    window_size: usize,
) -> Result<Vec<RssVerdict>, String> {
    if samples.len() != window_size * 6 || window_size == 0 {
        return Err("RSS sample set is incomplete".to_owned());
    }
    let mut client_vmrss = [0; 6];
    let mut server_vmrss = [0; 6];
    let mut client_smaps_rss = [0; 6];
    let mut server_smaps_rss = [0; 6];
    let mut client_anonymous = [0; 6];
    let mut server_anonymous = [0; 6];
    let mut client_anon_huge_pages = [0; 6];
    let mut server_anon_huge_pages = [0; 6];
    for (index, window) in samples.chunks_exact(window_size).enumerate() {
        client_vmrss[index] = median_twice(window.iter().map(|sample| sample.client.rss_kib))?;
        server_vmrss[index] = median_twice(window.iter().map(|sample| sample.server.rss_kib))?;
        client_smaps_rss[index] =
            median_twice(window.iter().map(|sample| sample.client.smaps_rss_kib))?;
        server_smaps_rss[index] =
            median_twice(window.iter().map(|sample| sample.server.smaps_rss_kib))?;
        client_anonymous[index] =
            median_twice(window.iter().map(|sample| sample.client.anonymous_kib))?;
        server_anonymous[index] =
            median_twice(window.iter().map(|sample| sample.server.anonymous_kib))?;
        client_anon_huge_pages[index] = median_twice(
            window
                .iter()
                .map(|sample| sample.client.anon_huge_pages_kib),
        )?;
        server_anon_huge_pages[index] = median_twice(
            window
                .iter()
                .map(|sample| sample.server.anon_huge_pages_kib),
        )?;
    }
    if let Some(index) = (0..6).find(|&index| {
        u128::from(client_vmrss[index]) * 100 > u128::from(client_vmrss[0]) * 105
            || u128::from(server_vmrss[index]) * 100 > u128::from(server_vmrss[0]) * 105
    }) {
        return Err(format!(
            "RSS window {} exceeds 105 percent: first_failing_window={} \
             client_vmrss_median_twice_kib={client_vmrss:?} \
             server_vmrss_median_twice_kib={server_vmrss:?} \
             client_smaps_rss_median_twice_kib={client_smaps_rss:?} \
             server_smaps_rss_median_twice_kib={server_smaps_rss:?} \
             client_anonymous_median_twice_kib={client_anonymous:?} \
             server_anonymous_median_twice_kib={server_anonymous:?} \
             client_anon_huge_pages_median_twice_kib={client_anon_huge_pages:?} \
             server_anon_huge_pages_median_twice_kib={server_anon_huge_pages:?}",
            index + 1,
            index + 1,
        ));
    }
    Ok((0..6)
        .map(|index| RssVerdict {
            window: index + 1,
            client_median_twice: client_vmrss[index],
            server_median_twice: server_vmrss[index],
            client_smaps_rss_median_twice: client_smaps_rss[index],
            server_smaps_rss_median_twice: server_smaps_rss[index],
            client_anonymous_median_twice: client_anonymous[index],
            server_anonymous_median_twice: server_anonymous[index],
            client_anon_huge_pages_median_twice: client_anon_huge_pages[index],
            server_anon_huge_pages_median_twice: server_anon_huge_pages[index],
        })
        .collect())
}

pub(super) fn median_twice(values: impl Iterator<Item = u64>) -> Result<u64, String> {
    let mut values: Vec<_> = values.collect();
    if values.is_empty() || values.len() % 2 != 0 {
        return Err("RSS window must contain a positive even sample count".to_owned());
    }
    values.sort_unstable();
    let middle = values.len() / 2;
    values[middle - 1]
        .checked_add(values[middle])
        .ok_or_else(|| "RSS median overflow".to_owned())
}

pub(super) fn validate_drain(sample: &PairSample, baseline: &PairSample) -> Result<(), String> {
    if sample.client.active != 0
        || sample.server.active != 0
        || sample.client.fds != baseline.client.fds
        || sample.server.fds != baseline.server.fds
        || sample.client.tasks != baseline.client.tasks
        || sample.server.tasks != baseline.server.tasks
    {
        return Err("drain is incomplete".to_owned());
    }
    Ok(())
}
