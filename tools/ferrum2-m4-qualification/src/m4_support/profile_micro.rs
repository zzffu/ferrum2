use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ferrum2_core::CanonicalDomain;
use ferrum2_dns::{
    DnsAddressRecords, DnsCache, DnsCacheKey, DnsCacheQtype, DnsServerId, ResolverGeneration,
};
use ferrum2_shadowsocks::UdpReplayWindow;

use super::profile_contract::{
    PROFILE_TCP_LATENCY_SAMPLE_CAP, ProfileArgs, ProfileOutcome, ReadyFile,
};
use super::profile_structural::StructuralMetrics;
use super::throughput::{percentile_99, rate_per_second};

pub(super) fn run_profile_replay(
    arguments: &ProfileArgs,
    ready_file: &Path,
) -> Result<ProfileOutcome, String> {
    let warmup = Duration::from_secs(arguments.warmup_seconds);
    let active = Duration::from_secs(arguments.active_seconds);
    let start = Instant::now();
    let warm_end = start + warmup;
    let active_end = warm_end + active;
    let mut replay = UdpReplayWindow::new();
    let mut packet_id = 0_u64;
    while Instant::now() < warm_end {
        replay
            .commit(packet_id)
            .map_err(|_| "profile replay warmup rejected a sequential ID".to_owned())?;
        packet_id = packet_id
            .checked_add(1)
            .ok_or_else(|| "profile replay packet ID overflow".to_owned())?;
    }
    let ready = ReadyFile::publish(
        ready_file,
        arguments.scenario,
        std::process::id(),
        None,
        arguments.warmup_seconds,
        arguments.active_seconds,
    )?;
    let mut operations = 0_u64;
    let mut words_touched = 0_u64;
    while Instant::now() < active_end {
        replay
            .commit(packet_id)
            .map_err(|_| "profile replay rejected a sequential ID".to_owned())?;
        packet_id = packet_id
            .checked_add(1)
            .ok_or_else(|| "profile replay packet ID overflow".to_owned())?;
        operations = operations
            .checked_add(1)
            .ok_or_else(|| "profile replay operation count overflow".to_owned())?;
        words_touched = words_touched
            .checked_add(u64::from(replay.last_advance_word_clears()))
            .ok_or_else(|| "profile replay work count overflow".to_owned())?;
    }
    ready.remove()?;
    if operations == 0 {
        return Err("profile replay completed no operations".to_owned());
    }
    Ok(ProfileOutcome {
        summary: format!(
            "m18_profile_workload_completion status=PASS scenario={} operations={operations} \
             replay_words_touched={words_touched} warmup_seconds={} active_seconds={} \
             drain=PASS rebind=PASS",
            arguments.scenario.label(),
            arguments.warmup_seconds,
            arguments.active_seconds,
        ),
        metric: "operations_per_second",
        value: rate_per_second(operations, active)?,
        checked_units: operations,
        p99_nanoseconds: None,
        io_completions: 0,
        scale_json: None,
        structural_metrics: StructuralMetrics::replay(words_touched, 0),
    })
}

pub(super) fn run_profile_dns_cache(
    arguments: &ProfileArgs,
    ready_file: &Path,
) -> Result<ProfileOutcome, String> {
    let capacity = arguments
        .scenario
        .dns_cache_capacity()
        .expect("DNS cache profile capacity");
    let cache = DnsCache::try_new(NonZeroUsize::new(capacity).expect("positive cache capacity"))
        .map_err(|error| format!("profile DNS cache construction failed: {error}"))?;
    let scan_before = cache
        .work_snapshot()
        .map_err(|error| format!("profile DNS cache snapshot failed: {error}"))?
        .cache_scan_entries;
    let keys = (0..capacity)
        .map(|index| {
            let name = CanonicalDomain::new(&format!("cache-{index}.profile.invalid"))
                .map_err(|_| "profile DNS cache key is invalid".to_owned())?;
            Ok(DnsCacheKey::new(
                DnsServerId::new(1),
                name,
                DnsCacheQtype::A,
                ResolverGeneration::new(1),
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let records = DnsAddressRecords::A(Arc::from([Ipv4Addr::new(192, 0, 2, 1)]));
    let ttl = Duration::from_secs(3_600);
    for key in &keys {
        cache_operation(&cache, key, &records, ttl)?;
    }
    for index in 0..capacity.saturating_add(2) {
        cache_operation(&cache, &keys[index % capacity], &records, ttl)?;
    }
    let warmup = Duration::from_secs(arguments.warmup_seconds);
    let active = Duration::from_secs(arguments.active_seconds);
    let start = Instant::now();
    let warm_end = start + warmup;
    let active_end = warm_end + active;
    let mut index = 0_usize;
    while Instant::now() < warm_end {
        cache_operation(&cache, &keys[index], &records, ttl)?;
        index = (index + 1) % capacity;
    }
    let ready = ReadyFile::publish(
        ready_file,
        arguments.scenario,
        std::process::id(),
        None,
        arguments.warmup_seconds,
        arguments.active_seconds,
    )?;
    let mut operations = 0_u64;
    let mut latencies = Vec::with_capacity(PROFILE_TCP_LATENCY_SAMPLE_CAP.min(65_536));
    while Instant::now() < active_end {
        let operation_start = Instant::now();
        cache_operation(&cache, &keys[index], &records, ttl)?;
        let elapsed = u64::try_from(operation_start.elapsed().as_nanos())
            .map_err(|_| "profile DNS cache latency overflow".to_owned())?;
        if latencies.len() < PROFILE_TCP_LATENCY_SAMPLE_CAP {
            latencies.push(elapsed);
        }
        operations = operations
            .checked_add(1)
            .ok_or_else(|| "profile DNS cache operation count overflow".to_owned())?;
        index = (index + 1) % capacity;
    }
    ready.remove()?;
    if operations == 0 || latencies.is_empty() {
        return Err("profile DNS cache completed no operations".to_owned());
    }
    let scan_after = cache
        .work_snapshot()
        .map_err(|error| format!("profile DNS cache snapshot failed: {error}"))?
        .cache_scan_entries;
    let cache_scan_entries = scan_after
        .checked_sub(scan_before)
        .ok_or_else(|| "profile DNS cache work counter regressed".to_owned())?;
    let p99_nanoseconds = percentile_99(latencies)?;
    Ok(ProfileOutcome {
        summary: format!(
            "m18_profile_workload_completion status=PASS scenario={} capacity={capacity} \
             operations={operations} p99_nanoseconds={p99_nanoseconds} \
             cache_scan_entries={cache_scan_entries} warmup_seconds={} active_seconds={} \
             drain=PASS rebind=PASS",
            arguments.scenario.label(),
            arguments.warmup_seconds,
            arguments.active_seconds,
        ),
        metric: "p99_nanoseconds",
        value: p99_nanoseconds,
        checked_units: operations,
        p99_nanoseconds: Some(p99_nanoseconds),
        io_completions: 0,
        scale_json: None,
        structural_metrics: StructuralMetrics::cache(cache_scan_entries),
    })
}

fn cache_operation(
    cache: &DnsCache,
    key: &DnsCacheKey,
    records: &DnsAddressRecords,
    ttl: Duration,
) -> Result<(), String> {
    let now = Instant::now();
    cache
        .insert_positive(key.clone(), records.clone(), ttl, now)
        .map_err(|error| format!("profile DNS cache insert failed: {error}"))?;
    if cache
        .get(key, now)
        .map_err(|error| format!("profile DNS cache lookup failed: {error}"))?
        .is_none()
    {
        return Err("profile DNS cache lost a freshly inserted entry".to_owned());
    }
    Ok(())
}
