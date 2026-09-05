use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ferrum2_dns::{
    DnsAddressRecords, DnsCache, DnsCacheAnswer, DnsCacheKey, DnsCacheQtype, DnsServerId,
    ResolverGeneration,
};

use crate::cli::{QualificationError, Result};
use crate::match_set::srs::canonical;
use crate::measurement::allocation::{allocation_region, finish_build};
use crate::measurement::statistics::measurement;
use crate::measurement::timing::benchmark;
use crate::report::Measurement;
use crate::route_program::scaled_iterations;

pub(crate) fn run_dns_cache(
    rule_sizes: &[usize],
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<()> {
    for &count in rule_sizes {
        let allocation_region = allocation_region();
        let started = Instant::now();
        let capacity = NonZeroUsize::new(count.saturating_add(1))
            .ok_or_else(|| QualificationError::new("DNS cache capacity overflow"))?;
        let cache = DnsCache::try_new(capacity)
            .map_err(|error| QualificationError::new(format!("DNS cache build failed: {error}")))?;
        let now = Instant::now();
        let mut hit_key = None;
        for index in 0..count {
            let key = DnsCacheKey::new(
                DnsServerId::new(3),
                canonical(&format!("cache-{index}.bench.invalid"))?,
                DnsCacheQtype::A,
                ResolverGeneration::new(1),
            );
            cache
                .insert_positive(
                    key.clone(),
                    DnsAddressRecords::A(Arc::from([Ipv4Addr::new(192, 0, 2, 9)])),
                    Duration::from_secs(60),
                    now,
                )
                .map_err(|error| {
                    QualificationError::new(format!("DNS cache insert failed: {error}"))
                })?;
            hit_key = Some(key);
        }
        let hit_key = hit_key.ok_or_else(|| QualificationError::new("empty DNS cache scale"))?;
        let miss_key = DnsCacheKey::new(
            DnsServerId::new(3),
            canonical("cache-miss.bench.invalid")?,
            DnsCacheQtype::A,
            ResolverGeneration::new(1),
        );
        let build = finish_build(started, &allocation_region)?;
        for (case, key, expected) in [
            ("cache_hit", &hit_key, 1_u64),
            ("cache_miss", &miss_key, 0_u64),
        ] {
            let read_cache = || match cache.get(key, now) {
                Ok(Some(DnsCacheAnswer::Positive(_))) => 1,
                Ok(Some(DnsCacheAnswer::Negative)) => 2,
                Ok(None) => 0,
                Err(_) => u64::MAX,
            };
            if read_cache() != expected {
                return Err(QualificationError::new(format!(
                    "DNS {case}/{count} correctness check failed"
                )));
            }
            let result = benchmark(read_cache, samples, base_iterations);
            measurements.push(measurement(
                format!("dns_policy/cache/{count}/{case}"),
                "dns_policy",
                "cache",
                case,
                count,
                None,
                None,
                base_iterations,
                build,
                Some(count),
                result,
            ));
        }
        run_cache_writes(count, samples, base_iterations, measurements)?;
    }
    Ok(())
}

/// Measures steady-state writes at capacity, with prebuilt request identities.
/// Time includes the cache lock, expiry maintenance, replacement, and eviction.
/// The fixed clock prevents elapsed benchmark time from changing the workload.
fn run_cache_writes(
    count: usize,
    samples: usize,
    base_iterations: u64,
    measurements: &mut Vec<Measurement>,
) -> Result<()> {
    for (case, key_count) in [("cache_fifo_insert", count + 1), ("cache_refresh", count)] {
        let keys = (0..key_count)
            .map(|index| {
                Ok(DnsCacheKey::new(
                    DnsServerId::new(3),
                    canonical(&format!("write-{index}.bench.invalid"))?,
                    DnsCacheQtype::A,
                    ResolverGeneration::new(1),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let records = DnsAddressRecords::A(Arc::from([Ipv4Addr::new(192, 0, 2, 9)]));
        let now = Instant::now();
        let ttl = Duration::from_secs(60);
        let allocation_region = allocation_region();
        let started = Instant::now();
        let capacity = NonZeroUsize::new(count)
            .ok_or_else(|| QualificationError::new("empty DNS cache write scale"))?;
        let cache = DnsCache::try_new(capacity)
            .map_err(|_| QualificationError::new("DNS cache write build failed"))?;
        for key in keys.iter().take(count) {
            cache
                .insert_positive(key.clone(), records.clone(), ttl, now)
                .map_err(|_| QualificationError::new("DNS cache write setup failed"))?;
        }
        let build = finish_build(started, &allocation_region)?;
        let iterations = scaled_iterations(base_iterations, 1, count);
        let mut index = count % key_count;
        let mut failed = false;
        let result = benchmark(
            || {
                failed |= cache
                    .insert_positive(keys[index].clone(), records.clone(), ttl, now)
                    .is_err();
                index = (index + 1) % key_count;
                u64::from(!failed)
            },
            samples,
            iterations,
        );
        let latest = (index + key_count - 1) % key_count;
        if failed
            || cache.entry_count(now).ok() != Some(count)
            || cache.get(&keys[latest], now).ok()
                != Some(Some(DnsCacheAnswer::Positive(records.clone())))
        {
            return Err(QualificationError::new(
                "DNS cache write correctness failed",
            ));
        }
        // The next key in the rotating over-capacity set must have been evicted.
        if key_count > count && cache.get(&keys[index], now).ok() != Some(None) {
            return Err(QualificationError::new(
                "DNS cache FIFO write eviction failed",
            ));
        }
        measurements.push(measurement(
            format!("dns_policy/cache/{count}/{case}"),
            "dns_policy",
            "cache",
            case,
            count,
            None,
            None,
            iterations,
            build,
            Some(count),
            result,
        ));
    }
    Ok(())
}
