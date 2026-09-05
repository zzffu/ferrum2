//! Bounded latency sampling and nearest-rank summaries shared by TCP and UDP.

#[derive(Debug, Eq, PartialEq)]
pub(super) struct LatencyPercentiles {
    pub(super) p50: u64,
    pub(super) p95: u64,
    pub(super) p99: u64,
    pub(super) samples: usize,
}

pub(super) fn latency_percentiles(
    mut values: Vec<u64>,
    name: &str,
) -> Result<LatencyPercentiles, String> {
    if values.is_empty() {
        return Err(format!("{name} has no latency samples"));
    }
    values.sort_unstable();
    let percentile = |percent: usize| {
        let rank = values
            .len()
            .checked_mul(percent)
            .ok_or_else(|| format!("{name} percentile rank overflow"))?
            .div_ceil(100);
        Ok::<u64, String>(values[rank - 1])
    };
    Ok(LatencyPercentiles {
        p50: percentile(50)?,
        p95: percentile(95)?,
        p99: percentile(99)?,
        samples: values.len(),
    })
}

pub(super) fn record_latency_sample(
    samples: &mut Vec<u64>,
    observed: u64,
    latency: u64,
    capacity: usize,
) -> Result<(), String> {
    if capacity == 0 {
        return Err("latency sample capacity is zero".to_owned());
    }
    if samples.len() < capacity {
        samples.push(latency);
        return Ok(());
    }
    let range = observed
        .checked_add(1)
        .ok_or_else(|| "latency observation count overflow".to_owned())?;
    let mut mixed = observed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^= mixed >> 31;
    let replacement = mixed % range;
    if replacement < capacity as u64 {
        samples[replacement as usize] = latency;
    }
    Ok(())
}
