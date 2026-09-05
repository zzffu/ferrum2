//! Fixed admission windows with complete accounting for the final in-flight work.

use super::diagnostic::{TCP_FAIRNESS_FLOWS, TCP_FAIRNESS_PAYLOAD};
use serde_json::{Value, json};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MeasuredWork {
    pub(super) checked_units: u64,
    /// Completed strictly after the admission deadline, in checked-unit units.
    pub(super) tail_checked_units: u64,
    /// Common admission start through max(admission deadline, last completion).
    /// This does not substitute for the separately captured process CPU window.
    pub(super) elapsed: Duration,
}

/// The deadline stops new work, while admitted work retains its complete result
/// and latency. Minimum coverage is checked afterward; it never extends admission.
pub(super) struct ActiveWorkWindow {
    active: Duration,
    measured: MeasuredWork,
}

impl ActiveWorkWindow {
    pub(super) fn new(active: Duration) -> Self {
        Self {
            active,
            measured: MeasuredWork {
                checked_units: 0,
                tail_checked_units: 0,
                elapsed: active,
            },
        }
    }

    pub(super) fn admits(&self, started: Duration) -> bool {
        started < self.active
    }

    pub(super) fn complete(
        &mut self,
        started: Duration,
        completed: Duration,
        units: u64,
    ) -> Result<(), String> {
        if !self.admits(started) || completed < started || units == 0 {
            return Err("active-window completion is invalid".to_owned());
        }
        let checked_units = self
            .measured
            .checked_units
            .checked_add(units)
            .ok_or_else(|| "active-window checked count overflow".to_owned())?;
        let tail_checked_units = self
            .measured
            .tail_checked_units
            .checked_add(if completed > self.active { units } else { 0 })
            .ok_or_else(|| "active-window tail count overflow".to_owned())?;
        self.measured = MeasuredWork {
            checked_units,
            tail_checked_units,
            elapsed: self.measured.elapsed.max(completed),
        };
        Ok(())
    }

    pub(super) fn finish(self, minimum: u64, name: &str) -> Result<MeasuredWork, String> {
        if self.measured.checked_units < minimum {
            return Err(format!(
                "{name} correctness coverage is below minimum: checked_units={} minimum={minimum} tail_checked_units={} active_elapsed_nanoseconds={}",
                self.measured.checked_units,
                self.measured.tail_checked_units,
                self.measured.elapsed.as_nanos(),
            ));
        }
        Ok(self.measured)
    }
}

pub(super) fn elapsed_nanoseconds(elapsed: Duration) -> Result<u64, String> {
    u64::try_from(elapsed.as_nanos()).map_err(|_| "active elapsed time overflow".to_owned())
}

pub(super) fn combine_flows(flows: &[MeasuredWork]) -> Result<MeasuredWork, String> {
    flows.iter().try_fold(
        MeasuredWork {
            checked_units: 0,
            tail_checked_units: 0,
            elapsed: Duration::ZERO,
        },
        |combined, flow| {
            Ok(MeasuredWork {
                checked_units: combined
                    .checked_units
                    .checked_add(flow.checked_units)
                    .ok_or_else(|| "fairness checked count overflow".to_owned())?,
                tail_checked_units: combined
                    .tail_checked_units
                    .checked_add(flow.tail_checked_units)
                    .ok_or_else(|| "fairness tail count overflow".to_owned())?,
                elapsed: combined.elapsed.max(flow.elapsed),
            })
        },
    )
}

pub(super) fn elapsed_rate(units: u64, elapsed: Duration, name: &str) -> Result<u64, String> {
    let nanos = elapsed.as_nanos();
    if units == 0 || nanos == 0 {
        return Err(format!("{name} has no measured work"));
    }
    let rate = u128::from(units)
        .checked_mul(1_000_000_000)
        .ok_or_else(|| format!("{name} rate numerator overflow"))?
        / nanos;
    u64::try_from(rate.max(1)).map_err(|_| format!("{name} rate overflow"))
}

pub(super) fn fairness_measurements(values: &[MeasuredWork]) -> Result<Value, String> {
    if values.len() != TCP_FAIRNESS_FLOWS || values.iter().any(|value| value.checked_units == 0) {
        return Err("fairness workload requires every flow to complete work".to_owned());
    }
    let measured = combine_flows(values)?;
    let values = values
        .iter()
        .map(|flow| flow.checked_units)
        .collect::<Vec<_>>();
    let sum = values.iter().try_fold(0_u128, |sum, value| {
        sum.checked_add(u128::from(*value))
            .ok_or_else(|| "fairness sum overflow".to_owned())
    })?;
    let checked_bytes =
        u64::try_from(sum).map_err(|_| "fairness checked byte count overflow".to_owned())?;
    if checked_bytes % (TCP_FAIRNESS_PAYLOAD as u64) != 0 {
        return Err("fairness transaction accounting is not payload aligned".to_owned());
    }
    let transactions = checked_bytes / (TCP_FAIRNESS_PAYLOAD as u64);
    let io_completions = transactions
        .checked_mul(2)
        .ok_or_else(|| "fairness I/O completion count overflow".to_owned())?;
    let squares = values.iter().try_fold(0_u128, |sum, value| {
        let value = u128::from(*value);
        sum.checked_add(
            value
                .checked_mul(value)
                .ok_or_else(|| "fairness square overflow".to_owned())?,
        )
        .ok_or_else(|| "fairness square sum overflow".to_owned())
    })?;
    let numerator = sum
        .checked_mul(sum)
        .and_then(|value| value.checked_mul(1_000_000_000))
        .ok_or_else(|| "fairness numerator overflow".to_owned())?;
    let denominator = (TCP_FAIRNESS_FLOWS as u128)
        .checked_mul(squares)
        .ok_or_else(|| "fairness denominator overflow".to_owned())?;
    let jain_ppb =
        u64::try_from(numerator / denominator).map_err(|_| "fairness index overflow".to_owned())?;
    Ok(json!({
        "measurements": {
            "fairness": jain_ppb,
            "aggregate_throughput": elapsed_rate(checked_bytes, measured.elapsed, "fairness throughput")?,
            "active_elapsed_nanoseconds": elapsed_nanoseconds(measured.elapsed)?,
            "tail_checked_units": measured.tail_checked_units,
            "io_completions": io_completions
        },
        "checked_units": checked_bytes,
        "checks": {
            "all_256_flows_ready": true,
            "all_256_flows_nonzero": true,
            "payload_exact": true,
            "no_gso": true
        }
    }))
}
