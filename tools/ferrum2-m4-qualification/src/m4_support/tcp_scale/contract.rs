use crate::m4_support::resource_sampling::PairSample;
use serde::Serialize;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::Barrier;

pub(crate) const SCALE_PAYLOAD_BYTES: usize = 32_768;
pub(crate) const FRAME_MAGIC: [u8; 8] = *b"F2SCL001";
pub(crate) const FRAME_FLOW_OFFSET: usize = FRAME_MAGIC.len();
pub(crate) const FRAME_GENERATION_OFFSET: usize = FRAME_FLOW_OFFSET + std::mem::size_of::<u64>();
pub(crate) const FRAME_SEQUENCE_OFFSET: usize = FRAME_GENERATION_OFFSET + std::mem::size_of::<u8>();
pub(crate) const FRAME_HEADER_BYTES: usize = FRAME_SEQUENCE_OFFSET + std::mem::size_of::<u64>();

pub(crate) const SESSIONS: usize = 10_000;
pub(crate) const PARTIAL_ACTIVE_FLOWS: usize = 1_000;
pub(crate) const PARTIAL_SELECTOR_MODULUS: usize = 10;
pub(crate) const PARTIAL_SELECTOR_REMAINDER: usize = 0;
pub(crate) const TOUCH_ROUNDS: usize = 2;
pub(crate) const RUNTIME_WORKER_THREADS: usize = 4;
pub(crate) const RESOURCE_SAMPLES_PER_PHASE: usize = 5;
pub(crate) const ACTIVE_SAMPLE_SLOT_DENOMINATOR: usize = RESOURCE_SAMPLES_PER_PHASE + 1;
pub(crate) const RESOURCE_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
pub(crate) const SCALE_IO_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const SCALE_PHASE_GRACE: Duration = Duration::from_secs(120);
pub(crate) const SCALE_START_LEAD: Duration = Duration::from_secs(2);
pub(crate) const SCALE_SETUP_IO_SLICE: Duration = Duration::from_secs(5);
pub(crate) const SCALE_SETUP_SESSION_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const SCALE_SCHEMA_VERSION: u8 = 1;
pub(crate) const MINIMUM_MEMORY_AVAILABLE_KIB: u64 = 8_000_000;
pub(crate) const MINIMUM_NOFILE_SOFT: u64 = 65_536;

#[derive(Serialize)]
pub(crate) struct ScaleEvidence {
    pub(crate) schema_version: u8,
    pub(crate) recipe: ScaleRecipe,
    pub(crate) correctness: ScaleCorrectness,
    pub(crate) traffic: ScaleTraffic,
    pub(crate) fairness: ScaleFairness,
    pub(crate) resource: ScaleResource,
}

#[derive(Serialize)]
pub(crate) struct ScaleRecipe {
    pub(crate) sessions: u64,
    pub(crate) setup_workers: u64,
    pub(crate) runtime_worker_threads: u64,
    pub(crate) application_futures: u64,
    pub(crate) target_futures: u64,
    pub(crate) payload_bytes: u64,
    pub(crate) touch_rounds: u64,
    pub(crate) partial_active_flows: u64,
    pub(crate) partial_selector_modulus: u64,
    pub(crate) partial_selector_remainder: u64,
    pub(crate) partial_seconds: u64,
    pub(crate) full_seconds: u64,
    pub(crate) resource_samples_per_phase: u64,
    pub(crate) quiescent_sample_interval_milliseconds: u64,
    pub(crate) active_sample_slot_denominator: u64,
}

#[derive(Serialize)]
pub(crate) struct ScaleCorrectness {
    pub(crate) target_accepted: u64,
    pub(crate) client_active: u64,
    pub(crate) server_active: u64,
    pub(crate) touch_completed_flows: u64,
    pub(crate) touch_completed_round_trips: u64,
    pub(crate) touch_checked_bytes: u64,
    pub(crate) payload_checks: u64,
    pub(crate) partial_nonzero_flows: u64,
    pub(crate) full_nonzero_flows: u64,
    pub(crate) application_tasks_joined: u64,
    pub(crate) target_tasks_joined: u64,
    pub(crate) drain: &'static str,
    pub(crate) rebind: &'static str,
    pub(crate) cleanup: &'static str,
}

#[derive(Serialize)]
pub(crate) struct ScaleTraffic {
    pub(crate) partial_checked_bytes: u64,
    pub(crate) partial_io_completions: u64,
    pub(crate) partial_discarded_tail_completions: u64,
    pub(crate) partial_flow_bytes: Vec<u64>,
    pub(crate) full_checked_bytes: u64,
    pub(crate) full_io_completions: u64,
    pub(crate) full_discarded_tail_completions: u64,
    pub(crate) full_elapsed_nanoseconds: u64,
    pub(crate) full_flow_bytes: Vec<u64>,
    pub(crate) full_flow_completions: Vec<u64>,
    pub(crate) aggregate_bytes_per_second: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ScaleFairness {
    pub(crate) jain_ppb: u64,
    pub(crate) minimum_bytes: u64,
    pub(crate) p01_bytes: u64,
    pub(crate) p05_bytes: u64,
    pub(crate) median_bytes: u64,
    pub(crate) p95_bytes: u64,
    pub(crate) p99_bytes: u64,
    pub(crate) maximum_bytes: u64,
    pub(crate) p01_to_median_ppm: u64,
}

#[derive(Serialize)]
pub(crate) struct ScaleResource {
    pub(crate) pre_load: Vec<ScalePairSample>,
    pub(crate) established: Vec<ScalePairSample>,
    pub(crate) touched: Vec<ScalePairSample>,
    pub(crate) partial_active: Vec<ScalePairSample>,
    pub(crate) full_active: Vec<ScalePairSample>,
    pub(crate) post_full: Vec<ScalePairSample>,
    pub(crate) drained: Vec<ScalePairSample>,
    pub(crate) client_touched_increment_bytes_per_connection: i64,
    pub(crate) server_touched_increment_bytes_per_connection: i64,
    pub(crate) combined_touched_increment_bytes_per_connection: i64,
    pub(crate) harness_peak_rss_kib: u64,
    pub(crate) memory_available_kib: u64,
    pub(crate) nofile_soft: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ScalePairSample {
    pub(crate) client_active: u64,
    pub(crate) server_active: u64,
    pub(crate) client_fds: u64,
    pub(crate) server_fds: u64,
    pub(crate) client_tasks: u64,
    pub(crate) server_tasks: u64,
    pub(crate) client_rss_kib: u64,
    pub(crate) server_rss_kib: u64,
    pub(crate) client_smaps_rss_kib: u64,
    pub(crate) server_smaps_rss_kib: u64,
    pub(crate) client_anonymous_kib: u64,
    pub(crate) server_anonymous_kib: u64,
    pub(crate) client_anon_huge_pages_kib: u64,
    pub(crate) server_anon_huge_pages_kib: u64,
    pub(crate) harness_rss_kib: u64,
}

impl ScalePairSample {
    pub(crate) fn observed(sample: PairSample, harness_rss_kib: u64) -> Self {
        Self {
            client_active: sample.client.active,
            server_active: sample.server.active,
            client_fds: sample.client.fds,
            server_fds: sample.server.fds,
            client_tasks: sample.client.tasks,
            server_tasks: sample.server.tasks,
            client_rss_kib: sample.client.rss_kib,
            server_rss_kib: sample.server.rss_kib,
            client_smaps_rss_kib: sample.client.smaps_rss_kib,
            server_smaps_rss_kib: sample.server.smaps_rss_kib,
            client_anonymous_kib: sample.client.anonymous_kib,
            server_anonymous_kib: sample.server.anonymous_kib,
            client_anon_huge_pages_kib: sample.client.anon_huge_pages_kib,
            server_anon_huge_pages_kib: sample.server.anon_huge_pages_kib,
            harness_rss_kib,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PhaseKind {
    Touch,
    Partial,
    Full,
}

impl PhaseKind {
    pub(crate) const fn selected(self, index: usize) -> bool {
        match self {
            Self::Touch | Self::Full => true,
            Self::Partial => index % PARTIAL_SELECTOR_MODULUS == PARTIAL_SELECTOR_REMAINDER,
        }
    }

    pub(crate) const fn expected(self) -> usize {
        match self {
            Self::Touch | Self::Full => SESSIONS,
            Self::Partial => PARTIAL_ACTIVE_FLOWS,
        }
    }
}

pub(crate) struct Phase {
    pub(crate) generation: u8,
    pub(crate) kind: PhaseKind,
    pub(crate) duration: Option<Duration>,
    pub(crate) first: Barrier,
    pub(crate) second: Barrier,
    pub(crate) started: OnceLock<Instant>,
    pub(crate) deadline: OnceLock<Instant>,
}

impl Phase {
    pub(crate) fn new(generation: u8, kind: PhaseKind, duration: Option<Duration>) -> Arc<Self> {
        let participants = kind.expected() + 1;
        Arc::new(Self {
            generation,
            kind,
            duration,
            first: Barrier::new(participants),
            second: Barrier::new(participants),
            started: OnceLock::new(),
            deadline: OnceLock::new(),
        })
    }

    pub(crate) async fn prepare_release(&self) -> Result<Instant, String> {
        tokio::time::timeout(SCALE_IO_TIMEOUT, self.first.wait())
            .await
            .map_err(|_| "scale first phase barrier timed out".to_owned())?;
        let started = Instant::now() + SCALE_START_LEAD;
        self.started
            .set(started)
            .map_err(|_| "scale phase start was set twice".to_owned())?;
        if let Some(duration) = self.duration {
            self.deadline
                .set(started + duration)
                .map_err(|_| "scale phase deadline was set twice".to_owned())?;
        }
        tokio::time::timeout(SCALE_IO_TIMEOUT, self.second.wait())
            .await
            .map_err(|_| "scale second phase barrier timed out".to_owned())?;
        if Instant::now() >= started {
            return Err("scale coordinator missed the common phase start".to_owned());
        }
        Ok(started)
    }

    pub(crate) async fn release(&self) -> Result<Instant, String> {
        let started = self.prepare_release().await?;
        tokio::time::sleep_until(started.into()).await;
        Ok(started)
    }
}

#[derive(Clone)]
pub(crate) enum ScaleCommand {
    Idle,
    Run(Arc<Phase>),
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FlowResult {
    pub(crate) generation: u8,
    pub(crate) index: usize,
    pub(crate) bytes: u64,
    pub(crate) completions: u64,
    pub(crate) discarded_tail_completions: u64,
}

pub(crate) struct CollectedPhase {
    pub(crate) flow_bytes: Vec<u64>,
    pub(crate) flow_completions: Vec<u64>,
    pub(crate) checked_bytes: u64,
    pub(crate) completions: u64,
    pub(crate) discarded_tail_completions: u64,
}

pub(crate) struct ExecutionResult {
    pub(crate) established: Vec<ScalePairSample>,
    pub(crate) touched: Vec<ScalePairSample>,
    pub(crate) partial_active: Vec<ScalePairSample>,
    pub(crate) full_active: Vec<ScalePairSample>,
    pub(crate) post_full: Vec<ScalePairSample>,
    pub(crate) touch: CollectedPhase,
    pub(crate) partial: CollectedPhase,
    pub(crate) full: CollectedPhase,
    pub(crate) full_elapsed: Duration,
    pub(crate) application_tasks_joined: usize,
    pub(crate) target_tasks_joined: usize,
    pub(crate) harness_peak_rss_kib: u64,
}

pub(crate) fn checked_sum(values: &[u64], name: &str) -> Result<u64, String> {
    values.iter().try_fold(0_u64, |sum, value| {
        sum.checked_add(*value)
            .ok_or_else(|| format!("{name} overflow"))
    })
}

pub(crate) fn nearest_rank(sorted: &[u64], percentile: usize) -> Result<u64, String> {
    if sorted.is_empty() || !(1..=100).contains(&percentile) {
        return Err("scale percentile input is invalid".to_owned());
    }
    let rank = sorted
        .len()
        .checked_mul(percentile)
        .and_then(|value| value.checked_add(99))
        .ok_or_else(|| "scale percentile rank overflow".to_owned())?
        / 100;
    Ok(sorted[rank - 1])
}

pub(crate) fn fairness_median(sorted: &[u64]) -> Result<u64, String> {
    if sorted.is_empty() || !sorted.len().is_multiple_of(2) {
        return Err("scale fairness median requires a nonempty even vector".to_owned());
    }
    let upper = sorted.len() / 2;
    sorted[upper - 1]
        .checked_add(sorted[upper])
        .ok_or_else(|| "scale fairness median overflow".to_owned())
        .map(|sum| sum / 2)
}

pub(crate) fn fairness(values: &[u64]) -> Result<ScaleFairness, String> {
    if values.len() != SESSIONS {
        return Err("scale fairness requires exactly 10000 flows".to_owned());
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let sum = values.iter().try_fold(0_u128, |sum, value| {
        sum.checked_add(u128::from(*value))
            .ok_or_else(|| "scale fairness sum overflow".to_owned())
    })?;
    let squares = values.iter().try_fold(0_u128, |total, value| {
        let value = u128::from(*value);
        total
            .checked_add(
                value
                    .checked_mul(value)
                    .ok_or_else(|| "scale fairness square overflow".to_owned())?,
            )
            .ok_or_else(|| "scale fairness square sum overflow".to_owned())
    })?;
    let denominator = u128::try_from(values.len())
        .expect("flow count fits u128")
        .checked_mul(squares)
        .ok_or_else(|| "scale fairness denominator overflow".to_owned())?;
    let jain_numerator = sum
        .checked_mul(sum)
        .and_then(|value| value.checked_mul(1_000_000_000))
        .ok_or_else(|| "scale Jain numerator overflow".to_owned())?;
    let jain_ppb = jain_numerator.checked_div(denominator).unwrap_or(0);
    let p01 = nearest_rank(&sorted, 1)?;
    let median = fairness_median(&sorted)?;
    let p01_to_median_ppm = if median == 0 {
        0
    } else {
        u128::from(p01)
            .checked_mul(1_000_000)
            .ok_or_else(|| "scale tail ratio overflow".to_owned())?
            / u128::from(median)
    };
    Ok(ScaleFairness {
        jain_ppb: u64::try_from(jain_ppb).map_err(|_| "scale Jain result overflow".to_owned())?,
        minimum_bytes: sorted[0],
        p01_bytes: p01,
        p05_bytes: nearest_rank(&sorted, 5)?,
        median_bytes: median,
        p95_bytes: nearest_rank(&sorted, 95)?,
        p99_bytes: nearest_rank(&sorted, 99)?,
        maximum_bytes: *sorted.last().expect("nonempty fairness input"),
        p01_to_median_ppm: u64::try_from(p01_to_median_ppm)
            .map_err(|_| "scale tail ratio result overflow".to_owned())?,
    })
}

pub(crate) fn median(values: impl Iterator<Item = u64>) -> Result<u64, String> {
    let mut values: Vec<_> = values.collect();
    if values.is_empty() {
        return Err("scale median input is empty".to_owned());
    }
    values.sort_unstable();
    Ok(values[values.len() / 2])
}

pub(crate) fn per_connection_increment(
    established: &[ScalePairSample],
    touched: &[ScalePairSample],
    side: impl Fn(&ScalePairSample) -> u64 + Copy,
) -> Result<i64, String> {
    let established_kib = i128::from(median(established.iter().map(side))?);
    let touched_kib = i128::from(median(touched.iter().map(side))?);
    let bytes = touched_kib
        .checked_sub(established_kib)
        .and_then(|value| value.checked_mul(1024))
        .ok_or_else(|| "scale per-connection RSS delta overflow".to_owned())?
        / i128::try_from(SESSIONS).expect("session count fits i128");
    i64::try_from(bytes).map_err(|_| "scale per-connection RSS delta exceeds i64".to_owned())
}

pub(crate) fn initialize_payload() -> Arc<[u8]> {
    let mut payload = vec![0_u8; SCALE_PAYLOAD_BYTES];
    for (offset, byte) in payload.iter_mut().enumerate() {
        *byte = u8::try_from(offset.wrapping_mul(17) % 251).expect("payload pattern fits u8");
    }
    payload.into()
}

pub(crate) fn encode_frame_header(
    buffer: &mut [u8],
    flow_index: usize,
    generation: u8,
    sequence: u64,
) -> Result<(), String> {
    if buffer.len() != SCALE_PAYLOAD_BYTES {
        return Err("scale frame buffer length is invalid".to_owned());
    }
    let flow_index =
        u64::try_from(flow_index).map_err(|_| "scale frame flow index exceeds u64".to_owned())?;
    buffer[..FRAME_MAGIC.len()].copy_from_slice(&FRAME_MAGIC);
    buffer[FRAME_FLOW_OFFSET..FRAME_GENERATION_OFFSET].copy_from_slice(&flow_index.to_be_bytes());
    buffer[FRAME_GENERATION_OFFSET] = generation;
    buffer[FRAME_SEQUENCE_OFFSET..FRAME_HEADER_BYTES].copy_from_slice(&sequence.to_be_bytes());
    Ok(())
}

pub(crate) fn validate_frame(
    buffer: &[u8],
    body: &[u8],
    flow_index: usize,
    generation: u8,
    sequence: u64,
) -> Result<(), String> {
    if buffer.len() != SCALE_PAYLOAD_BYTES || body.len() != SCALE_PAYLOAD_BYTES {
        return Err("scale frame buffer length is invalid".to_owned());
    }
    let expected_flow =
        u64::try_from(flow_index).map_err(|_| "scale frame flow index exceeds u64".to_owned())?;
    let observed_flow = u64::from_be_bytes(
        buffer[FRAME_FLOW_OFFSET..FRAME_GENERATION_OFFSET]
            .try_into()
            .expect("scale flow header has fixed width"),
    );
    let observed_sequence = u64::from_be_bytes(
        buffer[FRAME_SEQUENCE_OFFSET..FRAME_HEADER_BYTES]
            .try_into()
            .expect("scale sequence header has fixed width"),
    );
    if buffer[..FRAME_MAGIC.len()] != FRAME_MAGIC
        || observed_flow != expected_flow
        || buffer[FRAME_GENERATION_OFFSET] != generation
        || observed_sequence != sequence
        || buffer[FRAME_HEADER_BYTES..] != body[FRAME_HEADER_BYTES..]
    {
        return Err("scale application payload identity mismatch".to_owned());
    }
    Ok(())
}
