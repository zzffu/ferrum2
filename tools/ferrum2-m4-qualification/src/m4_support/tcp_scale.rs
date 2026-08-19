use super::*;

use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::{Barrier, mpsc as tokio_mpsc, watch};
use tokio::task::JoinSet;

pub(super) const PAYLOAD_BYTES: usize = 32_768;
const FRAME_MAGIC: [u8; 8] = *b"F2SCL001";
const FRAME_FLOW_OFFSET: usize = FRAME_MAGIC.len();
const FRAME_GENERATION_OFFSET: usize = FRAME_FLOW_OFFSET + std::mem::size_of::<u64>();
const FRAME_SEQUENCE_OFFSET: usize = FRAME_GENERATION_OFFSET + std::mem::size_of::<u8>();
const FRAME_HEADER_BYTES: usize = FRAME_SEQUENCE_OFFSET + std::mem::size_of::<u64>();

const SESSIONS: usize = 10_000;
const PARTIAL_ACTIVE_FLOWS: usize = 1_000;
const PARTIAL_SELECTOR_MODULUS: usize = 10;
const PARTIAL_SELECTOR_REMAINDER: usize = 0;
const TOUCH_ROUNDS: usize = 2;
const RUNTIME_WORKER_THREADS: usize = 4;
const RESOURCE_SAMPLES_PER_PHASE: usize = 5;
const ACTIVE_SAMPLE_SLOT_DENOMINATOR: usize = RESOURCE_SAMPLES_PER_PHASE + 1;
const RESOURCE_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
const SCALE_IO_TIMEOUT: Duration = Duration::from_secs(30);
const SCALE_PHASE_GRACE: Duration = Duration::from_secs(120);
const SCALE_START_LEAD: Duration = Duration::from_secs(2);
const SCALE_SETUP_IO_SLICE: Duration = Duration::from_secs(5);
const SCALE_SETUP_SESSION_TIMEOUT: Duration = Duration::from_secs(15);
const SCALE_SCHEMA_VERSION: u8 = 1;
const MINIMUM_MEMORY_AVAILABLE_KIB: u64 = 8_000_000;
const MINIMUM_NOFILE_SOFT: u64 = 65_536;

#[derive(Serialize)]
struct ScaleEvidence {
    schema_version: u8,
    recipe: ScaleRecipe,
    correctness: ScaleCorrectness,
    traffic: ScaleTraffic,
    fairness: ScaleFairness,
    resource: ScaleResource,
}

#[derive(Serialize)]
struct ScaleRecipe {
    sessions: u64,
    setup_workers: u64,
    runtime_worker_threads: u64,
    application_futures: u64,
    target_futures: u64,
    payload_bytes: u64,
    touch_rounds: u64,
    partial_active_flows: u64,
    partial_selector_modulus: u64,
    partial_selector_remainder: u64,
    partial_seconds: u64,
    full_seconds: u64,
    resource_samples_per_phase: u64,
    quiescent_sample_interval_milliseconds: u64,
    active_sample_slot_denominator: u64,
}

#[derive(Serialize)]
struct ScaleCorrectness {
    target_accepted: u64,
    client_active: u64,
    server_active: u64,
    touch_completed_flows: u64,
    touch_completed_round_trips: u64,
    touch_checked_bytes: u64,
    payload_checks: u64,
    partial_nonzero_flows: u64,
    full_nonzero_flows: u64,
    application_tasks_joined: u64,
    target_tasks_joined: u64,
    drain: &'static str,
    rebind: &'static str,
    cleanup: &'static str,
}

#[derive(Serialize)]
struct ScaleTraffic {
    partial_checked_bytes: u64,
    partial_io_completions: u64,
    partial_discarded_tail_completions: u64,
    partial_flow_bytes: Vec<u64>,
    full_checked_bytes: u64,
    full_io_completions: u64,
    full_discarded_tail_completions: u64,
    full_elapsed_nanoseconds: u64,
    full_flow_bytes: Vec<u64>,
    full_flow_completions: Vec<u64>,
    aggregate_bytes_per_second: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct ScaleFairness {
    jain_ppb: u64,
    minimum_bytes: u64,
    p01_bytes: u64,
    p05_bytes: u64,
    median_bytes: u64,
    p95_bytes: u64,
    p99_bytes: u64,
    maximum_bytes: u64,
    p01_to_median_ppm: u64,
}

#[derive(Serialize)]
struct ScaleResource {
    pre_load: Vec<ScalePairSample>,
    established: Vec<ScalePairSample>,
    touched: Vec<ScalePairSample>,
    partial_active: Vec<ScalePairSample>,
    full_active: Vec<ScalePairSample>,
    post_full: Vec<ScalePairSample>,
    drained: Vec<ScalePairSample>,
    client_touched_increment_bytes_per_connection: i64,
    server_touched_increment_bytes_per_connection: i64,
    combined_touched_increment_bytes_per_connection: i64,
    harness_peak_rss_kib: u64,
    memory_available_kib: u64,
    nofile_soft: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct ScalePairSample {
    client_active: u64,
    server_active: u64,
    client_fds: u64,
    server_fds: u64,
    client_tasks: u64,
    server_tasks: u64,
    client_rss_kib: u64,
    server_rss_kib: u64,
    client_smaps_rss_kib: u64,
    server_smaps_rss_kib: u64,
    client_anonymous_kib: u64,
    server_anonymous_kib: u64,
    client_anon_huge_pages_kib: u64,
    server_anon_huge_pages_kib: u64,
    harness_rss_kib: u64,
}

impl ScalePairSample {
    fn observed(sample: PairSample, harness_rss_kib: u64) -> Self {
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
enum PhaseKind {
    Touch,
    Partial,
    Full,
}

impl PhaseKind {
    const fn selected(self, index: usize) -> bool {
        match self {
            Self::Touch | Self::Full => true,
            Self::Partial => index % PARTIAL_SELECTOR_MODULUS == PARTIAL_SELECTOR_REMAINDER,
        }
    }

    const fn expected(self) -> usize {
        match self {
            Self::Touch | Self::Full => SESSIONS,
            Self::Partial => PARTIAL_ACTIVE_FLOWS,
        }
    }
}

struct Phase {
    generation: u8,
    kind: PhaseKind,
    duration: Option<Duration>,
    first: Barrier,
    second: Barrier,
    started: OnceLock<Instant>,
    deadline: OnceLock<Instant>,
}

impl Phase {
    fn new(generation: u8, kind: PhaseKind, duration: Option<Duration>) -> Arc<Self> {
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

    async fn prepare_release(&self) -> Result<Instant, String> {
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

    async fn release(&self) -> Result<Instant, String> {
        let started = self.prepare_release().await?;
        tokio::time::sleep_until(started.into()).await;
        Ok(started)
    }
}

#[derive(Clone)]
enum ScaleCommand {
    Idle,
    Run(Arc<Phase>),
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FlowResult {
    generation: u8,
    index: usize,
    bytes: u64,
    completions: u64,
    discarded_tail_completions: u64,
}

struct CollectedPhase {
    flow_bytes: Vec<u64>,
    flow_completions: Vec<u64>,
    checked_bytes: u64,
    completions: u64,
    discarded_tail_completions: u64,
}

struct ExecutionResult {
    established: Vec<ScalePairSample>,
    touched: Vec<ScalePairSample>,
    partial_active: Vec<ScalePairSample>,
    full_active: Vec<ScalePairSample>,
    post_full: Vec<ScalePairSample>,
    touch: CollectedPhase,
    partial: CollectedPhase,
    full: CollectedPhase,
    full_elapsed: Duration,
    application_tasks_joined: usize,
    target_tasks_joined: usize,
    harness_peak_rss_kib: u64,
}

fn checked_sum(values: &[u64], name: &str) -> Result<u64, String> {
    values.iter().try_fold(0_u64, |sum, value| {
        sum.checked_add(*value)
            .ok_or_else(|| format!("{name} overflow"))
    })
}

fn nearest_rank(sorted: &[u64], percentile: usize) -> Result<u64, String> {
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

fn fairness_median(sorted: &[u64]) -> Result<u64, String> {
    if sorted.is_empty() || !sorted.len().is_multiple_of(2) {
        return Err("scale fairness median requires a nonempty even vector".to_owned());
    }
    let upper = sorted.len() / 2;
    sorted[upper - 1]
        .checked_add(sorted[upper])
        .ok_or_else(|| "scale fairness median overflow".to_owned())
        .map(|sum| sum / 2)
}

fn fairness(values: &[u64]) -> Result<ScaleFairness, String> {
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

fn median(values: impl Iterator<Item = u64>) -> Result<u64, String> {
    let mut values: Vec<_> = values.collect();
    if values.is_empty() {
        return Err("scale median input is empty".to_owned());
    }
    values.sort_unstable();
    Ok(values[values.len() / 2])
}

fn per_connection_increment(
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

fn initialize_payload() -> Arc<[u8]> {
    let mut payload = vec![0_u8; PAYLOAD_BYTES];
    for (offset, byte) in payload.iter_mut().enumerate() {
        *byte = u8::try_from(offset.wrapping_mul(17) % 251).expect("payload pattern fits u8");
    }
    payload.into()
}

fn encode_frame_header(
    buffer: &mut [u8],
    flow_index: usize,
    generation: u8,
    sequence: u64,
) -> Result<(), String> {
    if buffer.len() != PAYLOAD_BYTES {
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

fn validate_frame(
    buffer: &[u8],
    body: &[u8],
    flow_index: usize,
    generation: u8,
    sequence: u64,
) -> Result<(), String> {
    if buffer.len() != PAYLOAD_BYTES || body.len() != PAYLOAD_BYTES {
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

async fn round_trip(
    stream: &mut TokioTcpStream,
    buffer: &mut [u8],
    body: &[u8],
    flow_index: usize,
    generation: u8,
    sequence: &mut u64,
) -> Result<(), String> {
    let expected_sequence = sequence
        .checked_add(1)
        .ok_or_else(|| "scale application sequence overflow".to_owned())?;
    encode_frame_header(buffer, flow_index, generation, expected_sequence)?;
    tokio::time::timeout(SCALE_IO_TIMEOUT, async {
        stream.write_all(buffer).await.map_err(clean_io)?;
        stream.read_exact(buffer).await.map_err(clean_io)?;
        Ok::<(), String>(())
    })
    .await
    .map_err(|_| "scale application round trip timed out".to_owned())??;
    validate_frame(buffer, body, flow_index, generation, expected_sequence)?;
    *sequence = expected_sequence;
    Ok(())
}

async fn run_application_flow(
    index: usize,
    mut stream: TokioTcpStream,
    mut commands: watch::Receiver<ScaleCommand>,
    results: tokio_mpsc::Sender<FlowResult>,
    ready: tokio_mpsc::Sender<usize>,
    payload: Arc<[u8]>,
) -> Result<(), String> {
    // Copying the nonzero deterministic body pre-touches this flow's resident request/response
    // buffer before established-resource sampling. Each round mutates only its small header.
    let mut buffer = payload.to_vec();
    std::hint::black_box(&buffer);
    let mut sequence = 0_u64;
    ready
        .send(index)
        .await
        .map_err(|_| "scale application readiness owner ended early".to_owned())?;
    loop {
        commands
            .changed()
            .await
            .map_err(|_| "scale command owner ended early".to_owned())?;
        let command = commands.borrow_and_update().clone();
        match command {
            ScaleCommand::Idle => {}
            ScaleCommand::Shutdown => return Ok(()),
            ScaleCommand::Run(phase) if !phase.kind.selected(index) => {}
            ScaleCommand::Run(phase) => {
                tokio::time::timeout(SCALE_IO_TIMEOUT, phase.first.wait())
                    .await
                    .map_err(|_| "scale application first barrier timed out".to_owned())?;
                tokio::time::timeout(SCALE_IO_TIMEOUT, phase.second.wait())
                    .await
                    .map_err(|_| "scale application second barrier timed out".to_owned())?;
                let started = *phase
                    .started
                    .get()
                    .ok_or_else(|| "scale phase has no common start".to_owned())?;
                if Instant::now() >= started {
                    return Err("scale application missed the common phase start".to_owned());
                }
                tokio::time::sleep_until(started.into()).await;
                let mut bytes = 0_u64;
                let mut completions = 0_u64;
                let mut discarded_tail_completions = 0_u64;
                match phase.kind {
                    PhaseKind::Touch => {
                        for _ in 0..TOUCH_ROUNDS {
                            round_trip(
                                &mut stream,
                                &mut buffer,
                                &payload,
                                index,
                                phase.generation,
                                &mut sequence,
                            )
                            .await?;
                            bytes = bytes
                                .checked_add(PAYLOAD_BYTES as u64)
                                .ok_or_else(|| "scale touch byte count overflow".to_owned())?;
                            completions = completions
                                .checked_add(1)
                                .ok_or_else(|| "scale touch completion overflow".to_owned())?;
                        }
                    }
                    PhaseKind::Partial | PhaseKind::Full => {
                        let deadline = *phase
                            .deadline
                            .get()
                            .ok_or_else(|| "scale timed phase has no deadline".to_owned())?;
                        while Instant::now() < deadline {
                            round_trip(
                                &mut stream,
                                &mut buffer,
                                &payload,
                                index,
                                phase.generation,
                                &mut sequence,
                            )
                            .await?;
                            if Instant::now() <= deadline {
                                bytes =
                                    bytes.checked_add(PAYLOAD_BYTES as u64).ok_or_else(|| {
                                        "scale timed phase byte count overflow".to_owned()
                                    })?;
                                completions = completions.checked_add(1).ok_or_else(|| {
                                    "scale timed phase completion overflow".to_owned()
                                })?;
                            } else {
                                discarded_tail_completions = 1;
                            }
                        }
                    }
                }
                results
                    .send(FlowResult {
                        generation: phase.generation,
                        index,
                        bytes,
                        completions,
                        discarded_tail_completions,
                    })
                    .await
                    .map_err(|_| "scale result owner ended early".to_owned())?;
            }
        }
    }
}

async fn run_target_flow(
    index: usize,
    mut stream: TokioTcpStream,
    ready: tokio_mpsc::Sender<usize>,
) -> Result<(), String> {
    let mut buffer = vec![0_u8; PAYLOAD_BYTES];
    // Keep first-touch page faults out of the product page-touch and bulk phases.
    buffer.fill(0x5a);
    std::hint::black_box(&buffer);
    ready
        .send(index)
        .await
        .map_err(|_| "scale target readiness owner ended early".to_owned())?;
    loop {
        match stream.read_exact(&mut buffer).await {
            Ok(_) => {
                tokio::time::timeout(SCALE_IO_TIMEOUT, stream.write_all(&buffer))
                    .await
                    .map_err(|_| "scale target response timed out".to_owned())?
                    .map_err(clean_io)?;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(clean_io(error)),
        }
    }
}

async fn await_task_readiness(
    label: &str,
    expected: usize,
    receiver: &mut tokio_mpsc::Receiver<usize>,
    errors: &mut tokio_mpsc::UnboundedReceiver<String>,
) -> Result<(), String> {
    let deadline = Instant::now() + SCALE_PHASE_GRACE;
    let mut observed = vec![false; expected];
    let mut ready = 0_usize;
    while ready < expected {
        let index = tokio::select! {
            result = tokio::time::timeout_at(deadline.into(), receiver.recv()) => {
                result
                    .map_err(|_| format!("scale {label} readiness timed out"))?
                    .ok_or_else(|| format!("scale {label} readiness ended early"))?
            }
            error = errors.recv() => {
                return Err(error.unwrap_or_else(|| "scale task error channel ended early".to_owned()));
            }
        };
        let slot = observed
            .get_mut(index)
            .ok_or_else(|| format!("scale {label} readiness index is out of range"))?;
        if *slot {
            return Err(format!("scale {label} readiness index is duplicated"));
        }
        *slot = true;
        ready += 1;
    }
    Ok(())
}

fn expected_indices(kind: PhaseKind) -> impl Iterator<Item = usize> {
    (0..SESSIONS).filter(move |index| kind.selected(*index))
}

async fn collect_phase(
    phase: &Phase,
    receiver: &mut tokio_mpsc::Receiver<FlowResult>,
    errors: &mut tokio_mpsc::UnboundedReceiver<String>,
) -> Result<CollectedPhase, String> {
    let expected = phase.kind.expected();
    let deadline = Instant::now() + SCALE_PHASE_GRACE;
    let mut by_index = BTreeMap::new();
    while by_index.len() < expected {
        let result = tokio::select! {
            result = tokio::time::timeout_at(deadline.into(), receiver.recv()) => {
                result
                    .map_err(|_| "scale phase results timed out".to_owned())?
                    .ok_or_else(|| "scale phase result channel ended early".to_owned())?
            }
            error = errors.recv() => {
                return Err(error.unwrap_or_else(|| "scale task error channel ended early".to_owned()));
            }
        };
        if result.generation != phase.generation
            || !phase.kind.selected(result.index)
            || by_index.insert(result.index, result).is_some()
        {
            return Err("scale phase result identity is invalid or duplicated".to_owned());
        }
    }
    let actual: Vec<_> = by_index.keys().copied().collect();
    let expected_indices: Vec<_> = expected_indices(phase.kind).collect();
    if actual != expected_indices {
        return Err("scale phase result set is incomplete".to_owned());
    }
    let flow_bytes: Vec<_> = by_index.values().map(|result| result.bytes).collect();
    let flow_completions: Vec<_> = by_index.values().map(|result| result.completions).collect();
    if by_index
        .values()
        .any(|result| result.discarded_tail_completions > 1)
    {
        return Err("scale flow discarded more than one tail completion".to_owned());
    }
    let discarded_tail_completions = by_index.values().try_fold(0_u64, |sum, result| {
        sum.checked_add(result.discarded_tail_completions)
            .ok_or_else(|| "scale discarded tail completion sum overflow".to_owned())
    })?;
    let checked_bytes = checked_sum(&flow_bytes, "scale phase byte sum")?;
    let completions = checked_sum(&flow_completions, "scale phase completion sum")?;
    for (bytes, completions) in flow_bytes.iter().zip(&flow_completions) {
        let expected_bytes = completions
            .checked_mul(PAYLOAD_BYTES as u64)
            .ok_or_else(|| "scale phase byte/completion product overflow".to_owned())?;
        if *bytes != expected_bytes {
            return Err("scale phase byte/completion accounting is inconsistent".to_owned());
        }
    }
    Ok(CollectedPhase {
        flow_bytes,
        flow_completions,
        checked_bytes,
        completions,
        discarded_tail_completions,
    })
}

async fn join_tasks(
    tasks: &mut JoinSet<Result<(), String>>,
    expected: usize,
    label: &str,
    allow_cancelled: bool,
) -> Result<usize, String> {
    let joined = tokio::time::timeout(SCALE_PHASE_GRACE, async {
        let mut joined = 0_usize;
        let mut first_error = None;
        while let Some(result) = tasks.join_next().await {
            joined += 1;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    first_error.get_or_insert(error);
                }
                Err(error) if allow_cancelled && error.is_cancelled() => {}
                Err(error) => {
                    first_error.get_or_insert_with(|| format!("{label} task failed: {error}"));
                }
            }
        }
        if joined != expected {
            return Err(format!("{label} joined {joined} of {expected} tasks"));
        }
        first_error.map_or(Ok(joined), Err)
    })
    .await;
    match joined {
        Ok(result) => result,
        Err(_) => {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            Err(format!("{label} task join timed out"))
        }
    }
}

fn validate_phase_accounting(
    phase: &CollectedPhase,
    expected: usize,
    require_nonzero: bool,
) -> Result<(), String> {
    if phase.flow_bytes.len() != expected
        || phase.flow_completions.len() != expected
        || (require_nonzero && phase.flow_bytes.contains(&0))
        || phase.checked_bytes != checked_sum(&phase.flow_bytes, "phase bytes")?
        || phase.completions != checked_sum(&phase.flow_completions, "phase completions")?
    {
        return Err("scale phase accounting failed closed".to_owned());
    }
    Ok(())
}

fn bounded_parallel_setup<T, F>(
    sessions: usize,
    workers: usize,
    deadline: Instant,
    operation: F,
) -> Result<Vec<T>, String>
where
    T: Send + 'static,
    F: Fn(usize, Instant) -> Result<T, String> + Send + Sync + 'static,
{
    if sessions == 0 || workers == 0 || workers > sessions {
        return Err("scale setup bounds are invalid".to_owned());
    }
    let next = Arc::new(AtomicUsize::new(0));
    let cancel = Arc::new(AtomicBool::new(false));
    let operation = Arc::new(operation);
    let (sender, receiver) = mpsc::sync_channel(workers);
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let worker_next = Arc::clone(&next);
        let worker_cancel = Arc::clone(&cancel);
        let worker_operation = Arc::clone(&operation);
        let worker_sender = sender.clone();
        let handle = spawn_worker(move || {
            loop {
                if worker_cancel.load(Ordering::SeqCst) {
                    break;
                }
                let index = worker_next.fetch_add(1, Ordering::SeqCst);
                if index >= sessions {
                    break;
                }
                let result = worker_operation(index, deadline);
                if result.is_err() {
                    worker_cancel.store(true, Ordering::SeqCst);
                }
                if worker_sender.send((index, result)).is_err() {
                    break;
                }
            }
            Ok(())
        });
        match handle {
            Ok(handle) => handles.push(handle),
            Err(error) => {
                cancel.store(true, Ordering::SeqCst);
                drop(sender);
                drop(receiver);
                let joined = join_unit_workers(handles);
                return match joined {
                    Ok(()) => Err(error),
                    Err(join_error) => Err(format!("{error}; cleanup: {join_error}")),
                };
            }
        }
    }
    drop(sender);
    let mut values: Vec<Option<T>> = (0..sessions).map(|_| None).collect();
    let mut received = 0_usize;
    let mut first_error = None;
    while received < sessions {
        let timeout = match remaining(deadline) {
            Ok(timeout) => timeout.min(SCALE_SETUP_IO_SLICE),
            Err(error) => {
                first_error = Some(error);
                break;
            }
        };
        match receiver.recv_timeout(timeout) {
            Ok((index, Ok(value))) => {
                let Some(slot) = values.get_mut(index) else {
                    first_error = Some("scale setup index is out of range".to_owned());
                    break;
                };
                if slot.replace(value).is_some() {
                    first_error = Some("scale setup index is duplicated".to_owned());
                    break;
                }
                received += 1;
            }
            Ok((_index, Err(error))) => {
                first_error = Some(error);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if Instant::now() >= deadline {
                    first_error = Some("scale setup result timed out".to_owned());
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                first_error = Some("scale setup workers ended early".to_owned());
                break;
            }
        }
    }
    if first_error.is_some() {
        cancel.store(true, Ordering::SeqCst);
    }
    drop(receiver);
    let joined = join_unit_workers(handles);
    if let Some(error) = first_error {
        return match joined {
            Ok(()) => Err(error),
            Err(join_error) => Err(format!("{error}; cleanup: {join_error}")),
        };
    }
    joined?;
    values
        .into_iter()
        .map(|value| value.ok_or_else(|| "scale setup result is missing".to_owned()))
        .collect()
}

fn scale_setup_io_timeout_at(now: Instant, deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(now)
        .filter(|duration| !duration.is_zero())
        .map(|duration| duration.min(SCALE_SETUP_IO_SLICE))
        .ok_or_else(|| "scale setup I/O deadline expired".to_owned())
}

fn scale_setup_io_timeout(deadline: Instant) -> Result<Duration, String> {
    scale_setup_io_timeout_at(Instant::now(), deadline)
}

fn scale_write_all(stream: &mut TcpStream, bytes: &[u8], deadline: Instant) -> Result<(), String> {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        stream
            .set_write_timeout(Some(scale_setup_io_timeout(deadline)?))
            .map_err(clean_io)?;
        match stream.write(&bytes[offset..]) {
            Ok(0) => {
                return Err(clean_io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "scale setup socket wrote zero bytes",
                )));
            }
            Ok(written) => offset += written,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(clean_io(error)),
        }
    }
    Ok(())
}

fn scale_read_exact(
    stream: &mut TcpStream,
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), String> {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        stream
            .set_read_timeout(Some(scale_setup_io_timeout(deadline)?))
            .map_err(clean_io)?;
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => {
                return Err(clean_io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "scale setup socket ended early",
                )));
            }
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(clean_io(error)),
        }
    }
    Ok(())
}

fn scale_socks_connect(
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    deadline: Instant,
) -> Result<TcpStream, String> {
    let timeout = scale_setup_io_timeout(deadline)?;
    let mut stream =
        TcpStream::connect_timeout(&SocketAddr::V4(proxy), timeout).map_err(clean_io)?;
    scale_write_all(&mut stream, &[5, 1, 0], deadline)?;
    let mut method = [0_u8; 2];
    scale_read_exact(&mut stream, &mut method, deadline)?;
    if method != [5, 0] {
        return Err("scale SOCKS authentication negotiation failed".to_owned());
    }
    let mut request = [0_u8; 10];
    request[..4].copy_from_slice(&[5, 1, 0, 1]);
    request[4..8].copy_from_slice(&target.ip().octets());
    request[8..].copy_from_slice(&target.port().to_be_bytes());
    scale_write_all(&mut stream, &request, deadline)?;
    let mut reply = [0_u8; 10];
    scale_read_exact(&mut stream, &mut reply, deadline)?;
    if reply[..4] != [5, 0, 0, 1] {
        return Err("scale SOCKS CONNECT failed".to_owned());
    }
    stream.set_read_timeout(None).map_err(clean_io)?;
    stream.set_write_timeout(None).map_err(clean_io)?;
    Ok(stream)
}

fn establish_scale_sessions(
    proxy: SocketAddrV4,
    target: SocketAddrV4,
) -> Result<Vec<TcpStream>, String> {
    bounded_parallel_setup(
        SESSIONS,
        SETUP_WORKERS,
        Instant::now() + DRAIN_TIMEOUT,
        move |_index, global_deadline| {
            let session_deadline =
                global_deadline.min(Instant::now() + SCALE_SETUP_SESSION_TIMEOUT);
            scale_socks_connect(proxy, target, session_deadline)
        },
    )
}

struct ScaleTargetAcceptor {
    result: mpsc::Receiver<Result<Vec<TcpStream>, String>>,
    cancel: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<(), String>>>,
}

impl ScaleTargetAcceptor {
    fn start(listener: TcpListener) -> Result<Self, String> {
        listener.set_nonblocking(true).map_err(clean_io)?;
        let (sender, result) = mpsc::sync_channel(1);
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker = spawn_worker(move || {
            let accepted = (|| {
                let mut streams = Vec::with_capacity(SESSIONS);
                while streams.len() < SESSIONS {
                    match listener.accept() {
                        Ok((stream, _)) => streams.push(stream),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            if worker_cancel.load(Ordering::SeqCst) {
                                return Err("scale target accept cancelled".to_owned());
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => return Err(clean_io(error)),
                    }
                }
                Ok(streams)
            })();
            let forwarded = accepted.as_ref().map(|_| ()).map_err(Clone::clone);
            sender
                .send(accepted)
                .map_err(|_| "scale target accept result owner ended early".to_owned())?;
            forwarded
        })?;
        Ok(Self {
            result,
            cancel,
            worker: Some(worker),
        })
    }

    fn finish(mut self, deadline: Instant) -> Result<Vec<TcpStream>, String> {
        let result = self
            .result
            .recv_timeout(remaining(deadline)?)
            .map_err(|_| "scale target did not accept 10000 streams".to_owned())?;
        let worker = self.worker.take().expect("scale target accept owner");
        let joined = join_worker(worker)?;
        match (result, joined) {
            (Ok(streams), Ok(())) if streams.len() == SESSIONS => Ok(streams),
            (Ok(_), Ok(())) => Err("scale target accepted the wrong stream count".to_owned()),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
}

impl Drop for ScaleTargetAcceptor {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn profile_nofile_soft() -> Result<u64, String> {
    let limits = fs::read_to_string("/proc/self/limits")
        .map_err(|_| "scale process limits are unavailable".to_owned())?;
    let soft = limits
        .lines()
        .find(|line| line.starts_with("Max open files"))
        .and_then(|line| line.split_whitespace().nth(3))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| "scale nofile soft limit is malformed".to_owned())?;
    if soft < MINIMUM_NOFILE_SOFT {
        return Err("scale nofile soft limit is below 65536".to_owned());
    }
    Ok(soft)
}

fn memory_available_kib() -> Result<u64, String> {
    let memory = fs::read_to_string("/proc/meminfo")
        .map_err(|_| "scale available memory is unavailable".to_owned())?;
    let available = memory
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| "scale available memory is malformed".to_owned())?;
    if available < MINIMUM_MEMORY_AVAILABLE_KIB {
        return Err("scale available memory is below 8000000 KiB".to_owned());
    }
    Ok(available)
}

fn collect_sample(
    client: &mut ProcessGuard,
    server: &mut ProcessGuard,
    client_metrics: SocketAddrV4,
    server_metrics: SocketAddrV4,
    owner_identity: Option<&PairSample>,
    harness_peak: &mut u64,
    deadline: Instant,
) -> Result<ScalePairSample, String> {
    let sample = sample_pair(client, server, client_metrics, server_metrics, deadline)?;
    if let Some(identity) = owner_identity {
        validate_owner_tuple(&sample, identity, SESSIONS as u64)?;
    }
    client.ensure_running()?;
    server.ensure_running()?;
    let harness_rss_kib = proc_sample(std::process::id())?.rss_kib;
    *harness_peak = (*harness_peak).max(harness_rss_kib);
    Ok(ScalePairSample::observed(sample, harness_rss_kib))
}

async fn collect_quiescent_samples(
    client: &mut ProcessGuard,
    server: &mut ProcessGuard,
    client_metrics: SocketAddrV4,
    server_metrics: SocketAddrV4,
    owner_identity: &PairSample,
    harness_peak: &mut u64,
    errors: &mut tokio_mpsc::UnboundedReceiver<String>,
) -> Result<Vec<ScalePairSample>, String> {
    let mut samples = Vec::with_capacity(RESOURCE_SAMPLES_PER_PHASE);
    for index in 0..RESOURCE_SAMPLES_PER_PHASE {
        if index != 0 {
            tokio::select! {
                () = tokio::time::sleep(RESOURCE_SAMPLE_INTERVAL) => {}
                error = errors.recv() => {
                    return Err(error.unwrap_or_else(|| "scale task error channel ended early".to_owned()));
                }
            }
        }
        samples.push(collect_sample(
            client,
            server,
            client_metrics,
            server_metrics,
            Some(owner_identity),
            harness_peak,
            Instant::now() + SCALE_IO_TIMEOUT,
        )?);
    }
    Ok(samples)
}

#[allow(clippy::too_many_arguments)]
async fn collect_active_samples(
    started: Instant,
    duration: Duration,
    client: &mut ProcessGuard,
    server: &mut ProcessGuard,
    client_metrics: SocketAddrV4,
    server_metrics: SocketAddrV4,
    owner_identity: &PairSample,
    harness_peak: &mut u64,
    errors: &mut tokio_mpsc::UnboundedReceiver<String>,
) -> Result<Vec<ScalePairSample>, String> {
    let mut samples = Vec::with_capacity(RESOURCE_SAMPLES_PER_PHASE);
    let phase_end = started + duration;
    let denominator =
        u32::try_from(ACTIVE_SAMPLE_SLOT_DENOMINATOR).expect("sample denominator fits u32");
    for index in 1..=RESOURCE_SAMPLES_PER_PHASE {
        let numerator = u32::try_from(index).expect("sample index fits u32");
        let slot = started + duration * numerator / denominator;
        if let Some(delay) = slot.checked_duration_since(Instant::now()) {
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                error = errors.recv() => {
                    return Err(error.unwrap_or_else(|| "scale task error channel ended early".to_owned()));
                }
            }
        } else {
            return Err("scale active resource sample slot was missed".to_owned());
        }
        let sample = collect_sample(
            client,
            server,
            client_metrics,
            server_metrics,
            Some(owner_identity),
            harness_peak,
            phase_end,
        )?;
        ensure_active_sample_before_deadline(Instant::now(), phase_end)?;
        samples.push(sample);
    }
    Ok(samples)
}

fn ensure_active_sample_before_deadline(now: Instant, phase_end: Instant) -> Result<(), String> {
    if now >= phase_end {
        return Err("scale active resource sample crossed the phase deadline".to_owned());
    }
    Ok(())
}

async fn release_phase(
    phase: &Phase,
    errors: &mut tokio_mpsc::UnboundedReceiver<String>,
) -> Result<Instant, String> {
    tokio::select! {
        result = phase.release() => result,
        error = errors.recv() => Err(error.unwrap_or_else(|| "scale task error channel ended early".to_owned())),
    }
}

fn to_tokio_streams(streams: Vec<TcpStream>) -> Result<Vec<TokioTcpStream>, String> {
    streams
        .into_iter()
        .map(|stream| {
            stream.set_nonblocking(true).map_err(clean_io)?;
            TokioTcpStream::from_std(stream).map_err(clean_io)
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
async fn execute(
    applications: Vec<TcpStream>,
    targets: Vec<TcpStream>,
    arguments: &ProfileArgs,
    ready_file: &Path,
    client: &mut ProcessGuard,
    server: &mut ProcessGuard,
    client_metrics: SocketAddrV4,
    server_metrics: SocketAddrV4,
    owner_identity: PairSample,
) -> Result<ExecutionResult, String> {
    if applications.len() != SESSIONS || targets.len() != SESSIONS {
        return Err("scale executor did not receive exact stream sets".to_owned());
    }
    let applications = to_tokio_streams(applications)?;
    let targets = to_tokio_streams(targets)?;
    let (commands, receiver) = watch::channel(ScaleCommand::Idle);
    let (result_sender, mut result_receiver) = tokio_mpsc::channel(SESSIONS);
    let (application_ready_sender, mut application_ready_receiver) = tokio_mpsc::channel(SESSIONS);
    let (target_ready_sender, mut target_ready_receiver) = tokio_mpsc::channel(SESSIONS);
    let (error_sender, mut error_receiver) = tokio_mpsc::unbounded_channel();
    let payload = initialize_payload();
    let mut application_tasks = JoinSet::new();
    for (index, stream) in applications.into_iter().enumerate() {
        let task_errors = error_sender.clone();
        let task_payload = Arc::clone(&payload);
        let task = run_application_flow(
            index,
            stream,
            receiver.clone(),
            result_sender.clone(),
            application_ready_sender.clone(),
            task_payload,
        );
        application_tasks.spawn(async move {
            let result = task.await;
            if let Err(error) = &result {
                let _ = task_errors.send(format!("scale application task {index}: {error}"));
            }
            result
        });
    }
    drop(receiver);
    drop(result_sender);
    drop(application_ready_sender);
    let mut target_tasks = JoinSet::new();
    for (index, stream) in targets.into_iter().enumerate() {
        let task_errors = error_sender.clone();
        let task_ready = target_ready_sender.clone();
        target_tasks.spawn(async move {
            let result = run_target_flow(index, stream, task_ready).await;
            if let Err(error) = &result {
                let _ = task_errors.send(format!("scale target task {index}: {error}"));
            }
            result
        });
    }
    drop(target_ready_sender);
    drop(error_sender);

    let execution = async {
        await_task_readiness(
            "application",
            SESSIONS,
            &mut application_ready_receiver,
            &mut error_receiver,
        )
        .await?;
        await_task_readiness(
            "target",
            SESSIONS,
            &mut target_ready_receiver,
            &mut error_receiver,
        )
        .await?;
        let mut harness_peak = 0_u64;
        let established = collect_quiescent_samples(
            client,
            server,
            client_metrics,
            server_metrics,
            &owner_identity,
            &mut harness_peak,
            &mut error_receiver,
        )
        .await?;

        let touch_phase = Phase::new(1, PhaseKind::Touch, None);
        commands
            .send(ScaleCommand::Run(Arc::clone(&touch_phase)))
            .map_err(|_| "scale application tasks ended before touch".to_owned())?;
        release_phase(&touch_phase, &mut error_receiver).await?;
        let touch = collect_phase(&touch_phase, &mut result_receiver, &mut error_receiver).await?;
        validate_phase_accounting(&touch, SESSIONS, true)?;
        let expected_touch_completions =
            u64::try_from(SESSIONS * TOUCH_ROUNDS).expect("touch completion count fits u64");
        if touch.completions != expected_touch_completions {
            return Err("scale touch did not complete two rounds on every flow".to_owned());
        }
        let touched = collect_quiescent_samples(
            client,
            server,
            client_metrics,
            server_metrics,
            &owner_identity,
            &mut harness_peak,
            &mut error_receiver,
        )
        .await?;

        let partial_duration = Duration::from_secs(arguments.warmup_seconds);
        let partial_phase = Phase::new(2, PhaseKind::Partial, Some(partial_duration));
        commands
            .send(ScaleCommand::Run(Arc::clone(&partial_phase)))
            .map_err(|_| "scale application tasks ended before partial phase".to_owned())?;
        let partial_started = release_phase(&partial_phase, &mut error_receiver).await?;
        let partial_active = collect_active_samples(
            partial_started,
            partial_duration,
            client,
            server,
            client_metrics,
            server_metrics,
            &owner_identity,
            &mut harness_peak,
            &mut error_receiver,
        )
        .await?;
        let partial =
            collect_phase(&partial_phase, &mut result_receiver, &mut error_receiver).await?;
        validate_phase_accounting(&partial, PARTIAL_ACTIVE_FLOWS, false)?;

        let full_duration = Duration::from_secs(arguments.active_seconds);
        let full_phase = Phase::new(3, PhaseKind::Full, Some(full_duration));
        commands
            .send(ScaleCommand::Run(Arc::clone(&full_phase)))
            .map_err(|_| "scale application tasks ended before full phase".to_owned())?;
        let full_started = tokio::select! {
            result = full_phase.prepare_release() => result?,
            error = error_receiver.recv() => {
                return Err(error.unwrap_or_else(|| "scale task error channel ended early".to_owned()));
            }
        };
        let mut ready = Some(ReadyFile::publish(
            ready_file,
            ProfileScenario::TcpScale10k,
            client.id(),
            Some(server.id()),
            arguments.warmup_seconds,
            arguments.active_seconds,
        )?);
        if Instant::now() >= full_started {
            return Err("scale ready publication missed the common full start".to_owned());
        }
        tokio::select! {
            () = tokio::time::sleep_until(full_started.into()) => {}
            error = error_receiver.recv() => {
                return Err(error.unwrap_or_else(|| "scale task error channel ended early".to_owned()));
            }
        }
        let full_active = collect_active_samples(
            full_started,
            full_duration,
            client,
            server,
            client_metrics,
            server_metrics,
            &owner_identity,
            &mut harness_peak,
            &mut error_receiver,
        )
        .await?;
        let full_deadline = *full_phase.deadline.get().expect("full phase deadline");
        tokio::time::sleep_until(full_deadline.into()).await;
        ready.take().expect("scale ready owner").remove()?;
        let full = collect_phase(&full_phase, &mut result_receiver, &mut error_receiver).await?;
        validate_phase_accounting(&full, SESSIONS, false)?;
        let full_elapsed =
            full_deadline.duration_since(*full_phase.started.get().expect("full phase start"));
        let post_full = collect_quiescent_samples(
            client,
            server,
            client_metrics,
            server_metrics,
            &owner_identity,
            &mut harness_peak,
            &mut error_receiver,
        )
        .await?;
        Ok::<_, String>((
            established,
            touched,
            partial_active,
            full_active,
            post_full,
            touch,
            partial,
            full,
            full_elapsed,
            harness_peak,
        ))
    }
    .await;

    let failed = execution.is_err();
    let _ = commands.send(ScaleCommand::Shutdown);
    if failed {
        application_tasks.abort_all();
    }
    let application_tasks_joined =
        join_tasks(&mut application_tasks, SESSIONS, "application", failed).await;
    let target_tasks_joined = join_tasks(&mut target_tasks, SESSIONS, "target", false).await;
    let joined = match (application_tasks_joined, target_tasks_joined) {
        (Ok(applications), Ok(targets)) => Ok((applications, targets)),
        (Err(error), Ok(_)) | (Ok(_), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(format!("{first}; {second}")),
    };
    let (execution, joined) = match (execution, joined) {
        (Ok(execution), Ok(joined)) => (execution, joined),
        (Err(error), Ok(_)) | (Ok(_), Err(error)) => return Err(error),
        (Err(execution_error), Err(join_error)) => {
            return Err(format!("{execution_error}; cleanup: {join_error}"));
        }
    };
    let (
        established,
        touched,
        partial_active,
        full_active,
        post_full,
        touch,
        partial,
        full,
        full_elapsed,
        harness_peak_rss_kib,
    ) = execution;
    let (application_tasks_joined, target_tasks_joined) = joined;
    Ok(ExecutionResult {
        established,
        touched,
        partial_active,
        full_active,
        post_full,
        touch,
        partial,
        full,
        full_elapsed,
        application_tasks_joined,
        target_tasks_joined,
        harness_peak_rss_kib,
    })
}

fn observed_pair(sample: PairSample) -> Result<ScalePairSample, String> {
    Ok(ScalePairSample::observed(
        sample,
        proc_sample(std::process::id())?.rss_kib,
    ))
}

fn staged_harness_peak(stages: &[&[ScalePairSample]]) -> Result<u64, String> {
    stages
        .iter()
        .flat_map(|stage| stage.iter())
        .map(|sample| sample.harness_rss_kib)
        .max()
        .ok_or_else(|| "scale resource observations are empty".to_owned())
}

fn build_outcome(
    arguments: &ProfileArgs,
    pre_load: ScalePairSample,
    owner_identity: PairSample,
    execution: ExecutionResult,
    drained: ScalePairSample,
    available_memory_kib: u64,
    nofile_soft: u64,
) -> Result<ProfileOutcome, String> {
    let fairness = fairness(&execution.full.flow_bytes)?;
    let full_elapsed_nanoseconds = u64::try_from(execution.full_elapsed.as_nanos())
        .map_err(|_| "scale full elapsed time exceeds u64".to_owned())?;
    let aggregate_bytes_per_second =
        rate_per_second(execution.full.checked_bytes, execution.full_elapsed)?;
    let client_increment =
        per_connection_increment(&execution.established, &execution.touched, |sample| {
            sample.client_smaps_rss_kib
        })?;
    let server_increment =
        per_connection_increment(&execution.established, &execution.touched, |sample| {
            sample.server_smaps_rss_kib
        })?;
    let combined_increment = client_increment
        .checked_add(server_increment)
        .ok_or_else(|| "scale combined per-connection RSS delta overflow".to_owned())?;
    let pre_load = vec![pre_load];
    let drained = vec![drained];
    let harness_peak_rss_kib = staged_harness_peak(&[
        &pre_load,
        &execution.established,
        &execution.touched,
        &execution.partial_active,
        &execution.full_active,
        &execution.post_full,
        &drained,
    ])?;
    if harness_peak_rss_kib
        != execution
            .harness_peak_rss_kib
            .max(pre_load[0].harness_rss_kib)
            .max(drained[0].harness_rss_kib)
    {
        return Err("scale harness RSS peak accounting is inconsistent".to_owned());
    }
    let touch_completed_flows = execution
        .touch
        .flow_bytes
        .iter()
        .filter(|value| **value != 0)
        .count();
    let partial_nonzero_flows = execution
        .partial
        .flow_bytes
        .iter()
        .filter(|value| **value != 0)
        .count();
    let full_nonzero_flows = execution
        .full
        .flow_bytes
        .iter()
        .filter(|value| **value != 0)
        .count();
    if touch_completed_flows != SESSIONS
        || owner_identity.client.active != SESSIONS as u64
        || owner_identity.server.active != SESSIONS as u64
        || execution.application_tasks_joined != SESSIONS
        || execution.target_tasks_joined != SESSIONS
    {
        return Err("scale lifecycle correctness is incomplete".to_owned());
    }
    let payload_checks = execution
        .touch
        .completions
        .checked_add(execution.partial.completions)
        .and_then(|value| value.checked_add(execution.partial.discarded_tail_completions))
        .and_then(|value| value.checked_add(execution.full.completions))
        .and_then(|value| value.checked_add(execution.full.discarded_tail_completions))
        .ok_or_else(|| "scale payload check count overflow".to_owned())?;
    let full_io_completions = execution.full.completions;
    let evidence = ScaleEvidence {
        schema_version: SCALE_SCHEMA_VERSION,
        recipe: ScaleRecipe {
            sessions: SESSIONS as u64,
            setup_workers: SETUP_WORKERS as u64,
            runtime_worker_threads: RUNTIME_WORKER_THREADS as u64,
            application_futures: SESSIONS as u64,
            target_futures: SESSIONS as u64,
            payload_bytes: PAYLOAD_BYTES as u64,
            touch_rounds: TOUCH_ROUNDS as u64,
            partial_active_flows: PARTIAL_ACTIVE_FLOWS as u64,
            partial_selector_modulus: PARTIAL_SELECTOR_MODULUS as u64,
            partial_selector_remainder: PARTIAL_SELECTOR_REMAINDER as u64,
            partial_seconds: arguments.warmup_seconds,
            full_seconds: arguments.active_seconds,
            resource_samples_per_phase: RESOURCE_SAMPLES_PER_PHASE as u64,
            quiescent_sample_interval_milliseconds: u64::try_from(
                RESOURCE_SAMPLE_INTERVAL.as_millis(),
            )
            .expect("resource interval fits u64"),
            active_sample_slot_denominator: ACTIVE_SAMPLE_SLOT_DENOMINATOR as u64,
        },
        correctness: ScaleCorrectness {
            target_accepted: SESSIONS as u64,
            client_active: owner_identity.client.active,
            server_active: owner_identity.server.active,
            touch_completed_flows: touch_completed_flows as u64,
            touch_completed_round_trips: execution.touch.completions,
            touch_checked_bytes: execution.touch.checked_bytes,
            payload_checks,
            partial_nonzero_flows: partial_nonzero_flows as u64,
            full_nonzero_flows: full_nonzero_flows as u64,
            application_tasks_joined: execution.application_tasks_joined as u64,
            target_tasks_joined: execution.target_tasks_joined as u64,
            drain: "PASS",
            rebind: "PASS",
            cleanup: "PASS",
        },
        traffic: ScaleTraffic {
            partial_checked_bytes: execution.partial.checked_bytes,
            partial_io_completions: execution.partial.completions,
            partial_discarded_tail_completions: execution.partial.discarded_tail_completions,
            partial_flow_bytes: execution.partial.flow_bytes,
            full_checked_bytes: execution.full.checked_bytes,
            full_io_completions,
            full_discarded_tail_completions: execution.full.discarded_tail_completions,
            full_elapsed_nanoseconds,
            full_flow_bytes: execution.full.flow_bytes,
            full_flow_completions: execution.full.flow_completions,
            aggregate_bytes_per_second,
        },
        fairness,
        resource: ScaleResource {
            pre_load,
            established: execution.established,
            touched: execution.touched,
            partial_active: execution.partial_active,
            full_active: execution.full_active,
            post_full: execution.post_full,
            drained,
            client_touched_increment_bytes_per_connection: client_increment,
            server_touched_increment_bytes_per_connection: server_increment,
            combined_touched_increment_bytes_per_connection: combined_increment,
            harness_peak_rss_kib,
            memory_available_kib: available_memory_kib,
            nofile_soft,
        },
    };
    let scale_json = serde_json::to_string(&evidence)
        .map_err(|_| "scale evidence could not be encoded".to_owned())?;
    if scale_json.len() + 4_096 > TCP_SCALE_EVIDENCE_LINE_MAX_BYTES {
        return Err("scale evidence exceeds its bounded trial envelope".to_owned());
    }
    Ok(ProfileOutcome {
        summary: format!(
            "m18_profile_workload_completion status=PASS scenario=tcp-scale-10k \
             sessions={SESSIONS} partial_flows={PARTIAL_ACTIVE_FLOWS} bytes={} \
             jain_ppb={} drain=PASS rebind=PASS",
            evidence.traffic.full_checked_bytes, evidence.fairness.jain_ppb,
        ),
        metric: "bytes_per_second",
        value: aggregate_bytes_per_second,
        checked_units: evidence.traffic.full_checked_bytes,
        p99_nanoseconds: None,
        io_completions: full_io_completions
            .checked_mul(2)
            .ok_or_else(|| "scale I/O completion count overflow".to_owned())?,
        scale_json: Some(scale_json),
    })
}

pub(super) fn run(arguments: &ProfileArgs, ready_file: &Path) -> Result<ProfileOutcome, String> {
    if arguments.warmup_seconds != 10 || arguments.active_seconds != 30 {
        return Err("tcp-scale-10k requires the fixed 10/30 second recipe".to_owned());
    }
    let cpu_count = thread::available_parallelism()
        .map_err(|_| "scale logical CPU count is unavailable".to_owned())?
        .get();
    let (memory_total_kib, _) = linux_capacity()?;
    if cpu_count < RUNTIME_WORKER_THREADS || memory_total_kib < 15_000_000 {
        return Err("scale host capacity is below the fixed recipe".to_owned());
    }
    let available_memory_kib = memory_available_kib()?;
    let nofile_soft = profile_nofile_soft()?;
    let mut directory = Some(
        tempfile::Builder::new()
            .prefix("profile-tcp-scale-")
            .tempdir()
            .map_err(clean_io)?,
    );
    let target_socket =
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).map_err(clean_io)?;
    target_socket
        .bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).into())
        .map_err(clean_io)?;
    target_socket
        .listen(i32::try_from(SESSIONS).expect("scale backlog fits i32"))
        .map_err(clean_io)?;
    let target_listener: TcpListener = target_socket.into();
    let target = v4(target_listener.local_addr().map_err(clean_io)?)?;
    let mut server_reservation = Some(PortReservation::new()?);
    let mut proxy_reservation = Some(PortReservation::new()?);
    let mut client_metrics_reservation = Some(PortReservation::new()?);
    let mut server_metrics_reservation = Some(PortReservation::new()?);
    let server_address = server_reservation
        .as_ref()
        .expect("server reservation")
        .address;
    let proxy_address = proxy_reservation
        .as_ref()
        .expect("proxy reservation")
        .address;
    let client_metrics = client_metrics_reservation
        .as_ref()
        .expect("client metrics reservation")
        .address;
    let server_metrics = server_metrics_reservation
        .as_ref()
        .expect("server metrics reservation")
        .address;
    let client_config = directory
        .as_ref()
        .expect("scale directory")
        .path()
        .join("client.toml");
    let server_config = directory
        .as_ref()
        .expect("scale directory")
        .path()
        .join("server.toml");
    let mut target_acceptor = None;
    let mut server_process = None;
    let mut client_process = None;
    let mut completed = None;
    let mut errors = Vec::new();

    let execution = (|| -> Result<(), String> {
        fs::write(
            &client_config,
            ferrum_client_config(proxy_address, server_address, Some(client_metrics)),
        )
        .map_err(clean_io)?;
        fs::write(
            &server_config,
            ferrum_server_config(server_address, Some(server_metrics)),
        )
        .map_err(clean_io)?;
        target_acceptor = Some(ScaleTargetAcceptor::start(target_listener)?);
        server_reservation
            .take()
            .expect("server reservation")
            .release();
        server_metrics_reservation
            .take()
            .expect("server metrics reservation")
            .release();
        server_process = Some(spawn_proxy(
            Topology::Ferrum,
            "scale server",
            &profile_binary(&arguments.binary_dir, "ferrum2-server")?,
            &server_config,
        )?);
        wait_for_metrics(
            server_process.as_mut().expect("scale server process"),
            server_metrics,
        )?;
        proxy_reservation
            .take()
            .expect("proxy reservation")
            .release();
        client_metrics_reservation
            .take()
            .expect("client metrics reservation")
            .release();
        client_process = Some(spawn_proxy(
            Topology::Ferrum,
            "scale client",
            &profile_binary(&arguments.binary_dir, "ferrum2-client")?,
            &client_config,
        )?);
        wait_for_metrics(
            client_process.as_mut().expect("scale client process"),
            client_metrics,
        )?;
        let pre_load_pair = sample_pair(
            client_process.as_mut().expect("scale client process"),
            server_process.as_mut().expect("scale server process"),
            client_metrics,
            server_metrics,
            Instant::now() + SCALE_IO_TIMEOUT,
        )?;
        if pre_load_pair.client.active != 0 || pre_load_pair.server.active != 0 {
            return Err("scale pre-load active gauges are not zero".to_owned());
        }
        client_process
            .as_mut()
            .expect("scale client process")
            .ensure_running()?;
        server_process
            .as_mut()
            .expect("scale server process")
            .ensure_running()?;
        let pre_load = observed_pair(pre_load_pair)?;
        let applications = establish_scale_sessions(proxy_address, target)?;
        let targets = target_acceptor
            .take()
            .expect("scale target acceptor")
            .finish(Instant::now() + DRAIN_TIMEOUT)?;
        let owner_identity = wait_for_sessions(
            client_process.as_mut().expect("scale client process"),
            server_process.as_mut().expect("scale server process"),
            client_metrics,
            server_metrics,
        )?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(RUNTIME_WORKER_THREADS)
            .enable_io()
            .enable_time()
            .build()
            .map_err(clean_io)?;
        // `block_on` keeps this coordinator on the caller thread. Only socket futures run on the
        // four runtime workers; procfs/metrics/child probes below never enter the worker pool.
        let scale_execution = runtime.block_on(execute(
            applications,
            targets,
            arguments,
            ready_file,
            client_process.as_mut().expect("scale client process"),
            server_process.as_mut().expect("scale server process"),
            client_metrics,
            server_metrics,
            owner_identity,
        ));
        runtime.shutdown_timeout(REAP_TIMEOUT);
        let scale_execution = scale_execution?;
        let drain_deadline = Instant::now() + DRAIN_TIMEOUT;
        let drained_pair = loop {
            let sample = sample_pair(
                client_process.as_mut().expect("scale client process"),
                server_process.as_mut().expect("scale server process"),
                client_metrics,
                server_metrics,
                drain_deadline,
            )?;
            client_process
                .as_mut()
                .expect("scale client process")
                .ensure_running()?;
            server_process
                .as_mut()
                .expect("scale server process")
                .ensure_running()?;
            if validate_drain(&sample, &pre_load_pair).is_ok() {
                break sample;
            }
            thread::sleep(remaining(drain_deadline)?.min(Duration::from_millis(100)));
        };
        completed = Some((
            pre_load,
            owner_identity,
            scale_execution,
            observed_pair(drained_pair)?,
        ));
        Ok(())
    })();
    if let Err(error) = execution {
        errors.push(error);
    }

    drop(target_acceptor.take());
    drop(server_reservation.take());
    drop(proxy_reservation.take());
    drop(client_metrics_reservation.take());
    drop(server_metrics_reservation.take());
    for (label, process) in [
        ("scale client", &mut client_process),
        ("scale server", &mut server_process),
    ] {
        if let Some(process) = process.as_mut()
            && let Err(error) = process.terminate()
        {
            errors.push(format!("{label} cleanup failed: {error}"));
        }
    }
    if let Some(directory) = directory.take()
        && let Err(error) = directory.close().map_err(clean_io)
    {
        errors.push(format!("scale directory cleanup failed: {error}"));
    }
    for result in [
        prove_tcp_rebind(proxy_address, "scale client"),
        prove_tcp_rebind(server_address, "scale server"),
        prove_tcp_rebind(client_metrics, "scale client metrics"),
        prove_tcp_rebind(server_metrics, "scale server metrics"),
        prove_tcp_rebind(target, "scale target"),
    ] {
        if let Err(error) = result {
            errors.push(error);
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    assert_no_owners()?;
    let (pre_load, owner_identity, scale_execution, drained) =
        completed.ok_or_else(|| "scale execution produced no completed evidence".to_owned())?;
    build_outcome(
        arguments,
        pre_load,
        owner_identity,
        scale_execution,
        drained,
        available_memory_kib,
        nofile_soft,
    )
}

fn synthetic_sample(value: u64) -> ScalePairSample {
    ScalePairSample {
        client_active: value,
        server_active: value,
        client_fds: value,
        server_fds: value,
        client_tasks: value,
        server_tasks: value,
        client_rss_kib: value,
        server_rss_kib: value,
        client_smaps_rss_kib: value,
        server_smaps_rss_kib: value,
        client_anonymous_kib: value,
        server_anonymous_kib: value,
        client_anon_huge_pages_kib: value,
        server_anon_huge_pages_kib: value,
        harness_rss_kib: value,
    }
}

fn maximum_shape_evidence() -> ScaleEvidence {
    let sample = synthetic_sample(u64::MAX);
    ScaleEvidence {
        schema_version: SCALE_SCHEMA_VERSION,
        recipe: ScaleRecipe {
            sessions: SESSIONS as u64,
            setup_workers: SETUP_WORKERS as u64,
            runtime_worker_threads: RUNTIME_WORKER_THREADS as u64,
            application_futures: SESSIONS as u64,
            target_futures: SESSIONS as u64,
            payload_bytes: PAYLOAD_BYTES as u64,
            touch_rounds: TOUCH_ROUNDS as u64,
            partial_active_flows: PARTIAL_ACTIVE_FLOWS as u64,
            partial_selector_modulus: PARTIAL_SELECTOR_MODULUS as u64,
            partial_selector_remainder: PARTIAL_SELECTOR_REMAINDER as u64,
            partial_seconds: 10,
            full_seconds: 30,
            resource_samples_per_phase: RESOURCE_SAMPLES_PER_PHASE as u64,
            quiescent_sample_interval_milliseconds: 1_000,
            active_sample_slot_denominator: ACTIVE_SAMPLE_SLOT_DENOMINATOR as u64,
        },
        correctness: ScaleCorrectness {
            target_accepted: u64::MAX,
            client_active: u64::MAX,
            server_active: u64::MAX,
            touch_completed_flows: u64::MAX,
            touch_completed_round_trips: u64::MAX,
            touch_checked_bytes: u64::MAX,
            payload_checks: u64::MAX,
            partial_nonzero_flows: u64::MAX,
            full_nonzero_flows: u64::MAX,
            application_tasks_joined: u64::MAX,
            target_tasks_joined: u64::MAX,
            drain: "PASS",
            rebind: "PASS",
            cleanup: "PASS",
        },
        traffic: ScaleTraffic {
            partial_checked_bytes: u64::MAX,
            partial_io_completions: u64::MAX,
            partial_discarded_tail_completions: u64::MAX,
            partial_flow_bytes: vec![u64::MAX; PARTIAL_ACTIVE_FLOWS],
            full_checked_bytes: u64::MAX,
            full_io_completions: u64::MAX,
            full_discarded_tail_completions: u64::MAX,
            full_elapsed_nanoseconds: u64::MAX,
            full_flow_bytes: vec![u64::MAX; SESSIONS],
            full_flow_completions: vec![u64::MAX; SESSIONS],
            aggregate_bytes_per_second: u64::MAX,
        },
        fairness: ScaleFairness {
            jain_ppb: u64::MAX,
            minimum_bytes: u64::MAX,
            p01_bytes: u64::MAX,
            p05_bytes: u64::MAX,
            median_bytes: u64::MAX,
            p95_bytes: u64::MAX,
            p99_bytes: u64::MAX,
            maximum_bytes: u64::MAX,
            p01_to_median_ppm: u64::MAX,
        },
        resource: ScaleResource {
            pre_load: vec![sample],
            established: vec![sample; RESOURCE_SAMPLES_PER_PHASE],
            touched: vec![sample; RESOURCE_SAMPLES_PER_PHASE],
            partial_active: vec![sample; RESOURCE_SAMPLES_PER_PHASE],
            full_active: vec![sample; RESOURCE_SAMPLES_PER_PHASE],
            post_full: vec![sample; RESOURCE_SAMPLES_PER_PHASE],
            drained: vec![sample],
            client_touched_increment_bytes_per_connection: i64::MAX,
            server_touched_increment_bytes_per_connection: i64::MAX,
            combined_touched_increment_bytes_per_connection: i64::MAX,
            harness_peak_rss_kib: u64::MAX,
            memory_available_kib: u64::MAX,
            nofile_soft: u64::MAX,
        },
    }
}

fn maximum_shape_trial() -> Result<String, String> {
    let scale = serde_json::to_value(maximum_shape_evidence())
        .map_err(|_| "maximum scale fixture could not be materialized".to_owned())?;
    serde_json::to_string(&serde_json::json!({
        "schema_version": PROFILE_TRIAL_SCHEMA_VERSION,
        "kind": "m18_profile_trial",
        "parent_sha": "ffffffffffffffffffffffffffffffffffffffff",
        "candidate_sha": "ffffffffffffffffffffffffffffffffffffffff",
        "member": "candidate",
        "pair": u64::MAX,
        "order": u64::MAX,
        "build_profile": "current",
        "scenario": "tcp-scale-10k",
        "warmup_seconds": u64::MAX,
        "active_seconds": u64::MAX,
        "topology": "shadowsocks",
        "application_payload_bytes": u64::MAX,
        "socks_datagram_bytes": null,
        "upstream_wire_bytes": null,
        "sha": "ffffffffffffffffffffffffffffffffffffffff",
        "tree": "ffffffffffffffffffffffffffffffffffffffff",
        "runner_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "client_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "server_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "rustc": "rustc 1.97.1 maximum fixture",
        "kernel": "maximum fixture kernel",
        "cpu_model": "maximum fixture cpu",
        "cpu_count": u64::MAX,
        "memory_kib": u64::MAX,
        "metric": "bytes_per_second",
        "value": u64::MAX,
        "checked_units": u64::MAX,
        "p99_nanoseconds": null,
        "io_completions": u64::MAX,
        "scale": scale,
        "correctness": "PASS",
        "status": "PASS",
    }))
    .map_err(|_| "maximum scale trial fixture could not be encoded".to_owned())
}

async fn double_barrier_probe() -> Result<(), String> {
    const PROBE_TASKS: usize = 4;
    let first = Arc::new(Barrier::new(PROBE_TASKS + 1));
    let second = Arc::new(Barrier::new(PROBE_TASKS + 1));
    let start = Arc::new(OnceLock::new());
    let mut tasks = JoinSet::new();
    for _ in 0..PROBE_TASKS {
        let first = Arc::clone(&first);
        let second = Arc::clone(&second);
        let start = Arc::clone(&start);
        tasks.spawn(async move {
            first.wait().await;
            second.wait().await;
            let start = *start
                .get()
                .ok_or_else(|| "barrier probe omitted common start".to_owned())?;
            if Instant::now() >= start {
                return Err("barrier probe released late".to_owned());
            }
            tokio::time::sleep_until(start.into()).await;
            Ok::<(), String>(())
        });
    }
    first.wait().await;
    start
        .set(Instant::now() + Duration::from_millis(100))
        .map_err(|_| "barrier probe start collision".to_owned())?;
    second.wait().await;
    while let Some(result) = tasks.join_next().await {
        result.map_err(|_| "barrier probe task panicked".to_owned())??;
    }
    Ok(())
}

pub(super) fn self_check() -> Result<(), String> {
    let timeout_clock = Instant::now();
    if scale_setup_io_timeout_at(
        timeout_clock,
        timeout_clock + SCALE_SETUP_IO_SLICE + Duration::from_secs(1),
    )? != SCALE_SETUP_IO_SLICE
        || scale_setup_io_timeout_at(timeout_clock, timeout_clock + Duration::from_millis(1))?
            != Duration::from_millis(1)
    {
        return Err("scale setup I/O timeout did not preserve its absolute bound".to_owned());
    }
    expect_rejected("expired scale setup I/O deadline", || {
        scale_setup_io_timeout_at(timeout_clock, timeout_clock)
    })?;
    let ordered = bounded_parallel_setup(
        8,
        3,
        Instant::now() + Duration::from_secs(1),
        |index, _deadline| Ok(index),
    )?;
    if ordered != (0..8).collect::<Vec<_>>() {
        return Err("scale bounded setup did not preserve session order".to_owned());
    }
    let released = Arc::new(AtomicBool::new(false));
    let worker_released = Arc::clone(&released);
    let setup_error = bounded_parallel_setup(
        100,
        4,
        Instant::now() + Duration::from_secs(1),
        move |index, deadline| {
            if index == 0 {
                worker_released.store(true, Ordering::SeqCst);
                return Err("sentinel scale setup failure".to_owned());
            }
            while !worker_released.load(Ordering::SeqCst) {
                if Instant::now() >= deadline {
                    return Err("scale setup cancellation probe timed out".to_owned());
                }
                thread::yield_now();
            }
            Ok(index)
        },
    )
    .expect_err("scale setup probe must reject its sentinel failure");
    if setup_error != "sentinel scale setup failure" || !released.load(Ordering::SeqCst) {
        return Err("scale bounded setup did not cancel on its first failure".to_owned());
    }
    let clock = Instant::now();
    ensure_active_sample_before_deadline(clock, clock + Duration::from_nanos(1))?;
    expect_rejected("active sample at phase deadline", || {
        ensure_active_sample_before_deadline(clock, clock)
    })?;
    let body = initialize_payload();
    let mut frame = body.to_vec();
    encode_frame_header(&mut frame, 7, 2, 9)?;
    validate_frame(&frame, &body, 7, 2, 9)?;
    for (name, mutation) in [
        ("scale frame magic", 0_usize),
        ("scale frame flow", FRAME_FLOW_OFFSET),
        ("scale frame generation", FRAME_GENERATION_OFFSET),
        ("scale frame stale sequence", FRAME_SEQUENCE_OFFSET),
        ("scale frame body", FRAME_HEADER_BYTES),
    ] {
        let mut malformed = frame.clone();
        malformed[mutation] ^= 1;
        expect_rejected(name, || validate_frame(&malformed, &body, 7, 2, 9))?;
    }
    let equal = vec![32_768_u64; SESSIONS];
    let equal_fairness = fairness(&equal)?;
    if equal_fairness.jain_ppb != 1_000_000_000
        || equal_fairness.p01_bytes != 32_768
        || equal_fairness.median_bytes != 32_768
        || equal_fairness.p01_to_median_ppm != 1_000_000
    {
        return Err("scale integer fairness contract is invalid".to_owned());
    }
    let mut starved = equal;
    starved[0] = 0;
    let starved_fairness = fairness(&starved)?;
    if starved_fairness.minimum_bytes != 0 || starved_fairness.jain_ppb >= 1_000_000_000 {
        return Err("scale zero-flow fairness did not remain measurable".to_owned());
    }
    let phase = CollectedPhase {
        flow_bytes: vec![PAYLOAD_BYTES as u64; PARTIAL_ACTIVE_FLOWS],
        flow_completions: vec![1; PARTIAL_ACTIVE_FLOWS],
        checked_bytes: (PAYLOAD_BYTES * PARTIAL_ACTIVE_FLOWS) as u64,
        completions: PARTIAL_ACTIVE_FLOWS as u64,
        discarded_tail_completions: PARTIAL_ACTIVE_FLOWS as u64,
    };
    validate_phase_accounting(&phase, PARTIAL_ACTIVE_FLOWS, true)?;
    let mut malformed = phase.flow_bytes.clone();
    malformed.pop();
    expect_rejected("incomplete scale phase vector", || {
        validate_phase_accounting(
            &CollectedPhase {
                flow_bytes: malformed,
                flow_completions: phase.flow_completions.clone(),
                checked_bytes: phase.checked_bytes,
                completions: phase.completions,
                discarded_tail_completions: phase.discarded_tail_completions,
            },
            PARTIAL_ACTIVE_FLOWS,
            true,
        )
    })?;
    let established = vec![synthetic_sample(1_000); RESOURCE_SAMPLES_PER_PHASE];
    let touched = vec![synthetic_sample(990); RESOURCE_SAMPLES_PER_PHASE];
    if per_connection_increment(&established, &touched, |sample| sample.client_smaps_rss_kib)? != -1
    {
        return Err("scale signed RSS delta was not preserved".to_owned());
    }
    let maximum_json = maximum_shape_trial()?;
    if maximum_json.contains('\n')
        || maximum_json.len() <= EVIDENCE_LINE_MAX_BYTES
        || maximum_json.len() + 4_096 > TCP_SCALE_EVIDENCE_LINE_MAX_BYTES
    {
        return Err("maximum scale fixture violates the evidence envelope".to_owned());
    }
    validate_evidence_line(&maximum_json, TCP_SCALE_EVIDENCE_LINE_MAX_BYTES)?;
    expect_rejected("scale evidence above dedicated cap", || {
        validate_evidence_line(
            &"x".repeat(TCP_SCALE_EVIDENCE_LINE_MAX_BYTES + 1),
            TCP_SCALE_EVIDENCE_LINE_MAX_BYTES,
        )
    })?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(RUNTIME_WORKER_THREADS)
        .enable_time()
        .build()
        .map_err(clean_io)?;
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(1), double_barrier_probe())
            .await
            .map_err(|_| "scale double-barrier probe timed out".to_owned())?
    })?;
    runtime.shutdown_timeout(REAP_TIMEOUT);
    Ok(())
}
