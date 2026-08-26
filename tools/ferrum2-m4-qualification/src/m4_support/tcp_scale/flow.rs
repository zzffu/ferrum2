use super::contract::{
    CollectedPhase, FlowResult, Phase, PhaseKind, SCALE_IO_TIMEOUT, SCALE_PAYLOAD_BYTES,
    SCALE_PHASE_GRACE, SESSIONS, ScaleCommand, TOUCH_ROUNDS, checked_sum, encode_frame_header,
    validate_frame,
};
use crate::m4_support::process_support::clean_io;
use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::{mpsc as tokio_mpsc, watch};
use tokio::task::JoinSet;

pub(crate) async fn round_trip(
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

pub(crate) async fn run_application_flow(
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
                                .checked_add(SCALE_PAYLOAD_BYTES as u64)
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
                                bytes = bytes.checked_add(SCALE_PAYLOAD_BYTES as u64).ok_or_else(
                                    || "scale timed phase byte count overflow".to_owned(),
                                )?;
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

pub(crate) async fn run_target_flow(
    index: usize,
    mut stream: TokioTcpStream,
    ready: tokio_mpsc::Sender<usize>,
) -> Result<(), String> {
    let mut buffer = vec![0_u8; SCALE_PAYLOAD_BYTES];
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

pub(crate) async fn await_task_readiness(
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

pub(crate) fn expected_indices(kind: PhaseKind) -> impl Iterator<Item = usize> {
    (0..SESSIONS).filter(move |index| kind.selected(*index))
}

pub(crate) async fn collect_phase(
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
            .checked_mul(SCALE_PAYLOAD_BYTES as u64)
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

pub(crate) async fn join_tasks(
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

pub(crate) fn validate_phase_accounting(
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
