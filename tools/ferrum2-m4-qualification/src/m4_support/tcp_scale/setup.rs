use super::contract::{
    ACTIVE_SAMPLE_SLOT_DENOMINATOR, MINIMUM_MEMORY_AVAILABLE_KIB, MINIMUM_NOFILE_SOFT, Phase,
    RESOURCE_SAMPLE_INTERVAL, RESOURCE_SAMPLES_PER_PHASE, SCALE_IO_TIMEOUT, SCALE_SETUP_IO_SLICE,
    SCALE_SETUP_SESSION_TIMEOUT, SESSIONS, ScalePairSample,
};
use crate::m4_support::process_support::{
    ProcessGuard, clean_io, join_unit_workers, join_worker, remaining, spawn_worker,
};
use crate::m4_support::resource_sampling::{
    PairSample, proc_sample, sample_pair, validate_owner_tuple,
};
use crate::m4_support::{DRAIN_TIMEOUT, SETUP_WORKERS};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tokio::sync::mpsc as tokio_mpsc;

pub(crate) fn bounded_parallel_setup<T, F>(
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

pub(crate) fn scale_setup_io_timeout_at(
    now: Instant,
    deadline: Instant,
) -> Result<Duration, String> {
    deadline
        .checked_duration_since(now)
        .filter(|duration| !duration.is_zero())
        .map(|duration| duration.min(SCALE_SETUP_IO_SLICE))
        .ok_or_else(|| "scale setup I/O deadline expired".to_owned())
}

pub(crate) fn scale_setup_io_timeout(deadline: Instant) -> Result<Duration, String> {
    scale_setup_io_timeout_at(Instant::now(), deadline)
}

pub(crate) fn scale_write_all(
    stream: &mut TcpStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), String> {
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

pub(crate) fn scale_read_exact(
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

pub(crate) fn scale_socks_connect(
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

pub(crate) fn establish_scale_sessions(
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

pub(crate) struct ScaleTargetAcceptor {
    pub(crate) result: mpsc::Receiver<Result<Vec<TcpStream>, String>>,
    pub(crate) cancel: Arc<AtomicBool>,
    pub(crate) worker: Option<JoinHandle<Result<(), String>>>,
}

impl ScaleTargetAcceptor {
    pub(crate) fn start(listener: TcpListener) -> Result<Self, String> {
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

    pub(crate) fn finish(mut self, deadline: Instant) -> Result<Vec<TcpStream>, String> {
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

pub(crate) fn profile_nofile_soft() -> Result<u64, String> {
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

pub(crate) fn memory_available_kib() -> Result<u64, String> {
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

pub(crate) fn collect_sample(
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

pub(crate) async fn collect_quiescent_samples(
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
pub(crate) async fn collect_active_samples(
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

pub(crate) fn ensure_active_sample_before_deadline(
    now: Instant,
    phase_end: Instant,
) -> Result<(), String> {
    if now >= phase_end {
        return Err("scale active resource sample crossed the phase deadline".to_owned());
    }
    Ok(())
}

pub(crate) async fn release_phase(
    phase: &Phase,
    errors: &mut tokio_mpsc::UnboundedReceiver<String>,
) -> Result<Instant, String> {
    tokio::select! {
        result = phase.release() => result,
        error = errors.recv() => Err(error.unwrap_or_else(|| "scale task error channel ended early".to_owned())),
    }
}
