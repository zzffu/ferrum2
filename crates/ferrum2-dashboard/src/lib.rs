//! Bounded process-local dashboard observations, independent of runtime control and HTTP.
//! Call [`Dashboard::sample`] periodically from one owner; browsers only read snapshots.
//! Connection leases never lock a shared table when transferring bytes. Each generation
//! owns separate counters, so retained old leases cannot affect a replacement runtime.

mod attribution;
mod connection;
mod io;
mod snapshot;
pub mod wire;

pub use connection::{
    Connection, ConnectionMetadata, ConnectionTarget, DecisionMetadata, SniffMetadata,
};
pub use io::{Direction, ObservedIo};

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use connection::Record;
use tokio::sync::watch;

const LIVE_LIMIT: usize = 4096;
// Detail rows always carry cancellation handles; a separate index covers additional
// hidden leases up to this fixed ceiling. Broadcast cancellation has no lease ceiling.
const CANCELLATION_LIMIT: usize = 65_536;
const HISTORY_LIMIT: usize = 512;
const LOG_LIMIT: usize = 1024;
const HISTORY_TTL: Duration = Duration::from_secs(300);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Default)]
struct Registry {
    live: BTreeMap<String, Arc<Record>>,
    history: VecDeque<(Instant, Arc<Record>)>,
    cancellation: BTreeMap<String, Weak<Record>>,
    active: usize,
    tcp_active: usize,
    udp_active: usize,
}

impl Registry {
    fn prune(&mut self, now: Instant) {
        while self
            .history
            .front()
            .is_some_and(|(at, _)| now.duration_since(*at) >= HISTORY_TTL)
        {
            self.history.pop_front();
        }
    }
}

struct Generation {
    id: u64,
    started: Instant,
    upload: AtomicU64,
    download: AtomicU64,
    omitted: AtomicUsize,
    registry: Mutex<Registry>,
    cancel_epoch: watch::Sender<u64>,
}

impl Generation {
    fn new(id: u64) -> Self {
        Self {
            id,
            started: Instant::now(),
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            omitted: AtomicUsize::new(0),
            registry: Mutex::new(Registry::default()),
            cancel_epoch: watch::channel(0).0,
        }
    }
}

#[derive(Clone)]
struct State {
    generation: Arc<Generation>,
    runtime: String,
    error: Option<String>,
    catalog: Arc<Value>,
    connection_catalog: Option<Arc<wire::ConnectionCatalogView>>,
    domains: Arc<Value>,
    resources: Arc<Value>,
    cpu: Option<f64>,
    memory: Option<u64>,
    logs: VecDeque<Arc<Value>>,
    log_sequence: u64,
    sampled: Instant,
    sampled_upload: u64,
    sampled_download: u64,
    upload_rate: f64,
    download_rate: f64,
}

struct Inner {
    details: bool,
    started: Instant,
    sequence: AtomicU64,
    catalog_sequence: AtomicU64,
    state: Mutex<State>,
}

/// Cloneable observation handle. Does not spawn tasks or own runtime/domain controls.
#[derive(Clone)]
pub struct Dashboard(Arc<Inner>);

impl Dashboard {
    /// Creates a stopped generation-zero observation store. With details disabled,
    /// connection source and target strings are discarded, not merely hidden in JSON.
    pub fn new(details: bool) -> Self {
        Self(Arc::new(Inner {
            details,
            started: Instant::now(),
            sequence: AtomicU64::new(0),
            catalog_sequence: AtomicU64::new(0),
            state: Mutex::new(State {
                generation: Arc::new(Generation::new(0)),
                runtime: "stopped".into(),
                error: None,
                catalog: Arc::new(Value::Null),
                connection_catalog: None,
                domains: Arc::new(json!({})),
                resources: Arc::new(json!({})),
                cpu: None,
                memory: None,
                logs: VecDeque::new(),
                log_sequence: 0,
                sampled: Instant::now(),
                sampled_upload: 0,
                sampled_download: 0,
                upload_rate: 0.0,
                download_rate: 0.0,
            }),
        }))
    }

    /// Replaces generation-owned observations and clears domain/resource handles.
    /// Old leases retain isolated counters and cancellation state until their owners exit.
    /// Process measurements, redacted catalog, and process logs survive replacement.
    pub fn start_generation(&self, generation: u64) {
        let mut state = lock(&self.0.state);
        state.generation = Arc::new(Generation::new(generation));
        state.connection_catalog = None;
        state.runtime = "starting".into();
        state.error = None;
        state.domains = Arc::new(json!({}));
        state.resources = Arc::new(json!({}));
        state.sampled = Instant::now();
        state.sampled_upload = 0;
        state.sampled_download = 0;
        state.upload_rate = 0.0;
        state.download_rate = 0.0;
    }

    /// Publishes a lifecycle state and a caller-redacted error. Unknown states are rejected.
    pub fn set_runtime(&self, state: &str, error: Option<&str>) {
        assert!(matches!(
            state,
            "stopped" | "starting" | "running" | "stopping" | "failed"
        ));
        let mut current = lock(&self.0.state);
        current.runtime = state.into();
        current.error = error.map(str::to_owned);
    }

    /// Publishes the caller's redacted catalog matching the browser protocol.
    pub fn set_catalog(&self, catalog: Value) {
        lock(&self.0.state).catalog = Arc::new(catalog);
    }

    /// Whether sensitive connection endpoints and route conditions may be captured.
    pub fn connection_details_enabled(&self) -> bool {
        self.0.details
    }

    /// Captures immutable indexed configuration facts for subsequent admissions.
    pub fn set_connection_catalog(&self, catalog: Value) {
        let generation = lock(&self.0.state).generation.clone();
        let id = self.0.catalog_sequence.fetch_add(1, Ordering::Relaxed);
        let catalog = Arc::new(attribution::catalog(id, &catalog, self.0.details));
        let mut state = lock(&self.0.state);
        if Arc::ptr_eq(&state.generation, &generation) {
            state.connection_catalog = Some(catalog);
        }
    }

    /// Publishes observations/capabilities from the current generation's real domain owners.
    pub fn set_domains(&self, domains: Value) {
        lock(&self.0.state).domains = Arc::new(domains);
    }

    /// Publishes measured resource state; unavailable fields must be null or absent.
    pub fn set_resources(&self, resources: Value) {
        lock(&self.0.state).resources = Arc::new(resources);
    }

    /// Publishes measured CPU percent and resident memory bytes; unknown values remain null.
    pub fn set_process(&self, cpu: Option<f64>, memory: Option<u64>) {
        let mut state = lock(&self.0.state);
        state.cpu = cpu.filter(|value| value.is_finite() && *value >= 0.0);
        state.memory = memory;
    }

    /// Samples interval byte rates independently of browser polling and expires old history.
    pub fn sample(&self) {
        let mut state = lock(&self.0.state);
        let now = Instant::now();
        let elapsed = now.duration_since(state.sampled).as_secs_f64();
        if elapsed > 0.0 {
            let upload = state.generation.upload.load(Ordering::Relaxed);
            let download = state.generation.download.load(Ordering::Relaxed);
            state.upload_rate = upload.saturating_sub(state.sampled_upload) as f64 / elapsed;
            state.download_rate = download.saturating_sub(state.sampled_download) as f64 / elapsed;
            state.sampled_upload = upload;
            state.sampled_download = download;
            state.sampled = now;
        }
        let generation = state.generation.clone();
        drop(state);
        let records: Vec<_> = {
            let mut registry = lock(&generation.registry);
            registry.prune(now);
            registry.live.values().cloned().collect()
        };
        for record in records {
            record.sample(now);
        }
    }

    /// Records an already-redacted structured tracing event. Oldest entries are evicted.
    /// IDs are process-local decimal strings and timestamps are process-relative milliseconds.
    pub fn record_log(&self, event: Value) {
        let mut state = lock(&self.0.state);
        state.log_sequence += 1;
        let level = event
            .get("level")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        let entry = json!({
            "id": state.log_sequence.to_string(),
            "elapsed_ms": self.0.started.elapsed().as_millis() as u64,
            "level": level,
            "event": event,
        });
        if state.logs.len() == LOG_LIMIT {
            state.logs.pop_front();
        }
        state.logs.push_back(Arc::new(entry));
    }

    /// Creates a flow/association lease. Saturation omits only detail storage, never counters.
    /// At most 4,096 live detail rows, 512 completed rows (five-minute TTL), and
    /// 1,024 logs are retained. Hidden live leases still contribute to totals.
    pub fn begin(&self, metadata: ConnectionMetadata) -> Connection {
        let (generation, catalog) = {
            let state = lock(&self.0.state);
            (state.generation.clone(), state.connection_catalog.clone())
        };
        let sequence = self.0.sequence.fetch_add(1, Ordering::Relaxed);
        Connection::new(generation, sequence, self.0.details, metadata, catalog)
    }

    /// Requests cooperative cancellation of precisely these current-generation IDs.
    /// Returns newly set individual cancellation signals; never declares retirement.
    /// Every visible row is addressable. A separate 65,536-entry index covers hidden
    /// leases; hidden leases beyond that index remain reachable by close-all only.
    pub fn close_connections(&self, ids: &[String]) -> usize {
        let state = lock(&self.0.state);
        let registry = lock(&state.generation.registry);
        ids.iter()
            .filter(|id| {
                registry
                    .live
                    .get(*id)
                    .cloned()
                    .or_else(|| registry.cancellation.get(*id).and_then(Weak::upgrade))
                    .is_some_and(|record| record.cancel())
            })
            .count()
    }

    /// Requests closure of all current live leases, including omitted/unindexed ones.
    /// Returns the live count targeted, not completed closures or newly signalled owners.
    /// The broadcast epoch is captured at admission: later arrivals are not cancelled.
    pub fn close_all_connections(&self) -> usize {
        let state = lock(&self.0.state);
        let registry = lock(&state.generation.registry);
        state
            .generation
            .cancel_epoch
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
        registry.active
    }

    /// Returns protocol-v2 JSON without altering the shared traffic sample.
    pub fn snapshot(&self) -> Value {
        serde_json::to_value(snapshot::Snapshot::capture(self)).expect("snapshot serialization")
    }

    /// Encodes directly from structured rows, outside registry and state locks.
    pub fn encode_snapshot(&self) -> Vec<u8> {
        serde_json::to_vec(&snapshot::Snapshot::capture(self)).expect("snapshot serialization")
    }
}

#[cfg(test)]
mod tests;
