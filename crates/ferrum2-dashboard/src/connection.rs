use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::{Value, json};
use tokio::sync::watch;

use crate::{CANCELLATION_LIMIT, Generation, HISTORY_LIMIT, LIVE_LIMIT, lock};

/// Metadata observed at the real flow/association admission seam; unknown endpoints stay None.
pub struct ConnectionMetadata {
    pub protocol: &'static str,
    pub inbound: &'static str,
    pub source: Option<String>,
    pub target: Option<String>,
}

struct Attribution {
    target: Option<String>,
    route: Option<String>,
    outbound: Option<String>,
}

pub(crate) struct Record {
    id: String,
    generation: u64,
    protocol: &'static str,
    inbound: &'static str,
    source: Option<String>,
    attribution: Mutex<Attribution>,
    started: Instant,
    started_ms: u64,
    upload: AtomicU64,
    download: AtomicU64,
    cancel: watch::Sender<bool>,
    sampled: Mutex<(Instant, u64, u64)>,
    upload_rate: AtomicU64,
    download_rate: AtomicU64,
}

impl Record {
    pub(crate) fn cancel(&self) -> bool {
        !self.cancel.send_replace(true)
    }

    pub(crate) fn sample(&self, now: Instant) {
        let upload = self.upload.load(Ordering::Relaxed);
        let download = self.download.load(Ordering::Relaxed);
        let mut previous = lock(&self.sampled);
        let elapsed = now.duration_since(previous.0).as_secs_f64();
        if elapsed > 0.0 {
            self.upload_rate.store(
                (upload.saturating_sub(previous.1) as f64 / elapsed).to_bits(),
                Ordering::Relaxed,
            );
            self.download_rate.store(
                (download.saturating_sub(previous.2) as f64 / elapsed).to_bits(),
                Ordering::Relaxed,
            );
            *previous = (now, upload, download);
        }
    }

    pub(crate) fn view(&self, now: Instant, state: &str) -> Value {
        let attribution = lock(&self.attribution);
        json!({
            "id": self.id,
            "generation": self.generation.to_string(),
            "protocol": self.protocol,
            "inbound": self.inbound,
            "source": self.source,
            "target": attribution.target,
            "route": attribution.route,
            "outbound": attribution.outbound,
            "started_ms": self.started_ms,
            "duration_ms": now.duration_since(self.started).as_millis() as u64,
            "upload_bytes": self.upload.load(Ordering::Relaxed).to_string(),
            "download_bytes": self.download.load(Ordering::Relaxed).to_string(),
            "upload_rate": f64::from_bits(self.upload_rate.load(Ordering::Relaxed)),
            "download_rate": f64::from_bits(self.download_rate.load(Ordering::Relaxed)),
            "state": state,
        })
    }
}

struct Lease {
    generation: Arc<Generation>,
    record: Arc<Record>,
    tracked: bool,
    details: bool,
    finished: AtomicBool,
    cancel_epoch: u64,
}

impl Lease {
    fn finish(&self, state: &str) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut registry = lock(&self.generation.registry);
        registry.active -= 1;
        match self.record.protocol {
            "tcp" => registry.tcp_active -= 1,
            "udp" => registry.udp_active -= 1,
            _ => {}
        }
        registry.cancellation.remove(&self.record.id);
        if !self.tracked {
            self.generation.omitted.fetch_sub(1, Ordering::Relaxed);
            return;
        }
        registry.live.remove(&self.record.id);
        let now = Instant::now();
        registry.prune(now);
        if registry.history.len() == HISTORY_LIMIT {
            registry.history.pop_front();
        }
        registry
            .history
            .push_back((now, self.record.view(now, state)));
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.finish("closed");
    }
}

/// Cloneable flow/association lease. Explicit finish is idempotent; dropping its final
/// owner retires it as `closed`. Cancellation is sticky and independent from retirement.
#[derive(Clone)]
pub struct Connection(Arc<Lease>);

impl Connection {
    pub(crate) fn new(
        generation: Arc<Generation>,
        sequence: u64,
        details: bool,
        metadata: ConnectionMetadata,
    ) -> Self {
        let started = Instant::now();
        let record = Arc::new(Record {
            id: format!("{}:{sequence}", generation.id),
            generation: generation.id,
            protocol: metadata.protocol,
            inbound: metadata.inbound,
            source: if details { metadata.source } else { None },
            attribution: Mutex::new(Attribution {
                target: if details { metadata.target } else { None },
                route: None,
                outbound: None,
            }),
            started,
            started_ms: started.duration_since(generation.started).as_millis() as u64,
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            cancel: watch::channel(false).0,
            sampled: Mutex::new((started, 0, 0)),
            upload_rate: AtomicU64::new(0),
            download_rate: AtomicU64::new(0),
        });
        let mut registry = lock(&generation.registry);
        let cancel_epoch = *generation.cancel_epoch.borrow();
        registry.active += 1;
        match metadata.protocol {
            "tcp" => registry.tcp_active += 1,
            "udp" => registry.udp_active += 1,
            _ => {}
        }
        let tracked = if registry.live.len() < LIVE_LIMIT {
            registry.live.insert(record.id.clone(), record.clone());
            true
        } else {
            generation.omitted.fetch_add(1, Ordering::Relaxed);
            false
        };
        if registry.cancellation.len() < CANCELLATION_LIMIT {
            registry
                .cancellation
                .insert(record.id.clone(), Arc::downgrade(&record));
        }
        drop(registry);
        Self(Arc::new(Lease {
            generation,
            record,
            tracked,
            details,
            cancel_epoch,
            finished: AtomicBool::new(false),
        }))
    }

    /// Stable, generation-qualified identity for explicit cancellation commands.
    pub fn id(&self) -> String {
        self.0.record.id.clone()
    }

    /// Updates the observed target, discarding it entirely when detail capture is disabled.
    pub fn set_target(&self, target: Option<String>) {
        if self.0.details {
            lock(&self.0.record.attribution).target = target;
        }
    }

    /// Records the real route and outbound attribution; it never evaluates or changes routing.
    pub fn set_route(&self, route: Option<String>, outbound: Option<String>) {
        let mut attribution = lock(&self.0.record.attribution);
        attribution.route = route;
        attribution.outbound = outbound;
    }

    /// Adds successfully transferred upload bytes. No shared table lock is acquired.
    pub fn upload(&self, bytes: usize) {
        if bytes != 0 && !self.0.finished.load(Ordering::Acquire) {
            self.0
                .record
                .upload
                .fetch_add(bytes as u64, Ordering::Relaxed);
            self.0
                .generation
                .upload
                .fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }

    /// Adds successfully transferred download bytes. No shared table lock is acquired.
    pub fn download(&self, bytes: usize) {
        if bytes != 0 && !self.0.finished.load(Ordering::Acquire) {
            self.0
                .record
                .download
                .fetch_add(bytes as u64, Ordering::Relaxed);
            self.0
                .generation
                .download
                .fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }

    /// Resolves when explicit closure is requested, including requests made before polling.
    /// Multiple clones may await it concurrently; safe to recreate inside `tokio::select!`.
    pub async fn cancelled(&self) {
        let mut receiver = self.0.record.cancel.subscribe();
        let mut epoch = self.0.generation.cancel_epoch.subscribe();
        tokio::select! {
            _ = receiver.wait_for(|cancelled| *cancelled) => {},
            _ = epoch.wait_for(|epoch| *epoch != self.0.cancel_epoch) => {},
        }
    }

    /// Retires once with the caller's actual terminal state after its I/O owners have stopped.
    /// Cancellation alone does not call this. Further byte observations are ignored.
    pub fn finish(&self, state: &str) {
        self.0.finish(state);
    }
}
