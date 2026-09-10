use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::watch;

use crate::wire::{
    ConnectionCatalogView, ConnectionDecisionKind, ConnectionDecisionView, ConnectionSniffProtocol,
    ConnectionSniffStatus, ConnectionSniffView, ConnectionView,
};
use crate::{CANCELLATION_LIMIT, Generation, HISTORY_LIMIT, LIVE_LIMIT, lock};

/// Facts captured at admission; endpoint rendering belongs to the sampler.
pub struct ConnectionMetadata {
    pub protocol: &'static str,
    pub inbound: &'static str,
    pub inbound_id: Option<usize>,
    pub source: Option<SocketAddr>,
    pub target: Option<ConnectionTarget>,
}

#[derive(Clone)]
pub enum ConnectionTarget {
    Socket(SocketAddr),
    Domain { name: String, port: u16 },
}

#[derive(Clone)]
pub struct DecisionMetadata {
    pub kind: ConnectionDecisionKind,
    pub rule_index: Option<usize>,
    pub rule_generation: Option<u64>,
    pub sniff: SniffMetadata,
}

#[derive(Clone)]
pub struct SniffMetadata {
    pub status: ConnectionSniffStatus,
    pub protocol: Option<ConnectionSniffProtocol>,
    pub domain: Option<String>,
    pub rule_index: Option<usize>,
}

#[derive(Clone)]
struct Facts {
    target: Option<ConnectionTarget>,
    decision: Option<(DecisionMetadata, Vec<usize>)>,
}

#[derive(Clone)]
struct Final {
    at: Instant,
    state: String,
    upload: u64,
    download: u64,
}

struct Attribution {
    facts: Arc<Facts>,
    final_state: Option<Final>,
}

pub(crate) struct Record {
    id: String,
    generation: u64,
    protocol: &'static str,
    inbound: &'static str,
    inbound_id: Option<usize>,
    source: Option<SocketAddr>,
    pub(crate) catalog: Option<Arc<ConnectionCatalogView>>,
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
        let elapsed = now.saturating_duration_since(previous.0).as_secs_f64();
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

    pub(crate) fn view(&self, now: Instant, active: bool) -> ConnectionView {
        let (facts, final_state) = {
            let attribution = lock(&self.attribution);
            (attribution.facts.clone(), attribution.final_state.clone())
        };
        let target = facts.target.as_ref().map(|target| match target {
            ConnectionTarget::Socket(address) => address.to_string(),
            ConnectionTarget::Domain { name, port } => format!("{name}:{port}"),
        });
        let requested_domain = match &facts.target {
            Some(ConnectionTarget::Domain { name, .. }) => Some(name.clone()),
            _ => None,
        };
        let decision = facts
            .decision
            .as_ref()
            .map(|(decision, hops)| ConnectionDecisionView {
                kind: decision.kind,
                rule_index: decision.rule_index,
                rule_generation: decision
                    .rule_generation
                    .map(|generation| generation.to_string()),
                hops: hops.clone(),
                sniff: ConnectionSniffView {
                    status: decision.sniff.status,
                    protocol: decision.sniff.protocol,
                    domain: decision.sniff.domain.clone(),
                    rule_index: decision.sniff.rule_index,
                },
            });
        let inbound_tag = self
            .catalog
            .as_ref()
            .and_then(|catalog| {
                catalog
                    .inbounds
                    .iter()
                    .find(|name| Some(name.index) == self.inbound_id)
            })
            .map(|name| name.tag.clone());
        ConnectionView {
            id: self.id.clone(),
            generation: self.generation.to_string(),
            protocol: self.protocol.to_owned(),
            inbound: self.inbound.to_owned(),
            inbound_tag,
            source: self.source.map(|address| address.to_string()),
            target,
            requested_domain,
            catalog_id: self.catalog.as_ref().map(|catalog| catalog.id.clone()),
            decision,
            started_ms: self.started_ms as f64,
            duration_ms: final_state
                .as_ref()
                .map_or(now, |final_state| final_state.at)
                .saturating_duration_since(self.started)
                .as_millis() as f64,
            upload_bytes: final_state
                .as_ref()
                .map_or_else(|| self.upload.load(Ordering::Relaxed), |state| state.upload)
                .to_string(),
            download_bytes: final_state
                .as_ref()
                .map_or_else(
                    || self.download.load(Ordering::Relaxed),
                    |state| state.download,
                )
                .to_string(),
            // Membership was captured atomically. A concurrently retired row may remain
            // active for this snapshot, but can never also appear in its history.
            state: if active {
                "active".to_owned()
            } else {
                final_state
                    .as_ref()
                    .expect("history is sealed")
                    .state
                    .clone()
            },
            upload_rate: if final_state.is_some() {
                0.0
            } else {
                f64::from_bits(self.upload_rate.load(Ordering::Relaxed))
            },
            download_rate: if final_state.is_some() {
                0.0
            } else {
                f64::from_bits(self.download_rate.load(Ordering::Relaxed))
            },
        }
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
        let now = Instant::now();
        if self.tracked {
            lock(&self.record.attribution).final_state = Some(Final {
                at: now,
                state: state.to_owned(),
                upload: self.record.upload.load(Ordering::Relaxed),
                download: self.record.download.load(Ordering::Relaxed),
            });
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
        registry.history.push_back((now, self.record.clone()));
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.finish("closed");
    }
}

/// Cloneable lease. Finish follows stopped I/O owners; the final owner otherwise retires it.
#[derive(Clone)]
pub struct Connection(Arc<Lease>);

impl Connection {
    pub(crate) fn new(
        generation: Arc<Generation>,
        sequence: u64,
        details: bool,
        metadata: ConnectionMetadata,
        catalog: Option<Arc<ConnectionCatalogView>>,
    ) -> Self {
        let started = Instant::now();
        let id = format!("{}:{sequence}", generation.id);
        let mut registry = lock(&generation.registry);
        let tracked = registry.live.len() < LIVE_LIMIT;
        let capture_details = tracked && details;
        let record = Arc::new(Record {
            id,
            generation: generation.id,
            protocol: metadata.protocol,
            inbound: metadata.inbound,
            inbound_id: if tracked { metadata.inbound_id } else { None },
            source: if capture_details {
                metadata.source
            } else {
                None
            },
            catalog: if tracked { catalog } else { None },
            attribution: Mutex::new(Attribution {
                facts: Arc::new(Facts {
                    target: if capture_details {
                        metadata.target
                    } else {
                        None
                    },
                    decision: None,
                }),
                final_state: None,
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
        let cancel_epoch = *generation.cancel_epoch.borrow();
        registry.active += 1;
        match metadata.protocol {
            "tcp" => registry.tcp_active += 1,
            "udp" => registry.udp_active += 1,
            _ => {}
        }
        if tracked {
            registry.live.insert(record.id.clone(), record.clone());
        } else {
            generation.omitted.fetch_add(1, Ordering::Relaxed);
        }
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

    /// Stable generation-qualified cancellation identity.
    pub fn id(&self) -> String {
        self.0.record.id.clone()
    }

    /// Captures an observed target only while the visible lease remains live.
    pub fn set_target(&self, target: Option<ConnectionTarget>) {
        if !self.0.details || !self.0.tracked {
            return;
        }
        let mut attribution = lock(&self.0.record.attribution);
        if self.0.finished.load(Ordering::Acquire) {
            return;
        }
        Arc::make_mut(&mut attribution.facts).target = target;
    }

    /// Publishes captured routing evidence. Concrete plans contain at most eight hops.
    pub fn set_decision(&self, mut decision: DecisionMetadata, hops: &[usize]) {
        if !self.0.tracked {
            return;
        }
        let mut attribution = lock(&self.0.record.attribution);
        if self.0.finished.load(Ordering::Acquire) {
            return;
        }
        if hops.len() > 8 {
            return;
        }
        if !self.0.details {
            decision.rule_index = None;
            decision.sniff = SniffMetadata {
                status: ConnectionSniffStatus::Redacted,
                protocol: None,
                domain: None,
                rule_index: None,
            };
        }
        Arc::make_mut(&mut attribution.facts).decision = Some((decision, hops.to_vec()));
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
