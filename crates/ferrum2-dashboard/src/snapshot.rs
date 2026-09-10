use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::wire::{ConnectionCatalogView, ConnectionView};
use crate::{Dashboard, State, lock};

pub(super) struct Snapshot {
    state: State,
    details: bool,
    uptime_ms: u64,
    upload: u64,
    download: u64,
    connections: Vec<ConnectionView>,
    history: Vec<ConnectionView>,
    catalogs: Vec<Arc<ConnectionCatalogView>>,
    active: usize,
    tcp_active: usize,
    udp_active: usize,
    omitted: usize,
}

impl Snapshot {
    pub(super) fn capture(dashboard: &Dashboard) -> Self {
        // Values/catalogs/log entries are immutable Arcs; this only captures bounded refs.
        let state = lock(&dashboard.0.state).clone();
        let generation = &state.generation;
        let now = Instant::now();
        let (live, history, active, tcp_active, udp_active, omitted) = {
            let mut registry = lock(&generation.registry);
            registry.prune(now);
            (
                registry.live.values().cloned().collect::<Vec<_>>(),
                registry
                    .history
                    .iter()
                    .map(|(_, record)| record.clone())
                    .collect::<Vec<_>>(),
                registry.active,
                registry.tcp_active,
                registry.udp_active,
                generation.omitted.load(Ordering::Relaxed),
            )
        };
        let mut catalogs = BTreeMap::new();
        for record in live.iter().chain(&history) {
            if let Some(catalog) = &record.catalog {
                catalogs
                    .entry(catalog.id.as_str())
                    .or_insert_with(|| catalog.clone());
            }
        }
        Self {
            details: dashboard.0.details,
            uptime_ms: now
                .saturating_duration_since(generation.started)
                .as_millis() as u64,
            upload: generation.upload.load(Ordering::Relaxed),
            download: generation.download.load(Ordering::Relaxed),
            connections: live.iter().map(|record| record.view(now, true)).collect(),
            history: history
                .iter()
                .map(|record| record.view(now, false))
                .collect(),
            catalogs: catalogs.into_values().collect(),
            active,
            tcp_active,
            udp_active,
            omitted,
            state,
        }
    }
}

#[derive(Serialize)]
struct Traffic {
    upload_bytes: String,
    download_bytes: String,
    upload_rate: f64,
    download_rate: f64,
}

#[derive(Serialize)]
struct Process {
    cpu_percent: Option<f64>,
    memory_bytes: Option<String>,
}

impl Serialize for Snapshot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(19))?;
        map.serialize_entry("version", &2)?;
        map.serialize_entry("generation", &self.state.generation.id.to_string())?;
        map.serialize_entry("state", &self.state.runtime)?;
        map.serialize_entry("error", &self.state.error)?;
        map.serialize_entry("details", &self.details)?;
        map.serialize_entry("uptime_ms", &self.uptime_ms)?;
        map.serialize_entry(
            "traffic",
            &Traffic {
                upload_bytes: self.upload.to_string(),
                download_bytes: self.download.to_string(),
                upload_rate: self.state.upload_rate,
                download_rate: self.state.download_rate,
            },
        )?;
        map.serialize_entry(
            "process",
            &Process {
                cpu_percent: self.state.cpu,
                memory_bytes: self.state.memory.map(|bytes| bytes.to_string()),
            },
        )?;
        map.serialize_entry("connections", &self.connections)?;
        map.serialize_entry("history", &self.history)?;
        map.serialize_entry(
            "connection_catalogs",
            &self.catalogs.iter().map(Arc::as_ref).collect::<Vec<_>>(),
        )?;
        map.serialize_entry("active_connections", &self.active)?;
        map.serialize_entry("active_tcp", &self.tcp_active)?;
        map.serialize_entry("active_udp", &self.udp_active)?;
        map.serialize_entry("omitted_connections", &self.omitted)?;
        map.serialize_entry(
            "logs",
            &self.state.logs.iter().map(Arc::as_ref).collect::<Vec<_>>(),
        )?;
        map.serialize_entry("resources", self.state.resources.as_ref())?;
        map.serialize_entry("catalog", self.state.catalog.as_ref())?;
        map.serialize_entry("domains", self.state.domains.as_ref())?;
        map.end()
    }
}
