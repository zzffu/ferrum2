use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::{mpsc, oneshot};

use super::{Command, RuntimeStats, ShutdownReport};
use crate::error::DnsError;
use crate::resolver::SelectedServer;
use crate::runtime_provider::{DnsEgress, RuntimeCounters};

pub(super) async fn run_commands(
    mut receiver: mpsc::Receiver<Command>,
    mut shutdown: oneshot::Receiver<()>,
    servers: Arc<Vec<SelectedServer>>,
    egress: Arc<dyn DnsEgress>,
    counters: Arc<RuntimeCounters>,
    runtime_handle: tokio::runtime::Handle,
) -> Result<ShutdownReport, DnsError> {
    let mut queries = super::query_owner::QueryOwner::default();
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            _ = queries.next(), if !queries.is_empty() => {},
            command = receiver.recv() => match command {
                Some(command) => queries.spawn(command, Arc::clone(&servers), Arc::clone(&egress), Arc::clone(&counters)),
                None => break,
            }
        }
    }

    receiver.close();
    queries.stop();
    while let Ok(command) = receiver.try_recv() {
        queries.reject(command);
    }
    while queries.next().await.is_some() {}
    let stats = runtime_stats(&counters);
    if queries.failed()
        || runtime_handle.metrics().num_alive_tasks() != 0
        || stats != RuntimeStats::default()
    {
        return Err(DnsError::Runtime);
    }
    Ok(ShutdownReport {
        runtime_tasks: 0,
        stats,
    })
}

pub(super) fn runtime_stats(counters: &RuntimeCounters) -> RuntimeStats {
    RuntimeStats {
        queries: counters.queries.load(Ordering::Acquire),
        tasks: counters.tasks.load(Ordering::Acquire),
        tcp_streams: counters.tcp_streams.load(Ordering::Acquire),
        udp_sockets: counters.udp_sockets.load(Ordering::Acquire),
        bridge_tasks: counters.bridge_tasks.load(Ordering::Acquire),
        sessions: counters.sessions.load(Ordering::Acquire),
        queues: counters.queues.load(Ordering::Acquire),
        buffers: counters.buffers.load(Ordering::Acquire),
    }
}
