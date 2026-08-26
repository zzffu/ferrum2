use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;

use super::{Command, RuntimeStats, ShutdownReport};
use crate::error::DnsError;
use crate::resolver::{self, SelectedServer};
use crate::runtime_provider::{
    DNS_QUERY_SCOPE, DnsEgress, FerrumRuntimeProvider, RuntimeCounters, TaskSet,
};

pub(super) async fn run_commands(
    mut receiver: mpsc::Receiver<Command>,
    mut shutdown: oneshot::Receiver<()>,
    servers: Arc<Vec<SelectedServer>>,
    egress: Arc<dyn DnsEgress>,
    counters: Arc<RuntimeCounters>,
    runtime_handle: tokio::runtime::Handle,
) -> Result<ShutdownReport, DnsError> {
    let mut queries = JoinSet::new();
    let (cancel, cancel_rx) = watch::channel(false);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            completed = queries.join_next(), if !queries.is_empty() => {
                let _ = completed;
            }
            command = receiver.recv() => match command {
                Some(Command::Lookup { server, name, record_type, deadline, mut reply, context }) => {
                    let target = servers[server].first_target_snapshot();
                    let plan = servers[server].plan_snapshot();
                    let servers = Arc::clone(&servers);
                    let egress = Arc::clone(&egress);
                    let counters = Arc::clone(&counters);
                    let tasks = TaskSet::default();
                    let query_tasks = tasks.clone();
                    let mut cancelled = cancel_rx.clone();
                    let query_scope = context.scope();
                    queries.spawn(async move {
                        let provider_scope = query_scope.clone();
                        let result = DNS_QUERY_SCOPE.scope(query_scope, async {
                            let provider = FerrumRuntimeProvider::new(
                                Arc::clone(&egress),
                                target.clone(),
                                plan.clone(),
                                deadline,
                                tasks.clone(),
                                Arc::clone(&counters),
                                provider_scope.clone(),
                            );
                            tokio::select! {
                                _ = cancelled.changed() => Err(DnsError::Shutdown),
                                _ = reply.closed() => Err(DnsError::Shutdown),
                                result = resolver::lookup(
                                    &servers[server],
                                    name.clone(),
                                    record_type,
                                    deadline,
                                    provider,
                                ) => result,
                            }
                        }).await;
                        query_tasks.abort_and_join().await;
                        drop(context);
                        if !reply.is_closed() {
                            let _ = reply.send(result);
                        }
                    });
                }
                Some(Command::LookupIps { server, name, deadline, mut reply, context }) => {
                    let target = servers[server].first_target_snapshot();
                    let plan = servers[server].plan_snapshot();
                    let servers = Arc::clone(&servers);
                    let egress = Arc::clone(&egress);
                    let counters = Arc::clone(&counters);
                    let tasks = TaskSet::default();
                    let query_tasks = tasks.clone();
                    let mut cancelled = cancel_rx.clone();
                    let query_scope = context.scope();
                    queries.spawn(async move {
                        let provider_scope = query_scope.clone();
                        let result = DNS_QUERY_SCOPE.scope(query_scope, async {
                            let provider = FerrumRuntimeProvider::new(
                                Arc::clone(&egress),
                                target.clone(),
                                plan.clone(),
                                deadline,
                                tasks.clone(),
                                Arc::clone(&counters),
                                provider_scope.clone(),
                            );
                            tokio::select! {
                                _ = cancelled.changed() => Err(DnsError::Shutdown),
                                _ = reply.closed() => Err(DnsError::Shutdown),
                                result = resolver::lookup_ips(
                                    &servers[server],
                                    name.clone(),
                                    deadline,
                                    provider,
                                ) => result,
                            }
                        }).await;
                        query_tasks.abort_and_join().await;
                        drop(context);
                        if !reply.is_closed() {
                            let _ = reply.send(result);
                        }
                    });
                }
                Some(Command::Query { server, request, deadline, mut reply, context }) => {
                    let target = servers[server].first_target_snapshot();
                    let plan = servers[server].plan_snapshot();
                    let servers = Arc::clone(&servers);
                    let egress = Arc::clone(&egress);
                    let counters = Arc::clone(&counters);
                    let tasks = TaskSet::default();
                    let query_tasks = tasks.clone();
                    let mut cancelled = cancel_rx.clone();
                    let query_scope = context.scope();
                    queries.spawn(async move {
                        let provider_scope = query_scope.clone();
                        let result = DNS_QUERY_SCOPE.scope(query_scope, async {
                            let provider = FerrumRuntimeProvider::new(
                                Arc::clone(&egress),
                                target.clone(),
                                plan.clone(),
                                deadline,
                                tasks.clone(),
                                Arc::clone(&counters),
                                provider_scope.clone(),
                            );
                            tokio::select! {
                                _ = cancelled.changed() => Err(DnsError::Shutdown),
                                _ = reply.closed() => Err(DnsError::Shutdown),
                                result = resolver::query(
                                    &servers[server],
                                    request.clone(),
                                    deadline,
                                    provider,
                                ) => result,
                            }
                        }).await;
                        query_tasks.abort_and_join().await;
                        drop(context);
                        if !reply.is_closed() {
                            let _ = reply.send(result);
                        }
                    });
                }
                None => break,
            }
        }
    }

    receiver.close();
    let _ = cancel.send(true);
    while let Ok(command) = receiver.try_recv() {
        match command {
            Command::Lookup { reply, context, .. } => {
                drop(context);
                let _ = reply.send(Err(DnsError::Shutdown));
            }
            Command::LookupIps { reply, context, .. } => {
                drop(context);
                let _ = reply.send(Err(DnsError::Shutdown));
            }
            Command::Query { reply, context, .. } => {
                drop(context);
                let _ = reply.send(Err(DnsError::Shutdown));
            }
        }
    }
    while queries.join_next().await.is_some() {}

    for _ in 0..256 {
        let stats = runtime_stats(&counters);
        if runtime_handle.metrics().num_alive_tasks() == 0 && stats == RuntimeStats::default() {
            return Ok(ShutdownReport {
                runtime_tasks: 0,
                stats,
            });
        }
        tokio::task::yield_now().await;
    }
    Err(DnsError::Runtime)
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
