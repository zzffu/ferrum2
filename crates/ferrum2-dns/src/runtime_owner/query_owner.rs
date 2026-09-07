//! Parent-retained query records own admission and cleanup independently of bodies.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::stream::{FuturesUnordered, StreamExt};
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::lookup::Lookup;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::{Instant, Sleep};

use super::Command;
use crate::DnsError;
use crate::resolver::{self, SelectedServer};
use crate::runtime_provider::{
    DNS_QUERY_SCOPE, DnsEgress, DnsQueryContext, FerrumRuntimeProvider, RuntimeCounters, TaskSet,
};

enum QueryOperation {
    Lookup {
        server: usize,
        name: Name,
        record_type: RecordType,
    },
    LookupIps {
        server: usize,
        name: Name,
    },
    Query {
        server: usize,
        request: Message,
    },
}

enum QueryReply {
    Lookup(oneshot::Sender<Result<Lookup, DnsError>>),
    LookupIps(oneshot::Sender<Result<Vec<IpAddr>, DnsError>>),
    Query(oneshot::Sender<Result<Message, DnsError>>),
}

enum QueryBodyResult {
    Lookup(Result<Lookup, DnsError>),
    LookupIps(Result<Vec<IpAddr>, DnsError>),
    Query(Result<Message, DnsError>),
    Failed(DnsError),
}

impl QueryReply {
    fn poll_closed(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        match self {
            Self::Lookup(reply) => reply.poll_closed(cx),
            Self::LookupIps(reply) => reply.poll_closed(cx),
            Self::Query(reply) => reply.poll_closed(cx),
        }
    }

    fn send(self, result: QueryBodyResult) {
        match (self, result) {
            (Self::Lookup(reply), QueryBodyResult::Lookup(result)) => {
                let _ = reply.send(result);
            }
            (Self::LookupIps(reply), QueryBodyResult::LookupIps(result)) => {
                let _ = reply.send(result);
            }
            (Self::Query(reply), QueryBodyResult::Query(result)) => {
                let _ = reply.send(result);
            }
            (reply, QueryBodyResult::Failed(error)) => reply.fail(error),
            (
                reply,
                QueryBodyResult::Lookup(_)
                | QueryBodyResult::LookupIps(_)
                | QueryBodyResult::Query(_),
            ) => reply.fail(DnsError::Runtime),
        }
    }

    fn fail(self, error: DnsError) {
        match self {
            Self::Lookup(reply) => {
                let _ = reply.send(Err(error));
            }
            Self::LookupIps(reply) => {
                let _ = reply.send(Err(error));
            }
            Self::Query(reply) => {
                let _ = reply.send(Err(error));
            }
        }
    }
}

struct QueryState {
    context: DnsQueryContext,
    tasks: TaskSet,
    reply: QueryReply,
    deadline: Pin<Box<Sleep>>,
    body: JoinSet<QueryBodyResult>,
    result: Option<QueryBodyResult>,
    stopped: Option<DnsError>,
}

impl QueryState {
    fn new(command: Command) -> (Self, QueryOperation, Instant) {
        let (operation, reply, context, deadline) = match command {
            Command::Lookup {
                server,
                name,
                record_type,
                reply,
                context,
                deadline,
            } => (
                QueryOperation::Lookup {
                    server,
                    name,
                    record_type,
                },
                QueryReply::Lookup(reply),
                context,
                deadline,
            ),
            Command::LookupIps {
                server,
                name,
                reply,
                context,
                deadline,
            } => (
                QueryOperation::LookupIps { server, name },
                QueryReply::LookupIps(reply),
                context,
                deadline,
            ),
            Command::Query {
                server,
                request,
                reply,
                context,
                deadline,
            } => (
                QueryOperation::Query { server, request },
                QueryReply::Query(reply),
                context,
                deadline,
            ),
        };
        (
            Self {
                context,
                tasks: TaskSet::default(),
                reply,
                deadline: Box::pin(tokio::time::sleep_until(deadline)),
                body: JoinSet::new(),
                result: None,
                stopped: None,
            },
            operation,
            deadline,
        )
    }

    fn stop(&mut self, reason: DnsError) {
        if self.stopped.is_none() || reason == DnsError::Runtime {
            self.stopped = Some(reason);
        }
        if self.context.is_root() {
            self.context.close_chain();
        }
        self.tasks.close();
        self.body.abort_all();
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> bool {
        self.context.register(cx);
        if let Poll::Ready(Some(joined)) = self.body.poll_join_next(cx) {
            self.result = Some(match joined {
                Ok(result) => result,
                Err(error) => {
                    if error.is_panic() || self.stopped.is_none() {
                        self.context.task_failed();
                        self.stop(DnsError::Runtime);
                    }
                    QueryBodyResult::Failed(self.stopped.unwrap_or(DnsError::Runtime))
                }
            });
            self.tasks.close();
            if self.context.is_root() {
                self.context.close_chain();
            }
        }
        let (failed, drained) = self.tasks.poll(cx);
        if failed {
            self.context.task_failed();
        }
        if self.context.has_task_failure() {
            self.stop(DnsError::Runtime);
        } else if self.result.is_none() {
            if self.reply.poll_closed(cx).is_ready()
                || (!self.context.is_root() && self.context.chain_closed())
            {
                self.stop(DnsError::Shutdown);
            } else if self.deadline.as_mut().poll(cx).is_ready() {
                self.stop(DnsError::Timeout);
            }
        }
        self.result.is_some()
            && drained
            && (!self.context.is_root() || self.context.children_drained(cx))
    }

    fn finish(self) {
        let Self {
            context,
            reply,
            result,
            stopped,
            tasks,
            deadline,
            body,
        } = self;
        let result = stopped
            .map(QueryBodyResult::Failed)
            .or(result)
            .expect("joined query result");
        drop((tasks, deadline, body));
        // Admission is the last cleanup resource, released before publishing a
        // result so callers cannot observe completion ahead of cleanup.
        drop(context);
        reply.send(result);
    }
}

/// A supervisor is polled independently; its separately spawned body never owns cleanup.
struct QueryRecord(Option<QueryState>);

impl Future for QueryRecord {
    type Output = bool;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<bool> {
        let state = self.0.as_mut().expect("live query supervisor");
        if !state.poll(cx) {
            return Poll::Pending;
        }
        let failed = state.context.has_task_failure();
        self.0.take().expect("completed query supervisor").finish();
        Poll::Ready(failed)
    }
}

#[derive(Default)]
pub(super) struct QueryOwner {
    records: FuturesUnordered<QueryRecord>,
    task_failed: bool,
}

impl QueryOwner {
    pub(super) fn spawn(
        &mut self,
        command: Command,
        servers: Arc<Vec<SelectedServer>>,
        egress: Arc<dyn DnsEgress>,
        counters: Arc<RuntimeCounters>,
    ) {
        let (mut record, operation, deadline) = QueryState::new(command);
        if record.context.chain_closed() {
            record.result = Some(QueryBodyResult::Failed(DnsError::Shutdown));
            record.stop(DnsError::Shutdown);
            self.records.push(QueryRecord(Some(record)));
            return;
        }
        let scope = record.context.scope();
        let registration = record.tasks.registrar();
        // All cleanup state is already in the parent record before constructing
        // or scheduling a body that may panic or never receive its first poll.
        let body = async move {
            let server_index = match &operation {
                QueryOperation::Lookup { server, .. }
                | QueryOperation::LookupIps { server, .. }
                | QueryOperation::Query { server, .. } => *server,
            };
            let server = &servers[server_index];
            let provider = FerrumRuntimeProvider::new(
                egress,
                server.first_target_snapshot(),
                server.plan_snapshot(),
                deadline,
                registration,
                counters,
                scope.clone(),
            );
            DNS_QUERY_SCOPE
                .scope(scope, async move {
                    match operation {
                        QueryOperation::Lookup {
                            name, record_type, ..
                        } => QueryBodyResult::Lookup(
                            resolver::lookup(server, name, record_type, deadline, provider).await,
                        ),
                        QueryOperation::LookupIps { name, .. } => QueryBodyResult::LookupIps(
                            resolver::lookup_ips(server, name, deadline, provider).await,
                        ),
                        QueryOperation::Query { request, .. } => QueryBodyResult::Query(
                            resolver::query(server, request, deadline, provider).await,
                        ),
                    }
                })
                .await
        };
        record.body.spawn(body);
        self.records.push(QueryRecord(Some(record)));
    }

    pub(super) fn reject(&mut self, command: Command) {
        let (mut record, _, _) = QueryState::new(command);
        record.result = Some(QueryBodyResult::Failed(DnsError::Shutdown));
        record.stop(DnsError::Shutdown);
        self.records.push(QueryRecord(Some(record)));
    }

    pub(super) fn stop(&mut self) {
        for record in self.records.iter_mut() {
            record
                .0
                .as_mut()
                .expect("live supervisor")
                .stop(DnsError::Shutdown);
        }
    }

    pub(super) fn failed(&self) -> bool {
        self.task_failed
    }
    pub(super) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub(super) async fn next(&mut self) -> Option<()> {
        let failed = self.records.next().await?;
        self.task_failed |= failed;
        Some(())
    }
}

#[cfg(test)]
mod tests;
