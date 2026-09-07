use std::collections::VecDeque;
use std::net::SocketAddr;

use ferrum2_runtime::{
    DirectUdpSessionAdmission, UDP_SESSION_QUEUE_DEPTH, UdpBufferBudget, UdpBufferReservation,
    UdpRuntimeError,
};
use ferrum2_shadowsocks::PendingUdpRequest;
use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use tokio::time::Instant;

use crate::run::dns_egress::ServerDnsResolver;

pub(super) struct QueuedRequest {
    pub pending: PendingUdpRequest,
    pub peer: SocketAddr,
    pub wire_len: usize,
    pub deadline: Instant,
    // Retained plaintext remains accounted even before its future is first polled.
    pub bytes: UdpBufferReservation,
}

pub(super) struct PreparedRequest<S> {
    pub request: QueuedRequest,
    pub prepared: Option<(DirectUdpSessionAdmission<S>, ServerDnsResolver, usize)>,
}

struct Entry {
    requests: VecDeque<QueuedRequest>,
}

type OpenResult<S> =
    Result<(DirectUdpSessionAdmission<S>, ServerDnsResolver, usize), UdpRuntimeError>;

/// Root-owned futures, not spawned task handles: dropping the set destroys the
/// actual resolver/open futures and their provisional capacity before shutdown.
/// Each identity has one open and a byte-accounted bounded FIFO of first packets.
pub(super) struct NewSessionWork<S> {
    entries: Vec<Option<Entry>>,
    futures: FuturesUnordered<BoxFuture<'static, (usize, OpenResult<S>)>>,
    budget: UdpBufferBudget,
    limit: usize,
}

impl<S: Send + 'static> NewSessionWork<S> {
    pub fn new(limit: usize, budget: UdpBufferBudget) -> Self {
        Self {
            entries: Vec::new(),
            futures: FuturesUnordered::new(),
            budget,
            limit,
        }
    }

    pub fn has_work(&self) -> bool {
        !self.futures.is_empty()
    }

    pub fn account(
        &self,
        pending: PendingUdpRequest,
        peer: SocketAddr,
        wire_len: usize,
        deadline: Instant,
    ) -> Result<QueuedRequest, UdpRuntimeError> {
        let bytes = self
            .budget
            .reserve(pending.datagram().allocated_capacity())?;
        Ok(QueuedRequest {
            pending,
            peer,
            wire_len,
            deadline,
            bytes,
        })
    }

    pub fn submit(
        &mut self,
        request: QueuedRequest,
        open: impl Future<Output = OpenResult<S>> + Send + 'static,
    ) -> Result<(), UdpRuntimeError> {
        if let Some(entry) = self.entries.iter_mut().flatten().find(|entry| {
            entry
                .requests
                .front()
                .expect("first request")
                .pending
                .same_identity(&request.pending)
        }) {
            if entry.requests.len() == UDP_SESSION_QUEUE_DEPTH {
                return Err(UdpRuntimeError::QueueFull);
            }
            entry.requests.push_back(request);
            return Ok(());
        }
        let slot = if let Some(slot) = self.entries.iter().position(Option::is_none) {
            slot
        } else if self.entries.len() < self.limit {
            self.entries.push(None);
            self.entries.len() - 1
        } else {
            return Err(UdpRuntimeError::SessionLimit);
        };
        let deadline = request.deadline;
        self.entries[slot] = Some(Entry {
            requests: VecDeque::from([request]),
        });
        self.futures.push(
            async move {
                let result = tokio::time::timeout_at(deadline, open)
                    .await
                    .unwrap_or(Err(UdpRuntimeError::Resolve));
                (slot, result)
            }
            .boxed(),
        );
        Ok(())
    }

    pub async fn next(&mut self) -> Result<VecDeque<PreparedRequest<S>>, UdpRuntimeError> {
        let (slot, result) = self.futures.next().await.expect("nonempty admission work");
        let mut entry = self.entries[slot].take().expect("owned admission entry");
        let prepared = result?;
        let first = entry.requests.pop_front().expect("first request");
        let mut ready = VecDeque::from([PreparedRequest {
            request: first,
            prepared: Some(prepared),
        }]);
        ready.extend(entry.requests.into_iter().map(|request| PreparedRequest {
            request,
            prepared: None,
        }));
        Ok(ready)
    }
}
