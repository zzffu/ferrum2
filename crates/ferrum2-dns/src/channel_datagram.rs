use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use bytes::BytesMut;
use tokio::sync::mpsc;

use crate::{BoxedDnsDatagramIo, DnsDatagramIo};

type Packet = DnsDatagramLease;
type ReserveFuture = Pin<
    Box<dyn Future<Output = Result<mpsc::OwnedPermit<Packet>, mpsc::error::SendError<()>>> + Send>,
>;

const CHANNEL_DEPTH: usize = 1;

/// One bounded datagram buffer whose allocation returns to its channel on drop.
///
/// Session endpoints move this lease through the channel instead of allocating a
/// packet for every query. The mutable backing is exposed for socket APIs such
/// as `recv_buf_from`; the channel still validates the configured maximum before
/// copying a received packet into Hickory's caller-owned slice.
pub struct DnsDatagramLease {
    buffer: Option<BytesMut>,
    pool: Arc<LeasePool>,
}

impl fmt::Debug for DnsDatagramLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsDatagramLease")
            .field("len", &self.len())
            .field("capacity", &self.buffer().capacity())
            .field("max_datagram_bytes", &self.max_datagram_bytes())
            .finish()
    }
}

impl DnsDatagramLease {
    /// Returns the initialized bytes in this datagram.
    pub fn as_slice(&self) -> &[u8] {
        self.buffer().as_ref()
    }

    /// Returns the mutable owned backing for an append-style socket receive.
    pub fn as_bytes_mut(&mut self) -> &mut BytesMut {
        self.buffer_mut()
    }

    /// Exchanges this lease's backing with another bounded owned buffer.
    ///
    /// This lets an endpoint move an already-materialized response into the
    /// channel without copying it. The displaced allocation remains owned by
    /// the caller and can be recycled into its protocol or socket state.
    pub fn swap_bytes_mut(&mut self, buffer: &mut BytesMut) -> io::Result<()> {
        if buffer.len() > self.max_datagram_bytes() || buffer.capacity() > self.max_datagram_bytes()
        {
            return Err(datagram_too_large_error());
        }
        std::mem::swap(self.buffer_mut(), buffer);
        Ok(())
    }

    /// Removes all initialized bytes while retaining the allocation.
    pub fn clear(&mut self) {
        self.buffer_mut().clear();
    }

    /// Returns the current initialized datagram length.
    pub fn len(&self) -> usize {
        self.buffer().len()
    }

    /// Returns whether this datagram is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer().is_empty()
    }

    /// Returns the closed maximum accepted datagram length.
    pub fn max_datagram_bytes(&self) -> usize {
        self.pool.max_datagram_bytes
    }

    /// Truncates the initialized bytes to `length`.
    pub fn truncate(&mut self, length: usize) {
        self.buffer_mut().truncate(length);
    }

    /// Appends a complete payload without exceeding the channel's bound.
    pub fn extend_from_slice(&mut self, payload: &[u8]) -> io::Result<()> {
        let Some(length) = self.len().checked_add(payload.len()) else {
            return Err(datagram_too_large_error());
        };
        if length > self.max_datagram_bytes() {
            return Err(datagram_too_large_error());
        }
        self.buffer_mut().extend_from_slice(payload);
        Ok(())
    }

    fn buffer(&self) -> &BytesMut {
        self.buffer.as_ref().expect("DNS datagram lease buffer")
    }

    fn buffer_mut(&mut self) -> &mut BytesMut {
        self.buffer.as_mut().expect("DNS datagram lease buffer")
    }
}

impl AsRef<[u8]> for DnsDatagramLease {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Deref for DnsDatagramLease {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl Drop for DnsDatagramLease {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            self.pool.release(buffer);
        }
    }
}

/// Producer endpoint for datagrams flowing back into the DNS runtime.
///
/// Acquire the sole incoming lease, receive directly into its `BytesMut`, then
/// send that same lease. Dropping it at any point returns its allocation. This
/// endpoint intentionally has one owner, matching the channel's single session
/// and single waiter contract.
pub struct DnsDatagramLeaseSender {
    sender: mpsc::Sender<Packet>,
    pool: Arc<LeasePool>,
}

impl DnsDatagramLeaseSender {
    /// Waits for the reusable incoming buffer.
    pub async fn lease(&self) -> io::Result<DnsDatagramLease> {
        poll_fn(|context| self.pool.poll_lease(context)).await
    }

    /// Publishes one complete datagram to the DNS runtime.
    pub async fn send(
        &self,
        lease: DnsDatagramLease,
    ) -> Result<(), mpsc::error::SendError<DnsDatagramLease>> {
        self.sender.send(lease).await
    }

    /// Returns whether the DNS runtime has dropped its receiving endpoint.
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
}

struct LeasePool {
    max_datagram_bytes: usize,
    state: Mutex<LeasePoolState>,
}

struct LeasePoolState {
    buffer: Option<BytesMut>,
    waiter: Option<Waker>,
}

impl LeasePool {
    fn new(max_datagram_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            max_datagram_bytes,
            state: Mutex::new(LeasePoolState {
                buffer: Some(BytesMut::with_capacity(max_datagram_bytes)),
                waiter: None,
            }),
        })
    }

    fn poll_lease(self: &Arc<Self>, context: &mut Context<'_>) -> Poll<io::Result<Packet>> {
        let Ok(mut state) = self.state.lock() else {
            return Poll::Ready(Err(io::Error::other("DNS datagram lease lock")));
        };
        if let Some(buffer) = state.buffer.take() {
            return Poll::Ready(Ok(DnsDatagramLease {
                buffer: Some(buffer),
                pool: Arc::clone(self),
            }));
        }
        if !state
            .waiter
            .as_ref()
            .is_some_and(|waiter| waiter.will_wake(context.waker()))
        {
            state.waiter = Some(context.waker().clone());
        }
        Poll::Pending
    }

    fn release(&self, mut buffer: BytesMut) {
        buffer.clear();
        if buffer.capacity() > self.max_datagram_bytes {
            buffer = BytesMut::with_capacity(self.max_datagram_bytes);
        }
        let waiter = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            if state.buffer.is_some() {
                return;
            }
            state.buffer = Some(buffer);
            state.waiter.take()
        };
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
}

/// A bounded in-process datagram boundary for a DNS egress session.
///
/// The DNS runtime owns `io`. The egress session drains complete datagram
/// leases from `outgoing` and publishes matching responses through `incoming`.
/// Each direction owns exactly one reusable buffer and the channel remains one
/// datagram deep.
pub struct ChannelDnsDatagram {
    io: BoxedDnsDatagramIo,
    outgoing: mpsc::Receiver<Packet>,
    incoming: DnsDatagramLeaseSender,
}

impl ChannelDnsDatagram {
    /// Creates a one-datagram-deep boundary with a closed maximum wire length.
    pub fn bounded(max_datagram_bytes: NonZeroUsize) -> Self {
        let max_datagram_bytes = max_datagram_bytes.get();
        let outgoing_pool = LeasePool::new(max_datagram_bytes);
        let incoming_pool = LeasePool::new(max_datagram_bytes);
        let (outgoing_sender, outgoing) = mpsc::channel(CHANNEL_DEPTH);
        let (incoming_sender, incoming_receiver) = mpsc::channel(CHANNEL_DEPTH);
        Self {
            io: Box::new(ChannelDatagramIo {
                outgoing: outgoing_sender,
                outgoing_pool,
                send: Mutex::new(SendState::default()),
                incoming: Mutex::new(incoming_receiver),
                max_datagram_bytes,
            }),
            outgoing,
            incoming: DnsDatagramLeaseSender {
                sender: incoming_sender,
                pool: incoming_pool,
            },
        }
    }

    /// Transfers the DNS-runtime endpoint and the two session endpoints.
    pub fn into_parts(
        self,
    ) -> (
        BoxedDnsDatagramIo,
        mpsc::Receiver<DnsDatagramLease>,
        DnsDatagramLeaseSender,
    ) {
        (self.io, self.outgoing, self.incoming)
    }
}

#[derive(Default)]
struct SendState {
    reserve: Option<ReserveFuture>,
    permit: Option<mpsc::OwnedPermit<Packet>>,
}

struct ChannelDatagramIo {
    outgoing: mpsc::Sender<Packet>,
    outgoing_pool: Arc<LeasePool>,
    send: Mutex<SendState>,
    incoming: Mutex<mpsc::Receiver<Packet>>,
    max_datagram_bytes: usize,
}

impl DnsDatagramIo for ChannelDatagramIo {
    fn poll_recv(&self, context: &mut Context<'_>, buffer: &mut [u8]) -> Poll<io::Result<usize>> {
        let Ok(mut incoming) = self.incoming.lock() else {
            return Poll::Ready(Err(io::Error::other("DNS UDP receive lock")));
        };
        match incoming.poll_recv(context) {
            Poll::Ready(Some(packet))
                if packet.len() <= self.max_datagram_bytes && packet.len() <= buffer.len() =>
            {
                buffer[..packet.len()].copy_from_slice(&packet);
                Poll::Ready(Ok(packet.len()))
            }
            Poll::Ready(Some(_)) => Poll::Ready(Err(datagram_too_large_error())),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_send(&self, context: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        if buffer.len() > self.max_datagram_bytes {
            return Poll::Ready(Err(datagram_too_large_error()));
        }
        let Ok(mut send) = self.send.lock() else {
            return Poll::Ready(Err(io::Error::other("DNS UDP send lock")));
        };
        if send.permit.is_none() {
            if send.reserve.is_none() {
                send.reserve = Some(Box::pin(self.outgoing.clone().reserve_owned()));
            }
            match send
                .reserve
                .as_mut()
                .expect("DNS UDP reserve future")
                .as_mut()
                .poll(context)
            {
                Poll::Ready(Ok(permit)) => {
                    send.reserve.take();
                    send.permit = Some(permit);
                }
                Poll::Ready(Err(_)) => {
                    send.reserve.take();
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        let mut lease = match self.outgoing_pool.poll_lease(context) {
            Poll::Ready(Ok(lease)) => lease,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        };
        lease
            .extend_from_slice(buffer)
            .expect("validated DNS datagram length");
        send.permit
            .take()
            .expect("DNS UDP reserved channel permit")
            .send(lease);
        Poll::Ready(Ok(buffer.len()))
    }
}

fn datagram_too_large_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "DNS UDP datagram too large")
}

#[cfg(test)]
mod tests;
