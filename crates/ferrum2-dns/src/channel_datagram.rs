use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

use tokio::sync::mpsc;

use crate::{BoxedDnsDatagramIo, DnsDatagramIo};

type Packet = Vec<u8>;
type ReserveFuture = Pin<
    Box<dyn Future<Output = Result<mpsc::OwnedPermit<Packet>, mpsc::error::SendError<()>>> + Send>,
>;

const CHANNEL_DEPTH: usize = 1;

/// A bounded in-process datagram boundary for a DNS egress session.
///
/// The DNS runtime owns `io`. The egress session drains complete datagrams from
/// `outgoing` and publishes matching responses through `incoming`. Keeping the
/// poll state here avoids duplicating lock and
/// backpressure behavior in every application adapter.
pub struct ChannelDnsDatagram {
    io: BoxedDnsDatagramIo,
    outgoing: mpsc::Receiver<Packet>,
    incoming: mpsc::Sender<Packet>,
}

impl ChannelDnsDatagram {
    /// Creates a one-datagram-deep boundary with a closed maximum wire length.
    pub fn bounded(max_datagram_bytes: NonZeroUsize) -> Self {
        let (outgoing_sender, outgoing) = mpsc::channel(CHANNEL_DEPTH);
        let (incoming, incoming_receiver) = mpsc::channel(CHANNEL_DEPTH);
        Self {
            io: Box::new(ChannelDatagramIo {
                outgoing: outgoing_sender,
                reserve: Mutex::new(None),
                incoming: Mutex::new(incoming_receiver),
                max_datagram_bytes: max_datagram_bytes.get(),
            }),
            outgoing,
            incoming,
        }
    }

    /// Transfers the DNS-runtime endpoint and the two session endpoints.
    pub fn into_parts(
        self,
    ) -> (
        BoxedDnsDatagramIo,
        mpsc::Receiver<Packet>,
        mpsc::Sender<Packet>,
    ) {
        (self.io, self.outgoing, self.incoming)
    }
}

struct ChannelDatagramIo {
    outgoing: mpsc::Sender<Packet>,
    reserve: Mutex<Option<ReserveFuture>>,
    incoming: Mutex<mpsc::Receiver<Packet>>,
    max_datagram_bytes: usize,
}

impl DnsDatagramIo for ChannelDatagramIo {
    fn poll_recv(&self, context: &mut Context<'_>, buffer: &mut [u8]) -> Poll<io::Result<usize>> {
        let Ok(mut incoming) = self.incoming.lock() else {
            return Poll::Ready(Err(io::Error::other("DNS UDP receive lock")));
        };
        match incoming.poll_recv(context) {
            Poll::Ready(Some(packet)) if packet.len() <= buffer.len() => {
                buffer[..packet.len()].copy_from_slice(&packet);
                Poll::Ready(Ok(packet.len()))
            }
            Poll::Ready(Some(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS UDP receive too large",
            ))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_send(&self, context: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        if buffer.len() > self.max_datagram_bytes {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS UDP send too large",
            )));
        }
        let Ok(mut reserve) = self.reserve.lock() else {
            return Poll::Ready(Err(io::Error::other("DNS UDP send lock")));
        };
        if reserve.is_none() {
            *reserve = Some(Box::pin(self.outgoing.clone().reserve_owned()));
        }
        match reserve
            .as_mut()
            .expect("DNS UDP reserve future")
            .as_mut()
            .poll(context)
        {
            Poll::Ready(Ok(permit)) => {
                reserve.take();
                permit.send(buffer.to_vec());
                Poll::Ready(Ok(buffer.len()))
            }
            Poll::Ready(Err(_)) => {
                reserve.take();
                Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests;
