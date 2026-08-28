use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use hickory_proto::op::{Message, SerialMessage};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::net::tcp::TcpStream as HickoryTcpStream;
use hickory_resolver::net::xfer::DnsStreamHandle;
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;

use super::{DnsProxy, DnsUdpEvent, DnsUdpObserver, ProxyIngress, ProxyTransport};

const MAX_DNS_UDP_WIRE: usize = 4096;

pub(super) fn encode_response(
    response: &Message,
    transport: ProxyTransport,
    advertised: u16,
    wire: &mut Vec<u8>,
) -> Option<()> {
    wire.clear();
    let mut encoder = BinEncoder::new(wire);
    let limit = match transport {
        ProxyTransport::Udp => usize::from(advertised).min(MAX_DNS_UDP_WIRE),
        ProxyTransport::Tcp => usize::from(u16::MAX),
    };
    encoder.set_max_size(u16::try_from(limit).expect("DNS wire limit fits u16"));
    response.emit(&mut encoder).ok()?;
    Some(())
}

#[derive(Clone)]
pub(super) struct UdpRequestPool {
    inner: Arc<UdpRequestPoolInner>,
}

struct UdpRequestPoolInner {
    available: Mutex<Vec<UdpRequestSlot>>,
    permits: Arc<Semaphore>,
}

struct UdpRequestSlot {
    request: Box<[u8; MAX_DNS_UDP_WIRE]>,
    response: Vec<u8>,
}

struct UdpRequestLease {
    inner: Arc<UdpRequestPoolInner>,
    slot: Option<UdpRequestSlot>,
    permit: Option<OwnedSemaphorePermit>,
}

struct UdpRequestCompletion {
    observer: Option<Arc<dyn DnsUdpObserver>>,
}

impl Drop for UdpRequestCompletion {
    fn drop(&mut self) {
        if let Some(observer) = &self.observer {
            observer.record(DnsUdpEvent::Completed);
        }
    }
}

impl UdpRequestPool {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(UdpRequestPoolInner {
                available: Mutex::new(Vec::new()),
                permits: Arc::new(Semaphore::new(capacity)),
            }),
        }
    }

    fn try_acquire(&self) -> Option<UdpRequestLease> {
        let permit = Arc::clone(&self.inner.permits).try_acquire_owned().ok()?;
        let slot = self
            .inner
            .available
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop()
            .unwrap_or_else(UdpRequestSlot::new);
        Some(UdpRequestLease {
            inner: Arc::clone(&self.inner),
            slot: Some(slot),
            permit: Some(permit),
        })
    }
}

impl UdpRequestSlot {
    fn new() -> Self {
        Self {
            request: Box::new([0; MAX_DNS_UDP_WIRE]),
            response: Vec::with_capacity(MAX_DNS_UDP_WIRE),
        }
    }
}

impl UdpRequestLease {
    fn request_mut(&mut self) -> &mut [u8; MAX_DNS_UDP_WIRE] {
        &mut self.slot.as_mut().expect("live UDP request lease").request
    }

    fn request(&self, length: usize) -> &[u8] {
        &self.slot.as_ref().expect("live UDP request lease").request[..length]
    }

    fn response_mut(&mut self) -> &mut Vec<u8> {
        &mut self.slot.as_mut().expect("live UDP request lease").response
    }

    fn response(&self) -> &[u8] {
        &self.slot.as_ref().expect("live UDP request lease").response
    }
}

impl Drop for UdpRequestLease {
    fn drop(&mut self) {
        if let Some(mut slot) = self.slot.take() {
            slot.response.clear();
            self.inner
                .available
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(slot);
        }
        drop(self.permit.take());
    }
}

pub(super) fn bind_tcp(address: SocketAddr, backlog: u32) -> io::Result<TcpListener> {
    let socket = match address.ip() {
        IpAddr::V4(_) => TcpSocket::new_v4()?,
        IpAddr::V6(_) => TcpSocket::new_v6()?,
    };
    #[cfg(unix)]
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(backlog)
}

pub(super) async fn udp_loop(
    socket: UdpSocket,
    inbound: usize,
    proxy: Arc<DnsProxy>,
    requests: UdpRequestPool,
    mut cancel: watch::Receiver<bool>,
) -> io::Result<()> {
    let socket = Arc::new(socket);
    let mut children = JoinSet::new();
    let mut request = [0_u8; MAX_DNS_UDP_WIRE];
    let result = 'listener: loop {
        while let Some(result) = children.try_join_next() {
            if let Err(error) = udp_child_result(result) {
                break 'listener Err(error);
            }
        }
        let (length, peer) = tokio::select! {
            result = socket.recv_from(&mut request) => match result {
                Ok(received) => received,
                Err(error) => break 'listener Err(error),
            },
            result = children.join_next(), if !children.is_empty() => {
                match result {
                    Some(result) => match udp_child_result(result) {
                        Ok(()) => continue,
                        Err(error) => break 'listener Err(error),
                    },
                    None => break 'listener Err(io::Error::other("DNS UDP request task stopped")),
                }
            }
            _ = cancelled(&mut cancel) => break 'listener Ok(()),
        };
        let Some(mut lease) = requests.try_acquire() else {
            proxy.observe_udp(DnsUdpEvent::PoolDrop);
            continue;
        };
        proxy.observe_udp(DnsUdpEvent::Acquired);
        lease.request_mut()[..length].copy_from_slice(&request[..length]);
        let socket = Arc::clone(&socket);
        let proxy = Arc::clone(&proxy);
        let completion = UdpRequestCompletion {
            observer: proxy.udp_observer(),
        };
        children.spawn(udp_request(
            socket, peer, inbound, proxy, lease, length, completion,
        ));
    };
    children.abort_all();
    while children.join_next().await.is_some() {}
    result
}

fn udp_child_result(result: Result<io::Result<()>, tokio::task::JoinError>) -> io::Result<()> {
    match result {
        Ok(result) => result,
        Err(_) => Err(io::Error::other("DNS UDP request task stopped")),
    }
}

async fn udp_request(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    inbound: usize,
    proxy: Arc<DnsProxy>,
    mut lease: UdpRequestLease,
    length: usize,
    _completion: UdpRequestCompletion,
) -> io::Result<()> {
    let Some(request) = Message::from_vec(lease.request(length)).ok() else {
        return Ok(());
    };
    if proxy
        .answer_message_into(
            ProxyIngress::Listener(inbound),
            ProxyTransport::Udp,
            request,
            lease.response_mut(),
        )
        .await
        .is_none()
    {
        proxy.observe_udp(DnsUdpEvent::EncodeFailure);
        return Ok(());
    }
    let sent = socket.send_to(lease.response(), peer).await?;
    if sent != lease.response().len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short DNS datagram",
        ));
    }
    Ok(())
}

pub(super) async fn tcp_loop(
    listener: TcpListener,
    inbound: usize,
    proxy: Arc<DnsProxy>,
    connections: Arc<Semaphore>,
    idle_timeout: Duration,
    mut cancel: watch::Receiver<bool>,
) -> io::Result<()> {
    let mut children = JoinSet::new();
    loop {
        let (stream, _) = tokio::select! {
            result = listener.accept() => result?,
            _ = children.join_next(), if !children.is_empty() => continue,
            _ = cancelled(&mut cancel) => break,
        };
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let proxy = Arc::clone(&proxy);
        children.spawn(async move {
            let _permit = permit;
            tcp_connection(stream, inbound, proxy, idle_timeout).await;
        });
    }
    children.abort_all();
    while children.join_next().await.is_some() {}
    Ok(())
}

pub(super) async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    if *cancel.borrow() {
        return;
    }
    let _ = cancel.changed().await;
}

pub(super) async fn tcp_connection(
    stream: TcpStream,
    inbound: usize,
    proxy: Arc<DnsProxy>,
    idle_timeout: Duration,
) {
    let peer = match stream.peer_addr() {
        Ok(peer) => peer,
        Err(_) => return,
    };
    let (mut stream, mut responses) =
        HickoryTcpStream::from_stream(AsyncIoTokioAsStd(stream), peer);
    loop {
        let Ok(Some(Ok(request))) = tokio::time::timeout(idle_timeout, stream.next()).await else {
            return;
        };
        let Some(response) = proxy
            .answer(
                ProxyIngress::Listener(inbound),
                ProxyTransport::Tcp,
                request.bytes(),
            )
            .await
        else {
            return;
        };
        if responses.send(SerialMessage::new(response, peer)).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::net::Ipv4Addr;

    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    use super::*;

    fn large_response() -> Message {
        let name = Name::from_ascii("bounded-encoding.example.").expect("test name");
        let mut response = Message::new(0x4102, MessageType::Response, OpCode::Query);
        response.add_query(Query::query(name.clone(), RecordType::A));
        for octet in 1..=80 {
            response.add_answer(Record::from_rdata(
                name.clone(),
                60,
                RData::A(A(Ipv4Addr::new(198, 51, 100, octet))),
            ));
        }
        response
    }

    #[test]
    fn udp_encoder_truncates_once_at_complete_record_boundaries() {
        let response = large_response();
        let mut wire = Vec::with_capacity(MAX_DNS_UDP_WIRE);

        encode_response(&response, ProxyTransport::Udp, 512, &mut wire)
            .expect("bounded UDP encoding");

        assert!(wire.len() <= 512);
        let decoded = Message::from_vec(&wire).expect("record-boundary UDP response");
        assert!(decoded.metadata.truncation);
        assert!(!decoded.answers.is_empty());
        assert!(decoded.answers.len() < response.answers.len());
    }

    #[test]
    fn tcp_encoder_ignores_udp_limit_and_keeps_the_complete_message() {
        let response = large_response();
        let mut wire = Vec::new();

        encode_response(&response, ProxyTransport::Tcp, 512, &mut wire)
            .expect("complete TCP encoding");

        let decoded = Message::from_vec(&wire).expect("complete TCP response");
        assert!(!decoded.metadata.truncation);
        assert_eq!(decoded.answers.len(), response.answers.len());
    }

    #[test]
    fn request_pool_is_bounded_and_reuses_returned_storage() {
        let pool = UdpRequestPool::new(1);
        let mut first = pool.try_acquire().expect("first request lease");
        let request_pointer = first.request_mut().as_ptr();
        first.response_mut().extend_from_slice(&[1, 2, 3]);
        let response_capacity = first.response_mut().capacity();
        assert!(pool.try_acquire().is_none(), "pool exceeded its hard limit");
        drop(first);

        let mut reused = pool.try_acquire().expect("returned request lease");
        assert_eq!(reused.request_mut().as_ptr(), request_pointer);
        assert!(reused.response().is_empty());
        assert_eq!(reused.response_mut().capacity(), response_capacity);
    }

    #[tokio::test]
    async fn cancelling_a_request_task_returns_its_pool_lease() {
        let pool = UdpRequestPool::new(1);
        let task_pool = pool.clone();
        let (held, held_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _lease = task_pool.try_acquire().expect("task request lease");
            held.send(()).expect("announce held lease");
            pending::<()>().await;
        });
        held_rx.await.expect("task acquired lease");
        assert!(pool.try_acquire().is_none());

        task.abort();
        assert!(
            task.await
                .expect_err("cancelled request task")
                .is_cancelled()
        );
        assert!(pool.try_acquire().is_some(), "cancel leaked request lease");
    }

    #[tokio::test]
    async fn panicking_request_task_returns_its_pool_lease() {
        let pool = UdpRequestPool::new(1);
        let task_pool = pool.clone();
        let task = tokio::spawn(async move {
            let _lease = task_pool.try_acquire().expect("task request lease");
            panic!("injected request panic");
        });

        assert!(task.await.expect_err("panicking request task").is_panic());
        assert!(pool.try_acquire().is_some(), "panic leaked request lease");
    }
}
