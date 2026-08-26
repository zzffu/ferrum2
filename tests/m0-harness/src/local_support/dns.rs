use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};

pub struct DnsAnswerServer {
    address: SocketAddrV4,
    observations: mpsc::Receiver<RecordType>,
    pending_observations: Mutex<Vec<RecordType>>,
    stop: mpsc::Sender<()>,
    worker: Option<std::thread::JoinHandle<Vec<RecordType>>>,
}

impl DnsAnswerServer {
    pub fn address(&self) -> SocketAddrV4 {
        self.address
    }

    pub fn wait_for_query(&self, expected: RecordType) {
        let mut pending = self
            .pending_observations
            .lock()
            .expect("pending DNS observations");
        if let Some(position) = pending.iter().position(|observed| *observed == expected) {
            pending.swap_remove(position);
            return;
        }
        loop {
            let observed = self
                .observations
                .recv_timeout(Duration::from_secs(5))
                .expect("DNS query observation");
            if observed == expected {
                return;
            }
            pending.push(observed);
        }
    }

    pub fn join(mut self) -> Vec<RecordType> {
        let _ = self.stop.send(());
        let observed = self
            .worker
            .take()
            .expect("DNS answer worker")
            .join()
            .expect("DNS answer worker join");
        let mut a = observed
            .iter()
            .filter(|record_type| **record_type == RecordType::A)
            .count();
        let mut aaaa = observed
            .iter()
            .filter(|record_type| **record_type == RecordType::AAAA)
            .count();
        let mut canonical = Vec::with_capacity(observed.len());
        while a != 0 || aaaa != 0 {
            if a != 0 {
                canonical.push(RecordType::A);
                a -= 1;
            }
            if aaaa != 0 {
                canonical.push(RecordType::AAAA);
                aaaa -= 1;
            }
        }
        canonical.extend(
            observed
                .into_iter()
                .filter(|record_type| !matches!(record_type, RecordType::A | RecordType::AAAA)),
        );
        canonical
    }
}

impl Drop for DnsAnswerServer {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = self.stop.send(());
            let _ = worker.join();
        }
    }
}

pub enum DnsReply {
    Addresses(Vec<Ipv4Addr>),
    NoData,
    WrongId,
    Silence(Duration),
    DelayedNoData(Duration),
}

pub struct DnsStep {
    pub record_type: RecordType,
    pub reply: DnsReply,
}

pub fn start_dns_answer(answer: Ipv4Addr, expected_queries: usize) -> DnsAnswerServer {
    assert!(
        expected_queries != 0 && expected_queries.is_multiple_of(2),
        "address lookups contain A/AAAA pairs"
    );
    let mut script = Vec::with_capacity(expected_queries);
    for _ in 0..expected_queries / 2 {
        script.extend([
            DnsStep {
                record_type: RecordType::A,
                reply: DnsReply::Addresses(vec![answer]),
            },
            DnsStep {
                record_type: RecordType::AAAA,
                reply: DnsReply::NoData,
            },
        ]);
    }
    start_dns_script(script)
}

pub fn start_dns_script(script: Vec<DnsStep>) -> DnsAnswerServer {
    assert!(!script.is_empty(), "DNS script must not be empty");
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("DNS answer bind");
    let address = match socket.local_addr().expect("DNS answer address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 DNS answer"),
    };
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("DNS answer timeout");
    let (observation, observations) = mpsc::channel();
    let (stop, stopped) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut script = script.into_iter().map(Some).collect::<Vec<_>>();
        let mut observed = Vec::with_capacity(script.len());
        let mut request = [0_u8; 4096];
        'steps: while script.iter().any(Option::is_some) {
            let (length, peer) = loop {
                match socket.recv_from(&mut request) {
                    Ok(received) => break received,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        if stopped.try_recv().is_ok() {
                            break 'steps;
                        }
                    }
                    Err(error) => panic!("DNS answer receive: {error}"),
                }
            };
            let request = Message::from_vec(&request[..length]).expect("DNS answer decode");
            let query = request.queries.first().expect("one DNS question").clone();
            let position = script
                .iter()
                .position(|step| {
                    step.as_ref()
                        .is_some_and(|step| step.record_type == query.query_type())
                })
                .expect("DNS script query type");
            let step = script[position].take().expect("pending DNS script step");
            observed.push(query.query_type());
            observation
                .send(query.query_type())
                .expect("DNS query observation receiver");
            match &step.reply {
                DnsReply::Silence(duration) => {
                    thread::sleep(*duration);
                    continue;
                }
                DnsReply::DelayedNoData(duration) => thread::sleep(*duration),
                _ => {}
            }
            let mut response = Message::new(request.id, MessageType::Response, request.op_code);
            response.metadata.recursion_available = true;
            response.add_query(query.clone());
            match step.reply {
                DnsReply::Addresses(addresses) => {
                    for address in addresses {
                        response.add_answer(Record::from_rdata(
                            query.name().clone(),
                            30,
                            RData::A(A(address)),
                        ));
                    }
                }
                DnsReply::WrongId => response.metadata.id = response.id.wrapping_add(1),
                DnsReply::NoData | DnsReply::DelayedNoData(_) => {}
                DnsReply::Silence(_) => unreachable!("silence continued"),
            }
            socket
                .send_to(&response.to_vec().expect("DNS answer encode"), peer)
                .expect("DNS answer response");
        }
        observed
    });
    DnsAnswerServer {
        address,
        observations,
        pending_observations: Mutex::new(Vec::new()),
        stop,
        worker: Some(worker),
    }
}
