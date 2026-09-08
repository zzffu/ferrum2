use super::bind_loopback_listener;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;
pub struct EchoWorker {
    address: SocketAddr,
    task: Option<thread::JoinHandle<Vec<u8>>>,
}

impl EchoWorker {
    pub fn join(mut self) -> thread::Result<Vec<u8>> {
        self.task.take().expect("echo worker").join()
    }
}

impl Drop for EchoWorker {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            let _ = TcpStream::connect(self.address);
            let _ = task.join();
        }
    }
}

pub fn start_echo() -> (SocketAddrV4, EchoWorker) {
    let (address, handle) =
        start_echo_at(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)));
    let address = match address {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 listener"),
    };
    (address, handle)
}

pub fn start_echo_at(bind: SocketAddr) -> (SocketAddr, EchoWorker) {
    let listener = match bind {
        SocketAddr::V4(address) if address.port() == 0 => {
            bind_loopback_listener(address).expect("echo listener")
        }
        _ => TcpListener::bind(bind).expect("echo listener"),
    };
    let address = listener.local_addr().expect("echo address");
    listener
        .set_nonblocking(true)
        .expect("nonblocking echo listener");
    let handle = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "echo accept timed out"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("echo accept failed: {error}"),
            }
        };
        stream.set_nonblocking(false).expect("blocking echo stream");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("echo timeout");
        let mut received = Vec::new();
        stream.read_to_end(&mut received).expect("echo read");
        stream.write_all(&received).expect("echo write");
        stream.shutdown(Shutdown::Write).expect("echo half close");
        received
    });
    (
        address,
        EchoWorker {
            address,
            task: Some(handle),
        },
    )
}
pub fn socks_connect_wire(client: SocketAddrV4, target: &[u8]) -> (TcpStream, [u8; 10]) {
    let mut stream = TcpStream::connect(client).expect("connect SOCKS client");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("SOCKS read timeout");
    stream.write_all(&[5, 1, 0]).expect("SOCKS greeting");
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).expect("SOCKS method");
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, 1, 0];
    request.extend_from_slice(target);
    stream.write_all(&request).expect("SOCKS request");
    let mut reply = [0_u8; 10];
    stream.read_exact(&mut reply).expect("SOCKS reply");
    (stream, reply)
}
