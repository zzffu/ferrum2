#[path = "../src/local_support/mod.rs"]
mod local_support;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use local_support::{
    ChildGuard, active_child_count, unused_loopback, wait_for_bound, write_client_config,
    write_server_config,
};

const CYCLES_PER_CATEGORY: usize = 20;
const CHILD_DEADLINE: Duration = Duration::from_secs(5);
type Cycle = (&'static str, fn(usize));

fn assert_exact_rebind(addresses: &[SocketAddrV4]) {
    for address in addresses {
        let listener = TcpListener::bind(address)
            .unwrap_or_else(|error| panic!("exact rebind failed for {address}: {error}"));
        assert_eq!(
            listener.local_addr().expect("rebound address"),
            std::net::SocketAddr::V4(*address)
        );
        drop(listener);
    }
}

fn socks_request(client: SocketAddrV4, target: SocketAddrV4) -> (TcpStream, [u8; 10]) {
    let mut stream = TcpStream::connect(client).expect("SOCKS connect");
    stream
        .set_read_timeout(Some(CHILD_DEADLINE))
        .expect("SOCKS timeout");
    stream.write_all(&[5, 1, 0]).expect("SOCKS greeting");
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).expect("SOCKS method");
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).expect("SOCKS request");
    let mut reply = [0_u8; 10];
    stream.read_exact(&mut reply).expect("SOCKS reply");
    (stream, reply)
}

fn start_echo(listener: TcpListener) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("echo accept");
        stream
            .set_read_timeout(Some(CHILD_DEADLINE))
            .expect("echo timeout");
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).expect("echo read");
        stream.write_all(&payload).expect("echo write");
    })
}

fn recording_target() -> (TcpListener, SocketAddrV4) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("recording target");
    let address = match listener.local_addr().expect("target address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 target"),
    };
    (listener, address)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetTerminal {
    Eof,
    Reset,
}

struct TargetFlowObserver {
    accepted: Receiver<()>,
    terminated: Receiver<TargetTerminal>,
    task: thread::JoinHandle<()>,
}

impl TargetFlowObserver {
    fn wait_for_accept(&self) {
        self.accepted
            .recv_timeout(CHILD_DEADLINE)
            .expect("target accept acknowledgement timed out");
    }

    fn wait_for_terminal(self) -> TargetTerminal {
        let terminal = self
            .terminated
            .recv_timeout(CHILD_DEADLINE)
            .expect("target terminal acknowledgement timed out");
        self.task.join().expect("target observer thread");
        terminal
    }
}

fn observe_target_flow(listener: TcpListener) -> TargetFlowObserver {
    let (accepted_sender, accepted) = mpsc::sync_channel(1);
    let (terminated_sender, terminated) = mpsc::sync_channel(1);
    let task = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("cooperative target accept");
        stream
            .set_read_timeout(Some(CHILD_DEADLINE))
            .expect("cooperative target timeout");
        accepted_sender
            .send(())
            .expect("report cooperative target accept");
        let mut byte = [0_u8; 1];
        let terminal = match stream.read(&mut byte) {
            Ok(0) => TargetTerminal::Eof,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                TargetTerminal::Reset
            }
            Ok(read) => panic!("cooperative target received {read} unexpected application bytes"),
            Err(error) => panic!("cooperative target did not receive EOF/reset: {error}"),
        };
        terminated_sender
            .send(terminal)
            .expect("report cooperative target terminal");
    });
    TargetFlowObserver {
        accepted,
        terminated,
        task,
    }
}

fn finish_cycle(
    directory: tempfile::TempDir,
    mut children: Vec<ChildGuard>,
    addresses: &[SocketAddrV4],
    baseline_children: usize,
) {
    for child in &mut children {
        child.terminate_and_reap(CHILD_DEADLINE);
    }
    drop(children);
    assert_eq!(active_child_count(), baseline_children);
    assert_exact_rebind(addresses);
    let path = directory.path().to_path_buf();
    drop(directory);
    assert!(
        !path.exists(),
        "temporary path survived: {}",
        path.display()
    );
}

fn success_cycle(baseline_children: usize) {
    let directory = tempfile::tempdir().expect("success tempdir");
    let server = unused_loopback();
    let server_metrics = unused_loopback();
    let client = unused_loopback();
    let client_metrics = unused_loopback();
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("echo target");
    let target = match target_listener.local_addr().expect("target address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 target"),
    };
    let echo = start_echo(target_listener);
    let server_config =
        write_server_config(directory.path(), server, Some(server_metrics)).expect("server config");
    let client_config = write_client_config(directory.path(), client, server, Some(client_metrics))
        .expect("client config");
    let mut server_child = ChildGuard::spawn("ferrum2-server", &server_config);
    wait_for_bound(&mut server_child, server);
    wait_for_bound(&mut server_child, server_metrics);
    let mut client_child = ChildGuard::spawn("ferrum2-client", &client_config);
    wait_for_bound(&mut client_child, client);
    wait_for_bound(&mut client_child, client_metrics);

    let (mut socks, reply) = socks_request(client, target);
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    socks.write_all(b"pass").expect("success payload");
    let mut echoed = [0_u8; 4];
    socks.read_exact(&mut echoed).expect("success echo");
    assert_eq!(&echoed, b"pass");
    drop(socks);
    echo.join().expect("echo thread");

    finish_cycle(
        directory,
        vec![client_child, server_child],
        &[client, client_metrics, server, server_metrics, target],
        baseline_children,
    );
}

fn authentication_reject_cycle(baseline_children: usize) {
    let directory = tempfile::tempdir().expect("auth tempdir");
    let proxy = unused_loopback();
    let metrics = unused_loopback();
    let (target_listener, target) = recording_target();
    target_listener
        .set_nonblocking(true)
        .expect("nonblocking recording target");
    let config =
        write_server_config(directory.path(), proxy, Some(metrics)).expect("server config");
    let mut child = ChildGuard::spawn("ferrum2-server", &config);
    wait_for_bound(&mut child, proxy);
    wait_for_bound(&mut child, metrics);
    let mut stream = TcpStream::connect(proxy).expect("auth reject connect");
    stream
        .set_read_timeout(Some(CHILD_DEADLINE))
        .expect("auth reject timeout");
    stream.write_all(&[0xa5; 43]).expect("auth reject packet");
    stream
        .shutdown(Shutdown::Write)
        .expect("auth reject half close");
    let mut byte = [0_u8; 1];
    assert_eq!(
        stream
            .read(&mut byte)
            .expect_err("auth reject reset")
            .kind(),
        std::io::ErrorKind::ConnectionReset
    );
    assert!(matches!(
        target_listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    drop(target_listener);
    finish_cycle(
        directory,
        vec![child],
        &[proxy, metrics, target],
        baseline_children,
    );
}

fn connect_failure_cycle(baseline_children: usize) {
    let directory = tempfile::tempdir().expect("connect failure tempdir");
    let proxy = unused_loopback();
    let metrics = unused_loopback();
    let unavailable_server = unused_loopback();
    let (target_listener, target) = recording_target();
    let config = write_client_config(directory.path(), proxy, unavailable_server, Some(metrics))
        .expect("client config");
    let mut child = ChildGuard::spawn("ferrum2-client", &config);
    wait_for_bound(&mut child, proxy);
    wait_for_bound(&mut child, metrics);
    let (_stream, reply) = socks_request(proxy, target);
    assert_eq!(reply, [5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
    drop(target_listener);
    finish_cycle(
        directory,
        vec![child],
        &[proxy, metrics, unavailable_server, target],
        baseline_children,
    );
}

fn cooperative_cancellation_cycle(baseline_children: usize) {
    let directory = tempfile::tempdir().expect("cooperative cancel tempdir");
    let server = unused_loopback();
    let server_metrics = unused_loopback();
    let client = unused_loopback();
    let client_metrics = unused_loopback();
    let (target_listener, target) = recording_target();
    let target_observer = observe_target_flow(target_listener);
    let server_config =
        write_server_config(directory.path(), server, Some(server_metrics)).expect("server config");
    let client_config = write_client_config(directory.path(), client, server, Some(client_metrics))
        .expect("client config");
    let mut server_child = ChildGuard::spawn("ferrum2-server", &server_config);
    wait_for_bound(&mut server_child, server);
    wait_for_bound(&mut server_child, server_metrics);
    let mut client_child = ChildGuard::spawn("ferrum2-client", &client_config);
    wait_for_bound(&mut client_child, client);
    wait_for_bound(&mut client_child, client_metrics);

    let (socks, reply) = socks_request(client, target);
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    target_observer.wait_for_accept();
    socks
        .shutdown(Shutdown::Both)
        .expect("cooperative client termination");
    drop(socks);
    assert!(matches!(
        target_observer.wait_for_terminal(),
        TargetTerminal::Eof | TargetTerminal::Reset
    ));
    client_child.assert_running();
    server_child.assert_running();
    finish_cycle(
        directory,
        vec![client_child, server_child],
        &[client, client_metrics, server, server_metrics, target],
        baseline_children,
    );
}

fn forced_termination_cycle(baseline_children: usize) {
    let directory = tempfile::tempdir().expect("forced termination tempdir");
    let proxy = unused_loopback();
    let metrics = unused_loopback();
    let (target_listener, target) = recording_target();
    let config =
        write_server_config(directory.path(), proxy, Some(metrics)).expect("server config");
    let mut child = ChildGuard::spawn("ferrum2-server", &config);
    wait_for_bound(&mut child, proxy);
    wait_for_bound(&mut child, metrics);
    let _held_flow = TcpStream::connect(proxy).expect("held forced flow");
    child.assert_running();
    drop(target_listener);
    finish_cycle(
        directory,
        vec![child],
        &[proxy, metrics, target],
        baseline_children,
    );
}

#[test]
fn exactly_100_mixed_real_process_cycles_cleanup_every_owned_boundary() {
    let baseline_children = active_child_count();
    let categories: [Cycle; 5] = [
        ("success", success_cycle),
        ("authentication-reject", authentication_reject_cycle),
        ("connect-failure", connect_failure_cycle),
        ("cooperative-cancellation", cooperative_cancellation_cycle),
        ("forced-termination", forced_termination_cycle),
    ];
    let mut executed = 0_usize;
    for (category, cycle) in categories {
        for iteration in 0..CYCLES_PER_CATEGORY {
            cycle(baseline_children);
            executed += 1;
            assert_eq!(
                active_child_count(),
                baseline_children,
                "{category} cycle {iteration} leaked a child"
            );
        }
    }
    assert_eq!(executed, 100);
}

#[test]
fn lifecycle_fixture_uses_exact_five_by_twenty_matrix() {
    assert_eq!(CYCLES_PER_CATEGORY * 5, 100);
    assert!(Path::new(env!("CARGO_MANIFEST_DIR")).is_dir());
}
