#[path = "../src/local_support/mod.rs"]
mod local_support;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use local_support::{
    ChildExit, ChildGuard, LoopbackReservation, active_child_count, reserve_loopback,
    reserve_unused_loopback, wait_for_bound, wait_for_metrics_ready, write_client_config,
    write_server_config,
};

const CYCLES_PER_CATEGORY: usize = 20;
const CHILD_DEADLINE: Duration = Duration::from_secs(5);
const MAX_SETUP_ATTEMPTS: usize = 3;
static LIFECYCLE_TEST_LOCK: Mutex<()> = Mutex::new(());
type Cycle = (&'static str, fn(usize, &str) -> Result<(), SetupCollision>);

#[derive(Debug)]
struct SetupCollision {
    exit: ChildExit,
    foreign_listener_count: usize,
}

fn address_is_occupied(address: SocketAddrV4) -> bool {
    match TcpListener::bind(address) {
        Ok(listener) => {
            drop(listener);
            false
        }
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => true,
        Err(error) => panic!("setup collision bind probe failed: {error}"),
    }
}

fn spawn_reserved_child(
    binary: &str,
    config: &Path,
    context: String,
    reservations: [LoopbackReservation; 2],
    metrics: SocketAddrV4,
) -> Result<ChildGuard, SetupCollision> {
    let addresses = reservations.each_ref().map(LoopbackReservation::address);
    let _released = reservations.map(LoopbackReservation::release);
    let mut child = ChildGuard::spawn_with_context(binary, config, context);
    match wait_for_metrics_ready(&mut child, metrics) {
        Ok(()) => Ok(child),
        Err(exit) => {
            let foreign_listener_count = addresses
                .into_iter()
                .filter(|address| address_is_occupied(*address))
                .count();
            if foreign_listener_count == 0 {
                panic!("{exit}");
            }
            Err(SetupCollision {
                exit,
                foreign_listener_count,
            })
        }
    }
}

fn run_cycle_with_retries(
    category: &str,
    iteration: usize,
    baseline_children: usize,
    cycle: fn(usize, &str) -> Result<(), SetupCollision>,
) {
    for attempt in 1..=MAX_SETUP_ATTEMPTS {
        let context = format!("category={category},iteration={iteration},attempt={attempt}");
        match cycle(baseline_children, &context) {
            Ok(()) => return,
            Err(collision) => {
                assert_eq!(
                    active_child_count(),
                    baseline_children,
                    "{context} collision leaked a child"
                );
                if attempt == MAX_SETUP_ATTEMPTS {
                    panic!(
                        "{context} exhausted setup retries: foreign_listener_count={} {}",
                        collision.foreign_listener_count, collision.exit
                    );
                }
            }
        }
    }
    unreachable!("bounded setup attempts always return or panic");
}

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

fn success_cycle(baseline_children: usize, context: &str) -> Result<(), SetupCollision> {
    let directory = tempfile::tempdir().expect("success tempdir");
    let server_reservation = reserve_unused_loopback();
    let server = server_reservation.address();
    let server_metrics_reservation = reserve_unused_loopback();
    let server_metrics = server_metrics_reservation.address();
    let client_reservation = reserve_unused_loopback();
    let client = client_reservation.address();
    let client_metrics_reservation = reserve_unused_loopback();
    let client_metrics = client_metrics_reservation.address();
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("echo target");
    let target = match target_listener.local_addr().expect("target address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 target"),
    };
    let server_config =
        write_server_config(directory.path(), server, Some(server_metrics)).expect("server config");
    let client_config = write_client_config(directory.path(), client, server, Some(client_metrics))
        .expect("client config");
    let server_child = spawn_reserved_child(
        "ferrum2-server",
        &server_config,
        format!("{context},child=server"),
        [server_reservation, server_metrics_reservation],
        server_metrics,
    )?;
    let client_child = spawn_reserved_child(
        "ferrum2-client",
        &client_config,
        format!("{context},child=client"),
        [client_reservation, client_metrics_reservation],
        client_metrics,
    )?;
    let echo = start_echo(target_listener);

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
    Ok(())
}

fn authentication_reject_cycle(
    baseline_children: usize,
    context: &str,
) -> Result<(), SetupCollision> {
    let directory = tempfile::tempdir().expect("auth tempdir");
    let proxy_reservation = reserve_unused_loopback();
    let proxy = proxy_reservation.address();
    let metrics_reservation = reserve_unused_loopback();
    let metrics = metrics_reservation.address();
    let (target_listener, target) = recording_target();
    target_listener
        .set_nonblocking(true)
        .expect("nonblocking recording target");
    let config =
        write_server_config(directory.path(), proxy, Some(metrics)).expect("server config");
    let child = spawn_reserved_child(
        "ferrum2-server",
        &config,
        format!("{context},child=server"),
        [proxy_reservation, metrics_reservation],
        metrics,
    )?;
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
    Ok(())
}

fn connect_failure_cycle(baseline_children: usize, context: &str) -> Result<(), SetupCollision> {
    let directory = tempfile::tempdir().expect("connect failure tempdir");
    let proxy_reservation = reserve_unused_loopback();
    let proxy = proxy_reservation.address();
    let metrics_reservation = reserve_unused_loopback();
    let metrics = metrics_reservation.address();
    let unavailable_server_reservation = reserve_unused_loopback();
    let unavailable_server = unavailable_server_reservation.address();
    let (target_listener, target) = recording_target();
    let config = write_client_config(directory.path(), proxy, unavailable_server, Some(metrics))
        .expect("client config");
    let _unavailable_server = unavailable_server_reservation.release();
    let child = spawn_reserved_child(
        "ferrum2-client",
        &config,
        format!("{context},child=client"),
        [proxy_reservation, metrics_reservation],
        metrics,
    )?;
    let (_stream, reply) = socks_request(proxy, target);
    assert_eq!(reply, [5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
    drop(target_listener);
    finish_cycle(
        directory,
        vec![child],
        &[proxy, metrics, unavailable_server, target],
        baseline_children,
    );
    Ok(())
}

fn cooperative_cancellation_cycle(
    baseline_children: usize,
    context: &str,
) -> Result<(), SetupCollision> {
    let directory = tempfile::tempdir().expect("cooperative cancel tempdir");
    let server_reservation = reserve_unused_loopback();
    let server = server_reservation.address();
    let server_metrics_reservation = reserve_unused_loopback();
    let server_metrics = server_metrics_reservation.address();
    let client_reservation = reserve_unused_loopback();
    let client = client_reservation.address();
    let client_metrics_reservation = reserve_unused_loopback();
    let client_metrics = client_metrics_reservation.address();
    let (target_listener, target) = recording_target();
    let server_config =
        write_server_config(directory.path(), server, Some(server_metrics)).expect("server config");
    let client_config = write_client_config(directory.path(), client, server, Some(client_metrics))
        .expect("client config");
    let mut server_child = spawn_reserved_child(
        "ferrum2-server",
        &server_config,
        format!("{context},child=server"),
        [server_reservation, server_metrics_reservation],
        server_metrics,
    )?;
    let mut client_child = spawn_reserved_child(
        "ferrum2-client",
        &client_config,
        format!("{context},child=client"),
        [client_reservation, client_metrics_reservation],
        client_metrics,
    )?;
    let target_observer = observe_target_flow(target_listener);

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
    Ok(())
}

fn forced_termination_cycle(baseline_children: usize, context: &str) -> Result<(), SetupCollision> {
    let directory = tempfile::tempdir().expect("forced termination tempdir");
    let proxy_reservation = reserve_unused_loopback();
    let proxy = proxy_reservation.address();
    let metrics_reservation = reserve_unused_loopback();
    let metrics = metrics_reservation.address();
    let (target_listener, target) = recording_target();
    let config =
        write_server_config(directory.path(), proxy, Some(metrics)).expect("server config");
    let mut child = spawn_reserved_child(
        "ferrum2-server",
        &config,
        format!("{context},child=server"),
        [proxy_reservation, metrics_reservation],
        metrics,
    )?;
    let _held_flow = TcpStream::connect(proxy).expect("held forced flow");
    child.assert_running();
    drop(target_listener);
    finish_cycle(
        directory,
        vec![child],
        &[proxy, metrics, target],
        baseline_children,
    );
    Ok(())
}

#[test]
fn exactly_100_mixed_real_process_cycles_cleanup_every_owned_boundary() {
    let _test_guard = LIFECYCLE_TEST_LOCK.lock().expect("lifecycle test lock");
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
            run_cycle_with_retries(category, iteration, baseline_children, cycle);
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

#[test]
fn foreign_listener_is_not_accepted_as_child_readiness() {
    let _test_guard = LIFECYCLE_TEST_LOCK.lock().expect("lifecycle test lock");
    let baseline_children = active_child_count();
    let directory = tempfile::tempdir().expect("foreign listener tempdir");
    let path = directory.path().to_path_buf();
    let (foreign_listener, address) = reserve_loopback();
    let config =
        write_server_config(directory.path(), address, None).expect("foreign listener config");
    let diagnostic_context = "category=foreign-port-regression,iteration=0,attempt=1,child=server";
    let mut child = ChildGuard::spawn_with_context("ferrum2-server", &config, diagnostic_context);

    let readiness = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_for_bound(&mut child, address);
    }));
    let panic = readiness.expect_err("foreign listener was accepted as child readiness");
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .expect("readiness panic message");
    assert!(message.contains("binary=ferrum2-server"));
    assert!(message.contains(diagnostic_context));
    assert!(message.contains("status="));
    assert!(message.contains("stdout_len="));
    assert!(message.contains("stdout_hash="));
    assert!(message.contains("stderr_len="));
    assert!(message.contains("stderr_hash="));
    assert!(!message.contains(local_support::SYNTHETIC_PSK));
    assert!(!message.contains(&path.display().to_string()));

    drop(child);
    assert_eq!(active_child_count(), baseline_children);
    drop(foreign_listener);
    assert_exact_rebind(&[address]);
    drop(directory);
    assert!(!path.exists(), "foreign listener temp path survived");
}
