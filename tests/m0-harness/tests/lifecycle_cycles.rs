#[path = "../src/local_support/mod.rs"]
mod local_support;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use local_support::{
    ChildExit, ChildGuard, LoopbackReservation, MetricsReadinessFailure, active_child_count,
    bind_loopback_listener, reserve_loopback, reserve_unused_loopback, wait_for_metrics_ready,
    write_client_config, write_server_config,
};

const CYCLES_PER_CATEGORY: usize = 20;
const CHILD_DEADLINE: Duration = Duration::from_secs(5);
const MAX_SETUP_ATTEMPTS: usize = 3;
const FOREIGN_OWNERSHIP_CONFIRMATIONS: usize = 3;
static LIFECYCLE_TEST_LOCK: Mutex<()> = Mutex::new(());
type Cycle = (
    &'static str,
    fn(usize, &str) -> Result<(), Box<SetupCollision>>,
);

#[derive(Debug)]
struct SetupCollision {
    exit: ChildExit,
    foreign_listener_count: usize,
    foreign_addresses: Vec<SocketAddrV4>,
    cleanup_verified: bool,
}

#[derive(Debug)]
enum ChildSetupError {
    Collision(Box<SetupCollision>),
    Genuine(Box<ChildExit>),
}

impl ChildSetupError {
    fn exit(&self) -> &ChildExit {
        match self {
            Self::Collision(collision) => &collision.exit,
            Self::Genuine(exit) => exit,
        }
    }
}

fn address_is_occupied(address: SocketAddrV4) -> bool {
    match bind_loopback_listener(address) {
        Ok(listener) => {
            drop(listener);
            false
        }
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => true,
        Err(error) => panic!("setup collision bind probe failed: {error}"),
    }
}

fn persistent_foreign_addresses(addresses: [SocketAddrV4; 2]) -> Vec<SocketAddrV4> {
    let mut occupied: Vec<_> = addresses
        .into_iter()
        .filter(|address| address_is_occupied(*address))
        .collect();
    for _ in 1..FOREIGN_OWNERSHIP_CONFIRMATIONS {
        thread::sleep(Duration::from_millis(20));
        occupied.retain(|address| address_is_occupied(*address));
    }
    occupied
}

fn spawn_reserved_child(
    binary: &str,
    config: &Path,
    context: String,
    reservations: [LoopbackReservation; 2],
    metrics: SocketAddrV4,
) -> Result<ChildGuard, ChildSetupError> {
    spawn_reserved_child_with_hook(binary, config, context, reservations, metrics, |_| 0)
}

fn spawn_reserved_child_with_hook(
    binary: &str,
    config: &Path,
    context: String,
    reservations: [LoopbackReservation; 2],
    metrics: SocketAddrV4,
    before_spawn: impl FnOnce([SocketAddrV4; 2]) -> usize,
) -> Result<ChildGuard, ChildSetupError> {
    let addresses = reservations.each_ref().map(LoopbackReservation::address);
    let _released = reservations.map(LoopbackReservation::release);
    let deferred_exit_checks = before_spawn(addresses);
    let mut child = ChildGuard::spawn_with_context(binary, config, context);
    child.defer_exit_observation_for_checks(deferred_exit_checks);
    let exit = match wait_for_metrics_ready(&mut child, addresses[0], metrics) {
        Ok(()) => return Ok(child),
        Err(MetricsReadinessFailure::ChildExited(exit)) => exit,
        Err(MetricsReadinessFailure::Deadline) => {
            child.terminate_and_reap_with_exit(CHILD_DEADLINE)
        }
    };
    {
        let foreign_addresses = persistent_foreign_addresses(addresses);
        let foreign_listener_count = foreign_addresses.len();
        if foreign_listener_count == 0 {
            return Err(ChildSetupError::Genuine(Box::new(exit)));
        }
        Err(ChildSetupError::Collision(Box::new(SetupCollision {
            exit,
            foreign_listener_count,
            foreign_addresses,
            cleanup_verified: false,
        })))
    }
}

struct ForeignSetup {
    proxy: Option<TcpListener>,
    metrics: SocketAddrV4,
    stop: Arc<AtomicBool>,
    task: Option<thread::JoinHandle<()>>,
}

impl ForeignSetup {
    fn start(addresses: [SocketAddrV4; 2], requests: Arc<AtomicUsize>, drip: bool) -> Self {
        let proxy = bind_loopback_listener(addresses[0]).expect("foreign proxy bind");
        let metrics_listener = bind_loopback_listener(addresses[1]).expect("foreign metrics bind");
        metrics_listener
            .set_nonblocking(true)
            .expect("foreign metrics nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let task_stop = Arc::clone(&stop);
        let task = thread::spawn(move || {
            let body = b"# HELP ferrum2_tcp_replay_entries Current exact TCP replay entries\n\
                         # TYPE ferrum2_tcp_replay_entries gauge\n\
                         ferrum2_tcp_replay_entries 0\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/plain; version=0.0.4\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            while !task_stop.load(Ordering::SeqCst) {
                match metrics_listener.accept() {
                    Ok((mut stream, _)) => {
                        requests.fetch_add(1, Ordering::SeqCst);
                        if drip {
                            for byte in response.as_bytes().iter().chain(body) {
                                if task_stop.load(Ordering::SeqCst)
                                    || stream.write_all(std::slice::from_ref(byte)).is_err()
                                {
                                    break;
                                }
                                thread::sleep(Duration::from_millis(100));
                            }
                        } else {
                            let _ = stream.write_all(response.as_bytes());
                            let _ = stream.write_all(body);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("foreign metrics accept failed: {error}"),
                }
            }
        });
        Self {
            proxy: Some(proxy),
            metrics: addresses[1],
            stop,
            task: Some(task),
        }
    }
}

impl Drop for ForeignSetup {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.metrics);
        if let Some(task) = self.task.take() {
            task.join().expect("foreign metrics responder");
        }
        drop(self.proxy.take());
    }
}

fn run_cycle_with_retries<F>(
    category: &str,
    iteration: usize,
    baseline_children: usize,
    mut cycle: F,
) where
    F: FnMut(usize, &str) -> Result<(), Box<SetupCollision>>,
{
    for attempt in 1..=MAX_SETUP_ATTEMPTS {
        let context = format!("category={category},iteration={iteration},attempt={attempt}");
        match cycle(baseline_children, &context) {
            Ok(()) => return,
            Err(collision) => {
                assert!(
                    collision.cleanup_verified,
                    "{context} collision cleanup was not verified"
                );
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
        let listener = bind_loopback_listener(*address)
            .unwrap_or_else(|error| panic!("exact rebind failed for {address}: {error}"));
        assert_eq!(
            listener.local_addr().expect("rebound address"),
            std::net::SocketAddr::V4(*address)
        );
        drop(listener);
    }
}

fn cleanup_failed_attempt(
    directory: tempfile::TempDir,
    mut started_children: Vec<ChildGuard>,
    addresses: &[SocketAddrV4],
    baseline_children: usize,
    error: ChildSetupError,
) -> Box<SetupCollision> {
    let (mut collision, genuine_failure) = match error {
        ChildSetupError::Collision(collision) => (collision, false),
        ChildSetupError::Genuine(exit) => (
            Box::new(SetupCollision {
                exit: *exit,
                foreign_listener_count: 0,
                foreign_addresses: Vec::new(),
                cleanup_verified: false,
            }),
            true,
        ),
    };
    for child in &mut started_children {
        child.terminate_and_reap(CHILD_DEADLINE);
    }
    drop(started_children);
    assert_eq!(
        active_child_count(),
        baseline_children,
        "failed setup attempt leaked a child"
    );
    let nonforeign: Vec<_> = addresses
        .iter()
        .copied()
        .filter(|address| !collision.foreign_addresses.contains(address))
        .collect();
    assert_exact_rebind(&nonforeign);
    let path = directory.path().to_path_buf();
    drop(directory);
    assert!(
        !path.exists(),
        "failed setup temporary path survived: {}",
        path.display()
    );
    collision.cleanup_verified = true;
    if genuine_failure {
        panic!("{}", collision.exit);
    }
    collision
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
    reserve_loopback()
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

fn success_cycle(baseline_children: usize, context: &str) -> Result<(), Box<SetupCollision>> {
    let directory = tempfile::tempdir().expect("success tempdir");
    let server_reservation = reserve_unused_loopback();
    let server = server_reservation.address();
    let server_metrics_reservation = reserve_unused_loopback();
    let server_metrics = server_metrics_reservation.address();
    let client_reservation = reserve_unused_loopback();
    let client = client_reservation.address();
    let client_metrics_reservation = reserve_unused_loopback();
    let client_metrics = client_metrics_reservation.address();
    let (target_listener, target) = reserve_loopback();
    let server_config =
        write_server_config(directory.path(), server, Some(server_metrics)).expect("server config");
    let client_config = write_client_config(directory.path(), client, server, Some(client_metrics))
        .expect("client config");
    let addresses = [client, client_metrics, server, server_metrics, target];
    let server_child = match spawn_reserved_child(
        "ferrum2-server",
        &server_config,
        format!("{context},child=server"),
        [server_reservation, server_metrics_reservation],
        server_metrics,
    ) {
        Ok(child) => child,
        Err(collision) => {
            drop(target_listener);
            return Err(cleanup_failed_attempt(
                directory,
                Vec::new(),
                &addresses,
                baseline_children,
                collision,
            ));
        }
    };
    let client_child = match spawn_reserved_child(
        "ferrum2-client",
        &client_config,
        format!("{context},child=client"),
        [client_reservation, client_metrics_reservation],
        client_metrics,
    ) {
        Ok(child) => child,
        Err(collision) => {
            drop(target_listener);
            return Err(cleanup_failed_attempt(
                directory,
                vec![server_child],
                &addresses,
                baseline_children,
                collision,
            ));
        }
    };
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
        &addresses,
        baseline_children,
    );
    Ok(())
}

fn authentication_reject_cycle(
    baseline_children: usize,
    context: &str,
) -> Result<(), Box<SetupCollision>> {
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
    let addresses = [proxy, metrics, target];
    let child = match spawn_reserved_child(
        "ferrum2-server",
        &config,
        format!("{context},child=server"),
        [proxy_reservation, metrics_reservation],
        metrics,
    ) {
        Ok(child) => child,
        Err(collision) => {
            drop(target_listener);
            return Err(cleanup_failed_attempt(
                directory,
                Vec::new(),
                &addresses,
                baseline_children,
                collision,
            ));
        }
    };
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
    finish_cycle(directory, vec![child], &addresses, baseline_children);
    Ok(())
}

fn connect_failure_cycle(
    baseline_children: usize,
    context: &str,
) -> Result<(), Box<SetupCollision>> {
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
    let addresses = [proxy, metrics, unavailable_server, target];
    let child = match spawn_reserved_child(
        "ferrum2-client",
        &config,
        format!("{context},child=client"),
        [proxy_reservation, metrics_reservation],
        metrics,
    ) {
        Ok(child) => child,
        Err(collision) => {
            drop(target_listener);
            return Err(cleanup_failed_attempt(
                directory,
                Vec::new(),
                &addresses,
                baseline_children,
                collision,
            ));
        }
    };
    let (_stream, reply) = socks_request(proxy, target);
    assert_eq!(reply, [5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
    drop(target_listener);
    finish_cycle(directory, vec![child], &addresses, baseline_children);
    Ok(())
}

fn cooperative_cancellation_cycle(
    baseline_children: usize,
    context: &str,
) -> Result<(), Box<SetupCollision>> {
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
    let addresses = [client, client_metrics, server, server_metrics, target];
    let mut server_child = match spawn_reserved_child(
        "ferrum2-server",
        &server_config,
        format!("{context},child=server"),
        [server_reservation, server_metrics_reservation],
        server_metrics,
    ) {
        Ok(child) => child,
        Err(collision) => {
            drop(target_listener);
            return Err(cleanup_failed_attempt(
                directory,
                Vec::new(),
                &addresses,
                baseline_children,
                collision,
            ));
        }
    };
    let mut client_child = match spawn_reserved_child(
        "ferrum2-client",
        &client_config,
        format!("{context},child=client"),
        [client_reservation, client_metrics_reservation],
        client_metrics,
    ) {
        Ok(child) => child,
        Err(collision) => {
            drop(target_listener);
            return Err(cleanup_failed_attempt(
                directory,
                vec![server_child],
                &addresses,
                baseline_children,
                collision,
            ));
        }
    };
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
        &addresses,
        baseline_children,
    );
    Ok(())
}

fn forced_termination_cycle(
    baseline_children: usize,
    context: &str,
) -> Result<(), Box<SetupCollision>> {
    let directory = tempfile::tempdir().expect("forced termination tempdir");
    let proxy_reservation = reserve_unused_loopback();
    let proxy = proxy_reservation.address();
    let metrics_reservation = reserve_unused_loopback();
    let metrics = metrics_reservation.address();
    let (target_listener, target) = recording_target();
    let config =
        write_server_config(directory.path(), proxy, Some(metrics)).expect("server config");
    let addresses = [proxy, metrics, target];
    let mut child = match spawn_reserved_child(
        "ferrum2-server",
        &config,
        format!("{context},child=server"),
        [proxy_reservation, metrics_reservation],
        metrics,
    ) {
        Ok(child) => child,
        Err(collision) => {
            drop(target_listener);
            return Err(cleanup_failed_attempt(
                directory,
                Vec::new(),
                &addresses,
                baseline_children,
                collision,
            ));
        }
    };
    let _held_flow = TcpStream::connect(proxy).expect("held forced flow");
    child.assert_running();
    drop(target_listener);
    finish_cycle(directory, vec![child], &addresses, baseline_children);
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
fn live_same_policy_listener_excludes_same_policy_contender() {
    let _test_guard = LIFECYCLE_TEST_LOCK.lock().expect("lifecycle test lock");
    let (incumbent, address) = reserve_loopback();
    let error = bind_loopback_listener(address).expect_err("live listener admitted a contender");
    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    drop(incumbent);
    assert_exact_rebind(&[address]);
}

#[test]
fn unrelated_metrics_responder_cannot_reset_fixed_readiness_deadline() {
    let _test_guard = LIFECYCLE_TEST_LOCK.lock().expect("lifecycle test lock");
    let baseline_children = active_child_count();
    let directory = tempfile::tempdir().expect("fixed deadline tempdir");
    let proxy_reservation = reserve_unused_loopback();
    let proxy = proxy_reservation.address();
    let metrics_reservation = reserve_unused_loopback();
    let metrics = metrics_reservation.address();
    let config = write_server_config(directory.path(), proxy, Some(metrics))
        .expect("deadline server config");
    let mut child = spawn_reserved_child(
        "ferrum2-server",
        &config,
        "category=fixed-deadline,iteration=0,attempt=1,child=server".to_owned(),
        [proxy_reservation, metrics_reservation],
        metrics,
    )
    .unwrap_or_else(|error| panic!("deadline server setup failed: {}", error.exit()));

    let foreign_proxy = reserve_unused_loopback().release();
    let foreign_metrics = reserve_unused_loopback().release();
    let requests = Arc::new(AtomicUsize::new(0));
    let foreign = ForeignSetup::start(
        [foreign_proxy, foreign_metrics],
        Arc::clone(&requests),
        true,
    );
    let started = Instant::now();
    let readiness = wait_for_metrics_ready(&mut child, proxy, foreign_metrics);
    let elapsed = started.elapsed();
    assert!(matches!(readiness, Err(MetricsReadinessFailure::Deadline)));
    assert!(
        elapsed >= Duration::from_millis(4_500) && elapsed <= Duration::from_secs(6),
        "fixed readiness deadline elapsed {elapsed:?}"
    );
    assert!(
        requests.load(Ordering::SeqCst) > 0,
        "drip metrics responder was not queried"
    );

    drop(foreign);
    child.terminate_and_reap(CHILD_DEADLINE);
    assert_eq!(active_child_count(), baseline_children);
    assert_exact_rebind(&[proxy, metrics, foreign_proxy, foreign_metrics]);
    let path = directory.path().to_path_buf();
    drop(directory);
    assert!(!path.exists(), "fixed deadline temp path survived");
}

#[test]
fn foreign_listener_is_not_accepted_as_child_readiness() {
    let _test_guard = LIFECYCLE_TEST_LOCK.lock().expect("lifecycle test lock");
    let baseline_children = active_child_count();
    let requests = Arc::new(AtomicUsize::new(0));
    let mut attempts = 0_usize;
    run_cycle_with_retries(
        "foreign-port-regression",
        0,
        baseline_children,
        |baseline_children, context| {
            attempts += 1;
            if attempts > 1 {
                return success_cycle(baseline_children, context);
            }

            let directory = tempfile::tempdir().expect("foreign listener tempdir");
            let path = directory.path().to_path_buf();
            let server_reservation = reserve_unused_loopback();
            let server = server_reservation.address();
            let server_metrics_reservation = reserve_unused_loopback();
            let server_metrics = server_metrics_reservation.address();
            let client_reservation = reserve_unused_loopback();
            let client = client_reservation.address();
            let client_metrics_reservation = reserve_unused_loopback();
            let client_metrics = client_metrics_reservation.address();
            let server_config = write_server_config(directory.path(), server, Some(server_metrics))
                .expect("foreign regression server config");
            let client_config =
                write_client_config(directory.path(), client, server, Some(client_metrics))
                    .expect("foreign regression client config");
            let server_child = spawn_reserved_child(
                "ferrum2-server",
                &server_config,
                format!("{context},child=server"),
                [server_reservation, server_metrics_reservation],
                server_metrics,
            )
            .unwrap_or_else(|error| panic!("regression server setup failed: {}", error.exit()));
            let diagnostic_context = format!("{context},child=client");
            let foreign = Arc::new(Mutex::new(None));
            let hook_foreign = Arc::clone(&foreign);
            let hook_requests = Arc::clone(&requests);
            let collision = match spawn_reserved_child_with_hook(
                "ferrum2-client",
                &client_config,
                diagnostic_context.clone(),
                [client_reservation, client_metrics_reservation],
                client_metrics,
                move |addresses| {
                    *hook_foreign.lock().expect("foreign setup owner") =
                        Some(ForeignSetup::start(addresses, hook_requests, false));
                    32
                },
            ) {
                Ok(mut child) => {
                    child.terminate_and_reap(CHILD_DEADLINE);
                    let mut server_child = server_child;
                    server_child.terminate_and_reap(CHILD_DEADLINE);
                    panic!("foreign Ferrum-looking responder was accepted as child readiness");
                }
                Err(error) => cleanup_failed_attempt(
                    directory,
                    vec![server_child],
                    &[server, server_metrics, client, client_metrics],
                    baseline_children,
                    error,
                ),
            };
            assert!(requests.load(Ordering::SeqCst) > 0);
            assert_eq!(collision.foreign_listener_count, 2);
            assert!(collision.cleanup_verified);
            let message = collision.exit.to_string();
            assert!(message.contains("binary=ferrum2-client"));
            assert!(message.contains(&diagnostic_context));
            assert!(message.contains("status="));
            assert!(message.contains("stdout_len="));
            assert!(message.contains("stdout_hash="));
            assert!(message.contains("stderr_len="));
            assert!(message.contains("stderr_hash="));
            assert!(!message.contains(local_support::SYNTHETIC_PSK));
            assert!(!message.contains(&path.display().to_string()));
            assert_eq!(active_child_count(), baseline_children);
            assert!(!path.exists(), "foreign listener temp path survived");
            drop(foreign.lock().expect("foreign setup owner").take());
            assert_exact_rebind(&[client, client_metrics]);
            Err(collision)
        },
    );
    assert_eq!(attempts, 2, "foreign collision did not retry exactly once");
    assert_eq!(active_child_count(), baseline_children);
}
