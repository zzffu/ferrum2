use super::*;

impl CaptureOwner {
    fn scripted(delay: Duration, send: bool, panic_after_delay: bool, linger: Duration) -> Self {
        let (sender, result) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            thread::sleep(delay);
            if panic_after_delay {
                panic!("scripted capture panic");
            }
            if send {
                let _ = sender.send(OutputSummary {
                    bytes: Box::new([]),
                    hash: 0,
                    truncated: false,
                });
                thread::sleep(linger);
            }
        });
        Self {
            result,
            worker: Some(worker),
            received: None,
            complete: false,
            failed: false,
        }
    }
}

static CONTRACT_REGISTRATION_ACTIVE: AtomicUsize = AtomicUsize::new(0);
static CONTRACT_REGISTRATION_FAILURES: AtomicUsize = AtomicUsize::new(0);
static CONTRACT_WORKER_ACTIVE: AtomicUsize = AtomicUsize::new(0);
static CONTRACT_WORKER_FAILURES: AtomicUsize = AtomicUsize::new(0);

struct FailingCaptureSpawner {
    calls: usize,
    fail_at: usize,
}

impl CaptureSpawner for FailingCaptureSpawner {
    fn spawn(&mut self, task: CaptureTask) -> io::Result<thread::JoinHandle<()>> {
        self.calls += 1;
        if self.calls == self.fail_at {
            return Err(io::Error::other("injected capture worker creation failure"));
        }
        ThreadCaptureSpawner.spawn(task)
    }
}

pub(crate) fn assert_process_support_contract() {
    let baseline = active_child_count();
    assert_eq!(PROCESS_CLEANUP_FAILURES.load(Ordering::SeqCst), 0);

    CONTRACT_REGISTRATION_ACTIVE.store(0, Ordering::SeqCst);
    CONTRACT_REGISTRATION_FAILURES.store(0, Ordering::SeqCst);
    ProcessRegistration::acquire(
        &CONTRACT_REGISTRATION_ACTIVE,
        &CONTRACT_REGISTRATION_FAILURES,
    )
    .release(true);
    assert_eq!(CONTRACT_REGISTRATION_ACTIVE.load(Ordering::SeqCst), 0);
    assert_eq!(CONTRACT_REGISTRATION_FAILURES.load(Ordering::SeqCst), 0);
    drop(ProcessRegistration::acquire(
        &CONTRACT_REGISTRATION_ACTIVE,
        &CONTRACT_REGISTRATION_FAILURES,
    ));
    assert_eq!(CONTRACT_REGISTRATION_ACTIVE.load(Ordering::SeqCst), 1);
    assert_eq!(CONTRACT_REGISTRATION_FAILURES.load(Ordering::SeqCst), 1);

    let mut first = CaptureOwner::scripted(Duration::ZERO, true, false, Duration::from_millis(50));
    let mut second =
        CaptureOwner::scripted(Duration::from_millis(500), true, false, Duration::ZERO);
    let shared_deadline = Instant::now() + Duration::from_millis(300);
    assert!(first.complete_until(shared_deadline));
    assert!(
        !second.complete_until(shared_deadline),
        "both captures must share one absolute deadline"
    );
    assert!(second.complete_until(Instant::now() + FORCED_REAP_TIMEOUT));
    assert!(first.finish().is_ok());
    assert!(second.finish().is_ok());

    for capture in [
        CaptureOwner::scripted(Duration::ZERO, false, false, Duration::ZERO),
        CaptureOwner::scripted(Duration::ZERO, false, true, Duration::ZERO),
    ] {
        CONTRACT_WORKER_ACTIVE.store(0, Ordering::SeqCst);
        CONTRACT_WORKER_FAILURES.store(0, Ordering::SeqCst);
        let mut process = OwnedProcess::tracked_child_with_registration(
            spawn_contract_child(),
            ProcessRegistration::acquire(&CONTRACT_WORKER_ACTIVE, &CONTRACT_WORKER_FAILURES),
        );
        process.inner_mut().stdout = Some(capture);
        process.inner_mut().stderr = Some(CaptureOwner::scripted(
            Duration::ZERO,
            true,
            false,
            Duration::ZERO,
        ));
        assert!(process.complete_until(Instant::now() + FORCED_REAP_TIMEOUT));
        assert!(process.finish().is_err());
        assert_eq!(CONTRACT_WORKER_ACTIVE.load(Ordering::SeqCst), 0);
        assert_eq!(CONTRACT_WORKER_FAILURES.load(Ordering::SeqCst), 1);
        assert_eq!(active_child_count(), baseline);
    }

    let mut pending = OwnedProcess::tracked_child(spawn_contract_child());
    pending.inner_mut().stdout = Some(CaptureOwner::scripted(
        Duration::from_millis(500),
        true,
        false,
        Duration::ZERO,
    ));
    pending.inner_mut().stderr = Some(CaptureOwner::scripted(
        Duration::from_millis(500),
        true,
        false,
        Duration::ZERO,
    ));
    assert!(pending.wait_for_exit_until(Instant::now() + FORCED_REAP_TIMEOUT));
    assert!(!pending.complete_until(Instant::now()));
    retain_pending_process(pending);
    assert_eq!(active_child_count(), baseline + 1);
    retry_pending_processes(Instant::now() + FORCED_REAP_TIMEOUT);
    assert!(
        pending_processes()
            .lock()
            .expect("pending process lock")
            .is_empty()
    );
    assert_eq!(active_child_count(), baseline);
    assert_eq!(PROCESS_CLEANUP_FAILURES.load(Ordering::SeqCst), 0);

    let address = reserve_contract_address();
    let mut unexpected = OwnedProcess::tracked_child(spawn_port_contract_child(address));
    wait_for_contract_port(&mut unexpected, address, true);
    unexpected
        .attach_captures(&mut ThreadCaptureSpawner)
        .expect("attach both capture workers");
    drop(unexpected);
    wait_for_contract_port_release(address);
    assert_eq!(active_child_count(), baseline);
    assert_eq!(PROCESS_CLEANUP_FAILURES.load(Ordering::SeqCst), 0);

    let mut setup_failure = OwnedProcess::tracked_child(spawn_port_contract_child(address));
    wait_for_contract_port(&mut setup_failure, address, true);
    let mut spawner = FailingCaptureSpawner {
        calls: 0,
        fail_at: 2,
    };
    assert!(setup_failure.attach_captures(&mut spawner).is_err());
    drop(setup_failure);
    wait_for_contract_port_release(address);
    assert_eq!(active_child_count(), baseline);
    assert_eq!(PROCESS_CLEANUP_FAILURES.load(Ordering::SeqCst), 0);

    let spawn_guard = hold_process_spawns();
    let mut retried = OwnedProcess::tracked_child(spawn_port_contract_child(address));
    wait_for_contract_port(&mut retried, address, true);
    retried
        .attach_captures(&mut ThreadCaptureSpawner)
        .expect("attach capture workers after setup retry");
    drop(retried);
    drop(spawn_guard);
    wait_for_contract_port_release(address);
    assert_eq!(active_child_count(), baseline);
    assert_eq!(PROCESS_CLEANUP_FAILURES.load(Ordering::SeqCst), 0);
}

#[cfg(windows)]
fn spawn_contract_child() -> Child {
    Command::new("cmd")
        .args(["/D", "/C", "exit", "0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn process contract child")
}

#[cfg(not(windows))]
fn spawn_contract_child() -> Child {
    Command::new("sh")
        .args(["-c", "exit 0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn process contract child")
}

fn reserve_contract_address() -> std::net::SocketAddrV4 {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .expect("reserve process contract address");
    let address = match listener.local_addr().expect("process contract address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 contract bind returned IPv6"),
    };
    drop(listener);
    address
}

fn spawn_port_contract_child(address: std::net::SocketAddrV4) -> Child {
    Command::new(std::env::current_exe().expect("process contract executable"))
        .args([
            "--exact",
            "process_contract_port_child",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("FERRUM2_PROCESS_CONTRACT_ADDRESS", address.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn port-owning process contract child")
}

fn wait_for_contract_port(
    process: &mut OwnedProcess,
    address: std::net::SocketAddrV4,
    occupied: bool,
) {
    let deadline = Instant::now() + FORCED_REAP_TIMEOUT;
    loop {
        assert_eq!(process.try_wait().expect("contract child status"), None);
        match std::net::TcpListener::bind(address) {
            Ok(listener) if !occupied => {
                drop(listener);
                return;
            }
            Ok(listener) => drop(listener),
            Err(error) if occupied && error.kind() == io::ErrorKind::AddrInUse => return,
            Err(error) if !occupied && error.kind() == io::ErrorKind::AddrInUse => {}
            Err(error) => panic!("process contract port probe failed: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "process contract port probe timed out"
        );
        thread::sleep(PROCESS_POLL);
    }
}

fn wait_for_contract_port_release(address: std::net::SocketAddrV4) {
    let deadline = Instant::now() + FORCED_REAP_TIMEOUT;
    loop {
        match std::net::TcpListener::bind(address) {
            Ok(listener) => {
                drop(listener);
                return;
            }
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
            Err(error) => panic!("process contract port release probe failed: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "process contract port release timed out"
        );
        thread::sleep(PROCESS_POLL);
    }
}
