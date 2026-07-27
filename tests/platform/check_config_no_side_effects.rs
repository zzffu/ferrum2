#![forbid(unsafe_code)]

use std::env;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const PROCESS_DEADLINE: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const OUTPUT_CAP: usize = 64 * 1024;
const VALID_STDOUT: &[u8] = b"configuration valid\n";
const INVALID_STDERR: &[u8] =
    b"error[config.semantic] shadowsocks.psk: configuration value is invalid\n";

fn main() {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.first().is_some_and(|value| value == "--self-test") {
        self_test();
        return;
    }
    if arguments.first().is_some_and(|value| value == "--mutation-connect") {
        let address = mutation_address(&arguments);
        TcpStream::connect_timeout(&address, Duration::from_secs(2))
            .expect("mutation connector reached trap");
        return;
    }
    if arguments
        .first()
        .is_some_and(|value| value == "--mutation-listen-exit2")
    {
        let address = mutation_address(&arguments);
        let listener = TcpListener::bind(address).expect("mutation listener bound");
        let _barrier = listener
            .accept()
            .expect("mutation listener observation barrier");
        eprint!("{}", String::from_utf8_lossy(INVALID_STDERR));
        std::process::exit(2);
    }
    assert_eq!(
        arguments.len(),
        2,
        "usage: check_config_no_side_effects <client-binary> <server-binary>"
    );
    let client = PathBuf::from(&arguments[0]);
    let server = PathBuf::from(&arguments[1]);
    assert!(client.is_file(), "client release artifact is missing");
    assert!(server.is_file(), "server release artifact is missing");

    let cases = [
        Case {
            label: "client-valid",
            binary: &client,
            config: "tests/platform/config/client-valid.toml",
            expected_exit: 0,
            expected_stdout: VALID_STDOUT,
            expected_stderr: b"",
            listener_ports: &[1080, 8388, 9090],
        },
        Case {
            label: "client-invalid-key-length",
            binary: &client,
            config: "tests/platform/config/client-invalid-key-length.toml",
            expected_exit: 2,
            expected_stdout: b"",
            expected_stderr: INVALID_STDERR,
            listener_ports: &[1080, 8388, 9090],
        },
        Case {
            label: "server-valid",
            binary: &server,
            config: "tests/platform/config/server-valid.toml",
            expected_exit: 0,
            expected_stdout: VALID_STDOUT,
            expected_stderr: b"",
            listener_ports: &[8388, 9090],
        },
        Case {
            label: "server-invalid-key-length",
            binary: &server,
            config: "tests/platform/config/server-invalid-key-length.toml",
            expected_exit: 2,
            expected_stdout: b"",
            expected_stderr: INVALID_STDERR,
            listener_ports: &[8388, 9090],
        },
    ];
    for case in cases {
        run_case(case);
    }
    println!("platform offline evidence: 4/4 exact outputs/exits and no listener was created");
}

fn mutation_address(arguments: &[std::ffi::OsString]) -> SocketAddr {
    arguments
        .get(1)
        .expect("mutation address")
        .to_str()
        .expect("UTF-8 mutation address")
        .parse()
        .expect("socket mutation address")
}

struct Case<'a> {
    label: &'static str,
    binary: &'a Path,
    config: &'static str,
    expected_exit: i32,
    expected_stdout: &'static [u8],
    expected_stderr: &'static [u8],
    listener_ports: &'static [u16],
}

fn run_case(case: Case<'_>) {
    let traps = case
        .listener_ports
        .iter()
        .map(|port| {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, *port))
                .unwrap_or_else(|error| panic!("{} pre-bind port {port}: {error}", case.label));
            listener
                .set_nonblocking(true)
                .expect("nonblocking connector trap");
            listener
        })
        .collect::<Vec<_>>();
    let mut command = Command::new(case.binary);
    command.args(["--config", case.config, "--check-config"]);
    let mut child = CapturedChild::spawn(&mut command, case.label);
    let observation = wait_and_observe(&mut child, &traps, None, case.label)
        .unwrap_or_else(|error| panic!("{}: {error}", case.label));
    validate_observation(
        case.label,
        &observation,
        case.expected_exit,
        case.expected_stdout,
        case.expected_stderr,
    )
    .unwrap_or_else(|error| panic!("{error}"));
    assert_no_connect(&traps, case.label).unwrap_or_else(|error| panic!("{error}"));
}

struct CapturedChild {
    child: Child,
    stdout: Option<JoinHandle<Vec<u8>>>,
    stderr: Option<JoinHandle<Vec<u8>>>,
}

impl CapturedChild {
    fn spawn(command: &mut Command, label: &str) -> Self {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .unwrap_or_else(|error| panic!("{label} spawn: {error}"));
        let stdout = capture(child.stdout.take().expect("captured stdout"));
        let stderr = capture(child.stderr.take().expect("captured stderr"));
        Self {
            child,
            stdout: Some(stdout),
            stderr: Some(stderr),
        }
    }

    fn finish(&mut self, status: ExitStatus) -> Observation {
        Observation {
            status,
            stdout: self
                .stdout
                .take()
                .expect("stdout capture")
                .join()
                .expect("stdout capture thread"),
            stderr: self
                .stderr
                .take()
                .expect("stderr capture")
                .join()
                .expect("stderr capture thread"),
            listener_created: false,
        }
    }

    fn terminate(&mut self) {
        let _ = self.child.kill();
        let deadline = Instant::now() + Duration::from_secs(2);
        let reaped = loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break true,
                Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
                _ => break false,
            }
        };
        if reaped {
            let _ = self.stdout.take().map(JoinHandle::join);
            let _ = self.stderr.take().map(JoinHandle::join);
        } else {
            self.stdout.take();
            self.stderr.take();
        }
    }
}

fn capture(mut stream: impl Read + Send + 'static) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut output = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return output,
                Ok(read) => {
                    let remaining = OUTPUT_CAP.saturating_sub(output.len());
                    output.extend_from_slice(&chunk[..read.min(remaining)]);
                }
            }
        }
    })
}

struct Observation {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    listener_created: bool,
}

fn wait_and_observe(
    child: &mut CapturedChild,
    connector_traps: &[TcpListener],
    listener_probe: Option<SocketAddr>,
    label: &str,
) -> Result<Observation, String> {
    let deadline = Instant::now() + PROCESS_DEADLINE;
    let mut listener_created = false;
    loop {
        if let Err(error) = assert_no_connect(connector_traps, label) {
            child.terminate();
            return Err(error);
        }
        if let Some(address) = listener_probe {
            if TcpStream::connect_timeout(&address, POLL_INTERVAL).is_ok() {
                listener_created = true;
            }
        }
        let status = match child.child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                child.terminate();
                return Err(format!("{label} status: {error}"));
            }
        };
        if let Some(status) = status {
            if let Err(error) = assert_no_connect(connector_traps, label) {
                child.terminate();
                return Err(error);
            }
            let mut observation = child.finish(status);
            observation.listener_created = listener_created;
            return Ok(observation);
        }
        if Instant::now() >= deadline {
            child.terminate();
            return Err(format!("{label} exceeded 10-second process deadline"));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn validate_observation(
    label: &str,
    observation: &Observation,
    expected_exit: i32,
    expected_stdout: &[u8],
    expected_stderr: &[u8],
) -> Result<(), String> {
    if observation.listener_created {
        return Err(format!("{label} created a forbidden listener"));
    }
    if observation.status.code() != Some(expected_exit) {
        return Err(format!(
            "{label} exact exit mismatch: actual={:?}, expected={expected_exit}",
            observation.status.code()
        ));
    }
    if observation.stdout != expected_stdout {
        return Err(format!("{label} exact stdout mismatch"));
    }
    if observation.stderr != expected_stderr {
        return Err(format!("{label} exact stderr mismatch"));
    }
    Ok(())
}

fn assert_no_connect(traps: &[TcpListener], label: &str) -> Result<(), String> {
    for listener in traps {
        match listener.accept() {
            Ok((_, address)) => {
                return Err(format!(
                    "{label} created a forbidden connector side effect to {address}"
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(format!("{label} connector trap failed: {error}")),
        }
    }
    Ok(())
}

fn self_test() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("self-test trap");
    listener
        .set_nonblocking(true)
        .expect("self-test nonblocking");
    let address = listener.local_addr().expect("self-test address");
    let executable = env::current_exe().expect("self-test executable");
    let mut command = Command::new(&executable);
    command.args(["--mutation-connect", &address.to_string()]);
    let mut mutation = CapturedChild::spawn(&mut command, "connector mutation");
    let result = wait_and_observe(&mut mutation, &[listener], None, "connector mutation");
    assert!(
        result.is_err_and(|error| error.contains("forbidden connector side effect")),
        "connector mutation must be rejected"
    );

    let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener mutation port");
    let address = reservation
        .local_addr()
        .expect("listener mutation address");
    drop(reservation);
    let mut command = Command::new(executable);
    command.args(["--mutation-listen-exit2", &address.to_string()]);
    let mut mutation = CapturedChild::spawn(&mut command, "listener mutation");
    let observation = wait_and_observe(
        &mut mutation,
        &[],
        Some(address),
        "listener mutation",
    )
    .expect("listener mutation completed");
    assert_eq!(observation.status.code(), Some(2));
    assert!(observation.stdout.is_empty());
    assert_eq!(observation.stderr, INVALID_STDERR);
    let result = validate_observation(
        "listener mutation",
        &observation,
        2,
        b"",
        INVALID_STDERR,
    );
    assert!(
        result.is_err_and(|error| error.contains("created a forbidden listener")),
        "live listener mutation with matching diagnostic and exit must be rejected"
    );
    println!("platform helper self-test: connector and live listener mutations rejected");
}
