#![forbid(unsafe_code)]

use std::env;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const PROCESS_DEADLINE: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

fn main() {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.first().is_some_and(|value| value == "--self-test") {
        self_test();
        return;
    }
    if arguments.first().is_some_and(|value| value == "--mutation-connect") {
        let address = arguments
            .get(1)
            .expect("mutation address")
            .to_str()
            .expect("UTF-8 mutation address")
            .parse::<SocketAddr>()
            .expect("socket mutation address");
        TcpStream::connect_timeout(&address, Duration::from_secs(2))
            .expect("mutation connector reached trap");
        return;
    }
    if arguments
        .first()
        .is_some_and(|value| value == "--mutation-listen")
    {
        let address = arguments
            .get(1)
            .expect("mutation address")
            .to_str()
            .expect("UTF-8 mutation address")
            .parse::<SocketAddr>()
            .expect("socket mutation address");
        TcpListener::bind(address).expect("mutation listener unexpectedly bound");
        return;
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
            listener_ports: &[1080, 8388, 9090],
        },
        Case {
            label: "client-invalid-key-length",
            binary: &client,
            config: "tests/platform/config/client-invalid-key-length.toml",
            expected_exit: 2,
            listener_ports: &[1080, 8388, 9090],
        },
        Case {
            label: "server-valid",
            binary: &server,
            config: "tests/platform/config/server-valid.toml",
            expected_exit: 0,
            listener_ports: &[8388, 9090],
        },
        Case {
            label: "server-invalid-key-length",
            binary: &server,
            config: "tests/platform/config/server-invalid-key-length.toml",
            expected_exit: 2,
            listener_ports: &[8388, 9090],
        },
    ];
    for case in cases {
        run_case(case);
    }
    println!("platform offline evidence: 4/4 exact exits and zero socket side effects");
}

struct Case<'a> {
    label: &'static str,
    binary: &'a Path,
    config: &'static str,
    expected_exit: i32,
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
                .expect("nonblocking side-effect trap");
            listener
        })
        .collect::<Vec<_>>();
    let mut command = Command::new(case.binary);
    command
        .args(["--config", case.config, "--check-config"])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("{} spawn: {error}", case.label));
    let status = wait_and_trap(&mut child, &traps, case.label)
        .unwrap_or_else(|error| panic!("{}: {error}", case.label));
    assert_eq!(
        status.code(),
        Some(case.expected_exit),
        "{} exact exit mismatch",
        case.label
    );
    assert_no_connect(&traps, case.label).unwrap_or_else(|error| panic!("{error}"));
}

fn wait_and_trap(
    child: &mut Child,
    traps: &[TcpListener],
    label: &str,
) -> Result<ExitStatus, String> {
    let deadline = Instant::now() + PROCESS_DEADLINE;
    loop {
        assert_no_connect(traps, label)?;
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("{label} status: {error}"))?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return Err(format!("{label} exceeded 10-second process deadline"));
        }
        thread::sleep(POLL_INTERVAL);
    }
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
            Err(error) => return Err(format!("{label} side-effect trap failed: {error}")),
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
    let mut mutation = Command::new(executable)
        .args(["--mutation-connect", &address.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn connector mutation");
    let result = wait_and_trap(&mut mutation, &[listener], "connector mutation");
    assert!(
        result.is_err_and(|error| error.contains("forbidden connector side effect")),
        "connector mutation must be rejected"
    );
    let _ = mutation.kill();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener mutation trap");
    listener
        .set_nonblocking(true)
        .expect("listener mutation nonblocking");
    let address = listener.local_addr().expect("listener mutation address");
    let executable = env::current_exe().expect("self-test executable");
    let mut mutation = Command::new(executable)
        .args(["--mutation-listen", &address.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn listener mutation");
    let status = wait_and_trap(&mut mutation, &[listener], "listener mutation")
        .expect("listener mutation process status");
    assert!(
        !status.success(),
        "pre-bound listener mutation must be rejected"
    );
    println!("platform helper self-test: connector/listener side-effect mutations rejected");
}
