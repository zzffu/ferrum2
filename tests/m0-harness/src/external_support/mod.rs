#![allow(dead_code)]

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const SYNTHETIC_PSK: &str = "AAECAwQFBgcICQoLDA0ODw==";
const METHOD: &str = "2022-blake3-aes-128-gcm";
const READINESS_TIMEOUT: Duration = Duration::from_secs(10);
const CASE_TIMEOUT: Duration = Duration::from_secs(60);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const CHILD_OUTPUT_CAP: usize = 256 * 1024;

#[derive(Clone, Copy, Debug)]
pub enum Reference {
    SingBox,
    ShadowsocksRust,
}

#[derive(Clone, Copy, Debug)]
pub enum Direction {
    FerrumClient,
    ReferenceClient,
}

struct Pin {
    expected_version: String,
    asset: String,
    size: u64,
    sha256: String,
    license_review: String,
}

struct Capture {
    bytes: Vec<u8>,
    truncated: bool,
}

struct ProcessGuard {
    label: &'static str,
    child: Child,
    stdout: Option<thread::JoinHandle<Capture>>,
    stderr: Option<thread::JoinHandle<Capture>>,
    reaped: bool,
}

impl ProcessGuard {
    fn spawn(label: &'static str, command: &mut Command) -> Self {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .unwrap_or_else(|error| panic!("spawn {label}: {error}"));
        let stdout = child.stdout.take().expect("captured stdout");
        let stderr = child.stderr.take().expect("captured stderr");
        Self {
            label,
            child,
            stdout: Some(capture_output(stdout)),
            stderr: Some(capture_output(stderr)),
            reaped: false,
        }
    }

    fn assert_running(&mut self) {
        if let Some(status) = self.child.try_wait().expect("child status") {
            let diagnostics = self.finish_capture();
            self.reaped = true;
            panic!(
                "{} exited before readiness with {status}: {diagnostics}",
                self.label
            );
        }
    }

    fn terminate(&mut self) {
        if self.reaped {
            return;
        }
        if self.child.try_wait().expect("child status").is_none() {
            self.child.kill().expect("kill child");
        }
        self.child.wait().expect("reap child");
        self.finish_capture();
        self.reaped = true;
    }

    fn finish_capture(&mut self) -> String {
        let stdout = self
            .stdout
            .take()
            .map(|handle| handle.join().expect("stdout capture"))
            .unwrap_or_else(|| Capture {
                bytes: Vec::new(),
                truncated: false,
            });
        let stderr = self
            .stderr
            .take()
            .map(|handle| handle.join().expect("stderr capture"))
            .unwrap_or_else(|| Capture {
                bytes: Vec::new(),
                truncated: false,
            });
        format!(
            "stdout={}, stderr={}",
            sanitize_capture(stdout),
            sanitize_capture(stderr)
        )
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        let diagnostics = self.finish_capture();
        if thread::panicking() {
            eprintln!("sanitized {} diagnostics: {diagnostics}", self.label);
        }
        self.reaped = true;
    }
}

fn capture_output(mut stream: impl Read + Send + 'static) -> thread::JoinHandle<Capture> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut truncated = false;
        let mut chunk = [0_u8; 8192];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return Capture { bytes, truncated },
                Ok(read) => {
                    let remaining = CHILD_OUTPUT_CAP.saturating_sub(bytes.len());
                    bytes.extend_from_slice(&chunk[..read.min(remaining)]);
                    truncated |= read > remaining;
                }
            }
        }
    })
}

fn sanitize_capture(capture: Capture) -> String {
    let text = String::from_utf8_lossy(&capture.bytes)
        .replace(SYNTHETIC_PSK, "[redacted]")
        .replace('\r', "\\r")
        .replace('\n', "\\n");
    if capture.truncated {
        format!("{text}[truncated at {CHILD_OUTPUT_CAP} bytes]")
    } else {
        text
    }
}

pub fn run_case(reference: Reference, direction: Direction) {
    let started = Instant::now();
    let pin = load_pin(reference);
    let archive = required_env(reference_archive_env(reference));
    verify_archive(&archive, &pin);

    let reference_binary = match (reference, direction) {
        (Reference::SingBox, _) => required_env("M0_SING_BOX_BIN"),
        (Reference::ShadowsocksRust, Direction::FerrumClient) => required_env("M0_SSSERVER_BIN"),
        (Reference::ShadowsocksRust, Direction::ReferenceClient) => required_env("M0_SSLOCAL_BIN"),
    };
    verify_version(reference, &reference_binary, &pin.expected_version);

    let directory = tempfile::tempdir().expect("isolated interop directory");
    let (target, echo) = start_echo();
    let proxy = unused_loopback();
    let shadowsocks = unused_loopback();

    let config_checksum = match direction {
        Direction::FerrumClient => run_ferrum_client_case(
            reference,
            &reference_binary,
            directory.path(),
            shadowsocks,
            proxy,
            target,
            started,
        ),
        Direction::ReferenceClient => run_reference_client_case(
            reference,
            &reference_binary,
            directory.path(),
            shadowsocks,
            proxy,
            target,
            started,
        ),
    };

    let received = echo.join().expect("echo thread");
    let expected = expected_payload();
    assert!(
        received == expected,
        "target bytes mismatch: received={}, expected={}",
        received.len(),
        expected.len()
    );
    assert!(started.elapsed() < CASE_TIMEOUT, "interop case timed out");
    eprintln!(
        "M0 interop evidence: reference={reference:?}, direction={direction:?}, \
         asset_sha256={}, config_sha256={config_checksum}, command_category=black-box-process, \
         result=success",
        pin.sha256
    );
}

fn run_ferrum_client_case(
    reference: Reference,
    reference_binary: &Path,
    directory: &Path,
    shadowsocks: SocketAddrV4,
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    started: Instant,
) -> String {
    let reference_config = reference_server_config(reference, shadowsocks);
    let reference_config_path = write_config(directory, "reference-server.json", &reference_config);
    let mut reference_command =
        reference_command(reference, reference_binary, &reference_config_path);
    let mut reference_process =
        ProcessGuard::spawn("reference Shadowsocks server", &mut reference_command);
    wait_for_bound(
        &mut reference_process,
        shadowsocks,
        started,
        "reference Shadowsocks server",
    );

    let ferrum_config = format!(
        "schema_version = 1\n\n[client]\nlisten = \"{proxy}\"\nserver = \"{shadowsocks}\"\n\n\
         [shadowsocks]\nmethod = \"{METHOD}\"\npsk = \"{SYNTHETIC_PSK}\"\n"
    );
    let ferrum_config_path = write_config(directory, "ferrum-client.toml", &ferrum_config);
    let mut ferrum_command = Command::new(ferrum_binary("ferrum2-client"));
    ferrum_command.args(["--config", path_text(&ferrum_config_path)]);
    let mut ferrum_process = ProcessGuard::spawn("ferrum client", &mut ferrum_command);
    wait_for_bound(&mut ferrum_process, proxy, started, "ferrum SOCKS listener");

    exercise_socks(proxy, target, started);
    ferrum_process.terminate();
    reference_process.terminate();
    sha256_bytes(reference_config.as_bytes())
}

fn run_reference_client_case(
    reference: Reference,
    reference_binary: &Path,
    directory: &Path,
    shadowsocks: SocketAddrV4,
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    started: Instant,
) -> String {
    let ferrum_config = format!(
        "schema_version = 1\n\n[server]\nlisten = \"{shadowsocks}\"\n\n\
         [shadowsocks]\nmethod = \"{METHOD}\"\npsk = \"{SYNTHETIC_PSK}\"\n"
    );
    let ferrum_config_path = write_config(directory, "ferrum-server.toml", &ferrum_config);
    let mut ferrum_command = Command::new(ferrum_binary("ferrum2-server"));
    ferrum_command.args(["--config", path_text(&ferrum_config_path)]);
    let mut ferrum_process = ProcessGuard::spawn("ferrum server", &mut ferrum_command);
    wait_for_bound(
        &mut ferrum_process,
        shadowsocks,
        started,
        "ferrum Shadowsocks listener",
    );

    let reference_config = reference_client_config(reference, shadowsocks, proxy);
    let reference_config_path = write_config(directory, "reference-client.json", &reference_config);
    let mut reference_command =
        reference_command(reference, reference_binary, &reference_config_path);
    let mut reference_process =
        ProcessGuard::spawn("reference SOCKS client", &mut reference_command);
    wait_for_bound(
        &mut reference_process,
        proxy,
        started,
        "reference SOCKS listener",
    );

    exercise_socks(proxy, target, started);
    reference_process.terminate();
    ferrum_process.terminate();
    sha256_bytes(reference_config.as_bytes())
}

fn exercise_socks(proxy: SocketAddrV4, target: SocketAddrV4, started: Instant) {
    assert!(started.elapsed() < CASE_TIMEOUT, "interop case timed out");
    let mut stream = TcpStream::connect_timeout(&proxy.into(), IO_TIMEOUT).expect("connect SOCKS");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("SOCKS read deadline");
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("SOCKS write deadline");
    stream.write_all(&[5, 1, 0]).expect("SOCKS greeting");
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).expect("SOCKS method");
    assert_eq!(method, [5, 0], "SOCKS no-auth selected");

    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).expect("SOCKS connect request");
    let mut reply = [0_u8; 10];
    stream.read_exact(&mut reply).expect("SOCKS connect reply");
    assert_eq!(&reply[..4], &[5, 0, 0, 1], "SOCKS connect succeeded");

    let payload = expected_payload();
    stream.write_all(&payload[..1]).expect("first payload");
    stream.write_all(&payload[1..]).expect("second payload");
    stream
        .shutdown(Shutdown::Write)
        .expect("client write half-close");
    let mut echoed = Vec::new();
    stream
        .read_to_end(&mut echoed)
        .expect("reverse half-close drain");
    assert!(
        echoed == payload,
        "reverse bytes mismatch: received={}, expected={}",
        echoed.len(),
        payload.len()
    );
    assert!(started.elapsed() < CASE_TIMEOUT, "interop case timed out");
}

fn expected_payload() -> Vec<u8> {
    let mut payload = vec![0x49];
    payload.extend(std::iter::repeat_n(0x5a, 16_385));
    payload
}

fn start_echo() -> (SocketAddrV4, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("echo listener");
    let address = ipv4_address(&listener);
    listener
        .set_nonblocking(true)
        .expect("nonblocking echo listener");
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + READINESS_TIMEOUT;
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "echo accept timed out");
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("echo accept: {error}"),
            }
        };
        stream.set_nonblocking(false).expect("blocking echo stream");
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .expect("echo read deadline");
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .expect("echo write deadline");
        let mut received = Vec::new();
        stream.read_to_end(&mut received).expect("echo read");
        stream.write_all(&received).expect("echo reverse write");
        stream.shutdown(Shutdown::Write).expect("echo half-close");
        received
    });
    (address, handle)
}

fn wait_for_listener(
    child: &mut ProcessGuard,
    address: SocketAddrV4,
    case_started: Instant,
    label: &str,
) {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        child.assert_running();
        if TcpStream::connect_timeout(&address.into(), Duration::from_millis(200)).is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline && case_started.elapsed() < CASE_TIMEOUT,
            "{label} readiness timed out"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_bound(
    child: &mut ProcessGuard,
    address: SocketAddrV4,
    case_started: Instant,
    label: &str,
) {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        child.assert_running();
        match TcpListener::bind(address) {
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => return,
            Ok(listener) => drop(listener),
            Err(error) => panic!("{label} readiness bind probe failed: {error}"),
        }
        assert!(
            Instant::now() < deadline && case_started.elapsed() < CASE_TIMEOUT,
            "{label} readiness timed out"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn unused_loopback() -> SocketAddrV4 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve loopback");
    ipv4_address(&listener)
}

fn ipv4_address(listener: &TcpListener) -> SocketAddrV4 {
    match listener.local_addr().expect("listener address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 listener returned IPv6"),
    }
}

fn reference_server_config(reference: Reference, address: SocketAddrV4) -> String {
    match reference {
        Reference::SingBox => format!(
            "{{\"log\":{{\"level\":\"error\",\"timestamp\":false}},\
             \"inbounds\":[{{\"type\":\"shadowsocks\",\"tag\":\"ss-in\",\
             \"listen\":\"127.0.0.1\",\"listen_port\":{},\"network\":\"tcp\",\
             \"method\":\"{METHOD}\",\"password\":\"{SYNTHETIC_PSK}\"}}],\
             \"outbounds\":[{{\"type\":\"direct\",\"tag\":\"direct\"}}],\
             \"route\":{{\"final\":\"direct\"}}}}",
            address.port()
        ),
        Reference::ShadowsocksRust => format!(
            "{{\"server\":\"127.0.0.1\",\"server_port\":{},\
             \"password\":\"{SYNTHETIC_PSK}\",\"method\":\"{METHOD}\",\
             \"mode\":\"tcp_only\"}}",
            address.port()
        ),
    }
}

fn reference_client_config(
    reference: Reference,
    server: SocketAddrV4,
    proxy: SocketAddrV4,
) -> String {
    match reference {
        Reference::SingBox => format!(
            "{{\"log\":{{\"level\":\"error\",\"timestamp\":false}},\
             \"inbounds\":[{{\"type\":\"socks\",\"tag\":\"socks-in\",\
             \"listen\":\"127.0.0.1\",\"listen_port\":{}}}],\
             \"outbounds\":[{{\"type\":\"shadowsocks\",\"tag\":\"ss-out\",\
             \"server\":\"127.0.0.1\",\"server_port\":{},\"method\":\"{METHOD}\",\
             \"password\":\"{SYNTHETIC_PSK}\",\"network\":\"tcp\"}}],\
             \"route\":{{\"final\":\"ss-out\"}}}}",
            proxy.port(),
            server.port()
        ),
        Reference::ShadowsocksRust => format!(
            "{{\"local_address\":\"127.0.0.1\",\"local_port\":{},\
             \"server\":\"127.0.0.1\",\"server_port\":{},\
             \"password\":\"{SYNTHETIC_PSK}\",\"method\":\"{METHOD}\",\
             \"mode\":\"tcp_only\"}}",
            proxy.port(),
            server.port()
        ),
    }
}

fn reference_command(reference: Reference, binary: &Path, config: &Path) -> Command {
    let mut command = Command::new(binary);
    match reference {
        Reference::SingBox => {
            command.args(["run", "-c", path_text(config)]);
        }
        Reference::ShadowsocksRust => {
            command.args(["-c", path_text(config)]);
        }
    }
    command
}

fn write_config(directory: &Path, name: &str, contents: &str) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, contents).expect("write isolated config");
    path
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("UTF-8 generated path")
}

fn ferrum_binary(name: &str) -> PathBuf {
    let test_executable = std::env::current_exe().expect("test executable");
    let profile = test_executable
        .parent()
        .and_then(Path::parent)
        .expect("Cargo target profile directory");
    let path = profile.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    assert!(
        path.is_file(),
        "required current-worktree binary is missing: {}; run the required clean \
         `cargo build --workspace --bins --locked` immediately before interop",
        path.display()
    );
    path
}

fn reference_archive_env(reference: Reference) -> &'static str {
    match reference {
        Reference::SingBox => "M0_SING_BOX_ARCHIVE",
        Reference::ShadowsocksRust => "M0_SHADOWSOCKS_RUST_ARCHIVE",
    }
}

fn required_env(name: &str) -> PathBuf {
    let value = std::env::var_os(name).unwrap_or_else(|| {
        panic!("required external process environment variable missing: {name}")
    });
    let path = PathBuf::from(value);
    assert!(path.is_file(), "required external file missing for {name}");
    path
}

fn load_pin(reference: Reference) -> Pin {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root");
    let text = fs::read_to_string(root.join("tests/interop/versions.toml"))
        .expect("read interop version pins");
    let section = match reference {
        Reference::SingBox => "sing_box",
        Reference::ShadowsocksRust => "shadowsocks_rust",
    };
    let values = parse_section(&text, section);
    let host = if cfg!(windows) { "windows" } else { "linux" };
    Pin {
        expected_version: value(&values, "expected_version").to_owned(),
        asset: value(&values, &format!("{host}_asset")).to_owned(),
        size: value(&values, &format!("{host}_size"))
            .parse()
            .expect("numeric asset size"),
        sha256: value(&values, &format!("{host}_sha256")).to_owned(),
        license_review: value(&values, "license_review").to_owned(),
    }
}

fn parse_section(text: &str, wanted: &str) -> HashMap<String, String> {
    let mut current = "";
    let mut values = HashMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            current = &line[1..line.len() - 1];
            continue;
        }
        if current != wanted || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, raw_value) = line.split_once('=').expect("pin key/value");
        values.insert(
            key.trim().to_owned(),
            raw_value.trim().trim_matches('"').to_owned(),
        );
    }
    values
}

fn value<'a>(values: &'a HashMap<String, String>, key: &str) -> &'a str {
    values
        .get(key)
        .unwrap_or_else(|| panic!("required pin field missing: {key}"))
}

fn verify_archive(path: &Path, pin: &Pin) {
    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some(pin.asset.as_str()),
        "reference archive asset name mismatch"
    );
    let metadata = fs::metadata(path).expect("reference archive metadata");
    assert_eq!(metadata.len(), pin.size, "reference archive size mismatch");
    let actual = sha256_file(path);
    assert_eq!(actual, pin.sha256, "reference archive SHA-256 mismatch");
    assert!(
        !pin.license_review.trim().is_empty()
            && pin.license_review.contains("independent test process"),
        "reference license/non-redistribution review is required"
    );
}

fn verify_version(reference: Reference, binary: &Path, expected: &str) {
    let output = match reference {
        Reference::SingBox => Command::new(binary).arg("version").output(),
        Reference::ShadowsocksRust => Command::new(binary).arg("--version").output(),
    }
    .expect("execute pinned reference version probe");
    assert!(output.status.success(), "reference version probe failed");
    let mut combined = output.stdout;
    combined.extend_from_slice(&output.stderr);
    let rendered = String::from_utf8_lossy(&combined);
    assert!(
        rendered.contains(expected),
        "reference version mismatch: expected reviewed output"
    );
}

fn sha256_file(path: &Path) -> String {
    let mut file = File::open(path).expect("open SHA-256 input");
    let mut state = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).expect("read SHA-256 input");
        if read == 0 {
            return hex_digest(state.finish());
        }
        state.update(&buffer[..read]);
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut state = Sha256::new();
    state.update(bytes);
    hex_digest(state.finish())
}

fn hex_digest(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    for byte in digest {
        text.push(HEX[usize::from(byte >> 4)] as char);
        text.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    text
}

struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            buffer: [0; 64],
            buffered: 0,
            length: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.length = self
            .length
            .checked_add(input.len() as u64)
            .expect("SHA-256 input length");
        if self.buffered != 0 {
            let take = (64 - self.buffered).min(input.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&input[..take]);
            self.buffered += take;
            input = &input[take..];
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }
        while input.len() >= 64 {
            let block: &[u8; 64] = input[..64].try_into().expect("64-byte SHA-256 block");
            self.compress(block);
            input = &input[64..];
        }
        self.buffer[..input.len()].copy_from_slice(input);
        self.buffered = input.len();
    }

    fn finish(mut self) -> [u8; 32] {
        let bit_length = self.length.checked_mul(8).expect("SHA-256 bit length");
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > 56 {
            self.buffer[self.buffered..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0; 64];
        } else {
            self.buffer[self.buffered..56].fill(0);
        }
        self.buffer[56..].copy_from_slice(&bit_length.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut digest = [0_u8; 32];
        for (chunk, word) in digest.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a_2f98,
            0x7137_4491,
            0xb5c0_fbcf,
            0xe9b5_dba5,
            0x3956_c25b,
            0x59f1_11f1,
            0x923f_82a4,
            0xab1c_5ed5,
            0xd807_aa98,
            0x1283_5b01,
            0x2431_85be,
            0x550c_7dc3,
            0x72be_5d74,
            0x80de_b1fe,
            0x9bdc_06a7,
            0xc19b_f174,
            0xe49b_69c1,
            0xefbe_4786,
            0x0fc1_9dc6,
            0x240c_a1cc,
            0x2de9_2c6f,
            0x4a74_84aa,
            0x5cb0_a9dc,
            0x76f9_88da,
            0x983e_5152,
            0xa831_c66d,
            0xb003_27c8,
            0xbf59_7fc7,
            0xc6e0_0bf3,
            0xd5a7_9147,
            0x06ca_6351,
            0x1429_2967,
            0x27b7_0a85,
            0x2e1b_2138,
            0x4d2c_6dfc,
            0x5338_0d13,
            0x650a_7354,
            0x766a_0abb,
            0x81c2_c92e,
            0x9272_2c85,
            0xa2bf_e8a1,
            0xa81a_664b,
            0xc24b_8b70,
            0xc76c_51a3,
            0xd192_e819,
            0xd699_0624,
            0xf40e_3585,
            0x106a_a070,
            0x19a4_c116,
            0x1e37_6c08,
            0x2748_774c,
            0x34b0_bcb5,
            0x391c_0cb3,
            0x4ed8_aa4a,
            0x5b9c_ca4f,
            0x682e_6ff3,
            0x748f_82ee,
            0x78a5_636f,
            0x84c8_7814,
            0x8cc7_0208,
            0x90be_fffa,
            0xa450_6ceb,
            0xbef9_a3f7,
            0xc671_78f2,
        ];
        let mut words = [0_u32; 64];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(chunk.try_into().expect("word"));
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sum1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (state, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *state = state.wrapping_add(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{sha256_bytes, sha256_file};
    use std::fs;

    #[test]
    fn sha256_matches_reviewed_known_answer() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("abc");
        fs::write(&path, b"abc").expect("write fixture");
        assert_eq!(sha256_file(&path), sha256_bytes(b"abc"));
    }
}
