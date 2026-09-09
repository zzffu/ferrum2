#[path = "local_e2e_support/mod.rs"]
mod support;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use support::*;

fn handshake(command: u16, extension: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    for value in [0x3366_u16, 1, 1, command] {
        packet.extend_from_slice(&value.to_be_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&1_u32.to_be_bytes());
    packet.extend_from_slice(&(21 + extension.len() as u32).to_be_bytes());
    packet.extend_from_slice(&0_u32.to_be_bytes());
    packet.extend_from_slice(extension);
    packet
}

fn game_wire(key: &[u8]) -> Vec<u8> {
    let mut extension = vec![2, 16];
    extension.extend_from_slice(key);
    let mut wire = handshake(0x1001, &[2, 3]);
    wire.extend(handshake(0x1002, &extension));
    wire.extend_from_slice(b"malformed after identification must survive\xff\0");
    wire
}

fn connect_echo(address: SocketAddrV4) -> (TcpStream, EchoWorker) {
    let (target, echo) = start_echo();
    let (stream, reply) = socks_connect(address, target);
    assert_eq!(&reply[..2], &[5, 0]);
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .expect("bounded application writes");
    (stream, echo)
}

fn finish_echo(mut stream: TcpStream, echo: EchoWorker, expected: &[u8]) {
    stream
        .shutdown(Shutdown::Write)
        .expect("application half close");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("response after half close");
    assert_eq!(response, expected);
    assert_eq!(echo.join().expect("echo exit"), expected);
}

fn capture_paths(directory: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(directory)
        .expect("capture directory")
        .map(|entry| entry.expect("capture entry").path())
        .filter(|path| path.file_name().unwrap() != "unrelated.keep")
        .collect()
}

fn wait_for_finalized(
    directory: &std::path::Path,
    count: usize,
) -> Vec<(std::path::PathBuf, String)> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let finalized: Vec<_> = capture_paths(directory)
            .into_iter()
            .filter_map(|path| {
                // Active Windows files can be locked; partial trailing JSON is not finalization.
                let text = std::fs::read_to_string(&path).ok()?;
                let last: Value = serde_json::from_str(text.lines().last()?).ok()?;
                (last["kind"] == "stopped").then_some((path, text))
            })
            .collect();
        if finalized.len() >= count {
            assert_eq!(finalized.len(), count, "unexpected finalized capture");
            return finalized;
        }
        assert!(
            Instant::now() < deadline,
            "captures did not finalize while proxy was running"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn assert_capture(text: &str, expected: &[(Vec<u8>, Vec<u8>)]) -> usize {
    let records: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).expect("complete JSONL record"))
        .collect();
    assert_eq!(records.first().unwrap()["kind"], "started");
    assert_eq!(records.last().unwrap()["kind"], "stopped");
    assert_eq!(records.last().unwrap()["complete"], true);
    for (index, record) in records.iter().enumerate() {
        assert_eq!(record["event_seq"], index as u64 + 1);
    }
    let connections: Vec<_> = records
        .iter()
        .filter(|r| r["kind"] == "connection")
        .collect();
    assert_eq!(connections.len(), 1);
    let identity = connections[0]["connection_id"].as_u64().unwrap();
    let ends: Vec<_> = records.iter().filter(|r| r["kind"] == "end").collect();
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0]["reason"], "completed");
    for record in records.iter().filter(|r| r.get("connection_id").is_some()) {
        assert_eq!(record["connection_id"], identity);
    }
    let mut directions = Vec::new();
    for direction in ["upload", "download"] {
        let mut bytes = Vec::new();
        for record in records
            .iter()
            .filter(|r| r["kind"] == "data" && r["direction"] == direction)
        {
            assert_eq!(record["offset"], bytes.len() as u64);
            bytes.extend(
                STANDARD
                    .decode(record["bytes"].as_str().unwrap())
                    .expect("raw bytes"),
            );
        }
        directions.push(bytes);
    }
    let index = expected
        .iter()
        .position(|(wire, _)| wire == &directions[0])
        .expect("recognized connection bytes");
    assert_eq!(directions[1], expected[index].0);
    let keys: Vec<_> = records
        .iter()
        .filter(|r| r["kind"] == "key" && !r["key_hex"].is_null())
        .map(|r| r["key_hex"].as_str().unwrap())
        .collect();
    assert_eq!(keys, vec![hex::encode(&expected[index].1).as_str()]);
    index
}

#[test]
fn directory_capture_selects_game_flows_and_finalizes_each_without_proxy_exit() {
    let spawn = local_support::hold_process_spawns_at_or_below(0);
    let workspace = tempfile::tempdir().expect("recording workspace");
    let address = unused_loopback();
    let config = workspace.path().join("client.toml");
    let directory = workspace.path().join("private-captures");
    let capture_literal = directory.to_string_lossy().replace('\\', "/");
    std::fs::write(
        &config,
        format!(
            "schema_version = 2\n\
         [[inbounds]]\ntag = \"in\"\nlisten = \"{address}\"\noutbound = \"direct\"\n\
         [[outbounds]]\ntag = \"direct\"\ntype = \"direct\"\n\
         [rocom]\nrecord_path = '{capture_literal}'\nmax_bytes = 1048576\n"
        ),
    )
    .expect("recording config");
    let check = local_support::run_binary_while_holding(
        "ferrum2-client",
        &["--config", config.to_str().unwrap(), "--check-config"],
        &spawn,
    );
    assert!(check.status.success());
    assert!(
        !directory.exists(),
        "offline validation created sensitive storage"
    );
    let mut client = ChildGuard::spawn_signallable_while_holding("ferrum2-client", &config, &spawn);
    wait_for_listener(&mut client, address);
    drop(spawn);
    assert!(
        directory.is_dir(),
        "normal startup did not create directory"
    );
    let sentinel = directory.join("unrelated.keep");
    std::fs::write(&sentinel, b"unrelated existing content").unwrap();

    // HTTP, arbitrary TCP, incomplete GCP, and invalid GCP must all forward without files.
    let invalid = {
        let mut header = handshake(0x1001, &[2, 3]);
        header[13..17].copy_from_slice(&0_u32.to_be_bytes());
        header
    };
    for plain in [
        b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
        b"plain TCP\xff\0",
        b"\x33\x66\0",
        &invalid,
    ] {
        let (mut stream, echo) = connect_echo(address);
        stream.write_all(plain).expect("ordinary traffic");
        finish_echo(stream, echo, plain);
    }
    assert!(
        capture_paths(&directory).is_empty(),
        "unrecognized traffic created capture files"
    );

    let expected: Vec<_> = [(0..16).collect::<Vec<u8>>(), (32..48).collect::<Vec<u8>>()]
        .into_iter()
        .map(|key| (game_wire(&key), key))
        .collect();
    let (mut first, first_echo) = connect_echo(address);
    let (mut second, second_echo) = connect_echo(address);
    // Both flows are live together; fragment their initial headers before sending the remainder.
    first.write_all(&expected[0].0[..3]).unwrap();
    second.write_all(&expected[1].0[..3]).unwrap();
    thread::sleep(Duration::from_millis(50));
    for chunk in expected[0].0[3..].chunks(3) {
        first.write_all(chunk).expect("first split game stream");
    }
    for chunk in expected[1].0[3..].chunks(3) {
        second.write_all(chunk).expect("second split game stream");
    }
    finish_echo(first, first_echo, &expected[0].0);
    let first_finalized = wait_for_finalized(&directory, 1);
    assert_eq!(assert_capture(&first_finalized[0].1, &expected), 0);
    // The first file is readable with its footer while another identified connection stays open.
    finish_echo(second, second_echo, &expected[1].0);
    let finalized = wait_for_finalized(&directory, 2);
    let mut indices: Vec<_> = finalized
        .iter()
        .map(|(_, text)| assert_capture(text, &expected))
        .collect();
    indices.sort_unstable();
    assert_eq!(indices, vec![0, 1]);
    assert_eq!(capture_paths(&directory).len(), 2);
    client.request_graceful_shutdown();
    let exit = client.wait_for_exit(Duration::from_secs(10));
    assert!(exit.status.success(), "{exit}");
    exit.assert_stderr_excludes(&[
        "private-captures",
        &hex::encode(&expected[0].1),
        "malformed after identification",
    ]);

    // Restart into the same directory: retain old files and unrelated entries byte-for-byte.
    let spawn = local_support::hold_process_spawns_at_or_below(0);
    let mut client = ChildGuard::spawn_signallable_while_holding("ferrum2-client", &config, &spawn);
    wait_for_listener(&mut client, address);
    drop(spawn);
    let (mut stream, echo) = connect_echo(address);
    stream.write_all(&expected[0].0).unwrap();
    finish_echo(stream, echo, &expected[0].0);
    let restarted = wait_for_finalized(&directory, 3);
    assert_eq!(capture_paths(&directory).len(), 3);
    for (path, text) in &finalized {
        assert_eq!(std::fs::read_to_string(path).unwrap(), *text);
    }
    let new_capture = restarted
        .iter()
        .find(|(path, _)| !finalized.iter().any(|(old, _)| old == path))
        .unwrap();
    assert_eq!(assert_capture(&new_capture.1, &expected), 0);
    assert_eq!(
        std::fs::read(&sentinel).unwrap(),
        b"unrelated existing content"
    );
    client.request_graceful_shutdown();
    let exit = client.wait_for_exit(Duration::from_secs(10));
    assert!(exit.status.success(), "{exit}");
    let _spawn = local_support::hold_process_spawns_at_or_below(0);
    assert_eq!(active_child_count(), 0);
    drop(bind_loopback_listener(address).expect("proxy listener reclaimed"));
}

#[test]
fn rocom_records_application_bytes_across_shadowsocks_without_changing_half_close() {
    let directory = tempfile::tempdir().expect("recording workspace");
    let server_address = unused_loopback();
    let client_address = unused_loopback();
    let server_config = write_tcp_only_server_config(directory.path(), server_address, None)
        .expect("server config");
    let client_config = write_client_config(directory.path(), client_address, server_address, None)
        .expect("client config");
    let captures = directory.path().join("captures");
    let capture_literal = captures.to_string_lossy().replace('\\', "/");
    let source = std::fs::read_to_string(&client_config).unwrap();
    std::fs::write(
        &client_config,
        format!("{source}\n[rocom]\nrecord_path = '{capture_literal}'\n"),
    )
    .unwrap();
    let mut server =
        ChildGuard::spawn_signallable("ferrum2-server", &server_config, "Shadowsocks recording");
    wait_for_listener(&mut server, server_address);
    let mut client =
        ChildGuard::spawn_signallable("ferrum2-client", &client_config, "Shadowsocks recording");
    wait_for_listener(&mut client, client_address);
    let (mut stream, echo) = connect_echo(client_address);
    let mut wire = handshake(0x1001, &[2, 3]);
    wire.extend_from_slice(b"opaque tail must remain exact\0\xff");
    stream.write_all(&wire[..7]).unwrap();
    stream.write_all(&wire[7..]).unwrap();
    finish_echo(stream, echo, &wire);

    let finalized = wait_for_finalized(&captures, 1);
    let records: Vec<Value> = finalized[0]
        .1
        .lines()
        .map(|line| serde_json::from_str(line).expect("complete JSONL record"))
        .collect();
    assert_eq!(records.last().unwrap()["complete"], true);
    for direction in ["upload", "download"] {
        let captured: Vec<u8> = records
            .iter()
            .filter(|record| record["kind"] == "data" && record["direction"] == direction)
            .flat_map(|record| {
                STANDARD
                    .decode(record["bytes"].as_str().unwrap())
                    .expect("raw bytes")
            })
            .collect();
        assert_eq!(captured, wire, "{direction}");
    }
    for mut child in [client, server] {
        child.request_graceful_shutdown();
        let exit = child.wait_for_exit(Duration::from_secs(8));
        assert!(
            exit.status.success(),
            "{exit}: {}",
            exit.shutdown_report_diagnostic()
        );
        exit.assert_stderr_excludes(&[SYNTHETIC_PSK, "opaque tail must remain exact"]);
    }
}
