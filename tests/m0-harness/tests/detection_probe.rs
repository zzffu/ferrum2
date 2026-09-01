#[path = "../src/local_support/mod.rs"]
mod local_support;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit, Nonce};
use blake3::derive_key;
use local_support::{ChildGuard, unused_loopback, wait_for_bound, write_tcp_only_server_config};

const PSK: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const KDF_CONTEXT: &str = "shadowsocks 2022 session subkey";
const FIXED_REGION_LEN: usize = 43;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedReason {
    ShortRead,
    Authentication,
    InvalidType,
    TimestampSkew,
    AddressBounds,
}

struct Probe {
    name: String,
    wire: Vec<u8>,
    expected: ExpectedReason,
}

fn subkey(salt: &[u8; 16]) -> [u8; 16] {
    let mut material = [0_u8; 32];
    material[..16].copy_from_slice(&PSK);
    material[16..].copy_from_slice(salt);
    derive_key(KDF_CONTEXT, &material)[..16]
        .try_into()
        .expect("fixed AES-128 subkey")
}

fn seal(key: &[u8; 16], nonce: u8, plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes128Gcm::new_from_slice(key).expect("AES-128 key");
    let mut ciphertext = plaintext.to_vec();
    let mut nonce_bytes = [0_u8; 12];
    nonce_bytes[0] = nonce;
    let tag = cipher
        .encrypt_inout_detached(
            &Nonce::from(nonce_bytes),
            &[],
            ciphertext.as_mut_slice().into(),
        )
        .expect("independent probe encryption");
    ciphertext.extend_from_slice(&tag);
    ciphertext
}

fn salt(case: u8) -> [u8; 16] {
    let mut salt = [0_u8; 16];
    salt[0] = 0x80;
    salt[15] = case;
    salt
}

fn request(
    salt: [u8; 16],
    message_type: u8,
    timestamp: u64,
    declared_variable_len: u16,
    variable: &[u8],
) -> Vec<u8> {
    let key = subkey(&salt);
    let mut fixed = vec![message_type];
    fixed.extend_from_slice(&timestamp.to_be_bytes());
    fixed.extend_from_slice(&declared_variable_len.to_be_bytes());
    let mut wire = salt.to_vec();
    wire.extend_from_slice(&seal(&key, 0, &fixed));
    wire.extend_from_slice(&seal(&key, 1, variable));
    wire
}

fn valid_variable(target: SocketAddrV4) -> Vec<u8> {
    let mut variable = vec![1];
    variable.extend_from_slice(&target.ip().octets());
    variable.extend_from_slice(&target.port().to_be_bytes());
    variable.extend_from_slice(&1_u16.to_be_bytes());
    variable.push(0xa5);
    variable
}

fn probes(now: u64, target: SocketAddrV4) -> Vec<Probe> {
    let variable = valid_variable(target);
    let valid = request(
        salt(1),
        0,
        now,
        u16::try_from(variable.len()).expect("bounded variable"),
        &variable,
    );
    assert_eq!(valid.len(), FIXED_REGION_LEN + variable.len() + 16);

    let mut probes = (0..FIXED_REGION_LEN)
        .map(|length| Probe {
            name: format!("short-{length}"),
            wire: valid[..length].to_vec(),
            expected: ExpectedReason::ShortRead,
        })
        .collect::<Vec<_>>();

    let mut authentication = request(
        salt(2),
        0,
        now,
        u16::try_from(variable.len()).expect("bounded variable"),
        &variable,
    );
    authentication[20] ^= 1;
    probes.push(Probe {
        name: "authentication".to_owned(),
        wire: authentication,
        expected: ExpectedReason::Authentication,
    });
    probes.push(Probe {
        name: "invalid-type".to_owned(),
        wire: request(
            salt(3),
            1,
            now,
            u16::try_from(variable.len()).expect("bounded variable"),
            &variable,
        ),
        expected: ExpectedReason::InvalidType,
    });
    probes.push(Probe {
        name: "stale-time".to_owned(),
        wire: request(
            salt(4),
            0,
            now.saturating_sub(120),
            u16::try_from(variable.len()).expect("bounded variable"),
            &variable,
        ),
        expected: ExpectedReason::TimestampSkew,
    });
    probes.push(Probe {
        name: "zero-variable-length".to_owned(),
        wire: request(salt(5), 0, now, 0, &[]),
        expected: ExpectedReason::AddressBounds,
    });
    probes
}

#[test]
fn independent_generator_preconditions_are_exact_and_typed() {
    let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080);
    let now = 1_900_000_000;
    let probes = probes(now, target);
    assert_eq!(probes.len(), 47);
    assert_eq!(
        probes
            .iter()
            .filter(|probe| probe.expected == ExpectedReason::ShortRead)
            .count(),
        43
    );
    assert_eq!(
        probes
            .iter()
            .map(|probe| probe.expected)
            .skip(43)
            .collect::<Vec<_>>(),
        [
            ExpectedReason::Authentication,
            ExpectedReason::InvalidType,
            ExpectedReason::TimestampSkew,
            ExpectedReason::AddressBounds,
        ]
    );
    for (length, probe) in probes[..43].iter().enumerate() {
        assert_eq!(probe.wire.len(), length);
    }
    assert_eq!(
        probes.last().expect("length row").wire.len(),
        FIXED_REGION_LEN + 16,
        "zero declared variable length still carries the valid nonce-one empty AEAD tag"
    );
}

#[test]
fn exact_47_native_connections_reset_and_never_reach_target() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let server_address = unused_loopback();
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("target listener");
    target
        .set_nonblocking(true)
        .expect("nonblocking target listener");
    let target_address = match target.local_addr().expect("target address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 target"),
    };
    let config = write_tcp_only_server_config(directory.path(), server_address, None)
        .expect("server config");
    let mut server = ChildGuard::spawn("ferrum2-server", &config);
    wait_for_bound(&mut server, server_address);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let probes = probes(now, target_address);
    assert_eq!(probes.len(), 47);
    for probe in probes {
        let mut stream = TcpStream::connect(server_address).expect("native probe connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("native probe timeout");
        stream.write_all(&probe.wire).expect("native probe write");
        stream
            .shutdown(Shutdown::Write)
            .expect("native probe half close");
        let mut byte = [0_u8; 1];
        let error = stream
            .read(&mut byte)
            .expect_err(&format!("{} must reset rather than return EOF", probe.name));
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset,
            "{} ({:?})",
            probe.name,
            probe.expected
        );
        match target.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!("{} reached the target", probe.name),
            Err(error) => panic!("target accept failed after {}: {error}", probe.name),
        }
    }

    server.terminate_and_reap(Duration::from_secs(5));
}
