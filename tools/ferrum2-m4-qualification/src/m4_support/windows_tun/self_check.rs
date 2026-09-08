use super::contract::parse;
use super::socket_io::payload;
use std::ffi::OsString;

pub(crate) fn run_self_check() -> Result<(), String> {
    let valid = [
        "--target-ip",
        "198.18.0.1",
        "--tcp-port",
        "32001",
        "--udp-port",
        "32002",
    ]
    .map(OsString::from)
    .to_vec();
    parse(&valid, "probe")?;
    for (flag, value) in [
        ("--target-ip", "198.18.0.2"),
        ("--scenario", "tcp-single"),
        ("--warmup-seconds", "1"),
        ("--diagnostic-ledger", "retired"),
    ] {
        let mut invalid = valid.clone();
        invalid.extend([OsString::from(flag), OsString::from(value)]);
        if parse(&invalid, "probe").is_ok() {
            return Err(format!(
                "qualification accepted duplicate or retired option {flag}"
            ));
        }
    }
    for ip in ["127.0.0.1", "0.0.0.0", "224.0.0.1", "hostname"] {
        let mut invalid = valid.clone();
        invalid[1] = OsString::from(ip);
        if parse(&invalid, "probe").is_ok() {
            return Err("qualification accepted invalid target".into());
        }
    }
    if payload(4096, 1, 0, 1) == payload(4096, 2, 0, 1)
        || payload(4096, 1, 0, 1) == payload(4096, 1, 1, 1)
        || payload(4096, 1, 0, 1) == payload(4096, 1, 0, 2)
    {
        return Err("qualification payload identities overlap".into());
    }
    let mut request = payload(4096, 1, 2, 3);
    let reply = super::socket_io::udp_ack(&request)?;
    if reply != *b"F2QA\0\0\x10\0\x01\x02\x03" {
        return Err("UDP acknowledgement does not bind request length and identity".into());
    }
    request[4095] ^= 1;
    if super::socket_io::udp_ack(&request).is_ok() {
        return Err("UDP acknowledgement accepted a corrupt request tail".into());
    }
    Ok(())
}
