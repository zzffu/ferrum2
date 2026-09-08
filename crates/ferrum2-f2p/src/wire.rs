use ferrum2_core::{ConnectErrorKind, TargetAddr, TargetHostRef};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub(crate) const MAX_TARGET_LEN: usize = 259;
pub(crate) fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid F2P message")
}

pub(crate) fn encode_target(target: &TargetAddr, output: &mut Vec<u8>) {
    match target.host() {
        TargetHostRef::Ip(IpAddr::V4(ip)) => {
            output.push(1);
            output.extend_from_slice(&ip.octets());
        }
        TargetHostRef::Ip(IpAddr::V6(ip)) => {
            output.push(4);
            output.extend_from_slice(&ip.octets());
        }
        TargetHostRef::Domain(name) => {
            output.extend_from_slice(&[3, name.len() as u8]);
            output.extend_from_slice(name.as_bytes());
        }
    }
    output.extend_from_slice(&target.port().get().to_be_bytes());
}

pub(crate) fn decode_target(input: &[u8]) -> io::Result<TargetAddr> {
    if input.len() < 3 || input.len() > MAX_TARGET_LEN {
        return Err(invalid());
    }
    let port = u16::from_be_bytes(input[input.len() - 2..].try_into().map_err(|_| invalid())?);
    match input[0] {
        1 if input.len() == 7 => TargetAddr::ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(input[1], input[2], input[3], input[4])),
            port,
        )),
        4 if input.len() == 19 => TargetAddr::ip(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&input[1..17]).map_err(|_| invalid())?,
            )),
            port,
        )),
        3 if input.len() == usize::from(input[1]) + 4 => TargetAddr::domain(
            std::str::from_utf8(&input[2..input.len() - 2]).map_err(|_| invalid())?,
            port,
        ),
        _ => return Err(invalid()),
    }
    .map_err(|_| invalid())
}

pub(crate) fn encode_endpoint(endpoint: SocketAddr, output: &mut Vec<u8>) {
    match endpoint.ip() {
        IpAddr::V4(ip) => {
            output.push(1);
            output.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            output.push(4);
            output.extend_from_slice(&ip.octets());
        }
    }
    output.extend_from_slice(&endpoint.port().to_be_bytes());
}

pub(crate) fn decode_endpoint(input: &[u8]) -> io::Result<SocketAddr> {
    decode_target(input)?.as_socket_addr().ok_or_else(invalid)
}

pub(crate) fn encode_error(error: ConnectErrorKind) -> u8 {
    match error {
        ConnectErrorKind::NetworkUnreachable => 1,
        ConnectErrorKind::HostUnreachable => 2,
        ConnectErrorKind::ConnectionRefused => 3,
        ConnectErrorKind::PolicyDenied => 4,
        ConnectErrorKind::Timeout => 5,
        ConnectErrorKind::Other => 6,
    }
}
pub(crate) fn decode_error(code: u8) -> io::Result<ConnectErrorKind> {
    Ok(match code {
        1 => ConnectErrorKind::NetworkUnreachable,
        2 => ConnectErrorKind::HostUnreachable,
        3 => ConnectErrorKind::ConnectionRefused,
        4 => ConnectErrorKind::PolicyDenied,
        5 => ConnectErrorKind::Timeout,
        6 => ConnectErrorKind::Other,
        _ => return Err(invalid()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn targets_are_exact_and_bounded() {
        for target in [
            TargetAddr::domain(&"a".repeat(255), 53).unwrap(),
            TargetAddr::ip("127.0.0.1:80".parse().unwrap()).unwrap(),
            TargetAddr::ip("[::1]:443".parse().unwrap()).unwrap(),
        ] {
            let mut bytes = Vec::new();
            encode_target(&target, &mut bytes);
            assert_eq!(decode_target(&bytes).unwrap(), target);
            let mut extra = bytes.clone();
            extra.push(0);
            assert!(decode_target(&extra).is_err());
            for length in 0..bytes.len() {
                assert!(decode_target(&bytes[..length]).is_err());
            }
            let length = bytes.len();
            bytes[length - 2..].fill(0);
            assert!(decode_target(&bytes).is_err());
        }
        assert!(decode_target(&[3, 1, 255, 0, 53]).is_err());
        assert!(decode_error(0).is_err());
        assert!(decode_error(7).is_err());
    }
}
