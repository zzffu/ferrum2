use std::net::{SocketAddr, SocketAddrV4};

use ferrum2_config::MAX_UDP_RECEIVE_WORKERS;
use tokio::net::UdpSocket;

use crate::run::RunError;

/// Validates the platform-specific server receive-root contract before any
/// listener is prepared.
pub(in crate::run) const fn validate_udp_receive_workers(
    receive_workers: usize,
) -> Result<(), RunError> {
    if receive_workers == 0 || receive_workers > MAX_UDP_RECEIVE_WORKERS {
        return Err(RunError::StartupProtocol);
    }
    if !cfg!(target_os = "linux") && receive_workers != 1 {
        return Err(RunError::StartupProtocol);
    }
    Ok(())
}

/// Binds one server UDP receive root.
///
/// A single worker retains Tokio's portable bind path. Linux multi-worker
/// mode enables `SO_REUSEPORT` before bind so independently owned roots can
/// share the configured endpoint. Protocol and runtime state remain shared,
/// so correctness does not depend on kernel flow affinity.
pub(in crate::run) async fn bind_server_udp_listener(
    listen: SocketAddrV4,
    receive_workers: usize,
) -> Result<UdpSocket, RunError> {
    validate_udp_receive_workers(receive_workers)?;
    if receive_workers == 1 {
        return UdpSocket::bind(SocketAddr::V4(listen))
            .await
            .map_err(|_| RunError::StartupBind);
    }

    #[cfg(target_os = "linux")]
    {
        bind_reuse_port_listener(listen).map_err(|_| RunError::StartupBind)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = listen;
        Err(RunError::StartupProtocol)
    }
}

#[cfg(target_os = "linux")]
fn bind_reuse_port_listener(listen: SocketAddrV4) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::V4(listen).into())?;
    let socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(socket)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    #[cfg(target_os = "linux")]
    use super::bind_server_udp_listener;
    use super::validate_udp_receive_workers;
    use crate::run::RunError;

    #[test]
    fn default_single_worker_is_supported_on_every_platform() {
        assert_eq!(validate_udp_receive_workers(1), Ok(()));
    }

    #[test]
    fn worker_bounds_fail_closed() {
        assert_eq!(
            validate_udp_receive_workers(0),
            Err(RunError::StartupProtocol)
        );
        assert_eq!(
            validate_udp_receive_workers(ferrum2_config::MAX_UDP_RECEIVE_WORKERS + 1),
            Err(RunError::StartupProtocol)
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn multiple_workers_fail_closed_off_linux() {
        assert_eq!(
            validate_udp_receive_workers(2),
            Err(RunError::StartupProtocol)
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn reuse_port_workers_bind_the_same_endpoint() {
        let first = bind_server_udp_listener(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), 2)
            .await
            .expect("bind first reuse-port worker");
        let listen = match first.local_addr().expect("first local address") {
            SocketAddr::V4(listen) => listen,
            SocketAddr::V6(_) => panic!("IPv4 listener returned IPv6 address"),
        };
        let second = bind_server_udp_listener(listen, 2)
            .await
            .expect("bind second reuse-port worker");
        assert_eq!(
            second.local_addr().expect("second local address"),
            SocketAddr::V4(listen)
        );
    }
}
