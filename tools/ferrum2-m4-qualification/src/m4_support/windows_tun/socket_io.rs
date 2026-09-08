use serde_json::Value;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};

pub(super) const BLOCK: usize = 16 * 1024;
pub(super) const BULK: usize = 8 * 1024 * 1024;
pub(super) const IO_LIMIT: Duration = Duration::from_secs(5);
pub(super) const FRAGMENT: usize = 4096;

pub(super) fn payload(length: usize, generation: u8, flow: u8, phase: u8) -> Vec<u8> {
    (0..length)
        .map(|index| match index % 16 {
            0 => generation,
            1 => flow,
            2 => phase,
            _ => {
                ((index as u64)
                    .wrapping_mul(131)
                    .wrapping_add((index / 256) as u64)
                    & 255) as u8
            }
        })
        .collect()
}

pub(super) async fn connect(address: SocketAddr) -> Result<TcpStream, String> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(|e| e.to_string())?;
    if address.is_ipv6() {
        socket2::SockRef::from(&socket)
            .set_only_v6(true)
            .map_err(|e| e.to_string())?;
    }
    socket
        .set_send_buffer_size(BLOCK as u32)
        .map_err(|e| e.to_string())?;
    socket
        .set_recv_buffer_size(BLOCK as u32)
        .map_err(|e| e.to_string())?;
    let stream = tokio::time::timeout(IO_LIMIT, socket.connect(address))
        .await
        .map_err(|_| "TCP connect deadline")?
        .map_err(|e| e.to_string())?;
    stream.set_nodelay(true).map_err(|e| e.to_string())?;
    Ok(stream)
}

fn bound_socket(address: SocketAddr, tcp: bool) -> Result<socket2::Socket, String> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(address),
        if tcp {
            socket2::Type::STREAM
        } else {
            socket2::Type::DGRAM
        },
        Some(if tcp {
            socket2::Protocol::TCP
        } else {
            socket2::Protocol::UDP
        }),
    )
    .map_err(|e| e.to_string())?;
    if address.is_ipv6() {
        socket.set_only_v6(true).map_err(|e| e.to_string())?;
    }
    socket.set_nonblocking(true).map_err(|e| e.to_string())?;
    socket.bind(&address.into()).map_err(|e| e.to_string())?;
    Ok(socket)
}

pub(super) fn listen(address: SocketAddr) -> Result<TcpListener, String> {
    let socket = bound_socket(address, true)?;
    socket.listen(32).map_err(|e| e.to_string())?;
    TcpListener::from_std(socket.into()).map_err(|e| e.to_string())
}

pub(super) fn bind_udp(address: SocketAddr) -> Result<UdpSocket, String> {
    let socket: std::net::UdpSocket = bound_socket(address, false)?.into();
    #[cfg(all(windows, target_arch = "x86_64"))]
    if address.is_ipv6() {
        // Windows otherwise may reject the 4096-byte request at the TUN's 1420-byte
        // MTU. Fragment at the real outgoing interface; never split in userspace.
        ferrum2_platform_windows::enable_ipv6_udp_fragmentation(&socket)
            .map_err(|e| e.to_string())?;
    }
    UdpSocket::from_std(socket).map_err(|e| e.to_string())
}

pub(super) async fn udp(address: SocketAddr) -> Result<UdpSocket, String> {
    let bind = SocketAddr::new(
        if address.is_ipv4() {
            std::net::Ipv4Addr::UNSPECIFIED.into()
        } else {
            std::net::Ipv6Addr::UNSPECIFIED.into()
        },
        0,
    );
    let socket = bind_udp(bind)?;
    socket.connect(address).await.map_err(|e| e.to_string())?;
    Ok(socket)
}

pub(super) async fn exchange(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), String> {
    tokio::time::timeout(IO_LIMIT, async {
        stream.write_all(bytes).await.map_err(|e| e.to_string())?;
        let mut reply = vec![0; bytes.len()];
        stream
            .read_exact(&mut reply)
            .await
            .map_err(|e| e.to_string())?;
        if reply != bytes {
            return Err("TCP payload mismatch".into());
        }
        Ok(())
    })
    .await
    .map_err(|_| "TCP exchange deadline".to_owned())?
}

/// Acknowledge only a completely validated request. The fixed-size reply fits the
/// TUN response MTU even when the request exercised ingress fragment reassembly.
pub(super) fn udp_ack(bytes: &[u8]) -> Result<[u8; 11], String> {
    if bytes.len() < 3 || bytes != payload(bytes.len(), bytes[0], bytes[1], bytes[2]) {
        return Err("UDP qualification request payload mismatch".into());
    }
    let length = u32::try_from(bytes.len()).map_err(|_| "UDP qualification request too large")?;
    let mut reply = [0; 11];
    reply[..4].copy_from_slice(b"F2QA");
    reply[4..8].copy_from_slice(&length.to_be_bytes());
    reply[8..].copy_from_slice(&bytes[..3]);
    Ok(reply)
}

pub(super) async fn datagram(socket: &UdpSocket, bytes: &[u8]) -> Result<(), String> {
    let expected = udp_ack(bytes)?;
    tokio::time::timeout(IO_LIMIT, async {
        if socket.send(bytes).await.map_err(|e| e.to_string())? != bytes.len() {
            return Err("partial UDP send".into());
        }
        let mut reply = vec![0; expected.len() + 1];
        let received = socket.recv(&mut reply).await.map_err(|e| e.to_string())?;
        if reply[..received] != expected {
            return Err("UDP payload mismatch".into());
        }
        Ok(())
    })
    .await
    .map_err(|_| "UDP exchange deadline".to_owned())?
}

// No application reads occur here. A full socket remaining unwritable for 100ms
// is the checked pressure witness; reaching the byte cap is a qualification failure.
pub(super) async fn pause_reader(stream: &TcpStream, bytes: &[u8]) -> Result<usize, String> {
    tokio::time::timeout(IO_LIMIT, async {
        let mut sent = 0;
        loop {
            stream.writable().await.map_err(|e| e.to_string())?;
            match stream.try_write(&bytes[sent..(sent + BLOCK).min(bytes.len())]) {
                Ok(0) => return Err("TCP terminated during paused-reader phase".into()),
                Ok(count) => {
                    sent += count;
                    if sent == bytes.len() {
                        return Err(
                            "paused reader did not produce backpressure before byte cap".into()
                        );
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if tokio::time::timeout(Duration::from_millis(100), stream.writable())
                        .await
                        .is_err()
                    {
                        if sent == 0 {
                            return Err("paused writer made no initial progress".into());
                        }
                        return Ok(sent);
                    }
                }
                Err(error) => return Err(format!("paused writer failed: {error}")),
            }
        }
    })
    .await
    .map_err(|_| "paused-reader progress deadline".to_owned())?
}

pub(super) async fn duplex(
    stream: &mut TcpStream,
    bytes: &[u8],
    sent: usize,
) -> Result<(), String> {
    tokio::time::timeout(IO_LIMIT, async {
        let (mut reader, mut writer) = stream.split();
        let send = async {
            for block in bytes[sent..].chunks(BLOCK) {
                writer.write_all(block).await.map_err(|e| e.to_string())?;
            }
            Ok::<_, String>(())
        };
        let receive = async {
            let mut reply = [0; BLOCK];
            for expected in bytes.chunks(BLOCK) {
                reader
                    .read_exact(&mut reply[..expected.len()])
                    .await
                    .map_err(|e| e.to_string())?;
                if reply[..expected.len()] != *expected {
                    return Err("full-duplex payload mismatch".into());
                }
            }
            Ok::<_, String>(())
        };
        tokio::try_join!(send, receive)?;
        Ok(())
    })
    .await
    .map_err(|_| "full-duplex progress deadline".to_owned())?
}

pub(super) fn publish(path: &Path, value: &Value) -> Result<(), String> {
    let parent = path.parent().ok_or("evidence path has no parent")?;
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    serde_json::to_writer(file.as_file_mut(), value).map_err(|e| e.to_string())?;
    file.flush().map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist_noclobber(path).map_err(|e| e.to_string())?;
    Ok(())
}

pub(super) fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
}
