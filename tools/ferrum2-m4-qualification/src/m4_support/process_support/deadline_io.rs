use std::io::{self, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

use super::{IO_TIMEOUT, clean_io};

/// Synchronous I/O honoring each installed timeout; injected implementations must
/// complete each operation finitely. The caller supplies one absolute deadline.
trait DeadlineIo: Read + Write {
    fn read_timeout(&self, timeout: Duration) -> io::Result<()>;
    fn write_timeout(&self, timeout: Duration) -> io::Result<()>;
}

impl DeadlineIo for TcpStream {
    fn read_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(timeout))
    }

    fn write_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.set_write_timeout(Some(timeout))
    }
}

pub(crate) fn io_timeout_at(now: Instant, deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| remaining.min(IO_TIMEOUT))
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
}

fn write_until(
    stream: &mut impl DeadlineIo,
    mut bytes: &[u8],
    deadline: Instant,
    now: &mut impl FnMut() -> Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.write_timeout(io_timeout_at(now(), deadline)?)?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    io_timeout_at(now(), deadline).map(|_| ())
}

fn read_until(
    stream: &mut impl DeadlineIo,
    mut bytes: &mut [u8],
    deadline: Instant,
    now: &mut impl FnMut() -> Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.read_timeout(io_timeout_at(now(), deadline)?)?;
        match stream.read(bytes) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    io_timeout_at(now(), deadline).map(|_| ())
}

pub(in crate::m4_support) fn write_all_until(
    stream: &mut TcpStream,
    bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    write_until(stream, bytes, deadline, &mut Instant::now)
}

pub(in crate::m4_support) fn read_exact_until(
    stream: &mut TcpStream,
    bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    read_until(stream, bytes, deadline, &mut Instant::now)
}

fn read_end_until(
    stream: &mut impl DeadlineIo,
    output: &mut Vec<u8>,
    maximum: usize,
    deadline: Instant,
    now: &mut impl FnMut() -> Instant,
) -> io::Result<()> {
    let mut buffer = [0_u8; 4096];
    loop {
        stream.read_timeout(io_timeout_at(now(), deadline)?)?;
        let capacity = maximum
            .saturating_sub(output.len())
            .saturating_add(1)
            .min(buffer.len());
        match stream.read(&mut buffer[..capacity]) {
            Ok(0) => return io_timeout_at(now(), deadline).map(|_| ()),
            Ok(read) => {
                if read > maximum.saturating_sub(output.len()) {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                output.extend_from_slice(&buffer[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

pub(in crate::m4_support) fn read_to_end_until(
    stream: &mut TcpStream,
    output: &mut Vec<u8>,
    maximum: usize,
    deadline: Instant,
) -> io::Result<()> {
    read_end_until(stream, output, maximum, deadline, &mut Instant::now)
}

fn negotiate(
    stream: &mut impl DeadlineIo,
    target: SocketAddrV4,
    deadline: Instant,
    now: &mut impl FnMut() -> Instant,
) -> Result<(), String> {
    write_until(stream, &[5, 1, 0], deadline, now).map_err(clean_io)?;
    let mut method = [0_u8; 2];
    read_until(stream, &mut method, deadline, now).map_err(clean_io)?;
    if method != [5, 0] {
        return Err("SOCKS authentication negotiation failed".to_owned());
    }
    let mut request = [0_u8; 10];
    request[..4].copy_from_slice(&[5, 1, 0, 1]);
    request[4..8].copy_from_slice(&target.ip().octets());
    request[8..].copy_from_slice(&target.port().to_be_bytes());
    write_until(stream, &request, deadline, now).map_err(clean_io)?;
    let mut reply = [0_u8; 10];
    read_until(stream, &mut reply, deadline, now).map_err(clean_io)?;
    if reply[..4] != [5, 0, 0, 1] {
        return Err("SOCKS CONNECT failed".to_owned());
    }
    stream.read_timeout(IO_TIMEOUT).map_err(clean_io)?;
    stream.write_timeout(IO_TIMEOUT).map_err(clean_io)?;
    io_timeout_at(now(), deadline).map_err(clean_io)?;
    Ok(())
}

/// Connects and negotiates by one absolute deadline. The returned blocking
/// stream retains finite read/write timeouts; payload owners must apply their
/// own absolute transaction deadline or explicitly hand off to async I/O.
pub(in crate::m4_support) fn socks_connect(
    proxy: SocketAddrV4,
    target: SocketAddrV4,
    deadline: Instant,
) -> Result<TcpStream, String> {
    let timeout = io_timeout_at(Instant::now(), deadline).map_err(clean_io)?;
    let mut stream =
        TcpStream::connect_timeout(&SocketAddr::V4(proxy), timeout).map_err(clean_io)?;
    negotiate(&mut stream, target, deadline, &mut Instant::now)?;
    Ok(stream)
}

#[cfg(test)]
mod tests;
