use super::contract::parse;
use super::socket_io::{BLOCK, runtime};
use std::ffi::OsString;
use std::io::Write;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;

async fn echo(mut stream: TcpStream) -> Result<(), String> {
    stream.set_nodelay(true).map_err(|e| e.to_string())?;
    let socket = socket2::SockRef::from(&stream);
    socket
        .set_send_buffer_size(BLOCK)
        .map_err(|e| e.to_string())?;
    socket
        .set_recv_buffer_size(BLOCK)
        .map_err(|e| e.to_string())?;
    let mut buffer = [0; BLOCK];
    loop {
        let count = tokio::time::timeout(Duration::from_secs(45), stream.read(&mut buffer))
            .await
            .map_err(|_| "support TCP idle deadline")?
            .map_err(|e| e.to_string())?;
        if count == 0 {
            stream.shutdown().await.map_err(|e| e.to_string())?;
            return Ok(());
        }
        tokio::time::timeout(Duration::from_secs(45), stream.write_all(&buffer[..count]))
            .await
            .map_err(|_| "support TCP write deadline")?
            .map_err(|e| e.to_string())?;
    }
}

pub(crate) fn run_support(arguments: &[OsString]) -> Result<String, String> {
    let args = parse(arguments, "support")?;
    runtime()?.block_on(async {
        let tcp = TcpListener::bind(args.tcp).await.map_err(|e| e.to_string())?;
        let udp = UdpSocket::bind(args.udp).await.map_err(|e| e.to_string())?;
        let mut connections = JoinSet::new();
        println!("windows_tun_support status=READY tcp={} udp={}", args.tcp, args.udp);
        std::io::stdout().flush().map_err(|e| e.to_string())?;
        let mut buffer = vec![0; 65_507];
        let deadline = tokio::time::sleep(Duration::from_secs(900));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                () = &mut deadline => return Err("support lifetime deadline".to_owned()),
                accepted = tcp.accept() => {
                    let (stream, _) = accepted.map_err(|e| e.to_string())?;
                    if connections.len() >= 32 {
                        return Err("support TCP connection bound exceeded".into());
                    }
                    connections.spawn(echo(stream));
                }
                completed = connections.join_next(), if !connections.is_empty() => {
                    // Route reset deliberately retires old sockets; their I/O
                    // error is expected, whereas a task panic is not.
                    let _ = completed.ok_or("support worker missing")?.map_err(|e| e.to_string())?;
                }
                received = udp.recv_from(&mut buffer) => {
                    let (count, peer) = received.map_err(|e| e.to_string())?;
                    let reply = super::socket_io::udp_ack(&buffer[..count])?;
                    let sent = tokio::time::timeout(Duration::from_secs(5), udp.send_to(&reply, peer))
                        .await.map_err(|_| "support UDP deadline")?.map_err(|e| e.to_string())?;
                    if sent != reply.len() { return Err("support partial UDP acknowledgement".into()); }
                }
            }
        }
        // JoinSet aborts every owned connection when the support future exits.
    })
}
