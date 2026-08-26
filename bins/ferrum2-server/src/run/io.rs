use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpSocket};

use super::RunError;

pub(super) fn bind_listener(
    address: std::net::SocketAddrV4,
    backlog: u32,
) -> Result<TcpListener, RunError> {
    let socket = TcpSocket::new_v4().map_err(|_| RunError::StartupBind)?;
    #[cfg(unix)]
    socket
        .set_reuseaddr(true)
        .map_err(|_| RunError::StartupBind)?;
    socket
        .bind(SocketAddr::V4(address))
        .map_err(|_| RunError::StartupBind)?;
    socket.listen(backlog).map_err(|_| RunError::StartupBind)
}

pub(super) async fn shutdown_signal() {
    #[cfg(windows)]
    {
        let Ok(mut ctrl_break) = tokio::signal::windows::ctrl_break() else {
            std::future::pending::<()>().await;
            return;
        };
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if result.is_err() {
                    std::future::pending::<()>().await;
                }
            }
            signal = ctrl_break.recv() => {
                if signal.is_none() {
                    std::future::pending::<()>().await;
                }
            }
        }
    }
    #[cfg(not(windows))]
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

#[cfg(all(test, unix))]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;
    use crate::run::test_support::reserve_address;

    #[cfg(unix)]
    #[tokio::test]
    async fn listener_policy_rebinds_after_traffic_and_excludes_live_contender() {
        let address = reserve_address();
        let listener = bind_listener(address, 1).expect("initial listener");
        let (client, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(address), listener.accept());
        let mut client = client.expect("client connect");
        let (mut accepted, _) = accepted.expect("listener accept");
        client.write_all(b"x").await.expect("client traffic");
        let mut request = [0_u8; 1];
        accepted
            .read_exact(&mut request)
            .await
            .expect("accepted traffic");
        accepted.write_all(b"y").await.expect("server traffic");
        accepted.shutdown().await.expect("server active close");
        let mut response = [0_u8; 1];
        client
            .read_exact(&mut response)
            .await
            .expect("client response");
        assert_eq!(response, *b"y");
        assert_eq!(client.read(&mut response).await.expect("client EOF"), 0);
        drop(accepted);
        drop(client);
        drop(listener);

        let rebound = bind_listener(address, 1).expect("exact listener restart");
        assert_eq!(
            bind_listener(address, 1).expect_err("live contender"),
            RunError::StartupBind
        );
        drop(rebound);
    }
}
