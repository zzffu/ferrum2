use ferrum2_core::TargetAddr;
use ferrum2_dns::{DnsProxy, ProxyIngress, ProxyTransport};
use ferrum2_observability::{Direction, Reason, Stage};
use ferrum2_runtime::CancellationToken;
use ferrum2_socks5::SocksStream;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};

use crate::run::context::ClientContext;
use crate::run::observation::record_udp_drop;

use super::endpoint::{SocksUdpEndpoint, SocksUdpPacket};

pub(super) async fn relay_hijacked_udp<IO>(
    endpoint: &mut SocksUdpEndpoint,
    control: &mut SocksStream<IO>,
    cancellation: &mut CancellationToken,
    context: &ClientContext,
    inbound: usize,
    proxy: &DnsProxy,
    first: Option<(TargetAddr, Vec<u8>)>,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    if let Some((target, payload)) = first
        && !answer_hijacked_udp(endpoint, cancellation, inbound, proxy, &target, &payload).await
    {
        return;
    }
    let mut control_byte = [0; 1];
    loop {
        let idle_deadline = endpoint.idle_deadline(context.runtime.idle_timeout);
        let received = tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = tokio::time::sleep_until(idle_deadline) => return,
            read = control.read(&mut control_byte) => {
                if !matches!(read, Ok(1)) {
                    return;
                }
                continue;
            }
            received = endpoint.receive() => received,
        };
        let (decoded, source_port) = match received {
            Ok(SocksUdpPacket::Valid {
                datagram,
                source_port,
            }) => (datagram, source_port),
            Ok(SocksUdpPacket::WrongSource) => {
                record_udp_drop(
                    context,
                    Direction::ClientToTarget,
                    Stage::Socks5,
                    Reason::Address,
                );
                continue;
            }
            Ok(SocksUdpPacket::InvalidWire) => {
                record_udp_drop(
                    context,
                    Direction::ClientToTarget,
                    Stage::Socks5,
                    Reason::Bounds,
                );
                continue;
            }
            Err(_) => return,
        };
        let target = decoded.to_target_addr();
        let payload = decoded.payload().to_vec();
        endpoint.accept(source_port);
        if !answer_hijacked_udp(endpoint, cancellation, inbound, proxy, &target, &payload).await {
            return;
        }
    }
}

pub(super) async fn answer_hijacked_udp(
    endpoint: &mut SocksUdpEndpoint,
    cancellation: &mut CancellationToken,
    inbound: usize,
    proxy: &DnsProxy,
    target: &TargetAddr,
    request: &[u8],
) -> bool {
    let response = tokio::select! {
        _ = cancellation.cancelled() => return false,
        response = proxy.answer(
            ProxyIngress::Ordinary(inbound),
            ProxyTransport::Udp,
            request,
        ) => response,
    };
    let Some(response) = response else {
        return true;
    };
    tokio::select! {
        _ = cancellation.cancelled() => false,
        result = endpoint.send(target, &response) => result.is_ok(),
    }
}
