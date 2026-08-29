use ferrum2_core::TargetAddr;
use ferrum2_dns::{DnsProxy, ProxyIngress, ProxyTransport};
use ferrum2_observability::{Direction, Reason, Stage};
use ferrum2_runtime::CancellationToken;
use ferrum2_socks5::SocksStream;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};

use crate::run::context::ClientContext;
use crate::run::observation::record_udp_drop;

use super::endpoint::{SocksUdpEndpoint, SocksUdpOwnedPacket, SocksUdpPacket};

pub(super) async fn relay_hijacked_udp<IO>(
    endpoint: &mut SocksUdpEndpoint,
    control: &mut SocksStream<IO>,
    cancellation: &mut CancellationToken,
    context: &ClientContext,
    inbound: usize,
    proxy: &DnsProxy,
    first: Option<SocksUdpOwnedPacket>,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    if let Some(packet) = first {
        let answered = answer_hijacked_udp(
            endpoint,
            cancellation,
            inbound,
            proxy,
            packet.target(),
            packet.payload(),
        )
        .await;
        if answered {
            endpoint.recycle(packet);
        } else {
            endpoint.recycle_failure(packet);
        }
        if !answered {
            return;
        }
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
        let packet = match received {
            Ok(SocksUdpPacket::Valid(packet)) => packet,
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
        endpoint.accept(packet.source_port());
        let answered = answer_hijacked_udp(
            endpoint,
            cancellation,
            inbound,
            proxy,
            packet.target(),
            packet.payload(),
        )
        .await;
        if answered {
            endpoint.recycle(packet);
        } else {
            endpoint.recycle_failure(packet);
        }
        if !answered {
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
