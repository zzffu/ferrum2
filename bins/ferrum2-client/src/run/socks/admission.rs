use crate::run::context::{ClientContext, ClientRouting};
use crate::run::egress::{ClientUdpAssociation, UdpPlanResponseError};
use crate::run::observation::{
    UdpPacketPhase, record_udp_drop, record_udp_packet_error, record_udp_runtime_error,
};
use bytes::BytesMut;
use ferrum2_core::TargetAddr;
use ferrum2_observability::{Direction, Outcome, Reason, Stage};
use tokio::time::Instant;

#[path = "endpoint.rs"]
mod endpoint;
pub(super) use endpoint::SocksUdpEndpoint;
use endpoint::{SocksUdpPacket, SourceCandidate};

pub(super) struct CandidateRequest {
    source: SourceCandidate,
    pub(super) target: TargetAddr,
    pub(super) payload: BytesMut,
    encoded_target_len: usize,
}
pub(super) struct AdmittedRequest {
    pub(super) wire_len: usize,
    pub(super) payload_len: usize,
}
pub(super) enum RequestDisposition {
    Admitted(AdmittedRequest),
    Dropped,
    Terminated,
}

pub(super) async fn receive_candidate(
    endpoint: &mut SocksUdpEndpoint,
    context: &ClientContext,
) -> std::io::Result<Option<CandidateRequest>> {
    Ok(match endpoint.receive().await? {
        SocksUdpPacket::Valid { datagram, source } => Some(CandidateRequest {
            source,
            target: datagram.to_target_addr(),
            payload: BytesMut::from(datagram.payload()),
            encoded_target_len: datagram.encoded_target_len(),
        }),
        SocksUdpPacket::WrongSource => {
            record_udp_drop(
                context,
                Direction::ClientToTarget,
                Stage::Socks5,
                Reason::Address,
            );
            None
        }
        SocksUdpPacket::InvalidWire => {
            record_udp_drop(
                context,
                Direction::ClientToTarget,
                Stage::Socks5,
                Reason::Bounds,
            );
            None
        }
    })
}

pub(super) fn admit_request(
    endpoint: &mut SocksUdpEndpoint,
    prepared: &mut ClientUdpAssociation,
    context: &ClientContext,
    routing: &ClientRouting,
    candidate: CandidateRequest,
) -> RequestDisposition {
    if candidate.payload.len()
        > prepared.payload_limit(
            &routing.outbounds,
            ferrum2_shadowsocks::UdpPacketDirection::Request,
            candidate.encoded_target_len,
        )
    {
        record_udp_drop(
            context,
            Direction::ClientToTarget,
            Stage::Shadowsocks,
            Reason::Bounds,
        );
        return RequestDisposition::Dropped;
    }
    if prepared.activate(&context.egress).is_err() {
        crate::run::observation::record_udp_terminal(
            context,
            Stage::Shadowsocks,
            Reason::Random,
            Outcome::Failed,
        );
        return RequestDisposition::Terminated;
    }
    let CandidateRequest {
        source,
        target,
        payload,
        ..
    } = candidate;
    let payload_len = payload.len();
    let now = Instant::now();
    match prepared.prepare_owned_application_request(
        &context.egress,
        &routing.outbounds,
        target,
        payload,
        now,
    ) {
        Ok(wire_len) => {
            endpoint.accept_admitted(source, now);
            RequestDisposition::Admitted(AdmittedRequest {
                wire_len,
                payload_len,
            })
        }
        Err(UdpPlanResponseError::Packet(error)) => {
            if record_udp_packet_error(
                context,
                Direction::ClientToTarget,
                UdpPacketPhase::RequestEncode,
                error,
            ) {
                RequestDisposition::Dropped
            } else {
                RequestDisposition::Terminated
            }
        }
        Err(UdpPlanResponseError::Runtime(error)) => {
            if record_udp_runtime_error(context, Direction::ClientToTarget, error) {
                RequestDisposition::Dropped
            } else {
                RequestDisposition::Terminated
            }
        }
    }
}

pub(super) fn admit_answer(
    endpoint: &mut SocksUdpEndpoint,
    candidate: CandidateRequest,
    response: &[u8],
) -> Result<usize, ()> {
    let length = endpoint
        .prepare_response(&candidate.target, response)
        .map_err(|_| ())?;
    endpoint.accept_admitted(candidate.source, Instant::now());
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::super::send::send_with_control;
    use super::*;
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use tokio::net::UdpSocket;

    #[tokio::test(start_paused = true)]
    async fn admitted_dns_answer_can_wait_past_old_idle_deadline_for_send_readiness() {
        let timeout = Duration::from_secs(10);
        let mut endpoint = SocksUdpEndpoint::bind(
            Ipv4Addr::LOCALHOST,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
            UdpSocket::bind,
        )
        .await
        .unwrap();
        let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = TargetAddr::ip("127.0.0.1:53".parse().unwrap()).unwrap();
        let mut wire = [0; 64];
        let length = ferrum2_socks5::encode_udp_datagram(&target, b"query", &mut wire).unwrap();
        application
            .send_to(&wire[..length], endpoint.local_addr().unwrap())
            .await
            .unwrap();
        let SocksUdpPacket::Valid { datagram, source } = endpoint.receive().await.unwrap() else {
            panic!("valid candidate")
        };
        let candidate = CandidateRequest {
            source,
            target: datagram.to_target_addr(),
            payload: BytesMut::from(datagram.payload()),
            encoded_target_len: datagram.encoded_target_len(),
        };
        let old_deadline = endpoint.idle_deadline(timeout);
        tokio::time::advance(Duration::from_secs(9)).await;
        let length = admit_answer(&mut endpoint, candidate, b"answer").unwrap();
        let deadline = endpoint.idle_deadline(timeout);
        assert_eq!(deadline, Instant::now() + timeout);
        let (mut control, _peer) = tokio::io::duplex(16);
        let (_session, mut session) = tokio::sync::watch::channel(false);
        let (release, receive) = tokio::sync::oneshot::channel();
        let send = async {
            receive.await.unwrap();
            Ok(length)
        };
        let sending = send_with_control(
            send,
            &mut control,
            std::future::pending(),
            &mut session,
            deadline,
        );
        tokio::pin!(sending);
        std::future::poll_fn(|cx| {
            assert!(sending.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(Instant::now() > old_deadline);
        std::future::poll_fn(|cx| {
            assert!(sending.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        release.send(()).unwrap();
        assert_eq!(sending.await, Ok(length));
    }
}
