use super::admission::{CandidateRequest, SocksUdpEndpoint, admit_answer, receive_candidate};
use crate::run::context::ClientContext;
use ferrum2_dns::{DnsProxy, ProxyIngress, ProxyTransport};
use ferrum2_runtime::CancellationToken;
use ferrum2_socks5::SocksStream;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};

pub(super) enum DnsDisposition {
    Admitted,
    Dropped,
    Terminated,
}

pub(super) async fn relay_hijacked_udp<IO: AsyncRead + AsyncWrite + Unpin>(
    endpoint: &mut SocksUdpEndpoint,
    control: &mut SocksStream<IO>,
    cancellation: &mut CancellationToken,
    context: &ClientContext,
    inbound: usize,
    proxy: &DnsProxy,
) {
    let mut control_byte = [0];
    loop {
        let deadline = endpoint.idle_deadline(context.runtime.idle_timeout);
        let candidate = tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = tokio::time::sleep_until(deadline) => return,
            read = control.read(&mut control_byte) => { if !matches!(read, Ok(1)) { return; } continue; }
            received = receive_candidate(endpoint, context) => match received { Ok(Some(candidate)) => candidate, Ok(None) => continue, Err(_) => return },
        };
        if matches!(
            answer_hijacked_udp(
                endpoint,
                control,
                cancellation,
                inbound,
                proxy,
                candidate,
                context.runtime.idle_timeout
            )
            .await,
            DnsDisposition::Terminated
        ) {
            return;
        }
    }
}

pub(super) async fn answer_hijacked_udp<IO: AsyncRead + AsyncWrite + Unpin>(
    endpoint: &mut SocksUdpEndpoint,
    control: &mut SocksStream<IO>,
    cancellation: &mut CancellationToken,
    inbound: usize,
    proxy: &DnsProxy,
    candidate: CandidateRequest,
    idle_timeout: Duration,
) -> DnsDisposition {
    let deadline = endpoint.idle_deadline(idle_timeout);
    let mut control_byte = [0];
    let response = {
        let answering = proxy.answer(
            ProxyIngress::Ordinary(inbound),
            ProxyTransport::Udp,
            &candidate.payload,
        );
        tokio::pin!(answering);
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return DnsDisposition::Terminated,
                _ = tokio::time::sleep_until(deadline) => return DnsDisposition::Terminated,
                read = control.read(&mut control_byte) => { if !matches!(read, Ok(1)) { return DnsDisposition::Terminated; } }
                response = &mut answering => break response,
            }
        }
    };
    let Some(response) = response else {
        return DnsDisposition::Dropped;
    };
    let Ok(length) = admit_answer(endpoint, candidate, &response) else {
        return DnsDisposition::Dropped;
    };
    // Successful admission renewed endpoint activity; the response gets that
    // configured idle period rather than the pre-answer deadline.
    let deadline = endpoint.idle_deadline(idle_timeout);
    let sending = endpoint.send_encoded(length);
    tokio::pin!(sending);
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => return DnsDisposition::Terminated,
            _ = tokio::time::sleep_until(deadline) => return DnsDisposition::Terminated,
            read = control.read(&mut control_byte) => { if !matches!(read, Ok(1)) { return DnsDisposition::Terminated; } }
            result = &mut sending => return if result.is_ok() { DnsDisposition::Admitted } else { DnsDisposition::Terminated },
        }
    }
}
