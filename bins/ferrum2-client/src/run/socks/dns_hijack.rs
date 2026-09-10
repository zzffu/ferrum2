use super::admission::{CandidateRequest, SocksUdpEndpoint, admit_answer, receive_candidate};
use crate::run::context::ClientContext;
use ferrum2_dns::{DnsProxy, ProxyIngress, ProxyTransport};
use ferrum2_runtime::CancellationToken;
use ferrum2_socks5::SocksStream;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};

pub(super) enum DnsDisposition {
    Admitted,
    Dropped,
    Terminated,
}

#[derive(Clone, Copy)]
pub(super) struct DnsRoute<'a> {
    pub(super) inbound: usize,
    pub(super) proxy: &'a DnsProxy,
}

pub(super) async fn relay_hijacked_udp<IO: AsyncRead + AsyncWrite + Unpin>(
    endpoint: &mut SocksUdpEndpoint,
    control: &mut SocksStream<IO>,
    cancellation: &mut CancellationToken,
    context: &ClientContext,
    route: DnsRoute<'_>,
) {
    let mut control_byte = [0];
    let observation = endpoint.observation.clone();
    loop {
        let deadline = endpoint.idle_deadline(context.runtime.idle_timeout);
        let candidate = tokio::select! {
            _ = cancellation.cancelled() => return,
            () = crate::run::context::observation_cancelled(observation.as_ref()) => {
                if let Some(observation) = &observation { observation.finish("cancelled"); }
                return;
            },
            _ = tokio::time::sleep_until(deadline) => return,
            read = control.read(&mut control_byte) => { if !matches!(read, Ok(1)) { return; } continue; }
            received = receive_candidate(endpoint, context) => match received { Ok(Some(candidate)) => candidate, Ok(None) => continue, Err(_) => return },
        };
        if matches!(
            answer_hijacked_udp(
                endpoint,
                control,
                cancellation,
                route,
                candidate,
                context,
                None
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
    route: DnsRoute<'_>,
    candidate: CandidateRequest,
    context: &ClientContext,
    decision: Option<ferrum2_dashboard::DecisionMetadata>,
) -> DnsDisposition {
    let idle_timeout = context.runtime.idle_timeout;
    let deadline = endpoint.idle_deadline(idle_timeout);
    let observation = endpoint.observation.clone();
    let mut control_byte = [0];
    let response = {
        let answering = route.proxy.answer(
            ProxyIngress::Ordinary(route.inbound),
            ProxyTransport::Udp,
            &candidate.payload,
        );
        tokio::pin!(answering);
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return DnsDisposition::Terminated,
                () = crate::run::context::observation_cancelled(observation.as_ref()) => {
                    if let Some(observation) = &observation { observation.finish("cancelled"); }
                    return DnsDisposition::Terminated;
                },
                _ = tokio::time::sleep_until(deadline) => return DnsDisposition::Terminated,
                read = control.read(&mut control_byte) => { if !matches!(read, Ok(1)) { return DnsDisposition::Terminated; } }
                response = &mut answering => break response,
            }
        }
    };
    let Some(response) = response else {
        return DnsDisposition::Dropped;
    };
    let observed_target = if endpoint.observation.is_none() {
        context
            .dashboard
            .as_ref()
            .filter(|dashboard| dashboard.connection_details_enabled())
            .map(|_| candidate.target.clone())
    } else {
        None
    };
    let payload_len = candidate.payload.len();
    let Ok(length) = admit_answer(endpoint, candidate, &response) else {
        return DnsDisposition::Dropped;
    };
    if endpoint.observation.is_none() {
        endpoint.observation = context.observe(
            "udp",
            "socks5",
            route.inbound,
            endpoint.source_addr(),
            observed_target.as_ref(),
        );
        if let (Some(observation), Some(decision)) = (&endpoint.observation, decision) {
            observation.set_decision(decision, &[]);
        }
    }
    let observation = endpoint.observation.clone();
    if let Some(observation) = &observation {
        observation.upload(payload_len);
    }
    // Successful admission renewed endpoint activity; the response gets that
    // configured idle period rather than the pre-answer deadline.
    let deadline = endpoint.idle_deadline(idle_timeout);
    let sending = endpoint.send_encoded(length);
    tokio::pin!(sending);
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => return DnsDisposition::Terminated,
            () = crate::run::context::observation_cancelled(observation.as_ref()) => {
                if let Some(observation) = &observation { observation.finish("cancelled"); }
                return DnsDisposition::Terminated;
            },
            _ = tokio::time::sleep_until(deadline) => return DnsDisposition::Terminated,
            read = control.read(&mut control_byte) => { if !matches!(read, Ok(1)) { return DnsDisposition::Terminated; } }
            result = &mut sending => return if result.is_ok() {
                if let Some(observation) = &observation { observation.download(response.len()); }
                DnsDisposition::Admitted
            } else { DnsDisposition::Terminated },
        }
    }
}
