use std::sync::Arc;

use ferrum2_config::RuntimeConfig;
use ferrum2_dns::DnsProxy;
use ferrum2_observability::Metrics;
use ferrum2_runtime::OwnerRegistry;
use ferrum2_socks5::Socks5Inbound;

#[cfg(test)]
use ferrum2_crypto::MethodSinglePskProvider;
#[cfg(test)]
use ferrum2_shadowsocks::MethodKeyAdapter;

use super::egress::{ClientEgressEngine, ClientOutboundContext};

pub(super) struct ClientRouting {
    pub(super) program: ferrum2_config::CompiledRoute,
    pub(super) outbounds: Arc<[ClientOutboundContext]>,
    pub(super) selector: ferrum2_rule::SelectorControl,
}

pub(super) struct ClientContext {
    pub(super) inbound: Socks5Inbound,
    pub(super) dashboard: Option<ferrum2_dashboard::Dashboard>,
    pub(super) recorder: Option<ferrum2_rocom::Recorder>,
    pub(super) egress: Arc<ClientEgressEngine>,
    #[cfg(test)]
    pub(super) keys: MethodKeyAdapter<MethodSinglePskProvider>,
    pub(super) runtime: RuntimeConfig,
    pub(super) public_udp_slots: Option<Arc<tokio::sync::Semaphore>>,
    pub(super) registry: OwnerRegistry,
    pub(super) metrics: Arc<Metrics>,
    pub(super) dns: Option<Arc<std::sync::OnceLock<Arc<DnsProxy>>>>,
}

impl ClientContext {
    pub(super) fn observe(
        &self,
        protocol: &'static str,
        inbound: &'static str,
        inbound_id: usize,
        source: Option<std::net::SocketAddr>,
        target: Option<&ferrum2_core::TargetAddr>,
    ) -> Option<ferrum2_dashboard::Connection> {
        self.dashboard.as_ref().map(|dashboard| {
            dashboard.begin(ferrum2_dashboard::ConnectionMetadata {
                protocol,
                inbound,
                inbound_id: Some(inbound_id),
                source: dashboard
                    .connection_details_enabled()
                    .then_some(source)
                    .flatten(),
                target: target
                    .filter(|_| dashboard.connection_details_enabled())
                    .map(|target| match target.host() {
                        ferrum2_core::TargetHostRef::Ip(ip) => {
                            ferrum2_dashboard::ConnectionTarget::Socket(std::net::SocketAddr::new(
                                ip,
                                target.port().get(),
                            ))
                        }
                        ferrum2_core::TargetHostRef::Domain(name) => {
                            ferrum2_dashboard::ConnectionTarget::Domain {
                                name: name.to_owned(),
                                port: target.port().get(),
                            }
                        }
                    }),
            })
        })
    }

    /// Observes ordinary TCP only; routing and DNS hijack remain with ingress owners.
    pub(super) async fn relay_tcp<A, B, C>(
        &self,
        application: &mut A,
        upstream: &mut B,
        source: Option<std::net::SocketAddr>,
        target: &ferrum2_core::TargetAddr,
        cancellation: C,
        observation: Option<&ferrum2_dashboard::Connection>,
    ) -> Result<ferrum2_runtime::RelayStats, ferrum2_runtime::RelayFailure>
    where
        A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        C: Future<Output = ()>,
    {
        if let Some(observation) = observation {
            use ferrum2_dashboard::{Direction, ObservedIo};
            let result = self
                .relay_recorded(
                    &mut ObservedIo::new(application, observation.clone(), Direction::Download),
                    &mut ObservedIo::new(upstream, observation.clone(), Direction::Upload),
                    source,
                    target,
                    async {
                        tokio::select! {
                            () = cancellation => {},
                            () = observation.cancelled() => {},
                        }
                    },
                )
                .await;
            observation.finish(match &result {
                Ok(_) => "completed",
                Err(failure) => match failure.kind {
                    ferrum2_runtime::RelayRunError::Io => "io",
                    ferrum2_runtime::RelayRunError::IdleTimeout => "idle_timeout",
                    ferrum2_runtime::RelayRunError::Cancelled => "cancelled",
                },
            });
            return result;
        }
        self.relay_recorded(application, upstream, source, target, cancellation)
            .await
    }

    async fn relay_recorded<A, B, C>(
        &self,
        application: &mut A,
        upstream: &mut B,
        source: Option<std::net::SocketAddr>,
        target: &ferrum2_core::TargetAddr,
        cancellation: C,
    ) -> Result<ferrum2_runtime::RelayStats, ferrum2_runtime::RelayFailure>
    where
        A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        C: Future<Output = ()>,
    {
        use ferrum2_rocom::{Direction, EndReason, ObservedIo};
        use ferrum2_runtime::{RelayRunError, relay_lifecycle};

        let Some(recorder) = &self.recorder else {
            return relay_lifecycle(
                application,
                upstream,
                self.runtime.idle_timeout,
                &self.registry,
                cancellation,
            )
            .await;
        };
        // Address rendering is confined to explicitly enabled sensitive evidence.
        let target = match target.host() {
            ferrum2_core::TargetHostRef::Ip(ip) => {
                std::net::SocketAddr::new(ip, target.port().get()).to_string()
            }
            ferrum2_core::TargetHostRef::Domain(domain) => format!("{domain}:{}", target.port()),
        };
        let capture = recorder.open(source.map(|source| source.to_string()), target);
        let result = relay_lifecycle(
            &mut ObservedIo::new(application, &capture, Direction::Upload),
            &mut ObservedIo::new(upstream, &capture, Direction::Download),
            self.runtime.idle_timeout,
            &self.registry,
            cancellation,
        )
        .await;
        capture.finish(match &result {
            Ok(_) => EndReason::Completed,
            Err(failure) => match failure.kind {
                RelayRunError::Io => EndReason::Io,
                RelayRunError::IdleTimeout => EndReason::IdleTimeout,
                RelayRunError::Cancelled => EndReason::Cancelled,
            },
        });
        result
    }
}

pub(super) async fn observation_cancelled(observation: Option<&ferrum2_dashboard::Connection>) {
    match observation {
        Some(observation) => observation.cancelled().await,
        None => std::future::pending().await,
    }
}
