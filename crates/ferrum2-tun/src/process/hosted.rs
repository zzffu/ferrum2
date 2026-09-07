use ferrum2_runtime::{PreparedProcessRoot, ProcessCancellation, ProcessFuture, ProcessRoot};

use super::TunRootRequest;

pub(super) fn build<E>(spec: TunRootRequest<E>) -> ProcessRoot<E>
where
    E: Copy + Send + 'static,
{
    let startup = spec.startup;
    drop(spec);
    ProcessRoot::new(move || async move { Err::<UnsupportedTargetRoot, _>(startup) })
}

struct UnsupportedTargetRoot;

impl<E> PreparedProcessRoot<E> for UnsupportedTargetRoot
where
    E: Send + 'static,
{
    fn activate(&mut self) -> Result<(), E> {
        unreachable!("unsupported TUN target cannot prepare")
    }

    fn run(self: Box<Self>, _cancellation: ProcessCancellation) -> ProcessFuture<Result<(), E>> {
        unreachable!("unsupported TUN target cannot run")
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), E>> {
        unreachable!("unsupported TUN target cannot roll back")
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ferrum2_runtime::{OwnerRegistry, ProcessCause, ProcessSupervisor};

    use crate::{
        Config, SessionCancellation, TcpFlow, TunRootRequest, UdpCandidate, UdpFiltering,
        UnderlayPublisher, process_root,
    };

    #[tokio::test]
    async fn library_test_root_fails_during_preparation() {
        let registry = OwnerRegistry::new();
        let root = process_root(TunRootRequest {
            config: Config {
                adapter_name: "unsupported".into(),
                ipv4: None,
                ipv6: None,
                mtu: 1_500,
                ring_capacity: 1 << 20,
                ready_timeout: Duration::from_secs(1),
                max_tcp_flows: 1,
                tcp_timeout: Duration::from_secs(1),
                udp_timeout: Duration::from_secs(1),
                max_udp_mappings: 1,
                udp_filtering: UdpFiltering::EndpointIndependent,
                capture_routes: Vec::new(),
                physical_endpoints: Vec::new(),
                default_binder: false,
                ipv4_dns_address: None,
                ipv6_dns_address: None,
                strict_route: false,
            },
            initial_network_generation: 0,
            underlay: UnderlayPublisher::new(),
            network_catalog: ferrum2_platform_windows::WindowsNetworkInterfaceCatalog::system(),
            startup: "startup",
            runtime: "runtime",
            cleanup: "cleanup",
            registry: registry.clone(),
            udp_buffer_budget: ferrum2_runtime::UdpBufferBudget::new_tun(1 << 20, registry.clone()),
            handle_tcp: std::sync::Arc::new(|_: TcpFlow, _: _, _: SessionCancellation| {
                Box::pin(async {})
            }),
            handle_udp: std::sync::Arc::new(|_: UdpCandidate, _: _, _: SessionCancellation| {
                Box::pin(async {})
            }),
            handle_network_lifecycle: std::sync::Arc::new(|_, _| Box::pin(async { Ok(()) })),
            events: std::sync::Arc::new(|_| {}),
        });
        let supervisor = ProcessSupervisor::new(vec![root], Duration::from_secs(1), registry)
            .expect("one unsupported TUN root");

        let report = supervisor.run_until(std::future::pending::<()>()).await;

        match report.cause() {
            ProcessCause::PreparationFailed { root, error } => {
                assert_eq!(root.get(), 0);
                assert_eq!(*error, "startup");
            }
            other => panic!("library-test TUN root did not fail closed: {other:?}"),
        }
    }
}
