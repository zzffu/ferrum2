use ferrum2_runtime::OwnerRegistry;

use super::{LifecycleLink, SessionItem};
use crate::{TcpFlow, TunEventSink, UdpCandidate, UnderlayPublisher};

pub(crate) const OWNER_WORK_BUDGET: usize = 64;

pub(crate) struct OwnerSessionServices {
    pub(crate) registry: OwnerRegistry,
    pub(crate) udp_buffer_budget: ferrum2_runtime::UdpBufferBudget,
    pub(crate) runtime: tokio::runtime::Handle,
    pub(crate) network_catalog: ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
    pub(crate) events: TunEventSink,
    pub(crate) underlay: UnderlayPublisher,
    pub(crate) flow_output: tokio::sync::mpsc::Sender<SessionItem<TcpFlow>>,
    pub(crate) datagram_output: tokio::sync::mpsc::Sender<SessionItem<UdpCandidate>>,
    pub(crate) network_lifecycle_output: LifecycleLink,
    pub(crate) max_udp_associations: usize,
}
