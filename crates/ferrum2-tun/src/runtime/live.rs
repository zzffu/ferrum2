use std::sync::Arc;

use ferrum2_net::NetworkSnapshot;
use ferrum2_runtime::OwnerRegistry;

use super::{NetworkResetBridgeOutcome, NetworkResetRequest, SessionItem};
use crate::{OwnerWake, TcpFlow, TunEventSink, UdpCandidate, UnderlayPublisher};

pub(crate) const OWNER_WORK_BUDGET: usize = 64;

pub(crate) enum OwnerReady {
    Ready {
        work: OwnerWake,
        snapshot: Arc<NetworkSnapshot>,
        initialization: std::sync::mpsc::SyncSender<NetworkResetBridgeOutcome>,
    },
    Failed,
}

pub(crate) struct OwnerSessionServices {
    pub(crate) ready: std::sync::mpsc::SyncSender<OwnerReady>,
    pub(crate) registry: OwnerRegistry,
    pub(crate) network_catalog: ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
    pub(crate) events: TunEventSink,
    pub(crate) underlay: UnderlayPublisher,
    pub(crate) flow_output: tokio::sync::mpsc::Sender<SessionItem<TcpFlow>>,
    pub(crate) datagram_output: tokio::sync::mpsc::Sender<SessionItem<UdpCandidate>>,
    pub(crate) network_lifecycle_output: tokio::sync::mpsc::Sender<NetworkResetRequest>,
    pub(crate) max_udp_associations: usize,
}
