use std::ops::Deref;

use ferrum2_runtime::{
    NetworkInterfaceCatalog, NetworkInterfaceCatalogError, NetworkInterfaceObservation,
    ResolvedInterface, ResolvedSocketBinder, SystemBestRoute,
};
use socket2::Socket;

use crate::{
    AdapterConfig, CreateError, Error, ErrorKind, ManagedTunHealth, NetworkChangeOutcome,
    NetworkChangeWaitOutcome, SendOutcome, WaitOutcome,
};

const UNSUPPORTED: Error = Error::new(ErrorKind::UnrecoverableCorruption);

pub struct Adapter;
pub struct WindowsNetworkChangeMonitor;
pub struct StopSignal;
pub struct WorkSignal;
pub struct ReceivedPacket<'a>(&'a [u8]);
#[derive(Clone)]
pub struct UnderlayPolicy;

/// Fail-closed placeholder for the Windows socket binding boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsResolvedSocketBinder;

impl ResolvedSocketBinder for WindowsResolvedSocketBinder {
    type Error = Error;

    fn bind_resolved_socket(
        &self,
        _: &Socket,
        _: std::net::SocketAddr,
        _: &ResolvedInterface,
    ) -> Result<(), Self::Error> {
        Err(UNSUPPORTED)
    }
}

/// Fail-closed placeholder for the Windows read-only network catalog.
#[derive(Clone, Copy, Default)]
pub struct WindowsNetworkInterfaceCatalog {
    managed_tun: Option<(u64, u32)>,
}

impl WindowsNetworkInterfaceCatalog {
    /// Builds a catalog without a managed TUN identity.
    pub const fn system() -> Self {
        Self { managed_tun: None }
    }

    /// Builds a catalog that classifies one exact managed TUN identity.
    pub fn excluding_managed_tun(stable_id: u64, index: u32) -> Result<Self, Error> {
        if stable_id == 0 || index == 0 {
            return Err(Error::invalid_input());
        }
        Ok(Self {
            managed_tun: Some((stable_id, index)),
        })
    }
}

impl std::fmt::Debug for WindowsNetworkInterfaceCatalog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WindowsNetworkInterfaceCatalog")
            .field("managed_tun", &self.managed_tun.is_some())
            .finish()
    }
}

impl NetworkInterfaceCatalog for WindowsNetworkInterfaceCatalog {
    fn read_interfaces(
        &self,
    ) -> Result<Vec<NetworkInterfaceObservation>, NetworkInterfaceCatalogError> {
        Err(NetworkInterfaceCatalogError)
    }

    fn system_best_route(
        &self,
        _: std::net::SocketAddr,
    ) -> Result<SystemBestRoute, NetworkInterfaceCatalogError> {
        Err(NetworkInterfaceCatalogError)
    }
}

impl Adapter {
    pub fn create(
        _: AdapterConfig,
        _: std::time::Instant,
        _: &std::sync::atomic::AtomicBool,
        _: WindowsNetworkInterfaceCatalog,
    ) -> Result<Self, CreateError> {
        Err(CreateError::operation())
    }
    pub fn stop_signal(&self) -> StopSignal {
        StopSignal
    }
    pub fn work_signal(&self) -> WorkSignal {
        WorkSignal
    }
    pub fn underlay_policy(&self) -> Option<UnderlayPolicy> {
        None
    }
    pub fn network_interface_catalog(&self) -> WindowsNetworkInterfaceCatalog {
        WindowsNetworkInterfaceCatalog::system()
    }
    pub fn refresh_underlay(&mut self) -> Result<Option<UnderlayPolicy>, Error> {
        Err(UNSUPPORTED)
    }
    pub fn managed_health(&self) -> Result<ManagedTunHealth, Error> {
        Err(UNSUPPORTED)
    }
    pub fn revalidate_network_change(&mut self) -> Result<NetworkChangeOutcome, Error> {
        Err(UNSUPPORTED)
    }
    pub fn receive(&mut self) -> Result<Option<ReceivedPacket<'_>>, Error> {
        Err(UNSUPPORTED)
    }
    pub fn wait(&mut self, _: std::time::Duration) -> Result<WaitOutcome, Error> {
        Err(UNSUPPORTED)
    }
    pub fn send(&mut self, _: &[u8]) -> Result<SendOutcome, Error> {
        Err(UNSUPPORTED)
    }
    pub fn cleanup(self) -> Result<(), Error> {
        Ok(())
    }
}

impl WindowsNetworkChangeMonitor {
    pub fn new() -> Result<Self, Error> {
        Err(UNSUPPORTED)
    }

    pub fn wait(&mut self, _: std::time::Duration) -> Result<NetworkChangeWaitOutcome, Error> {
        Err(UNSUPPORTED)
    }

    pub fn stop_signal(&self) -> StopSignal {
        StopSignal
    }

    pub fn close(self) -> Result<(), Error> {
        Err(UNSUPPORTED)
    }
}

impl StopSignal {
    pub fn signal(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl Clone for StopSignal {
    fn clone(&self) -> Self {
        Self
    }
}

impl WorkSignal {
    pub fn signal(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl Clone for WorkSignal {
    fn clone(&self) -> Self {
        Self
    }
}

impl UnderlayPolicy {
    pub fn generation_is_current(&self) -> bool {
        false
    }
}

impl Deref for ReceivedPacket<'_> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.0
    }
}
