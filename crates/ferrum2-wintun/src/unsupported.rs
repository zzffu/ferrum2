use std::ops::Deref;

use crate::{
    AdapterConfig, CreateError, Error, ErrorKind, ManagedTunHealth, NetworkChangeOutcome,
    SendOutcome, WaitOutcome,
};

const UNSUPPORTED: Error = Error::new(ErrorKind::UnrecoverableCorruption);

pub struct Adapter;
pub struct StopSignal;
pub struct WorkSignal;
pub struct ReceivedPacket<'a>(&'a [u8]);
#[derive(Clone)]
pub struct UnderlayPolicy;

impl Adapter {
    pub fn create(
        _: AdapterConfig,
        _: std::time::Instant,
        _: &std::sync::atomic::AtomicBool,
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
