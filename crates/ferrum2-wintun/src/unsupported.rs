use std::ops::Deref;

use crate::{AdapterConfig, CreateError, Error};

pub struct Adapter;
pub struct StopSignal;
pub struct ReceivedPacket<'a>(&'a [u8]);

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
    pub fn receive(&mut self) -> Result<Option<ReceivedPacket<'_>>, Error> {
        Err(Error)
    }
    pub fn wait(&self, _: std::time::Duration) -> Result<bool, Error> {
        Err(Error)
    }
    pub fn send(&mut self, _: &[u8]) -> Result<(), Error> {
        Err(Error)
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

impl Deref for ReceivedPacket<'_> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.0
    }
}
