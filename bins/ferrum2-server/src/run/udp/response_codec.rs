use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use ferrum2_crypto::{Clock, SecureRandom};
use ferrum2_runtime::{
    MAX_UDP_WIRE_DATAGRAM_BYTES, UdpBufferBudget, UdpBufferReservation, UdpRuntimeError,
};
use ferrum2_shadowsocks::{ServerResponseCapability, UdpPacketError, UdpPacketScratch, UdpServer};

const MAX_CACHED_RESPONSE_RESOURCES: usize = 4;

struct ResponseCodec {
    available_scratch: Vec<ResponseScratch>,
    available_wires: Vec<ResponseWire>,
}

struct ResponseScratch {
    scratch: UdpPacketScratch,
    _reservation: UdpBufferReservation,
}

impl ResponseScratch {
    fn reserve(budget: &UdpBufferBudget) -> Result<Self, UdpRuntimeError> {
        let reservation = budget.reserve(MAX_UDP_WIRE_DATAGRAM_BYTES)?;
        Ok(Self {
            scratch: UdpPacketScratch::new(),
            _reservation: reservation,
        })
    }
}

pub(super) struct ResponseWire {
    pub(super) wire: Vec<u8>,
    _reservation: UdpBufferReservation,
}

impl ResponseWire {
    pub(super) fn reserve(budget: &UdpBufferBudget) -> Result<Self, UdpRuntimeError> {
        let reservation = budget.reserve(MAX_UDP_WIRE_DATAGRAM_BYTES)?;
        let wire = vec![0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
        if wire.capacity() != reservation.capacity() {
            return Err(UdpRuntimeError::Bounds);
        }
        Ok(Self {
            wire,
            _reservation: reservation,
        })
    }
}

pub(super) struct ResponseCodecPool {
    state: Mutex<ResponseCodec>,
    pub(super) budget: UdpBufferBudget,
    pub(super) returned: tokio::sync::Notify,
}

impl ResponseCodecPool {
    pub(super) fn new(budget: UdpBufferBudget) -> Result<Self, UdpRuntimeError> {
        let initial_scratch = ResponseScratch::reserve(&budget)?;
        let initial_wire = ResponseWire::reserve(&budget)?;
        Ok(Self {
            state: Mutex::new(ResponseCodec {
                available_scratch: vec![initial_scratch],
                available_wires: vec![initial_wire],
            }),
            budget,
            returned: tokio::sync::Notify::new(),
        })
    }

    pub(super) fn try_encode(
        self: &Arc<Self>,
        protocol: &UdpServer,
        capability: ServerResponseCapability,
        clock: &(impl Clock + ?Sized),
        random: &(impl SecureRandom + ?Sized),
        datagram: &ferrum2_core::Datagram,
    ) -> Result<Option<EncodedResponseWire>, ResponseEncodeError> {
        let Some(mut lease) = self.try_lease()? else {
            return Ok(None);
        };
        let encoded = {
            let (response_wire, scratch) = lease.encode_buffers();
            protocol.encode_response(
                capability,
                clock,
                random,
                datagram,
                0,
                response_wire,
                scratch,
            )
        };
        match encoded {
            Ok(encoded) => {
                let response_wire = lease.wire.take().expect("response wire lease is live");
                drop(lease);
                Ok(Some(EncodedResponseWire {
                    wire: ResponseWireLease {
                        pool: Arc::clone(self),
                        wire: Some(response_wire),
                    },
                    wire_len: encoded.wire_len(),
                    peer: encoded.peer(),
                }))
            }
            Err(error) => Err(ResponseEncodeError::Protocol(error)),
        }
    }

    fn try_lease(&self) -> Result<Option<ResponseEncodeLease<'_>>, ResponseEncodeError> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.available_scratch.clear();
                state.available_wires.clear();
                drop(state);
                self.returned.notify_waiters();
                return Err(ResponseEncodeError::Protocol(
                    UdpPacketError::StateUnavailable,
                ));
            }
        };
        let scratch = match state.available_scratch.pop() {
            Some(scratch) => scratch,
            None => match ResponseScratch::reserve(&self.budget) {
                Ok(scratch) => scratch,
                Err(UdpRuntimeError::BufferLimit) => return Ok(None),
                Err(error) => return Err(ResponseEncodeError::Runtime(error)),
            },
        };
        let wire = match state.available_wires.pop() {
            Some(wire) => wire,
            None => match ResponseWire::reserve(&self.budget) {
                Ok(wire) => wire,
                Err(UdpRuntimeError::BufferLimit) => {
                    state.available_scratch.push(scratch);
                    return Ok(None);
                }
                Err(error) => {
                    state.available_scratch.push(scratch);
                    return Err(ResponseEncodeError::Runtime(error));
                }
            },
        };
        drop(state);
        Ok(Some(ResponseEncodeLease {
            pool: self,
            scratch: Some(scratch),
            wire: Some(wire),
        }))
    }

    fn release_resources(
        &self,
        mut scratch: Option<ResponseScratch>,
        mut response_wire: Option<ResponseWire>,
    ) {
        match self.state.lock() {
            Ok(mut state) => {
                if state.available_scratch.len() < MAX_CACHED_RESPONSE_RESOURCES
                    && let Some(scratch) = scratch.take()
                {
                    state.available_scratch.push(scratch);
                }
                if state.available_wires.len() < MAX_CACHED_RESPONSE_RESOURCES
                    && let Some(response_wire) = response_wire.take()
                {
                    state.available_wires.push(response_wire);
                }
            }
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.available_scratch.clear();
                state.available_wires.clear();
            }
        }
        drop(scratch);
        drop(response_wire);
        self.returned.notify_waiters();
    }

    pub(super) fn release(&self, response_wire: ResponseWire) {
        self.release_resources(None, Some(response_wire));
    }

    pub(super) fn notify_capacity_change(&self) {
        self.returned.notify_waiters();
    }
}

struct ResponseEncodeLease<'a> {
    pool: &'a ResponseCodecPool,
    scratch: Option<ResponseScratch>,
    wire: Option<ResponseWire>,
}

impl ResponseEncodeLease<'_> {
    fn encode_buffers(&mut self) -> (&mut [u8], &mut UdpPacketScratch) {
        let wire = &mut self
            .wire
            .as_mut()
            .expect("response wire lease is live")
            .wire;
        let scratch = &mut self
            .scratch
            .as_mut()
            .expect("response scratch lease is live")
            .scratch;
        (wire, scratch)
    }
}

impl Drop for ResponseEncodeLease<'_> {
    fn drop(&mut self) {
        self.pool
            .release_resources(self.scratch.take(), self.wire.take());
    }
}

pub(super) struct ResponseWireLease {
    pub(super) pool: Arc<ResponseCodecPool>,
    pub(super) wire: Option<ResponseWire>,
}

impl ResponseWireLease {
    pub(super) fn wire(&self, wire_len: usize) -> &[u8] {
        &self
            .wire
            .as_ref()
            .expect("response wire lease is live")
            .wire[..wire_len]
    }
}

impl Drop for ResponseWireLease {
    fn drop(&mut self) {
        if let Some(wire) = self.wire.take() {
            self.pool.release(wire);
        }
    }
}

pub(super) struct EncodedResponseWire {
    pub(super) wire: ResponseWireLease,
    pub(super) wire_len: usize,
    pub(super) peer: SocketAddr,
}

pub(super) enum ResponseEncodeError {
    Protocol(UdpPacketError),
    Runtime(UdpRuntimeError),
}
