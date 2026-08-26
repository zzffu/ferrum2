use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use ferrum2_crypto::{SystemClock, SystemRandom};
use ferrum2_runtime::{
    MAX_UDP_WIRE_DATAGRAM_BYTES, UdpBufferBudget, UdpBufferReservation, UdpRuntimeError,
};
use ferrum2_shadowsocks::{ServerResponseCapability, UdpPacketError, UdpPacketScratch, UdpServer};

pub(super) struct ResponseCodec {
    pub(super) scratch: UdpPacketScratch,
    pub(super) available_wires: Vec<ResponseWire>,
    pub(super) _scratch_reservation: UdpBufferReservation,
}

pub(super) struct ResponseWire {
    pub(super) wire: Vec<u8>,
    pub(super) _wire_reservation: UdpBufferReservation,
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
            _wire_reservation: reservation,
        })
    }
}

pub(super) struct ResponseCodecPool {
    pub(super) state: Mutex<ResponseCodec>,
    pub(super) budget: UdpBufferBudget,
    pub(super) returned: tokio::sync::Notify,
}

impl ResponseCodecPool {
    pub(super) fn new(budget: UdpBufferBudget) -> Result<Self, UdpRuntimeError> {
        let scratch_reservation = budget.reserve(MAX_UDP_WIRE_DATAGRAM_BYTES)?;
        let initial_wire = ResponseWire::reserve(&budget)?;
        Ok(Self {
            state: Mutex::new(ResponseCodec {
                scratch: UdpPacketScratch::new(),
                available_wires: vec![initial_wire],
                _scratch_reservation: scratch_reservation,
            }),
            budget,
            returned: tokio::sync::Notify::new(),
        })
    }

    pub(super) fn try_encode(
        self: &Arc<Self>,
        protocol: &UdpServer,
        capability: ServerResponseCapability,
        clock: &SystemClock,
        datagram: &ferrum2_core::Datagram,
    ) -> Result<Option<EncodedResponseWire>, ResponseEncodeError> {
        let mut codec = self
            .state
            .lock()
            .map_err(|_| ResponseEncodeError::Protocol(UdpPacketError::StateUnavailable))?;
        let mut response_wire = match codec.available_wires.pop() {
            Some(wire) => wire,
            None => match ResponseWire::reserve(&self.budget) {
                Ok(wire) => wire,
                Err(UdpRuntimeError::BufferLimit) => return Ok(None),
                Err(error) => return Err(ResponseEncodeError::Runtime(error)),
            },
        };
        let encoded = protocol.encode_response(
            capability,
            clock,
            &SystemRandom,
            datagram,
            0,
            &mut response_wire.wire,
            &mut codec.scratch,
        );
        drop(codec);
        match encoded {
            Ok(encoded) => Ok(Some(EncodedResponseWire {
                wire: ResponseWireLease {
                    pool: Arc::clone(self),
                    wire: Some(response_wire),
                },
                wire_len: encoded.wire_len(),
                peer: encoded.peer(),
            })),
            Err(error) => {
                self.release(response_wire);
                Err(ResponseEncodeError::Protocol(error))
            }
        }
    }

    pub(super) fn release(&self, response_wire: ResponseWire) {
        let mut response_wire = Some(response_wire);
        if let Ok(mut codec) = self.state.lock()
            && codec.available_wires.is_empty()
        {
            codec
                .available_wires
                .push(response_wire.take().expect("response wire is available"));
        }
        drop(response_wire);
        self.returned.notify_waiters();
    }

    pub(super) fn notify_capacity_change(&self) {
        self.returned.notify_waiters();
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
