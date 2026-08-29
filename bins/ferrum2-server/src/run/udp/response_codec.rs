use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ferrum2_crypto::{SystemClock, SystemRandom};
use ferrum2_runtime::{
    MAX_UDP_WIRE_DATAGRAM_BYTES, UdpBufferBudget, UdpBufferReservation, UdpRuntimeError,
};
use ferrum2_shadowsocks::{ServerResponseCapability, UdpPacketError, UdpServer};
#[cfg(feature = "structural-metrics")]
use ferrum2_structural::{LockSite, StructuralLocal};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

pub(super) const MAX_RESPONSE_CODEC_SHARDS: usize = 4;
const RESPONSE_WIRES_PER_SHARD: usize = 2;

struct ResponseCodec {
    available_wires: Vec<ResponseWire>,
}

struct CodecShard {
    state: Mutex<ResponseCodec>,
    available: Arc<Semaphore>,
}

pub(super) struct ResponseWire {
    pub(super) wire: Vec<u8>,
    pub(super) _wire_reservation: UdpBufferReservation,
}

impl ResponseWire {
    fn reserve(budget: &UdpBufferBudget) -> Result<Self, UdpRuntimeError> {
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
    shards: Box<[CodecShard]>,
    immediate_leases: AtomicU64,
    waited_leases: AtomicU64,
    wait_nanoseconds: AtomicU64,
}

impl ResponseCodecPool {
    pub(super) fn new(
        budget: UdpBufferBudget,
        maximum_sessions: usize,
    ) -> Result<Self, UdpRuntimeError> {
        let shard_count = response_codec_shards(maximum_sessions);
        let mut shards = Vec::new();
        shards
            .try_reserve_exact(shard_count)
            .map_err(|_| UdpRuntimeError::BufferLimit)?;
        for _ in 0..shard_count {
            let mut available_wires = Vec::new();
            available_wires
                .try_reserve_exact(RESPONSE_WIRES_PER_SHARD)
                .map_err(|_| UdpRuntimeError::BufferLimit)?;
            for _ in 0..RESPONSE_WIRES_PER_SHARD {
                available_wires.push(ResponseWire::reserve(&budget)?);
            }
            shards.push(CodecShard {
                state: Mutex::new(ResponseCodec { available_wires }),
                available: Arc::new(Semaphore::new(RESPONSE_WIRES_PER_SHARD)),
            });
        }
        Ok(Self {
            shards: shards.into_boxed_slice(),
            immediate_leases: AtomicU64::new(0),
            waited_leases: AtomicU64::new(0),
            wait_nanoseconds: AtomicU64::new(0),
        })
    }

    #[cfg(any(not(feature = "structural-metrics"), test))]
    pub(super) async fn encode(
        self: &Arc<Self>,
        protocol: &UdpServer,
        capability: ServerResponseCapability,
        clock: &SystemClock,
        datagram: &ferrum2_core::Datagram,
    ) -> Result<EncodedResponseWire, ResponseEncodeError> {
        self.encode_inner(
            protocol,
            capability,
            clock,
            datagram,
            #[cfg(feature = "structural-metrics")]
            None,
        )
        .await
    }

    #[cfg(feature = "structural-metrics")]
    pub(super) async fn encode_structural(
        self: &Arc<Self>,
        protocol: &UdpServer,
        capability: ServerResponseCapability,
        clock: &SystemClock,
        datagram: &ferrum2_core::Datagram,
        structural: &StructuralLocal,
    ) -> Result<EncodedResponseWire, ResponseEncodeError> {
        self.encode_inner(protocol, capability, clock, datagram, Some(structural))
            .await
    }

    async fn encode_inner(
        self: &Arc<Self>,
        protocol: &UdpServer,
        capability: ServerResponseCapability,
        clock: &SystemClock,
        datagram: &ferrum2_core::Datagram,
        #[cfg(feature = "structural-metrics")] structural: Option<&StructuralLocal>,
    ) -> Result<EncodedResponseWire, ResponseEncodeError> {
        let shard_index = self.shard_index(capability);
        let shard = &self.shards[shard_index];
        let permit = match Arc::clone(&shard.available).try_acquire_owned() {
            Ok(permit) => {
                self.immediate_leases.fetch_add(1, Ordering::Relaxed);
                permit
            }
            Err(TryAcquireError::NoPermits) => {
                self.waited_leases.fetch_add(1, Ordering::Relaxed);
                let started = Instant::now();
                let permit = Arc::clone(&shard.available)
                    .acquire_owned()
                    .await
                    .map_err(|_| ResponseEncodeError::Runtime(UdpRuntimeError::Cancelled))?;
                let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
                self.wait_nanoseconds.fetch_add(elapsed, Ordering::Relaxed);
                permit
            }
            Err(TryAcquireError::Closed) => {
                return Err(ResponseEncodeError::Runtime(UdpRuntimeError::Cancelled));
            }
        };
        let mut response_wire = {
            #[cfg(feature = "structural-metrics")]
            let lock_started = structural.map(|_| Instant::now());
            let mut codec = shard
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            #[cfg(feature = "structural-metrics")]
            let lock_wait = lock_started.map(|started| started.elapsed());
            #[cfg(feature = "structural-metrics")]
            let hold_started = structural.map(|_| Instant::now());
            let response_wire = codec
                .available_wires
                .pop()
                .expect("response wire permit owns one fixed wire");
            drop(codec);
            #[cfg(feature = "structural-metrics")]
            if let Some(structural) = structural {
                structural.lock(
                    LockSite::ResponseCodec,
                    duration_nanoseconds(lock_wait.unwrap_or_default()),
                    duration_nanoseconds(
                        hold_started
                            .expect("instrumented codec hold has a start")
                            .elapsed(),
                    ),
                );
            }
            response_wire
        };
        #[cfg(feature = "structural-metrics")]
        let encoded = if let Some(structural) = structural {
            protocol.encode_response_structural(
                capability,
                clock,
                &SystemRandom,
                datagram,
                0,
                &mut response_wire.wire,
                structural,
            )
        } else {
            protocol.encode_response(
                capability,
                clock,
                &SystemRandom,
                datagram,
                0,
                &mut response_wire.wire,
            )
        };
        #[cfg(not(feature = "structural-metrics"))]
        let encoded = protocol.encode_response(
            capability,
            clock,
            &SystemRandom,
            datagram,
            0,
            &mut response_wire.wire,
        );
        match encoded {
            Ok(encoded) => Ok(EncodedResponseWire {
                wire: ResponseWireLease {
                    pool: Arc::clone(self),
                    shard_index,
                    wire: Some(response_wire),
                    permit: Some(permit),
                    #[cfg(feature = "structural-metrics")]
                    structural: structural.cloned(),
                },
                wire_len: encoded.wire_len(),
                peer: encoded.peer(),
            }),
            Err(error) => {
                self.release(
                    shard_index,
                    response_wire,
                    #[cfg(feature = "structural-metrics")]
                    structural,
                );
                drop(permit);
                Err(ResponseEncodeError::Protocol(error))
            }
        }
    }

    fn shard_index(&self, capability: ServerResponseCapability) -> usize {
        let mut hasher = DefaultHasher::new();
        capability.hash(&mut hasher);
        hasher.finish() as usize & (self.shards.len() - 1)
    }

    fn release(
        &self,
        shard_index: usize,
        response_wire: ResponseWire,
        #[cfg(feature = "structural-metrics")] structural: Option<&StructuralLocal>,
    ) {
        #[cfg(feature = "structural-metrics")]
        let lock_started = structural.map(|_| Instant::now());
        let mut codec = self.shards[shard_index]
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(feature = "structural-metrics")]
        let lock_wait = lock_started.map(|started| started.elapsed());
        #[cfg(feature = "structural-metrics")]
        let hold_started = structural.map(|_| Instant::now());
        codec.available_wires.push(response_wire);
        drop(codec);
        #[cfg(feature = "structural-metrics")]
        if let Some(structural) = structural {
            structural.lock(
                LockSite::ResponseCodec,
                duration_nanoseconds(lock_wait.unwrap_or_default()),
                duration_nanoseconds(
                    hold_started
                        .expect("instrumented codec release has a hold start")
                        .elapsed(),
                ),
            );
        }
    }

    #[cfg(test)]
    pub(super) fn observations(&self) -> (u64, u64, u64) {
        (
            self.immediate_leases.load(Ordering::Relaxed),
            self.waited_leases.load(Ordering::Relaxed),
            self.wait_nanoseconds.load(Ordering::Relaxed),
        )
    }

    #[cfg(test)]
    pub(super) fn shard_count(&self) -> usize {
        self.shards.len()
    }

    #[cfg(test)]
    pub(super) fn available_wire_count(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                shard
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .available_wires
                    .len()
            })
            .sum()
    }
}

#[cfg(feature = "structural-metrics")]
fn duration_nanoseconds(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

pub(super) fn response_codec_shards(maximum_sessions: usize) -> usize {
    let parallelism = std::thread::available_parallelism().map_or(1, usize::from);
    let target = maximum_sessions
        .max(1)
        .min(parallelism)
        .min(MAX_RESPONSE_CODEC_SHARDS);
    1_usize << target.ilog2()
}

pub(super) fn maximum_response_codec_reservation_bytes(maximum_sessions: usize) -> Option<usize> {
    let target = maximum_sessions.clamp(1, MAX_RESPONSE_CODEC_SHARDS);
    let maximum_shards = 1_usize << target.ilog2();
    maximum_shards
        .checked_mul(RESPONSE_WIRES_PER_SHARD)
        .and_then(|wires| wires.checked_mul(MAX_UDP_WIRE_DATAGRAM_BYTES))
}

pub(super) struct ResponseWireLease {
    pub(super) pool: Arc<ResponseCodecPool>,
    pub(super) shard_index: usize,
    pub(super) wire: Option<ResponseWire>,
    pub(super) permit: Option<OwnedSemaphorePermit>,
    #[cfg(feature = "structural-metrics")]
    pub(super) structural: Option<StructuralLocal>,
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
            self.pool.release(
                self.shard_index,
                wire,
                #[cfg(feature = "structural-metrics")]
                self.structural.as_ref(),
            );
        }
        drop(self.permit.take());
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
