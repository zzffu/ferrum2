//! Feature-gated structural performance counters.
//!
//! This crate deliberately has no dependencies and no global recorder. A
//! composition root creates a [`StructuralHub`], gives each worker or flow a
//! [`StructuralLocal`], and takes a [`StructuralSnapshot`] at an evidence
//! boundary. Every dimension is represented by a closed enum; addresses,
//! session identities, peers, and arbitrary labels cannot enter the schema.
//!
//! Counters use the units declared by [`StructuralCounter::unit`]. Updates are
//! relaxed, saturating, and distributed over a fixed set of cache-line-aligned
//! shards. A snapshot reads and exactly aggregates every shard. It is exact
//! once producers are quiescent; while producers are active it is a
//! non-transactional observation of the relaxed counters.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// The fixed number of preallocated counter shards in every hub.
pub const STRUCTURAL_SHARD_COUNT: usize = 64;

/// The unit carried by a structural counter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StructuralUnit {
    /// A dimensionless event or object count.
    Count,
    /// A byte count.
    Bytes,
    /// A duration expressed in nanoseconds.
    Nanoseconds,
}

/// A closed, identity-free structural counter schema.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum StructuralCounter {
    TcpDecryptPrepareCopyBytes,
    TcpFrameEncodeCopyBytes,
    TcpPlainToEncryptCopyBytes,
    TcpDecryptToPlainCopyBytes,
    UdpPayloadToWireCopyBytes,
    SocksUdpCopyBytes,
    DnsUdpCopyBytes,
    TcpZeroizedBytes,
    UdpRequestWireResizeBytes,
    UdpRequestWireZeroBytes,
    TcpReadSelfWakeups,
    TcpPollBudgetExhaustions,
    RelayActivityWakeups,
    UdpAesBodyCipherConstructions,
    ReplayClearedWords,
    ReplayClearedBits,
    SocksUdpAllocations,
    DnsUdpAllocations,
    UdpOwnedFastPathHits,
    FtbrFastPathConnections,
    FtbrFallbackDirectConnections,
    FtbrFallbackMultiHopConnections,
    FtbrFallbackTunConnections,
    FtbrFallbackDnsConnections,
    FtbrFallbackRuleSetConnections,
    FtbrFallbackServerNonDirectConnections,
    FtbrFallbackUnsupportedFlowConnections,
    FtbrOwnedUploadFrames,
    FtbrBorrowedDownloadFrames,
    FtbrPartialWrites,
    FtbrFrames,
    FtbrEncryptBufferCapacityBytes,
    FtbrDecryptBufferCapacityBytes,
    FtbrRelayBufferCapacityRemovedBytes,
    AdmissionLockWaitNanoseconds,
    AdmissionLockHoldNanoseconds,
    AdmissionLockSamples,
    UdpServerLockWaitNanoseconds,
    UdpServerLockHoldNanoseconds,
    UdpServerLockSamples,
    UdpMappingsLockWaitNanoseconds,
    UdpMappingsLockHoldNanoseconds,
    UdpMappingsLockSamples,
    SessionShardLockWaitNanoseconds,
    SessionShardLockHoldNanoseconds,
    SessionShardLockSamples,
    ResponseCodecLockWaitNanoseconds,
    ResponseCodecLockHoldNanoseconds,
    ResponseCodecLockSamples,
}

impl StructuralCounter {
    /// Every counter in stable schema order.
    pub const ALL: &'static [Self] = &[
        Self::TcpDecryptPrepareCopyBytes,
        Self::TcpFrameEncodeCopyBytes,
        Self::TcpPlainToEncryptCopyBytes,
        Self::TcpDecryptToPlainCopyBytes,
        Self::UdpPayloadToWireCopyBytes,
        Self::SocksUdpCopyBytes,
        Self::DnsUdpCopyBytes,
        Self::TcpZeroizedBytes,
        Self::UdpRequestWireResizeBytes,
        Self::UdpRequestWireZeroBytes,
        Self::TcpReadSelfWakeups,
        Self::TcpPollBudgetExhaustions,
        Self::RelayActivityWakeups,
        Self::UdpAesBodyCipherConstructions,
        Self::ReplayClearedWords,
        Self::ReplayClearedBits,
        Self::SocksUdpAllocations,
        Self::DnsUdpAllocations,
        Self::UdpOwnedFastPathHits,
        Self::FtbrFastPathConnections,
        Self::FtbrFallbackDirectConnections,
        Self::FtbrFallbackMultiHopConnections,
        Self::FtbrFallbackTunConnections,
        Self::FtbrFallbackDnsConnections,
        Self::FtbrFallbackRuleSetConnections,
        Self::FtbrFallbackServerNonDirectConnections,
        Self::FtbrFallbackUnsupportedFlowConnections,
        Self::FtbrOwnedUploadFrames,
        Self::FtbrBorrowedDownloadFrames,
        Self::FtbrPartialWrites,
        Self::FtbrFrames,
        Self::FtbrEncryptBufferCapacityBytes,
        Self::FtbrDecryptBufferCapacityBytes,
        Self::FtbrRelayBufferCapacityRemovedBytes,
        Self::AdmissionLockWaitNanoseconds,
        Self::AdmissionLockHoldNanoseconds,
        Self::AdmissionLockSamples,
        Self::UdpServerLockWaitNanoseconds,
        Self::UdpServerLockHoldNanoseconds,
        Self::UdpServerLockSamples,
        Self::UdpMappingsLockWaitNanoseconds,
        Self::UdpMappingsLockHoldNanoseconds,
        Self::UdpMappingsLockSamples,
        Self::SessionShardLockWaitNanoseconds,
        Self::SessionShardLockHoldNanoseconds,
        Self::SessionShardLockSamples,
        Self::ResponseCodecLockWaitNanoseconds,
        Self::ResponseCodecLockHoldNanoseconds,
        Self::ResponseCodecLockSamples,
    ];

    /// Number of counters in the closed schema.
    pub const COUNT: usize = Self::ALL.len();

    /// The counter's stable evidence name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::TcpDecryptPrepareCopyBytes => "tcp_decrypt_prepare_copy_bytes",
            Self::TcpFrameEncodeCopyBytes => "tcp_frame_encode_copy_bytes",
            Self::TcpPlainToEncryptCopyBytes => "tcp_plain_to_encrypt_copy_bytes",
            Self::TcpDecryptToPlainCopyBytes => "tcp_decrypt_to_plain_copy_bytes",
            Self::UdpPayloadToWireCopyBytes => "udp_payload_to_wire_copy_bytes",
            Self::SocksUdpCopyBytes => "socks_udp_copy_bytes",
            Self::DnsUdpCopyBytes => "dns_udp_copy_bytes",
            Self::TcpZeroizedBytes => "tcp_zeroized_bytes",
            Self::UdpRequestWireResizeBytes => "udp_request_wire_resize_bytes",
            Self::UdpRequestWireZeroBytes => "udp_request_wire_zero_bytes",
            Self::TcpReadSelfWakeups => "tcp_read_self_wakeups",
            Self::TcpPollBudgetExhaustions => "tcp_poll_budget_exhaustions",
            Self::RelayActivityWakeups => "relay_activity_wakeups",
            Self::UdpAesBodyCipherConstructions => "udp_aes_body_cipher_constructions",
            Self::ReplayClearedWords => "replay_cleared_words",
            Self::ReplayClearedBits => "replay_cleared_bits",
            Self::SocksUdpAllocations => "socks_udp_allocations",
            Self::DnsUdpAllocations => "dns_udp_allocations",
            Self::UdpOwnedFastPathHits => "udp_owned_fast_path_hits",
            Self::FtbrFastPathConnections => "tcp_fused_fast_path_connections",
            Self::FtbrFallbackDirectConnections => "tcp_fused_fallback_direct_connections",
            Self::FtbrFallbackMultiHopConnections => "tcp_fused_fallback_multi_hop_connections",
            Self::FtbrFallbackTunConnections => "tcp_fused_fallback_tun_connections",
            Self::FtbrFallbackDnsConnections => "tcp_fused_fallback_dns_connections",
            Self::FtbrFallbackRuleSetConnections => "tcp_fused_fallback_rule_set_connections",
            Self::FtbrFallbackServerNonDirectConnections => {
                "tcp_fused_fallback_server_non_direct_connections"
            }
            Self::FtbrFallbackUnsupportedFlowConnections => {
                "tcp_fused_fallback_unsupported_flow_connections"
            }
            Self::FtbrOwnedUploadFrames => "tcp_fused_owned_upload_frames",
            Self::FtbrBorrowedDownloadFrames => "tcp_fused_borrowed_download_frames",
            Self::FtbrPartialWrites => "tcp_fused_partial_writes",
            Self::FtbrFrames => "tcp_fused_frames",
            Self::FtbrEncryptBufferCapacityBytes => "tcp_fused_encrypt_buffer_capacity_bytes",
            Self::FtbrDecryptBufferCapacityBytes => "tcp_fused_decrypt_buffer_capacity_bytes",
            Self::FtbrRelayBufferCapacityRemovedBytes => {
                "tcp_fused_relay_buffer_capacity_removed_bytes"
            }
            Self::AdmissionLockWaitNanoseconds => "admission_lock_wait_nanoseconds",
            Self::AdmissionLockHoldNanoseconds => "admission_lock_hold_nanoseconds",
            Self::AdmissionLockSamples => "admission_lock_samples",
            Self::UdpServerLockWaitNanoseconds => "udp_server_lock_wait_nanoseconds",
            Self::UdpServerLockHoldNanoseconds => "udp_server_lock_hold_nanoseconds",
            Self::UdpServerLockSamples => "udp_server_lock_samples",
            Self::UdpMappingsLockWaitNanoseconds => "udp_mappings_lock_wait_nanoseconds",
            Self::UdpMappingsLockHoldNanoseconds => "udp_mappings_lock_hold_nanoseconds",
            Self::UdpMappingsLockSamples => "udp_mappings_lock_samples",
            Self::SessionShardLockWaitNanoseconds => "session_shard_lock_wait_nanoseconds",
            Self::SessionShardLockHoldNanoseconds => "session_shard_lock_hold_nanoseconds",
            Self::SessionShardLockSamples => "session_shard_lock_samples",
            Self::ResponseCodecLockWaitNanoseconds => "response_codec_lock_wait_nanoseconds",
            Self::ResponseCodecLockHoldNanoseconds => "response_codec_lock_hold_nanoseconds",
            Self::ResponseCodecLockSamples => "response_codec_lock_samples",
        }
    }

    /// The counter's fixed unit.
    pub const fn unit(self) -> StructuralUnit {
        match self {
            Self::TcpDecryptPrepareCopyBytes
            | Self::TcpFrameEncodeCopyBytes
            | Self::TcpPlainToEncryptCopyBytes
            | Self::TcpDecryptToPlainCopyBytes
            | Self::UdpPayloadToWireCopyBytes
            | Self::SocksUdpCopyBytes
            | Self::DnsUdpCopyBytes
            | Self::TcpZeroizedBytes
            | Self::UdpRequestWireResizeBytes
            | Self::UdpRequestWireZeroBytes
            | Self::FtbrEncryptBufferCapacityBytes
            | Self::FtbrDecryptBufferCapacityBytes
            | Self::FtbrRelayBufferCapacityRemovedBytes => StructuralUnit::Bytes,
            Self::AdmissionLockWaitNanoseconds
            | Self::AdmissionLockHoldNanoseconds
            | Self::UdpServerLockWaitNanoseconds
            | Self::UdpServerLockHoldNanoseconds
            | Self::UdpMappingsLockWaitNanoseconds
            | Self::UdpMappingsLockHoldNanoseconds
            | Self::SessionShardLockWaitNanoseconds
            | Self::SessionShardLockHoldNanoseconds
            | Self::ResponseCodecLockWaitNanoseconds
            | Self::ResponseCodecLockHoldNanoseconds => StructuralUnit::Nanoseconds,
            _ => StructuralUnit::Count,
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// A closed FTBR fallback reason.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FtbrFallbackReason {
    Direct,
    MultiHop,
    Tun,
    Dns,
    RuleSet,
    ServerNonDirect,
    UnsupportedFlow,
}

impl FtbrFallbackReason {
    /// Every fallback reason in stable schema order.
    pub const ALL: &'static [Self] = &[
        Self::Direct,
        Self::MultiHop,
        Self::Tun,
        Self::Dns,
        Self::RuleSet,
        Self::ServerNonDirect,
        Self::UnsupportedFlow,
    ];

    /// The dedicated counter for this reason.
    pub const fn counter(self) -> StructuralCounter {
        match self {
            Self::Direct => StructuralCounter::FtbrFallbackDirectConnections,
            Self::MultiHop => StructuralCounter::FtbrFallbackMultiHopConnections,
            Self::Tun => StructuralCounter::FtbrFallbackTunConnections,
            Self::Dns => StructuralCounter::FtbrFallbackDnsConnections,
            Self::RuleSet => StructuralCounter::FtbrFallbackRuleSetConnections,
            Self::ServerNonDirect => StructuralCounter::FtbrFallbackServerNonDirectConnections,
            Self::UnsupportedFlow => StructuralCounter::FtbrFallbackUnsupportedFlowConnections,
        }
    }
}

/// A closed hot-lock site.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LockSite {
    Admission,
    UdpServer,
    UdpMappings,
    SessionShard,
    ResponseCodec,
}

impl LockSite {
    /// Every lock site in stable schema order.
    pub const ALL: &'static [Self] = &[
        Self::Admission,
        Self::UdpServer,
        Self::UdpMappings,
        Self::SessionShard,
        Self::ResponseCodec,
    ];

    const fn counters(self) -> (StructuralCounter, StructuralCounter, StructuralCounter) {
        match self {
            Self::Admission => (
                StructuralCounter::AdmissionLockWaitNanoseconds,
                StructuralCounter::AdmissionLockHoldNanoseconds,
                StructuralCounter::AdmissionLockSamples,
            ),
            Self::UdpServer => (
                StructuralCounter::UdpServerLockWaitNanoseconds,
                StructuralCounter::UdpServerLockHoldNanoseconds,
                StructuralCounter::UdpServerLockSamples,
            ),
            Self::UdpMappings => (
                StructuralCounter::UdpMappingsLockWaitNanoseconds,
                StructuralCounter::UdpMappingsLockHoldNanoseconds,
                StructuralCounter::UdpMappingsLockSamples,
            ),
            Self::SessionShard => (
                StructuralCounter::SessionShardLockWaitNanoseconds,
                StructuralCounter::SessionShardLockHoldNanoseconds,
                StructuralCounter::SessionShardLockSamples,
            ),
            Self::ResponseCodec => (
                StructuralCounter::ResponseCodecLockWaitNanoseconds,
                StructuralCounter::ResponseCodecLockHoldNanoseconds,
                StructuralCounter::ResponseCodecLockSamples,
            ),
        }
    }
}

#[repr(align(64))]
struct CacheLineAligned<T>(T);

struct CounterShard {
    counters: [AtomicU64; StructuralCounter::COUNT],
    overflowed: AtomicBool,
}

impl CounterShard {
    fn new() -> Self {
        Self {
            counters: std::array::from_fn(|_| AtomicU64::new(0)),
            overflowed: AtomicBool::new(false),
        }
    }

    fn add(&self, counter: StructuralCounter, value: u64) {
        let cell = &self.counters[counter.index()];
        let mut current = cell.load(Ordering::Relaxed);
        loop {
            let (next, overflowed) = match current.checked_add(value) {
                Some(next) => (next, false),
                None => (u64::MAX, true),
            };
            match cell.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => {
                    if overflowed {
                        self.overflowed.store(true, Ordering::Relaxed);
                    }
                    return;
                }
                Err(observed) => current = observed,
            }
        }
    }
}

struct HubInner {
    next_shard: AtomicUsize,
    shards: [CacheLineAligned<CounterShard>; STRUCTURAL_SHARD_COUNT],
}

impl HubInner {
    fn new() -> Self {
        Self {
            next_shard: AtomicUsize::new(0),
            shards: std::array::from_fn(|_| CacheLineAligned(CounterShard::new())),
        }
    }
}

/// Owner of one fixed, preallocated structural counter set.
#[derive(Clone)]
pub struct StructuralHub {
    inner: Arc<HubInner>,
}

impl StructuralHub {
    /// Creates an empty hub and preallocates all shards.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(HubInner::new()),
        }
    }

    /// Assigns one local recorder to a fixed shard in round-robin order.
    pub fn local(&self) -> StructuralLocal {
        let shard = self.inner.next_shard.fetch_add(1, Ordering::Relaxed) % STRUCTURAL_SHARD_COUNT;
        StructuralLocal {
            inner: Arc::clone(&self.inner),
            shard,
        }
    }

    /// Reads and saturatingly aggregates every counter shard.
    pub fn snapshot(&self) -> StructuralSnapshot {
        let mut counters = [0_u64; StructuralCounter::COUNT];
        let mut overflowed = false;
        for shard in &self.inner.shards {
            overflowed |= shard.0.overflowed.load(Ordering::Relaxed);
            for (index, total) in counters.iter_mut().enumerate() {
                let value = shard.0.counters[index].load(Ordering::Relaxed);
                match total.checked_add(value) {
                    Some(sum) => *total = sum,
                    None => {
                        *total = u64::MAX;
                        overflowed = true;
                    }
                }
            }
        }
        StructuralSnapshot {
            counters,
            overflowed,
        }
    }
}

impl Default for StructuralHub {
    fn default() -> Self {
        Self::new()
    }
}

/// A cloneable recorder bound to one hub shard.
#[derive(Clone)]
pub struct StructuralLocal {
    inner: Arc<HubInner>,
    shard: usize,
}

impl StructuralLocal {
    /// Saturatingly adds `value` to one closed counter.
    pub fn add(&self, counter: StructuralCounter, value: u64) {
        self.inner.shards[self.shard].0.add(counter, value);
    }

    /// Records one wait/hold sample for a closed lock site.
    pub fn lock(&self, site: LockSite, wait_nanoseconds: u64, hold_nanoseconds: u64) {
        let (wait, hold, samples) = site.counters();
        self.add(wait, wait_nanoseconds);
        self.add(hold, hold_nanoseconds);
        self.add(samples, 1);
    }
}

/// An aggregated, identity-free observation of one hub.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuralSnapshot {
    counters: [u64; StructuralCounter::COUNT],
    overflowed: bool,
}

impl StructuralSnapshot {
    /// Returns the aggregated value for one counter.
    pub fn get(&self, counter: StructuralCounter) -> u64 {
        self.counters[counter.index()]
    }

    /// Reports whether any local update or cross-shard aggregation saturated.
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Iterates over every counter and value in stable schema order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (StructuralCounter, u64)> + '_ {
        StructuralCounter::ALL
            .iter()
            .copied()
            .map(|counter| (counter, self.get(counter)))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::mem::align_of;

    use super::{
        CacheLineAligned, FtbrFallbackReason, LockSite, StructuralCounter, StructuralHub,
        StructuralLocal, StructuralSnapshot,
    };

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn multiple_locals_aggregate_exactly() {
        let hub = StructuralHub::new();
        let first = hub.local();
        let second = hub.local();
        first.add(StructuralCounter::DnsUdpCopyBytes, 11);
        second.add(StructuralCounter::DnsUdpCopyBytes, 31);
        first.add(StructuralCounter::SocksUdpAllocations, 2);

        let snapshot = hub.snapshot();
        assert_eq!(snapshot.get(StructuralCounter::DnsUdpCopyBytes), 42);
        assert_eq!(snapshot.get(StructuralCounter::SocksUdpAllocations), 2);
        assert!(!snapshot.overflowed());
    }

    #[test]
    fn saturation_is_sticky_and_reported() {
        let hub = StructuralHub::new();
        let local = hub.local();
        local.add(StructuralCounter::ReplayClearedBits, u64::MAX);
        local.add(StructuralCounter::ReplayClearedBits, 1);

        let snapshot = hub.snapshot();
        assert_eq!(snapshot.get(StructuralCounter::ReplayClearedBits), u64::MAX);
        assert!(snapshot.overflowed());
    }

    #[test]
    fn cross_shard_aggregation_saturates_and_reports_overflow() {
        let hub = StructuralHub::new();
        hub.local()
            .add(StructuralCounter::TcpZeroizedBytes, u64::MAX);
        hub.local().add(StructuralCounter::TcpZeroizedBytes, 1);

        let snapshot = hub.snapshot();
        assert_eq!(snapshot.get(StructuralCounter::TcpZeroizedBytes), u64::MAX);
        assert!(snapshot.overflowed());
    }

    #[test]
    fn lock_records_only_the_selected_site() {
        let hub = StructuralHub::new();
        hub.local().lock(LockSite::Admission, 7, 13);

        let snapshot = hub.snapshot();
        assert_eq!(
            snapshot.get(StructuralCounter::AdmissionLockWaitNanoseconds),
            7
        );
        assert_eq!(
            snapshot.get(StructuralCounter::AdmissionLockHoldNanoseconds),
            13
        );
        assert_eq!(snapshot.get(StructuralCounter::AdmissionLockSamples), 1);
        assert_eq!(snapshot.get(StructuralCounter::UdpServerLockSamples), 0);
    }

    #[test]
    fn public_recorders_and_snapshots_are_send_and_sync() {
        assert_send_sync::<StructuralHub>();
        assert_send_sync::<StructuralLocal>();
        assert_send_sync::<StructuralSnapshot>();
    }

    #[test]
    fn counter_schema_is_closed_and_complete() {
        assert_eq!(StructuralCounter::COUNT, 49);
        assert_eq!(LockSite::ALL.len(), 5);
        assert_eq!(FtbrFallbackReason::ALL.len(), 7);
        assert_eq!(align_of::<CacheLineAligned<super::CounterShard>>(), 64);

        let names: BTreeSet<_> = StructuralCounter::ALL
            .iter()
            .map(|counter| counter.name())
            .collect();
        assert_eq!(names.len(), StructuralCounter::COUNT);
        for (index, counter) in StructuralCounter::ALL.iter().copied().enumerate() {
            assert_eq!(counter.index(), index);
        }
        for reason in FtbrFallbackReason::ALL {
            assert!(StructuralCounter::ALL.contains(&reason.counter()));
        }
    }
}
