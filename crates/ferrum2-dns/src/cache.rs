use std::cmp::{Ordering, Reverse};
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use ferrum2_core::{CanonicalDomain, DomainName};

/// Stable numeric identity of one validated DNS server.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DnsServerId(u32);

impl DnsServerId {
    /// Creates an identity assigned by validated configuration order.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the underlying stable numeric identity.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Generation of one fully materialized DNS resolver graph.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResolverGeneration(u64);

impl ResolverGeneration {
    /// Creates a materialized resolver generation.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying generation counter.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next generation without wrapping.
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// Address query types stored independently by the shared DNS cache.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DnsCacheQtype {
    /// IPv4 address records.
    A,
    /// IPv6 address records.
    Aaaa,
}

/// Complete server-scoped, type-scoped, generation-scoped DNS cache key.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct DnsCacheKey {
    server: DnsServerId,
    canonical_name: CanonicalDomain,
    qtype: DnsCacheQtype,
    generation: ResolverGeneration,
}

impl DnsCacheKey {
    /// Creates a key from one validated server and canonical domain.
    pub fn new(
        server: DnsServerId,
        canonical_name: CanonicalDomain,
        qtype: DnsCacheQtype,
        generation: ResolverGeneration,
    ) -> Self {
        Self {
            server,
            canonical_name,
            qtype,
            generation,
        }
    }

    /// Creates a key from a protocol domain when it has an application-safe
    /// canonical representation. The root-only protocol name is not cached.
    pub fn from_domain(
        server: DnsServerId,
        domain: &DomainName,
        qtype: DnsCacheQtype,
        generation: ResolverGeneration,
    ) -> Option<Self> {
        Some(Self::new(
            server,
            domain.canonical()?.clone(),
            qtype,
            generation,
        ))
    }

    /// Returns the selected server identity.
    pub const fn server(&self) -> DnsServerId {
        self.server
    }

    /// Returns the canonical name.
    pub const fn canonical_name(&self) -> &CanonicalDomain {
        &self.canonical_name
    }

    /// Returns the independently cached address type.
    pub const fn qtype(&self) -> DnsCacheQtype {
        self.qtype
    }

    /// Returns the resolver generation.
    pub const fn generation(&self) -> ResolverGeneration {
        self.generation
    }
}

impl fmt::Debug for DnsCacheKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsCacheKey")
            .field("server", &self.server)
            .field("canonical_name", &"[redacted]")
            .field("qtype", &self.qtype)
            .field("generation", &self.generation)
            .finish()
    }
}

/// Typed positive address records retained by the DNS cache.
#[derive(Clone, Eq, PartialEq)]
pub enum DnsAddressRecords {
    /// IPv4 records for an A key.
    A(Arc<[Ipv4Addr]>),
    /// IPv6 records for an AAAA key.
    Aaaa(Arc<[Ipv6Addr]>),
}

impl DnsAddressRecords {
    /// Returns the matching cache query type.
    pub const fn qtype(&self) -> DnsCacheQtype {
        match self {
            Self::A(_) => DnsCacheQtype::A,
            Self::Aaaa(_) => DnsCacheQtype::Aaaa,
        }
    }

    /// Returns the number of cached address records.
    pub fn len(&self) -> usize {
        match self {
            Self::A(records) => records.len(),
            Self::Aaaa(records) => records.len(),
        }
    }

    /// Returns whether the positive record set is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns IPv4 records when this is an A answer.
    pub fn ipv4(&self) -> Option<&[Ipv4Addr]> {
        match self {
            Self::A(records) => Some(records),
            Self::Aaaa(_) => None,
        }
    }

    /// Returns IPv6 records when this is an AAAA answer.
    pub fn ipv6(&self) -> Option<&[Ipv6Addr]> {
        match self {
            Self::A(_) => None,
            Self::Aaaa(records) => Some(records),
        }
    }
}

impl fmt::Debug for DnsAddressRecords {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsAddressRecords")
            .field("qtype", &self.qtype())
            .field("records", &self.len())
            .finish()
    }
}

/// Positive or negative TTL-aware DNS cache answer.
#[derive(Clone, Eq, PartialEq)]
pub enum DnsCacheAnswer {
    /// One non-negative address answer.
    Positive(DnsAddressRecords),
    /// NXDOMAIN or NODATA retained with its validated negative TTL.
    Negative,
}

impl fmt::Debug for DnsCacheAnswer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Positive(records) => records.fmt(formatter),
            Self::Negative => formatter.write_str("DnsCacheAnswer::Negative"),
        }
    }
}

#[derive(Clone)]
struct DnsCacheEntry {
    answer: DnsCacheAnswer,
    expires_at: Instant,
    serial: u64,
}

#[derive(Clone)]
struct InsertionNode {
    key: DnsCacheKey,
    serial: u64,
}

#[derive(Clone)]
struct ExpiryNode {
    expires_at: Instant,
    serial: u64,
    key: DnsCacheKey,
}

impl PartialEq for ExpiryNode {
    fn eq(&self, other: &Self) -> bool {
        self.expires_at == other.expires_at && self.serial == other.serial
    }
}

impl Eq for ExpiryNode {}

impl PartialOrd for ExpiryNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExpiryNode {
    fn cmp(&self, other: &Self) -> Ordering {
        self.expires_at
            .cmp(&other.expires_at)
            .then_with(|| self.serial.cmp(&other.serial))
    }
}

struct DnsCacheState {
    capacity: usize,
    entries: HashMap<DnsCacheKey, DnsCacheEntry>,
    insertion_order: VecDeque<InsertionNode>,
    expiry_order: BinaryHeap<Reverse<ExpiryNode>>,
    next_serial: u64,
    observer: Option<Arc<dyn DnsCacheObserver>>,
    cache_scan_entries: u64,
}

impl DnsCacheState {
    fn record_scan(&mut self, entries: usize) {
        self.cache_scan_entries = self
            .cache_scan_entries
            .saturating_add(u64::try_from(entries).unwrap_or(u64::MAX));
    }

    fn remove(&mut self, key: &DnsCacheKey) {
        self.entries.remove(key);
    }

    fn purge_expired(&mut self, now: Instant) {
        while self
            .expiry_order
            .peek()
            .is_some_and(|Reverse(node)| node.expires_at <= now)
        {
            let Reverse(node) = self
                .expiry_order
                .pop()
                .expect("peeked DNS cache expiry node");
            self.record_scan(1);
            let is_current = self
                .entries
                .get(&node.key)
                .is_some_and(|entry| entry.serial == node.serial && entry.expires_at <= now);
            if is_current {
                self.entries.remove(&node.key);
            }
        }
        self.maybe_rebuild_indexes();
    }

    fn evict_until_available(&mut self) {
        while self.entries.len() >= self.capacity {
            let Some(oldest) = self.insertion_order.pop_front() else {
                self.rebuild_indexes();
                continue;
            };
            self.record_scan(1);
            let is_current = self
                .entries
                .get(&oldest.key)
                .is_some_and(|entry| entry.serial == oldest.serial);
            if is_current {
                self.entries.remove(&oldest.key);
            }
        }
    }

    fn allocate_serial(&mut self) -> u64 {
        if self.next_serial == u64::MAX {
            self.renumber_serials();
        }
        let serial = self.next_serial;
        self.next_serial = self
            .next_serial
            .checked_add(1)
            .expect("bounded DNS cache exhausted serial space");
        serial
    }

    fn renumber_serials(&mut self) {
        self.record_scan(self.entries.len().saturating_mul(2));
        let mut keys = self
            .entries
            .iter()
            .map(|(key, entry)| (entry.serial, key.clone()))
            .collect::<Vec<_>>();
        keys.sort_unstable_by_key(|(serial, _)| *serial);
        for (serial, (_, key)) in keys.iter().enumerate() {
            self.entries
                .get_mut(key)
                .expect("DNS cache key collected from entries")
                .serial = u64::try_from(serial).expect("DNS cache capacity fits u64");
        }
        self.next_serial = u64::try_from(keys.len()).expect("DNS cache capacity fits u64");
        self.rebuild_indexes();
    }

    fn maybe_rebuild_indexes(&mut self) {
        if self.entries.is_empty() {
            self.insertion_order.clear();
            self.expiry_order.clear();
            return;
        }
        let rebuild_limit = self.entries.len().saturating_mul(2).saturating_add(1);
        if self.insertion_order.len() > rebuild_limit || self.expiry_order.len() > rebuild_limit {
            self.rebuild_indexes();
        }
    }

    fn rebuild_indexes(&mut self) {
        self.record_scan(self.entries.len().saturating_mul(2));
        let mut insertion_order = self
            .entries
            .iter()
            .map(|(key, entry)| InsertionNode {
                key: key.clone(),
                serial: entry.serial,
            })
            .collect::<Vec<_>>();
        insertion_order.sort_unstable_by_key(|node| node.serial);
        self.insertion_order = insertion_order.into();
        self.expiry_order = self
            .entries
            .iter()
            .map(|(key, entry)| {
                Reverse(ExpiryNode {
                    expires_at: entry.expires_at,
                    serial: entry.serial,
                    key: key.clone(),
                })
            })
            .collect();
    }
}

/// Cloneable, bounded cache shared by TCP, UDP, and fixed-endpoint consumers.
#[derive(Clone)]
pub struct DnsCache {
    state: Arc<Mutex<DnsCacheState>>,
}

/// Closed cache lookup outcome exposed to low-cardinality telemetry adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsCacheLookup {
    Hit,
    Miss,
}

/// Identity-free cumulative work observed inside the cache indexes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DnsCacheWorkSnapshot {
    /// Expiry, eviction, renumbering, and rebuild index entries examined.
    pub cache_scan_entries: u64,
}

/// Identity-free observer for cache lookups.
pub trait DnsCacheObserver: Send + Sync + 'static {
    fn record(&self, qtype: DnsCacheQtype, outcome: DnsCacheLookup);
}

impl<F> DnsCacheObserver for F
where
    F: Fn(DnsCacheQtype, DnsCacheLookup) + Send + Sync + 'static,
{
    fn record(&self, qtype: DnsCacheQtype, outcome: DnsCacheLookup) {
        self(qtype, outcome);
    }
}

impl DnsCache {
    /// Allocates storage for at most `capacity` server/name/type/generation keys.
    pub fn try_new(capacity: NonZeroUsize) -> Result<Self, DnsCacheError> {
        let capacity = capacity.get();
        let mut entries = HashMap::new();
        entries
            .try_reserve(capacity)
            .map_err(|_| DnsCacheError::Allocation)?;
        let mut insertion_order = VecDeque::new();
        insertion_order
            .try_reserve(capacity)
            .map_err(|_| DnsCacheError::Allocation)?;
        let mut expiry_order = BinaryHeap::new();
        expiry_order
            .try_reserve(capacity)
            .map_err(|_| DnsCacheError::Allocation)?;
        Ok(Self {
            state: Arc::new(Mutex::new(DnsCacheState {
                capacity,
                entries,
                insertion_order,
                expiry_order,
                next_serial: 0,
                observer: None,
                cache_scan_entries: 0,
            })),
        })
    }

    /// Installs one identity-free observer shared by every clone of this cache.
    pub fn try_with_observer(
        self,
        observer: Arc<dyn DnsCacheObserver>,
    ) -> Result<Self, DnsCacheError> {
        self.lock()?.observer = Some(observer);
        Ok(self)
    }

    /// Returns the configured maximum number of cache keys.
    pub fn capacity(&self) -> Result<usize, DnsCacheError> {
        Ok(self.lock()?.capacity)
    }

    /// Returns cumulative identity-free index work for qualification tooling.
    pub fn work_snapshot(&self) -> Result<DnsCacheWorkSnapshot, DnsCacheError> {
        Ok(DnsCacheWorkSnapshot {
            cache_scan_entries: self.lock()?.cache_scan_entries,
        })
    }

    /// Returns a live answer and lazily removes this key when expired.
    pub fn get(
        &self,
        key: &DnsCacheKey,
        now: Instant,
    ) -> Result<Option<DnsCacheAnswer>, DnsCacheError> {
        let (answer, observer) = {
            let mut state = self.lock()?;
            let expired = state
                .entries
                .get(key)
                .is_some_and(|entry| entry.expires_at <= now);
            if expired {
                state.remove(key);
                state.maybe_rebuild_indexes();
            }
            (
                state.entries.get(key).map(|entry| entry.answer.clone()),
                state.observer.as_ref().map(Arc::clone),
            )
        };
        if let Some(observer) = observer {
            observer.record(
                key.qtype(),
                if answer.is_some() {
                    DnsCacheLookup::Hit
                } else {
                    DnsCacheLookup::Miss
                },
            );
        }
        Ok(answer)
    }

    /// Inserts one positive answer using the DNS response TTL.
    pub fn insert_positive(
        &self,
        key: DnsCacheKey,
        records: DnsAddressRecords,
        ttl: Duration,
        now: Instant,
    ) -> Result<(), DnsCacheError> {
        if key.qtype != records.qtype() {
            return Err(DnsCacheError::AddressFamily);
        }
        self.insert(key, DnsCacheAnswer::Positive(records), ttl, now)
    }

    /// Inserts one negative answer using its SOA-derived negative TTL.
    pub fn insert_negative(
        &self,
        key: DnsCacheKey,
        ttl: Duration,
        now: Instant,
    ) -> Result<(), DnsCacheError> {
        self.insert(key, DnsCacheAnswer::Negative, ttl, now)
    }

    /// Returns the number of live keys after lazily purging expired entries.
    pub fn entry_count(&self, now: Instant) -> Result<usize, DnsCacheError> {
        let mut state = self.lock()?;
        state.purge_expired(now);
        Ok(state.entries.len())
    }

    fn insert(
        &self,
        key: DnsCacheKey,
        answer: DnsCacheAnswer,
        ttl: Duration,
        now: Instant,
    ) -> Result<(), DnsCacheError> {
        let expires_at = now.checked_add(ttl).ok_or(DnsCacheError::TtlOverflow)?;
        let mut state = self.lock()?;
        state.purge_expired(now);
        state.remove(&key);
        if ttl.is_zero() {
            state.maybe_rebuild_indexes();
            return Ok(());
        }
        state.evict_until_available();
        let serial = state.allocate_serial();
        state.insertion_order.push_back(InsertionNode {
            key: key.clone(),
            serial,
        });
        state.expiry_order.push(Reverse(ExpiryNode {
            expires_at,
            serial,
            key: key.clone(),
        }));
        state.entries.insert(
            key,
            DnsCacheEntry {
                answer,
                expires_at,
                serial,
            },
        );
        state.maybe_rebuild_indexes();
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, DnsCacheState>, DnsCacheError> {
        self.state.lock().map_err(|_| DnsCacheError::Unavailable)
    }
}

impl fmt::Debug for DnsCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DnsCache([redacted])")
    }
}

/// Closed DNS cache construction or operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsCacheError {
    /// Initial bounded storage reservation failed.
    Allocation,
    /// Cache state is unavailable after an internal panic poisoned its lock.
    Unavailable,
    /// Adding the supplied TTL overflowed the monotonic clock.
    TtlOverflow,
    /// Positive records do not match the key's A or AAAA type.
    AddressFamily,
}

impl fmt::Display for DnsCacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Allocation => "DNS cache allocation failed",
            Self::Unavailable => "DNS cache is unavailable",
            Self::TtlOverflow => "DNS cache TTL overflowed",
            Self::AddressFamily => "DNS cache address family is invalid",
        })
    }
}

impl std::error::Error for DnsCacheError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str) -> DnsCacheKey {
        DnsCacheKey::new(
            DnsServerId::new(1),
            CanonicalDomain::new(name).expect("cache test domain"),
            DnsCacheQtype::A,
            ResolverGeneration::new(1),
        )
    }

    fn records(octet: u8) -> DnsAddressRecords {
        DnsAddressRecords::A(Arc::from([Ipv4Addr::new(192, 0, 2, octet)]))
    }

    #[test]
    fn replacement_serial_prevents_stale_expiry_from_removing_the_new_answer() {
        let cache =
            DnsCache::try_new(NonZeroUsize::new(2).expect("cache capacity")).expect("cache");
        let now = Instant::now();
        let key = key("replace.example");
        cache
            .insert_positive(key.clone(), records(1), Duration::from_secs(1), now)
            .expect("first answer");
        cache
            .insert_positive(key.clone(), records(2), Duration::from_secs(10), now)
            .expect("replacement answer");

        assert_eq!(
            cache
                .get(&key, now + Duration::from_secs(2))
                .expect("replacement lookup"),
            Some(DnsCacheAnswer::Positive(records(2)))
        );
    }

    #[test]
    fn eviction_skips_stale_queue_nodes_and_uses_current_insertion_order() {
        let cache =
            DnsCache::try_new(NonZeroUsize::new(2).expect("cache capacity")).expect("cache");
        let now = Instant::now();
        let first = key("first.example");
        let second = key("second.example");
        let third = key("third.example");
        for (key, octet) in [(&first, 1), (&second, 2), (&first, 3), (&third, 4)] {
            cache
                .insert_positive(key.clone(), records(octet), Duration::from_secs(60), now)
                .expect("cache insert");
        }

        assert_eq!(cache.get(&second, now).expect("evicted lookup"), None);
        assert_eq!(
            cache.get(&first, now).expect("replacement lookup"),
            Some(DnsCacheAnswer::Positive(records(3)))
        );
        assert!(cache.get(&third, now).expect("newest lookup").is_some());
    }

    #[test]
    fn expiry_heap_work_tracks_only_due_nodes() {
        let cache =
            DnsCache::try_new(NonZeroUsize::new(4).expect("cache capacity")).expect("cache");
        let now = Instant::now();
        let first = key("expires-first.example");
        let second = key("expires-second.example");
        let third = key("expires-third.example");
        for (key, ttl, octet) in [(&first, 1, 1), (&second, 3, 2), (&third, 5, 3)] {
            cache
                .insert_positive(key.clone(), records(octet), Duration::from_secs(ttl), now)
                .expect("cache insert");
        }

        assert_eq!(
            cache
                .entry_count(now + Duration::from_secs(3))
                .expect("expiry purge"),
            1
        );
        assert_eq!(cache.get(&first, now).expect("first expired"), None);
        assert_eq!(cache.get(&second, now).expect("second expired"), None);
        assert!(cache.get(&third, now).expect("third live").is_some());
        assert_eq!(
            cache
                .work_snapshot()
                .expect("work snapshot")
                .cache_scan_entries,
            2
        );
    }

    #[test]
    fn repeated_replacement_rebuilds_stale_indexes_with_a_hard_bound() {
        let cache =
            DnsCache::try_new(NonZeroUsize::new(64).expect("cache capacity")).expect("cache");
        let now = Instant::now();
        let key = key("stale.example");
        for octet in 1..=100 {
            cache
                .insert_positive(
                    key.clone(),
                    records(octet),
                    Duration::from_secs(60 + u64::from(octet)),
                    now,
                )
                .expect("replacement insert");
        }

        let state = cache.lock().expect("cache state");
        let limit = state.entries.len() * 2 + 1;
        assert_eq!(state.entries.len(), 1);
        assert!(state.insertion_order.len() <= limit);
        assert!(state.expiry_order.len() <= limit);
    }
}
