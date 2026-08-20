use std::collections::{HashMap, VecDeque};
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
}

struct DnsCacheState {
    capacity: usize,
    entries: HashMap<DnsCacheKey, DnsCacheEntry>,
    insertion_order: VecDeque<DnsCacheKey>,
    observer: Option<Arc<dyn DnsCacheObserver>>,
}

impl DnsCacheState {
    fn remove(&mut self, key: &DnsCacheKey) {
        self.entries.remove(key);
        if let Some(index) = self
            .insertion_order
            .iter()
            .position(|candidate| candidate == key)
        {
            self.insertion_order.remove(index);
        }
    }

    fn purge_expired(&mut self, now: Instant) {
        self.entries.retain(|_, entry| entry.expires_at > now);
        let entries = &self.entries;
        self.insertion_order.retain(|key| entries.contains_key(key));
    }

    fn evict_until_available(&mut self) {
        while self.entries.len() >= self.capacity {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
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
        Ok(Self {
            state: Arc::new(Mutex::new(DnsCacheState {
                capacity,
                entries,
                insertion_order,
                observer: None,
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
            return Ok(());
        }
        state.evict_until_available();
        state.insertion_order.push_back(key.clone());
        state
            .entries
            .insert(key, DnsCacheEntry { answer, expires_at });
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
