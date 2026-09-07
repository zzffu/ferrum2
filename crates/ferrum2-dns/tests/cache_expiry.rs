use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use ferrum2_core::CanonicalDomain;
use ferrum2_dns::{
    DnsCache, DnsCacheAnswer, DnsCacheKey, DnsCacheQtype, DnsServerId, ResolverGeneration,
};

fn key(index: usize) -> DnsCacheKey {
    DnsCacheKey::new(
        DnsServerId::new(1),
        CanonicalDomain::new(&format!("key-{index}.example")).expect("canonical key"),
        DnsCacheQtype::A,
        ResolverGeneration::new(1),
    )
}

#[test]
fn unordered_expiry_is_reclaimed_before_the_oldest_live_entry() {
    let cache = DnsCache::try_new(NonZeroUsize::new(3).expect("capacity")).expect("cache");
    let now = Instant::now();
    for (index, seconds) in [(0, 100), (1, 1), (2, 200)] {
        cache
            .insert_negative(key(index), Duration::from_secs(seconds), now)
            .expect("insert");
    }
    let later = now + Duration::from_secs(2);
    cache
        .insert_negative(key(3), Duration::from_secs(50), later)
        .expect("reclaim expired middle entry");
    // Check before entry_count: a diagnostic purge must not conceal a bad eviction.
    let answers: Vec<_> = (0..4)
        .map(|index| cache.get(&key(index), later).expect("lookup"))
        .collect();
    assert_eq!(
        answers,
        vec![
            Some(DnsCacheAnswer::Negative),
            None,
            Some(DnsCacheAnswer::Negative),
            Some(DnsCacheAnswer::Negative),
        ]
    );
    assert_eq!(cache.entry_count(later), Ok(3));
}

#[test]
fn refreshed_and_removed_expirations_do_not_hide_shorter_new_ttls() {
    let cache = DnsCache::try_new(NonZeroUsize::new(2).expect("capacity")).expect("cache");
    let now = Instant::now();
    cache
        .insert_negative(key(0), Duration::from_secs(10), now)
        .expect("initial entry");
    cache
        .insert_negative(key(0), Duration::from_secs(100), now)
        .expect("extend original minimum");
    cache
        .insert_negative(key(1), Duration::from_secs(5), now)
        .expect("earlier expiration");
    cache
        .insert_negative(
            key(2),
            Duration::from_secs(50),
            now + Duration::from_secs(5),
        )
        .expect("expire before eviction at exact TTL boundary");
    assert_eq!(cache.get(&key(0), now), Ok(Some(DnsCacheAnswer::Negative)));
    assert_eq!(cache.get(&key(1), now), Ok(None));

    cache
        .insert_negative(key(2), Duration::ZERO, now)
        .expect("invalidate without evicting another key");
    cache
        .insert_negative(key(3), Duration::from_secs(1), now)
        .expect("shorter TTL after removal");
    assert_eq!(cache.entry_count(now + Duration::from_secs(1)), Ok(1));
    assert_eq!(cache.get(&key(0), now), Ok(Some(DnsCacheAnswer::Negative)));
    assert_eq!(cache.get(&key(3), now), Ok(None));
}

#[test]
fn repeated_refreshes_keep_fifo_capacity_and_lookup_does_not_refresh_order() {
    let cache = DnsCache::try_new(NonZeroUsize::new(2).expect("capacity")).expect("cache");
    let now = Instant::now();
    for index in 0..2 {
        cache
            .insert_negative(key(index), Duration::from_secs(60), now)
            .expect("initial entry");
    }
    for _ in 0..1_000 {
        cache
            .insert_negative(key(0), Duration::from_secs(60), now)
            .expect("refresh");
    }
    assert_eq!(cache.get(&key(1), now), Ok(Some(DnsCacheAnswer::Negative)));
    cache
        .insert_negative(key(2), Duration::from_secs(60), now)
        .expect("FIFO insert");
    let answers: Vec<_> = (0..3)
        .map(|index| cache.get(&key(index), now).expect("lookup"))
        .collect();
    assert_eq!(
        answers,
        vec![
            Some(DnsCacheAnswer::Negative),
            None,
            Some(DnsCacheAnswer::Negative)
        ]
    );
    assert_eq!(cache.entry_count(now), Ok(2));
}

#[test]
fn batch_expiry_preserves_live_fifo_and_entry_count_drains_every_due_key() {
    let cache = DnsCache::try_new(NonZeroUsize::new(129).unwrap()).unwrap();
    let now = Instant::now();
    cache
        .insert_negative(key(0), Duration::from_secs(60), now)
        .unwrap();
    for index in 1..129 {
        cache
            .insert_negative(key(index), Duration::from_secs(1), now)
            .unwrap();
    }
    let later = now + Duration::from_secs(1);
    cache
        .insert_negative(key(129), Duration::from_secs(60), later)
        .unwrap();
    // The oldest live key survives even when the full cache expires behind it.
    assert_eq!(
        cache.get(&key(0), later),
        Ok(Some(DnsCacheAnswer::Negative))
    );
    assert_eq!(cache.entry_count(later), Ok(2));
    for index in 1..129 {
        assert_eq!(cache.get(&key(index), later), Ok(None));
    }
    assert_eq!(
        cache.get(&key(129), later),
        Ok(Some(DnsCacheAnswer::Negative))
    );
    assert_eq!(cache.entry_count(later + Duration::from_secs(60)), Ok(0));
}
