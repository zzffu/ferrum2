use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use ferrum2_core::CanonicalDomain;

use super::super::{
    DnsCache, DnsCacheAnswer, DnsCacheKey, DnsCacheQtype, DnsServerId, ResolverGeneration,
};

#[test]
fn clearing_a_shared_cache_removes_answers_and_preserves_reuse() {
    let cache = DnsCache::try_new(NonZeroUsize::new(2).unwrap()).unwrap();
    let shared = cache.clone();
    let key = DnsCacheKey::new(
        DnsServerId::new(0),
        CanonicalDomain::new("clear.example").unwrap(),
        DnsCacheQtype::A,
        ResolverGeneration::new(1),
    );
    let now = Instant::now();
    cache
        .insert_negative(key.clone(), Duration::from_secs(60), now)
        .unwrap();
    assert_eq!(shared.clear(), Ok(1));
    assert_eq!(cache.get(&key, now), Ok(None));
    cache
        .insert_negative(key.clone(), Duration::from_secs(120), now)
        .unwrap();
    assert_eq!(
        shared.get(&key, now + Duration::from_secs(61)),
        Ok(Some(DnsCacheAnswer::Negative))
    );
    assert_eq!(cache.entry_count(now + Duration::from_secs(121)), Ok(0));
    assert_eq!(shared.clear(), Ok(0));
}

#[test]
fn bounded_churn_preserves_fifo_and_exact_expiry_against_a_reference() {
    let keys: Vec<_> = (0..37)
        .map(|index| {
            DnsCacheKey::new(
                DnsServerId::new(index % 3),
                CanonicalDomain::new(&format!("key-{}.example", index / 3)).unwrap(),
                if index % 2 == 0 {
                    DnsCacheQtype::A
                } else {
                    DnsCacheQtype::Aaaa
                },
                ResolverGeneration::new(u64::from(index % 5)),
            )
        })
        .collect();
    for capacity in [1, 7, 31] {
        let cache = DnsCache::try_new(NonZeroUsize::new(capacity).unwrap()).unwrap();
        let mut reference = VecDeque::<(usize, Instant)>::new();
        let start = Instant::now();
        let mut random = 0x79ab_ef25_u32;
        for step in 0..10_000 {
            random = random.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let index = random as usize % keys.len();
            let now = start + Duration::from_millis(step / 4);
            reference.retain(|(_, expiry)| *expiry > now);
            match random % 4 {
                0..=2 => {
                    // Zero TTL, equal deadlines, shortening, and extension all
                    // interleave with slot reuse and non-head removal.
                    let ttl = Duration::from_millis(u64::from((random >> 8) % 41));
                    reference.retain(|(key, _)| *key != index);
                    if !ttl.is_zero() {
                        if reference.len() == capacity {
                            reference.pop_front();
                        }
                        reference.push_back((index, now + ttl));
                    }
                    cache
                        .insert_negative(keys[index].clone(), ttl, now)
                        .unwrap();
                }
                3 => {
                    let expected = reference
                        .iter()
                        .any(|(key, _)| *key == index)
                        .then_some(DnsCacheAnswer::Negative);
                    assert_eq!(cache.get(&keys[index], now), Ok(expected));
                }
                _ => unreachable!(),
            }
            // Resource bounds are part of this cache's contract: a lazy heap
            // that retains one deadline per refresh fails under this churn.
            {
                let state = cache.lock().unwrap();
                assert_eq!(state.deadlines.len(), state.index.len());
                assert_eq!(state.slots.len(), state.index.len() + state.free.len());
                assert!(state.slots.len() <= capacity);
            }
            if step % 29 == 0 {
                assert_eq!(cache.entry_count(now), Ok(reference.len()));
                for (index, key) in keys.iter().enumerate() {
                    let expected = reference
                        .iter()
                        .any(|(candidate, _)| *candidate == index)
                        .then_some(DnsCacheAnswer::Negative);
                    assert_eq!(cache.get(key, now), Ok(expected));
                }
            }
        }
        assert_eq!(cache.entry_count(start + Duration::from_secs(60)), Ok(0));
        let state = cache.lock().unwrap();
        assert!(state.deadlines.is_empty());
        assert_eq!(state.free.len(), state.slots.len());
    }
}
