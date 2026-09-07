use std::io;
use std::sync::Mutex;

use super::{DnsUdpPool, DnsUdpPoolKey, IdleDnsUdp, invalid_target};

pub(super) struct DnsUdpPoolState<T> {
    pub(super) inner: Mutex<DnsUdpPoolInner<T>>,
}

pub(super) struct DnsUdpPoolInner<T> {
    pub(super) generation: u64,
    accepts_reuse: bool,
    exhausted: bool,
    completed_generation: u64,
    reset: Option<PoolReset>,
    pub(super) idle: Vec<T>,
}

struct PoolReset {
    generation: u64,
    retired: bool,
}

impl<T> Default for DnsUdpPoolState<T> {
    fn default() -> Self {
        Self {
            inner: Mutex::new(DnsUdpPoolInner {
                generation: 0,
                accepts_reuse: true,
                exhausted: false,
                completed_generation: 0,
                reset: None,
                idle: Vec::new(),
            }),
        }
    }
}

impl<T> DnsUdpPoolState<T> {
    pub(super) fn fence(&self, generation: u64) -> Result<(), ()> {
        let mut inner = self.inner.lock().map_err(|_| ())?;
        if generation == 0 || generation < inner.completed_generation || inner.exhausted {
            return Err(());
        }
        if let Some(reset) = &inner.reset {
            return if reset.generation == generation {
                Ok(())
            } else {
                Err(())
            };
        }
        if generation == inner.completed_generation {
            return Ok(());
        }
        inner.accepts_reuse = false;
        inner.reset = Some(PoolReset {
            generation,
            retired: false,
        });
        match inner.generation.checked_add(1) {
            Some(next) => {
                inner.generation = next;
                Ok(())
            }
            None => {
                inner.exhausted = true;
                Err(())
            }
        }
    }

    pub(super) fn retire(&self, generation: u64) -> Result<usize, ()> {
        let mut inner = self.inner.lock().map_err(|_| ())?;
        let Some(reset) = &mut inner.reset else {
            return if generation != 0 && generation == inner.completed_generation {
                Ok(0)
            } else {
                Err(())
            };
        };
        if reset.generation != generation {
            return Err(());
        }
        reset.retired = true;
        let idle = std::mem::take(&mut inner.idle);
        drop(inner);
        let count = idle.len();
        // Idle associations may enter socket/manager locks on drop.
        drop(idle);
        Ok(count)
    }

    pub(super) fn reopen(&self, generation: u64) -> Result<(), ()> {
        let mut inner = self.inner.lock().map_err(|_| ())?;
        if inner.exhausted {
            return Err(());
        }
        match &inner.reset {
            Some(reset) if reset.generation == generation && reset.retired => {
                inner.completed_generation = generation;
                inner.reset = None;
                inner.accepts_reuse = true;
                Ok(())
            }
            None if generation != 0 && generation == inner.completed_generation => Ok(()),
            Some(_) | None => Err(()),
        }
    }

    pub(super) fn put(&self, generation: u64, value: T) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if inner.accepts_reuse && inner.generation == generation {
            inner.idle.push(value);
        } else {
            drop(inner);
            drop(value);
        }
    }
}

pub(super) fn take_dns_udp(
    pool: &DnsUdpPool,
    key: &DnsUdpPoolKey,
) -> io::Result<(Option<IdleDnsUdp>, Option<IdleDnsUdp>, u64)> {
    let mut pool = pool.inner.lock().map_err(|_| invalid_target())?;
    if !pool.accepts_reuse {
        return Err(invalid_target());
    }
    let generation = pool.generation;
    let (matching, stale) = match pool.idle.iter().position(|idle| idle.key == *key) {
        Some(index) => (Some(pool.idle.swap_remove(index)), None),
        None => (None, pool.idle.pop()),
    };
    Ok((matching, stale, generation))
}
