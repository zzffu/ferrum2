use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use super::{DnsCacheAnswer, DnsCacheError, DnsCacheKey, DnsCacheObserver};

#[cfg(test)]
mod tests;

struct Entry {
    key: DnsCacheKey,
    answer: DnsCacheAnswer,
    expires_at: Instant,
    previous: Option<usize>,
    next: Option<usize>,
    heap_position: usize,
}

/// Stable slots back both the FIFO links and an indexed min-heap. Every live
/// entry has exactly one deadline; refresh/removal cannot accumulate stale work.
pub(super) struct DnsCacheState {
    pub(super) capacity: usize,
    index: HashMap<DnsCacheKey, usize>,
    slots: Vec<Option<Entry>>,
    free: Vec<usize>,
    oldest: Option<usize>,
    newest: Option<usize>,
    deadlines: Vec<usize>,
    pub(super) observer: Option<Arc<dyn DnsCacheObserver>>,
}

impl DnsCacheState {
    pub(super) fn clear(&mut self) -> usize {
        let removed = self.index.len();
        self.index.clear();
        self.slots.clear();
        self.free.clear();
        self.deadlines.clear();
        self.oldest = None;
        self.newest = None;
        removed
    }

    pub(super) fn try_new(capacity: usize) -> Result<Self, DnsCacheError> {
        let mut index = HashMap::new();
        index
            .try_reserve(capacity)
            .map_err(|_| DnsCacheError::Allocation)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| DnsCacheError::Allocation)?;
        let mut free = Vec::new();
        free.try_reserve_exact(capacity)
            .map_err(|_| DnsCacheError::Allocation)?;
        let mut deadlines = Vec::new();
        deadlines
            .try_reserve_exact(capacity)
            .map_err(|_| DnsCacheError::Allocation)?;
        Ok(Self {
            capacity,
            index,
            slots,
            free,
            oldest: None,
            newest: None,
            deadlines,
            observer: None,
        })
    }

    fn entry(&self, id: usize) -> &Entry {
        self.slots[id].as_ref().expect("live cache slot")
    }

    fn entry_mut(&mut self, id: usize) -> &mut Entry {
        self.slots[id].as_mut().expect("live cache slot")
    }

    pub(super) fn get(&mut self, key: &DnsCacheKey, now: Instant) -> Option<DnsCacheAnswer> {
        let id = *self.index.get(key)?;
        if self.entry(id).expires_at <= now {
            self.remove(id);
            None
        } else {
            Some(self.entry(id).answer.clone())
        }
    }

    pub(super) fn insert(
        &mut self,
        key: DnsCacheKey,
        answer: DnsCacheAnswer,
        expires_at: Instant,
        now: Instant,
    ) {
        if let Some(&id) = self.index.get(&key) {
            self.remove(id);
        }
        if expires_at == now {
            return;
        }
        // One due removal suffices to make room, and bounds insertion cleanup
        // even when every TTL expires together. Exact counts drain the rest.
        self.expire_one(now);
        if self.index.len() == self.capacity {
            self.remove(self.oldest.expect("full cache has oldest entry"));
        }
        let id = self.free.pop().unwrap_or_else(|| {
            self.slots.push(None);
            self.slots.len() - 1
        });
        self.slots[id] = Some(Entry {
            key: key.clone(),
            answer,
            expires_at,
            previous: self.newest,
            next: None,
            heap_position: self.deadlines.len(),
        });
        if let Some(newest) = self.newest {
            self.entry_mut(newest).next = Some(id);
        } else {
            self.oldest = Some(id);
        }
        self.newest = Some(id);
        self.index.insert(key, id);
        self.deadlines.push(id);
        self.sift_up(self.deadlines.len() - 1);
    }

    pub(super) fn entry_count(&mut self, now: Instant) -> usize {
        while self.expire_one(now) {}
        self.index.len()
    }

    fn expire_one(&mut self, now: Instant) -> bool {
        let Some(&id) = self.deadlines.first() else {
            return false;
        };
        if self.entry(id).expires_at > now {
            return false;
        }
        self.remove(id);
        true
    }

    fn remove(&mut self, id: usize) {
        let entry = self.slots[id].take().expect("live cache slot");
        self.index.remove(&entry.key);
        if let Some(previous) = entry.previous {
            self.entry_mut(previous).next = entry.next;
        } else {
            self.oldest = entry.next;
        }
        if let Some(next) = entry.next {
            self.entry_mut(next).previous = entry.previous;
        } else {
            self.newest = entry.previous;
        }
        self.deadlines.swap_remove(entry.heap_position);
        if entry.heap_position < self.deadlines.len() {
            let moved = self.deadlines[entry.heap_position];
            self.entry_mut(moved).heap_position = entry.heap_position;
            let position = self.sift_up(entry.heap_position);
            self.sift_down(position);
        }
        self.free.push(id);
    }

    fn earlier(&self, left: usize, right: usize) -> bool {
        self.entry(self.deadlines[left]).expires_at < self.entry(self.deadlines[right]).expires_at
    }

    fn swap_deadlines(&mut self, left: usize, right: usize) {
        self.deadlines.swap(left, right);
        let left_id = self.deadlines[left];
        let right_id = self.deadlines[right];
        self.entry_mut(left_id).heap_position = left;
        self.entry_mut(right_id).heap_position = right;
    }

    fn sift_up(&mut self, mut position: usize) -> usize {
        while position > 0 {
            let parent = (position - 1) / 2;
            if !self.earlier(position, parent) {
                break;
            }
            self.swap_deadlines(position, parent);
            position = parent;
        }
        position
    }

    fn sift_down(&mut self, mut position: usize) {
        loop {
            let left = position * 2 + 1;
            if left >= self.deadlines.len() {
                break;
            }
            let right = left + 1;
            let child = if right < self.deadlines.len() && self.earlier(right, left) {
                right
            } else {
                left
            };
            if !self.earlier(child, position) {
                break;
            }
            self.swap_deadlines(position, child);
            position = child;
        }
    }
}
