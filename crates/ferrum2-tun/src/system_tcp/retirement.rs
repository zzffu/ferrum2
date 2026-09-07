use std::sync::atomic::Ordering;

use super::quarantine::PORT_QUARANTINE_MILLIS;
use super::{
    FlowTuple, MAX_RETIRED_IDENTITIES, RetiredMapping, ReverseTuple, RewritePlan, SystemTcp,
};
use crate::TunEvent;

impl SystemTcp {
    pub(super) fn retire_all(&mut self, now_millis: i64, preserve_rewrite: bool) -> usize {
        let mut retired = 0;
        for slot in 0..self.slots.len() {
            if self.slots[slot].is_some() {
                self.retire_slot(slot, now_millis, preserve_rewrite);
                retired += 1;
            }
        }
        self.active_deadline_millis = None;
        self.pending_slots.clear();
        retired
    }

    pub(super) fn retire_slot(&mut self, slot: usize, now_millis: i64, preserve_rewrite: bool) {
        let Some(mapping) = self.slots[slot].take() else {
            return;
        };
        if mapping.pending_flow.is_some() {
            self.pending_slots.retain(|pending| *pending != slot);
        }
        let removed_forward = self.forward.remove(&mapping.forward);
        let removed_reverse = self.reverse.remove(&mapping.reverse);
        debug_assert_eq!(removed_forward, Some(slot));
        debug_assert_eq!(removed_reverse, Some(slot));
        if let Some(socket) = &mapping.socket {
            socket.fence();
        }
        let expires_at = now_millis.saturating_add(PORT_QUARANTINE_MILLIS);
        if preserve_rewrite && self.retired_forward.len() < MAX_RETIRED_IDENTITIES {
            let retired = RetiredMapping {
                forward_plan: RewritePlan {
                    source: mapping.reverse.peer,
                    destination: mapping.reverse.listener,
                },
                reverse_plan: RewritePlan {
                    source: mapping.forward.target,
                    destination: mapping.forward.source,
                },
                reverse: mapping.reverse,
                expires_at,
            };
            let replaced_reverse = self
                .retired_reverse
                .insert(mapping.reverse, mapping.forward);
            let replaced_forward = self.retired_forward.insert(mapping.forward, retired);
            debug_assert!(replaced_reverse.is_none());
            debug_assert!(replaced_forward.is_none());
            self.retired_deadline_millis = Some(
                self.retired_deadline_millis
                    .map_or(expires_at, |deadline| deadline.min(expires_at)),
            );
        }
        if let Ok(mut quarantine) = self.quarantine.lock() {
            if preserve_rewrite {
                quarantine.release(mapping.family, mapping.translated_port, now_millis);
            } else {
                quarantine.defer_release(mapping.family, mapping.translated_port);
            }
        } else {
            // Keep poisoned identities unavailable, but finish closing the real resources.
            self.listener_failed.store(true, Ordering::Release);
        }
        self.free_slots.push(slot);
        self.active -= 1;
        self.flow_count.fetch_sub(1, Ordering::AcqRel);
        self.events.emit(TunEvent::TcpFlowsActive(self.active));
    }

    pub(super) fn retired_reverse_plan(
        &mut self,
        reverse: ReverseTuple,
        now_millis: i64,
    ) -> Option<RewritePlan> {
        let forward = self.retired_reverse.get(&reverse).copied()?;
        let Some(mapping) = self.retired_forward.get(&forward).copied() else {
            self.retired_reverse.remove(&reverse);
            return None;
        };
        if mapping.expires_at > now_millis {
            Some(mapping.reverse_plan)
        } else {
            self.retired_reverse.remove(&reverse);
            self.retired_forward.remove(&forward);
            if self.retired_deadline_millis == Some(mapping.expires_at) {
                self.recompute_retired_deadline();
            }
            None
        }
    }

    pub(super) fn retired_forward_plan(
        &mut self,
        forward: FlowTuple,
        now_millis: i64,
    ) -> Option<RewritePlan> {
        let mapping = self.retired_forward.get(&forward).copied()?;
        if mapping.expires_at > now_millis {
            Some(mapping.forward_plan)
        } else {
            self.retired_forward.remove(&forward);
            self.retired_reverse.remove(&mapping.reverse);
            if self.retired_deadline_millis == Some(mapping.expires_at) {
                self.recompute_retired_deadline();
            }
            None
        }
    }

    pub(super) fn reap_retired(&mut self, now_millis: i64) -> bool {
        if self
            .retired_deadline_millis
            .is_none_or(|due| due > now_millis)
        {
            return false;
        }
        let reverse = &mut self.retired_reverse;
        let mut reaped = false;
        let mut next_deadline = None;
        self.retired_forward.retain(|forward, mapping| {
            if mapping.expires_at <= now_millis {
                let removed = reverse.remove(&mapping.reverse);
                debug_assert_eq!(removed, Some(*forward));
                reaped = true;
                false
            } else {
                next_deadline = Some(next_deadline.map_or(mapping.expires_at, |deadline: i64| {
                    deadline.min(mapping.expires_at)
                }));
                true
            }
        });
        self.retired_deadline_millis = next_deadline;
        reaped
    }

    fn recompute_retired_deadline(&mut self) {
        self.retired_deadline_millis = self
            .retired_forward
            .values()
            .map(|mapping| mapping.expires_at)
            .min();
    }
}
