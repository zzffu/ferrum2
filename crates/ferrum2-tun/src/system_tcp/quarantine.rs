use std::cmp::Reverse;
use std::collections::BinaryHeap;

use super::AddressFamily;

pub(crate) const PORT_QUARANTINE_MILLIS: i64 = 240_000;
const PORT_SLOTS: usize = u16::MAX as usize + 1;
const AVAILABLE: i64 = i64::MIN;
const ACTIVE: i64 = i64::MAX;
const PENDING_RELEASE: i64 = i64::MAX - 1;

/// Process-long internal-port ownership and 2-MSL quarantine state.
///
/// Each address family has exactly 65,535 usable identities shared by listener
/// ports and translated peer ports. Active and quarantined identities occupy the
/// same fixed table, so resets cannot accidentally reuse either half of an old
/// wire tuple and the table cannot grow with connection churn.
pub(crate) struct PortQuarantine {
    ipv4: FamilyPorts,
    ipv6: FamilyPorts,
    last_now_millis: i64,
}

impl Default for PortQuarantine {
    fn default() -> Self {
        Self {
            ipv4: FamilyPorts::new(),
            ipv6: FamilyPorts::new(),
            last_now_millis: 0,
        }
    }
}

impl PortQuarantine {
    pub(super) fn allocate(&mut self, family: AddressFamily, now_millis: i64) -> Option<u16> {
        let now_millis = self.observe_time(now_millis);
        self.family_mut(family).allocate(now_millis)
    }

    pub(super) fn claim(&mut self, family: AddressFamily, port: u16) -> bool {
        let now_millis = self.last_now_millis;
        self.family_mut(family).claim(port, now_millis)
    }

    pub(super) fn unclaim(&mut self, family: AddressFamily, port: u16) {
        self.family_mut(family).unclaim(port);
    }

    pub(super) fn release(&mut self, family: AddressFamily, port: u16, now_millis: i64) {
        let now_millis = self.observe_time(now_millis);
        self.family_mut(family).release(port, now_millis);
    }

    /// Retires an identity without trusting a potentially stale caller timestamp.
    ///
    /// The next supervisor-clock observation starts the full quarantine interval,
    /// which can conservatively extend but never shorten wire-identity isolation.
    pub(super) fn defer_release(&mut self, family: AddressFamily, port: u16) {
        self.family_mut(family).defer_release(port);
    }

    pub(super) fn reap(&mut self, now_millis: i64) -> bool {
        let now_millis = self.observe_time(now_millis);
        self.ipv4.reap(now_millis) | self.ipv6.reap(now_millis)
    }

    pub(super) fn next_deadline_millis(&self) -> Option<i64> {
        if self.ipv4.pending_release != 0 || self.ipv6.pending_release != 0 {
            return Some(self.last_now_millis);
        }
        match (
            self.ipv4.next_deadline_millis(),
            self.ipv6.next_deadline_millis(),
        ) {
            (Some(ipv4), Some(ipv6)) => Some(ipv4.min(ipv6)),
            (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
            (None, None) => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn counts(&self) -> ((usize, usize), (usize, usize)) {
        (
            (self.ipv4.active, self.ipv4.quarantined),
            (self.ipv6.active, self.ipv6.quarantined),
        )
    }

    #[cfg(test)]
    pub(super) fn set_next_port_for_test(&mut self, family: AddressFamily, port: u16) {
        assert_ne!(port, 0, "translated test port must be non-zero");
        self.family_mut(family).cursor = port;
    }

    fn observe_time(&mut self, now_millis: i64) -> i64 {
        self.last_now_millis = self.last_now_millis.max(now_millis);
        self.ipv4.observe_time(self.last_now_millis);
        self.ipv6.observe_time(self.last_now_millis);
        self.last_now_millis
    }

    fn family_mut(&mut self, family: AddressFamily) -> &mut FamilyPorts {
        match family {
            AddressFamily::Ipv4 => &mut self.ipv4,
            AddressFamily::Ipv6 => &mut self.ipv6,
        }
    }
}

struct FamilyPorts {
    expires_at: Box<[i64]>,
    cursor: u16,
    active: usize,
    quarantined: usize,
    pending_release: usize,
    pending_ports: Vec<u16>,
    deadlines: BinaryHeap<Reverse<(i64, u16)>>,
}

impl FamilyPorts {
    fn new() -> Self {
        Self {
            expires_at: vec![AVAILABLE; PORT_SLOTS].into_boxed_slice(),
            cursor: 49_152,
            active: 0,
            quarantined: 0,
            pending_release: 0,
            pending_ports: Vec::new(),
            deadlines: BinaryHeap::with_capacity(PORT_SLOTS - 1),
        }
    }

    fn allocate(&mut self, now_millis: i64) -> Option<u16> {
        self.reap(now_millis);
        if self.active + self.quarantined == PORT_SLOTS - 1 {
            return None;
        }
        for _ in 0..u16::MAX {
            let port = self.cursor;
            self.cursor = if port == u16::MAX { 1 } else { port + 1 };
            if self.claim(port, now_millis) {
                return Some(port);
            }
        }
        None
    }

    fn claim(&mut self, port: u16, now_millis: i64) -> bool {
        self.reap(now_millis);
        if port == 0 || self.expires_at[usize::from(port)] != AVAILABLE {
            return false;
        }
        self.expires_at[usize::from(port)] = ACTIVE;
        self.active += 1;
        true
    }

    fn unclaim(&mut self, port: u16) {
        if port != 0 && self.expires_at[usize::from(port)] == ACTIVE {
            self.expires_at[usize::from(port)] = AVAILABLE;
            self.active -= 1;
        }
    }

    fn release(&mut self, port: u16, now_millis: i64) {
        if port == 0 || self.expires_at[usize::from(port)] != ACTIVE {
            return;
        }
        let Some(expires_at) = quarantine_deadline(now_millis) else {
            self.defer_release(port);
            return;
        };
        self.expires_at[usize::from(port)] = expires_at;
        self.active -= 1;
        self.quarantined += 1;
        self.deadlines.push(Reverse((expires_at, port)));
    }

    fn defer_release(&mut self, port: u16) {
        if port == 0 || self.expires_at[usize::from(port)] != ACTIVE {
            return;
        }
        self.expires_at[usize::from(port)] = PENDING_RELEASE;
        self.active -= 1;
        self.quarantined += 1;
        self.pending_release += 1;
        self.pending_ports.push(port);
    }

    fn observe_time(&mut self, now_millis: i64) {
        if self.pending_release == 0 {
            return;
        }
        let Some(expires_at) = quarantine_deadline(now_millis) else {
            return;
        };
        for port in self.pending_ports.drain(..) {
            self.expires_at[usize::from(port)] = expires_at;
            self.deadlines.push(Reverse((expires_at, port)));
        }
        self.pending_release = 0;
    }

    fn reap(&mut self, now_millis: i64) -> bool {
        let mut reaped = false;
        while let Some(&Reverse((expires_at, port))) = self.deadlines.peek() {
            if expires_at > now_millis {
                break;
            }
            self.deadlines.pop();
            if self.expires_at[usize::from(port)] == expires_at {
                self.expires_at[usize::from(port)] = AVAILABLE;
                self.quarantined -= 1;
                reaped = true;
            }
        }
        reaped
    }

    fn next_deadline_millis(&self) -> Option<i64> {
        self.deadlines.peek().map(|entry| entry.0.0)
    }
}

fn quarantine_deadline(now_millis: i64) -> Option<i64> {
    now_millis
        .checked_add(PORT_QUARANTINE_MILLIS)
        .filter(|deadline| *deadline < PENDING_RELEASE)
}
