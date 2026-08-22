use std::sync::Arc;

/// Cloneable, platform-neutral signal used to interrupt the TUN owner wait.
///
/// The callback must be non-blocking. Signalling is deliberately best-effort:
/// shared state is changed before this hook is invoked, so a coalesced signal
/// never loses the underlying work.
#[derive(Clone)]
pub struct OwnerWake {
    signal: Arc<dyn Fn() + Send + Sync>,
}

impl OwnerWake {
    /// Creates a wake handle around one non-blocking signal operation.
    pub fn new(signal: impl Fn() + Send + Sync + 'static) -> Self {
        Self {
            signal: Arc::new(signal),
        }
    }

    /// Interrupts the owner wait after shared state has changed.
    pub fn signal(&self) {
        (self.signal)();
    }
}

impl Default for OwnerWake {
    fn default() -> Self {
        Self::new(|| {})
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::OwnerWake;

    #[test]
    fn clones_signal_the_same_coalescible_source() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let wake = OwnerWake::new(move || {
            observed.fetch_add(1, Ordering::SeqCst);
        });

        wake.signal();
        wake.clone().signal();

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
