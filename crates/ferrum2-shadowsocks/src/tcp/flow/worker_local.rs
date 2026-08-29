use std::cell::RefCell;

use zeroize::{Zeroize, Zeroizing};

use crate::tcp::wire::MAX_DECRYPT_WIRE_LEN;

std::thread_local! {
    static WIRE_STAGING: RefCell<Option<Zeroizing<Box<[u8]>>>> = const { RefCell::new(None) };
}

struct ClearOnDrop<'a> {
    bytes: &'a mut [u8],
}

impl ClearOnDrop<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.bytes
    }
}

impl Drop for ClearOnDrop<'_> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Runs one synchronous decrypt operation against wire storage local to the
/// current OS worker. The used range is cleared before the borrow is released,
/// including during unwinding. A reentrant borrow reports `None` so the flow can
/// use its receive-scratch fallback without holding this borrow across a poll
/// boundary.
pub(super) fn try_with_wire_staging<R>(
    used_len: usize,
    operation: impl FnOnce(&mut [u8]) -> R,
) -> Option<R> {
    assert!(used_len <= MAX_DECRYPT_WIRE_LEN);
    WIRE_STAGING.with(|slot| {
        let mut slot = slot.try_borrow_mut().ok()?;
        let staging = slot.get_or_insert_with(|| {
            Zeroizing::new(vec![0_u8; MAX_DECRYPT_WIRE_LEN].into_boxed_slice())
        });
        let mut clear = ClearOnDrop {
            bytes: &mut staging[..used_len],
        };
        Some(operation(clear.as_mut()))
    })
}

#[cfg(feature = "tokio")]
struct ClearPrefixOnDrop<'a> {
    bytes: &'a mut [u8],
    clear_prefix: usize,
}

#[cfg(feature = "tokio")]
impl ClearPrefixOnDrop<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.bytes
    }
}

#[cfg(feature = "tokio")]
impl Drop for ClearPrefixOnDrop<'_> {
    fn drop(&mut self) {
        self.bytes[..self.clear_prefix].zeroize();
    }
}

/// Runs one synchronous operation against worker-local wire storage and clears
/// only the prefix reported by a normal return. Until the operation returns,
/// the guard conservatively owns the complete exposed range so unwinding clears
/// every byte that the operation could have touched. On a normal return the
/// reported prefix must cover every modified byte and the remaining suffix must
/// still equal its entry state.
#[cfg(feature = "tokio")]
pub(super) fn try_with_wire_staging_clear_prefix<R>(
    exposed_len: usize,
    operation: impl FnOnce(&mut [u8]) -> (usize, R),
) -> Option<R> {
    assert!(exposed_len <= MAX_DECRYPT_WIRE_LEN);
    WIRE_STAGING.with(|slot| {
        let mut slot = slot.try_borrow_mut().ok()?;
        let staging = slot.get_or_insert_with(|| {
            Zeroizing::new(vec![0_u8; MAX_DECRYPT_WIRE_LEN].into_boxed_slice())
        });
        let mut clear = ClearPrefixOnDrop {
            bytes: &mut staging[..exposed_len],
            clear_prefix: exposed_len,
        };
        let (clear_prefix, result) = operation(clear.as_mut());
        assert!(clear_prefix <= exposed_len);
        clear.clear_prefix = clear_prefix;
        Some(result)
    })
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::try_with_wire_staging;
    #[cfg(feature = "tokio")]
    use super::try_with_wire_staging_clear_prefix;

    #[test]
    fn staging_reuses_cleared_storage_after_every_exit() {
        let first = try_with_wire_staging(32, |staging| {
            assert!(staging.iter().all(|byte| *byte == 0));
            staging.fill(0xa5);
            staging.as_ptr()
        })
        .expect("initial staging borrow");

        let error = try_with_wire_staging(32, |staging| {
            assert_eq!(staging.as_ptr(), first);
            assert!(staging.iter().all(|byte| *byte == 0));
            staging.fill(0x5a);
            Err::<(), ()>(())
        });
        assert_eq!(error, Some(Err(())));

        let panic = catch_unwind(AssertUnwindSafe(|| {
            try_with_wire_staging(32, |staging| {
                assert_eq!(staging.as_ptr(), first);
                assert!(staging.iter().all(|byte| *byte == 0));
                staging.fill(0x3c);
                panic!("exercise unwind clearing");
            });
        }));
        assert!(panic.is_err());

        try_with_wire_staging(32, |staging| {
            assert_eq!(staging.as_ptr(), first);
            assert!(staging.iter().all(|byte| *byte == 0));
            assert!(try_with_wire_staging(1, |_| ()).is_none());
        })
        .expect("staging remains reusable after unwind");
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn dynamic_staging_clears_reported_prefix_and_full_range_on_unwind() {
        try_with_wire_staging_clear_prefix(32, |staging| {
            assert!(staging.iter().all(|byte| *byte == 0));
            staging[..7].fill(0xa5);
            assert!(staging[7..].iter().all(|byte| *byte == 0));
            (7, ())
        })
        .expect("dynamic staging borrow");

        try_with_wire_staging(32, |staging| {
            assert!(staging.iter().all(|byte| *byte == 0));
        })
        .expect("inspect dynamic prefix clear");

        let panic = catch_unwind(AssertUnwindSafe(|| {
            try_with_wire_staging_clear_prefix(32, |staging| -> (usize, ()) {
                staging.fill(0x5a);
                panic!("exercise conservative unwind clearing");
            });
        }));
        assert!(panic.is_err());

        try_with_wire_staging(32, |staging| {
            assert!(staging.iter().all(|byte| *byte == 0));
        })
        .expect("inspect unwind clear");
    }
}
