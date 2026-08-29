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

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::try_with_wire_staging;

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
}
