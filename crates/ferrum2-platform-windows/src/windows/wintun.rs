use std::cell::Cell;

use crate::Error;

#[derive(Default)]
pub(super) struct SessionJournal {
    waiting: Cell<bool>,
}

impl SessionJournal {
    pub(super) fn begin_wait(&self) -> Result<WaitGuard<'_>, Error> {
        if self.waiting.replace(true) {
            return Err(Error);
        }
        Ok(WaitGuard(&self.waiting))
    }

    pub(super) fn cleanup_is_safe(&self) -> bool {
        !self.waiting.get()
    }
}

pub(super) struct WaitGuard<'a>(&'a Cell<bool>);

impl Drop for WaitGuard<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_journal_blocks_overlapping_waits() {
        let journal = SessionJournal::default();
        let wait = journal.begin_wait().unwrap();
        assert!(journal.begin_wait().is_err());
        drop(wait);
        assert!(journal.cleanup_is_safe());
    }
}
