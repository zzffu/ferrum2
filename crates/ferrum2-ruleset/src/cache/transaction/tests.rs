use std::cell::Cell;

use super::*;
use crate::cache::{read_cache_sync, read_held_cache};
use ferrum2_core::CanonicalDomain;
use tokio_util::sync::CancellationToken;

const AI: &[u8] = include_bytes!("../../../../../tests/fixtures/srs/ai.srs");
const IP: &[u8] = include_bytes!("../../../../../tests/fixtures/srs/cnip.srs");
const URL: &str = "https://fixture.invalid/input.srs";

fn stop() -> WorkStop {
    WorkStop {
        cancel: CancellationToken::new(),
        deadline: None,
    }
}
fn metadata() -> DownloadMetadata {
    DownloadMetadata {
        etag: Some("reviewed".into()),
        last_modified: None,
    }
}

fn seed(directory: &CacheDirectory, name: &RuleSetCacheName, bytes: &[u8], generation: u64) {
    let stop = stop();
    let mut transaction = CacheTransaction::begin(directory, &stop).unwrap();
    transaction.write_chunk(bytes, &stop).unwrap();
    let compiled = transaction.compile(&stop).unwrap();
    transaction
        .commit(CacheCommit {
            directory,
            name,
            url: URL,
            metadata: metadata(),
            compiled: &compiled,
            generation,
            stop: &stop,
        })
        .unwrap();
    transaction.cleanup().unwrap();
}

#[derive(Clone, Copy, Debug)]
enum FailAt {
    Metadata,
    Header,
    Flush,
    Sync,
    Persist,
    DirectorySync,
    Cleanup,
    ObservePersist,
    CancelBeforePersist,
    CancelAfterPersist,
}

struct FailingIo {
    failure: FailAt,
    writes: Cell<usize>,
    cancel: CancellationToken,
    persist_error: Cell<Option<(std::io::ErrorKind, Option<i32>)>>,
}
impl TransactionIo for FailingIo {
    fn write(&self, file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
        let index = self.writes.get();
        self.writes.set(index + 1);
        if matches!(
            (self.failure, index),
            (FailAt::Metadata, 0) | (FailAt::Header, 1)
        ) {
            file.write_all(&bytes[..bytes.len().min(2)])?;
            return Err(std::io::Error::other("injected write"));
        }
        SystemTransactionIo.write(file, bytes)
    }
    fn flush(&self, file: &mut File) -> std::io::Result<()> {
        if matches!(self.failure, FailAt::Flush) {
            return Err(std::io::Error::other("injected flush"));
        }
        SystemTransactionIo.flush(file)
    }
    fn sync(&self, file: &File) -> std::io::Result<()> {
        if matches!(self.failure, FailAt::Sync) {
            return Err(std::io::Error::other("injected sync"));
        }
        SystemTransactionIo.sync(file)?;
        if matches!(self.failure, FailAt::CancelBeforePersist) {
            self.cancel.cancel();
        }
        Ok(())
    }
    fn persist(&self, temp: NamedTempFile, path: &Path) -> Result<File, PersistError> {
        if matches!(self.failure, FailAt::Persist) {
            return Err(PersistError {
                error: std::io::Error::other("injected persist"),
                file: temp,
            });
        }
        let result = SystemTransactionIo.persist(temp, path);
        if result.is_ok() && matches!(self.failure, FailAt::CancelAfterPersist) {
            self.cancel.cancel();
        }
        if let Err(error) = &result {
            self.persist_error
                .set(Some((error.error.kind(), error.error.raw_os_error())));
        }
        result
    }
    fn sync_directory(&self, directory: &Path) -> std::io::Result<()> {
        if matches!(self.failure, FailAt::DirectorySync) {
            return Err(std::io::Error::other("injected directory sync"));
        }
        SystemTransactionIo.sync_directory(directory)
    }
    fn close(&self, temp: NamedTempFile) -> std::io::Result<()> {
        temp.close()?;
        if matches!(self.failure, FailAt::Cleanup) {
            return Err(std::io::Error::other("injected close outcome"));
        }
        Ok(())
    }
}

#[test]
fn precommit_failures_preserve_old_complete_container_and_remove_owned_temp() {
    for failure in [
        FailAt::Metadata,
        FailAt::Header,
        FailAt::Flush,
        FailAt::Sync,
        FailAt::Persist,
        FailAt::DirectorySync,
    ] {
        let root = tempfile::tempdir().unwrap();
        let directory = CacheDirectory::new(root.path().to_owned());
        directory.acquire().unwrap();
        let name = RuleSetCacheName::new("item").unwrap();
        seed(&directory, &name, AI, 7);
        let path = cache_path(root.path(), &name);
        let before = std::fs::read(&path).unwrap();
        let stop = stop();
        let mut transaction = CacheTransaction::begin(&directory, &stop).unwrap();
        transaction.write_chunk(IP, &stop).unwrap();
        let compiled = transaction.compile(&stop).unwrap();
        let io = FailingIo {
            failure,
            writes: Cell::new(0),
            cancel: CancellationToken::new(),
            persist_error: Cell::new(None),
        };
        let error = transaction
            .commit_with(
                CacheCommit {
                    directory: &directory,
                    name: &name,
                    url: URL,
                    metadata: metadata(),
                    compiled: &compiled,
                    generation: 8,
                    stop: &stop,
                },
                &io,
            )
            .unwrap_err();
        assert_eq!(error.kind(), RuleSetLoadErrorKind::CacheWrite);
        transaction.cleanup().unwrap();
        let loaded = read_cache_sync(&directory, &name, URL, &stop)
            .unwrap()
            .unwrap();
        if matches!(failure, FailAt::DirectorySync) {
            assert_eq!(loaded.loaded.generation, 8); // committed, durability uncertain
        } else {
            assert_eq!(std::fs::read(&path).unwrap(), before, "{failure:?}");
            assert_eq!(loaded.loaded.generation, 7);
        }
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 2);
        directory.release().unwrap();
    }
}

#[test]
fn held_file_read_cannot_mix_replaced_payload_and_metadata() {
    let root = tempfile::tempdir().unwrap();
    let directory = CacheDirectory::new(root.path().to_owned());
    directory.acquire().unwrap();
    let name = RuleSetCacheName::new("item").unwrap();
    seed(&directory, &name, AI, 7);
    let mut held = File::open(cache_path(root.path(), &name)).unwrap();
    let stop = stop();
    let mut transaction = CacheTransaction::begin(&directory, &stop).unwrap();
    transaction.write_chunk(IP, &stop).unwrap();
    let compiled = transaction.compile(&stop).unwrap();
    let io = FailingIo {
        failure: FailAt::ObservePersist,
        writes: Cell::new(0),
        cancel: CancellationToken::new(),
        persist_error: Cell::new(None),
    };
    let replacement = transaction.commit_with(
        CacheCommit {
            directory: &directory,
            name: &name,
            url: URL,
            metadata: metadata(),
            compiled: &compiled,
            generation: 8,
            stop: &stop,
        },
        &io,
    );
    transaction.cleanup().unwrap();
    #[cfg(not(windows))]
    replacement.as_ref().expect("replace open destination");
    // Windows MoveFileEx may reject replacing an open destination. That is a
    // closed write failure preserving the old complete target, never a reopen.
    if let Err(error) = replacement {
        assert_eq!(error.kind(), RuleSetLoadErrorKind::CacheWrite);
        // ERROR_ACCESS_DENIED from the real pinned persist call, not an
        // arbitrary CacheWrite (e.g. metadata, flush, or injected IO failure).
        assert_eq!(
            io.persist_error.get(),
            Some((std::io::ErrorKind::PermissionDenied, Some(5)))
        );
    }
    let replaced = replacement.is_ok();
    let old = read_held_cache(&mut held, URL, &stop).unwrap();
    let new = read_cache_sync(&directory, &name, URL, &stop)
        .unwrap()
        .unwrap();
    assert_eq!(
        (old.loaded.generation, new.loaded.generation),
        (7, if replaced { 8 } else { 7 })
    );
    let domain = CanonicalDomain::new("api.openai.example").unwrap();
    assert!(old.loaded.match_set.matches_domain(&domain));
    assert_eq!(new.loaded.match_set.matches_domain(&domain), !replaced);
    drop(held);
    // Closing the old destination is the sole changed condition. Ordinary
    // replacement must succeed on every platform; no remove-old fallback.
    seed(&directory, &name, IP, 9);
    assert_eq!(
        read_cache_sync(&directory, &name, URL, &stop)
            .unwrap()
            .unwrap()
            .loaded
            .generation,
        9
    );
    directory.release().unwrap();
}

#[test]
fn header_metadata_digest_lengths_and_schema_are_closed() {
    let root = tempfile::tempdir().unwrap();
    let directory = CacheDirectory::new(root.path().to_owned());
    directory.acquire().unwrap();
    let name = RuleSetCacheName::new("item").unwrap();
    seed(&directory, &name, AI, 1);
    let path = cache_path(root.path(), &name);
    let original = std::fs::read(&path).unwrap();
    for position in [0, 8, 12, 16, 24, 28, 32, 64] {
        let mut changed = original.clone();
        changed[position] ^= 1;
        std::fs::write(&path, &changed).unwrap();
        assert!(
            read_cache_sync(&directory, &name, URL, &stop()).is_err(),
            "changed byte {position}"
        );
    }
    let mut trailing = original.clone();
    trailing.push(0);
    std::fs::write(&path, trailing).unwrap();
    assert!(read_cache_sync(&directory, &name, URL, &stop()).is_err());
    std::fs::write(&path, &original[..original.len() - 1]).unwrap();
    assert!(read_cache_sync(&directory, &name, URL, &stop()).is_err());
    directory.release().unwrap();
}

#[test]
fn metadata_duplicate_fields_are_rejected_even_with_a_matching_digest() {
    let root = tempfile::tempdir().unwrap();
    let directory = CacheDirectory::new(root.path().to_owned());
    directory.acquire().unwrap();
    let name = RuleSetCacheName::new("item").unwrap();
    seed(&directory, &name, AI, 1);
    let path = cache_path(root.path(), &name);
    let mut original = std::fs::read(&path).unwrap();
    let mut metadata = original[HEADER_BYTES + AI.len()..].to_vec();
    metadata.pop();
    metadata.extend_from_slice(b",\"schema\":1}");
    original.truncate(HEADER_BYTES + AI.len());
    original[..HEADER_BYTES].copy_from_slice(&Header::encode(AI.len() as u64, &metadata));
    original.extend(metadata);
    std::fs::write(&path, original).unwrap();
    assert_eq!(
        read_cache_sync(&directory, &name, URL, &stop())
            .err()
            .unwrap()
            .kind(),
        RuleSetLoadErrorKind::CacheMetadata
    );
    directory.release().unwrap();
}

#[test]
fn old_pair_files_are_not_read_deleted_or_used_as_offline_cache() {
    let root = tempfile::tempdir().unwrap();
    let directory = CacheDirectory::new(root.path().to_owned());
    directory.acquire().unwrap();
    std::fs::write(root.path().join("item.srs"), AI).unwrap();
    std::fs::write(root.path().join("item.meta"), b"{}").unwrap();
    assert!(
        read_cache_sync(
            &directory,
            &RuleSetCacheName::new("item").unwrap(),
            URL,
            &stop()
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(std::fs::read(root.path().join("item.srs")).unwrap(), AI);
    assert_eq!(std::fs::read(root.path().join("item.meta")).unwrap(), b"{}");
    directory.release().unwrap();
}

#[test]
fn cleanup_failure_is_not_reported_as_a_successful_transaction() {
    let root = tempfile::tempdir().unwrap();
    let directory = CacheDirectory::new(root.path().to_owned());
    directory.acquire().unwrap();
    let mut transaction = CacheTransaction::begin(&directory, &stop()).unwrap();
    let io = FailingIo {
        failure: FailAt::Cleanup,
        writes: Cell::new(0),
        cancel: CancellationToken::new(),
        persist_error: Cell::new(None),
    };
    assert_eq!(
        transaction.cleanup_with(&io).unwrap_err().kind(),
        RuleSetLoadErrorKind::CacheCleanup
    );
    directory.release().unwrap();
}

#[test]
fn stable_hashed_names_do_not_encode_windows_device_basenames_or_case_aliases() {
    let root = Path::new("cache");
    for tag in ["CON", "NUL", "COM1", "LPT1"] {
        let path = cache_path(root, &RuleSetCacheName::new(tag).unwrap());
        assert!(
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("rs-")
        );
    }
    assert_ne!(
        cache_path(root, &RuleSetCacheName::new("Ai").unwrap()),
        cache_path(root, &RuleSetCacheName::new("ai").unwrap())
    );
}

#[test]
fn cancellation_around_persist_keeps_the_complete_committed_generation() {
    for (failure, expected_generation) in [
        (FailAt::CancelBeforePersist, 7),
        (FailAt::CancelAfterPersist, 8),
    ] {
        let root = tempfile::tempdir().unwrap();
        let directory = CacheDirectory::new(root.path().to_owned());
        directory.acquire().unwrap();
        let name = RuleSetCacheName::new("item").unwrap();
        seed(&directory, &name, AI, 7);
        let operation_stop = stop();
        let mut transaction = CacheTransaction::begin(&directory, &operation_stop).unwrap();
        transaction.write_chunk(IP, &operation_stop).unwrap();
        let compiled = transaction.compile(&operation_stop).unwrap();
        let io = FailingIo {
            failure,
            writes: Cell::new(0),
            cancel: operation_stop.cancel.clone(),
            persist_error: Cell::new(None),
        };
        let committed = transaction.commit_with(
            CacheCommit {
                directory: &directory,
                name: &name,
                url: URL,
                metadata: metadata(),
                compiled: &compiled,
                generation: 8,
                stop: &operation_stop,
            },
            &io,
        );
        // The session observes cancellation after commit too, while cleanup
        // owns only an uncommitted temp and cannot remove the replaced target.
        let observed = committed.and_then(|()| operation_stop.check());
        assert_eq!(
            observed.unwrap_err().kind(),
            RuleSetLoadErrorKind::Cancelled
        );
        transaction.cleanup().unwrap();
        let loaded = read_cache_sync(&directory, &name, URL, &stop())
            .unwrap()
            .unwrap();
        assert_eq!(loaded.loaded.generation, expected_generation);
        assert_eq!(
            loaded
                .loaded
                .match_set
                .matches_domain(&CanonicalDomain::new("api.openai.example").unwrap()),
            expected_generation == 7
        );
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 2);
        directory.release().unwrap();
    }
}
