use std::io::Cursor;
use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::{mpsc, oneshot};

use super::*;
use crate::download::{RuleSetDownloadFuture, RuleSetDownloadRequest, RuleSetDownloadResponse};
use crate::source::{RuleSetDownloadMode, RuleSetDownloadResolver};

const AI: &[u8] = include_bytes!("../../../../tests/fixtures/srs/ai.srs");

struct PanickingDownloader;

impl RuleSetDownloader for PanickingDownloader {
    fn fetch(&self, _: RuleSetDownloadRequest) -> RuleSetDownloadFuture<'_> {
        Box::pin(async { panic!("controlled downloader failure") })
    }
}

struct ControlledDownloader {
    entered: mpsc::UnboundedSender<()>,
    proceed: Semaphore,
}

impl RuleSetDownloader for ControlledDownloader {
    fn fetch(&self, _: RuleSetDownloadRequest) -> RuleSetDownloadFuture<'_> {
        Box::pin(async move {
            self.entered.send(()).expect("observed fetch");
            self.proceed
                .acquire()
                .await
                .expect("release fetch")
                .forget();
            Ok(RuleSetDownloadResponse::downloaded(
                Box::new(Cursor::new(AI)),
                None,
                None,
            ))
        })
    }
}

fn source(name: &str) -> RuleSetRemoteSource {
    RuleSetRemoteSource::new(
        RuleSetCacheName::new(name).expect("name"),
        "https://fixture.test/ai.srs",
        RuleSetDownloadMode::ClientResolved(RuleSetDownloadResolver::System),
        None,
        None,
    )
    .expect("source")
}

fn config(cache: &TempDir) -> RuleSetLoaderConfig {
    RuleSetLoaderConfig::new(cache.path().to_owned(), Duration::from_secs(5), 2).expect("config")
}

fn launch(
    work: &Arc<RuleSetCacheWork>,
    downloader: &Arc<ControlledDownloader>,
    config: &RuleSetLoaderConfig,
    name: &str,
) -> tokio::task::JoinHandle<Result<OperationOutput, RuleSetLoadError>> {
    let work = Arc::clone(work);
    let downloader = Arc::clone(downloader);
    let config = config.clone();
    let source = source(name);
    tokio::spawn(async move {
        work.execute(
            Operation::Load {
                source,
                generation: 1,
            },
            downloader,
            config,
        )
        .await
    })
}

async fn entered(receiver: &mut mpsc::UnboundedReceiver<()>) {
    tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await
        .expect("fetch deadline")
        .expect("fetch");
}

#[tokio::test]
async fn unrelated_downloads_overlap_but_same_key_waits_for_transaction() {
    let cache = TempDir::new().expect("cache");
    let config = config(&cache);
    let work = Arc::new(RuleSetCacheWork::new(&config));
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let downloader = Arc::new(ControlledDownloader {
        entered: sender,
        proceed: Semaphore::new(0),
    });
    let first = launch(&work, &downloader, &config, "first");
    entered(&mut receiver).await;
    let second = launch(&work, &downloader, &config, "second");
    entered(&mut receiver).await;
    downloader.proceed.add_permits(2);
    assert!(first.await.expect("first join").is_ok());
    assert!(second.await.expect("second join").is_ok());

    let first = launch(&work, &downloader, &config, "same");
    entered(&mut receiver).await;
    let second = launch(&work, &downloader, &config, "same");
    assert!(
        tokio::time::timeout(Duration::from_millis(20), receiver.recv())
            .await
            .is_err()
    );
    downloader.proceed.add_permits(1);
    assert!(first.await.expect("first join").is_ok());
    entered(&mut receiver).await;
    downloader.proceed.add_permits(1);
    assert!(second.await.expect("second join").is_ok());
    work.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn cancelled_waiter_and_shutdown_retain_worker_and_directory_lease() {
    let cache = TempDir::new().expect("cache");
    let config = config(&cache);
    let work = Arc::new(RuleSetCacheWork::new(&config));
    let (sender, _receiver) = mpsc::unbounded_channel();
    let downloader = Arc::new(ControlledDownloader {
        entered: sender,
        proceed: Semaphore::new(4),
    });
    let (entered, ready) = oneshot::channel();
    let (resume, wait) = std::sync::mpsc::channel();
    work.directory.pause_next_worker(entered, wait);
    let load = launch(&work, &downloader, &config, "first");
    ready.await.expect("worker owns lease");
    load.abort();
    assert!(matches!(load.await, Err(error) if error.is_cancelled()));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), work.shutdown())
            .await
            .is_err()
    );

    let other = RuleSetCacheWork::new(&config);
    let result = other
        .execute(
            Operation::Load {
                source: source("other"),
                generation: 1,
            },
            Arc::clone(&downloader),
            config.clone(),
        )
        .await;
    assert!(matches!(result, Err(error) if error.kind() == RuleSetLoadErrorKind::CacheBusy));
    other.shutdown().await.expect("other shutdown");
    assert!(
        tokio::time::timeout(Duration::from_millis(20), work.shutdown())
            .await
            .is_err()
    );
    resume.send(()).expect("resume actual worker");
    work.shutdown().await.expect("retry joins worker");

    let next = RuleSetCacheWork::new(&config);
    assert!(
        next.execute(
            Operation::Load {
                source: source("next"),
                generation: 1
            },
            downloader,
            config
        )
        .await
        .is_ok()
    );
    next.shutdown().await.expect("next shutdown");
}

#[tokio::test]
async fn cancelled_admission_cannot_release_two_existing_operations() {
    let cache = TempDir::new().expect("cache");
    let config = config(&cache);
    let work = Arc::new(RuleSetCacheWork::new(&config));
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let downloader = Arc::new(ControlledDownloader {
        entered: sender,
        proceed: Semaphore::new(0),
    });
    let first = launch(&work, &downloader, &config, "first");
    entered(&mut receiver).await;
    let second = launch(&work, &downloader, &config, "second");
    entered(&mut receiver).await;
    let third = launch(&work, &downloader, &config, "third");
    assert!(
        tokio::time::timeout(Duration::from_millis(20), receiver.recv())
            .await
            .is_err()
    );
    third.abort();
    assert!(matches!(third.await, Err(error) if error.is_cancelled()));
    let fourth = launch(&work, &downloader, &config, "fourth");
    assert!(
        tokio::time::timeout(Duration::from_millis(20), receiver.recv())
            .await
            .is_err()
    );
    downloader.proceed.add_permits(3);
    assert!(first.await.expect("first join").is_ok());
    assert!(second.await.expect("second join").is_ok());
    entered(&mut receiver).await;
    assert!(fourth.await.expect("fourth join").is_ok());
    work.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn excessive_or_duplicate_declarations_fail_before_fetch() {
    let cache = TempDir::new().expect("cache");
    let config = config(&cache);
    let work = RuleSetCacheWork::new(&config);
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let downloader = Arc::new(ControlledDownloader {
        entered: sender,
        proceed: Semaphore::new(0),
    });
    let sources = (0..65)
        .map(|index| source(&format!("source{index}")))
        .collect();
    let result = work
        .execute(
            Operation::Materialize {
                sources,
                generation: 1,
            },
            Arc::clone(&downloader),
            config.clone(),
        )
        .await;
    assert!(matches!(result, Err(error) if error.kind() == RuleSetLoadErrorKind::CacheLimit));
    let sources = vec![source("duplicate"), source("duplicate")];
    let result = work
        .execute(
            Operation::Materialize {
                sources,
                generation: 1,
            },
            downloader,
            config,
        )
        .await;
    assert!(matches!(result, Err(error) if error.kind() == RuleSetLoadErrorKind::RegistryCompile));
    assert!(receiver.try_recv().is_err());
    work.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn reaped_failure_stays_visible_while_shutdown_joins_another_worker() {
    let cache = TempDir::new().expect("cache");
    let config = config(&cache);
    let work = Arc::new(RuleSetCacheWork::new(&config));
    let (sender, _receiver) = mpsc::unbounded_channel();
    let downloader = Arc::new(ControlledDownloader {
        entered: sender,
        proceed: Semaphore::new(2),
    });
    let (entered, ready) = oneshot::channel();
    let (resume, wait) = std::sync::mpsc::channel();
    work.directory.pause_next_worker(entered, wait);
    let first = launch(&work, &downloader, &config, "first");
    ready.await.expect("worker owns lease");
    let failed = work
        .execute(
            Operation::Load {
                source: source("panic"),
                generation: 1,
            },
            Arc::new(PanickingDownloader),
            config.clone(),
        )
        .await;
    assert!(matches!(failed, Err(error) if error.kind() == RuleSetLoadErrorKind::Task));
    assert!(
        launch(&work, &downloader, &config, "later")
            .await
            .expect("later join")
            .is_ok()
    );
    first.abort();
    assert!(matches!(first.await, Err(error) if error.is_cancelled()));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), work.shutdown())
            .await
            .is_err()
    );
    resume.send(()).expect("resume actual worker");
    assert_eq!(
        work.shutdown().await.expect_err("retained failure").kind(),
        RuleSetLoadErrorKind::Task
    );
    assert_eq!(
        work.shutdown().await.expect_err("sticky failure").kind(),
        RuleSetLoadErrorKind::Task
    );
    let next = RuleSetCacheWork::new(&config);
    assert!(
        next.execute(
            Operation::Load {
                source: source("next"),
                generation: 1
            },
            downloader,
            config
        )
        .await
        .is_ok()
    );
    next.shutdown().await.expect("next shutdown");
}

#[tokio::test]
async fn aggregate_excess_never_exposes_a_partial_initial_snapshot() {
    use ferrum2_rule::srs::{SrsDecodeLimits, decode_srs};
    let admitted = decode_srs(Cursor::new(AI), SrsDecodeLimits::default())
        .unwrap()
        .compile()
        .unwrap();
    let usage = admitted.resource_usage();
    let cache = TempDir::new().unwrap();
    let config = config(&cache);
    let mut work = RuleSetCacheWork::new(&config);
    work.snapshot_limits = ferrum2_rule::RuleEngineSnapshotLimits::new(
        usage.entries(),
        usage.expanded_bytes().max(1),
        usage.keyword_bytes().max(1),
    )
    .unwrap();
    let (sender, _receiver) = mpsc::unbounded_channel();
    let downloader = Arc::new(ControlledDownloader {
        entered: sender,
        proceed: Semaphore::new(2),
    });
    let result = work
        .execute(
            Operation::Materialize {
                sources: vec![source("first"), source("second")],
                generation: 1,
            },
            Arc::clone(&downloader),
            config.clone(),
        )
        .await;
    assert!(matches!(result, Err(error) if error.kind() == RuleSetLoadErrorKind::CacheLimit));
    work.shutdown().await.unwrap();
    // Individually committed resources remain usable, but no Materialized output
    // escaped when the complete declaration cohort could not be admitted.
    let offline = RuleSetCacheWork::new(&config);
    let result = offline
        .execute(
            Operation::Load {
                source: source("first"),
                generation: 2,
            },
            downloader,
            RuleSetLoaderConfig::new(cache.path().to_owned(), Duration::from_millis(5), 2).unwrap(),
        )
        .await;
    assert!(
        matches!(result, Ok(OperationOutput::Loaded(value)) if value.disposition == RuleSetLoadDisposition::OfflineCache)
    );
    offline.shutdown().await.unwrap();
}

#[tokio::test]
async fn aggregate_rejected_refresh_preserves_cache_bytes_and_live_snapshot() {
    use ferrum2_rule::{MatchSetBuilder, RuleEngineSnapshotBuilder, RuleEngineSnapshotLimits};
    let cache = TempDir::new().unwrap();
    let config = config(&cache);
    let work = RuleSetCacheWork::new(&config);
    let (sender, _receiver) = mpsc::unbounded_channel();
    let downloader = Arc::new(ControlledDownloader {
        entered: sender,
        proceed: Semaphore::new(2),
    });
    work.execute(
        Operation::Load {
            source: source("item"),
            generation: 1,
        },
        Arc::clone(&downloader),
        config.clone(),
    )
    .await
    .unwrap();
    let container = std::fs::read_dir(cache.path())
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "frs-cache")
        })
        .unwrap()
        .path();
    let before = std::fs::read(&container).unwrap();
    // A compatible complete old registry with deliberately tight admission.
    // Its cache may contain a newer independently committed complete resource.
    let mut set = MatchSetBuilder::new();
    set.add_exact_domain("old.example").unwrap();
    set.add_domain_suffix("old.example").unwrap();
    set.add_domain_keyword("old").unwrap();
    let mut builder = RuleEngineSnapshotBuilder::with_limits(
        1,
        RuleEngineSnapshotLimits::new(3, 64, 16).unwrap(),
    );
    let set = builder.add_match_set(set.build().unwrap()).unwrap();
    let rule_set = builder.add_rule_set("item", set).unwrap();
    let registry = Arc::new(RuleEngineRegistry::new(builder.build().unwrap()));
    let current = registry.snapshot();
    let result = work
        .execute(
            Operation::Refresh {
                source: source("item"),
                registry: Arc::clone(&registry),
                rule_set,
            },
            downloader,
            config,
        )
        .await
        .unwrap();
    assert!(matches!(
        result,
        OperationOutput::Refreshed(RuleSetRefreshOutcome::RetainedCache(
            RuleSetLoadDisposition::StaleCache
        ))
    ));
    assert!(Arc::ptr_eq(&current, &registry.snapshot()));
    assert_eq!(std::fs::read(container).unwrap(), before);
    work.shutdown().await.unwrap();
}
