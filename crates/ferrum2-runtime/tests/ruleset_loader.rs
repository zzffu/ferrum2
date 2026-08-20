use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use ferrum2_core::CanonicalDomain;
use ferrum2_core::route::compile_egress_plans_with_roots;
use ferrum2_core::selector::{SelectorDefinition, TaggedInbound, TaggedOutbound};
use ferrum2_dns::DnsServerId;
use ferrum2_rule::RuleEngineRegistry;
use ferrum2_runtime::{
    RuleSetCacheName, RuleSetDownloadError, RuleSetDownloadErrorKind, RuleSetDownloadFuture,
    RuleSetDownloadRequest, RuleSetDownloadResolver, RuleSetDownloadResponse, RuleSetDownloader,
    RuleSetLoadDisposition, RuleSetLoadErrorKind, RuleSetLoader, RuleSetLoaderConfig,
    RuleSetRefreshOutcome, RuleSetRefreshService, RuleSetRemoteSource,
    materialize_rule_set_snapshot,
};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;

const ADS_SRS: &[u8] = include_bytes!("../../../tests/fixtures/srs/ads.srs");
const AI_SRS: &[u8] = include_bytes!("../../../tests/fixtures/srs/ai.srs");
const CN_SRS: &[u8] = include_bytes!("../../../tests/fixtures/srs/cn.srs");
const CNIP_SRS: &[u8] = include_bytes!("../../../tests/fixtures/srs/cnip.srs");

#[derive(Clone, Debug, Eq, PartialEq)]
struct SeenRequest {
    resolver: RuleSetDownloadResolver,
    conditional: bool,
    max_redirects: u8,
    detour_hops: Option<Vec<usize>>,
}

enum FakeResult {
    Download(Vec<u8>),
    NotModified,
    Error(RuleSetDownloadErrorKind),
}

#[derive(Clone)]
struct FakeDownloader {
    results: Arc<Mutex<VecDeque<FakeResult>>>,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
}

impl FakeDownloader {
    fn new(results: impl IntoIterator<Item = FakeResult>) -> Self {
        Self {
            results: Arc::new(Mutex::new(results.into_iter().collect())),
            seen: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn seen(&self) -> Vec<SeenRequest> {
        lock(&self.seen).clone()
    }
}

impl RuleSetDownloader for FakeDownloader {
    fn fetch(&self, request: RuleSetDownloadRequest) -> RuleSetDownloadFuture<'_> {
        let result = lock(&self.results).pop_front().expect("fake result");
        lock(&self.seen).push(SeenRequest {
            resolver: request.resolver(),
            conditional: request.if_none_match().is_some() || request.if_modified_since().is_some(),
            max_redirects: request.max_redirects(),
            detour_hops: request.detour().map(|detour| detour.hops().to_vec()),
        });
        Box::pin(async move {
            match result {
                FakeResult::Download(bytes) => {
                    let capacity = bytes.len().max(1);
                    let (mut writer, reader) = tokio::io::duplex(capacity);
                    tokio::spawn(async move {
                        writer.write_all(&bytes).await.expect("write fake body");
                    });
                    Ok(RuleSetDownloadResponse::downloaded(
                        Box::new(reader),
                        Some("fixture-etag".into()),
                        Some("Thu, 20 Aug 2026 00:00:00 GMT".into()),
                    ))
                }
                FakeResult::NotModified => Ok(RuleSetDownloadResponse::not_modified()),
                FakeResult::Error(kind) => Err(RuleSetDownloadError::new(kind)),
            }
        })
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn config(cache: &TempDir) -> RuleSetLoaderConfig {
    RuleSetLoaderConfig::new(cache.path().to_path_buf(), Duration::from_secs(2), 4)
        .expect("loader config")
}

fn source() -> ferrum2_runtime::RuleSetRemoteSource {
    RuleSetRemoteSource::new(
        RuleSetCacheName::new("ai").expect("cache name"),
        "https://rules.example/ai.srs",
        RuleSetDownloadResolver::DnsServer(DnsServerId::new(7)),
        None,
        Some(Duration::from_secs(60)),
    )
    .expect("source")
}

#[tokio::test]
async fn first_download_is_strictly_compiled_cached_and_conditionally_reused() {
    let cache = TempDir::new().expect("cache");
    let downloader = FakeDownloader::new([
        FakeResult::Download(AI_SRS.to_vec()),
        FakeResult::NotModified,
    ]);
    let loader = RuleSetLoader::new(config(&cache), downloader.clone());

    let first = loader.load(&source(), 11).await.expect("first load");
    assert_eq!(first.disposition(), RuleSetLoadDisposition::Downloaded);
    assert_eq!(first.generation(), 11);
    assert_eq!(first.srs_version(), 2);
    assert!(first.capabilities().domain_keyword);
    assert!(cache.path().join("ai.srs").is_file());
    assert!(cache.path().join("ai.meta").is_file());

    let second = loader.load(&source(), 12).await.expect("conditional load");
    assert_eq!(second.disposition(), RuleSetLoadDisposition::NotModified);
    assert_eq!(second.generation(), 11);
    assert_eq!(
        downloader.seen(),
        vec![
            SeenRequest {
                resolver: RuleSetDownloadResolver::DnsServer(DnsServerId::new(7)),
                conditional: false,
                max_redirects: 4,
                detour_hops: None,
            },
            SeenRequest {
                resolver: RuleSetDownloadResolver::DnsServer(DnsServerId::new(7)),
                conditional: true,
                max_redirects: 4,
                detour_hops: None,
            },
        ]
    );
}

#[tokio::test]
async fn each_download_captures_the_current_selector_detour_snapshot() {
    let cache = TempDir::new().expect("cache");
    let downloader = FakeDownloader::new([
        FakeResult::Download(AI_SRS.to_vec()),
        FakeResult::Download(AI_SRS.to_vec()),
    ]);
    let (control, mut roots) = compile_egress_plans_with_roots(
        &[TaggedInbound::new("entry", 0)],
        &[
            TaggedOutbound::new("first", 0),
            TaggedOutbound::new("second", 1),
        ],
        &[],
        &[SelectorDefinition::new(
            "download",
            vec!["first", "second"],
            Some("first"),
        )],
        &["download"],
    )
    .expect("selector graph");
    let source = RuleSetRemoteSource::new(
        RuleSetCacheName::new("dynamic").expect("cache name"),
        "https://rules.example/dynamic.srs",
        RuleSetDownloadResolver::System,
        Some(roots.remove(0)),
        None,
    )
    .expect("source");
    let loader = RuleSetLoader::new(config(&cache), downloader.clone());

    loader.load(&source, 1).await.expect("first download");
    control
        .switch("download", "second")
        .expect("switch download selector");
    loader.load(&source, 2).await.expect("second download");

    let seen = downloader.seen();
    assert_eq!(seen[0].detour_hops.as_deref(), Some([0].as_slice()));
    assert_eq!(seen[1].detour_hops.as_deref(), Some([1].as_slice()));
}

#[tokio::test]
async fn four_pinned_binary_rule_sets_load_into_one_publishable_snapshot() {
    let cache = TempDir::new().expect("cache");
    let fixtures = [ADS_SRS, AI_SRS, CN_SRS, CNIP_SRS];
    let downloader = FakeDownloader::new(
        fixtures
            .into_iter()
            .map(|fixture| FakeResult::Download(fixture.to_vec())),
    );
    let loader = RuleSetLoader::new(config(&cache), downloader);
    let sources = ["ads", "ai", "cn", "cnip"]
        .into_iter()
        .map(|name| {
            RuleSetRemoteSource::new(
                RuleSetCacheName::new(name).expect("cache name"),
                &format!("https://rules.example/{name}.srs"),
                RuleSetDownloadResolver::System,
                None,
                None,
            )
            .expect("source")
        })
        .collect::<Vec<_>>();

    let materialized = materialize_rule_set_snapshot(&loader, &sources, 17)
        .await
        .expect("four RuleSet snapshot");
    assert_eq!(materialized.snapshot().generation(), 17);
    assert_eq!(materialized.rule_set_ids().len(), 4);
    assert!(
        materialized
            .dispositions()
            .iter()
            .all(|value| *value == RuleSetLoadDisposition::Downloaded)
    );
    let snapshot = materialized.snapshot();
    let compiled = materialized
        .rule_set_ids()
        .iter()
        .map(|id| {
            let descriptor = snapshot.rule_set(*id).expect("RuleSet descriptor");
            snapshot
                .match_set(descriptor.match_set())
                .expect("compiled MatchSet")
        })
        .collect::<Vec<_>>();
    assert!(
        compiled[0].matches_domain(&CanonicalDomain::new("x.0.myikas.com").expect("ads probe"))
    );
    assert!(
        compiled[1].matches_domain(&CanonicalDomain::new("api.openai.example").expect("ai probe"))
    );
    assert!(compiled[2].matches_domain(&CanonicalDomain::new("x.0.zone").expect("cn probe")));
    assert!(compiled[3].matches_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 8, 8))));
    assert!(!compiled[3].matches_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

#[tokio::test]
async fn offline_or_invalid_refresh_keeps_the_last_complete_cache() {
    let cache = TempDir::new().expect("cache");
    let initial = FakeDownloader::new([FakeResult::Download(AI_SRS.to_vec())]);
    RuleSetLoader::new(config(&cache), initial)
        .load(&source(), 3)
        .await
        .expect("seed cache");
    let original = std::fs::read(cache.path().join("ai.srs")).expect("cached SRS");

    let offline = FakeDownloader::new([FakeResult::Error(RuleSetDownloadErrorKind::Resolution)]);
    let stale = RuleSetLoader::new(config(&cache), offline)
        .load(&source(), 4)
        .await
        .expect("offline cache");
    assert_eq!(stale.disposition(), RuleSetLoadDisposition::OfflineCache);
    assert_eq!(
        stale.degraded_failure(),
        Some(RuleSetLoadErrorKind::Download(
            RuleSetDownloadErrorKind::Resolution
        ))
    );
    assert_eq!(stale.generation(), 3);

    let invalid = FakeDownloader::new([FakeResult::Download(b"not an SRS".to_vec())]);
    let stale = RuleSetLoader::new(config(&cache), invalid)
        .load(&source(), 5)
        .await
        .expect("invalid refresh retains cache");
    assert_eq!(stale.disposition(), RuleSetLoadDisposition::StaleCache);
    assert!(matches!(
        stale.degraded_failure(),
        Some(RuleSetLoadErrorKind::Decode(_))
    ));
    assert_eq!(
        std::fs::read(cache.path().join("ai.srs")).expect("cached SRS"),
        original
    );
    let mut cache_files: Vec<_> = std::fs::read_dir(cache.path())
        .expect("cache directory")
        .map(|entry| entry.expect("cache entry").file_name())
        .collect();
    cache_files.sort();
    assert_eq!(
        cache_files,
        [
            std::ffi::OsString::from("ai.meta"),
            std::ffi::OsString::from("ai.srs")
        ]
    );
}

#[tokio::test]
async fn initial_snapshot_retains_each_degraded_cache_failure() {
    let cache = TempDir::new().expect("cache");
    RuleSetLoader::new(
        config(&cache),
        FakeDownloader::new([FakeResult::Download(AI_SRS.to_vec())]),
    )
    .load(&source(), 3)
    .await
    .expect("seed cache");

    let failure = RuleSetLoadErrorKind::Download(RuleSetDownloadErrorKind::Resolution);
    let loader = RuleSetLoader::new(
        config(&cache),
        FakeDownloader::new([FakeResult::Error(RuleSetDownloadErrorKind::Resolution)]),
    );
    let materialized = materialize_rule_set_snapshot(&loader, &[source()], 4)
        .await
        .expect("degraded cache is still a complete snapshot");
    assert_eq!(
        materialized.dispositions(),
        [RuleSetLoadDisposition::OfflineCache]
    );
    assert_eq!(materialized.degraded_failures(), [Some(failure)]);

    let (_snapshot, ids, dispositions, degraded_failures) = materialized.into_parts();
    assert_eq!(ids.len(), 1);
    assert_eq!(
        dispositions.as_ref(),
        [RuleSetLoadDisposition::OfflineCache]
    );
    assert_eq!(degraded_failures.as_ref(), [Some(failure)]);
}

#[tokio::test]
async fn startup_without_a_valid_cache_fails_closed() {
    let cache = TempDir::new().expect("cache");
    let downloader = FakeDownloader::new([FakeResult::Error(RuleSetDownloadErrorKind::Resolution)]);
    let error = RuleSetLoader::new(config(&cache), downloader)
        .load(&source(), 1)
        .await
        .expect_err("no fallback cache");
    assert_eq!(
        error.kind(),
        RuleSetLoadErrorKind::Download(RuleSetDownloadErrorKind::Resolution)
    );
}

#[tokio::test]
async fn corrupt_or_incomplete_cache_is_never_an_offline_fallback() {
    let cache = TempDir::new().expect("cache");
    let initial = FakeDownloader::new([FakeResult::Download(AI_SRS.to_vec())]);
    RuleSetLoader::new(config(&cache), initial)
        .load(&source(), 3)
        .await
        .expect("seed cache");

    std::fs::write(cache.path().join("ai.srs"), b"corrupt").expect("corrupt cache");
    let offline = FakeDownloader::new([FakeResult::Error(RuleSetDownloadErrorKind::Resolution)]);
    let error = RuleSetLoader::new(config(&cache), offline)
        .load(&source(), 4)
        .await
        .expect_err("corrupt cache must not be served");
    assert_eq!(error.kind(), RuleSetLoadErrorKind::CacheDigest);

    std::fs::remove_file(cache.path().join("ai.meta")).expect("remove metadata");
    let not_modified = FakeDownloader::new([FakeResult::NotModified]);
    let error = RuleSetLoader::new(config(&cache), not_modified)
        .load(&source(), 4)
        .await
        .expect_err("an incomplete cache cannot satisfy 304");
    assert_eq!(error.kind(), RuleSetLoadErrorKind::CacheMetadata);
}

#[tokio::test]
async fn complete_snapshot_refreshes_atomically_and_failures_keep_generation() {
    let cache = TempDir::new().expect("cache");
    let downloader = FakeDownloader::new([
        FakeResult::Download(AI_SRS.to_vec()),
        FakeResult::Download(AI_SRS.to_vec()),
        FakeResult::Download(b"not an SRS".to_vec()),
        FakeResult::Error(RuleSetDownloadErrorKind::Body),
        FakeResult::NotModified,
    ]);
    let loader = Arc::new(RuleSetLoader::new(config(&cache), downloader));
    let declared = source();
    let materialized = materialize_rule_set_snapshot(&loader, std::slice::from_ref(&declared), 1)
        .await
        .expect("initial snapshot");
    assert_eq!(materialized.snapshot().generation(), 1);
    assert_eq!(materialized.rule_set_ids().len(), 1);
    assert_eq!(
        materialized.dispositions(),
        [RuleSetLoadDisposition::Downloaded]
    );
    assert_eq!(materialized.degraded_failures(), [None]);
    let (snapshot, ids, dispositions, degraded_failures) = materialized.into_parts();
    assert_eq!(dispositions.as_ref(), [RuleSetLoadDisposition::Downloaded]);
    assert_eq!(degraded_failures.as_ref(), [None]);
    let ids = ids.into_vec();
    let registry = Arc::new(RuleEngineRegistry::new(snapshot));
    let service = RuleSetRefreshService::new(
        Arc::clone(&loader),
        Arc::clone(&registry),
        vec![declared],
        ids.clone(),
    )
    .expect("refresh service");

    assert_eq!(
        service.refresh_once(0).await,
        RuleSetRefreshOutcome::Updated {
            previous_generation: 1,
            generation: 2,
        }
    );
    assert_eq!(registry.generation(), 2);
    assert_eq!(
        registry
            .snapshot()
            .rule_set(ids[0])
            .expect("stable ID")
            .tag(),
        "ai"
    );

    assert_eq!(
        service.refresh_once(0).await,
        RuleSetRefreshOutcome::RetainedCache(RuleSetLoadDisposition::StaleCache)
    );
    assert_eq!(registry.generation(), 2);
    assert_eq!(
        service.refresh_once(0).await,
        RuleSetRefreshOutcome::RetainedCache(RuleSetLoadDisposition::OfflineCache)
    );
    assert_eq!(registry.generation(), 2);
    assert_eq!(
        service.refresh_once(0).await,
        RuleSetRefreshOutcome::NotModified
    );
    assert_eq!(registry.generation(), 2);
}

#[tokio::test]
async fn capability_shape_change_never_replaces_the_cache_or_live_snapshot() {
    let cache = TempDir::new().expect("cache");
    let loader = Arc::new(RuleSetLoader::new(
        config(&cache),
        FakeDownloader::new([
            FakeResult::Download(AI_SRS.to_vec()),
            FakeResult::Download(CNIP_SRS.to_vec()),
        ]),
    ));
    let declared = source();
    let materialized = materialize_rule_set_snapshot(&loader, std::slice::from_ref(&declared), 1)
        .await
        .expect("initial domain snapshot");
    let (snapshot, ids, _, _) = materialized.into_parts();
    let ids = ids.into_vec();
    let registry = Arc::new(RuleEngineRegistry::new(snapshot));
    let service = RuleSetRefreshService::new(
        Arc::clone(&loader),
        Arc::clone(&registry),
        vec![declared],
        ids.clone(),
    )
    .expect("refresh service");

    assert_eq!(
        service.refresh_once(0).await,
        RuleSetRefreshOutcome::RetainedCache(RuleSetLoadDisposition::StaleCache)
    );
    assert_eq!(registry.generation(), 1);
    let current = registry.snapshot();
    let descriptor = current.rule_set(ids[0]).expect("stable RuleSet ID");
    let compiled = current
        .match_set(descriptor.match_set())
        .expect("old compiled domain set");
    assert!(
        compiled
            .matches_domain(&CanonicalDomain::new("api.openai.example").expect("old domain probe"))
    );
    assert!(!compiled.matches_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 8, 8))));
    assert_eq!(
        std::fs::read(cache.path().join("ai.srs")).expect("retained cached SRS"),
        AI_SRS
    );
}

#[test]
fn source_and_cache_paths_reject_implicit_or_unsafe_inputs() {
    for name in ["", ".", "..", "../escape", "has/slash"] {
        assert_eq!(
            RuleSetCacheName::new(name).expect_err("unsafe name").kind(),
            RuleSetLoadErrorKind::InvalidCacheName
        );
    }
    let name = RuleSetCacheName::new("safe-name").expect("safe name");
    for url in [
        "http://rules.example/a.srs",
        "https://127.0.0.1/a.srs",
        "https://user@rules.example/a.srs",
        "https://rules.example/a.srs#fragment",
    ] {
        assert_eq!(
            RuleSetRemoteSource::new(
                name.clone(),
                url,
                RuleSetDownloadResolver::System,
                None,
                None,
            )
            .expect_err("invalid source")
            .kind(),
            RuleSetLoadErrorKind::InvalidSource
        );
    }
    assert_eq!(
        RuleSetLoaderConfig::new(PathBuf::new(), Duration::from_secs(1), 1)
            .expect_err("empty cache path")
            .kind(),
        RuleSetLoadErrorKind::InvalidLoaderConfig
    );
}
