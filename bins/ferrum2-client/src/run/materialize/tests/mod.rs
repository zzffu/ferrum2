use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::str::FromStr as _;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use ferrum2_config::RouteAction;
use ferrum2_core::TargetAddr;
use ferrum2_dns::{
    ApplicationResolver, ApplicationResolverAdapter, DnsError, DnsPolicyQuery, DnsPolicyStep,
    DnsStrategy, FixedEndpointMaterializeError, TaggedResolver,
};
use ferrum2_rule::{Network, RouteMetadata, RouteProgramAction};
use ferrum2_ruleset::{
    RuleSetDownloadError, RuleSetDownloadErrorKind, RuleSetDownloadFuture, RuleSetDownloadMode,
    RuleSetDownloadRequest, RuleSetDownloadResolver, RuleSetDownloadResponse,
    RuleSetHostResolveOutcome, RuleSetHostResolverKind, RuleSetLoadDisposition,
    RuleSetLoadErrorKind, RuleSetRefreshOutcome,
};
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener as TokioTcpListener, UdpSocket};
use tokio::sync::oneshot;

use super::outcome::classify_rule_set_load_error_kind;
use super::ruleset::{
    AbortRuleSetBridge, RuleSetBridgeIo, RuleSetBridgeTasks, refresh_rule_set_result,
    rule_set_host_resolve_observer,
};
use super::*;

const ADS_SRS: &[u8] = include_bytes!("../../../../../../tests/fixtures/srs/ads.srs");
const AI_SRS: &[u8] = include_bytes!("../../../../../../tests/fixtures/srs/ai.srs");
const CN_SRS: &[u8] = include_bytes!("../../../../../../tests/fixtures/srs/cn.srs");
const CNIP_SRS: &[u8] = include_bytes!("../../../../../../tests/fixtures/srs/cnip.srs");
static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug, Eq, PartialEq)]
struct SeenDownload {
    mode: RuleSetDownloadMode,
    detour: Option<Vec<usize>>,
}

struct RecordingDownloader {
    fail: bool,
    fixture_set: bool,
    seen: Mutex<Vec<SeenDownload>>,
}

impl RecordingDownloader {
    fn success() -> Self {
        Self {
            fail: false,
            fixture_set: false,
            seen: Mutex::new(Vec::new()),
        }
    }

    fn failure() -> Self {
        Self {
            fail: true,
            fixture_set: false,
            seen: Mutex::new(Vec::new()),
        }
    }

    fn fixture_set() -> Self {
        Self {
            fail: false,
            fixture_set: true,
            seen: Mutex::new(Vec::new()),
        }
    }

    fn seen(&self) -> Vec<SeenDownload> {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl RuleSetDownloader for RecordingDownloader {
    fn fetch(&self, request: RuleSetDownloadRequest) -> RuleSetDownloadFuture<'_> {
        let body = if self.fixture_set {
            match request.url().rsplit('/').next() {
                Some("ads.srs") => ADS_SRS,
                Some("ai.srs") => AI_SRS,
                Some("cn.srs") => CN_SRS,
                Some("cnip.srs") => CNIP_SRS,
                _ => &[],
            }
        } else {
            ADS_SRS
        };
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(SeenDownload {
                mode: request.mode(),
                detour: request.detour().map(|plan| plan.hops().to_vec()),
            });
        let fail = self.fail;
        Box::pin(async move {
            if fail {
                Err(RuleSetDownloadError::new(RuleSetDownloadErrorKind::Connect))
            } else {
                Ok(RuleSetDownloadResponse::downloaded(
                    Box::new(body),
                    None,
                    None,
                ))
            }
        })
    }
}

struct TestConfig {
    path: PathBuf,
    cache_dir: PathBuf,
}

impl TestConfig {
    fn new(source: impl FnOnce(&str) -> String) -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "ferrum2-client-materialize-{}-{id}",
            std::process::id()
        ));
        let path = base.with_extension("toml");
        let cache_dir = base.with_extension("cache");
        let cache = cache_dir.to_string_lossy().replace('\\', "/");
        std::fs::write(&path, source(&cache)).expect("write materializer test config");
        Self { path, cache_dir }
    }
}

impl Drop for TestConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir_all(&self.cache_dir);
    }
}

fn reserve_address() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve address");
    listener.local_addr().expect("reserved address")
}

mod endpoint;
mod ruleset;
