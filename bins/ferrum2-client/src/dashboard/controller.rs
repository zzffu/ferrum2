use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use ferrum2_config::PreparedClientV2;
use ferrum2_dashboard::Dashboard;
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::run::management::{ControlSlot, Management};
use crate::run::{RunError, run_generation};

use super::config::{ConfigStore, catalog};

pub(super) enum RequestKind {
    Config,
    Command(Value),
}
pub(super) struct ControlRequest {
    pub(super) kind: RequestKind,
    pub(super) reply: oneshot::Sender<Result<Value, &'static str>>,
    pub(super) submitted: Instant,
}

struct Generation {
    stop: watch::Sender<bool>,
    task: JoinHandle<Result<(), RunError>>,
}

pub(super) struct Controller {
    config: ConfigStore,
    dashboard: Dashboard,
    controls: ControlSlot,
    log_level: Arc<std::sync::atomic::AtomicU8>,
    generation: u64,
    active: Option<Generation>,
    running_revision: Option<String>,
    cleanup_failed: bool,
}

impl Controller {
    pub(super) fn new(
        path: PathBuf,
        dashboard: Dashboard,
        log_level: Arc<std::sync::atomic::AtomicU8>,
    ) -> Result<Self, &'static str> {
        Ok(Self {
            config: ConfigStore::open(path).map_err(|error| error.code())?,
            dashboard,
            log_level,
            controls: Arc::new(RwLock::new(None)),
            generation: 0,
            active: None,
            running_revision: None,
            cleanup_failed: false,
        })
    }

    pub(super) async fn run(
        mut self,
        mut requests: mpsc::Receiver<ControlRequest>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), &'static str> {
        if let Err(code) = self.start_disk() {
            self.fail(code);
        }
        let mut reap = tokio::time::interval(Duration::from_millis(100));
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                _ = reap.tick() => self.reap_finished().await,
                request = requests.recv() => {
                    let Some(request) = request else { break; };
                    if request.reply.is_closed() { continue; }
                    if request.submitted.elapsed() > Duration::from_secs(30) {
                        let _ = request.reply.send(Err("dashboard.expired"));
                        continue;
                    }
                    self.reap_finished().await;
                    let result = match request.kind {
                        RequestKind::Config => self.configuration(),
                        RequestKind::Command(command) => self.command(command, &mut shutdown).await.map(|result| json!({"result":result})),
                    };
                    let _ = request.reply.send(result);
                }
            }
        }
        requests.close();
        while let Ok(request) = requests.try_recv() {
            let _ = request.reply.send(Err("dashboard.stopped"));
        }
        self.stop().await
    }

    fn configuration(&self) -> Result<Value, &'static str> {
        let document = self.config.read().map_err(|error| error.code())?;
        let running = self.dashboard.snapshot()["state"] == "running";
        Ok(json!({
            "source": document.source,
            "revision": document.revision,
            "running_revision": if running { self.running_revision.as_ref() } else { None },
        }))
    }

    fn start_disk(&mut self) -> Result<(), &'static str> {
        let document = self.config.read().map_err(|error| error.code())?;
        let prepared = self
            .config
            .validate(&document.source)
            .map_err(|error| error.code())?;
        self.start(prepared, &document.source, document.revision.clone())
    }

    fn start(
        &mut self,
        prepared: PreparedClientV2,
        source: &str,
        revision: String,
    ) -> Result<(), &'static str> {
        if self.active.is_some() {
            return Err("runtime.conflict");
        }
        if self.cleanup_failed {
            return Err("runtime.cleanup_failed");
        }
        if prepared.has_tun() && !crate::cli::tun_target_supported() {
            return Err("config.tun_unsupported");
        }
        let catalog = catalog(source).map_err(|error| error.code())?;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or("runtime.generation_exhausted")?;
        self.dashboard.start_generation(self.generation);
        self.dashboard.set_catalog(catalog);
        self.dashboard.set_runtime("starting", None);
        self.running_revision = Some(revision);
        let management = Management {
            dashboard: self.dashboard.clone(),
            controls: Arc::clone(&self.controls),
            log_level: Arc::clone(&self.log_level),
        };
        let (stop, mut stopped) = watch::channel(false);
        let task = tokio::spawn(async move {
            run_generation(
                prepared,
                async move {
                    if !*stopped.borrow() {
                        let _ = stopped.changed().await;
                    }
                },
                Some(management),
            )
            .await
        });
        self.active = Some(Generation { stop, task });
        Ok(())
    }

    async fn reap_finished(&mut self) {
        if !self
            .active
            .as_ref()
            .is_some_and(|active| active.task.is_finished())
        {
            return;
        }
        let active = self.active.take().expect("finished generation exists");
        let result = active.task.await;
        self.retire();
        match result {
            Ok(Ok(())) => self.dashboard.set_runtime("stopped", None),
            Ok(Err(error)) => {
                self.cleanup_failed |= error == RunError::ShutdownCleanup;
                self.fail(error.diagnostic_category());
            }
            Err(_) => {
                self.cleanup_failed = true;
                self.fail("runtime.join");
            }
        }
    }

    async fn stop(&mut self) -> Result<(), &'static str> {
        let Some(active) = self.active.take() else {
            return if self.cleanup_failed {
                Err("runtime.cleanup_failed")
            } else {
                Ok(())
            };
        };
        self.dashboard.set_runtime("stopping", None);
        *self
            .controls
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        let _ = active.stop.send(true);
        // Never timeout/drop the generation future: it owns transitive cleanup.
        let result = active.task.await;
        self.retire();
        match result {
            Ok(Ok(())) => {
                self.dashboard.set_runtime("stopped", None);
                Ok(())
            }
            Ok(Err(error)) => {
                self.cleanup_failed |= error == RunError::ShutdownCleanup;
                self.fail(error.diagnostic_category());
                Err(error.diagnostic_category())
            }
            Err(_) => {
                self.cleanup_failed = true;
                self.fail("runtime.join");
                Err("runtime.join")
            }
        }
    }

    fn retire(&mut self) {
        self.running_revision = None;
        *self
            .controls
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        self.dashboard.set_domains(json!({"capabilities":[]}));
        self.dashboard.set_resources(json!({}));
    }

    fn fail(&self, code: &'static str) {
        self.dashboard.set_runtime("failed", Some(code));
        self.dashboard
            .record_log(json!({"level":"ERROR","event":"runtime","reason":code}));
    }

    async fn command(
        &mut self,
        command: Value,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<Value, &'static str> {
        if *shutdown.borrow() {
            return Err("dashboard.stopped");
        }
        let action = command
            .get("action")
            .and_then(Value::as_str)
            .ok_or("dashboard.action")?;
        let generation = command
            .get("generation")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or("dashboard.generation")?;
        if generation != self.generation {
            return Err("dashboard.generation_conflict");
        }
        match action {
            "runtime.start" => {
                self.start_disk()?;
                Ok(json!({"state":"starting"}))
            }
            "runtime.stop" => {
                self.stop().await?;
                Ok(json!({"state":"stopped"}))
            }
            "runtime.restart" => {
                let document = self.config.read().map_err(|error| error.code())?;
                let prepared = self
                    .config
                    .validate(&document.source)
                    .map_err(|error| error.code())?;
                self.stop().await?;
                if *shutdown.borrow() {
                    return Err("dashboard.stopped");
                }
                self.start(prepared, &document.source, document.revision.clone())?;
                Ok(json!({"state":"starting"}))
            }
            "connections.close" => {
                let ids = command
                    .get("ids")
                    .and_then(Value::as_array)
                    .ok_or("connections.ids")?;
                if ids.len() > 4096 {
                    return Err("connections.limit");
                }
                let ids = ids
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .filter(|id| id.len() <= 64)
                            .map(str::to_owned)
                            .ok_or("connections.id")
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(json!({"requested":self.dashboard.close_connections(&ids)}))
            }
            "connections.close_all" => {
                Ok(json!({"requested":self.dashboard.close_all_connections()}))
            }
            "config.validate" => {
                let source = source(&command)?;
                let prepared = self.config.validate(source).map_err(|error| error.code())?;
                if prepared.has_tun() && !crate::cli::tun_target_supported() {
                    return Err("config.tun_unsupported");
                }
                Ok(json!({"valid":true,"materialized":false}))
            }
            "config.save" | "config.apply" => {
                let source = source(&command)?;
                let revision = command
                    .get("revision")
                    .and_then(Value::as_str)
                    .ok_or("config.revision")?;
                let prepared = self.config.validate(source).map_err(|error| error.code())?;
                if prepared.has_tun() && !crate::cli::tun_target_supported() {
                    return Err("config.tun_unsupported");
                }
                let document = self
                    .config
                    .save(source, revision)
                    .map_err(|error| error.code())?;
                if action == "config.apply" {
                    self.stop().await?;
                    if *shutdown.borrow() {
                        return Err("dashboard.stopped");
                    }
                    self.start(prepared, &document.source, document.revision.clone())?;
                }
                Ok(
                    json!({"revision":document.revision,"state":if action == "config.apply" {"starting"} else {"saved"}}),
                )
            }
            "diagnostics.export" => {
                let snapshot = self.dashboard.snapshot();
                Ok(
                    json!({"version":env!("CARGO_PKG_VERSION"),"generation":snapshot["generation"],
                    "state":snapshot["state"],"error":snapshot["error"],"traffic":snapshot["traffic"],
                    "resources":snapshot["resources"],"process":snapshot["process"],"logs":snapshot["logs"],
                    "metrics":snapshot["domains"]["metrics"]}),
                )
            }
            "selectors.select" | "outbounds.probe" | "routes.test" | "rulesets.refresh"
            | "dns.clear" | "dns.query" => {
                let control = self
                    .controls
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
                    .ok_or("runtime.unavailable")?;
                let result = {
                    let work = control.command(&command);
                    tokio::pin!(work);
                    tokio::select! {
                        biased;
                        _ = shutdown.changed() => Err("dashboard.stopped"),
                        result = &mut work => result,
                    }
                };
                // The command future's read lease is dropped before waiting for retirement.
                if *shutdown.borrow() {
                    control.shutdown().await;
                    return Err("dashboard.stopped");
                }
                let result = result?;
                self.dashboard.set_domains(control.snapshot());
                Ok(result)
            }
            _ => Err("dashboard.action"),
        }
    }
}

fn source(command: &Value) -> Result<&str, &'static str> {
    command
        .get("source")
        .and_then(Value::as_str)
        .ok_or("config.source")
}
