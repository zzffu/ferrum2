use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;

use super::process_support::{PROBE_TIMEOUT, env, first_line, json, probe_text};
use super::{PROFILE, REFERENCE_SHA256};

pub(super) struct HostedIdentity {
    pub(super) sha: String,
    pub(super) run_id: String,
    pub(super) run_attempt: String,
    pub(super) event: String,
    pub(super) image_version: String,
    pub(super) kernel: String,
    pub(super) cpu_model: String,
    pub(super) cpu_count: usize,
    pub(super) memory_kib: u64,
    pub(super) runner_temp_free_kib: u64,
    pub(super) nofile_soft: u64,
    pub(super) rustc: String,
    pub(super) cc: String,
    pub(super) linker: String,
}

impl HostedIdentity {
    pub(super) fn load(requested_sha: &str, output: &Path) -> Result<Self, String> {
        let environment = EnvironmentIdentity {
            github_actions: env("GITHUB_ACTIONS")?,
            runner_os: env("RUNNER_OS")?,
            runner_arch: env("RUNNER_ARCH")?,
            image_os: env("ImageOS")?,
            github_sha: env("GITHUB_SHA")?,
        };
        validate_environment(requested_sha, &environment)?;
        let head = probe_text(
            "checkout HEAD probe",
            "git",
            ["rev-parse", "HEAD"],
            PROBE_TIMEOUT,
        )?;
        if head.trim() != requested_sha {
            return Err("checkout HEAD does not match requested SHA".to_owned());
        }
        if !probe_text(
            "checkout status probe",
            "git",
            ["status", "--porcelain=v1"],
            PROBE_TIMEOUT,
        )?
        .is_empty()
        {
            return Err("checkout is dirty before generated writes".to_owned());
        }
        validate_output_path(output)?;
        let runner_temp_free_kib = validate_temp_free(output)?;
        let cpu_count = thread::available_parallelism()
            .map_err(|_| "logical CPU count is unavailable".to_owned())?
            .get();
        let (memory_kib, cpu_model) = linux_capacity()?;
        if cpu_count < 4 || memory_kib < 15_000_000 {
            return Err("host capacity is below M4-GHA-01".to_owned());
        }
        let nofile_soft = validate_nofile()?;
        let rustc = first_line(&probe_text(
            "Rust version probe",
            "rustc",
            ["--version"],
            PROBE_TIMEOUT,
        )?);
        if !rustc.starts_with("rustc 1.97.1 ") {
            return Err("Rust toolchain is not 1.97.1".to_owned());
        }
        let event = env("GITHUB_EVENT_NAME")?;
        if event != "push" && event != "workflow_dispatch" {
            return Err("hosted event is outside the performance profile".to_owned());
        }
        let run_id = env("GITHUB_RUN_ID")?;
        let run_attempt = env("GITHUB_RUN_ATTEMPT")?;
        if run_id.parse::<u64>().is_err() || run_attempt.parse::<u64>().is_err() {
            return Err("hosted run identity is malformed".to_owned());
        }
        Ok(Self {
            sha: requested_sha.to_owned(),
            run_id,
            run_attempt,
            event,
            image_version: env("ImageVersion")?,
            kernel: first_line(&probe_text(
                "kernel identity probe",
                "uname",
                ["-srvmo"],
                PROBE_TIMEOUT,
            )?),
            cpu_model,
            cpu_count,
            memory_kib,
            runner_temp_free_kib,
            nofile_soft,
            rustc,
            cc: first_line(&probe_text(
                "C compiler identity probe",
                "cc",
                ["--version"],
                PROBE_TIMEOUT,
            )?),
            linker: first_line(&probe_text(
                "linker identity probe",
                "ld",
                ["--version"],
                PROBE_TIMEOUT,
            )?),
        })
    }

    pub(super) fn json_fields(&self) -> String {
        format!(
            "\"profile\":{},\"sha\":{},\"run_id\":{},\"run_attempt\":{},\
             \"image_version\":{},\"kernel\":{},\"cpu_model\":{},\"cpu_count\":{},\
             \"memory_kib\":{},\"runner_temp_free_kib\":{},\"nofile_soft\":{},\
             \"event\":{},\"rustc\":{},\"cc\":{},\"linker\":{},\
             \"reference_sha256\":{}",
            json(PROFILE),
            json(&self.sha),
            json(&self.run_id),
            json(&self.run_attempt),
            json(&self.image_version),
            json(&self.kernel),
            json(&self.cpu_model),
            self.cpu_count,
            self.memory_kib,
            self.runner_temp_free_kib,
            self.nofile_soft,
            json(&self.event),
            json(&self.rustc),
            json(&self.cc),
            json(&self.linker),
            json(REFERENCE_SHA256),
        )
    }
}

pub(super) struct EnvironmentIdentity {
    pub(super) github_actions: String,
    pub(super) runner_os: String,
    pub(super) runner_arch: String,
    pub(super) image_os: String,
    pub(super) github_sha: String,
}

pub(super) fn validate_environment(
    requested_sha: &str,
    identity: &EnvironmentIdentity,
) -> Result<(), String> {
    if requested_sha.len() != 40
        || !requested_sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || identity.github_sha != requested_sha
    {
        return Err("SHA identity mismatch".to_owned());
    }
    if identity.github_actions != "true"
        || identity.runner_os != "Linux"
        || identity.runner_arch != "X64"
        || identity.image_os != "ubuntu24"
    {
        return Err("host identity mismatch".to_owned());
    }
    Ok(())
}

pub(super) fn validate_output_path(output: &Path) -> Result<(), String> {
    if output.exists() {
        return Err("output already exists".to_owned());
    }
    let runner_temp = PathBuf::from(env("RUNNER_TEMP")?);
    let root = runner_temp.join("m4");
    let root = root
        .canonicalize()
        .map_err(|_| "RUNNER_TEMP/m4 must exist".to_owned())?;
    let parent = output
        .parent()
        .ok_or_else(|| "output has no parent".to_owned())?
        .canonicalize()
        .map_err(|_| "output parent does not exist".to_owned())?;
    if !parent.starts_with(&root) || output.extension() != Some(OsStr::new("jsonl")) {
        return Err("output must be a new JSONL file below RUNNER_TEMP/m4".to_owned());
    }
    Ok(())
}

pub(super) fn validate_temp_free(output: &Path) -> Result<u64, String> {
    let parent = output.parent().expect("validated output parent");
    let result = probe_text(
        "runner-temp capacity probe",
        "df",
        [OsString::from("-Pk"), parent.as_os_str().to_owned()],
        PROBE_TIMEOUT,
    )?;
    let available = result
        .lines()
        .last()
        .and_then(|line| line.split_whitespace().nth(3))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| "runner-temp free capacity is malformed".to_owned())?;
    if available < 6_000_000 {
        return Err("runner-temp free capacity is below M4-GHA-01".to_owned());
    }
    Ok(available)
}

pub(super) fn linux_capacity() -> Result<(u64, String), String> {
    let meminfo = fs::read_to_string("/proc/meminfo")
        .map_err(|_| "Linux memory identity is unavailable".to_owned())?;
    let memory_kib = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:")?.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| "Linux memory identity is malformed".to_owned())?;
    let cpuinfo = fs::read_to_string("/proc/cpuinfo")
        .map_err(|_| "Linux CPU identity is unavailable".to_owned())?;
    let cpu_model = cpuinfo
        .lines()
        .find_map(|line| line.strip_prefix("model name\t: "))
        .ok_or_else(|| "Linux CPU model is unavailable".to_owned())?
        .to_owned();
    Ok((memory_kib, cpu_model))
}

pub(super) fn validate_nofile() -> Result<u64, String> {
    let limits = fs::read_to_string("/proc/self/limits")
        .map_err(|_| "process limits are unavailable".to_owned())?;
    let soft = limits
        .lines()
        .find(|line| line.starts_with("Max open files"))
        .and_then(|line| line.split_whitespace().nth(3))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| "nofile soft limit is malformed".to_owned())?;
    if soft != 65_536 {
        return Err("nofile soft limit is not 65536".to_owned());
    }
    Ok(soft)
}
