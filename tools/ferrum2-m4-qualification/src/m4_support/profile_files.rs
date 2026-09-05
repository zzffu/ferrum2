use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use super::process_support::clean_io;
use super::profile_contract::ProfileScenario;
use super::self_check::expect_rejected;

pub(super) fn validate_profile_relative(relative: &Path) -> Result<(), String> {
    if relative.is_absolute()
        || !relative.starts_with("profiles")
        || relative.components().count() < 2
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("profile file must be a relative child of profiles/".to_owned());
    }
    Ok(())
}

fn is_redirect(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    let reparse = metadata.file_attributes() & 0x400 != 0; // FILE_ATTRIBUTE_REPARSE_POINT
    #[cfg(not(windows))]
    let reparse = false;
    metadata.file_type().is_symlink() || reparse
}

fn inspect_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !is_redirect(&metadata) => Ok(()),
        Ok(_) => Err("profile parent must be a plain directory".to_owned()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("profile parent metadata is unavailable".to_owned()),
    }
}

/// Validates the complete existing parent chain before creating any directory.
/// This rejects pre-existing redirects; it does not defend against concurrent
/// replacement by an actor with the same filesystem permissions.
pub(super) fn resolve_profile_ready_file(
    repository: &Path,
    relative: &Path,
) -> Result<PathBuf, String> {
    validate_profile_relative(relative)?;
    inspect_directory(repository)?;
    let repository = repository.canonicalize().map_err(clean_io)?;
    let parent_relative = relative.parent().expect("validated profile parent");
    let mut current = repository.clone();
    let mut parents = Vec::new();
    for part in parent_relative.components() {
        current.push(part.as_os_str());
        inspect_directory(&current)?;
        parents.push(current.clone());
    }
    let requested = repository.join(relative);
    match fs::symlink_metadata(&requested) {
        Ok(metadata) if metadata.is_file() && !is_redirect(&metadata) => {}
        Ok(_) => return Err("profile file must not be a redirected or non-file entry".to_owned()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("profile file metadata is unavailable".to_owned()),
    }
    // Nothing above this point mutates the filesystem, including permissions.
    let profiles = repository.join("profiles");
    for directory in &parents {
        #[cfg(unix)]
        let created = fs::DirBuilder::new().mode(0o700).create(directory);
        #[cfg(not(unix))]
        let created = fs::create_dir(directory);
        match created {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(clean_io(error)),
        }
        inspect_directory(directory)?;
        let actual = directory.canonicalize().map_err(clean_io)?;
        if actual != *directory || !actual.starts_with(&profiles) {
            return Err("profile file escaped profiles/".to_owned());
        }
    }
    let parent = parents.last().expect("validated profiles child");
    #[cfg(unix)]
    {
        fs::set_permissions(&profiles, fs::Permissions::from_mode(0o700)).map_err(clean_io)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(clean_io)?;
    }
    Ok(parent.join(relative.file_name().expect("validated profile filename")))
}

pub(super) struct ReadyFile {
    path: Option<PathBuf>,
}

impl ReadyFile {
    pub(super) fn publish(
        path: &Path,
        scenario: ProfileScenario,
        client_pid: u32,
        server_pid: Option<u32>,
        warmup_seconds: u64,
        active_seconds: u64,
    ) -> Result<Self, String> {
        let parent = path
            .parent()
            .ok_or_else(|| "profile ready file has no parent".to_owned())?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(clean_io)?;
        write!(
            temporary,
            "scenario={}\nclient_pid={}\nserver_pid={}\nwarmup_seconds={}\nactive_seconds={}\n",
            scenario.label(),
            client_pid,
            server_pid.map_or_else(|| "none".to_owned(), |pid| pid.to_string()),
            warmup_seconds,
            active_seconds,
        )
        .map_err(clean_io)?;
        temporary.flush().map_err(clean_io)?;
        #[cfg(unix)]
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(clean_io)?;
        temporary.as_file().sync_all().map_err(clean_io)?;
        fs::hard_link(temporary.path(), path).map_err(|_| {
            "profile ready file already exists or could not be published".to_owned()
        })?;
        if let Err(error) = temporary.close() {
            let _ = fs::remove_file(path);
            return Err(clean_io(error));
        }
        Ok(Self {
            path: Some(path.to_path_buf()),
        })
    }

    pub(super) fn remove(mut self) -> Result<(), String> {
        let path = self.path.take().expect("ready file owner");
        fs::remove_file(path).map_err(clean_io)
    }
}

impl Drop for ReadyFile {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

pub(super) fn run_self_check() -> Result<(), String> {
    let profile_ready = tempfile::tempdir().map_err(clean_io)?;
    let ready_path = profile_ready.path().join("ready.txt");
    let ready = ReadyFile::publish(&ready_path, ProfileScenario::TcpBulk, 11, Some(12), 1, 10)?;
    if fs::read_to_string(&ready_path).map_err(clean_io)?
        != "scenario=tcp-bulk\nclient_pid=11\nserver_pid=12\nwarmup_seconds=1\nactive_seconds=10\n"
    {
        return Err("profile ready file fields are incomplete".to_owned());
    }
    expect_rejected("profile ready collision", || {
        ReadyFile::publish(&ready_path, ProfileScenario::TcpBulk, 21, Some(22), 1, 10)
    })?;
    if fs::read_to_string(&ready_path).map_err(clean_io)?
        != "scenario=tcp-bulk\nclient_pid=11\nserver_pid=12\nwarmup_seconds=1\nactive_seconds=10\n"
    {
        return Err("profile ready collision overwrote the sentinel".to_owned());
    }
    ready.remove()?;
    if ready_path.exists() {
        return Err("profile ready file survived explicit cleanup".to_owned());
    }
    let direct_ready = ReadyFile::publish(
        &ready_path,
        ProfileScenario::UdpDirectSmall128,
        30,
        None,
        1,
        10,
    )?;
    if fs::read_to_string(&ready_path).map_err(clean_io)?
        != "scenario=udp-direct-small-128\nclient_pid=30\nserver_pid=none\nwarmup_seconds=1\nactive_seconds=10\n"
    {
        return Err("direct profile ready file claimed a server process".to_owned());
    }
    direct_ready.remove()?;
    {
        let _ready = ReadyFile::publish(
            &ready_path,
            ProfileScenario::UdpSmallHigh,
            31,
            Some(32),
            1,
            10,
        )?;
    }
    if ready_path.exists() {
        return Err("profile ready file survived unwind cleanup".to_owned());
    }
    check_resolver()?;
    Ok(())
}

fn check_resolver() -> Result<(), String> {
    let repository = tempfile::tempdir().map_err(clean_io)?;
    let outside = tempfile::tempdir().map_err(clean_io)?;
    for relative in [
        outside.path().join("new/ready.txt"),
        PathBuf::from("profiles/../new/ready.txt"),
        PathBuf::from("profiles"),
        PathBuf::from("elsewhere/new/ready.txt"),
    ] {
        expect_rejected("profile path preflight", || {
            resolve_profile_ready_file(repository.path(), &relative)
        })?;
        if fs::read_dir(repository.path())
            .map_err(clean_io)?
            .next()
            .is_some()
            || fs::read_dir(outside.path())
                .map_err(clean_io)?
                .next()
                .is_some()
        {
            return Err("rejected profile path mutated a directory".to_owned());
        }
    }
    let ready_path =
        resolve_profile_ready_file(repository.path(), Path::new("profiles/nested/ready.txt"))?;
    if ready_path
        != repository
            .path()
            .canonicalize()
            .map_err(clean_io)?
            .join("profiles/nested/ready.txt")
        || ready_path.exists()
    {
        return Err("profile path resolution has the wrong result".to_owned());
    }
    let ready = ReadyFile::publish(&ready_path, ProfileScenario::TcpBulk, 1, Some(2), 1, 10)?;
    #[cfg(unix)]
    {
        for (path, mode) in [
            (repository.path().join("profiles"), 0o700),
            (ready_path.parent().expect("ready parent").to_owned(), 0o700),
            (ready_path.clone(), 0o600),
        ] {
            if fs::metadata(path).map_err(clean_io)?.permissions().mode() & 0o777 != mode {
                return Err("profile file permissions are not private".to_owned());
            }
        }
    }
    ready.remove()?;
    fs::write(repository.path().join("profiles/blocked"), b"sentinel").map_err(clean_io)?;
    expect_rejected("profile non-directory ancestor", || {
        resolve_profile_ready_file(
            repository.path(),
            Path::new("profiles/blocked/new/ready.txt"),
        )
    })?;
    if fs::read(repository.path().join("profiles/blocked")).map_err(clean_io)? != b"sentinel" {
        return Err("profile ancestor validation changed a file".to_owned());
    }
    #[cfg(unix)]
    {
        let link = repository.path().join("profiles/redirect");
        std::os::unix::fs::symlink(outside.path(), &link).map_err(clean_io)?;
        expect_rejected("profile nested directory redirect", || {
            resolve_profile_ready_file(
                repository.path(),
                Path::new("profiles/redirect/new/ready.txt"),
            )
        })?;
        if fs::read_dir(outside.path())
            .map_err(clean_io)?
            .next()
            .is_some()
            || !fs::symlink_metadata(&link)
                .map_err(clean_io)?
                .file_type()
                .is_symlink()
        {
            return Err("profile redirect rejection mutated outside state".to_owned());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn bounded_probe_deadline_contract_profile_files_use_validated_parents() {
        super::run_self_check().expect("finite temporary-filesystem contract");
    }
}
