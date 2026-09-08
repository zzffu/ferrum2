use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};

pub(super) struct Args {
    pub tcp: SocketAddr,
    pub udp: SocketAddr,
    pub output: Option<PathBuf>,
    pub reset: Option<(PathBuf, PathBuf)>,
}

pub(super) fn fresh_path(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        || path.file_name().is_none()
        || path.exists()
        || path.symlink_metadata().is_ok()
        || !path.parent().is_some_and(Path::is_dir)
    {
        return Err("evidence paths must be absolute, fresh files in existing directories".into());
    }
    // Do not traverse a caller-controlled link when publishing controller evidence.
    for ancestor in path.parent().into_iter().flat_map(Path::ancestors) {
        if ancestor
            .symlink_metadata()
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("evidence path ancestor is a symbolic link".into());
        }
    }
    Ok(path)
}

pub(super) fn parse(arguments: &[OsString], mode: &str) -> Result<Args, String> {
    if !arguments.len().is_multiple_of(2) {
        return Err("qualification options require flag/value pairs".into());
    }
    let mut values = BTreeMap::new();
    for pair in arguments.chunks_exact(2) {
        let flag = pair[0].to_str().ok_or("option is not UTF-8")?;
        let value = pair[1].to_str().ok_or("value is not UTF-8")?;
        let allowed = matches!(flag, "--tcp-port" | "--udp-port")
            || (mode == "support" && flag == "--listen-ip")
            || (mode != "support" && flag == "--target-ip")
            || (mode == "qualification"
                && matches!(
                    flag,
                    "--output" | "--reset-ready-file" | "--reset-release-file"
                ));
        if !allowed || values.insert(flag, value).is_some() {
            return Err(format!(
                "unsupported or duplicate qualification option: {flag}"
            ));
        }
    }
    let ip_flag = if mode == "support" {
        "--listen-ip"
    } else {
        "--target-ip"
    };
    let ip: IpAddr = values
        .remove(ip_flag)
        .ok_or("missing IP address")?
        .parse()
        .map_err(|_| "IP must be literal")?;
    if ip.is_multicast() || (mode != "support" && (ip.is_unspecified() || ip.is_loopback())) {
        return Err("qualification requires a non-loopback unicast target".into());
    }
    let mut port = |flag| -> Result<u16, String> {
        let text = values
            .remove(flag)
            .ok_or_else(|| format!("missing {flag}"))?;
        let port: u16 = text.parse().map_err(|_| format!("invalid {flag}"))?;
        if port == 0 || port.to_string() != text {
            return Err(format!("invalid {flag}"));
        }
        Ok(port)
    };
    let tcp = SocketAddr::new(ip, port("--tcp-port")?);
    let udp = SocketAddr::new(ip, port("--udp-port")?);
    let output = values.remove("--output").map(fresh_path).transpose()?;
    if mode == "qualification" && output.is_none() {
        return Err("qualification requires --output".into());
    }
    let reset = match (
        values.remove("--reset-ready-file"),
        values.remove("--reset-release-file"),
    ) {
        (None, None) => None,
        (Some(ready), Some(release)) => Some((fresh_path(ready)?, fresh_path(release)?)),
        _ => return Err("reset markers must be supplied together".into()),
    };
    if let Some((ready, release)) = &reset
        && (ready == release || output.as_ref() == Some(ready) || output.as_ref() == Some(release))
    {
        return Err("evidence paths must be distinct".into());
    }
    Ok(Args {
        tcp,
        udp,
        output,
        reset,
    })
}
