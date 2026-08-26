#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

#[test]
fn profiling_wrapper_enforces_bounds_and_records_stage_results() {
    let root = workspace_root();
    let fake = tempfile::tempdir().expect("fake tool directory");
    let log = fake.path().join("calls.log");
    let tool = r#"#!/usr/bin/env bash
set -u
tool=${0##*/}
case "$tool:$1" in
  perf:--version) printf '%s\n' 'perf version fake' ;;
  perf:list) printf '  %s\n' "$2" ;;
  perf:stat)
    output=
    while (($#)); do
      if [[ $1 == -o ]]; then output=$2; shift 2; else shift; fi
    done
    if [[ -n $output ]]; then
      printf '%s\n' perf_stat >>"$PROFILE_FAKE_LOG"
      if [[ ${PROFILE_FAKE_UNSUPPORTED:-0} == 1 ]]; then printf '%s\n' '<not supported>;cycles:u' >"$output"; else printf '%s\n' '1;task-clock' >"$output"; fi
    else
      printf '%s\n' perf_preflight >>"$PROFILE_FAKE_LOG"
    fi ;;
  samply:--version) printf '%s\n' 'samply 0.13.1' ;;
  samply:record)
    if [[ ${2:-} == --help ]]; then printf '%s\n' '--pid --duration --rate --save-only --output'; exit 0; fi
    output=
    while (($#)); do
      if [[ $1 == --output ]]; then output=$2; shift 2; else shift; fi
    done
    printf '%s\n' samply >>"$PROFILE_FAKE_LOG"
    trap 'printf "%s\n" fake-profile >"$output"; printf "%s\n" samply_int >>"$PROFILE_FAKE_LOG"; exit 0' INT
    while true; do sleep 0.05; done ;;
  readlink:*) printf '%s\n' /fake/ferrum2-client ;;
  readelf:*) printf '%s\n' '    Build ID: 0123456789abcdef' ;;
  git:-C)
    if [[ $3 == status ]]; then
      [[ ! -e ${PROFILE_EXPECT_OUTPUT:?} ]] || exit 98
      exit 0
    fi
    if [[ ${5:-} == 'HEAD^{tree}' || ${4:-} == 'HEAD^{tree}' ]]; then printf '%040d\n' 2; else printf '%040d\n' 1; fi ;;
  *) exit 97 ;;
esac
"#;
    for name in ["perf", "samply", "readlink", "readelf", "git"] {
        let path = fake.path().join(name);
        fs::write(&path, tool).expect("fake tool");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("fake tool mode");
    }
    let mut path = vec![fake.path().to_path_buf()];
    path.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let path = std::env::join_paths(path).expect("test PATH");
    let profiles = root.join("profiles");
    fs::create_dir_all(&profiles).expect("profiles directory");
    let reserve = tempfile::NamedTempFile::new_in(&profiles).expect("output reservation");
    let output = reserve.path().to_path_buf();
    reserve.close().expect("remove output reservation");
    let run = |output: &Path, unsupported: bool, duration: &str, frequency: &str| {
        let mut command = Command::new(root.join("tools/profile-cpu.sh"));
        command
            .args([
                "--scenario",
                "tcp-bulk",
                "--role",
                "client",
                "--pid",
                &std::process::id().to_string(),
                "--duration",
                duration,
                "--frequency",
                frequency,
                "--output",
            ])
            .arg(output)
            .env("PATH", &path)
            .env("PROFILE_FAKE_LOG", &log)
            .env("PROFILE_EXPECT_OUTPUT", output);
        if unsupported {
            command.env("PROFILE_FAKE_UNSUPPORTED", "1");
        }
        command.output().expect("profiling wrapper must start")
    };

    let success = run(&output, false, "1", "1");
    assert!(
        success.status.success(),
        "{}",
        String::from_utf8_lossy(&success.stderr)
    );
    let calls: Vec<_> = fs::read_to_string(&log)
        .expect("fake call log")
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(calls.len(), 4);
    assert_eq!(
        calls.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "perf_preflight".to_owned(),
            "perf_stat".to_owned(),
            "samply".to_owned(),
            "samply_int".to_owned(),
        ])
    );
    let stages = fs::read_to_string(output.join("stage-status.txt")).expect("stage results");
    assert!(
        stages
            .lines()
            .any(|line| line == "stage=samply status=PASS")
    );
    assert!(stages.lines().any(|line| line == "result=PASS exit_code=0"));
    assert!(
        fs::read_to_string(output.join("metadata.txt"))
            .expect("profile metadata")
            .lines()
            .any(|line| line == "worktree_clean=true")
    );

    let calls_before_overflow = fs::read(&log).expect("fake call log");
    for (duration, frequency) in [("18446744073709551616", "1"), ("1", "18446744073709551616")] {
        let reserve = tempfile::NamedTempFile::new_in(&profiles).expect("overflow reservation");
        let overflow_output = reserve.path().to_path_buf();
        reserve.close().expect("remove overflow reservation");
        let overflow = run(&overflow_output, false, duration, frequency);
        assert_eq!(overflow.status.code(), Some(2));
        assert!(!overflow_output.exists());
    }
    assert_eq!(
        fs::read(&log).expect("fake call log"),
        calls_before_overflow
    );

    for artifact in [
        "metadata.txt",
        "perf-stat.txt",
        "samply.json.gz",
        "stage-status.txt",
    ] {
        assert!(output.join(artifact).is_file(), "missing {artifact}");
    }
    assert_eq!(
        fs::metadata(&output)
            .expect("output mode")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(output.join("metadata.txt"))
            .expect("metadata mode")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let metadata_before = fs::read(output.join("metadata.txt")).expect("metadata");
    assert!(!run(&output, false, "1", "1").status.success());
    assert_eq!(
        fs::read(output.join("metadata.txt")).expect("metadata"),
        metadata_before
    );

    let reserve = tempfile::NamedTempFile::new_in(&profiles).expect("failed output reservation");
    let failed = reserve.path().to_path_buf();
    reserve.close().expect("remove failed output reservation");
    let failure = run(&failed, true, "1", "1");
    assert!(!failure.status.success());
    assert!(
        fs::read_to_string(failed.join("perf-stat.txt"))
            .expect("partial perf evidence")
            .contains("<not supported>")
    );
    assert!(!failed.join("samply.json.gz").exists());
    assert!(
        fs::read_to_string(failed.join("stage-status.txt"))
            .expect("failed stages")
            .lines()
            .any(|line| line == "stage=perf_stat status=FAIL")
    );

    let outside = fake.path().join("outside-profiles");
    assert!(!run(&outside, false, "1", "1").status.success());
    assert!(!outside.exists());
    fs::remove_dir_all(output).expect("remove successful evidence");
    fs::remove_dir_all(failed).expect("remove failed evidence");
}
