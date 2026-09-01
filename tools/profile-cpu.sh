#!/usr/bin/env bash
set -u -o pipefail

export LC_ALL=C
umask 077

readonly STDERR_CAP_BYTES=65536
readonly SAMPLY_STOP_GRACE_SECONDS=5
readonly PERF_EVENTS="task-clock,cycles:u,instructions:u,branches:u,branch-misses:u,cache-references:u,cache-misses:u,context-switches,page-faults"
output_created=0
metadata_file=
stage_file=

usage() {
    cat <<'EOF'
Usage: tools/profile-cpu.sh --scenario <tcp-bulk|udp-small-high> --role <client|server> --pid <PID> --duration <1..300> --frequency <1..1000> --output <profiles/new-directory>

Attach perf stat and exact Samply 0.13.1 to one already-running Ferrum process.
The output must be a new canonical child of the repository profiles/ directory.
EOF
}

record_stage() {
    ((output_created == 1)) || return 0
    printf 'stage=%s status=%s\n' "$1" "$2" >>"$stage_file"
    printf 'stage.%s=%s\n' "$1" "$2" >>"$metadata_file"
}

die() {
    record_stage "$1" FAIL
    printf 'profile-cpu: %s\n' "$2" >&2
    exit 1
}

finish() {
    local status=$?
    local result=FAIL
    trap - EXIT
    ((status == 0)) && result=PASS
    if ((output_created == 1)); then
        printf 'result=%s exit_code=%s\n' "$result" "$status" >>"$stage_file"
        printf 'result=%s\nexit_code=%s\n' "$result" "$status" >>"$metadata_file"
    fi
    exit "$status"
}
trap finish EXIT

bounded_stderr() {
    local destination=$1
    local remaining=$STDERR_CAP_BYTES
    local chunk read_status write_count
    : >"$destination"
    while true; do
        chunk=
        IFS= read -r -N 4096 chunk
        read_status=$?
        if [[ -n "$chunk" && $remaining -gt 0 ]]; then
            write_count=${#chunk}
            ((write_count > remaining)) && write_count=$remaining
            printf '%s' "${chunk:0:write_count}" >>"$destination"
            ((remaining -= write_count))
        fi
        ((read_status == 0)) || break
    done
}

run_with_bounded_stderr() {
    local destination=$1
    local command_status sink_status=0 sink_pid sink_input sink_output
    shift
    coproc PROFILE_STDERR_SINK { bounded_stderr "$destination"; }
    sink_pid=$PROFILE_STDERR_SINK_PID
    sink_output=${PROFILE_STDERR_SINK[0]}
    sink_input=${PROFILE_STDERR_SINK[1]}
    "$@" 2>&"$sink_input"
    command_status=$?
    exec {sink_input}>&-
    wait "$sink_pid" || sink_status=$?
    exec {sink_output}<&-
    ((sink_status == 0)) || return 125
    return "$command_status"
}

single_line() {
    [[ -n "$1" && "$1" != *$'\n'* && "$1" != *$'\r'* ]]
}

has_private_mode() {
    local path=$1
    local expected=$2
    local actual
    actual=$(stat -Lc '%a' -- "$path") || return 1
    [[ $actual == "$expected" ]]
}

scenario=
role=
pid=
duration=
frequency=
output=

if (($# == 1)) && [[ $1 == --help || $1 == -h ]]; then
    usage
    exit 0
fi

while (($# > 0)); do
    (($# >= 2)) || { usage >&2; exit 2; }
    case "$1" in
        --scenario) scenario=$2 ;;
        --role) role=$2 ;;
        --pid) pid=$2 ;;
        --duration) duration=$2 ;;
        --frequency) frequency=$2 ;;
        --output) output=$2 ;;
        *) usage >&2; exit 2 ;;
    esac
    shift 2
done

[[ $scenario == tcp-bulk || $scenario == udp-small-high ]] || { usage >&2; exit 2; }
[[ $role == client || $role == server ]] || { usage >&2; exit 2; }
[[ $pid =~ ^[1-9][0-9]*$ ]] || { usage >&2; exit 2; }
[[ $duration =~ ^[1-9][0-9]{0,2}$ ]] && ((10#$duration <= 300)) || { usage >&2; exit 2; }
[[ $frequency =~ ^[1-9][0-9]{0,3}$ ]] && ((10#$frequency <= 1000)) || { usage >&2; exit 2; }
[[ -n $output ]] || { usage >&2; exit 2; }
[[ $OSTYPE == linux* ]] || { printf 'profile-cpu: Linux is required\n' >&2; exit 1; }

for command_name in realpath mkdir chmod git rustc cargo uname perf samply readlink readelf stat sleep grep timeout; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf 'profile-cpu: required command unavailable: %s\n' "$command_name" >&2
        exit 1
    }
done

script_path=${BASH_SOURCE[0]}
script_dir_part=${script_path%/*}
[[ $script_dir_part != "$script_path" ]] || script_dir_part=.
script_dir=$(cd -- "$script_dir_part" && pwd -P) || exit 1
repo_root=$(cd -- "$script_dir/.." && pwd -P) || exit 1
candidate_sha=$(git -C "$repo_root" rev-parse HEAD) || die preflight "candidate SHA unavailable"
candidate_tree=$(git -C "$repo_root" rev-parse 'HEAD^{tree}') || die preflight "candidate tree unavailable"
git_status=$(git -C "$repo_root" status --porcelain=v1 --untracked-files=normal) || die preflight "worktree status unavailable"
worktree_clean=false
[[ -z $git_status ]] && worktree_clean=true
expected_profiles_root=$repo_root/profiles
if [[ ! -e $expected_profiles_root && ! -L $expected_profiles_root ]]; then
    mkdir -m 700 -- "$expected_profiles_root" || exit 1
fi
[[ -d $expected_profiles_root && ! -L $expected_profiles_root ]] || {
    printf 'profile-cpu: profiles/ must be a real directory\n' >&2
    exit 1
}
profiles_root=$(realpath -e -- "$expected_profiles_root") || exit 1
[[ $profiles_root == "$expected_profiles_root" ]] || {
    printf 'profile-cpu: profiles/ canonical path mismatch\n' >&2
    exit 1
}
chmod 700 -- "$profiles_root" || exit 1
has_private_mode "$profiles_root" 700 || {
    printf 'profile-cpu: profiles/ cannot enforce private permissions\n' >&2
    exit 1
}
case "$output" in
    /*) output_candidate=$output ;;
    *) output_candidate=$repo_root/$output ;;
esac
output_dir=$(realpath -m -- "$output_candidate") || exit 1
[[ $output_dir == "$profiles_root/"* ]] || {
    printf 'profile-cpu: output must be below repository profiles/\n' >&2
    exit 1
}
[[ ! -e $output_dir && ! -L $output_dir ]] || {
    printf 'profile-cpu: output already exists\n' >&2
    exit 1
}
mkdir -m 700 -- "$output_dir" || exit 1
chmod 700 -- "$output_dir" || exit 1
has_private_mode "$output_dir" 700 || {
    printf 'profile-cpu: output cannot enforce private permissions\n' >&2
    exit 1
}

metadata_file=$output_dir/metadata.txt
stage_file=$output_dir/stage-status.txt
: >"$metadata_file"
: >"$stage_file"
chmod 600 -- "$metadata_file" "$stage_file" || exit 1
has_private_mode "$metadata_file" 600 && has_private_mode "$stage_file" 600 || {
    printf 'profile-cpu: evidence files cannot enforce private permissions\n' >&2
    exit 1
}
output_created=1
{
    printf 'build_profile=profiling\n'
    printf 'scenario=%s\n' "$scenario"
    printf 'load=profile-workload\n'
    printf 'duration_seconds=%s\n' "$duration"
    printf 'sampling_frequency_hz=%s\n' "$frequency"
    printf 'role=%s\n' "$role"
    printf 'pid=%s\n' "$pid"
} >"$metadata_file"
record_stage arguments PASS
record_stage preflight STARTED

rustc_version=$(rustc --version) || die preflight "rustc identity unavailable"
cargo_version=$(cargo --version) || die preflight "Cargo identity unavailable"
kernel=$(uname -srmo) || die preflight "kernel identity unavailable"
for value in "$candidate_sha" "$candidate_tree" "$rustc_version" "$cargo_version" "$kernel"; do
    single_line "$value" || die preflight "invalid multiline identity"
done
cpu_model=
while IFS=: read -r key value; do
    if [[ ${key//[[:space:]]/} == modelname ]]; then
        cpu_model=${value#${value%%[![:space:]]*}}
        break
    fi
done </proc/cpuinfo
single_line "$cpu_model" || die preflight "CPU identity unavailable"

if ! run_with_bounded_stderr "$output_dir/perf-version.stderr.txt" perf --version >"$output_dir/perf-version.txt"; then
    die preflight "perf identity failed"
fi
perf_version=$(<"$output_dir/perf-version.txt")
single_line "$perf_version" || die preflight "invalid perf identity"
if ! run_with_bounded_stderr "$output_dir/samply-version.stderr.txt" samply --version >"$output_dir/samply-version.txt"; then
    die preflight "Samply identity failed"
fi
samply_version=$(<"$output_dir/samply-version.txt")
[[ $samply_version == "samply 0.13.1" ]] || die preflight "exact Samply 0.13.1 is required"
if ! run_with_bounded_stderr "$output_dir/samply-help.stderr.txt" samply record --help >"$output_dir/samply-record-help.txt"; then
    die preflight "Samply record help failed"
fi
for option in --pid --duration --rate --save-only --output; do
    grep -Fq -- "$option" "$output_dir/samply-record-help.txt" || die preflight "Samply record option unavailable"
done
if ! run_with_bounded_stderr "$output_dir/timeout-help.stderr.txt" timeout --help >"$output_dir/timeout-help.txt"; then
    die preflight "timeout help failed"
fi
for option in --preserve-status --signal --kill-after; do
    grep -Fq -- "$option" "$output_dir/timeout-help.txt" || die preflight "required timeout option unavailable"
done

expected_binary=ferrum2-$role
process_identity=
binary_identity=
verify_target() {
    local proc_stat stat_tail current_process current_binary executable
    kill -0 "$pid" 2>/dev/null || return 1
    executable=$(readlink -e -- "/proc/$pid/exe") || return 1
    [[ ${executable##*/} == "$expected_binary" ]] || return 1
    IFS= read -r proc_stat <"/proc/$pid/stat" || return 1
    stat_tail=${proc_stat##*) }
    set -- $stat_tail
    (($# >= 20)) && [[ ${20} =~ ^[0-9]+$ ]] || return 1
    current_process=$(stat -Lc '%d:%i' -- "/proc/$pid"):${20} || return 1
    current_binary=$(stat -Lc '%d:%i' -- "/proc/$pid/exe") || return 1
    if [[ -z $process_identity ]]; then
        process_identity=$current_process
        binary_identity=$current_binary
    else
        [[ $current_process == "$process_identity" && $current_binary == "$binary_identity" ]] || return 1
    fi
}
verify_target || die preflight "PID is not the requested live Ferrum executable"

binary_notes=$(readelf -n -- "/proc/$pid/exe") || die preflight "binary build ID unavailable"
binary_build_id=
build_id_count=0
while IFS= read -r line; do
    if [[ $line =~ Build[[:space:]]ID:[[:space:]]([[:xdigit:]]+) ]]; then
        binary_build_id=${BASH_REMATCH[1]}
        ((build_id_count += 1))
    fi
done <<<"$binary_notes"
((build_id_count == 1)) || die preflight "binary must contain one build ID"

for event in task-clock cycles instructions branches branch-misses cache-references cache-misses context-switches page-faults; do
    if ! run_with_bounded_stderr "$output_dir/perf-list-$event.stderr.txt" perf list "$event" >"$output_dir/perf-list-$event.txt"; then
        die preflight "perf event listing failed"
    fi
    grep -Eq "(^|[[:space:]])$event([[:space:]]|$)" "$output_dir/perf-list-$event.txt" || die preflight "required perf event unavailable"
    printf 'event.%s=available\n' "$event" >>"$metadata_file"
done
if ! run_with_bounded_stderr "$output_dir/perf-preflight.stderr.txt" perf stat -e "$PERF_EVENTS" -p "$pid" -- sleep 0 >/dev/null; then
    die preflight "perf attach permission or event preflight failed"
fi

{
    printf 'candidate_sha=%s\n' "$candidate_sha"
    printf 'candidate_tree=%s\n' "$candidate_tree"
    printf 'worktree_clean=%s\n' "$worktree_clean"
    printf 'kernel=%s\n' "$kernel"
    printf 'cpu=%s\n' "$cpu_model"
    printf 'perf=%s\n' "$perf_version"
    printf 'samply=%s\n' "$samply_version"
    printf 'rustc=%s\n' "$rustc_version"
    printf 'cargo=%s\n' "$cargo_version"
    printf 'binary=%s\n' "$expected_binary"
    printf 'binary_build_id=%s\n' "$binary_build_id"
} >>"$metadata_file"
record_stage preflight PASS

record_stage perf_stat STARTED
verify_target || die perf_stat "target identity changed before perf stat"
if ! run_with_bounded_stderr "$output_dir/perf-stat.stderr.txt" perf stat -x ';' -o "$output_dir/perf-stat.txt" -e "$PERF_EVENTS" -p "$pid" -- sleep "$duration"; then
    die perf_stat "perf stat failed"
fi
verify_target || die perf_stat "target identity changed during perf stat"
[[ -s $output_dir/perf-stat.txt ]] || die perf_stat "perf stat produced no evidence"
has_private_mode "$output_dir/perf-stat.txt" 600 || die perf_stat "perf evidence is not private"
if grep -Eq '<not supported>|<not counted>' "$output_dir/perf-stat.txt"; then
    die perf_stat "perf reported unsupported or not-counted evidence"
fi
record_stage perf_stat PASS

record_stage samply STARTED
verify_target || die samply "target identity changed before Samply"
if ! run_with_bounded_stderr "$output_dir/samply.stderr.txt" timeout --preserve-status --signal=INT --kill-after="${SAMPLY_STOP_GRACE_SECONDS}s" "${duration}s" samply record --pid "$pid" --duration "$duration" --rate "$frequency" --save-only --output "$output_dir/samply.json.gz"; then
    die samply "Samply record failed"
fi
verify_target || die samply "target identity changed during Samply"
[[ -s $output_dir/samply.json.gz ]] || die samply "Samply produced no evidence"
has_private_mode "$output_dir/samply.json.gz" 600 || die samply "Samply evidence is not private"
record_stage samply PASS
exit 0
