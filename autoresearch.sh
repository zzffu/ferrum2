#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
export PATH="$HOME/.cargo/bin:$PATH"

readonly TOOLCHAIN="1.97.1"
readonly SELECTION="udp-small-high"
readonly MODE="diagnostic"
readonly WARMUP_SECONDS="3"
readonly ACTIVE_SECONDS="30"
readonly PAIRS="6"

case "$(uname -r)" in
    *[Mm]icrosoft*) ;;
    *)
        echo "autoresearch: this benchmark must run inside WSL" >&2
        exit 2
        ;;
esac

for command in cargo git python3 flock pgrep pkill; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "autoresearch: missing required command: $command" >&2
        exit 2
    fi
done

repository="$(git rev-parse --show-toplevel)"
cd "$repository"

cache_root="${XDG_CACHE_HOME:-$HOME/.cache}/ferrum2-autoresearch-wsl"
mkdir -p "$cache_root"
exec 9>"$cache_root/run.lock"
if ! flock -n 9; then
    echo "autoresearch: another WSL benchmark is already running" >&2
    exit 2
fi

for process in ferrum2-client ferrum2-server; do
    if pgrep -x "$process" >/dev/null; then
        echo "autoresearch: refusing to disturb existing $process process" >&2
        exit 2
    fi
done

run_root="$(mktemp -d /tmp/ferrum2-autoresearch.XXXXXX)"
parent_root="$run_root/parent"
candidate_root="$run_root/candidate"
parent_target_cache="$cache_root/target-parent"
candidate_target_cache="$cache_root/target-candidate"
parent_added=0
candidate_added=0

cleanup() {
    local status=$?
    set +e
    for signal in TERM KILL; do
        for process in ferrum2-client ferrum2-server; do
            pkill "-$signal" -x "$process" >/dev/null 2>&1 || true
        done
        if [[ "$signal" == "TERM" ]]; then
            sleep 1
        fi
    done
    if ((candidate_added)); then
        if [[ -d "$candidate_root/target" ]]; then
            rm -rf "$candidate_target_cache"
            mv "$candidate_root/target" "$candidate_target_cache" || true
        fi
        git worktree remove --force "$candidate_root" >/dev/null 2>&1 || true
    fi
    if ((parent_added)); then
        if [[ -d "$parent_root/target" ]]; then
            rm -rf "$parent_target_cache"
            mv "$parent_root/target" "$parent_target_cache" || true
        fi
        git worktree remove --force "$parent_root" >/dev/null 2>&1 || true
    fi
    rm -rf "$run_root"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

parent_sha="$(git rev-parse HEAD)"
index_file="$run_root/candidate.index"
GIT_INDEX_FILE="$index_file" git read-tree HEAD
GIT_INDEX_FILE="$index_file" git add -A -- .
candidate_tree="$(GIT_INDEX_FILE="$index_file" git write-tree)"
parent_epoch="$(git show -s --format=%ct "$parent_sha")"
candidate_sha="$(
    printf '%s\n' "autoresearch WSL candidate snapshot" |
        GIT_AUTHOR_NAME=autoresearch \
        GIT_AUTHOR_EMAIL=autoresearch@localhost \
        GIT_COMMITTER_NAME=autoresearch \
        GIT_COMMITTER_EMAIL=autoresearch@localhost \
        GIT_AUTHOR_DATE="@$parent_epoch +0000" \
        GIT_COMMITTER_DATE="@$parent_epoch +0000" \
        git commit-tree "$candidate_tree" -p "$parent_sha"
)"

python3 -B -m tools.performance_candidate validate-git \
    --repository "$repository" \
    --parent-sha "$parent_sha" \
    --candidate-sha "$candidate_sha"

git worktree add --detach "$parent_root" "$parent_sha" >/dev/null
parent_added=1
git worktree add --detach "$candidate_root" "$candidate_sha" >/dev/null
candidate_added=1
if [[ -d "$parent_target_cache" ]]; then
    mv "$parent_target_cache" "$parent_root/target"
fi
if [[ -d "$candidate_target_cache" ]]; then
    mv "$candidate_target_cache" "$candidate_root/target"
fi

build_member() {
    local member_root=$1
    shift
    (
        cd "$member_root"
        CARGO_TARGET_DIR="$member_root/target" cargo "+$TOOLCHAIN" build \
            --profile profiling \
            -p ferrum2-client \
            -p ferrum2-server \
            "$@" \
            --bins \
            --locked
    )
}

build_member "$parent_root"
build_member "$candidate_root" -p ferrum2-m4-qualification

runner="$candidate_root/target/profiling/m4-qualification"
(
    cd "$candidate_root"
    "$runner" self-check
)

policy="$candidate_root/tools/performance_candidate_policy.json"
plan="$run_root/performance-plan.json"
summary="$run_root/performance-summary.json"
markdown="$run_root/performance-summary.md"

(
    cd "$candidate_root"
    python3 -B -m tools.performance_candidate plan \
        --mode "$MODE" \
        --selection "$SELECTION" \
        --warmup-seconds "$WARMUP_SECONDS" \
        --active-seconds "$ACTIVE_SECONDS" \
        --pairs "$PAIRS" \
        --policy "$policy" \
        --output "$plan"
)

trial_contract="$(
    cd "$candidate_root"
    python3 -B -m tools.performance_candidate linux-trial-contract \
        --plan "$plan" \
        --policy "$policy" \
        --scenario "$SELECTION" \
        --output-format tsv
)"
IFS=$'\t' read -r trial_unit trial_runner_image producer_sha controller_sha recipe_sha bundle_sha <<<"$trial_contract"
for value in "$trial_unit" "$trial_runner_image" "$producer_sha" "$controller_sha" "$recipe_sha" "$bundle_sha"; do
    if [[ -z "$value" ]]; then
        echo "autoresearch: incomplete Linux trial contract" >&2
        exit 2
    fi
done

run_member() {
    local member=$1
    local pair=$2
    local order=$3
    local member_root
    if [[ "$member" == "parent" ]]; then
        member_root="$parent_root"
    else
        member_root="$candidate_root"
    fi
    mkdir -p "$member_root/profiles/paired"
    (
        cd "$member_root"
        "$runner" profile-workload \
            --scenario "$SELECTION" \
            --warmup-seconds "$WARMUP_SECONDS" \
            --active-seconds "$ACTIVE_SECONDS" \
            --repository-root "$member_root" \
            --binary-dir "$member_root/target/profiling" \
            --ready-file "profiles/paired/$SELECTION-$member-$pair.ready" \
            --output "profiles/paired/$SELECTION-$member-$pair.jsonl" \
            --parent-sha "$parent_sha" \
            --candidate-sha "$candidate_sha" \
            --member "$member" \
            --pair "$pair" \
            --order "$order" \
            --build-profile current \
            --unit "$trial_unit" \
            --runner-image "$trial_runner_image" \
            --producer-source-sha256 "$producer_sha" \
            --controller-source-sha256 "$controller_sha" \
            --semantic-recipe-sha256 "$recipe_sha" \
            --evidence-bundle-sha256 "$bundle_sha"
    )
}

for pair in 1 2 3 4 5 6; do
    if ((pair % 2 == 1)); then
        run_member parent "$pair" 1
        run_member candidate "$pair" 2
    else
        run_member candidate "$pair" 1
        run_member parent "$pair" 2
    fi
done

(
    cd "$candidate_root"
    python3 -B -m tools.performance_candidate summarize \
        --plan "$plan" \
        --parent-root "$parent_root/profiles/paired" \
        --candidate-root "$candidate_root/profiles/paired" \
        --parent-sha "$parent_sha" \
        --candidate-sha "$candidate_sha" \
        --policy "$policy" \
        --output "$summary" \
        --markdown "$markdown"
)

run_id="${parent_sha:0:12}-${candidate_sha:0:12}-$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="$repository/profiles/autoresearch/$run_id"
mkdir -p "$evidence_dir"
cp "$plan" "$summary" "$markdown" "$evidence_dir/"
cp -a "$parent_root/profiles/paired" "$evidence_dir/parent"
cp -a "$candidate_root/profiles/paired" "$evidence_dir/candidate"

python3 -B - "$summary" "$parent_sha" "$candidate_sha" "$evidence_dir" <<'PY'
import json
import statistics
import sys

summary_path, parent_sha, candidate_sha, evidence_dir = sys.argv[1:]
with open(summary_path, "r", encoding="utf-8") as source:
    summary = json.load(source)
scenario = next(
    item for item in summary["scenarios"] if item["scenario"] == "udp-small-high"
)
parent_values = [pair["parent_value"] for pair in scenario["pairs"]]
candidate_values = [pair["candidate_value"] for pair in scenario["pairs"]]
deltas = [pair["improvement_percent"] for pair in scenario["pairs"]]

print(
    "METRIC udp_small_high_median_improvement_percent="
    f'{scenario["median_improvement_percent"]}'
)
print(
    "METRIC udp_small_high_parent_median_datagrams_per_second="
    f"{statistics.median(parent_values)}"
)
print(
    "METRIC udp_small_high_candidate_median_datagrams_per_second="
    f"{statistics.median(candidate_values)}"
)
print(f'METRIC udp_small_high_wins={scenario["wins"]}')
print(f'METRIC udp_small_high_losses={scenario["losses"]}')
print(f'METRIC udp_small_high_spread_percent={scenario["spread_percent"]}')
print(f"ASI parent_sha={parent_sha}")
print(f"ASI candidate_snapshot_sha={candidate_sha}")
print("ASI workflow_selection=diagnostic/udp-small-high/3/30/6")
print(f"ASI pair_deltas_percent={json.dumps(deltas, separators=(',', ':'))}")
print(
    "ASI warnings="
    + json.dumps(scenario["warnings"], separators=(",", ":"))
)
print(f"ASI evidence_dir={evidence_dir}")
PY
