#!/usr/bin/env bash
set -euo pipefail

export RUSTUP_TOOLCHAIN=1.97.1
readonly WARMUP_SECONDS=3
readonly ACTIVE_SECONDS=10
readonly PROFILE_DIR=profiles/autoresearch

if command -v cargo >/dev/null 2>&1; then
  cargo_runner=cargo
elif command -v cargo.exe >/dev/null 2>&1; then
  cargo_runner=cargo.exe
elif command -v where.exe >/dev/null 2>&1; then
  IFS= read -r cargo_runner < <(where.exe cargo)
  cargo_runner="${cargo_runner%$'\r'}"
  cargo_runner="${cargo_runner//\\//}"
else
  printf 'cargo is unavailable\n' >&2
  exit 1
fi

"$cargo_runner" build --profile profiling \
  -p ferrum2-client -p ferrum2-server -p ferrum2-m4-qualification \
  --bins --locked >&2

runner=target/profiling/m4-qualification
if [[ ! -x "$runner" && -x "$runner.exe" ]]; then
  runner="$runner.exe"
fi
[[ -x "$runner" ]]

mkdir -p "$PROFILE_DIR"

run_scenario() {
  local scenario=$1
  local output
  rm -f "$PROFILE_DIR/$scenario.ready"
  output="$($runner profile-workload \
    --scenario "$scenario" \
    --warmup-seconds "$WARMUP_SECONDS" \
    --active-seconds "$ACTIVE_SECONDS" \
    --ready-file "$PROFILE_DIR/$scenario.ready")"
  printf '%s\n' "$output" >&2
  printf '%s\n' "$output"
}

dns_direct_output="$(run_scenario dns-direct)"
dns_detoured_output="$(run_scenario dns-detoured)"

extract_value() {
  local output=$1
  local field=$2
  if [[ "$output" =~ $field=([0-9]+) ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  printf 'missing %s in workload output: %s\n' "$field" "$output" >&2
  return 1
}

dns_direct_queries="$(extract_value "$dns_direct_output" queries)"
dns_direct_p99="$(extract_value "$dns_direct_output" p99_nanoseconds)"
dns_detoured_queries="$(extract_value "$dns_detoured_output" queries)"
dns_detoured_p99="$(extract_value "$dns_detoured_output" p99_nanoseconds)"

printf 'METRIC dns_direct_queries_per_second=%s\n' "$((dns_direct_queries / ACTIVE_SECONDS))"
printf 'METRIC dns_direct_p99_nanoseconds=%s\n' "$dns_direct_p99"
printf 'METRIC dns_detoured_queries_per_second=%s\n' "$((dns_detoured_queries / ACTIVE_SECONDS))"
printf 'METRIC dns_detoured_p99_nanoseconds=%s\n' "$dns_detoured_p99"
