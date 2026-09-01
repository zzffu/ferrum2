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

bulk_output="$(run_scenario tcp-bulk)"
stream_output="$(run_scenario tcp-stream-64k)"
request_1k_output="$(run_scenario tcp-request-1k)"
request_4k_output="$(run_scenario tcp-request-4k)"
request_16k_output="$(run_scenario tcp-request-16k)"

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

bulk_bytes="$(extract_value "$bulk_output" bytes)"
stream_bytes="$(extract_value "$stream_output" bytes)"
request_1k_p99="$(extract_value "$request_1k_output" p99_nanoseconds)"
request_4k_p99="$(extract_value "$request_4k_output" p99_nanoseconds)"
request_16k_p99="$(extract_value "$request_16k_output" p99_nanoseconds)"

printf 'METRIC tcp_stream_64k_bytes_per_second=%s\n' "$((stream_bytes / ACTIVE_SECONDS))"
printf 'METRIC tcp_bulk_bytes_per_second=%s\n' "$((bulk_bytes / ACTIVE_SECONDS))"
printf 'METRIC tcp_request_1k_p99_nanoseconds=%s\n' "$request_1k_p99"
printf 'METRIC tcp_request_4k_p99_nanoseconds=%s\n' "$request_4k_p99"
printf 'METRIC tcp_request_16k_p99_nanoseconds=%s\n' "$request_16k_p99"
