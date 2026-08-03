#!/bin/sh
set -eu

LC_ALL=C
export LC_ALL

TOOL_NAME=rustloc
TOOL=${RUSTLOC:-rustloc}
TOOL_VERSION=0.19.1
SERIES=rustloc-0.19.1-tests-v1
METRIC=tests
BASELINE_FILE=ci/test-budget-baseline.txt

usage() {
  cat <<'USAGE'
Usage:
  test-budget.sh install-hook [--force]
  test-budget.sh bind [--base COMMIT]
  test-budget.sh verify [--candidate COMMIT]
  test-budget.sh ticket [--staged | --candidate COMMIT] [--base COMMIT]
  test-budget.sh milestone --candidate COMMIT
  test-budget.sh ci --candidate COMMIT [--base COMMIT]
  test-budget.sh self-test

Exit 0: PASS; exit 1: BLOCKED; exit 2: ERROR.
USAGE
}

error() {
  printf 'test_budget status=ERROR reason=%s\n' "$1" >&2
  exit 2
}

blocked() {
  printf 'test_budget status=BLOCKED reason=%s\n' "$1" >&2
  exit 1
}

is_uint() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

repo=$(git rev-parse --show-toplevel 2>/dev/null) || error not_a_git_worktree
cd "$repo"

tmp_root=
cleanup() {
  if [ -n "${tmp_root:-}" ] && [ -d "$tmp_root" ]; then
    rm -rf "$tmp_root"
  fi
}
trap cleanup EXIT HUP INT TERM

need_tmp() {
  if [ -z "${tmp_root:-}" ]; then
    tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/ferrum2-test-budget.XXXXXX") || error mktemp_failed
  fi
}

resolve_commit() {
  git rev-parse --verify "$1^{commit}" 2>/dev/null || error invalid_commit
}

first_parent() {
  git rev-parse --verify "$1^1" 2>/dev/null || error missing_parent
}

count_parents() {
  git rev-list --parents -n 1 "$1" | awk '{print NF - 1}'
}

check_tool() {
  command -v "$TOOL" >/dev/null 2>&1 || error rustloc_missing
  actual=$("$TOOL" --version 2>/dev/null | tr -d '\r') || error rustloc_version_failed
  [ "$actual" = "rustloc $TOOL_VERSION" ] || error rustloc_version_mismatch
}

kv_get() {
  key=$1
  file=$2
  awk -F= -v wanted="$key" '
    /^[[:space:]]*(#|$)/ { next }
    $1 == wanted {
      if (seen) exit 2
      value = substr($0, index($0, "=") + 1)
      sub(/\r$/, "", value)
      print value
      seen = 1
    }
    END { if (!seen) exit 1 }
  ' "$file"
}

load_baseline() {
  file=$1
  [ -f "$file" ] || error baseline_missing

  unknown=$(awk -F= '
    /^[[:space:]]*(#|$)/ { next }
    $1 !~ /^(schema|series|tool|tool_version|metric|milestone|commit|code|tests|max_test_growth|ticket_warning)$/ { print $1; exit }
  ' "$file")
  [ -z "$unknown" ] || error baseline_unknown_key

  b_schema=$(kv_get schema "$file") || error baseline_schema_missing
  b_series=$(kv_get series "$file") || error baseline_series_missing
  b_tool=$(kv_get tool "$file") || error baseline_tool_missing
  b_tool_version=$(kv_get tool_version "$file") || error baseline_tool_version_missing
  b_metric=$(kv_get metric "$file") || error baseline_metric_missing
  b_milestone=$(kv_get milestone "$file") || error baseline_milestone_missing
  b_commit=$(kv_get commit "$file") || error baseline_commit_missing
  b_code=$(kv_get code "$file") || error baseline_code_missing
  b_tests=$(kv_get tests "$file") || error baseline_tests_missing
  b_max_test_growth=$(kv_get max_test_growth "$file") || error baseline_max_test_growth_missing
  b_ticket_warning=$(kv_get ticket_warning "$file") || error baseline_ticket_warning_missing

  [ "$b_schema" = 2 ] || error baseline_schema_mismatch
  [ "$b_series" = "$SERIES" ] || error baseline_series_mismatch
  [ "$b_tool" = "$TOOL_NAME" ] || error baseline_tool_mismatch
  [ "$b_tool_version" = "$TOOL_VERSION" ] || error baseline_tool_version_mismatch
  [ "$b_metric" = "$METRIC" ] || error baseline_metric_mismatch
  printf '%s\n' "$b_milestone" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*$' \
    || error baseline_milestone_invalid
  printf '%s\n' "$b_commit" | grep -Eq '^[0-9a-f]{40}$' || error baseline_commit_invalid
  is_uint "$b_code" || error baseline_code_invalid
  is_uint "$b_tests" || error baseline_tests_invalid
  is_uint "$b_max_test_growth" || error baseline_max_test_growth_invalid
  is_uint "$b_ticket_warning" || error baseline_ticket_warning_invalid
  [ "$b_code" -gt 0 ] || error baseline_code_zero
  resolve_commit "$b_commit" >/dev/null
}

materialize_tree() {
  object=$1
  dest=$2
  need_tmp
  tree=$(git rev-parse --verify "$object^{tree}" 2>/dev/null) || error invalid_tree
  index="$tmp_root/index.$$.${materialize_seq:-0}"
  materialize_seq=$(( ${materialize_seq:-0} + 1 ))
  mkdir -p "$dest"
  rm -f "$index"
  GIT_INDEX_FILE="$index" git read-tree "$tree" >/dev/null 2>&1 || error read_tree_failed
  GIT_INDEX_FILE="$index" git checkout-index --all --force --prefix="$dest/" >/dev/null 2>&1 || error checkout_index_failed
  rm -f "$index"
}

parse_csv_total() {
  file=$1
  awk -F, '
    function clean(v) {
      gsub(/\r/, "", v)
      gsub(/^"|"$/, "", v)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
      return v
    }
    NR == 1 {
      for (i = 1; i <= NF; i++) {
        name = tolower(clean($i))
        column[name] = i
      }
      if (!("label" in column) || !("code" in column) ||
          !("tests" in column) || !("examples" in column)) {
        invalid = 1
      }
      next
    }
    invalid { next }
    {
      label = clean($(column["label"]))
      if (toupper(label) ~ /^TOTAL([[:space:]]*\(|$)/) {
        if (found) {
          invalid = 1
          next
        }
        code = clean($(column["code"]))
        tests = clean($(column["tests"]))
        examples = clean($(column["examples"]))
        if (code !~ /^[0-9]+$/ || tests !~ /^[0-9]+$/ || examples !~ /^[0-9]+$/) {
          invalid = 1
          next
        }
        result = code " " tests " " examples
        found = 1
      }
    }
    END {
      if (invalid || !found) exit 2
      print result
    }
  ' "$file"
}

count_dir() {
  dir=$1
  label=$2
  need_tmp
  csv="$tmp_root/$label.csv"
  (cd "$dir" && "$TOOL" --lang rust -t code,tests,examples --output csv --output-file-path "$csv" >/dev/null) \
    || error rustloc_count_failed
  values=$(parse_csv_total "$csv") || error rustloc_csv_invalid
  set -- $values
  count_code=$1
  count_tests=$2
  count_examples=$3
}

count_object() {
  object=$1
  label=$2
  need_tmp
  dir="$tmp_root/tree.$label"
  materialize_tree "$object" "$dir"
  count_dir "$dir" "$label"
}

count_staged() {
  need_tmp
  tree=$(git write-tree 2>/dev/null) || error write_tree_failed
  count_object "$tree" staged
}

verify_baseline() {
  verify_candidate=$1
  git merge-base --is-ancestor "$b_commit" "$verify_candidate" 2>/dev/null \
    || error baseline_not_ancestor
  count_object "$b_commit" baseline
  [ "$count_code" -eq "$b_code" ] || error baseline_code_mismatch
  [ "$count_tests" -eq "$b_tests" ] || error baseline_tests_mismatch
  printf 'test_budget baseline=PASS schema=2 series=%s milestone=%s commit=%s code=%s tests=%s ratio=%s max_test_growth=%s ticket_warning=%s\n' \
    "$b_series" "$b_milestone" "$b_commit" "$b_code" "$b_tests" \
    "$(ratio "$b_tests" "$b_code")" "$b_max_test_growth" "$b_ticket_warning"
}

ratio() {
  awk -v n="$1" -v d="$2" 'BEGIN { printf "%.6f", n / d }'
}

positive_growth() {
  if [ "$1" -gt "$2" ]; then
    printf '%s\n' $(( $1 - $2 ))
  else
    printf '0\n'
  fi
}

compare_budget() {
  mode=$1
  base_code=$2
  base_tests=$3
  candidate_code=$4
  candidate_tests=$5

  [ "$candidate_code" -gt 0 ] || blocked candidate_code_zero
  ticket_code_growth=$(positive_growth "$candidate_code" "$base_code")
  ticket_test_growth=$(positive_growth "$candidate_tests" "$base_tests")
  ticket_debt=$(( ticket_test_growth - ticket_code_growth ))
  test_growth=$(positive_growth "$candidate_tests" "$b_tests")

  if [ "$test_growth" -gt "$b_max_test_growth" ]; then
    printf 'test_budget status=BLOCKED reason=test_growth_limit_exceeded mode=%s milestone=%s code=%s tests=%s test_growth=%s max_test_growth=%s\n' \
      "$mode" "$b_milestone" "$candidate_code" "$candidate_tests" \
      "$test_growth" "$b_max_test_growth" >&2
    exit 1
  fi

  ticket_warning=no
  case "$mode" in
    ticket-staged|ticket-commit|ci)
      if [ "$ticket_test_growth" -gt "$b_ticket_warning" ]; then
        ticket_warning=yes
        printf 'test_budget warning=ticket_test_growth_exceeded mode=%s ticket_test_growth=%s threshold=%s\n' \
          "$mode" "$ticket_test_growth" "$b_ticket_warning"
      fi
      ;;
  esac

  remaining=$(( b_max_test_growth - test_growth ))
  printf 'test_budget status=PASS mode=%s milestone=%s code=%s tests=%s examples=%s ratio=%s test_growth=%s max_test_growth=%s remaining=%s ticket_code_growth=%s ticket_test_growth=%s ticket_debt=%s ticket_warning=%s\n' \
    "$mode" "$b_milestone" "$candidate_code" "$candidate_tests" \
    "$candidate_examples" "$(ratio "$candidate_tests" "$candidate_code")" \
    "$test_growth" "$b_max_test_growth" "$remaining" "$ticket_code_growth" \
    "$ticket_test_growth" "$ticket_debt" "$ticket_warning"
}

branch_base() {
  branch=$(git symbolic-ref --quiet --short HEAD 2>/dev/null) || error detached_head
  git config --local --get "branch.$branch.testBudgetBase" 2>/dev/null || error ticket_base_not_bound
}

control_paths() {
  case "$1" in
    scripts/test-budget.sh|ci/test-budget-baseline.txt|.githooks/pre-commit|.github/workflows/m0.yml|.gitattributes)
      return 0 ;;
    *) return 1 ;;
  esac
}

staged_control_changed() {
  git diff --cached --name-only | while IFS= read -r path; do
    if control_paths "$path"; then
      printf '%s\n' "$path"
    fi
  done
}

range_control_changed() {
  from=$1
  to=$2
  git diff --name-only "$from" "$to" | while IFS= read -r path; do
    if control_paths "$path"; then
      printf '%s\n' "$path"
    fi
  done
}

only_control_and_docs() {
  allowed_saw_control=false
  while IFS= read -r allowed_path; do
    [ -n "$allowed_path" ] || continue
    if control_paths "$allowed_path"; then
      allowed_saw_control=true
    else
      case "$allowed_path" in
        *.md) ;;
        *) return 1 ;;
      esac
    fi
  done
  [ "$allowed_saw_control" = true ]
}

validate_staged_control() {
  validation_controls=$(staged_control_changed)
  [ -n "$validation_controls" ] || return 0
  git rev-parse --verify -q MERGE_HEAD >/dev/null 2>&1 \
    && blocked control_commit_must_be_single_parent
  validation_paths=$(git diff --cached --name-only)
  printf '%s\n' "$validation_paths" | only_control_and_docs \
    || blocked control_plane_changed
  if printf '%s\n' "$validation_controls" | grep -Fqx "$BASELINE_FILE"; then
    need_tmp
    validation_old="$tmp_root/staged-old-baseline.txt"
    validation_new="$tmp_root/staged-new-baseline.txt"
    baseline_from_commit HEAD "$validation_old"
    git show ":$BASELINE_FILE" > "$validation_new" 2>/dev/null \
      || error staged_baseline_missing
    validate_policy_transition "$validation_old" "$validation_new" HEAD
  fi
  printf 'test_budget control=PASS mode=ticket-staged\n'
}

path_blob_at() {
  git rev-parse --verify "$1:$2" 2>/dev/null || printf '%s\n' missing
}

merge_inherits_control_paths() {
  validation_merge=$1
  set -- $(git rev-list --parents -n 1 "$validation_merge")
  shift
  for validation_path in scripts/test-budget.sh ci/test-budget-baseline.txt \
    .githooks/pre-commit .github/workflows/m0.yml .gitattributes; do
    validation_blob=$(path_blob_at "$validation_merge" "$validation_path")
    validation_inherited=false
    for validation_parent in "$@"; do
      if [ "$validation_blob" = "$(path_blob_at "$validation_parent" "$validation_path")" ]; then
        validation_inherited=true
        break
      fi
    done
    [ "$validation_inherited" = true ] || return 1
  done
}

validate_control_range() {
  validation_base=$1
  validation_candidate=$2
  for validation_commit in $(git rev-list --reverse --ancestry-path \
    "$validation_base..$validation_candidate"); do
    validation_parent_count=$(count_parents "$validation_commit")
    if [ "$validation_parent_count" -ne 1 ]; then
      merge_inherits_control_paths "$validation_commit" \
        || blocked control_merge_resolution
      continue
    fi
    validation_parent=$(first_parent "$validation_commit")
    validation_controls=$(range_control_changed "$validation_parent" "$validation_commit")
    [ -n "$validation_controls" ] || continue
    validation_paths=$(git diff --name-only "$validation_parent" "$validation_commit")
    printf '%s\n' "$validation_paths" | only_control_and_docs \
      || blocked control_plane_changed
    if ! git diff --quiet "$validation_parent" "$validation_commit" -- "$BASELINE_FILE"; then
      need_tmp
      validation_old="$tmp_root/policy-old.$validation_commit.txt"
      validation_new="$tmp_root/policy-new.$validation_commit.txt"
      baseline_from_commit "$validation_parent" "$validation_old"
      baseline_from_commit "$validation_commit" "$validation_new"
      validate_policy_transition "$validation_old" "$validation_new" "$validation_commit"
    fi
    printf 'test_budget control=PASS mode=commit commit=%s\n' "$validation_commit"
  done
}

baseline_from_commit() {
  commit=$1
  dest=$2
  git show "$commit:$BASELINE_FILE" > "$dest" 2>/dev/null || error baseline_missing_in_candidate
}

range_rust_changed() {
  git log --format= --name-only "$1..$2" -- '*.rs' | grep -q .
}

validate_policy_transition() {
  transition_old=$1
  transition_new=$2
  transition_end=$3

  load_baseline "$transition_new"
  new_milestone=$b_milestone
  new_commit=$b_commit
  new_code=$b_code
  new_tests=$b_tests
  new_max_test_growth=$b_max_test_growth
  new_ticket_warning=$b_ticket_warning

  old_schema=$(kv_get schema "$transition_old") || error policy_transition_source_schema_missing
  case "$old_schema" in
    1)
      range_rust_changed "$new_commit" "$transition_end" \
        && blocked policy_activation_after_rust_change
      ;;
    2)
      load_baseline "$transition_old"
      old_milestone=$b_milestone
      old_commit=$b_commit
      old_code=$b_code
      old_tests=$b_tests
      old_max_test_growth=$b_max_test_growth
      old_ticket_warning=$b_ticket_warning
      if [ "$new_milestone" = "$old_milestone" ]; then
        [ "$new_commit" = "$old_commit" ] || blocked policy_base_changed_within_milestone
        [ "$new_code" -eq "$old_code" ] || blocked policy_base_code_changed_within_milestone
        [ "$new_tests" -eq "$old_tests" ] || blocked policy_base_tests_changed_within_milestone
        [ "$new_ticket_warning" -eq "$old_ticket_warning" ] \
          || blocked policy_ticket_warning_changed_within_milestone
        [ "$new_max_test_growth" -le "$old_max_test_growth" ] \
          || blocked policy_envelope_increase
      else
        range_rust_changed "$new_commit" "$transition_end" \
          && blocked policy_activation_after_rust_change
      fi
      ;;
    *) error policy_transition_source_schema_mismatch ;;
  esac

  load_baseline "$transition_new"
  verify_baseline "$transition_end"
  printf 'test_budget policy_transition=PASS milestone=%s base=%s max_test_growth=%s\n' \
    "$b_milestone" "$b_commit" "$b_max_test_growth"
}

self_test() {
  b_milestone=self-test
  b_code=100
  b_tests=200
  b_max_test_growth=10
  b_ticket_warning=5
  candidate_examples=0

  output=$(compare_budget ticket-commit 100 200 1000 210)
  printf '%s\n' "$output" | grep -Fq 'status=PASS' || error self_test_equality_failed
  printf '%s\n' "$output" | grep -Fq 'test_growth=10' || error self_test_growth_failed
  printf '%s\n' "$output" | grep -Fq 'ticket_warning=yes' || error self_test_warning_failed

  overflow_status=0
  (compare_budget ticket-commit 100 200 100000 211 >/dev/null 2>&1) || overflow_status=$?
  [ "$overflow_status" -eq 1 ] || error self_test_overflow_failed
  printf 'test_budget self_test=PASS equality=PASS overflow=BLOCKED code_padding=NO_EFFECT warning=PASS\n'
}

command=${1:-}
[ -n "$command" ] || { usage >&2; exit 2; }
shift

case "$command" in
  install-hook)
    force=false
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --force) force=true; shift ;;
        *) usage >&2; exit 2 ;;
      esac
    done
    [ -x .githooks/pre-commit ] || error hook_missing_or_not_executable
    current=$(git config --local --get core.hooksPath 2>/dev/null || true)
    if [ -n "$current" ] && [ "$current" != .githooks ] && ! $force; then
      error hooks_path_conflict
    fi
    git config --local core.hooksPath .githooks
    printf 'test_budget hook=PASS path=.githooks\n'
    ;;

  bind)
    base=HEAD
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --base) base=$2; shift 2 ;;
        *) usage >&2; exit 2 ;;
      esac
    done
    base=$(resolve_commit "$base")
    branch=$(git symbolic-ref --quiet --short HEAD 2>/dev/null) || error detached_head
    load_baseline "$BASELINE_FILE"
    git merge-base --is-ancestor "$b_commit" "$base" 2>/dev/null \
      || error ticket_base_before_baseline
    current=$(git config --local --get "branch.$branch.testBudgetBase" 2>/dev/null || true)
    if [ -n "$current" ] && [ "$current" != "$base" ]; then
      error ticket_base_already_bound
    fi
    git config --local "branch.$branch.testBudgetBase" "$base"
    printf 'test_budget bind=PASS branch=%s base=%s\n' "$branch" "$base"
    ;;

  verify)
    candidate=HEAD
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --candidate) candidate=$2; shift 2 ;;
        *) usage >&2; exit 2 ;;
      esac
    done
    candidate=$(resolve_commit "$candidate")
    check_tool
    need_tmp
    candidate_baseline="$tmp_root/verify-baseline.txt"
    baseline_from_commit "$candidate" "$candidate_baseline"
    load_baseline "$candidate_baseline"
    verify_baseline "$candidate"
    ;;

  ticket)
    staged=false
    candidate=
    base=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --staged) staged=true; shift ;;
        --candidate) candidate=$2; shift 2 ;;
        --base) base=$2; shift 2 ;;
        *) usage >&2; exit 2 ;;
      esac
    done
    if $staged && [ -n "$candidate" ]; then error candidate_mode_conflict; fi
    [ -n "$base" ] || base=$(branch_base)
    base=$(resolve_commit "$base")
    check_tool

    if $staged || [ -z "$candidate" ]; then
      need_tmp
      staged_baseline="$tmp_root/ticket-staged-baseline.txt"
      git show ":$BASELINE_FILE" > "$staged_baseline" 2>/dev/null \
        || error staged_baseline_missing
      load_baseline "$staged_baseline"
      git merge-base --is-ancestor "$b_commit" "$base" 2>/dev/null \
        || error ticket_base_before_baseline
      verify_baseline "$base"
      count_object "$base" ticket_base
      base_code=$count_code
      base_tests=$count_tests
      validate_staged_control
      count_staged
      mode=ticket-staged
    else
      candidate=$(resolve_commit "$candidate")
      git merge-base --is-ancestor "$base" "$candidate" 2>/dev/null || error ticket_base_not_ancestor
      validate_control_range "$base" "$candidate"
      need_tmp
      candidate_baseline="$tmp_root/ticket-candidate-baseline.txt"
      baseline_from_commit "$candidate" "$candidate_baseline"
      load_baseline "$candidate_baseline"
      git merge-base --is-ancestor "$b_commit" "$base" 2>/dev/null \
        || error ticket_base_before_baseline
      verify_baseline "$candidate"
      count_object "$base" ticket_base
      base_code=$count_code
      base_tests=$count_tests
      count_object "$candidate" ticket_candidate
      mode=ticket-commit
    fi
    candidate_code=$count_code
    candidate_tests=$count_tests
    candidate_examples=$count_examples
    compare_budget "$mode" "$base_code" "$base_tests" "$candidate_code" "$candidate_tests"
    ;;

  milestone)
    candidate=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --candidate) candidate=$2; shift 2 ;;
        *) usage >&2; exit 2 ;;
      esac
    done
    [ -n "$candidate" ] || error candidate_required
    candidate=$(resolve_commit "$candidate")
    check_tool
    need_tmp
    candidate_baseline="$tmp_root/milestone-baseline.txt"
    baseline_from_commit "$candidate" "$candidate_baseline"
    load_baseline "$candidate_baseline"
    verify_baseline "$candidate"
    count_object "$candidate" milestone_candidate
    candidate_code=$count_code
    candidate_tests=$count_tests
    candidate_examples=$count_examples
    compare_budget milestone "$b_code" "$b_tests" "$candidate_code" "$candidate_tests"
    ;;

  ci)
    candidate=
    base=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --candidate) candidate=$2; shift 2 ;;
        --base) base=$2; shift 2 ;;
        *) usage >&2; exit 2 ;;
      esac
    done
    [ -n "$candidate" ] || error candidate_required
    candidate=$(resolve_commit "$candidate")
    [ -n "$base" ] || base=$(first_parent "$candidate")
    base=$(resolve_commit "$base")
    git merge-base --is-ancestor "$base" "$candidate" 2>/dev/null || error ci_base_not_ancestor
    check_tool
    need_tmp
    validate_control_range "$base" "$candidate"
    candidate_baseline="$tmp_root/ci-candidate-baseline.txt"
    baseline_from_commit "$candidate" "$candidate_baseline"
    load_baseline "$candidate_baseline"
    verify_baseline "$candidate"
    count_object "$base" ci_base
    base_code=$count_code
    base_tests=$count_tests
    count_object "$candidate" ci_candidate
    candidate_code=$count_code
    candidate_tests=$count_tests
    candidate_examples=$count_examples
    compare_budget ci "$base_code" "$base_tests" "$candidate_code" "$candidate_tests"
    ;;

  self-test)
    [ "$#" -eq 0 ] || { usage >&2; exit 2; }
    self_test
    ;;

  -h|--help|help)
    usage
    ;;

  *)
    usage >&2
    exit 2
    ;;
esac
