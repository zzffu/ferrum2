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
TICKET_ALLOWANCE=120
RATCHET_STEP_NUM=1
RATCHET_STEP_DEN=20
TARGET_RATIO_NUM=1
TARGET_RATIO_DEN=1
MIN_GROWTH=200

usage() {
  cat <<'USAGE'
Usage:
  test-budget.sh install-hook [--force]
  test-budget.sh bind [--base COMMIT]
  test-budget.sh verify [--candidate COMMIT]
  test-budget.sh ticket [--staged | --candidate COMMIT] [--base COMMIT]
  test-budget.sh milestone --candidate COMMIT
  test-budget.sh ratchet --candidate COMMIT --write
  test-budget.sh ci --candidate COMMIT [--base COMMIT]

Exit 0: PASS/PASS_HOLD; exit 1: BLOCKED; exit 2: ERROR.
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
    $1 !~ /^(schema|series|tool|tool_version|metric|commit|code|tests)$/ { print $1; exit }
  ' "$file")
  [ -z "$unknown" ] || error baseline_unknown_key

  b_schema=$(kv_get schema "$file") || error baseline_schema_missing
  b_series=$(kv_get series "$file") || error baseline_series_missing
  b_tool=$(kv_get tool "$file") || error baseline_tool_missing
  b_tool_version=$(kv_get tool_version "$file") || error baseline_tool_version_missing
  b_metric=$(kv_get metric "$file") || error baseline_metric_missing
  b_commit=$(kv_get commit "$file") || error baseline_commit_missing
  b_code=$(kv_get code "$file") || error baseline_code_missing
  b_tests=$(kv_get tests "$file") || error baseline_tests_missing

  [ "$b_schema" = 1 ] || error baseline_schema_mismatch
  [ "$b_series" = "$SERIES" ] || error baseline_series_mismatch
  [ "$b_tool" = "$TOOL_NAME" ] || error baseline_tool_mismatch
  [ "$b_tool_version" = "$TOOL_VERSION" ] || error baseline_tool_version_mismatch
  [ "$b_metric" = "$METRIC" ] || error baseline_metric_mismatch
  printf '%s\n' "$b_commit" | grep -Eq '^[0-9a-f]{40}$' || error baseline_commit_invalid
  is_uint "$b_code" || error baseline_code_invalid
  is_uint "$b_tests" || error baseline_tests_invalid
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
  printf 'test_budget baseline=PASS series=%s commit=%s code=%s tests=%s ratio=%s\n' \
    "$b_series" "$b_commit" "$b_code" "$b_tests" "$(ratio "$b_tests" "$b_code")"
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

  anchor_code_growth=$(positive_growth "$candidate_code" "$b_code")
  anchor_test_growth=$(positive_growth "$candidate_tests" "$b_tests")
  anchor_debt=$(( anchor_test_growth - anchor_code_growth ))
  material_growth=$(( anchor_code_growth + anchor_test_growth ))

  ratio_state=held
  if [ $(( candidate_tests * b_code )) -gt $(( b_tests * candidate_code )) ]; then
    ratio_state=regressed
  elif [ $(( candidate_tests * b_code )) -lt $(( b_tests * candidate_code )) ]; then
    ratio_state=improved
  fi

  [ "$ticket_debt" -le "$TICKET_ALLOWANCE" ] || blocked ticket_allowance_exceeded
  [ "$anchor_debt" -le "$TICKET_ALLOWANCE" ] || blocked anchor_allowance_exceeded

  required_num=$b_tests
  required_den=$b_code
  baseline_eligible=no

  if [ "$material_growth" -ge "$MIN_GROWTH" ]; then
    step_num=$(( RATCHET_STEP_DEN * b_tests - RATCHET_STEP_NUM * b_code ))
    step_den=$(( RATCHET_STEP_DEN * b_code ))
    if [ $(( step_num * TARGET_RATIO_DEN )) -le $(( TARGET_RATIO_NUM * step_den )) ]; then
      required_num=$TARGET_RATIO_NUM
      required_den=$TARGET_RATIO_DEN
    else
      required_num=$step_num
      required_den=$step_den
    fi
    [ $(( candidate_tests * required_den )) -le $(( required_num * candidate_code )) ] \
      || blocked milestone_ratchet_missed
    baseline_eligible=yes
    status=PASS_ADVANCE
  elif [ "$ratio_state" = regressed ]; then
    status=PASS_HOLD
  else
    status=PASS_ADVANCE
    baseline_eligible=yes
  fi

  printf 'test_budget status=%s mode=%s code=%s tests=%s examples=%s ratio=%s ratio_state=%s ticket_code_growth=%s ticket_test_growth=%s ticket_debt=%s anchor_code_growth=%s anchor_test_growth=%s anchor_debt=%s material_growth=%s required=%s/%s required_ratio=%s baseline_eligible=%s\n' \
    "$status" "$mode" "$candidate_code" "$candidate_tests" "$candidate_examples" \
    "$(ratio "$candidate_tests" "$candidate_code")" "$ratio_state" \
    "$ticket_code_growth" "$ticket_test_growth" "$ticket_debt" \
    "$anchor_code_growth" "$anchor_test_growth" "$anchor_debt" "$material_growth" \
    "$required_num" "$required_den" "$(ratio "$required_num" "$required_den")" \
    "$baseline_eligible"
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
  printf '%s\n' "$validation_controls" | grep -Fqx "$BASELINE_FILE" \
    && blocked ratchet_commit_not_baseline_only
  git rev-parse --verify -q MERGE_HEAD >/dev/null 2>&1 \
    && blocked control_commit_must_be_single_parent
  validation_paths=$(git diff --cached --name-only)
  printf '%s\n' "$validation_paths" | only_control_and_docs \
    || blocked control_plane_changed
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
    printf 'test_budget control=PASS mode=commit commit=%s\n' "$validation_commit"
  done
}

baseline_from_commit() {
  commit=$1
  dest=$2
  git show "$commit:$BASELINE_FILE" > "$dest" 2>/dev/null || error baseline_missing_in_candidate
}

baseline_exists_at() {
  git cat-file -e "$1:$BASELINE_FILE" 2>/dev/null
}

rust_changed() {
  git diff --name-only "$1" "$2" -- '*.rs' | grep -q .
}

range_rust_changed() {
  git log --format= --name-only "$1..$2" -- '*.rs' | grep -q .
}

only_path_changed() {
  from=$1
  to=$2
  path=$3
  changed=$(git diff --name-only "$from" "$to")
  [ "$changed" = "$path" ]
}

write_baseline() {
  candidate=$1
  code=$2
  tests=$3
  need_tmp
  target="$tmp_root/new-baseline.txt"
  cat > "$target" <<EOF_BASELINE
schema=1
series=$SERIES
tool=$TOOL_NAME
tool_version=$TOOL_VERSION
metric=$METRIC
commit=$candidate
code=$code
tests=$tests
EOF_BASELINE
  if [ -f "$BASELINE_FILE" ] && cmp -s "$target" "$BASELINE_FILE"; then
    baseline_changed=false
  else
    cp "$target" "$BASELINE_FILE"
    baseline_changed=true
  fi
}

same_file_at() {
  left=$1
  right=$2
  path=$3
  left_blob=$(git rev-parse "$left:$path" 2>/dev/null || true)
  right_blob=$(git rev-parse "$right:$path" 2>/dev/null || true)
  [ -n "$left_blob" ] && [ "$left_blob" = "$right_blob" ]
}

content_parent() {
  commit=$1
  path=$2
  set -- $(git rev-list --parents -n 1 "$commit")
  shift
  match=
  for parent in "$@"; do
    if same_file_at "$commit" "$parent" "$path"; then
      [ -z "$match" ] || error ambiguous_content_parent
      match=$parent
    fi
  done
  [ -n "$match" ] || error content_parent_not_found
  printf '%s\n' "$match"
}

find_adoption_commit() {
  adoption_base=$1
  adoption_candidate=$2
  adoption_source=$3
  adoption_match=
  for adoption_item in $(git rev-list --reverse --ancestry-path \
    "$adoption_base..$adoption_candidate"); do
    [ "$(count_parents "$adoption_item")" -eq 1 ] || continue
    [ "$(first_parent "$adoption_item")" = "$adoption_source" ] || continue
    baseline_exists_at "$adoption_item" || continue
    baseline_exists_at "$adoption_source" && continue
    [ -z "$adoption_match" ] || error ambiguous_adoption_commit
    adoption_match=$adoption_item
  done
  [ -n "$adoption_match" ] || blocked adoption_commit_not_found
  printf '%s\n' "$adoption_match"
}

require_only_baseline_dirty() {
  git diff --quiet HEAD -- . ":(exclude)$BASELINE_FILE" \
    || error ratchet_worktree_has_other_changes
  untracked=$(git ls-files --others --exclude-standard)
  [ -z "$untracked" ] || error ratchet_worktree_has_untracked_files
}

staged_ratchet() {
  require_only_baseline_dirty
  need_tmp
  head=$(resolve_commit HEAD)
  old_baseline="$tmp_root/staged-old-baseline.txt"
  new_baseline="$tmp_root/staged-new-baseline.txt"
  baseline_from_commit "$head" "$old_baseline"
  git show ":$BASELINE_FILE" > "$new_baseline" 2>/dev/null || error staged_baseline_missing

  load_baseline "$old_baseline"
  verify_baseline "$head"
  count_object "$head" staged_ratchet_candidate
  candidate_code=$count_code
  candidate_tests=$count_tests
  candidate_examples=$count_examples
  output=$(compare_budget staged-ratchet "$b_code" "$b_tests" "$candidate_code" "$candidate_tests") || exit $?
  printf '%s\n' "$output"
  printf '%s\n' "$output" | grep -q 'baseline_eligible=yes' || blocked baseline_not_eligible

  load_baseline "$new_baseline"
  [ "$b_commit" = "$head" ] || blocked ratchet_commit_pointer_mismatch
  [ "$b_code" -eq "$candidate_code" ] || blocked ratchet_code_mismatch
  [ "$b_tests" -eq "$candidate_tests" ] || blocked ratchet_tests_mismatch
  printf 'test_budget status=PASS_RATCHET_STAGED mode=ticket commit=%s\n' "$head"
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
    load_baseline "$BASELINE_FILE"
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
    if $staged; then
      staged_paths=$(git diff --cached --name-only)
      if [ "$staged_paths" = "$BASELINE_FILE" ]; then
        check_tool
        staged_ratchet
        exit 0
      fi
    fi
    [ -n "$base" ] || base=$(branch_base)
    base=$(resolve_commit "$base")
    check_tool
    load_baseline "$BASELINE_FILE"
    git merge-base --is-ancestor "$b_commit" "$base" 2>/dev/null || error ticket_base_before_baseline
    verify_baseline "$base"
    count_object "$base" ticket_base
    base_code=$count_code
    base_tests=$count_tests

    if $staged || [ -z "$candidate" ]; then
      validate_staged_control
      count_staged
      mode=ticket-staged
    else
      candidate=$(resolve_commit "$candidate")
      git merge-base --is-ancestor "$base" "$candidate" 2>/dev/null || error ticket_base_not_ancestor
      validate_control_range "$base" "$candidate"
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
    load_baseline "$BASELINE_FILE"
    verify_baseline "$candidate"
    count_object "$candidate" milestone_candidate
    candidate_code=$count_code
    candidate_tests=$count_tests
    candidate_examples=$count_examples
    compare_budget milestone "$b_code" "$b_tests" "$candidate_code" "$candidate_tests"
    ;;

  ratchet)
    candidate=
    write=false
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --candidate) candidate=$2; shift 2 ;;
        --write) write=true; shift ;;
        *) usage >&2; exit 2 ;;
      esac
    done
    [ -n "$candidate" ] || error candidate_required
    $write || error write_required
    candidate=$(resolve_commit "$candidate")
    head=$(resolve_commit HEAD)
    [ "$candidate" = "$head" ] || error ratchet_candidate_not_head
    require_only_baseline_dirty
    check_tool
    need_tmp
    accepted_baseline="$tmp_root/ratchet-accepted-baseline.txt"
    baseline_from_commit "$head" "$accepted_baseline"
    load_baseline "$accepted_baseline"

    # A committed baseline-only closeout is already complete. Treat reruns as a
    # verified no-op instead of creating an endless chain of baseline commits.
    if [ "$(count_parents "$head")" -eq 1 ]; then
      parent=$(first_parent "$head")
      if [ "$b_commit" = "$parent" ] && only_path_changed "$parent" "$head" "$BASELINE_FILE"; then
        verify_baseline "$head"
        count_object "$head" closed_ratchet_candidate
        [ "$count_code" -eq "$b_code" ] || error ratchet_code_mismatch
        [ "$count_tests" -eq "$b_tests" ] || error ratchet_tests_mismatch
        printf 'test_budget ratchet=PASS commit=%s file=%s changed=no already_closed=yes\n' \
          "$head" "$BASELINE_FILE"
        exit 0
      fi
    fi

    verify_baseline "$candidate"
    count_object "$candidate" ratchet_candidate
    candidate_code=$count_code
    candidate_tests=$count_tests
    candidate_examples=$count_examples

    # Capture the comparison output while preserving its exit status.
    output=$(compare_budget ratchet "$b_code" "$b_tests" "$candidate_code" "$candidate_tests") || exit $?
    printf '%s\n' "$output"
    printf '%s\n' "$output" | grep -q 'baseline_eligible=yes' || blocked baseline_not_eligible
    write_baseline "$candidate" "$candidate_code" "$candidate_tests"
    printf 'test_budget ratchet=PASS commit=%s file=%s changed=%s already_closed=no\n' \
      "$candidate" "$BASELINE_FILE" "$baseline_changed"
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

    candidate_baseline="$tmp_root/candidate-baseline.txt"
    baseline_from_commit "$candidate" "$candidate_baseline"
    load_baseline "$candidate_baseline"

    parent_count=$(count_parents "$candidate")
    baseline_changed_in_range=false
    if ! git diff --quiet "$base" "$candidate" -- "$BASELINE_FILE"; then
      baseline_changed_in_range=true
    fi

    # Initial adoption may be an intermediate commit in a push range. Its
    # baseline still points at its exact non-Rust parent; later Rust commits are
    # measured normally against that accepted anchor.
    if ! baseline_exists_at "$base"; then
      git merge-base --is-ancestor "$base" "$b_commit" 2>/dev/null \
        || blocked adoption_source_outside_range
      adoption_commit=$(find_adoption_commit "$base" "$candidate" "$b_commit")
      [ "$(count_parents "$adoption_commit")" -eq 1 ] \
        || blocked adoption_commit_must_be_single_parent
      adoption_source=$(first_parent "$adoption_commit")
      [ "$b_commit" = "$adoption_source" ] || blocked adoption_baseline_mismatch
      if range_rust_changed "$base" "$adoption_commit"; then blocked adoption_changes_rust; fi
      validate_control_range "$adoption_commit" "$candidate"
      verify_baseline "$candidate"
      count_object "$candidate" adoption_candidate
      candidate_code=$count_code
      candidate_tests=$count_tests
      candidate_examples=$count_examples
      printf 'test_budget adoption=PASS mode=ci commit=%s source=%s\n' \
        "$adoption_commit" "$adoption_source"
      compare_budget ci-adopt "$b_code" "$b_tests" "$candidate_code" "$candidate_tests"
      exit 0
    fi

    validate_control_range "$base" "$candidate"

    # Ratchet commits are baseline-only and point to their exact parent. For a
    # pull request merge SHA, inspect the parent that supplied the new baseline.
    if $baseline_changed_in_range; then
      if [ "$parent_count" -eq 1 ]; then
        closeout_commit=$candidate
      else
        closeout_commit=$(content_parent "$candidate" "$BASELINE_FILE")
      fi
      [ "$(count_parents "$closeout_commit")" -eq 1 ] \
        || blocked ratchet_closeout_must_be_single_parent
      closeout_source=$(first_parent "$closeout_commit")
      only_path_changed "$closeout_source" "$closeout_commit" "$BASELINE_FILE" \
        || blocked ratchet_commit_not_baseline_only
      [ "$b_commit" = "$closeout_source" ] || blocked ratchet_commit_pointer_mismatch

      old_baseline="$tmp_root/old-baseline.txt"
      baseline_from_commit "$closeout_source" "$old_baseline"
      load_baseline "$old_baseline"
      verify_baseline "$closeout_source"
      count_object "$closeout_source" accepted_candidate
      candidate_code=$count_code
      candidate_tests=$count_tests
      candidate_examples=$count_examples
      output=$(compare_budget ci-ratchet "$b_code" "$b_tests" "$candidate_code" "$candidate_tests") || exit $?
      printf '%s\n' "$output"
      printf '%s\n' "$output" | grep -q 'baseline_eligible=yes' || blocked baseline_not_eligible

      load_baseline "$candidate_baseline"
      [ "$b_commit" = "$closeout_source" ] || blocked ratchet_commit_pointer_mismatch
      [ "$b_code" -eq "$candidate_code" ] || blocked ratchet_code_mismatch
      [ "$b_tests" -eq "$candidate_tests" ] || blocked ratchet_tests_mismatch
      verify_baseline "$candidate"
      count_object "$candidate" ratchet_exact_candidate
      [ "$count_code" -eq "$b_code" ] || blocked ratchet_merge_code_changed
      [ "$count_tests" -eq "$b_tests" ] || blocked ratchet_merge_tests_changed
      printf 'test_budget status=PASS_RATCHET mode=ci commit=%s closeout=%s baseline=%s\n' \
        "$candidate" "$closeout_commit" "$b_commit"
      exit 0
    fi

    git merge-base --is-ancestor "$b_commit" "$base" 2>/dev/null \
      || error ci_base_before_baseline
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

  -h|--help|help)
    usage
    ;;

  *)
    usage >&2
    exit 2
    ;;
esac
