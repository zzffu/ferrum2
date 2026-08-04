#!/bin/sh
set -eu

LC_ALL=C
export LC_ALL

TOOL_NAME=rustloc
TOOL=${RUSTLOC:-rustloc}
TOOL_VERSION=0.19.1
SCHEMA=3
SERIES=rustloc-0.19.1-test-footprint-v2
PREVIOUS_SERIES=rustloc-0.19.1-test-footprint-v1
LEGACY_SERIES=rustloc-0.19.1-tests-v1
METRIC=test_footprint
LEGACY_METRIC=tests
CLASSIFICATION=path-v2
PREVIOUS_CLASSIFICATION=path-v1
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

Exit 0: PASS, WARN, or REVIEW_REQUIRED.
Exit 1: BLOCKED because policy/control integrity failed.
Exit 2: ERROR because the tool, repository, or input could not be evaluated reliably.
USAGE
}

error() {
  printf 'test_budget status=ERROR policy=test_footprint reason=%s\n' "$1" >&2
  exit 2
}

blocked() {
  printf 'test_budget status=BLOCKED policy=test_footprint reason=%s\n' "$1" >&2
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
    tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/ferrum2-test-footprint.XXXXXX") \
      || error mktemp_failed
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

parse_baseline() {
  file=$1
  [ -f "$file" ] || error baseline_missing

  unknown=$(awk -F= '
    /^[[:space:]]*(#|$)/ { next }
    $1 !~ /^(schema|series|tool|tool_version|metric|classification|milestone|commit|code|tests|ratio_warning_milli|ratio_review_milli|ticket_warning|ticket_review|file_warning|file_review|policy_revision|reforecast_ref)$/ {
      print $1
      exit
    }
  ' "$file")
  [ -z "$unknown" ] || error baseline_unknown_key

  b_schema=$(kv_get schema "$file") || error baseline_schema_missing
  b_series=$(kv_get series "$file") || error baseline_series_missing
  b_tool=$(kv_get tool "$file") || error baseline_tool_missing
  b_tool_version=$(kv_get tool_version "$file") || error baseline_tool_version_missing
  b_metric=$(kv_get metric "$file") || error baseline_metric_missing
  b_classification=$(kv_get classification "$file") || error baseline_classification_missing
  b_milestone=$(kv_get milestone "$file") || error baseline_milestone_missing
  b_commit=$(kv_get commit "$file") || error baseline_commit_missing
  b_code=$(kv_get code "$file") || error baseline_code_missing
  b_tests=$(kv_get tests "$file") || error baseline_tests_missing
  b_ratio_warning_milli=$(kv_get ratio_warning_milli "$file") \
    || error baseline_ratio_warning_missing
  b_ratio_review_milli=$(kv_get ratio_review_milli "$file") \
    || error baseline_ratio_review_missing
  b_ticket_warning=$(kv_get ticket_warning "$file") || error baseline_ticket_warning_missing
  b_ticket_review=$(kv_get ticket_review "$file") || error baseline_ticket_review_missing
  b_file_warning=$(kv_get file_warning "$file") || error baseline_file_warning_missing
  b_file_review=$(kv_get file_review "$file") || error baseline_file_review_missing
  b_policy_revision=$(kv_get policy_revision "$file") || error baseline_policy_revision_missing
  b_reforecast_ref=$(kv_get reforecast_ref "$file") || error baseline_reforecast_ref_missing

  is_uint "$b_schema" || error baseline_schema_invalid
  printf '%s\n' "$b_milestone" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*$' \
    || error baseline_milestone_invalid
  printf '%s\n' "$b_commit" | grep -Eq '^[0-9a-f]{40}$' || error baseline_commit_invalid
  is_uint "$b_code" || error baseline_code_invalid
  is_uint "$b_tests" || error baseline_tests_invalid
  is_uint "$b_ratio_warning_milli" || error baseline_ratio_warning_invalid
  is_uint "$b_ratio_review_milli" || error baseline_ratio_review_invalid
  is_uint "$b_ticket_warning" || error baseline_ticket_warning_invalid
  is_uint "$b_ticket_review" || error baseline_ticket_review_invalid
  is_uint "$b_file_warning" || error baseline_file_warning_invalid
  is_uint "$b_file_review" || error baseline_file_review_invalid
  is_uint "$b_policy_revision" || error baseline_policy_revision_invalid
  printf '%s\n' "$b_reforecast_ref" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._/#-]*$' \
    || error baseline_reforecast_ref_invalid

  [ "$b_code" -gt 0 ] || error baseline_code_zero
  [ "$b_ratio_warning_milli" -gt 0 ] || error baseline_ratio_warning_zero
  [ "$b_ratio_review_milli" -gt "$b_ratio_warning_milli" ] \
    || error baseline_ratio_threshold_order
  [ "$b_ticket_warning" -gt 0 ] || error baseline_ticket_warning_zero
  [ "$b_ticket_review" -gt "$b_ticket_warning" ] \
    || error baseline_ticket_threshold_order
  [ "$b_file_warning" -gt 0 ] || error baseline_file_warning_zero
  [ "$b_file_review" -gt "$b_file_warning" ] || error baseline_file_threshold_order
  [ "$b_policy_revision" -gt 0 ] || error baseline_policy_revision_zero
  resolve_commit "$b_commit" >/dev/null
}

load_baseline() {
  parse_baseline "$1"
  [ "$b_schema" = "$SCHEMA" ] || error baseline_schema_mismatch
  [ "$b_series" = "$SERIES" ] || error baseline_series_mismatch
  [ "$b_tool" = "$TOOL_NAME" ] || error baseline_tool_mismatch
  [ "$b_tool_version" = "$TOOL_VERSION" ] || error baseline_tool_version_mismatch
  [ "$b_metric" = "$METRIC" ] || error baseline_metric_mismatch
  [ "$b_classification" = "$CLASSIFICATION" ] || error baseline_classification_mismatch
}

load_transition_baseline() {
  parse_baseline "$1"
  [ "$b_schema" = "$SCHEMA" ] || error baseline_schema_mismatch
  [ "$b_tool" = "$TOOL_NAME" ] || error baseline_tool_mismatch
  [ "$b_tool_version" = "$TOOL_VERSION" ] || error baseline_tool_version_mismatch
  [ "$b_metric" = "$METRIC" ] || error baseline_metric_mismatch
  case "$b_series:$b_classification" in
    "$SERIES:$CLASSIFICATION"|"$PREVIOUS_SERIES:$PREVIOUS_CLASSIFICATION") ;;
    "$SERIES:"*|"$PREVIOUS_SERIES:"*) error baseline_classification_mismatch ;;
    *) error baseline_series_mismatch ;;
  esac
}

load_schema2_baseline() {
  file=$1
  [ -f "$file" ] || error baseline_missing
  unknown=$(awk -F= '
    /^[[:space:]]*(#|$)/ { next }
    $1 !~ /^(schema|series|tool|tool_version|metric|milestone|commit|code|tests|max_test_growth|ticket_warning)$/ {
      print $1
      exit
    }
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
  [ "$b_series" = "$LEGACY_SERIES" ] || error baseline_series_mismatch
  [ "$b_tool" = "$TOOL_NAME" ] || error baseline_tool_mismatch
  [ "$b_tool_version" = "$TOOL_VERSION" ] || error baseline_tool_version_mismatch
  [ "$b_metric" = "$LEGACY_METRIC" ] || error baseline_metric_mismatch
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
  GIT_INDEX_FILE="$index" git checkout-index --all --force --prefix="$dest/" >/dev/null 2>&1 \
    || error checkout_index_failed
  rm -f "$index"
}

parse_csv_report() {
  csv=$1
  root_dir=$2
  report=$3
  map=$4
  path_prefix=${5:-}
  raw_map="$map.raw"
  normalized_root=$(printf '%s' "$root_dir" | tr '\\' '/')
  normalized_prefix=$(printf '%s' "$path_prefix" | tr '\\' '/' | sed 's:/*$::')

  rm -f "$report" "$map" "$raw_map"
  awk -F, -v root="$normalized_root" -v prefix="$normalized_prefix" \
    -v report="$report" -v map="$raw_map" '
    BEGIN { case_loc = 0; support_loc = 0; fixture_loc = 0 }
    function clean(v) {
      gsub(/\r/, "", v)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
      if (v ~ /^".*"$/) {
        sub(/^"/, "", v)
        sub(/"$/, "", v)
        gsub(/""/, "\"", v)
      }
      return v
    }
    function normalize_path(v) {
      gsub(/\\/, "/", v)
      sub(/^\.\//, "", v)
      if (root != "" && index(v, root "/") == 1) {
        v = substr(v, length(root) + 2)
      }
      return v
    }
    function category(path, lower) {
      lower = tolower(path)
      if (lower ~ /(^|\/)tests\/fixtures\// ||
          lower ~ /(^|\/)test[-_]fixtures\// ||
          lower ~ /(^|\/)(snapshots|testdata)\//) {
        return "fixture"
      }
      if (lower ~ /(^|\/)tests\/[^\/]+\/src\// ||
          lower ~ /(^|\/)tests\/(common|support|helpers|fakes)\// ||
          lower ~ /(^|\/)tests\/[^\/]+\/(common|support|helpers|fakes)\// ||
          lower ~ /(^|\/)tests\/(common|support|helpers|fakes)\.rs$/ ||
          lower ~ /(^|\/)tests\/[^\/]*_(support|helpers|fakes)\.rs$/ ||
          lower ~ /(^|\/)tests\/.*\/(common|support|helpers|fakes)\.rs$/ ||
          lower ~ /(^|\/)tests\/.*\/[^\/]*_(support|helpers|fakes)\.rs$/) {
        return "support"
      }
      return "case"
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
    /^[[:space:]]*$/ { next }
    {
      label = normalize_path(clean($(column["label"])))
      code = clean($(column["code"]))
      tests = clean($(column["tests"]))
      examples = clean($(column["examples"]))
      if (code !~ /^[0-9]+$/ || tests !~ /^[0-9]+$/ || examples !~ /^[0-9]+$/) {
        invalid = 1
        next
      }
      if (toupper(label) ~ /^TOTAL([[:space:]]*\(|$)/) {
        if (found_total) {
          invalid = 1
          next
        }
        total_code = code
        total_tests = tests
        total_examples = examples
        found_total = 1
        next
      }
      if (label == "") {
        invalid = 1
        next
      }
      if (prefix != "") label = prefix "/" label
      cat = category(label)
      file_test_sum += tests
      if (cat == "case") case_loc += tests
      else if (cat == "support") support_loc += tests
      else if (cat == "fixture") fixture_loc += tests
      else invalid = 1

      if (tests > 0) {
        print label "\t" tests "\t" cat > map
        if (tests > largest_tests ||
            (tests == largest_tests && (largest_path == "" || label < largest_path))) {
          largest_tests = tests
          largest_path = label
          largest_category = cat
        }
      }
    }
    END {
      if (invalid || !found_total || file_test_sum != total_tests ||
          case_loc + support_loc + fixture_loc != total_tests) {
        exit 2
      }
      if (largest_path == "") {
        largest_path = "none"
        largest_category = "none"
        largest_tests = 0
      }
      print "code=" total_code > report
      print "tests=" total_tests >> report
      print "examples=" total_examples >> report
      print "test_case_loc=" case_loc >> report
      print "test_support_loc=" support_loc >> report
      print "test_fixture_loc=" fixture_loc >> report
      print "largest_test_file=" largest_path >> report
      print "largest_test_file_tests=" largest_tests >> report
      print "largest_test_file_category=" largest_category >> report
    }
  ' "$csv" || return 2

  if [ -f "$raw_map" ]; then
    sort -t "$(printf '\t')" -k1,1 "$raw_map" > "$map"
  else
    : > "$map"
  fi
  rm -f "$raw_map"
}

merge_count_reports() {
  merge_left_report=$1
  merge_left_map=$2
  merge_right_report=$3
  merge_right_map=$4
  merge_report=$5
  merge_map=$6
  merge_raw_map="$merge_map.raw"

  merge_left_code=$(kv_get code "$merge_left_report") || return 2
  merge_right_code=$(kv_get code "$merge_right_report") || return 2
  merge_left_tests=$(kv_get tests "$merge_left_report") || return 2
  merge_right_tests=$(kv_get tests "$merge_right_report") || return 2
  merge_left_examples=$(kv_get examples "$merge_left_report") || return 2
  merge_right_examples=$(kv_get examples "$merge_right_report") || return 2
  merge_left_case=$(kv_get test_case_loc "$merge_left_report") || return 2
  merge_right_case=$(kv_get test_case_loc "$merge_right_report") || return 2
  merge_left_support=$(kv_get test_support_loc "$merge_left_report") || return 2
  merge_right_support=$(kv_get test_support_loc "$merge_right_report") || return 2
  merge_left_fixture=$(kv_get test_fixture_loc "$merge_left_report") || return 2
  merge_right_fixture=$(kv_get test_fixture_loc "$merge_right_report") || return 2

  merge_code=$(( merge_left_code + merge_right_code ))
  merge_tests=$(( merge_left_tests + merge_right_tests ))
  merge_examples=$(( merge_left_examples + merge_right_examples ))
  merge_case=$(( merge_left_case + merge_right_case ))
  merge_support=$(( merge_left_support + merge_right_support ))
  merge_fixture=$(( merge_left_fixture + merge_right_fixture ))
  [ $(( merge_case + merge_support + merge_fixture )) -eq "$merge_tests" ] || return 2

  rm -f "$merge_report" "$merge_map" "$merge_raw_map"
  awk -F '\t' '
    NF != 3 || $1 == "" || $2 !~ /^[0-9]+$/ || $3 !~ /^(case|support|fixture)$/ {
      invalid = 1
      next
    }
    seen[$1]++ { invalid = 1; next }
    { print }
    END { if (invalid) exit 2 }
  ' "$merge_left_map" "$merge_right_map" > "$merge_raw_map" || {
    rm -f "$merge_raw_map"
    return 2
  }
  sort -t "$(printf '\t')" -k1,1 "$merge_raw_map" > "$merge_map"
  rm -f "$merge_raw_map"

  merge_largest_path=$(awk -F '\t' '
    $2 > largest || ($2 == largest && (path == "" || $1 < path)) {
      largest = $2
      path = $1
    }
    END { print path == "" ? "none" : path }
  ' "$merge_map") || return 2
  if [ "$merge_largest_path" = none ]; then
    merge_largest_tests=0
    merge_largest_category=none
  else
    merge_largest_tests=$(awk -F '\t' -v path="$merge_largest_path" \
      '$1 == path { print $2; found = 1 } END { if (!found) exit 2 }' "$merge_map") || return 2
    merge_largest_category=$(awk -F '\t' -v path="$merge_largest_path" \
      '$1 == path { print $3; found = 1 } END { if (!found) exit 2 }' "$merge_map") || return 2
  fi

  {
    printf 'code=%s\n' "$merge_code"
    printf 'tests=%s\n' "$merge_tests"
    printf 'examples=%s\n' "$merge_examples"
    printf 'test_case_loc=%s\n' "$merge_case"
    printf 'test_support_loc=%s\n' "$merge_support"
    printf 'test_fixture_loc=%s\n' "$merge_fixture"
    printf 'largest_test_file=%s\n' "$merge_largest_path"
    printf 'largest_test_file_tests=%s\n' "$merge_largest_tests"
    printf 'largest_test_file_category=%s\n' "$merge_largest_category"
  } > "$merge_report"
}

load_count_report() {
  report=$1
  map=$2
  count_code=$(kv_get code "$report") || error rustloc_report_code_missing
  count_tests=$(kv_get tests "$report") || error rustloc_report_tests_missing
  count_examples=$(kv_get examples "$report") || error rustloc_report_examples_missing
  count_test_case_loc=$(kv_get test_case_loc "$report") || error rustloc_report_case_missing
  count_test_support_loc=$(kv_get test_support_loc "$report") || error rustloc_report_support_missing
  count_test_fixture_loc=$(kv_get test_fixture_loc "$report") || error rustloc_report_fixture_missing
  count_largest_test_file=$(kv_get largest_test_file "$report") || error rustloc_report_largest_missing
  count_largest_test_file_tests=$(kv_get largest_test_file_tests "$report") \
    || error rustloc_report_largest_tests_missing
  count_largest_test_file_category=$(kv_get largest_test_file_category "$report") \
    || error rustloc_report_largest_category_missing
  count_file_map=$map
}

count_workspace_dir() {
  dir=$1
  label=$2
  need_tmp
  workspace_csv="$tmp_root/$label.workspace.csv"
  workspace_report="$tmp_root/$label.workspace.report"
  workspace_map="$tmp_root/$label.workspace.files.tsv"
  (cd "$dir" && "$TOOL" --lang rust --by-file -t code,tests,examples \
    --output csv --output-file-path "$workspace_csv" >/dev/null) \
    || error rustloc_count_failed
  parse_csv_report "$workspace_csv" "$dir" "$workspace_report" "$workspace_map" \
    || error rustloc_csv_invalid
  load_count_report "$workspace_report" "$workspace_map"
}

count_dir() {
  dir=$1
  label=$2
  count_workspace_dir "$dir" "$label"

  fixture_dir="$dir/tests/fixtures"
  if [ ! -d "$fixture_dir" ]; then
    return
  fi

  fixture_csv="$tmp_root/$label.fixture.csv"
  fixture_report="$tmp_root/$label.fixture.report"
  fixture_map="$tmp_root/$label.fixture.files.tsv"
  (cd "$dir" && "$TOOL" tests/fixtures --lang rust --by-file -t code,tests,examples \
    --output csv --output-file-path "$fixture_csv" >/dev/null) \
    || error rustloc_fixture_count_failed
  parse_csv_report "$fixture_csv" "$fixture_dir" "$fixture_report" "$fixture_map" \
    tests/fixtures || error rustloc_fixture_csv_invalid
  combined_report="$tmp_root/$label.report"
  combined_map="$tmp_root/$label.files.tsv"
  merge_count_reports "$workspace_report" "$workspace_map" "$fixture_report" "$fixture_map" \
    "$combined_report" "$combined_map" || error rustloc_report_merge_invalid
  load_count_report "$combined_report" "$combined_map"
}

count_object() {
  object=$1
  label=$2
  need_tmp
  dir="$tmp_root/tree.$label.${materialize_seq:-0}"
  materialize_tree "$object" "$dir"
  count_dir "$dir" "$label"
}

count_workspace_object() {
  object=$1
  label=$2
  need_tmp
  dir="$tmp_root/tree.$label.${materialize_seq:-0}"
  materialize_tree "$object" "$dir"
  count_workspace_dir "$dir" "$label"
}

count_staged() {
  need_tmp
  tree=$(git write-tree 2>/dev/null) || error write_tree_failed
  count_object "$tree" staged
}

ratio() {
  if [ "$2" -eq 0 ]; then
    printf '0.000000\n'
  else
    awk -v n="$1" -v d="$2" 'BEGIN { printf "%.6f", n / d }'
  fi
}

format_milli() {
  awk -v n="$1" 'BEGIN { printf "%.3f", n / 1000 }'
}

ratio_level() {
  tests=$1
  code=$2
  if [ $(( tests * 1000 )) -gt $(( code * b_ratio_review_milli )) ]; then
    printf 'REVIEW_REQUIRED\n'
  elif [ $(( tests * 1000 )) -gt $(( code * b_ratio_warning_milli )) ]; then
    printf 'WARN\n'
  else
    printf 'PASS\n'
  fi
}

positive_growth() {
  if [ "$1" -gt "$2" ]; then
    printf '%s\n' $(( $1 - $2 ))
  else
    printf '0\n'
  fi
}

signed_delta() {
  printf '%s\n' $(( $1 - $2 ))
}

capture_base_count() {
  base_code=$count_code
  base_tests=$count_tests
  base_examples=$count_examples
  base_test_case_loc=$count_test_case_loc
  base_test_support_loc=$count_test_support_loc
  base_test_fixture_loc=$count_test_fixture_loc
  base_file_map=$count_file_map
}

capture_candidate_count() {
  candidate_code=$count_code
  candidate_tests=$count_tests
  candidate_examples=$count_examples
  candidate_test_case_loc=$count_test_case_loc
  candidate_test_support_loc=$count_test_support_loc
  candidate_test_fixture_loc=$count_test_fixture_loc
  candidate_largest_test_file=$count_largest_test_file
  candidate_largest_test_file_tests=$count_largest_test_file_tests
  candidate_largest_test_file_category=$count_largest_test_file_category
  candidate_file_map=$count_file_map
}

changed_file_metrics() {
  base_map=$1
  candidate_map=$2
  values=$(awk -F '\t' -v warning="$b_file_warning" -v review="$b_file_review" \
    -v base_file="$base_map" '
    FILENAME == base_file {
      base[$1] = $2
      next
    }
    {
      path = $1
      current = $2 + 0
      category = $3
      previous = (path in base) ? base[path] + 0 : 0
      if (current <= previous) next
      growth = current - previous
      if (current > review) review_count++
      else if (current > warning) warning_count++
      if (current > largest_tests ||
          (current == largest_tests && (largest_path == "" || path < largest_path))) {
        largest_tests = current
        largest_growth = growth
        largest_path = path
        largest_category = category
      }
    }
    END {
      if (largest_path == "") {
        largest_path = "none"
        largest_category = "none"
        largest_tests = 0
        largest_growth = 0
      }
      gsub(/[[:space:]]/, "%20", largest_path)
      printf "%d %d %d %d %s %s\n", warning_count, review_count,
        largest_tests, largest_growth, largest_path, largest_category
    }
  ' "$base_map" "$candidate_map") || error file_delta_failed
  set -- $values
  changed_file_warning_count=$1
  changed_file_review_count=$2
  largest_changed_test_file_tests=$3
  largest_changed_test_file_growth=$4
  largest_changed_test_file=$5
  largest_changed_test_file_category=$6
}

promote_status() {
  proposed=$1
  case "$status:$proposed" in
    REVIEW_REQUIRED:*) ;;
    WARN:REVIEW_REQUIRED) status=REVIEW_REQUIRED ;;
    WARN:*) ;;
    PASS:WARN) status=WARN ;;
    PASS:REVIEW_REQUIRED) status=REVIEW_REQUIRED ;;
  esac
}

add_reason() {
  reason=$1
  if [ "$reasons" = none ]; then
    reasons=$reason
  else
    reasons="$reasons,$reason"
  fi
}

compare_footprint() {
  mode=$1
  [ "$candidate_code" -gt 0 ] || blocked candidate_code_zero
  [ $(( candidate_test_case_loc + candidate_test_support_loc + candidate_test_fixture_loc )) \
      -eq "$candidate_tests" ] || error candidate_category_sum_mismatch

  change_code_growth=$(positive_growth "$candidate_code" "$base_code")
  change_test_growth=$(positive_growth "$candidate_tests" "$base_tests")
  change_test_delta=$(signed_delta "$candidate_tests" "$base_tests")
  milestone_test_growth=$(positive_growth "$candidate_tests" "$b_tests")
  test_case_delta=$(signed_delta "$candidate_test_case_loc" "$base_test_case_loc")
  test_support_delta=$(signed_delta "$candidate_test_support_loc" "$base_test_support_loc")
  test_fixture_delta=$(signed_delta "$candidate_test_fixture_loc" "$base_test_fixture_loc")

  changed_file_metrics "$base_file_map" "$candidate_file_map"

  ratio_status=$(ratio_level "$candidate_tests" "$candidate_code")
  change_status=PASS
  file_status=PASS
  status=PASS
  reasons=none

  case "$mode" in
    ticket-staged|ticket-commit|ci)
      if [ "$change_test_growth" -gt "$b_ticket_review" ]; then
        change_status=REVIEW_REQUIRED
      elif [ "$change_test_growth" -gt "$b_ticket_warning" ]; then
        change_status=WARN
      fi
      ;;
  esac

  if [ "$changed_file_review_count" -gt 0 ]; then
    file_status=REVIEW_REQUIRED
  elif [ "$changed_file_warning_count" -gt 0 ]; then
    file_status=WARN
  fi

  promote_status "$ratio_status"
  promote_status "$change_status"
  promote_status "$file_status"
  [ "$ratio_status" = PASS ] || add_reason ratio
  [ "$change_status" = PASS ] || add_reason change_test_growth
  [ "$file_status" = PASS ] || add_reason changed_test_file_size

  case "$candidate_largest_test_file" in
    *[[:space:]]*) candidate_largest_test_file_print=$(printf '%s' "$candidate_largest_test_file" | sed 's/[[:space:]]/%20/g') ;;
    *) candidate_largest_test_file_print=$candidate_largest_test_file ;;
  esac

  printf 'test_budget footprint=REPORT schema=%s classification=%s mode=%s milestone=%s code=%s tests=%s examples=%s ratio=%s test_case_loc=%s test_support_loc=%s test_fixture_loc=%s test_case_delta=%s test_support_delta=%s test_fixture_delta=%s category_sum=PASS largest_test_file=%s largest_test_file_tests=%s largest_test_file_category=%s\n' \
    "$SCHEMA" "$CLASSIFICATION" "$mode" "$b_milestone" "$candidate_code" \
    "$candidate_tests" "$candidate_examples" "$(ratio "$candidate_tests" "$candidate_code")" \
    "$candidate_test_case_loc" "$candidate_test_support_loc" "$candidate_test_fixture_loc" \
    "$test_case_delta" "$test_support_delta" "$test_fixture_delta" \
    "$candidate_largest_test_file_print" "$candidate_largest_test_file_tests" \
    "$candidate_largest_test_file_category"

  printf 'test_budget status=%s policy=test_footprint numeric_gate=advisory integrity_gate=PASS reasons=%s mode=%s milestone=%s policy_revision=%s reforecast_ref=%s milestone_test_growth=%s change_code_growth=%s change_test_growth=%s change_test_delta=%s ratio_level=%s ratio_warning=%s ratio_review=%s change_level=%s ticket_warning=%s ticket_review=%s file_level=%s file_warning=%s file_review=%s changed_file_warning_count=%s changed_file_review_count=%s largest_changed_test_file=%s largest_changed_test_file_tests=%s largest_changed_test_file_growth=%s largest_changed_test_file_category=%s\n' \
    "$status" "$reasons" "$mode" "$b_milestone" "$b_policy_revision" \
    "$b_reforecast_ref" "$milestone_test_growth" "$change_code_growth" \
    "$change_test_growth" "$change_test_delta" "$ratio_status" \
    "$(format_milli "$b_ratio_warning_milli")" "$(format_milli "$b_ratio_review_milli")" \
    "$change_status" "$b_ticket_warning" "$b_ticket_review" "$file_status" \
    "$b_file_warning" "$b_file_review" "$changed_file_warning_count" \
    "$changed_file_review_count" "$largest_changed_test_file" \
    "$largest_changed_test_file_tests" "$largest_changed_test_file_growth" \
    "$largest_changed_test_file_category"
}

verify_baseline() {
  verify_candidate=$1
  git merge-base --is-ancestor "$b_commit" "$verify_candidate" 2>/dev/null \
    || error baseline_not_ancestor
  if [ "$b_series:$b_classification" = "$PREVIOUS_SERIES:$PREVIOUS_CLASSIFICATION" ]; then
    count_workspace_object "$b_commit" baseline
  else
    count_object "$b_commit" baseline
  fi
  [ "$count_code" -eq "$b_code" ] || error baseline_code_mismatch
  [ "$count_tests" -eq "$b_tests" ] || error baseline_tests_mismatch
  baseline_ratio_level=$(ratio_level "$b_tests" "$b_code")
  baseline_largest=$count_largest_test_file
  case "$baseline_largest" in
    *[[:space:]]*) baseline_largest=$(printf '%s' "$baseline_largest" | sed 's/[[:space:]]/%20/g') ;;
  esac
  printf 'test_budget baseline=PASS policy=test_footprint schema=%s series=%s classification=%s milestone=%s commit=%s code=%s tests=%s ratio=%s ratio_level=%s test_case_loc=%s test_support_loc=%s test_fixture_loc=%s category_sum=PASS largest_test_file=%s largest_test_file_tests=%s largest_test_file_category=%s ratio_warning=%s ratio_review=%s ticket_warning=%s ticket_review=%s file_warning=%s file_review=%s policy_revision=%s reforecast_ref=%s\n' \
    "$SCHEMA" "$b_series" "$b_classification" "$b_milestone" "$b_commit" \
    "$b_code" "$b_tests" "$(ratio "$b_tests" "$b_code")" "$baseline_ratio_level" \
    "$count_test_case_loc" "$count_test_support_loc" "$count_test_fixture_loc" \
    "$baseline_largest" "$count_largest_test_file_tests" \
    "$count_largest_test_file_category" "$(format_milli "$b_ratio_warning_milli")" \
    "$(format_milli "$b_ratio_review_milli")" "$b_ticket_warning" "$b_ticket_review" \
    "$b_file_warning" "$b_file_review" "$b_policy_revision" "$b_reforecast_ref"
}

verify_schema2_baseline() {
  verify_candidate=$1
  git merge-base --is-ancestor "$b_commit" "$verify_candidate" 2>/dev/null \
    || error baseline_not_ancestor
  count_workspace_object "$b_commit" baseline-schema2
  [ "$count_code" -eq "$b_code" ] || error baseline_code_mismatch
  [ "$count_tests" -eq "$b_tests" ] || error baseline_tests_mismatch
  printf 'test_budget baseline=PASS policy=test_footprint schema=2 series=%s milestone=%s commit=%s code=%s tests=%s ratio=%s max_test_growth=%s ticket_warning=%s\n' \
    "$b_series" "$b_milestone" "$b_commit" "$b_code" "$b_tests" \
    "$(ratio "$b_tests" "$b_code")" "$b_max_test_growth" "$b_ticket_warning"
}

branch_base() {
  branch=$(git symbolic-ref --quiet --short HEAD 2>/dev/null) || error detached_head
  current=$(git config --local --get "branch.$branch.testFootprintBase" 2>/dev/null || true)
  legacy=$(git config --local --get "branch.$branch.testBudgetBase" 2>/dev/null || true)
  if [ -n "$current" ] && [ -n "$legacy" ] && [ "$current" != "$legacy" ]; then
    error ticket_base_binding_conflict
  fi
  [ -n "$current" ] || current=$legacy
  [ -n "$current" ] || error ticket_base_not_bound
  printf '%s\n' "$current"
}

protected_control_paths() {
  cat <<'PATHS'
scripts/test-budget.sh
ci/test-budget-baseline.txt
.githooks/pre-commit
.github/workflows/m0.yml
.gitattributes
.agents/skills/milestone-workflow/SKILL.md
.agents/skills/milestone-workflow/references/plan.md
.agents/skills/milestone-workflow/references/execute.md
.agents/skills/milestone-workflow/references/close.md
.codex/agents/engineer.toml
docs/agents/milestone-workflow.md
PATHS
}

control_paths() {
  wanted=$1
  protected_control_paths | grep -Fqx "$wanted"
}

staged_control_changed() {
  git diff --cached --name-only --no-renames | while IFS= read -r path; do
    if control_paths "$path"; then
      printf '%s\n' "$path"
    fi
  done
}

range_control_changed() {
  from=$1
  to=$2
  git diff --name-only --no-renames "$from" "$to" | while IFS= read -r path; do
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

baseline_from_commit() {
  commit=$1
  dest=$2
  git show "$commit:$BASELINE_FILE" > "$dest" 2>/dev/null || error baseline_missing_in_candidate
}

range_rust_changed() {
  git log --no-renames --format= --name-only "$1..$2" -- '*.rs' | grep -q .
}

legacy_schema() {
  kv_get schema "$1" || error policy_transition_source_schema_missing
}

policy_thresholds_changed() {
  [ "$new_ratio_warning_milli" != "$old_ratio_warning_milli" ] ||
    [ "$new_ratio_review_milli" != "$old_ratio_review_milli" ] ||
    [ "$new_ticket_warning" != "$old_ticket_warning" ] ||
    [ "$new_ticket_review" != "$old_ticket_review" ] ||
    [ "$new_file_warning" != "$old_file_warning" ] ||
    [ "$new_file_review" != "$old_file_review" ]
}

validate_schema2_policy_transition() {
  transition_old=$1
  transition_new=$2
  transition_end=$3

  load_schema2_baseline "$transition_new"
  new_milestone=$b_milestone
  new_commit=$b_commit
  new_code=$b_code
  new_tests=$b_tests
  new_max_test_growth=$b_max_test_growth
  new_ticket_warning=$b_ticket_warning

  old_schema=$(legacy_schema "$transition_old")
  case "$old_schema" in
    1)
      range_rust_changed "$new_commit" "$transition_end" \
        && blocked policy_activation_after_rust_change
      ;;
    2)
      load_schema2_baseline "$transition_old"
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

  load_schema2_baseline "$transition_new"
  verify_schema2_baseline "$transition_end"
  printf 'test_budget policy_transition=PASS policy=test_footprint transition=legacy-schema2 milestone=%s base=%s max_test_growth=%s ticket_warning=%s\n' \
    "$b_milestone" "$b_commit" "$b_max_test_growth" "$b_ticket_warning"
}

validate_policy_transition() {
  transition_old=$1
  transition_new=$2
  transition_end=$3

  transition_schema=$(legacy_schema "$transition_new")
  case "$transition_schema" in
    2)
      validate_schema2_policy_transition "$transition_old" "$transition_new" "$transition_end"
      return
      ;;
    3) ;;
    *) error policy_transition_schema_mismatch ;;
  esac

  load_transition_baseline "$transition_new"
  new_series=$b_series
  new_classification=$b_classification
  new_milestone=$b_milestone
  new_commit=$b_commit
  new_code=$b_code
  new_tests=$b_tests
  new_ratio_warning_milli=$b_ratio_warning_milli
  new_ratio_review_milli=$b_ratio_review_milli
  new_ticket_warning=$b_ticket_warning
  new_ticket_review=$b_ticket_review
  new_file_warning=$b_file_warning
  new_file_review=$b_file_review
  new_policy_revision=$b_policy_revision
  new_reforecast_ref=$b_reforecast_ref

  old_schema=$(legacy_schema "$transition_old")
  transition_kind=activation
  case "$old_schema" in
    1|2)
      [ "$new_policy_revision" -eq 1 ] || blocked policy_upgrade_revision_must_start_at_one
      range_rust_changed "$new_commit" "$transition_end" \
        && blocked policy_activation_after_rust_change
      ;;
    3)
      parse_baseline "$transition_old"
      [ "$b_schema" = "$SCHEMA" ] || error policy_transition_source_schema_mismatch
      [ "$b_tool" = "$TOOL_NAME" ] || error policy_transition_source_tool_mismatch
      [ "$b_tool_version" = "$TOOL_VERSION" ] \
        || error policy_transition_source_tool_version_mismatch
      [ "$b_metric" = "$METRIC" ] || error policy_transition_source_metric_mismatch
      old_series=$b_series
      old_classification=$b_classification
      old_milestone=$b_milestone
      old_commit=$b_commit
      old_code=$b_code
      old_tests=$b_tests
      old_ratio_warning_milli=$b_ratio_warning_milli
      old_ratio_review_milli=$b_ratio_review_milli
      old_ticket_warning=$b_ticket_warning
      old_ticket_review=$b_ticket_review
      old_file_warning=$b_file_warning
      old_file_review=$b_file_review
      old_policy_revision=$b_policy_revision
      old_reforecast_ref=$b_reforecast_ref

      measurement_transition=false
      if [ "$new_series" != "$old_series" ] || \
          [ "$new_classification" != "$old_classification" ]; then
        [ "$old_series" = "$PREVIOUS_SERIES" ] && \
          [ "$old_classification" = "$PREVIOUS_CLASSIFICATION" ] && \
          [ "$new_series" = "$SERIES" ] && \
          [ "$new_classification" = "$CLASSIFICATION" ] \
          || blocked policy_measurement_transition_invalid
        measurement_transition=true
      fi

      if [ "$new_milestone" = "$old_milestone" ]; then
        [ "$new_commit" = "$old_commit" ] || blocked policy_base_changed_within_milestone
        [ "$new_policy_revision" -eq $(( old_policy_revision + 1 )) ] \
          || blocked policy_revision_not_incremented
        [ "$new_reforecast_ref" != "$old_reforecast_ref" ] \
          || blocked policy_reforecast_ref_unchanged
        if $measurement_transition; then
          [ "$new_code" -eq "$old_code" ] \
            || blocked policy_measurement_transition_changed_code
          [ "$new_tests" -gt "$old_tests" ] \
            || blocked policy_measurement_transition_did_not_add_fixture_tests
          if policy_thresholds_changed; then
            blocked policy_measurement_transition_changed_thresholds
          fi
          transition_kind=measurement-series
        else
          [ "$new_code" -eq "$old_code" ] || blocked policy_base_code_changed_within_milestone
          [ "$new_tests" -eq "$old_tests" ] \
            || blocked policy_base_tests_changed_within_milestone
          policy_thresholds_changed || blocked policy_revision_without_threshold_change
          transition_kind=reforecast
        fi
      else
        if $measurement_transition; then
          blocked policy_measurement_transition_changed_milestone
        fi
        [ "$new_policy_revision" -eq 1 ] || blocked successor_policy_revision_must_start_at_one
        range_rust_changed "$new_commit" "$transition_end" \
          && blocked policy_activation_after_rust_change
        transition_kind=successor
      fi
      ;;
    *) error policy_transition_source_schema_mismatch ;;
  esac

  load_transition_baseline "$transition_new"
  verify_baseline "$transition_end"
  printf 'test_budget policy_transition=PASS policy=test_footprint transition=%s series=%s classification=%s milestone=%s base=%s policy_revision=%s reforecast_ref=%s ratio_warning=%s ratio_review=%s ticket_warning=%s ticket_review=%s file_warning=%s file_review=%s\n' \
    "$transition_kind" "$b_series" "$b_classification" "$b_milestone" "$b_commit" \
    "$b_policy_revision" "$b_reforecast_ref" \
    "$(format_milli "$b_ratio_warning_milli")" "$(format_milli "$b_ratio_review_milli")" \
    "$b_ticket_warning" "$b_ticket_review" "$b_file_warning" "$b_file_review"
}

validate_staged_control() {
  validation_controls=$(staged_control_changed)
  [ -n "$validation_controls" ] || return 0
  git rev-parse --verify -q MERGE_HEAD >/dev/null 2>&1 \
    && blocked control_commit_must_be_single_parent
  validation_paths=$(git diff --cached --name-only --no-renames)
  printf '%s\n' "$validation_paths" | only_control_and_docs || blocked control_plane_changed
  if printf '%s\n' "$validation_controls" | grep -Fqx "$BASELINE_FILE"; then
    need_tmp
    validation_old="$tmp_root/staged-old-baseline.txt"
    validation_new="$tmp_root/staged-new-baseline.txt"
    baseline_from_commit HEAD "$validation_old"
    git show ":$BASELINE_FILE" > "$validation_new" 2>/dev/null \
      || error staged_baseline_missing
    validate_policy_transition "$validation_old" "$validation_new" HEAD
  fi
  printf 'test_budget control=PASS policy=test_footprint mode=ticket-staged\n'
}

path_blob_at() {
  git rev-parse --verify "$1:$2" 2>/dev/null || printf '%s\n' missing
}

merge_inherits_control_paths() {
  validation_merge=$1
  set -- $(git rev-list --parents -n 1 "$validation_merge")
  shift
  for validation_path in $(protected_control_paths); do
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
      merge_inherits_control_paths "$validation_commit" || blocked control_merge_resolution
      continue
    fi
    validation_parent=$(first_parent "$validation_commit")
    validation_controls=$(range_control_changed "$validation_parent" "$validation_commit")
    [ -n "$validation_controls" ] || continue
    validation_paths=$(git diff --name-only --no-renames "$validation_parent" "$validation_commit")
    printf '%s\n' "$validation_paths" | only_control_and_docs || blocked control_plane_changed
    if ! git diff --quiet "$validation_parent" "$validation_commit" -- "$BASELINE_FILE"; then
      need_tmp
      validation_old="$tmp_root/policy-old.$validation_commit.txt"
      validation_new="$tmp_root/policy-new.$validation_commit.txt"
      baseline_from_commit "$validation_parent" "$validation_old"
      baseline_from_commit "$validation_commit" "$validation_new"
      validate_policy_transition "$validation_old" "$validation_new" "$validation_commit"
    fi
    printf 'test_budget control=PASS policy=test_footprint mode=commit commit=%s\n' \
      "$validation_commit"
  done
}

self_test() {
  need_tmp
  csv="$tmp_root/self-test.csv"
  report="$tmp_root/self-test.report"
  map="$tmp_root/self-test.files.tsv"
  cat > "$csv" <<'CSV'
label,code,tests,examples
src/lib.rs,100,20,0
crates/demo/tests/case.rs,0,250,0
crates/demo/tests/common/mod.rs,0,50,0
crates/demo/tests/helpers.rs,0,5,0
tests/fixtures/demo/generator.rs,0,10,0
TOTAL (5 files),100,335,0
CSV
  parse_csv_report "$csv" "$repo" "$report" "$map" || error self_test_csv_parse_failed
  load_count_report "$report" "$map"
  [ "$count_code" -eq 100 ] || error self_test_code_failed
  [ "$count_tests" -eq 335 ] || error self_test_tests_failed
  [ "$count_test_case_loc" -eq 270 ] || error self_test_case_failed
  [ "$count_test_support_loc" -eq 55 ] || error self_test_support_failed
  [ "$count_test_fixture_loc" -eq 10 ] || error self_test_fixture_failed

  cat > "$csv" <<'CSV'
label,code,tests,examples
src/lib.rs,100,20,0
crates/demo/tests/case.rs,0,250,0
crates/demo/tests/common/mod.rs,0,50,0
TOTAL (3 files),100,320,0
CSV
  parse_csv_report "$csv" "$repo" "$report" "$map" || error self_test_zero_fixture_parse_failed
  load_count_report "$report" "$map"
  [ "$count_test_fixture_loc" -eq 0 ] || error self_test_zero_fixture_failed

  workspace_csv="$tmp_root/self-test-workspace.csv"
  workspace_report="$tmp_root/self-test-workspace.report"
  workspace_map="$tmp_root/self-test-workspace.files.tsv"
  fixture_csv="$tmp_root/self-test-fixture.csv"
  fixture_report="$tmp_root/self-test-fixture.report"
  fixture_map="$tmp_root/self-test-fixture.files.tsv"
  combined_report="$tmp_root/self-test-combined.report"
  combined_map="$tmp_root/self-test-combined.files.tsv"
  cat > "$workspace_csv" <<'CSV'
label,code,tests,examples
src/lib.rs,100,20,0
tests/common.rs,0,5,0
TOTAL (2 files),100,25,0
CSV
  cat > "$fixture_csv" <<'CSV'
label,code,tests,examples
crypto/generator.rs,0,10,0
TOTAL (1 file),0,10,0
CSV
  parse_csv_report "$workspace_csv" "$repo" "$workspace_report" "$workspace_map" \
    || error self_test_workspace_parse_failed
  parse_csv_report "$fixture_csv" "$repo/tests/fixtures" "$fixture_report" "$fixture_map" \
    tests/fixtures || error self_test_fixture_prefix_parse_failed
  merge_count_reports "$workspace_report" "$workspace_map" "$fixture_report" "$fixture_map" \
    "$combined_report" "$combined_map" || error self_test_merge_failed
  load_count_report "$combined_report" "$combined_map"
  [ "$count_code" -eq 100 ] || error self_test_merged_code_failed
  [ "$count_tests" -eq 35 ] || error self_test_merged_tests_failed
  [ "$count_test_case_loc" -eq 20 ] || error self_test_merged_case_failed
  [ "$count_test_support_loc" -eq 5 ] || error self_test_merged_support_failed
  [ "$count_test_fixture_loc" -eq 10 ] || error self_test_merged_fixture_failed
  awk -F '\t' '
    $1 == "tests/fixtures/crypto/generator.rs" && $2 == 10 && $3 == "fixture" { found = 1 }
    END { if (!found) exit 1 }
  ' "$combined_map" || error self_test_merged_fixture_path_failed
  duplicate_map="$tmp_root/self-test-duplicate.files.tsv"
  cp "$fixture_map" "$duplicate_map"
  printf 'src/lib.rs\t10\tfixture\n' >> "$duplicate_map"
  if merge_count_reports "$workspace_report" "$workspace_map" "$fixture_report" \
      "$duplicate_map" "$combined_report" "$combined_map"; then
    error self_test_duplicate_merge_accepted
  fi

  b_milestone=self-test
  b_tests=0
  b_ratio_warning_milli=2000
  b_ratio_review_milli=2500
  b_ticket_warning=240
  b_ticket_review=600
  b_file_warning=800
  b_file_review=1200
  b_policy_revision=1
  b_reforecast_ref=self-test

  base_file_map="$tmp_root/base.tsv"
  candidate_file_map="$tmp_root/candidate.tsv"
  printf 'crates/demo/tests/case.rs\t100\tcase\n' > "$base_file_map"
  printf 'crates/demo/tests/case.rs\t200\tcase\n' > "$candidate_file_map"
  base_code=100
  base_tests=100
  base_examples=0
  base_test_case_loc=100
  base_test_support_loc=0
  base_test_fixture_loc=0
  candidate_code=100
  candidate_tests=200
  candidate_examples=0
  candidate_test_case_loc=200
  candidate_test_support_loc=0
  candidate_test_fixture_loc=0
  candidate_largest_test_file=crates/demo/tests/case.rs
  candidate_largest_test_file_tests=200
  candidate_largest_test_file_category=case
  output=$(compare_footprint ticket-commit)
  printf '%s\n' "$output" | grep -Fq 'status=PASS' || error self_test_pass_failed

  printf 'crates/demo/tests/case.rs\t441\tcase\n' > "$candidate_file_map"
  candidate_code=1000
  candidate_tests=441
  candidate_test_case_loc=441
  candidate_largest_test_file_tests=441
  output=$(compare_footprint ticket-commit)
  printf '%s\n' "$output" | grep -Fq 'status=WARN' || error self_test_warning_failed
  printf '%s\n' "$output" | grep -Fq 'change_level=WARN' || error self_test_change_warning_failed

  printf 'crates/demo/tests/case.rs\t701\tcase\n' > "$candidate_file_map"
  candidate_code=1000
  candidate_tests=701
  candidate_test_case_loc=701
  candidate_largest_test_file_tests=701
  output=$(compare_footprint ticket-commit)
  printf '%s\n' "$output" | grep -Fq 'status=REVIEW_REQUIRED' \
    || error self_test_change_review_failed

  printf 'crates/demo/tests/big.rs\t1200\tcase\n' > "$base_file_map"
  printf 'crates/demo/tests/big.rs\t1201\tcase\n' > "$candidate_file_map"
  base_code=1000
  base_tests=1200
  base_test_case_loc=1200
  candidate_code=1000
  candidate_tests=1201
  candidate_test_case_loc=1201
  candidate_largest_test_file=crates/demo/tests/big.rs
  candidate_largest_test_file_tests=1201
  output=$(compare_footprint ticket-commit)
  printf '%s\n' "$output" | grep -Fq 'file_level=REVIEW_REQUIRED' \
    || error self_test_file_review_failed

  printf 'src/lib.rs\t251\tcase\n' > "$base_file_map"
  cp "$base_file_map" "$candidate_file_map"
  base_code=100
  base_tests=251
  base_test_case_loc=251
  candidate_code=100
  candidate_tests=251
  candidate_test_case_loc=251
  candidate_largest_test_file=src/lib.rs
  candidate_largest_test_file_tests=251
  output=$(compare_footprint milestone)
  printf '%s\n' "$output" | grep -Fq 'ratio_level=REVIEW_REQUIRED' \
    || error self_test_ratio_review_failed

  : > "$base_file_map"
  printf 'tests/new_large.rs\t801\tcase\n' > "$candidate_file_map"
  base_code=1000
  base_tests=0
  base_test_case_loc=0
  candidate_code=1000
  candidate_tests=801
  candidate_test_case_loc=801
  candidate_largest_test_file=tests/new_large.rs
  candidate_largest_test_file_tests=801
  output=$(compare_footprint milestone)
  printf '%s\n' "$output" | grep -Fq 'file_level=WARN' \
    || error self_test_empty_base_file_map_failed

  printf 'test_budget self_test=PASS policy=test_footprint schema=%s categories=PASS fixture_scan=PASS duplicate_rejection=PASS numeric_nonblocking=PASS thresholds=PASS\n' \
    "$SCHEMA"
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
    printf 'test_budget hook=PASS policy=test_footprint path=.githooks\n'
    ;;

  bind)
    base=HEAD
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --base) [ "$#" -ge 2 ] || error base_value_missing; base=$2; shift 2 ;;
        *) usage >&2; exit 2 ;;
      esac
    done
    base=$(resolve_commit "$base")
    branch=$(git symbolic-ref --quiet --short HEAD 2>/dev/null) || error detached_head
    load_baseline "$BASELINE_FILE"
    git merge-base --is-ancestor "$b_commit" "$base" 2>/dev/null \
      || error ticket_base_before_baseline
    current=$(git config --local --get "branch.$branch.testFootprintBase" 2>/dev/null || true)
    legacy=$(git config --local --get "branch.$branch.testBudgetBase" 2>/dev/null || true)
    binding_migrated=no
    for bound in "$current" "$legacy"; do
      if [ -n "$bound" ] && [ "$bound" != "$base" ]; then
        if git merge-base --is-ancestor "$bound" "$b_commit" 2>/dev/null; then
          binding_migrated=yes
        else
          error ticket_base_already_bound
        fi
      fi
    done
    if [ "$binding_migrated" = yes ]; then
      git config --local --unset-all "branch.$branch.testFootprintBase" 2>/dev/null || true
      git config --local --unset-all "branch.$branch.testBudgetBase" 2>/dev/null || true
    fi
    git config --local "branch.$branch.testFootprintBase" "$base"
    printf 'test_budget bind=PASS policy=test_footprint branch=%s base=%s migrated_stale_binding=%s\n' \
      "$branch" "$base" "$binding_migrated"
    ;;

  verify)
    candidate=HEAD
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --candidate) [ "$#" -ge 2 ] || error candidate_value_missing; candidate=$2; shift 2 ;;
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
        --candidate) [ "$#" -ge 2 ] || error candidate_value_missing; candidate=$2; shift 2 ;;
        --base) [ "$#" -ge 2 ] || error base_value_missing; base=$2; shift 2 ;;
        *) usage >&2; exit 2 ;;
      esac
    done
    if $staged && [ -n "$candidate" ]; then error candidate_mode_conflict; fi
    staged_evaluation=false
    if $staged || [ -z "$candidate" ]; then
      staged_evaluation=true
    fi
    if [ -z "$base" ]; then
      if $staged_evaluation && [ -n "$(staged_control_changed)" ]; then
        base=HEAD
        printf 'test_budget base_adjustment=PASS policy=test_footprint metric_base=HEAD reason=staged_control_change\n'
      else
        base=$(branch_base)
      fi
    fi
    base=$(resolve_commit "$base")
    check_tool

    if $staged_evaluation; then
      need_tmp
      staged_baseline="$tmp_root/ticket-staged-baseline.txt"
      git show ":$BASELINE_FILE" > "$staged_baseline" 2>/dev/null \
        || error staged_baseline_missing
      load_baseline "$staged_baseline"
      git merge-base --is-ancestor "$b_commit" "$base" 2>/dev/null \
        || error ticket_base_before_baseline
      verify_baseline "$base"
      count_object "$base" ticket_base
      capture_base_count
      validate_staged_control
      count_staged
      capture_candidate_count
      mode=ticket-staged
    else
      candidate=$(resolve_commit "$candidate")
      git merge-base --is-ancestor "$base" "$candidate" 2>/dev/null \
        || error ticket_base_not_ancestor
      validate_control_range "$base" "$candidate"
      need_tmp
      candidate_baseline="$tmp_root/ticket-candidate-baseline.txt"
      baseline_from_commit "$candidate" "$candidate_baseline"
      load_baseline "$candidate_baseline"
      git merge-base --is-ancestor "$b_commit" "$base" 2>/dev/null \
        || error ticket_base_before_baseline
      verify_baseline "$candidate"
      count_object "$base" ticket_base
      capture_base_count
      count_object "$candidate" ticket_candidate
      capture_candidate_count
      mode=ticket-commit
    fi
    compare_footprint "$mode"
    ;;

  milestone)
    candidate=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --candidate) [ "$#" -ge 2 ] || error candidate_value_missing; candidate=$2; shift 2 ;;
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
    capture_base_count
    count_object "$candidate" milestone_candidate
    capture_candidate_count
    compare_footprint milestone
    ;;

  ci)
    candidate=
    base=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --candidate) [ "$#" -ge 2 ] || error candidate_value_missing; candidate=$2; shift 2 ;;
        --base) [ "$#" -ge 2 ] || error base_value_missing; base=$2; shift 2 ;;
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
    metric_base=$base
    if ! git merge-base --is-ancestor "$b_commit" "$metric_base" 2>/dev/null; then
      metric_base=$b_commit
      printf 'test_budget base_adjustment=PASS policy=test_footprint requested_base=%s metric_base=%s reason=requested_base_before_policy_baseline\n' \
        "$base" "$metric_base"
    fi
    count_object "$metric_base" ci_base
    capture_base_count
    count_object "$candidate" ci_candidate
    capture_candidate_count
    compare_footprint ci
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
