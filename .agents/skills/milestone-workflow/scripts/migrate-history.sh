#!/bin/sh
set -eu

repo=.
through=
apply=false

usage() {
  cat <<'USAGE'
Usage: migrate-history.sh --through M<N> [--repo PATH] [--apply]

Archive ticket and handoff bodies for milestones M0..M<N>. Dry-run is the default.
Old paths become short redirects; specs, test plans, ADRs, and later milestones are
left untouched. Re-running after a successful apply makes no changes.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo)
      [ "$#" -ge 2 ] || { echo "--repo requires a path" >&2; exit 2; }
      repo=$2
      shift 2
      ;;
    --through)
      [ "$#" -ge 2 ] || { echo "--through requires a milestone" >&2; exit 2; }
      through=$2
      shift 2
      ;;
    --apply)
      apply=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$through" in
  M[0-9]*) through_num=${through#M} ;;
  *) echo "--through must look like M3" >&2; exit 2 ;;
esac
case "$through_num" in
  ''|*[!0-9]*) echo "--through must look like M3" >&2; exit 2 ;;
esac

if [ -d "$repo" ]; then
  repo=$(CDPATH= cd -- "$repo" && pwd)
elif $apply; then
  mkdir -p "$repo"
  repo=$(CDPATH= cd -- "$repo" && pwd)
else
  echo "repository directory does not exist: $repo" >&2
  exit 1
fi
cd "$repo"

work=${TMPDIR:-/tmp}/milestone-history.$$
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir -p "$work"

moved=0
redirected=0
unchanged=0
conflicts=0
indexes=0
selected=

milestone_number() {
  value=$1
  case "$value" in
    M[0-9]*) number=${value#M} ;;
    *) return 1 ;;
  esac
  case "$number" in ''|*[!0-9]*) return 1 ;; esac
  printf '%s\n' "$number"
}

tracked() {
  git rev-parse --is-inside-work-tree >/dev/null 2>&1 &&
    git ls-files --error-unmatch -- "$1" >/dev/null 2>&1
}

write_redirect() {
  source_path=$1
  target_path=$2
  label=$3
  source_dir=$(dirname "$source_path")
  relative=$(printf '%s' "$target_path" | sed 's#^docs/#../#')
  tmp="$work/redirect.$redirected"
  cat > "$tmp" <<EOF_REDIRECT
<!-- milestone-history:v1 target=$target_path -->
# $label — archived

Full record: [$target_path]($relative)
EOF_REDIRECT
  if [ -f "$source_path" ] && cmp -s "$tmp" "$source_path"; then
    unchanged=$((unchanged + 1))
    return
  fi
  if $apply; then
    mkdir -p "$source_dir"
    cat "$tmp" > "$source_path"
  fi
  redirected=$((redirected + 1))
}

archive_one() {
  source_path=$1
  milestone=$2
  kind=$3
  label=$4
  target_path="docs/history/$milestone/$kind/$(basename "$source_path")"
  marker="<!-- milestone-history:v1 target=$target_path -->"

  selected="$selected $milestone"

  if [ -f "$source_path" ] && grep -Fqx "$marker" "$source_path" 2>/dev/null; then
    if [ -f "$target_path" ]; then
      unchanged=$((unchanged + 1))
      return
    fi
    echo "missing archive target for redirect: $source_path -> $target_path" >&2
    conflicts=$((conflicts + 1))
    return
  fi

  if [ ! -f "$source_path" ]; then
    [ -f "$target_path" ] && unchanged=$((unchanged + 1))
    return
  fi

  if [ -e "$target_path" ]; then
    if cmp -s "$source_path" "$target_path"; then
      echo "redirect: $source_path -> $target_path"
      write_redirect "$source_path" "$target_path" "$label"
      return
    fi
    echo "archive conflict: $source_path and $target_path differ" >&2
    conflicts=$((conflicts + 1))
    return
  fi

  echo "archive: $source_path -> $target_path"
  if $apply; then
    mkdir -p "$(dirname "$target_path")"
    if tracked "$source_path"; then
      git mv "$source_path" "$target_path"
    else
      mv "$source_path" "$target_path"
    fi
  fi
  moved=$((moved + 1))
  write_redirect "$source_path" "$target_path" "$label"
}

: > "$work/tickets"
for path in docs/tickets/M*-T*.md; do
  [ -f "$path" ] || continue
  printf '%s\n' "$path"
done > "$work/tickets"

while IFS= read -r path; do
  [ -n "$path" ] || continue
  base=$(basename "$path" .md)
  milestone=$(printf '%s\n' "$base" | sed -n 's/^\(M[0-9][0-9]*\)-T.*/\1/p')
  [ -n "$milestone" ] || continue
  number=$(milestone_number "$milestone") || continue
  [ "$number" -le "$through_num" ] || continue
  label=$(printf '%s\n' "$base" | sed 's/-/ /2')
  archive_one "$path" "$milestone" tickets "$label"
done < "$work/tickets"

: > "$work/handoffs"
for path in docs/handoffs/HANDOFF-M*.md; do
  [ -f "$path" ] || continue
  printf '%s\n' "$path"
done > "$work/handoffs"

while IFS= read -r path; do
  [ -n "$path" ] || continue
  base=$(basename "$path" .md)
  milestone=$(printf '%s\n' "$base" | sed -n 's/^HANDOFF-\(M[0-9][0-9]*\)-.*/\1/p')
  [ -n "$milestone" ] || continue
  number=$(milestone_number "$milestone") || continue
  [ "$number" -le "$through_num" ] || continue
  archive_one "$path" "$milestone" handoffs "$base"
done < "$work/handoffs"

[ "$conflicts" -eq 0 ] || {
  echo "migration stopped: $conflicts conflict(s)" >&2
  exit 1
}

# Include milestones already archived even when this run only saw redirect files.
if [ -d docs/history ]; then
  for dir in docs/history/M*; do
    [ -d "$dir" ] || continue
    milestone=$(basename "$dir")
    number=$(milestone_number "$milestone") || continue
    [ "$number" -le "$through_num" ] || continue
    selected="$selected $milestone"
  done
fi

printf '%s\n' $selected 2>/dev/null | sed '/^$/d' | sort -u > "$work/milestones"
while IFS= read -r milestone; do
  [ -n "$milestone" ] || continue
  index="docs/history/$milestone/README.md"
  tmp="$work/index.$milestone"
  {
    echo "# $milestone history"
    echo
    echo "Closed ticket and handoff bodies. Their original paths contain redirects."
    if [ -d "docs/history/$milestone/tickets" ]; then
      echo
      echo "## Tickets"
      echo
      for item in "docs/history/$milestone/tickets"/*.md; do
        [ -f "$item" ] || continue
        name=$(basename "$item" .md)
        printf -- '- [%s](tickets/%s)\n' "$name" "$(basename "$item")"
      done
    fi
    if [ -d "docs/history/$milestone/handoffs" ]; then
      echo
      echo "## Handoffs"
      echo
      for item in "docs/history/$milestone/handoffs"/*.md; do
        [ -f "$item" ] || continue
        name=$(basename "$item" .md)
        printf -- '- [%s](handoffs/%s)\n' "$name" "$(basename "$item")"
      done
    fi
  } > "$tmp"

  if [ -f "$index" ] && cmp -s "$tmp" "$index"; then
    unchanged=$((unchanged + 1))
  else
    echo "index: $index"
    if $apply; then
      mkdir -p "$(dirname "$index")"
      cat "$tmp" > "$index"
    fi
    indexes=$((indexes + 1))
  fi
done < "$work/milestones"

printf 'summary: archive=%s redirect=%s index=%s unchanged=%s through=%s mode=%s\n' \
  "$moved" "$redirected" "$indexes" "$unchanged" "$through" \
  "$($apply && printf apply || printf dry-run)"
