#!/usr/bin/env bash
set -u -o pipefail
script_path=${BASH_SOURCE[0]}
script_dir_part=${script_path%/*}
[[ $script_dir_part != "$script_path" ]] || script_dir_part=.
script_dir=$(cd -- "$script_dir_part" && pwd -P) || exit 1
exec python3 -B "$script_dir/cpu_profile/record.py" "$@"
