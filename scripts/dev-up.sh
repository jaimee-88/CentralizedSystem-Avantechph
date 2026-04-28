#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project_dir="$repo_root/AvantechPortal"

if [[ -x "$repo_root/.venv/bin/python" ]]; then
  py="$repo_root/.venv/bin/python"
elif [[ -x "$project_dir/.venv/bin/python" ]]; then
  py="$project_dir/.venv/bin/python"
else
  py="python3"
fi

cd "$project_dir"

"$py" manage.py migrate

# Default to the usual dev port unless args are provided.
if [[ "$#" -eq 0 ]]; then
  "$py" manage.py runserver 0.0.0.0:8000
else
  "$py" manage.py runserver "$@"
fi
