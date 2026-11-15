#!/usr/bin/env bash
set -euo pipefail
project_root=$1
environment_script=$2
lsf_module=$3
python_path=$4
worker_script=$5
profile=$6
cd -- "$project_root"
if [[ -n "$environment_script" ]]; then
    source "$environment_script"
fi
if [[ -n "$lsf_module" ]]; then
    module load "$lsf_module"
fi
exec "$python_path" -B "$worker_script" worker --command-profile "$profile"
