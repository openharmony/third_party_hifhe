#!/usr/bin/env bash

set -euo pipefail

HIFHE_ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HIFHE_PROVIDER_DIR=${HIFHE_PROVIDER_DIR:-"${HIFHE_ROOT_DIR}/build"}
if [[ -z "${HITLS_ROOT_DIR:-}" && -f "${HIFHE_PROVIDER_DIR}/base_path.txt" ]]; then
    HITLS_ROOT_DIR=$(<"${HIFHE_PROVIDER_DIR}/base_path.txt")
fi
HITLS_ROOT_DIR=${HITLS_ROOT_DIR:-"${HIFHE_ROOT_DIR}/platform/openhitls"}
cd "${HIFHE_ROOT_DIR}/testcode/output"

export HIFHE_PROVIDER_PATH="${HIFHE_PROVIDER_DIR}"
export LD_LIBRARY_PATH="${HIFHE_PROVIDER_DIR}:${HITLS_ROOT_DIR}/build${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

if [[ $# -gt 0 ]]; then
    IFS='|' read -ra SUITES <<< "$1"
else
    mapfile -t SUITES < <(find "${HIFHE_ROOT_DIR}/testcode/sdv" -name '*.data' -printf '%f\n' | sed 's/\.data$//')
fi

for SUITE in "${SUITES[@]}"; do
    "./${SUITE}" NO_DETAIL
done
