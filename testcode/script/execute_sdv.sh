#!/usr/bin/env bash

set -euo pipefail

HIFHE_ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HIFHE_PROVIDER_DIR=${HIFHE_PROVIDER_DIR:-"${HIFHE_ROOT_DIR}/build"}
if [[ $# -gt 0 ]]; then
    IFS='|' read -ra SUITES <<< "$1"
    for SUITE in "${SUITES[@]}"; do
        ctest --test-dir "${HIFHE_PROVIDER_DIR}" --output-on-failure --no-tests=error -L sdv -R "^${SUITE}$"
    done
else
    ctest --test-dir "${HIFHE_PROVIDER_DIR}" --output-on-failure --no-tests=error -L sdv
fi
