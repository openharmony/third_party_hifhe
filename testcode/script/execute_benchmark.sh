#!/usr/bin/env bash

# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

# Runs the benchmark with the provider and openHiTLS libraries on the path.
# Every argument is passed through, so:
#
#   bash testcode/script/execute_benchmark.sh -h
#   bash testcode/script/execute_benchmark.sh -a Kernel
#   bash testcode/script/execute_benchmark.sh -p bgv-2048-48-17bit -s 3
#   bash testcode/script/execute_benchmark.sh -m

set -euo pipefail

HIFHE_ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HIFHE_PROVIDER_DIR=${HIFHE_PROVIDER_DIR:-"${HIFHE_ROOT_DIR}/build"}

HITLS_ROOT_DIR=${HITLS_ROOT_DIR:-}
if [[ -z "${HITLS_ROOT_DIR}" && -f "${HIFHE_PROVIDER_DIR}/base_path.txt" ]]; then
    HITLS_ROOT_DIR=$(<"${HIFHE_PROVIDER_DIR}/base_path.txt")
fi
HITLS_ROOT_DIR=${HITLS_ROOT_DIR:-"${HIFHE_ROOT_DIR}/platform/openhitls"}

BENCH_BIN="${HIFHE_ROOT_DIR}/testcode/output/hifhe_benchmark"
if [[ ! -x "${BENCH_BIN}" ]]; then
    echo "[ERROR] ${BENCH_BIN} not found. Run build_benchmark.sh first." >&2
    exit 1
fi

export LD_LIBRARY_PATH="${HIFHE_PROVIDER_DIR}:${HITLS_ROOT_DIR}/build${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

cd "${HIFHE_ROOT_DIR}/testcode/output"
./hifhe_benchmark "$@"
