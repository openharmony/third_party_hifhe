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

# Builds the benchmark from the library implementation objects.

set -euo pipefail

usage()
{
    cat <<'USAGE'
Usage: build_benchmark.sh [asan] [clean] [run]
                          [--enable bgv] [--disable bgv]

  asan       build with AddressSanitizer
  clean      remove the benchmark binary, then exit
  run        build, then run every benchmark
  --enable   force an algorithm's modules on  (-DHIFHE_<ALG>=ON)
  --disable  force an algorithm's modules off (-DHIFHE_<ALG>=OFF)

Without --enable/--disable, reuse the library build configuration.
The Bgv module requires HITLS_PROVIDER; Kernel runs without it.

The binary lands in testcode/output/hifhe_benchmark. For finer control run it
directly, or use execute_benchmark.sh:

  bash testcode/script/execute_benchmark.sh -a Kernel
USAGE
}

HIFHE_ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HIFHE_PROVIDER_DIR=${HIFHE_PROVIDER_DIR:-"${HIFHE_ROOT_DIR}/build"}

HITLS_ROOT_DIR=${HITLS_ROOT_DIR:-}
if [[ -z "${HITLS_ROOT_DIR}" && -f "${HIFHE_PROVIDER_DIR}/base_path.txt" ]]; then
    HITLS_ROOT_DIR=$(<"${HIFHE_PROVIDER_DIR}/base_path.txt")
fi
HITLS_ROOT_DIR=${HITLS_ROOT_DIR:-"${HIFHE_ROOT_DIR}/platform/openhitls"}

ENABLE_ASAN=OFF
DO_RUN="no"
# Empty means reuse the library build configuration.
HIFHE_BGV=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        asan) ENABLE_ASAN=ON ;;
        run)  DO_RUN="yes" ;;
        clean)
            rm -f "${HIFHE_ROOT_DIR}/testcode/output/hifhe_benchmark"
            echo "Benchmark build cleaned."
            exit 0
            ;;
        --enable|--disable)
            [[ "$1" == "--enable" ]] && STATE=ON || STATE=OFF
            shift
            case "${1:-}" in
                bgv)
                    if [[ "${STATE}" == OFF ]]; then
                        echo "BGV is the only algorithm and cannot be disabled" >&2
                        exit 1
                    fi
                    HIFHE_BGV=${STATE}
                    ;;
                *) echo "Expected bgv after --enable/--disable" >&2; exit 1 ;;
            esac
            ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
    shift
done

CMAKE_FEATURE_ARGS=()
[[ -n "${HIFHE_BGV}"  ]] && CMAKE_FEATURE_ARGS+=("-DHIFHE_BGV=${HIFHE_BGV}")


CMAKE_FEATURE_ARGS+=("-DHITLS_ROOT_PATH=${HITLS_ROOT_DIR}")
cmake -S "${HIFHE_ROOT_DIR}" -B "${HIFHE_PROVIDER_DIR}" \
    -DBUILD_BENCHMARK=ON \
    -DHIFHE_ENABLE_ASAN="${ENABLE_ASAN}" \
    "${CMAKE_FEATURE_ARGS[@]}"
cmake --build "${HIFHE_PROVIDER_DIR}" --target hifhe_benchmark --parallel "$(nproc)"

if [[ "${DO_RUN}" == "yes" ]]; then
    bash "${HIFHE_ROOT_DIR}/testcode/script/execute_benchmark.sh"
fi
