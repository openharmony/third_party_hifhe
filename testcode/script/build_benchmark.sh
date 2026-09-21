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

# Builds testcode/benchmark standalone: no test-suite generation, so it is
# quick enough to run between edits. Needs build/libhifhe_provider.so, i.e.
# build_hifhe.sh has already run.

set -euo pipefail

usage()
{
    cat <<'USAGE'
Usage: build_benchmark.sh [asan] [clean] [run]
                          [--enable ckks|bgv] [--disable ckks|bgv]

  asan       build with AddressSanitizer
  clean      remove the benchmark build and binary, then exit
  run        build, then run every benchmark
  --enable   force an algorithm's modules on  (-DHIFHE_<ALG>=ON)
  --disable  force an algorithm's modules off (-DHIFHE_<ALG>=OFF)

Without --enable/--disable each algorithm follows the provider: the modules
built are the ones whose algorithm is in build/include/hifhe_config.h. A
module calls its algorithm directly, so asking for one the provider was built
without will not link.

The binary lands in testcode/output/hifhe_benchmark. For finer control run it
directly, or use execute_benchmark.sh:

  bash testcode/script/execute_benchmark.sh -a Kernel
USAGE
}

HIFHE_ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BENCH_SRC_DIR="${HIFHE_ROOT_DIR}/testcode/benchmark"
BENCH_BUILD_DIR="${BENCH_SRC_DIR}/build"
HIFHE_PROVIDER_DIR=${HIFHE_PROVIDER_DIR:-"${HIFHE_ROOT_DIR}/build"}

HITLS_ROOT_DIR=${HITLS_ROOT_DIR:-}
if [[ -z "${HITLS_ROOT_DIR}" && -f "${HIFHE_PROVIDER_DIR}/base_path.txt" ]]; then
    HITLS_ROOT_DIR=$(<"${HIFHE_PROVIDER_DIR}/base_path.txt")
fi
HITLS_ROOT_DIR=${HITLS_ROOT_DIR:-"${HIFHE_ROOT_DIR}/platform/openhitls"}

ENABLE_ASAN=OFF
DO_RUN="no"
# Empty means "follow the provider"; CMake reads hifhe_config.h for the default.
HIFHE_CKKS=""
HIFHE_BGV=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        asan) ENABLE_ASAN=ON ;;
        run)  DO_RUN="yes" ;;
        clean)
            rm -rf "${BENCH_BUILD_DIR}" "${HIFHE_ROOT_DIR}/testcode/output/hifhe_benchmark"
            echo "Benchmark build cleaned."
            exit 0
            ;;
        --enable|--disable)
            [[ "$1" == "--enable" ]] && STATE=ON || STATE=OFF
            shift
            case "${1:-}" in
                ckks) HIFHE_CKKS=${STATE} ;;
                bgv)  HIFHE_BGV=${STATE} ;;
                *) echo "Expected ckks or bgv after --enable/--disable" >&2; exit 1 ;;
            esac
            ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
    shift
done

CMAKE_FEATURE_ARGS=()
[[ -n "${HIFHE_CKKS}" ]] && CMAKE_FEATURE_ARGS+=("-DHIFHE_CKKS=${HIFHE_CKKS}")
[[ -n "${HIFHE_BGV}"  ]] && CMAKE_FEATURE_ARGS+=("-DHIFHE_BGV=${HIFHE_BGV}")

if [[ ! -f "${HIFHE_PROVIDER_DIR}/libhifhe_provider.so" ]]; then
    echo "[ERROR] ${HIFHE_PROVIDER_DIR}/libhifhe_provider.so not found. Run build_hifhe.sh first." >&2
    exit 1
fi

# The provider headers are compiled against the same macro set the library was.
MACROS=""
if [[ -f "${HITLS_ROOT_DIR}/build/macro.txt" ]]; then
    MACROS="$(tr '\n' ' ' < "${HITLS_ROOT_DIR}/build/macro.txt")"
fi

CFLAGS="${MACROS}"
if [[ "${ENABLE_ASAN}" == "ON" ]]; then
    CFLAGS="${CFLAGS} -fsanitize=address -fno-omit-frame-pointer"
fi

mkdir -p "${BENCH_BUILD_DIR}"
cmake -S "${BENCH_SRC_DIR}" -B "${BENCH_BUILD_DIR}" \
    -DHITLS_ROOT_DIR="${HITLS_ROOT_DIR}" \
    -DHIFHE_PROVIDER_DIR="${HIFHE_PROVIDER_DIR}" \
    "${CMAKE_FEATURE_ARGS[@]}" \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_EXE_LINKER_FLAGS="$([[ "${ENABLE_ASAN}" == "ON" ]] && echo -fsanitize=address)"
cmake --build "${BENCH_BUILD_DIR}" --parallel "$(nproc)"

echo "Built: ${HIFHE_ROOT_DIR}/testcode/output/hifhe_benchmark"

if [[ "${DO_RUN}" == "yes" ]]; then
    bash "${HIFHE_ROOT_DIR}/testcode/script/execute_benchmark.sh"
fi
