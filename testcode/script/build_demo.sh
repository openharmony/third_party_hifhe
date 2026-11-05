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

# Builds testcode/demo standalone: no test-suite generation. Needs
# build/libhifhe.so, i.e. build_hifhe.sh has already run.

set -euo pipefail

usage()
{
    cat <<'USAGE'
Usage: build_demo.sh [asan] [clean]

  asan    build with AddressSanitizer
  clean   remove the demo build and binaries, then exit

Binaries land in testcode/output/demo, named after their source files.
They carry an rpath to the provider and openHiTLS build
directories, so they run without LD_LIBRARY_PATH:

  testcode/output/demo/hifhe_bgv_provider_demo
  testcode/output/demo/hifhe_bgv_demo
USAGE
}

HIFHE_ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
DEMO_SRC_DIR="${HIFHE_ROOT_DIR}/testcode/demo"
DEMO_BUILD_DIR="${DEMO_SRC_DIR}/build"
DEMO_OUT_DIR="${HIFHE_ROOT_DIR}/testcode/output/demo"
HIFHE_PROVIDER_DIR=${HIFHE_PROVIDER_DIR:-"${HIFHE_ROOT_DIR}/build"}

HITLS_ROOT_DIR=${HITLS_ROOT_DIR:-}
if [[ -z "${HITLS_ROOT_DIR}" && -f "${HIFHE_PROVIDER_DIR}/base_path.txt" ]]; then
    HITLS_ROOT_DIR=$(<"${HIFHE_PROVIDER_DIR}/base_path.txt")
fi
HITLS_ROOT_DIR=${HITLS_ROOT_DIR:-"${HIFHE_ROOT_DIR}/platform/openhitls"}

ENABLE_ASAN=OFF
while [[ $# -gt 0 ]]; do
    case "$1" in
        asan) ENABLE_ASAN=ON ;;
        clean)
            rm -rf "${DEMO_BUILD_DIR}" "${DEMO_OUT_DIR}"
            echo "Demo build cleaned."
            exit 0
            ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
    shift
done

if [[ ! -f "${HIFHE_PROVIDER_DIR}/libhifhe.so" ]]; then
    echo "[ERROR] ${HIFHE_PROVIDER_DIR}/libhifhe.so not found. Run build_hifhe.sh first." >&2
    exit 1
fi

CFLAGS=""
LDFLAGS=""
if [[ "${ENABLE_ASAN}" == "ON" ]]; then
    CFLAGS="-fsanitize=address -fno-omit-frame-pointer"
    LDFLAGS="-fsanitize=address"
fi

mkdir -p "${DEMO_BUILD_DIR}"
cmake -S "${DEMO_SRC_DIR}" -B "${DEMO_BUILD_DIR}" \
    -DHITLS_ROOT_DIR="${HITLS_ROOT_DIR}" \
    -DHIFHE_PROVIDER_DIR="${HIFHE_PROVIDER_DIR}" \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}"
cmake --build "${DEMO_BUILD_DIR}" --parallel "$(nproc)"

echo "Built into ${DEMO_OUT_DIR}:"
ls -1 "${DEMO_OUT_DIR}"
