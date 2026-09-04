#!/usr/bin/env bash

set -euo pipefail

HIFHE_ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BUILD_TYPE=Release
HIFHE_ENABLE_ASAN=OFF
HIFHE_ENABLE_GCOV=OFF
HIFHE_BUILD_SHARED=ON
HIFHE_BUILD_STATIC=ON
HIFHE_CKKS=ON
HITLS_ROOT_PATH=""
BUILD_ARGS=""
OPENHITLS_REPO=${OPENHITLS_REPO:-https://github.com/openHiTLS/openHiTLS.git}
OPENHITLS_REF=${OPENHITLS_REF:-openhitls-0.4.0-alpha8}

while [[ $# -gt 0 ]]; do
    case "$1" in
        debug) BUILD_TYPE=Debug; shift ;;
        asan) HIFHE_ENABLE_ASAN=ON; shift ;;
        gcov) HIFHE_ENABLE_GCOV=ON; shift ;;
        shared) HIFHE_BUILD_STATIC=OFF; shift ;;
        static) HIFHE_BUILD_SHARED=OFF; shift ;;
        --enable)
            [[ $# -ge 2 && "${2,,}" == "ckks" ]] || { echo "Unknown algorithm" >&2; exit 1; }
            HIFHE_CKKS=ON
            shift 2
            ;;
        --disable)
            [[ $# -ge 2 && "${2,,}" == "ckks" ]] || { echo "Unknown algorithm" >&2; exit 1; }
            HIFHE_CKKS=OFF
            shift 2
            ;;
        --hitls_dir)
            [[ $# -ge 2 && -d "$2" ]] || { echo "Invalid openHiTLS directory" >&2; exit 1; }
            HITLS_ROOT_PATH=$(realpath "$2")
            shift 2
            ;;
        --build_args)
            [[ $# -ge 2 ]] || { echo "Missing build arguments" >&2; exit 1; }
            BUILD_ARGS=$2
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [debug] [asan] [gcov] [shared|static] [--enable ckks] [--disable ckks]"
            echo "          [--hitls_dir PATH] [--build_args FLAGS]"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "${HITLS_ROOT_PATH}" ]]; then
    HITLS_ROOT_PATH="${HIFHE_ROOT_DIR}/platform/openhitls"
    if [[ ! -d "${HITLS_ROOT_PATH}" ]]; then
        mkdir -p "${HIFHE_ROOT_DIR}/platform"
        git clone --depth 1 --branch "${OPENHITLS_REF}" "${OPENHITLS_REPO}" "${HITLS_ROOT_PATH}"
    fi
fi

if [[ ! -f "${HITLS_ROOT_PATH}/build/libhitls_crypto.so" ||
      ! -f "${HITLS_ROOT_PATH}/build/libhitls_bsl.so" ]]; then
    (cd "${HITLS_ROOT_PATH}/testcode/script" && bash build_hitls.sh shared)
fi

cmake -E remove_directory "${HIFHE_ROOT_DIR}/build"
cmake -S "${HIFHE_ROOT_DIR}" -B "${HIFHE_ROOT_DIR}/build" \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DCMAKE_C_FLAGS="${BUILD_ARGS}" \
    -DHIFHE_ENABLE_ASAN="${HIFHE_ENABLE_ASAN}" \
    -DHIFHE_ENABLE_GCOV="${HIFHE_ENABLE_GCOV}" \
    -DHIFHE_BUILD_SHARED="${HIFHE_BUILD_SHARED}" \
    -DHIFHE_BUILD_STATIC="${HIFHE_BUILD_STATIC}" \
    -DHIFHE_CKKS="${HIFHE_CKKS}" \
    -DHITLS_ROOT_PATH="${HITLS_ROOT_PATH}"
cmake --build "${HIFHE_ROOT_DIR}/build" --parallel
printf '%s\n' "${HITLS_ROOT_PATH}" > "${HIFHE_ROOT_DIR}/build/base_path.txt"
