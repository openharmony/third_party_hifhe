#!/usr/bin/env bash

set -euo pipefail

HIFHE_ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HITLS_ROOT_DIR=${HITLS_ROOT_DIR:-}
HIFHE_PROVIDER_DIR=${HIFHE_PROVIDER_DIR:-"${HIFHE_ROOT_DIR}/build"}
RUN_TESTS=""
HIFHE_ENABLE_ASAN=OFF
HIFHE_ENABLE_GCOV=OFF

if [[ -z "${HITLS_ROOT_DIR}" && -f "${HIFHE_PROVIDER_DIR}/base_path.txt" ]]; then
    HITLS_ROOT_DIR=$(<"${HIFHE_PROVIDER_DIR}/base_path.txt")
fi
HITLS_ROOT_DIR=${HITLS_ROOT_DIR:-"${HIFHE_ROOT_DIR}/platform/openhitls"}

for ARG in "$@"; do
    case "${ARG}" in
        asan) HIFHE_ENABLE_ASAN=ON ;;
        gcov) HIFHE_ENABLE_GCOV=ON ;;
        run-tests=*) RUN_TESTS=${ARG#run-tests=} ;;
        list-suites)
            find "${HIFHE_ROOT_DIR}/testcode/sdv" -name '*.data' -printf '%f\n' | sed 's/\.data$//'
            exit 0
            ;;
        clean)
            cmake -E remove_directory "${HIFHE_ROOT_DIR}/testcode/build"
            cmake -E remove_directory "${HIFHE_ROOT_DIR}/testcode/framework/gen_test/build"
            cmake -E remove_directory "${HIFHE_ROOT_DIR}/testcode/output"
            exit 0
            ;;
        -h|--help)
            echo "Usage: $0 [asan] [gcov] [run-tests=name|name] [list-suites] [clean]"
            exit 0
            ;;
        *) echo "Unknown option: ${ARG}" >&2; exit 1 ;;
    esac
done

if [[ ! -f "${HIFHE_PROVIDER_DIR}/libhifhe_provider.so" ]]; then
    echo "Provider not found: ${HIFHE_PROVIDER_DIR}/libhifhe_provider.so" >&2
    exit 1
fi
TEST_SUITES=""
if [[ -n "${RUN_TESTS}" ]]; then
    IFS='|' read -ra NAMES <<< "${RUN_TESTS}"
    for NAME in "${NAMES[@]}"; do
        SUITE=$(find "${HIFHE_ROOT_DIR}/testcode/sdv" -name "${NAME}.data" -print -quit)
        [[ -n "${SUITE}" ]] || { echo "Test not found: ${NAME}" >&2; exit 1; }
        TEST_SUITES+="${SUITE%.data} "
    done
else
    while IFS= read -r SUITE; do
        TEST_SUITES+="${SUITE%.data} "
    done < <(find "${HIFHE_ROOT_DIR}/testcode/sdv" -name '*.data' -print)
fi

cmake -E remove_directory "${HIFHE_ROOT_DIR}/testcode/build"
cmake -S "${HIFHE_ROOT_DIR}/testcode" -B "${HIFHE_ROOT_DIR}/testcode/build" \
    -DHITLS_ROOT_DIR="${HITLS_ROOT_DIR}" \
    -DHIFHE_PROVIDER_DIR="${HIFHE_PROVIDER_DIR}" \
    -DHIFHE_ENABLE_ASAN="${HIFHE_ENABLE_ASAN}" \
    -DHIFHE_ENABLE_GCOV="${HIFHE_ENABLE_GCOV}" \
    -DGEN_TEST_FILES="${TEST_SUITES}"
cmake --build "${HIFHE_ROOT_DIR}/testcode/build" --parallel
