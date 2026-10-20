# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

# Builds two ways: as a subdirectory of testcode (-DBUILD_BENCHMARK=ON), or
# standalone. Standalone is the one to use while optimising: it skips the
# test-suite generation the SDV build needs and takes a couple of seconds.

cmake_minimum_required(VERSION 3.16)

set(BENCH_STANDALONE OFF)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(hifhe_benchmark C)
    set(BENCH_STANDALONE ON)
    set(CMAKE_C_STANDARD 11)
    set(CMAKE_C_STANDARD_REQUIRED ON)

    set(HIFHE_ROOT "${PROJECT_SOURCE_DIR}/../..")
    if(NOT HITLS_ROOT_DIR)
        if(EXISTS "${HIFHE_ROOT}/build/base_path.txt")
            file(READ "${HIFHE_ROOT}/build/base_path.txt" HITLS_ROOT_DIR)
            string(STRIP "${HITLS_ROOT_DIR}" HITLS_ROOT_DIR)
        else()
            set(HITLS_ROOT_DIR "${HIFHE_ROOT}/platform/openhitls")
        endif()
    endif()
    set(HIFHE_DEPENDENCY_DIRS ${HITLS_ROOT_DIR}/build ${HIFHE_ROOT}/build)
    if(NOT HIFHE_PROVIDER_DIR)
        set(HIFHE_PROVIDER_DIR "${HIFHE_ROOT}/build")
    endif()

    find_library(HITLS_CRYPTO_LIB hitls_crypto PATHS ${HIFHE_DEPENDENCY_DIRS} NO_DEFAULT_PATH)
    find_library(HITLS_BSL_LIB    hitls_bsl    PATHS ${HIFHE_DEPENDENCY_DIRS} NO_DEFAULT_PATH)
    find_library(HIFHE_PROVIDER_LIB hifhe_provider PATHS ${HIFHE_DEPENDENCY_DIRS} NO_DEFAULT_PATH)
    foreach(LIB IN ITEMS HITLS_CRYPTO_LIB HITLS_BSL_LIB HIFHE_PROVIDER_LIB)
        if(NOT ${LIB})
            message(FATAL_ERROR "Required library ${LIB} not found in: ${HIFHE_DEPENDENCY_DIRS}")
        endif()
    endforeach()

    add_compile_options(-Wall -Wextra -Werror)
endif()

# The Bgv module drives the provider entry points; the Kernel module reaches
# into the transforms, so it needs the private headers as well.
include_directories(
    ${HITLS_ROOT_DIR}/include/bsl
    ${HITLS_ROOT_DIR}/include/crypto
    ${HITLS_ROOT_DIR}/bsl/include
    ${HITLS_ROOT_DIR}/config/macro_config
    ${HITLS_ROOT_DIR}/conf/macro_config
    ${HITLS_ROOT_DIR}/crypto/include
    ${HIFHE_ROOT}/include
    ${HIFHE_PROVIDER_DIR}/include
    ${HIFHE_ROOT}/src/bgv/include
    ${HIFHE_ROOT}/src/bgv/src
    ${HIFHE_ROOT}/src/bgv/src/include
)

# Default each switch to what the provider was actually built with, so the
# benchmark never references an algorithm that was trimmed out of it. Either
# can be forced on the command line, e.g. -DHIFHE_BGV=OFF.
set(HIFHE_CFG_HEADER "${HIFHE_PROVIDER_DIR}/include/hifhe_config.h")
set(HIFHE_BGV_DEFAULT OFF)
set(HIFHE_CKKS_DEFAULT OFF)
if(EXISTS "${HIFHE_CFG_HEADER}")
    file(STRINGS "${HIFHE_CFG_HEADER}" HIFHE_CFG_BGV
        REGEX "^#define[ \t]+HIFHE_BGV([ \t]|$)")
    file(STRINGS "${HIFHE_CFG_HEADER}" HIFHE_CFG_CKKS
        REGEX "^#define[ \t]+HIFHE_CKKS([ \t]|$)")
    if(HIFHE_CFG_BGV)
        set(HIFHE_BGV_DEFAULT ON)
    endif()
    if(HIFHE_CFG_CKKS)
        set(HIFHE_CKKS_DEFAULT ON)
    endif()
else()
    message(WARNING "[benchmark] ${HIFHE_CFG_HEADER} not found; every module is off")
endif()

option(HIFHE_BGV  "Build the BGV benchmark modules"  ${HIFHE_BGV_DEFAULT})
option(HIFHE_CKKS "Build the CKKS benchmark modules" ${HIFHE_CKKS_DEFAULT})

set(BENCH_SOURCES "")
if(HIFHE_BGV)
    # Both BGV modules, Kernel and Bgv, live in this file.
    list(APPEND BENCH_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/bgv_bench.c")
endif()
# CKKS has no module yet; add ckks_bench.c here under if(HIFHE_CKKS).

message(STATUS "[benchmark] BGV: ${HIFHE_BGV}  CKKS: ${HIFHE_CKKS}")

# A module calls its algorithm directly, so it is only built when that
# algorithm is in the provider. With none selected there is nothing to
# measure, and the driver would link against a registry of zero entries.
if(NOT BENCH_SOURCES)
    message(FATAL_ERROR
        "[benchmark] no modules selected (HIFHE_BGV=${HIFHE_BGV}, "
        "HIFHE_CKKS=${HIFHE_CKKS}). Build the provider with the algorithm you "
        "want to measure, or pass -DHIFHE_<ALG>=ON.")
endif()

add_executable(hifhe_benchmark "${CMAKE_CURRENT_SOURCE_DIR}/benchmark.c" ${BENCH_SOURCES})

set_target_properties(hifhe_benchmark PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${HIFHE_ROOT}/testcode/output"
)

# The SDV build compiles at -g -O0 so a failure is debuggable. A benchmark at
# -O0 measures the compiler, not the library, so the level is forced back up
# here; target options come after CMAKE_C_FLAGS, so this one wins.
target_compile_options(hifhe_benchmark PRIVATE -O2 -g)

target_link_libraries(hifhe_benchmark
    ${HITLS_CRYPTO_LIB}
    ${HITLS_BSL_LIB}
    ${HIFHE_PROVIDER_LIB}
    -Wl,--no-as-needed
    -lpthread
    -Wl,--as-needed
)

if(BENCH_STANDALONE)
    # Standalone has no install step to place the shared libraries, so the
    # binary carries the paths it was linked against.
    set_target_properties(hifhe_benchmark PROPERTIES
        BUILD_RPATH "${HITLS_ROOT_DIR}/build;${HIFHE_ROOT}/build"
    )
endif()
