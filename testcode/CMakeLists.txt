# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

cmake_minimum_required(VERSION 3.16)
project(hifhe_test C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(HIFHE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")
set(HIFHE_PROVIDER_DIR "${HIFHE_ROOT}/build" CACHE PATH "HiFHE provider build directory")
set(HITLS_LIB_DIR "${HITLS_ROOT_DIR}/build" CACHE PATH "openHiTLS library directory")
option(HIFHE_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(HIFHE_ENABLE_GCOV "Enable coverage" OFF)

find_package(Threads REQUIRED)
find_library(HITLS_CRYPTO_LIB hitls_crypto PATHS "${HITLS_LIB_DIR}" NO_DEFAULT_PATH)
find_library(HITLS_BSL_LIB hitls_bsl PATHS "${HITLS_LIB_DIR}" NO_DEFAULT_PATH)
find_library(HIFHE_PROVIDER_LIB hifhe_provider PATHS "${HIFHE_PROVIDER_DIR}" NO_DEFAULT_PATH)
foreach(LIB HITLS_CRYPTO_LIB HITLS_BSL_LIB HIFHE_PROVIDER_LIB)
    if(NOT ${LIB})
        message(FATAL_ERROR "Required library ${LIB} not found")
    endif()
endforeach()

add_compile_options(-Wall -Wextra -Werror -Wno-enum-conversion)
if(HIFHE_ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()
if(HIFHE_ENABLE_GCOV)
    add_compile_options(--coverage)
    add_link_options(--coverage)
endif()

include(ExternalProject)
ExternalProject_Add(gen_testcase
    SOURCE_DIR "${HIFHE_ROOT}/testcode/framework/gen_test"
    BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/gen_testcase"
    CONFIGURE_COMMAND ${CMAKE_COMMAND}
        -DHITLS_ROOT_DIR=${HITLS_ROOT_DIR}
        -DPRINT_TO_TERMINAL=ON
        <SOURCE_DIR>
    BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR>
    INSTALL_COMMAND ""
    UPDATE_COMMAND ""
    EXCLUDE_FROM_ALL TRUE
)

option(BUILD_BENCHMARK "Build the benchmark alongside the test suites" OFF)

add_subdirectory(sdv)
if(BUILD_BENCHMARK)
    add_subdirectory(benchmark)
endif()
