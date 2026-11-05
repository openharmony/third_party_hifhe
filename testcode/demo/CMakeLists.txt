# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

# One executable per demo/*.c, named after the file.
# Builds with the root tests or standalone.

cmake_minimum_required(VERSION 3.16)

set(DEMO_STANDALONE OFF)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(hifhe_demo C)
    set(DEMO_STANDALONE ON)
    set(CMAKE_C_STANDARD 11)
    set(CMAKE_C_STANDARD_REQUIRED ON)
    enable_testing()

    set(HIFHE_ROOT "${PROJECT_SOURCE_DIR}/../..")
    if(NOT HITLS_ROOT_DIR)
        if(EXISTS "${HIFHE_ROOT}/build/base_path.txt")
            file(READ "${HIFHE_ROOT}/build/base_path.txt" HITLS_ROOT_DIR)
            string(STRIP "${HITLS_ROOT_DIR}" HITLS_ROOT_DIR)
        else()
            set(HITLS_ROOT_DIR "${HIFHE_ROOT}/platform/openhitls")
        endif()
    endif()
    if(NOT HIFHE_PROVIDER_DIR)
        set(HIFHE_PROVIDER_DIR "${HIFHE_ROOT}/build")
    endif()
    set(HIFHE_DEPENDENCY_DIRS ${HITLS_ROOT_DIR}/build ${HIFHE_PROVIDER_DIR})

    find_library(HITLS_CRYPTO_LIB hitls_crypto PATHS ${HIFHE_DEPENDENCY_DIRS} NO_DEFAULT_PATH)
    find_library(HITLS_BSL_LIB hitls_bsl PATHS ${HIFHE_DEPENDENCY_DIRS} NO_DEFAULT_PATH)
    foreach(LIB IN ITEMS HITLS_CRYPTO_LIB HITLS_BSL_LIB)
        if(NOT ${LIB})
            message(FATAL_ERROR "Required library ${LIB} not found in: ${HIFHE_DEPENDENCY_DIRS}")
        endif()
    endforeach()

    add_compile_options(-Wall -Wextra -Werror)
endif()

if(DEMO_STANDALONE)
    find_library(HIFHE_DEMO_LIB hifhe PATHS "${HIFHE_PROVIDER_DIR}" NO_DEFAULT_PATH)
    if(NOT HIFHE_DEMO_LIB)
        message(FATAL_ERROR "libhifhe not found in ${HIFHE_PROVIDER_DIR}")
    endif()
    file(STRINGS "${HIFHE_PROVIDER_DIR}/include/hifhe_config.h" HIFHE_DEMO_PROVIDER
        REGEX "^#define HITLS_PROVIDER 1$")
    if(NOT EXISTS "${HIFHE_PROVIDER_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}hifhe${CMAKE_SHARED_LIBRARY_SUFFIX}")
        set(HIFHE_DEMO_PROVIDER OFF)
    endif()
else()
    set(HIFHE_PROVIDER_DIR "${CMAKE_BINARY_DIR}")
    set(HIFHE_DEMO_LIB hifhe_provider)
    set(HIFHE_DEMO_PROVIDER OFF)
    if(HITLS_PROVIDER AND HIFHE_BUILD_SHARED)
        set(HIFHE_DEMO_PROVIDER ON)
    endif()
endif()

# openHiTLS headers read the same macro set the libraries were built with.
set(HIFHE_MACRO_FILE "${HITLS_ROOT_DIR}/build/macros.txt")
if(EXISTS "${HIFHE_MACRO_FILE}")
    file(STRINGS "${HIFHE_MACRO_FILE}" HIFHE_HITLS_MACROS)
    add_compile_options(${HIFHE_HITLS_MACROS})
else()
    message(WARNING "[demo] ${HIFHE_MACRO_FILE} not found; building without the openHiTLS macro set")
endif()

# A demo stays on the public surface: include/ plus the openHiTLS headers,
# no private algorithm headers.
include_directories(
    ${HITLS_ROOT_DIR}/include/bsl
    ${HITLS_ROOT_DIR}/include/crypto
    ${HITLS_ROOT_DIR}/config/macro_config
    ${HITLS_ROOT_DIR}/conf/macro_config
    ${HIFHE_ROOT}/include
    ${HIFHE_PROVIDER_DIR}/include
)

set(DEMO_OUTPUT_DIR "${HIFHE_ROOT}/testcode/output/demo" CACHE PATH "Demo binary directory")
file(MAKE_DIRECTORY "${DEMO_OUTPUT_DIR}")

file(GLOB DEMO_FILES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.c")
if(NOT DEMO_FILES)
    message(FATAL_ERROR "[demo] no sources in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

foreach(DEMO_FILE ${DEMO_FILES})
    get_filename_component(DEMO_STEM ${DEMO_FILE} NAME_WE)
    if(DEMO_STEM STREQUAL "hifhe_bgv_provider_demo" AND NOT HIFHE_DEMO_PROVIDER)
        file(REMOVE "${DEMO_OUTPUT_DIR}/${DEMO_STEM}")
        continue()
    endif()
    set(DEMO_NAME "${DEMO_STEM}")
    add_executable(${DEMO_NAME} ${DEMO_FILE})
    set_target_properties(${DEMO_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${DEMO_OUTPUT_DIR}"
        BUILD_RPATH "${HITLS_ROOT_DIR}/build;${HIFHE_PROVIDER_DIR}"
    )
    target_compile_options(${DEMO_NAME} PRIVATE "$<$<NOT:$<CONFIG:Debug>>:-O2>" -g)
    if(NOT DEMO_STEM STREQUAL "hifhe_bgv_provider_demo")
        target_link_libraries(${DEMO_NAME} ${HIFHE_DEMO_LIB})
    endif()
    target_link_libraries(${DEMO_NAME}
        -Wl,--no-as-needed
        ${HITLS_CRYPTO_LIB}
        ${HITLS_BSL_LIB}
        -lpthread
        -lm
        -Wl,--as-needed
    )
    add_test(NAME ${DEMO_NAME} COMMAND ${DEMO_NAME})
    if(DEMO_STEM STREQUAL "hifhe_bgv_provider_demo")
        target_compile_definitions(${DEMO_NAME} PRIVATE HITLS_PROVIDER)
        if(NOT DEMO_STANDALONE)
            add_dependencies(${DEMO_NAME} hifhe_provider)
        endif()
        set_tests_properties(${DEMO_NAME} PROPERTIES
            ENVIRONMENT "HIFHE_PROVIDER_PATH=${HIFHE_PROVIDER_DIR};ASAN_OPTIONS=detect_leaks=1")
    else()
        set_tests_properties(${DEMO_NAME} PROPERTIES
            ENVIRONMENT "HIFHE_PROVIDER_PATH=/nonexistent;ASAN_OPTIONS=detect_leaks=1")
    endif()
    message(STATUS "[demo] ${DEMO_NAME} from ${DEMO_STEM}.c")
endforeach()
