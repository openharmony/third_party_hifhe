# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

file(GLOB TEST_SOURCE CONFIGURE_DEPENDS
    "${HIFHE_ROOT}/testcode/framework/gen_test/*.c"
    "${HIFHE_ROOT}/testcode/framework/crypto/*.c"
)
list(FILTER TEST_SOURCE EXCLUDE REGEX "/main\\.c$")

add_library(TESTCASE_PRE STATIC ${TEST_SOURCE})
target_include_directories(TESTCASE_PRE PRIVATE
    ${HIFHE_ROOT}/testcode/framework/include
    ${HIFHE_ROOT}/testcode/framework/crypto
    ${HITLS_ROOT_DIR}/config/macro_config
    ${HITLS_ROOT_DIR}/conf/macro_config
    ${HITLS_ROOT_DIR}/crypto/include
    ${HITLS_ROOT_DIR}/crypto/eal/src
    ${HITLS_ROOT_DIR}/include/crypto
    ${HITLS_ROOT_DIR}/include/bsl
    ${HITLS_ROOT_DIR}/bsl/err/include
)

add_library(SHARED_COMPILE_DEFS INTERFACE)
target_include_directories(SHARED_COMPILE_DEFS INTERFACE
    ${HIFHE_ROOT}/include ${HIFHE_CONFIG_DIR})
target_compile_definitions(SHARED_COMPILE_DEFS INTERFACE
    HITLS_BSL_ERR
    HITLS_BSL_SAL
    HITLS_BSL_SAL_MEM
    HITLS_CRYPTO_DRBG
    HITLS_CRYPTO_DRBG_HASH
    HITLS_CRYPTO_EAL
    HITLS_CRYPTO_MD
    HITLS_CRYPTO_PKEY
    HITLS_CRYPTO_PKEY_CRYPT
    HITLS_CRYPTO_SHA256
    HITLS_NO_CONFIG_CHECK
    PRINT_TO_TERMINAL
)
if(HITLS_PROVIDER)
    target_compile_definitions(SHARED_COMPILE_DEFS INTERFACE HITLS_PROVIDER)
endif()
target_link_libraries(TESTCASE_PRE PRIVATE SHARED_COMPILE_DEFS)

file(MAKE_DIRECTORY "${HIFHE_ROOT}/testcode/output")
file(MAKE_DIRECTORY "${HIFHE_ROOT}/testcode/output/log")
if(GEN_TEST_FILES)
    separate_arguments(TEST_FILES UNIX_COMMAND "${GEN_TEST_FILES}")
else()
    file(GLOB_RECURSE TEST_DATA CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.data")
    foreach(DATA_FILE ${TEST_DATA})
        string(REGEX REPLACE "\\.data$" "" TEST_SUITE "${DATA_FILE}")
        list(APPEND TEST_FILES "${TEST_SUITE}")
    endforeach()
endif()

foreach(TEST_SUITE ${TEST_FILES})
    get_filename_component(SUITE_NAME ${TEST_SUITE} NAME)
    set(PUBLIC_SUITE OFF)
    if(SUITE_NAME MATCHES "_(api|provider)$" OR
       (SUITE_NAME STREQUAL "test_suite_sdv_hifhe_bgv_kat" AND NOT HITLS_PROVIDER))
        set(PUBLIC_SUITE ON)
    endif()
    if((SUITE_NAME MATCHES "_bgv" AND NOT HIFHE_BGV) OR
       (SUITE_NAME MATCHES "_bgv" AND NOT PUBLIC_SUITE AND NOT HITLS_PROVIDER) OR
       (SUITE_NAME MATCHES "_provider$" AND (NOT HITLS_PROVIDER OR NOT HIFHE_BUILD_SHARED)))
        message(STATUS "skip ${SUITE_NAME}: required feature disabled")
        # Drop any binary an earlier, wider build left behind.
        file(REMOVE "${HIFHE_ROOT}/testcode/output/${SUITE_NAME}")
        continue()
    endif()
    file(TOUCH "${HIFHE_ROOT}/testcode/output/${SUITE_NAME}.c")
    add_custom_target(${SUITE_NAME}_generate
        COMMAND ${HIFHE_ROOT}/testcode/output/gen_testcase ${TEST_SUITE}
        DEPENDS gen_testcase
        WORKING_DIRECTORY "${HIFHE_ROOT}/testcode/output"
    )

    add_executable(${SUITE_NAME} "${HIFHE_ROOT}/testcode/output/${SUITE_NAME}.c")
    add_dependencies(${SUITE_NAME} ${SUITE_NAME}_generate)
    set_target_properties(${SUITE_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${HIFHE_ROOT}/testcode/output"
    )
    target_include_directories(${SUITE_NAME} PRIVATE
        ${HIFHE_ROOT}/include
        ${HIFHE_ROOT}/testcode/framework/include
        ${HIFHE_ROOT}/testcode/framework/crypto
        ${HITLS_ROOT_DIR}/config/macro_config
        ${HITLS_ROOT_DIR}/conf/macro_config
        ${HITLS_ROOT_DIR}/crypto/include
        ${HITLS_ROOT_DIR}/include/crypto
        ${HITLS_ROOT_DIR}/include/bsl
    )
    if(PUBLIC_SUITE)
        target_link_libraries(${SUITE_NAME} PRIVATE hifhe_provider)
    else()
        target_sources(${SUITE_NAME} PRIVATE ${HIFHE_OBJECTS})
        target_include_directories(${SUITE_NAME} PRIVATE
            ${HIFHE_ROOT}/src/common
            ${HIFHE_ROOT}/src/bgv/include
            ${HIFHE_ROOT}/src/bgv/src
            ${HIFHE_ROOT}/src/bgv/src/include)
    endif()
    target_link_libraries(${SUITE_NAME} PRIVATE
        TESTCASE_PRE SHARED_COMPILE_DEFS
        ${HITLS_CRYPTO_LIB} ${HITLS_BSL_LIB}
        Threads::Threads m ${CMAKE_DL_LIBS}
    )
    if(NOT APPLE)
        target_link_options(${SUITE_NAME} PRIVATE "$<$<NOT:$<CONFIG:Debug>>:LINKER:-z,noexecstack>")
    endif()
    add_test(NAME ${SUITE_NAME} COMMAND ${SUITE_NAME} NO_DETAIL)
    set_tests_properties(${SUITE_NAME} PROPERTIES
        WORKING_DIRECTORY "${HIFHE_ROOT}/testcode/output"
        LABELS sdv
        ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}:${HITLS_LIB_DIR};HIFHE_PROVIDER_PATH=${CMAKE_BINARY_DIR};ASAN_OPTIONS=detect_leaks=1")
endforeach()
