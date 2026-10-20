# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

project(GEN_TEST)

set(GEN_TESTCASE "gen_testcase")
set(HITLS_SRC ${PROJECT_SOURCE_DIR}/../../..)
set(EXECUTABLE_OUTPUT_PATH ${HITLS_SRC}/testcode/output)

file(GLOB GEN_SOURCE_SRC CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/*.c"
)

include_directories(
    ${HITLS_SRC}/testcode/framework/include
    ${HITLS_SRC}/testcode/framework/crypto
    ${HITLS_ROOT_DIR}/config/macro_config
    ${HITLS_ROOT_DIR}/conf/macro_config
    ${HITLS_ROOT_DIR}/crypto/include
    ${HITLS_ROOT_DIR}/include/crypto
    ${HITLS_ROOT_DIR}/include/bsl
    ${HITLS_ROOT_DIR}/bsl/err/include
)

add_executable(${GEN_TESTCASE} ${GEN_SOURCE_SRC})

if(PRINT_TO_TERMINAL)
    target_compile_options(${GEN_TESTCASE} PRIVATE -DPRINT_TO_TERMINAL)
endif()
