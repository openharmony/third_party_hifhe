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
project(HiFHE C)

include(GNUInstallDirs)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(hifhe_options)
include(hifhe_dependencies)
include(hifhe_generate_config)
include(hifhe_build_options)
include(hifhe_helpers)

add_subdirectory(src)
include(hifhe_build_targets)

install(FILES include/hifhe.h include/hifhe_types.h include/hifhe_err.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

message(STATUS "[HiFHE] BGV: ${HIFHE_BGV}")
message(STATUS "[HiFHE] Provider: ${HITLS_PROVIDER}")
message(STATUS "[HiFHE] shared: ${HIFHE_BUILD_SHARED}")
message(STATUS "[HiFHE] static: ${HIFHE_BUILD_STATIC}")

if(HIFHE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(testcode)
endif()
if(BUILD_BENCHMARK)
    add_subdirectory(testcode/benchmark)
endif()
