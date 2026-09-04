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

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h")
install(FILES "${CMAKE_BINARY_DIR}/include/hifhe_config.h"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
if(HIFHE_CKKS)
    install(FILES src/ckks/include/crypt_ckks.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()

message(STATUS "[HiFHE] CKKS: ${HIFHE_CKKS}")
message(STATUS "[HiFHE] shared: ${HIFHE_BUILD_SHARED}")
message(STATUS "[HiFHE] static: ${HIFHE_BUILD_STATIC}")
