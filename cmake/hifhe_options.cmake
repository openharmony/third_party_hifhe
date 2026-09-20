# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

set(HITLS_ROOT_PATH "${PROJECT_SOURCE_DIR}/platform/openhitls" CACHE PATH
    "openHiTLS source directory")
set(HITLS_LIB_DIR "${HITLS_ROOT_PATH}/build" CACHE PATH
    "openHiTLS library directory")

option(HIFHE_BUILD_SHARED "Build the shared provider library" ON)
option(HIFHE_BUILD_STATIC "Build the static provider library" ON)
option(HIFHE_CKKS "Build CKKS" ON)
option(HIFHE_BGV "Build BGV" ON)
option(HIFHE_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(HIFHE_ENABLE_GCOV "Enable coverage" OFF)

if(NOT HIFHE_BUILD_SHARED AND NOT HIFHE_BUILD_STATIC)
    message(FATAL_ERROR "At least one provider library type must be enabled")
endif()
