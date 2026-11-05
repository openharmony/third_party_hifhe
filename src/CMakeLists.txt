# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

file(GLOB HIFHE_COMMON_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/common/*.c"
)

hifhe_add_object_library(hifhe_common_objects ${HIFHE_COMMON_SOURCES})

if(HITLS_PROVIDER)
    add_subdirectory(provider)
endif()
if(HIFHE_BGV)
    add_subdirectory(bgv)
endif()
hifhe_add_object_library(hifhe_api_objects api/hifhe_api.c)
target_include_directories(hifhe_api_objects PRIVATE
    ${PROJECT_SOURCE_DIR}/src/common
    ${HITLS_ROOT_PATH}/config/macro_config
    ${HITLS_ROOT_PATH}/crypto/include
    ${HITLS_ROOT_PATH}/bsl/sal/include)
target_compile_definitions(hifhe_api_objects PRIVATE HITLS_CRYPTO_EAL
    HITLS_BSL_SAL HITLS_BSL_SAL_MEM
    HITLS_NO_CONFIG_CHECK)
