# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

file(GLOB HIFHE_PROVIDER_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/*.c"
)

hifhe_add_object_library(hifhe_provider_objects ${HIFHE_PROVIDER_SOURCES})
target_include_directories(hifhe_provider_objects PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${HITLS_ROOT_PATH}/config/macro_config
    ${HITLS_ROOT_PATH}/conf/macro_config
)
