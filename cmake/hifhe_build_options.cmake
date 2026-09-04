# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

add_library(_hifhe_compile_options INTERFACE)
target_compile_features(_hifhe_compile_options INTERFACE c_std_11)
target_compile_options(_hifhe_compile_options INTERFACE -Wall -Wextra -Werror)

if(HIFHE_ENABLE_ASAN)
    target_compile_options(_hifhe_compile_options INTERFACE
        -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(_hifhe_compile_options INTERFACE -fsanitize=address)
endif()
if(HIFHE_ENABLE_GCOV)
    target_compile_options(_hifhe_compile_options INTERFACE --coverage)
    target_link_options(_hifhe_compile_options INTERFACE --coverage)
endif()

add_library(_hifhe_public_headers INTERFACE)
target_include_directories(_hifhe_public_headers INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${HIFHE_CONFIG_DIR}>
    $<BUILD_INTERFACE:${HITLS_ROOT_PATH}/include/bsl>
    $<BUILD_INTERFACE:${HITLS_ROOT_PATH}/include/crypto>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
if(HIFHE_CKKS)
    target_include_directories(_hifhe_public_headers INTERFACE
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/ckks/include>
    )
endif()
