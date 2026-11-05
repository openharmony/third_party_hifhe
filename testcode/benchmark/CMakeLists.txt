# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

add_executable(hifhe_benchmark benchmark.c bgv_bench.c ${HIFHE_OBJECTS})
target_include_directories(hifhe_benchmark PRIVATE
    ${PROJECT_SOURCE_DIR}/src/bgv/include
    ${PROJECT_SOURCE_DIR}/src/bgv/src
    ${PROJECT_SOURCE_DIR}/src/bgv/src/include
    ${HITLS_ROOT_PATH}/config/macro_config
    ${HITLS_ROOT_PATH}/crypto/include)
target_compile_options(hifhe_benchmark PRIVATE -g
    -include "${PROJECT_SOURCE_DIR}/src/common/bgv_adapter_types.h")
target_link_libraries(hifhe_benchmark PRIVATE _hifhe_public_headers _hifhe_compile_options
    ${HITLS_CRYPTO_LIB} ${HITLS_BSL_LIB} pthread m)
set_target_properties(hifhe_benchmark PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/testcode/output"
    BUILD_RPATH "${HITLS_LIB_DIR}")
