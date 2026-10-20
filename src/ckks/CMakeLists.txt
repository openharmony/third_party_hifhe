# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

file(GLOB HIFHE_CKKS_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
)

hifhe_add_object_library(hifhe_ckks_objects ${HIFHE_CKKS_SOURCES})
target_include_directories(hifhe_ckks_objects PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${HITLS_ROOT_PATH}/config/macro_config
    ${HITLS_ROOT_PATH}/conf/macro_config
    ${HITLS_ROOT_PATH}/bsl/err/include
    ${HITLS_ROOT_PATH}/bsl/include
    ${HITLS_ROOT_PATH}/bsl/sal/include
    ${HITLS_ROOT_PATH}/crypto/bn/include
    ${HITLS_ROOT_PATH}/crypto/include
)
target_compile_definitions(hifhe_ckks_objects PRIVATE
    HITLS_BSL_ERR
    HITLS_BSL_PARAMS
    HITLS_BSL_SAL
    HITLS_BSL_SAL_MEM
    HITLS_CRYPTO_BN
    HITLS_CRYPTO_BN_BASIC
    HITLS_CRYPTO_BN_RAND
    HITLS_CRYPTO_BN_STR_CONV
    HITLS_CRYPTO_CKKS
    HITLS_CRYPTO_EAL
    HITLS_CRYPTO_PKEY
    HITLS_CRYPTO_PKEY_CRYPT
    HITLS_CRYPTO_PROVIDER
    HITLS_NO_CONFIG_CHECK
    HITLS_SIXTY_FOUR_BITS
)
