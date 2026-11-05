# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

set(HIFHE_CONFIG_DIR "${CMAKE_BINARY_DIR}/include")
file(MAKE_DIRECTORY "${HIFHE_CONFIG_DIR}")
set(HIFHE_ENABLE_BGV ${HIFHE_BGV})
configure_file(
    "${CMAKE_CURRENT_LIST_DIR}/hifhe_config.h.in"
    "${HIFHE_CONFIG_DIR}/hifhe_config.h"
    @ONLY
)
