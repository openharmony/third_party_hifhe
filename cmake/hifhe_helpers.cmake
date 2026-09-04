# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

set_property(GLOBAL PROPERTY HIFHE_OBJECT_TARGETS "")

function(hifhe_add_object_library TARGET)
    add_library(${TARGET} OBJECT ${ARGN})
    set_target_properties(${TARGET} PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_link_libraries(${TARGET} PRIVATE
        _hifhe_compile_options
        _hifhe_public_headers
    )
    set_property(GLOBAL APPEND PROPERTY HIFHE_OBJECT_TARGETS ${TARGET})

    foreach(SOURCE_FILE ${ARGN})
        get_filename_component(SOURCE_NAME ${SOURCE_FILE} NAME)
        set_source_files_properties(${SOURCE_FILE} PROPERTIES
            COMPILE_DEFINITIONS "__FILENAME__=\"${SOURCE_NAME}\""
        )
    endforeach()
endfunction()
