# Copyright (c) 2026 openHiTLS. All Rights Reserved.
# HiFHE is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

get_property(HIFHE_OBJECT_TARGETS GLOBAL PROPERTY HIFHE_OBJECT_TARGETS)
if(NOT HIFHE_OBJECT_TARGETS)
    message(FATAL_ERROR "No HiFHE object targets configured")
endif()

set(HIFHE_OBJECTS)
foreach(OBJECT_TARGET ${HIFHE_OBJECT_TARGETS})
    list(APPEND HIFHE_OBJECTS $<TARGET_OBJECTS:${OBJECT_TARGET}>)
endforeach()

function(hifhe_add_provider TARGET LIB_TYPE)
    add_library(${TARGET} ${LIB_TYPE} ${HIFHE_OBJECTS})
    set_target_properties(${TARGET} PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
        OUTPUT_NAME hifhe_provider
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )
    target_link_libraries(${TARGET}
        PUBLIC _hifhe_public_headers
        PRIVATE _hifhe_compile_options ${HITLS_BSL_LIB} ${HITLS_CRYPTO_LIB}
    )
    if(HIFHE_CKKS)
        target_link_libraries(${TARGET} PRIVATE m)
    endif()
endfunction()

set(HIFHE_INSTALL_TARGETS)
if(HIFHE_BUILD_SHARED)
    hifhe_add_provider(hifhe_provider SHARED)
    list(APPEND HIFHE_INSTALL_TARGETS hifhe_provider)
endif()
if(HIFHE_BUILD_STATIC)
    if(HIFHE_BUILD_SHARED)
        set(HIFHE_STATIC_TARGET hifhe_provider_static)
    else()
        set(HIFHE_STATIC_TARGET hifhe_provider)
    endif()
    hifhe_add_provider(${HIFHE_STATIC_TARGET} STATIC)
    list(APPEND HIFHE_INSTALL_TARGETS ${HIFHE_STATIC_TARGET})
endif()

install(TARGETS ${HIFHE_INSTALL_TARGETS}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
