/*
 * Copyright (c) 2026 openHiTLS. All Rights Reserved.
 * HiFHE is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef HIFHE_ERR_H
#define HIFHE_ERR_H

typedef enum {
    HIFHE_SUCCESS = 0,
    HIFHE_NOT_SUPPORTED = 0x39000001,
    HIFHE_INVALID_ARGUMENT,
    HIFHE_MEMORY_ERROR,
    HIFHE_NULL_INPUT,
    HIFHE_BUFFER_TOO_SMALL,
    HIFHE_KEY_NOT_SET,
    HIFHE_DECODE_ERROR
} HIFHE_ERROR;

#endif
