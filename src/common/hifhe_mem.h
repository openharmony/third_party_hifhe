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
/*
 * The allocator every HiFHE module goes through. Defaults to malloc and free,
 * and an application can take it over with HIFHE_SetMemFuncs.
 */

#ifndef HIFHE_MEM_H
#define HIFHE_MEM_H

#include <stdint.h>
#include "hifhe.h"

#ifdef __cplusplus
extern "C" {
#endif

/* NULL on a zero length or on failure. */
void *HifheMalloc(uint32_t len);

/* Zeroed. NULL on a zero count or length, on num * len overflow, or on failure. */
void *HifheCalloc(uint32_t num, uint32_t len);

/* A NULL pointer is accepted and ignored. */
void HifheFree(void *ptr);

/* Overwrites len bytes with zero. Not elided when the buffer is then freed. */
void HifheCleanse(void *ptr, uint32_t len);

#ifdef __cplusplus
}
#endif
#endif
