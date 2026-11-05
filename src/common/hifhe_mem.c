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

#include "hifhe_mem.h"

#include <stdlib.h>
#include <string.h>
#include "hifhe_err.h"
#include "hifhe_err_internal.h"

static void *DefaultMalloc(uint32_t len)
{
    return malloc((size_t)len);
}

static void DefaultFree(void *ptr)
{
    free(ptr);
}

static HIFHE_MallocFunc g_malloc = DefaultMalloc;
static HIFHE_FreeFunc g_free = DefaultFree;

int32_t HIFHE_SetMemFuncs(HIFHE_MallocFunc mallocFunc, HIFHE_FreeFunc freeFunc)
{
    if ((mallocFunc == NULL) != (freeFunc == NULL)) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    g_malloc = (mallocFunc != NULL) ? mallocFunc : DefaultMalloc;
    g_free = (freeFunc != NULL) ? freeFunc : DefaultFree;
    return HIFHE_SUCCESS;
}

void *HifheMalloc(uint32_t len)
{
    if (len == 0u) {
        return NULL;
    }
    return g_malloc(len);
}

void *HifheCalloc(uint32_t num, uint32_t len)
{
    if (num == 0u || len == 0u || num > UINT32_MAX / len) {
        return NULL;
    }
    uint32_t total = num * len;
    void *ptr = g_malloc(total);
    if (ptr == NULL) {
        return NULL;
    }
    (void)memset(ptr, 0, total);
    return ptr;
}

void HifheFree(void *ptr)
{
    if (ptr == NULL) {
        return;
    }
    g_free(ptr);
}

void HifheCleanse(void *ptr, uint32_t len)
{
    if (ptr == NULL || len == 0u) {
        return;
    }
    (void)memset(ptr, 0, len);
    /* The barrier is what keeps the store from being dropped as dead when the
     * buffer is freed or goes out of scope right after. */
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#else
    static void *volatile sink;
    sink = ptr;
#endif
}
