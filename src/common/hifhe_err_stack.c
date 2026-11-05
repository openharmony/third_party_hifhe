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

#include "hifhe_err_internal.h"

#include <stddef.h>

typedef struct {
    int32_t error;
    const char *file;
    uint32_t line;
} ErrEntry;

/* One stack per thread, in thread-local storage, so recording a failure never
 * allocates, never fails and never needs a lock: no two threads can reach the
 * same entry. The t_ prefix is the reminder that none of this is shared. */
static _Thread_local ErrEntry t_stack[HIFHE_ERR_STACK_DEPTH];
static _Thread_local uint32_t t_depth;
static _Thread_local uint32_t t_mark;

void HIFHE_ErrPushError(int32_t error, const char *file, uint32_t line)
{
    if (error == HIFHE_SUCCESS) {
        return;
    }
    if (t_depth == HIFHE_ERR_STACK_DEPTH) {
        /* Drop the oldest, so a stack nobody cleared cannot hide what is
         * failing now. */
        for (uint32_t i = 1; i < HIFHE_ERR_STACK_DEPTH; ++i) {
            t_stack[i - 1] = t_stack[i];
        }
        t_depth--;
        if (t_mark > 0u) {
            t_mark--;
        }
    }
    t_stack[t_depth].error = error;
    t_stack[t_depth].file = file;
    t_stack[t_depth].line = line;
    t_depth++;
}

int32_t HIFHE_ErrPeekError(const char **file, uint32_t *line)
{
    if (t_depth == 0u) {
        return HIFHE_SUCCESS;
    }
    if (file != NULL) {
        *file = t_stack[0].file;
    }
    if (line != NULL) {
        *line = t_stack[0].line;
    }
    return t_stack[0].error;
}

int32_t HIFHE_ErrPeekLastError(const char **file, uint32_t *line)
{
    if (t_depth == 0u) {
        return HIFHE_SUCCESS;
    }
    const ErrEntry *e = &t_stack[t_depth - 1u];
    if (file != NULL) {
        *file = e->file;
    }
    if (line != NULL) {
        *line = e->line;
    }
    return e->error;
}

uint32_t HIFHE_ErrDepth(void)
{
    return t_depth;
}

void HIFHE_ErrClearError(void)
{
    t_depth = 0u;
    t_mark = 0u;
}

void HIFHE_ErrSetMark(void)
{
    t_mark = t_depth;
}

void HIFHE_ErrPopToMark(void)
{
    if (t_mark <= t_depth) {
        t_depth = t_mark;
    }
    t_mark = 0u;
}
