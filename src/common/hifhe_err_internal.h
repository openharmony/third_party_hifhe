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
 * How the library records a failure. One push at the origin, where a literal
 * error code is first returned, and none at the sites that pass one along.
 */

#ifndef HIFHE_ERR_INTERNAL_H
#define HIFHE_ERR_INTERNAL_H

#include <stdint.h>
#include "hifhe_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HIFHE_ERR_STACK_DEPTH 20u

/* Not in the public surface yet, so not in cmake/hifhe.exports either. */
void HIFHE_ErrPushError(int32_t error, const char *file, uint32_t line);
uint32_t HIFHE_ErrDepth(void);
void HIFHE_ErrClearError(void);
void HIFHE_ErrSetMark(void);
void HIFHE_ErrPopToMark(void);

/* The code cannot be HIFHE_SUCCESS. */
#define HIFHE_ERR_PUSH_ERROR(e) HIFHE_ErrPushError((int32_t)(e), __FILENAME__, (uint32_t)__LINE__)

/* Brackets a call whose failure is an answer rather than a fault. */
#define HIFHE_ERR_SET_MARK()    HIFHE_ErrSetMark()
#define HIFHE_ERR_POP_TO_MARK() HIFHE_ErrPopToMark()

#ifdef __cplusplus
}
#endif
#endif
