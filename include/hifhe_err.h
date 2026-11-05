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

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HIFHE_SUCCESS = 0,
    HIFHE_NOT_SUPPORTED = 0x39000001,
    HIFHE_INVALID_ARGUMENT,
    HIFHE_MEMORY_ERROR,
    HIFHE_NULL_INPUT,
    HIFHE_BUFFER_TOO_SMALL,
    HIFHE_KEY_NOT_SET,
    HIFHE_DECODE_ERROR,
    HIFHE_PARAM_NOT_SET,
    HIFHE_PARAM_INVALID,
    HIFHE_KEY_REPEATED_SET,
    HIFHE_CT_DEGREE_MISMATCH,
    HIFHE_NO_RELIN_KEY,
    HIFHE_NO_GALOIS_KEY,
    /* No modulus left in the chain to drop. */
    HIFHE_MODSWITCH_EXHAUSTED,
    HIFHE_SERDES_FAIL,
    HIFHE_INTERNAL,
    HIFHE_BAD_STATE,
    HIFHE_CONTEXT_MISMATCH,
    HIFHE_DEPTH_EXCEEDED,
    HIFHE_LIMIT_EXCEEDED,
    HIFHE_RANDOM_ERROR,
    HIFHE_HASH_ERROR,
    HIFHE_PARAM_ID_INVALID,       /* Unknown parameter preset. */
    HIFHE_PARAM_REPEATED_SET,     /* Parameters are already configured. */
    HIFHE_INVALID_LENGTH,         /* Invalid byte length or element count. */
    HIFHE_VALUE_OUT_OF_RANGE,     /* Input value exceeds the supported range. */
    HIFHE_TEXT_TYPE_MISMATCH,     /* Wrong plaintext/ciphertext type. */
    HIFHE_OUTPUT_NOT_EMPTY,       /* Output object must initially be NULL. */
    HIFHE_ALG_MISMATCH,           /* Algorithms differ. */
    HIFHE_PARAM_MISMATCH,         /* Algorithm parameters differ. */
    HIFHE_KEY_MISMATCH,           /* Ciphertext and key origins differ. */
    HIFHE_BUFFER_OVERLAP,         /* Output buffer overlaps its length field. */
    HIFHE_VERSION_NOT_SUPPORTED  /* Unsupported serialization version. */
} HIFHE_ERROR;

/* ---- error stack ----
 * Every failure the library decides is recorded once, where the code is first
 * returned, with the file and line that decided it. The stack is per thread,
 * holds HIFHE_ERR_STACK_DEPTH entries and drops its oldest when it wraps, and
 * is never cleared on its own, so read it right after the call that failed.
 * A successful call pushes nothing. A NULL-buffer size query also pushes nothing. */
/* file and line may be NULL. The return is HIFHE_SUCCESS on an empty stack. */
int32_t HIFHE_ErrPeekError(const char **file, uint32_t *line);
int32_t HIFHE_ErrPeekLastError(const char **file, uint32_t *line);

#ifdef __cplusplus
}
#endif
#endif
