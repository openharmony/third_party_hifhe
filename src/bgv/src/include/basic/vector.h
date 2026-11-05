/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

/* Vector containers over BSL_SAL. `.data` is always owned by the vector. */

#ifndef HIFHE_BASIC_VECTOR_H
#define HIFHE_BASIC_VECTOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "hifhe_err.h"
#include "kernel/modulus.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t size;
    int64_t *data;
} Int64Vector;

typedef struct {
    uint32_t size;
    uint64_t *data;
} Uint64Vector;

typedef struct {
    uint32_t size;
    uint32_t *data;
} Uint32Vector;

typedef struct {
    uint32_t size;
    uint8_t *data;
} Uint8Vector;

typedef struct {
    uint64_t first;
    uint64_t second;
} Uint64Pair;

/* ModulusVector is the canonical shape for RNS bases and twiddle tables. */
typedef Uint64Vector ModulusVector;
typedef Uint64Vector Message;
typedef Int64Vector MessageInt;

/* Create / Destroy, required for every container. */
HIFHE_ERROR Uint64Vector_Create(Uint64Vector *v, const uint64_t *data, uint32_t size);
HIFHE_ERROR Uint64Vector_Destroy(Uint64Vector *v);

HIFHE_ERROR Int64Vector_Create(Int64Vector *v, const int64_t *data, uint32_t size);
HIFHE_ERROR Int64Vector_Destroy(Int64Vector *v);

HIFHE_ERROR Uint32Vector_Create(Uint32Vector *v, const uint32_t *data, uint32_t size);
HIFHE_ERROR Uint32Vector_Destroy(Uint32Vector *v);

/* Byte buffer, used for sampler randomness pools. */
HIFHE_ERROR Uint8Vector_Create(Uint8Vector *v, const uint8_t *data, uint32_t size);
HIFHE_ERROR Uint8Vector_Destroy(Uint8Vector *v);
/* Wipe before releasing. */
HIFHE_ERROR Uint8Vector_Cleanse(Uint8Vector *v);
HIFHE_ERROR Int64Vector_Cleanse(Int64Vector *v);
HIFHE_ERROR Uint64Vector_Cleanse(Uint64Vector *v);

/* ModulusVector extras. CopyN takes a pre-known slice length. */
HIFHE_ERROR ModulusVector_CopyN(ModulusVector *dst, const ModulusVector *src, uint32_t size);
static inline HIFHE_ERROR ModulusVector_Copy(ModulusVector *dst, const ModulusVector *src)
{
    return ModulusVector_CopyN(dst, src, src->size);
}

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_BASIC_VECTOR_H */
