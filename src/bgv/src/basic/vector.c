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

#include <string.h>
#include <stdlib.h>
#include "hifhe_mem.h"
#include "hifhe_err_internal.h"
#include "basic/vector.h"

/* One flavour of vector. A NULL `data` zero-fills, size 0 allocates nothing.
 * Declared per flavour in vector.h. */
#define HIFHE_DEFINE_VECTOR(Name, T)                                                 \
    HIFHE_ERROR Name##_Create(Name *v, const T *data, uint32_t size)                 \
    {                                                                                \
        if (v == NULL) {                                                             \
            HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);                                    \
            return HIFHE_NULL_INPUT;                                                 \
        }                                                                            \
        v->size = 0u;                                                                \
        v->data = NULL;                                                              \
        if (size == 0u)                                                              \
            return HIFHE_SUCCESS;                                                    \
        /* The allocation below is sized in uint32 while the fill counts in       \
     * size_t, so a larger count wraps the allocation and the fill runs off   \
     * the end of it. */ \
        if (size > UINT32_MAX / (uint32_t)sizeof(T)) {                               \
            HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);                                 \
            return HIFHE_PARAM_INVALID;                                              \
        }                                                                            \
        v->data = (T *)HifheMalloc(size * (uint32_t)sizeof(T));                      \
        if (v->data == NULL) {                                                       \
            HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);                                  \
            return HIFHE_MEMORY_ERROR;                                               \
        }                                                                            \
        v->size = size;                                                              \
        if (data != NULL) {                                                          \
            memcpy(v->data, data, size * sizeof(T));                                 \
        } else {                                                                     \
            memset(v->data, 0, size * sizeof(T));                                    \
        }                                                                            \
        return HIFHE_SUCCESS;                                                        \
    }                                                                                \
                                                                                     \
    HIFHE_ERROR Name##_Destroy(Name *v)                                              \
    {                                                                                \
        if (v == NULL) {                                                             \
            HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);                                    \
            return HIFHE_NULL_INPUT;                                                 \
        }                                                                            \
        if (v->data != NULL) {                                                       \
            HifheFree(v->data);                                                      \
        }                                                                            \
        v->data = NULL;                                                              \
        v->size = 0u;                                                                \
        return HIFHE_SUCCESS;                                                        \
    }

/* Wipe the payload, then release it. */
#define HIFHE_DEFINE_VECTOR_CLEANSE(Name, T)                     \
    HIFHE_ERROR Name##_Cleanse(Name *v)                          \
    {                                                            \
        if (v == NULL) {                                         \
            HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);                \
            return HIFHE_NULL_INPUT;                             \
        }                                                        \
        if (v->data != NULL && v->size > 0u) {                   \
            HifheCleanse(v->data, v->size *(uint32_t)sizeof(T)); \
        }                                                        \
        return Name##_Destroy(v);                                \
    }

HIFHE_DEFINE_VECTOR(Uint64Vector, uint64_t)
HIFHE_DEFINE_VECTOR(Int64Vector, int64_t)
HIFHE_DEFINE_VECTOR(Uint32Vector, uint32_t)
HIFHE_DEFINE_VECTOR(Uint8Vector, uint8_t)

HIFHE_DEFINE_VECTOR_CLEANSE(Uint8Vector, uint8_t)
HIFHE_DEFINE_VECTOR_CLEANSE(Int64Vector, int64_t)
HIFHE_DEFINE_VECTOR_CLEANSE(Uint64Vector, uint64_t)

/* --- ModulusVector (= Uint64Vector) extra ops --- */
HIFHE_ERROR ModulusVector_CopyN(ModulusVector *dst, const ModulusVector *src, uint32_t size)
{
    if (dst == NULL || src == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (size > src->size) {
        size = src->size;
    }
    Uint64Vector_Destroy(dst);
    return Uint64Vector_Create(dst, src->data, size);
}
