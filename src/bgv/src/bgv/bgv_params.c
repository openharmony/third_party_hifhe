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
#include "hifhe_err_internal.h"
#include "bgv/bgv.h"
#include "rlwe/rlwe.h"

HIFHE_ERROR BGV_BGVParameter_Create(BGVParameter *out, Modulus plainMod, uint64_t correctionFactor,
                                    uint32_t defaultCiphertextSize, uint32_t polyDegree, const ModulusVector *cipherMod)
{
    if (out == NULL || cipherMod == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    memset(out, 0, sizeof(*out));
    int32_t r = RLWE_RlweParameter_Create(&out->rlweParameter, defaultCiphertextSize, polyDegree, cipherMod);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    out->plainMod = plainMod;
    out->correctionFactor = correctionFactor;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_BGVParameter_Destroy(BGVParameter *self)
{
    if (self == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    RLWE_RlweParameter_Destroy(&self->rlweParameter);
    self->plainMod = 0u;
    self->correctionFactor = 0u;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_BGVParameter_Copy(BGVParameter *dst, const BGVParameter *src)
{
    if (dst == NULL || src == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    BGV_BGVParameter_Destroy(dst);
    int32_t r = RLWE_RlweParameter_Copy(&dst->rlweParameter, &src->rlweParameter);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    dst->plainMod = src->plainMod;
    dst->correctionFactor = src->correctionFactor;
    return HIFHE_SUCCESS;
}
