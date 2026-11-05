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
#include "hifhe_mem.h"
#include "hifhe_err_internal.h"
#include "rlwe/rlwe.h"
#include "rlwe/rlwe_context.h"
#include "rlwe/crt_ops.h"
#include "rlwe/rns_ops.h"
#include "kernel/modulus.h"

/* ---------------- CrtPolyConfig ---------------- */

HIFHE_ERROR RLWE_CrtPolyConfig_Copy(CrtPolyConfig *dst, const CrtPolyConfig *src)
{
    if (dst == NULL || src == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    int32_t r = ModulusVector_Copy(&dst->rnsbase, &src->rnsbase);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    dst->dtype = src->dtype;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR RLWE_CrtPolyConfig_Destroy(CrtPolyConfig *self)
{
    if (self == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    Uint64Vector_Destroy(&self->rnsbase);
    self->dtype = HIFHE_POLY;
    return HIFHE_SUCCESS;
}

/* ---------------- CrtPoly lifecycle ---------------- */

HIFHE_ERROR RLWE_CrtPoly_Create(CrtPoly *out, const CrtPolyConfig *cfg, RlweContext *ctx)
{
    if (out == NULL || cfg == NULL || ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    memset(out, 0, sizeof(*out));
    int32_t r = RLWE_CrtPolyConfig_Copy(&out->config, cfg);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    out->context = ctx;
    out->dataSize = RLWE_CrtPoly_CalDataSize(cfg, ctx);
    out->data = (uint64_t *)HifheCalloc(out->dataSize, (uint32_t)sizeof(uint64_t));
    if (out->data == NULL) {
        RLWE_CrtPolyConfig_Destroy(&out->config);
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    out->ownsData = 1u;
    out->ownsConfig = 1u;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR RLWE_CrtPoly_CreateFromExist(CrtPoly *out, uint64_t *data, uint32_t size, const CrtPolyConfig *cfg,
                                         RlweContext *ctx)
{
    if (out == NULL || cfg == NULL || ctx == NULL || data == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    memset(out, 0, sizeof(*out));
    int32_t r = RLWE_CrtPolyConfig_Copy(&out->config, cfg);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    out->context = ctx;
    out->dataSize = RLWE_CrtPoly_CalDataSize(cfg, ctx);
    if (size < out->dataSize) {
        RLWE_CrtPolyConfig_Destroy(&out->config);
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    out->data = data;
    out->ownsData = 0u;
    out->ownsConfig = 1u;
    return HIFHE_SUCCESS;
}

/* Full replacement; storage comes from RLWE_CrtPoly_Create. */
HIFHE_ERROR RLWE_CrtPoly_Copy(CrtPoly *dst, const CrtPoly *src)
{
    if (dst == NULL || src == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (src->context == NULL || src->data == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }

    CrtPoly fresh;
    int32_t r = RLWE_CrtPoly_Create(&fresh, &src->config, src->context);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    if (fresh.dataSize != src->dataSize) {
        RLWE_CrtPoly_Destroy(&fresh);
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    memcpy(fresh.data, src->data, src->dataSize * sizeof(uint64_t));

    RLWE_CrtPoly_Destroy(dst);
    *dst = fresh;
    return HIFHE_SUCCESS;
}

/* Wipes owned coefficients before releasing them. A view owns nothing and
 * leaves the underlying buffer alone. */
HIFHE_ERROR RLWE_CrtPoly_Destroy(CrtPoly *self)
{
    if (self == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (self->ownsData && self->data != NULL) {
        if (self->dataSize > 0u) {
            HifheCleanse(self->data, self->dataSize * (uint32_t)sizeof(uint64_t));
        }
        HifheFree(self->data);
    }
    if (self->ownsConfig) {
        RLWE_CrtPolyConfig_Destroy(&self->config);
    } else {
        memset(&self->config, 0, sizeof(self->config));
    }
    self->data = NULL;
    self->dataSize = 0u;
    self->ownsData = 0u;
    self->ownsConfig = 0u;
    return HIFHE_SUCCESS;
}

/* View onto the i-th RnsPoly slice. `out` does not own storage. */
HIFHE_ERROR RLWE_CrtPoly_GetRnsPolyAt(RnsPoly *out, uint32_t index, const CrtPoly *self)
{
    if (out == NULL || self == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (index >= self->config.rnsbase.size) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    uint32_t N = self->context->parameter->polyDegree;
    memset(out, 0, sizeof(*out));
    out->config.modulus = self->config.rnsbase.data[index];
    out->config.dtype = self->config.dtype;
    out->context = self->context;
    out->dataSize = N;
    out->data = self->data + (index * N);
    out->ownsData = 0u;
    return HIFHE_SUCCESS;
}

/* ---------------- CRT-level arithmetic ---------------- */

/* The loop alone. An accumulating op keeps whatever form `out` already
 * carries, so this does not touch it. */
static HIFHE_ERROR ForEachSliceRaw(CrtPoly *out, const CrtPoly *a, const CrtPoly *b,
                                   HIFHE_ERROR (*op)(RnsPoly *, const RnsPoly *, const RnsPoly *))
{
    if (out == NULL || a == NULL || b == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (a->config.rnsbase.size != b->config.rnsbase.size) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    if (a->config.rnsbase.size != out->config.rnsbase.size) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    for (uint32_t i = 0; i < a->config.rnsbase.size; ++i) {
        RnsPoly ap, bp, op_;
        int32_t r;
        r = RLWE_CrtPoly_GetRnsPolyAt(&ap, i, a);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = RLWE_CrtPoly_GetRnsPolyAt(&bp, i, b);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = RLWE_CrtPoly_GetRnsPolyAt(&op_, i, out);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = op(&op_, &ap, &bp);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
    }
    return HIFHE_SUCCESS;
}

/* The same walk, after which `out` takes a's form. */
static HIFHE_ERROR ForEachSlice(CrtPoly *out, const CrtPoly *a, const CrtPoly *b,
                                HIFHE_ERROR (*op)(RnsPoly *, const RnsPoly *, const RnsPoly *))
{
    HIFHE_ERROR r = ForEachSliceRaw(out, a, b, op);
    if (r == HIFHE_SUCCESS) {
        out->config.dtype = a->config.dtype;
    }
    return r;
}

HIFHE_ERROR RLWE_CrtPoly_Add(CrtPoly *out, const CrtPoly *a, const CrtPoly *b)
{
    return ForEachSlice(out, a, b, RLWE_RnsPoly_Add);
}

HIFHE_ERROR RLWE_CrtPoly_Sub(CrtPoly *out, const CrtPoly *a, const CrtPoly *b)
{
    return ForEachSlice(out, a, b, RLWE_RnsPoly_Sub);
}

HIFHE_ERROR RLWE_CrtPoly_MulDot(CrtPoly *out, const CrtPoly *a, const CrtPoly *b)
{
    return ForEachSlice(out, a, b, RLWE_RnsPoly_MulDot);
}

static HIFHE_ERROR ForEachSliceUnary(CrtPoly *out, const CrtPoly *a, HIFHE_ERROR (*op)(RnsPoly *, const RnsPoly *))
{
    if (out == NULL || a == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (a->config.rnsbase.size != out->config.rnsbase.size) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    for (uint32_t i = 0; i < a->config.rnsbase.size; ++i) {
        RnsPoly ap, op_;
        int32_t r;
        r = RLWE_CrtPoly_GetRnsPolyAt(&ap, i, a);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = RLWE_CrtPoly_GetRnsPolyAt(&op_, i, out);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = op(&op_, &ap);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
    }
    out->config.dtype = a->config.dtype;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR RLWE_CrtPoly_Neg(CrtPoly *out, const CrtPoly *a)
{
    return ForEachSliceUnary(out, a, RLWE_RnsPoly_Neg);
}

HIFHE_ERROR RLWE_CrtPoly_MulDotAcc(CrtPoly *out, const CrtPoly *a, const CrtPoly *b)
{
    return ForEachSliceRaw(out, a, b, RLWE_RnsPoly_MulDotAcc);
}

HIFHE_ERROR RLWE_CrtPoly_MulScalar(CrtPoly *out, const CrtPoly *a, uint64_t x)
{
    if (out == NULL || a == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (a->config.rnsbase.size != out->config.rnsbase.size) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    for (uint32_t i = 0; i < a->config.rnsbase.size; ++i) {
        RnsPoly ap, op_;
        int32_t r;
        r = RLWE_CrtPoly_GetRnsPolyAt(&ap, i, a);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = RLWE_CrtPoly_GetRnsPolyAt(&op_, i, out);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = RLWE_RnsPoly_MulScalar(&op_, &ap, x);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
    }
    out->config.dtype = a->config.dtype;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR RLWE_CrtPoly_MulScalarPerLimb(CrtPoly *out, const CrtPoly *a, const uint64_t *xPerLimb)
{
    if (out == NULL || a == NULL || xPerLimb == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (a->config.rnsbase.size != out->config.rnsbase.size) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    for (uint32_t i = 0; i < a->config.rnsbase.size; ++i) {
        RnsPoly ap, op_;
        int32_t r;
        r = RLWE_CrtPoly_GetRnsPolyAt(&ap, i, a);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = RLWE_CrtPoly_GetRnsPolyAt(&op_, i, out);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = RLWE_RnsPoly_MulScalar(&op_, &ap, xPerLimb[i]);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
    }
    out->config.dtype = a->config.dtype;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR RLWE_CrtPoly_Assign(CrtPoly *dst, const CrtPoly *src)
{
    if (dst == NULL || src == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (dst->dataSize != src->dataSize) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    if (dst->data != src->data) {
        memcpy(dst->data, src->data, src->dataSize * sizeof(uint64_t));
    }
    dst->config.dtype = src->config.dtype;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR RLWE_CrtPoly_SetSigned(CrtPoly *self, const int64_t *v)
{
    if (self == NULL || v == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    for (uint32_t i = 0; i < self->config.rnsbase.size; ++i) {
        RnsPoly p;
        int32_t r = RLWE_CrtPoly_GetRnsPolyAt(&p, i, self);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = RLWE_RnsPoly_SetSigned(&p, v);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
    }
    self->config.dtype = HIFHE_POLY;
    return HIFHE_SUCCESS;
}

/* Convert every slice, then record the new form. A poly already in `want`
 * is left untouched. */
static HIFHE_ERROR ConvertAllSlices(CrtPoly *self, PolyForm want, HIFHE_ERROR (*op)(RnsPoly *))
{
    if (self == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (self->config.dtype == want) {
        return HIFHE_SUCCESS;
    }
    for (uint32_t i = 0; i < self->config.rnsbase.size; ++i) {
        RnsPoly p;
        int32_t r = RLWE_CrtPoly_GetRnsPolyAt(&p, i, self);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = op(&p);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
    }
    self->config.dtype = want;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR RLWE_CrtPoly_ToNtt(CrtPoly *self)
{
    return ConvertAllSlices(self, HIFHE_NTT, RLWE_RnsPoly_ToNtt);
}

HIFHE_ERROR RLWE_CrtPoly_ToPoly(CrtPoly *self)
{
    return ConvertAllSlices(self, HIFHE_POLY, RLWE_RnsPoly_ToPoly);
}
