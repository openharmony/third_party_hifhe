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
#include "bsl_sal.h"
#include "rlwe/rlwe.h"
#include "rlwe/rlwe_context.h"
#include "rlwe/rns_ops.h"
#include "kernel/modulus.h"
#include "kernel/ntt.h"
#include "rlwe/rlwe_context.h"

/* ---------------- lifecycle ---------------- */

HIFHE_ERROR RLWE_RnsPoly_Create(RnsPoly *out, const RnsPolyConfig *cfg, RlweContext *ctx)
{
    if (out == NULL || cfg == NULL || ctx == NULL) return HIFHE_NULL_INPUT;
    memset(out, 0, sizeof(*out));
    out->config   = *cfg;
    out->context  = ctx;
    out->dataSize = ctx->parameter->polyDegree;
    out->data     = (uint64_t *)BSL_SAL_Calloc(out->dataSize, (uint32_t)sizeof(uint64_t));
    if (out->data == NULL) return HIFHE_MEMORY_ERROR;
    out->ownsData = 1u;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR RLWE_RnsPoly_Destroy(RnsPoly *self)
{
    if (self == NULL) return HIFHE_NULL_INPUT;
    if (self->ownsData && self->data != NULL) {
        BSL_SAL_Free(self->data);
    }
    self->data     = NULL;
    self->dataSize = 0u;
    self->ownsData = 0u;
    return HIFHE_SUCCESS;
}

/* ---------------- pointwise arithmetic ---------------- */

static HIFHE_ERROR CheckShape(const RnsPoly *a, const RnsPoly *b)
{
    if (a == NULL || b == NULL) return HIFHE_NULL_INPUT;
    if (a->config.modulus != b->config.modulus) return HIFHE_PARAM_INVALID;
    if (a->dataSize != b->dataSize) return HIFHE_PARAM_INVALID;
    if (a->context != b->context) return HIFHE_PARAM_INVALID;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR RLWE_RnsPoly_Add(RnsPoly *out, const RnsPoly *a, const RnsPoly *b)
{
    int32_t r = CheckShape(a, b);
    if (r != HIFHE_SUCCESS) return r;
    if (out == NULL) return HIFHE_NULL_INPUT;
    Modulus q = a->config.modulus;
    for (uint32_t i = 0; i < a->dataSize; ++i) {
        uint64_t s = a->data[i] + b->data[i];
        if (s >= q) s -= q;
        out->data[i] = s;
    }
    out->config = a->config;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR RLWE_RnsPoly_Sub(RnsPoly *out, const RnsPoly *a, const RnsPoly *b)
{
    int32_t r = CheckShape(a, b);
    if (r != HIFHE_SUCCESS) return r;
    if (out == NULL) return HIFHE_NULL_INPUT;
    Modulus q = a->config.modulus;
    for (uint32_t i = 0; i < a->dataSize; ++i) {
        uint64_t d = a->data[i] + q - b->data[i];
        if (d >= q) d -= q;
        out->data[i] = d;
    }
    out->config = a->config;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR RLWE_RnsPoly_Neg(RnsPoly *out, const RnsPoly *a)
{
    if (out == NULL || a == NULL) return HIFHE_NULL_INPUT;
    Modulus q = a->config.modulus;
    for (uint32_t i = 0; i < a->dataSize; ++i) {
        out->data[i] = (a->data[i] == 0u) ? 0u : (q - a->data[i]);
    }
    out->config = a->config;
    return HIFHE_SUCCESS;
}

/* Barrett constant for this limb, or NULL when the modulus is not one of the
 * context's. Fetched once per loop. */
static const BarrettConst *LimbBarrett(const RnsPoly *p)
{
    return (p != NULL && p->context != NULL)
               ? RLWE_RlweContext_GetBarrettByModulus(p->context, p->config.modulus)
               : NULL;
}

HIFHE_ERROR RLWE_RnsPoly_MulDot(RnsPoly *out, const RnsPoly *a, const RnsPoly *b)
{
    int32_t r = CheckShape(a, b);
    if (r != HIFHE_SUCCESS) return r;
    if (out == NULL) return HIFHE_NULL_INPUT;
    Modulus q = a->config.modulus;
    /* Both operands vary, so Shoup does not apply. Barrett does, and the
     * context already carries the constant. */
    const BarrettConst *bc = LimbBarrett(a);
    if (bc != NULL) {
        for (uint32_t i = 0; i < a->dataSize; ++i) {
            ModulusWide p = (ModulusWide)a->data[i] * (ModulusWide)b->data[i];
            out->data[i] = Kernel_BarrettReduce128((uint64_t)(p >> 64), (uint64_t)p, bc);
        }
    } else {
        for (uint32_t i = 0; i < a->dataSize; ++i) {
            out->data[i] = (uint64_t)(((ModulusWide)a->data[i] * (ModulusWide)b->data[i]) % (ModulusWide)q);
        }
    }
    out->config = a->config;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR RLWE_RnsPoly_MulDotAcc(RnsPoly *out, const RnsPoly *a, const RnsPoly *b)
{
    int32_t r = CheckShape(a, b);
    if (r != HIFHE_SUCCESS) return r;
    if (out == NULL) return HIFHE_NULL_INPUT;
    Modulus q = a->config.modulus;
    const BarrettConst *bc = LimbBarrett(a);
    for (uint32_t i = 0; i < a->dataSize; ++i) {
        ModulusWide w = (ModulusWide)a->data[i] * (ModulusWide)b->data[i];
        uint64_t p = (bc != NULL)
                         ? Kernel_BarrettReduce128((uint64_t)(w >> 64), (uint64_t)w, bc)
                         : (uint64_t)(w % (ModulusWide)q);
        uint64_t s = out->data[i] + p;
        if (s >= q) s -= q;
        out->data[i] = s;
    }
    return HIFHE_SUCCESS;
}

HIFHE_ERROR RLWE_RnsPoly_MulScalar(RnsPoly *out, const RnsPoly *a, uint64_t x)
{
    if (out == NULL || a == NULL) return HIFHE_NULL_INPUT;
    Modulus q = a->config.modulus;
    uint64_t xMod = x % q;
    if (xMod == 1u) {
        if (out->data != a->data) {
            memcpy(out->data, a->data, a->dataSize * sizeof(uint64_t));
        }
    } else {
        /* One fixed multiplier for every coefficient. Building the Shoup
         * constant costs one division instead of dataSize. */
        ShoupConst sc;
        if (Kernel_ShoupConst_Init(&sc, xMod, q) == HIFHE_SUCCESS) {
            for (uint32_t i = 0; i < a->dataSize; ++i) {
                out->data[i] = Kernel_ShoupMulMod(a->data[i], &sc);
            }
        } else {
            for (uint32_t i = 0; i < a->dataSize; ++i) {
                out->data[i] = (uint64_t)(((ModulusWide)a->data[i] * (ModulusWide)xMod) % (ModulusWide)q);
            }
        }
    }
    out->config = a->config;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR RLWE_RnsPoly_SetSigned(RnsPoly *self, const int64_t *v)
{
    if (self == NULL || v == NULL) return HIFHE_NULL_INPUT;
    Modulus q = self->config.modulus;
    if (q < 2u) return HIFHE_PARAM_INVALID;
    /* Sampler output is in [-2, 2] for CBD-2 and {-1, 0, 1} for ternary, so
     * the reduction never runs in practice. The compare keeps the function
     * correct for any input. */
    for (uint32_t i = 0; i < self->dataSize; ++i) {
        int64_t s = v[i];
        uint64_t m = (s >= 0) ? (uint64_t)s : (uint64_t)(-s);
        if (m >= q) m %= q;
        self->data[i] = (s >= 0) ? m : ((m == 0u) ? 0u : q - m);
    }
    self->config.dtype = HIFHE_POLY;
    return HIFHE_SUCCESS;
}

/* ---------------- NTT domain conversion ---------------- */

HIFHE_ERROR RLWE_RnsPoly_ToNtt(RnsPoly *self)
{
    if (self == NULL) return HIFHE_NULL_INPUT;
    if (self->config.dtype == HIFHE_NTT) return HIFHE_SUCCESS;
    const NttTables *tbl = RLWE_RlweContext_GetNttTablesByModulus(self->context,
                                                                   self->config.modulus);
    if (tbl == NULL) return HIFHE_INTERNAL;
    int32_t r = Kernel_Ntt_Forward(self->data, tbl);
    if (r != HIFHE_SUCCESS) return r;
    self->config.dtype = HIFHE_NTT;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR RLWE_RnsPoly_ToPoly(RnsPoly *self)
{
    if (self == NULL) return HIFHE_NULL_INPUT;
    if (self->config.dtype == HIFHE_POLY) return HIFHE_SUCCESS;
    const NttTables *tbl = RLWE_RlweContext_GetNttTablesByModulus(self->context,
                                                                   self->config.modulus);
    if (tbl == NULL) return HIFHE_INTERNAL;
    int32_t r = Kernel_Ntt_Inverse(self->data, tbl);
    if (r != HIFHE_SUCCESS) return r;
    self->config.dtype = HIFHE_POLY;
    return HIFHE_SUCCESS;
}

