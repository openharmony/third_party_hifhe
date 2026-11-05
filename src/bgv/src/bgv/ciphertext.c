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

#include <stdbool.h>
#include <string.h>
#include "hifhe_mem.h"
#include "hifhe_err_internal.h"
#include "bgv/ciphertext.h"
#include "rlwe/rlwe.h"
#include "rlwe/crt_ops.h"
#include "rlwe/rns_ops.h"

HIFHE_ERROR BGV_CiphertextConfig_Create(CiphertextConfig *out, uint32_t ciphertextSize, uint64_t correctionFactor,
                                        const RnsBase *rnsBase)
{
    if (out == NULL || rnsBase == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    memset(out, 0, sizeof(*out));
    if (ciphertextSize < 2u || ciphertextSize > HIFHE_BGV_MAX_CIPHERTEXT_SIZE) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_CT_DEGREE_MISMATCH);
        return HIFHE_CT_DEGREE_MISMATCH;
    }
    int32_t r = Uint64Vector_Create(&out->crtConfig.rnsbase, rnsBase->data, rnsBase->size);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    out->crtConfig.dtype = HIFHE_NTT;
    out->ciphertextSize = ciphertextSize;
    out->correctionFactor = correctionFactor;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_CiphertextConfig_Destroy(CiphertextConfig *self)
{
    if (self == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    RLWE_CrtPolyConfig_Destroy(&self->crtConfig);
    memset(self->seed, 0, sizeof(self->seed));
    self->ciphertextSize = 0u;
    self->correctionFactor = 0u;
    self->caps = HIFHE_CAP_NONE;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_CiphertextConfig_Copy(CiphertextConfig *dst, const CiphertextConfig *src)
{
    if (dst == NULL || src == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    BGV_CiphertextConfig_Destroy(dst);
    int32_t r = RLWE_CrtPolyConfig_Copy(&dst->crtConfig, &src->crtConfig);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    dst->ciphertextSize = src->ciphertextSize;
    dst->correctionFactor = src->correctionFactor;
    dst->caps = src->caps;
    memcpy(dst->seed, src->seed, sizeof(dst->seed));
    return HIFHE_SUCCESS;
}

static HIFHE_ERROR CiphertextCreateImpl(Ciphertext *out, const CiphertextConfig *cfg, BGVContext *ctx, bool zeroed)
{
    if (out == NULL || cfg == NULL || ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    memset(out, 0, sizeof(*out));
    int32_t r = BGV_CiphertextConfig_Copy(&out->config, cfg);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    out->context = ctx;
    out->dataSize = BGV_Ciphertext_CalDataSize(cfg, ctx);
    out->data = zeroed ? (uint64_t *)HifheCalloc(out->dataSize, (uint32_t)sizeof(uint64_t)) :
                         (uint64_t *)HifheMalloc(out->dataSize * (uint32_t)sizeof(uint64_t));
    if (out->data == NULL) {
        BGV_CiphertextConfig_Destroy(&out->config);
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    out->ownsData = 1u;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_Ciphertext_Create(Ciphertext *out, const CiphertextConfig *cfg, BGVContext *ctx)
{
    return CiphertextCreateImpl(out, cfg, ctx, true);
}

HIFHE_ERROR BGV_Ciphertext_CreateUninit(Ciphertext *out, const CiphertextConfig *cfg, BGVContext *ctx)
{
    return CiphertextCreateImpl(out, cfg, ctx, false);
}

/* CiphertextConfig_Create already selects HIFHE_NTT. */
HIFHE_ERROR BGV_Ciphertext_CreateSize2Ntt(Ciphertext *out, uint64_t correctionFactor, const RnsBase *base,
                                          BGVContext *ctx)
{
    if (out == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    /* Zeroed up front so a failure here still leaves `out` safe to destroy. */
    memset(out, 0, sizeof(*out));
    CiphertextConfig cfg;
    int32_t r = BGV_CiphertextConfig_Create(&cfg, 2u, correctionFactor, base);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    r = BGV_Ciphertext_Create(out, &cfg, ctx);
    BGV_CiphertextConfig_Destroy(&cfg);
    return r;
}

/* Storage comes from BGV_Ciphertext_Create. */
HIFHE_ERROR BGV_Ciphertext_Copy(Ciphertext *dst, const Ciphertext *src)
{
    if (dst == NULL || src == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (src->context == NULL || src->data == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }

    Ciphertext fresh;
    int32_t r = BGV_Ciphertext_Create(&fresh, &src->config, src->context);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    if (fresh.dataSize != src->dataSize) {
        BGV_Ciphertext_Destroy(&fresh);
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    memcpy(fresh.data, src->data, src->dataSize * sizeof(uint64_t));

    BGV_Ciphertext_Destroy(dst);
    *dst = fresh;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_Ciphertext_Destroy(Ciphertext *self)
{
    if (self == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (self->ownsData && self->data != NULL) {
        HifheFree(self->data);
    }
    BGV_CiphertextConfig_Destroy(&self->config);
    self->data = NULL;
    self->dataSize = 0u;
    self->ownsData = 0u;
    return HIFHE_SUCCESS;
}

/* View onto the i-th CrtPoly component. Owns nothing, so RLWE_CrtPoly_Destroy
 * on it frees nothing. */
HIFHE_ERROR BGV_Ciphertext_GetCrtPolyAt(CrtPoly *out, uint32_t index, const Ciphertext *self)
{
    if (out == NULL || self == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (index >= self->config.ciphertextSize) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    uint32_t sliceSz = RLWE_CrtPoly_CalDataSize(&self->config.crtConfig, &self->context->rlweContext);
    memset(out, 0, sizeof(*out));
    out->config = self->config.crtConfig; /* shallow: rnsbase aliased */
    out->context = (RlweContext *)&self->context->rlweContext;
    out->dataSize = sliceSz;
    out->data = self->data + (index * sliceSz);
    out->ownsData = 0u;
    out->ownsConfig = 0u;
    return HIFHE_SUCCESS;
}

/* ---------------- component-wise arithmetic ---------------- */

static HIFHE_ERROR ForEachComponent(Ciphertext *out, const Ciphertext *a, const Ciphertext *b,
                                    HIFHE_ERROR (*op)(CrtPoly *, const CrtPoly *, const CrtPoly *))
{
    if (out == NULL || a == NULL || b == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    uint32_t K = a->config.ciphertextSize;
    if (b->config.ciphertextSize != K) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_CT_DEGREE_MISMATCH);
        return HIFHE_CT_DEGREE_MISMATCH;
    }
    if (out->config.ciphertextSize != K) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_CT_DEGREE_MISMATCH);
        return HIFHE_CT_DEGREE_MISMATCH;
    }
    for (uint32_t k = 0; k < K; ++k) {
        CrtPoly av, bv, ov;
        int32_t r;
        r = BGV_Ciphertext_GetCrtPolyAt(&av, k, a);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = BGV_Ciphertext_GetCrtPolyAt(&bv, k, b);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = BGV_Ciphertext_GetCrtPolyAt(&ov, k, out);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = op(&ov, &av, &bv);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
    }
    out->config.crtConfig.dtype = a->config.crtConfig.dtype;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_Ciphertext_Add(Ciphertext *out, const Ciphertext *a, const Ciphertext *b)
{
    return ForEachComponent(out, a, b, RLWE_CrtPoly_Add);
}

HIFHE_ERROR BGV_Ciphertext_Neg(Ciphertext *out, const Ciphertext *a)
{
    if (out == NULL || a == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (out->config.ciphertextSize != a->config.ciphertextSize) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_CT_DEGREE_MISMATCH);
        return HIFHE_CT_DEGREE_MISMATCH;
    }
    for (uint32_t k = 0; k < a->config.ciphertextSize; ++k) {
        CrtPoly av, ov;
        int32_t r;
        r = BGV_Ciphertext_GetCrtPolyAt(&av, k, a);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = BGV_Ciphertext_GetCrtPolyAt(&ov, k, out);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = RLWE_CrtPoly_Neg(&ov, &av);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
    }
    out->config.crtConfig.dtype = a->config.crtConfig.dtype;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_Ciphertext_MulScalar(Ciphertext *out, const Ciphertext *a, uint64_t x)
{
    if (out == NULL || a == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (out->config.ciphertextSize != a->config.ciphertextSize) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_CT_DEGREE_MISMATCH);
        return HIFHE_CT_DEGREE_MISMATCH;
    }
    for (uint32_t k = 0; k < a->config.ciphertextSize; ++k) {
        CrtPoly av, ov;
        int32_t r;
        r = BGV_Ciphertext_GetCrtPolyAt(&av, k, a);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = BGV_Ciphertext_GetCrtPolyAt(&ov, k, out);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = RLWE_CrtPoly_MulScalar(&ov, &av, x);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
    }
    out->config.crtConfig.dtype = a->config.crtConfig.dtype;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_Ciphertext_MulCrtPoly(Ciphertext *out, const Ciphertext *a, const CrtPoly *p)
{
    if (out == NULL || a == NULL || p == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (out->config.ciphertextSize != a->config.ciphertextSize) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_CT_DEGREE_MISMATCH);
        return HIFHE_CT_DEGREE_MISMATCH;
    }
    for (uint32_t k = 0; k < a->config.ciphertextSize; ++k) {
        CrtPoly av, ov;
        int32_t r;
        r = BGV_Ciphertext_GetCrtPolyAt(&av, k, a);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = BGV_Ciphertext_GetCrtPolyAt(&ov, k, out);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        r = RLWE_CrtPoly_MulDot(&ov, &av, p);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
    }
    out->config.crtConfig.dtype = a->config.crtConfig.dtype;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_Ciphertext_AddCrtPolyAt(Ciphertext *self, uint32_t index, const CrtPoly *p)
{
    if (self == NULL || p == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    CrtPoly v;
    int32_t r = BGV_Ciphertext_GetCrtPolyAt(&v, index, self);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    return RLWE_CrtPoly_Add(&v, &v, p);
}

HIFHE_ERROR BGV_Ciphertext_SetCrtPolyAt(Ciphertext *self, uint32_t index, const CrtPoly *p)
{
    if (self == NULL || p == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    CrtPoly v;
    int32_t r = BGV_Ciphertext_GetCrtPolyAt(&v, index, self);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    return RLWE_CrtPoly_Assign(&v, p);
}
