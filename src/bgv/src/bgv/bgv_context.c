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
#include "bgv/bgv.h"
#include "bgv/plaintext.h"
#include "bgv/ciphertext.h"
#include "bgv/params_check.h"
#include "kernel/ntt.h"
#include "kernel/modulus.h"
#include "rlwe/rlwe.h"
#include "rlwe/rlwe_context.h"

HIFHE_ERROR BGV_BGVContext_Create(BGVContext *out, BGVParameter *param)
{
    return BGV_BGVContext_CreateWithTables(out, param, NULL);
}

HIFHE_ERROR BGV_BGVContext_CreateWithTables(BGVContext *out, BGVParameter *param, uint64_t *const *cipherTables)
{
    if (out == NULL || param == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    memset(out, 0, sizeof(*out));
    out->bgvParameter = param;
    int32_t r = RLWE_RlweContext_BuildWithTables(&out->rlweContext, &param->rlweParameter, cipherTables);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    /* Slot packing by default; the plainMod NTT tables build on first use. */
    out->useSlotMap = 0u;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_BGVContext_EnsurePlainNtt(BGVContext *ctx)
{
    return BGV_BGVContext_EnsurePlainNttWith(ctx, NULL);
}

HIFHE_ERROR BGV_BGVContext_EnsurePlainNttWith(BGVContext *ctx, uint64_t *table)
{
    if (ctx == NULL || ctx->bgvParameter == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (ctx->ptNttReady) {
        return HIFHE_SUCCESS;
    }

    uint32_t N = ctx->rlweContext.parameter->polyDegree;
    Modulus t = ctx->bgvParameter->plainMod;
    /* Slot packing is a negacyclic NTT mod t, so t must be Proth for this ring. */
    if (!BGV_Params_IsPlainModNttFriendly(t, N)) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }

    int32_t r;
    if (table != NULL) {
        /* Caller's block. Never copied or freed. */
        ctx->ptTableBuf = table;
        ctx->ownsPtTableBuf = 0u;
        r = Kernel_Ntt_AttachTables(&ctx->ptNtt, ctx->ptTableBuf, t, N);
    } else {
        ctx->ptTableBuf = (uint64_t *)HifheMalloc((uint32_t)(HIFHE_NTT_TABLE_WORDS(N) * sizeof(uint64_t)));
        if (ctx->ptTableBuf == NULL) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
            return HIFHE_MEMORY_ERROR;
        }
        ctx->ownsPtTableBuf = 1u;
        r = Kernel_Ntt_BuildTables(&ctx->ptNtt, ctx->ptTableBuf, t, N);
    }
    if (r != HIFHE_SUCCESS) {
        if (ctx->ownsPtTableBuf && ctx->ptTableBuf != NULL) {
            HifheFree(ctx->ptTableBuf);
        }
        ctx->ptTableBuf = NULL;
        ctx->ownsPtTableBuf = 0u;
        return r;
    }
    ctx->ptNttReady = 1u;
    return HIFHE_SUCCESS;
}

static uint32_t BitRevU32(uint32_t x, uint32_t bits)
{
    uint32_t r = 0u;
    for (uint32_t i = 0; i < bits; ++i) {
        if ((x >> i) & 1u) {
            r |= 1u << (bits - 1u - i);
        }
    }
    return r;
}

/* slotMap[i] = plaintext-NTT position of logical slot i. The slots form a
 * 2 x (N/2) matrix:
 *   row 0 col c -> zeta^(3^c),   row 1 col c -> zeta^(-3^c)
 * NTT output is bit-reversed, so the position is brv((exponent - 1) / 2). */
HIFHE_ERROR BGV_BGVContext_EnsureSlotMap(BGVContext *ctx)
{
    if (ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (ctx->slotMapReady) {
        return HIFHE_SUCCESS;
    }

    int32_t r = BGV_BGVContext_EnsurePlainNtt(ctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }

    uint32_t N = ctx->rlweContext.parameter->polyDegree;
    uint32_t logN = 0u;
    while ((1u << logN) < N) {
        logN++;
    }
    uint64_t twoN = 2ull * (uint64_t)N;

    r = Uint32Vector_Create(&ctx->slotMap, NULL, N);
    if (r != HIFHE_SUCCESS) {
        return r;
    }

    uint32_t half = N / 2u;
    uint64_t g = 1u;
    for (uint32_t c = 0; c < half; ++c) {
        ctx->slotMap.data[c] = BitRevU32((uint32_t)((g - 1u) / 2u), logN);
        ctx->slotMap.data[c + half] = BitRevU32((uint32_t)((twoN - g - 1u) / 2u), logN);
        g = (g * 3u) % twoN;
    }
    ctx->slotMapReady = 1u;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_BGVContext_Destroy(BGVContext *self)
{
    if (self == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    RLWE_RlweContext_Destroy(&self->rlweContext);
    if (self->ownsPtTableBuf && self->ptTableBuf != NULL) {
        HifheFree(self->ptTableBuf);
    }
    self->ptTableBuf = NULL;
    self->ownsPtTableBuf = 0u;
    memset(&self->ptNtt, 0, sizeof(self->ptNtt));
    self->ptNttReady = 0u;
    Uint32Vector_Destroy(&self->slotMap);
    self->slotMapReady = 0u;
    self->useSlotMap = 0u;
    self->bgvParameter = NULL;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_BGVContext_GetDefaultPlaintextConfig(PlaintextConfig *out, const BGVContext *ctx)
{
    if (out == NULL || ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    memset(out, 0, sizeof(*out));
    /* Plaintext lives on the full cipher RNS base. */
    int32_t r = Uint64Vector_Create(&out->crtConfig.rnsbase, ctx->rlweContext.cipherRnsBase.data,
                                    ctx->rlweContext.cipherRnsBase.size);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    out->crtConfig.dtype = HIFHE_NTT;
    out->scaleFactor = ctx->bgvParameter->correctionFactor;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_BGVContext_GetDefaultCiphertextConfig(CiphertextConfig *out, const BGVContext *ctx)
{
    if (out == NULL || ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    /* Defer to Create so the header defaults live in one place. */
    return BGV_CiphertextConfig_Create(out, ctx->bgvParameter->rlweParameter.defaultCiphertextSize,
                                       ctx->bgvParameter->correctionFactor, &ctx->rlweContext.cipherRnsBase);
}
