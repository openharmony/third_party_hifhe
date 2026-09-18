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
#include "kernel/ntt.h"
#include "kernel/modulus.h"

/* ---------------- RlweParameter ---------------- */

HIFHE_ERROR RLWE_RlweParameter_Create(RlweParameter *out,
                                    uint32_t defaultCiphertextSize,
                                    uint32_t polyDegree,
                                    const ModulusVector *cipherMod)
{
    if (out == NULL || cipherMod == NULL) return HIFHE_NULL_INPUT;
    memset(out, 0, sizeof(*out));
    out->defaultCiphertextSize = defaultCiphertextSize;
    out->polyDegree = polyDegree;
    return Uint64Vector_Create(&out->cipherMod, cipherMod->data, cipherMod->size);
}

HIFHE_ERROR RLWE_RlweParameter_Destroy(RlweParameter *self)
{
    if (self == NULL) return HIFHE_NULL_INPUT;
    Uint64Vector_Destroy(&self->cipherMod);
    return HIFHE_SUCCESS;
}

HIFHE_ERROR RLWE_RlweParameter_Copy(RlweParameter *dst, const RlweParameter *src)
{
    if (dst == NULL || src == NULL) return HIFHE_NULL_INPUT;
    RLWE_RlweParameter_Destroy(dst);
    return RLWE_RlweParameter_Create(dst,
        src->defaultCiphertextSize, src->polyDegree, &src->cipherMod);
}

/* ---------------- RlweContext ---------------- */

HIFHE_ERROR RLWE_RlweContext_BuildWithTables(RlweContext *out, RlweParameter *param,
                                           uint64_t *const *tables)
{
    if (out == NULL || param == NULL) return HIFHE_NULL_INPUT;
    memset(out, 0, sizeof(*out));
    out->parameter = param;

    uint32_t L = param->cipherMod.size;
    uint32_t N = param->polyDegree;
    if (L == 0u || N == 0u) return HIFHE_PARAM_INVALID;

    BgvContext_Init(&out->seedCtx);

    /* Allocate table arrays. */
    out->nttTables  = (NttTables    *)BSL_SAL_Calloc(L, (uint32_t)sizeof(NttTables));
    out->tableBuf   = (uint64_t    **)BSL_SAL_Calloc(L, (uint32_t)sizeof(uint64_t *));
    if (out->nttTables == NULL || out->tableBuf == NULL) {
        goto oom;
    }
    /* Supplied tables are taken as a set. Mixing shared and owned blocks
     * would need per-entry bookkeeping. */
    out->ownsTableBuf = (tables == NULL) ? 1u : 0u;

    for (uint32_t i = 0; i < L; ++i) {
        Modulus q = param->cipherMod.data[i];
        int32_t r;
        if (tables != NULL) {
            /* Point at the caller's block. Nothing is computed or copied. */
            out->tableBuf[i] = tables[i];
            r = Kernel_Ntt_AttachTables(&out->nttTables[i], out->tableBuf[i], q, N);
        } else {
            out->tableBuf[i] = (uint64_t *)BSL_SAL_Malloc(
                (uint32_t)(HIFHE_NTT_TABLE_WORDS(N) * sizeof(uint64_t)));
            if (out->tableBuf[i] == NULL) goto oom;
            r = Kernel_Ntt_BuildTables(&out->nttTables[i], out->tableBuf[i], q, N);
        }
        if (r != HIFHE_SUCCESS) goto err;

        /* Counted per iteration so Destroy can release the blocks already
         * allocated if a later one fails. */
        out->tablesCount = i + 1u;
    }

    /* Copy cipherRnsBase for convenience. */
    int32_t r2 = Uint64Vector_Create(&out->cipherRnsBase,
                                     param->cipherMod.data, param->cipherMod.size);
    if (r2 != HIFHE_SUCCESS) goto err;

    return HIFHE_SUCCESS;

oom:
    RLWE_RlweContext_Destroy(out);
    return HIFHE_MEMORY_ERROR;
err:
    RLWE_RlweContext_Destroy(out);
    return HIFHE_INTERNAL;
}

HIFHE_ERROR RLWE_RlweContext_Destroy(RlweContext *self)
{
    if (self == NULL) return HIFHE_NULL_INPUT;
    if (self->tableBuf != NULL) {
        /* Borrowed blocks belong to the caller. Only the pointer array is
         * freed in that case. */
        if (self->ownsTableBuf) {
            for (uint32_t i = 0; i < self->tablesCount; ++i) {
                if (self->tableBuf[i] != NULL) BSL_SAL_Free(self->tableBuf[i]);
            }
        }
        BSL_SAL_Free(self->tableBuf);
    }
    if (self->nttTables != NULL) BSL_SAL_Free(self->nttTables);
    Uint64Vector_Destroy(&self->cipherRnsBase);
    BgvContext_ClearSeed(&self->seedCtx);
    memset(self, 0, sizeof(*self));
    return HIFHE_SUCCESS;
}

const NttTables *RLWE_RlweContext_GetNttTablesByModulus(const RlweContext *ctx, Modulus q)
{
    if (ctx == NULL) return NULL;
    for (uint32_t i = 0; i < ctx->tablesCount; ++i) {
        if (ctx->nttTables[i].q == q) return &ctx->nttTables[i];
    }
    return NULL;
}

const BarrettConst *RLWE_RlweContext_GetBarrettByModulus(const RlweContext *ctx, Modulus q)
{
    if (ctx == NULL) return NULL;
    for (uint32_t i = 0; i < ctx->tablesCount; ++i) {
        if (ctx->nttTables[i].q == q) return &ctx->nttTables[i].barrett;
    }
    return NULL;
}
