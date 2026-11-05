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
#include "bgv/plaintext.h"
#include "rlwe/rlwe.h"

HIFHE_ERROR BGV_PlaintextConfig_Create(PlaintextConfig *out, const CrtPolyConfig *crtConfig, uint64_t scale)
{
    if (out == NULL || crtConfig == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    memset(out, 0, sizeof(*out));
    int32_t r = RLWE_CrtPolyConfig_Copy(&out->crtConfig, crtConfig);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    out->scaleFactor = scale;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_PlaintextConfig_Destroy(PlaintextConfig *self)
{
    if (self == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    RLWE_CrtPolyConfig_Destroy(&self->crtConfig);
    self->scaleFactor = 0u;
    return HIFHE_SUCCESS;
}

static HIFHE_ERROR PlaintextCreateImpl(Plaintext *out, const PlaintextConfig *cfg, BGVContext *ctx, bool zeroed)
{
    if (out == NULL || cfg == NULL || ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    memset(out, 0, sizeof(*out));
    int32_t r = BGV_PlaintextConfig_Create(&out->config, &cfg->crtConfig, cfg->scaleFactor);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    out->config.caps = cfg->caps;
    out->context = ctx;
    out->dataSize = BGV_Plaintext_CalDataSize(cfg, ctx);
    out->data = zeroed ? (uint64_t *)HifheCalloc(out->dataSize, (uint32_t)sizeof(uint64_t)) :
                         (uint64_t *)HifheMalloc(out->dataSize * (uint32_t)sizeof(uint64_t));
    if (out->data == NULL) {
        BGV_PlaintextConfig_Destroy(&out->config);
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    out->ownsData = 1u;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_Plaintext_Create(Plaintext *out, const PlaintextConfig *cfg, BGVContext *ctx)
{
    return PlaintextCreateImpl(out, cfg, ctx, true);
}

HIFHE_ERROR BGV_Plaintext_CreateUninit(Plaintext *out, const PlaintextConfig *cfg, BGVContext *ctx)
{
    return PlaintextCreateImpl(out, cfg, ctx, false);
}

HIFHE_ERROR BGV_Plaintext_CreateFromCrtPoly(Plaintext *out, CrtPoly *poly, uint64_t scale, BGVContext *ctx)
{
    if (out == NULL || poly == NULL || ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (poly->data == NULL || !poly->ownsData || !poly->ownsConfig) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    memset(out, 0, sizeof(*out));
    out->config.crtConfig = poly->config; /* moves the rnsbase vector */
    out->config.scaleFactor = scale;
    out->config.caps = HIFHE_CAP_NONE;
    out->context = ctx;
    out->dataSize = poly->dataSize;
    out->data = poly->data;
    out->ownsData = 1u;
    memset(poly, 0, sizeof(*poly)); /* ownership has moved */
    return HIFHE_SUCCESS;
}

/* Storage comes from BGV_Plaintext_Create. */
HIFHE_ERROR BGV_Plaintext_Copy(Plaintext *dst, const Plaintext *src)
{
    if (dst == NULL || src == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (src->context == NULL || src->data == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }

    Plaintext fresh;
    int32_t r = BGV_Plaintext_Create(&fresh, &src->config, src->context);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    if (fresh.dataSize != src->dataSize) {
        BGV_Plaintext_Destroy(&fresh);
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    memcpy(fresh.data, src->data, src->dataSize * sizeof(uint64_t));

    BGV_Plaintext_Destroy(dst);
    *dst = fresh;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_Plaintext_Destroy(Plaintext *self)
{
    if (self == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    /* Secret keys are plaintexts, and decrypted messages are too: wipe the
     * coefficients rather than leaving them in freed memory. */
    if (self->ownsData && self->data != NULL) {
        HifheCleanse(self->data, self->dataSize * (uint32_t)sizeof(uint64_t));
        HifheFree(self->data);
    }
    BGV_PlaintextConfig_Destroy(&self->config);
    self->data = NULL;
    self->dataSize = 0u;
    self->ownsData = 0u;
    return HIFHE_SUCCESS;
}

/* Owns neither buffer nor config, so RLWE_CrtPoly_Destroy frees nothing. */
HIFHE_ERROR BGV_Plaintext_GetCrtPoly(CrtPoly *out, const Plaintext *self)
{
    if (out == NULL || self == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    memset(out, 0, sizeof(*out));
    out->config = self->config.crtConfig; /* shallow: rnsbase aliased */
    out->context = (RlweContext *)&self->context->rlweContext;
    out->dataSize = self->dataSize;
    out->data = self->data;
    out->ownsData = 0u;
    out->ownsConfig = 0u;
    return HIFHE_SUCCESS;
}
