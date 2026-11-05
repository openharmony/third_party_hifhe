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

#ifndef HIFHE_BGV_PLAINTEXT_H
#define HIFHE_BGV_PLAINTEXT_H

#include <stdint.h>
#include <stddef.h>
#include "hifhe_err.h"
#include "rlwe/rlwe.h"
#include "bgv/bgv.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    CrtPolyConfig crtConfig;
    uint64_t scaleFactor;
    uint32_t caps; /* HIFHE_CAP_* bits; rides the wire dtype word */
} PlaintextConfig;

typedef struct Plaintext {
    PlaintextConfig config;
    BGVContext *context;
    uint32_t dataSize; /* == rnsbase.size * polyDegree */
    uint64_t *data;
    uint8_t ownsData;
} Plaintext;

HIFHE_ERROR BGV_PlaintextConfig_Create(PlaintextConfig *out, const CrtPolyConfig *crtConfig, uint64_t scale);
HIFHE_ERROR BGV_PlaintextConfig_Destroy(PlaintextConfig *self);

/* dataSize = rnsbase.size * polyDegree */
static inline uint32_t BGV_Plaintext_CalDataSize(const PlaintextConfig *cfg, const BGVContext *ctx)
{
    return RLWE_CrtPoly_CalDataSize(&cfg->crtConfig, &ctx->rlweContext);
}

HIFHE_ERROR BGV_Plaintext_Create(Plaintext *out, const PlaintextConfig *cfg, BGVContext *ctx);
/* As BGV_Plaintext_Create, but the buffer is left uninitialised: for callers
 * that overwrite every word before reading any. */
HIFHE_ERROR BGV_Plaintext_CreateUninit(Plaintext *out, const PlaintextConfig *cfg, BGVContext *ctx);
/* Adopt a CrtPoly's storage instead of allocating and copying. `poly` must
 * own both its buffer and its config; on success it is left empty and the
 * plaintext owns what it held. Lets a producer that already built a poly
 * through RLWE_CrtPoly_Create hand it over without a second allocation. */
HIFHE_ERROR BGV_Plaintext_CreateFromCrtPoly(Plaintext *out, CrtPoly *poly, uint64_t scale, BGVContext *ctx);
HIFHE_ERROR BGV_Plaintext_Copy(Plaintext *dst, const Plaintext *src);
HIFHE_ERROR BGV_Plaintext_Destroy(Plaintext *self);

/* CrtPoly view of the payload. Owns nothing. */
HIFHE_ERROR BGV_Plaintext_GetCrtPoly(CrtPoly *out, const Plaintext *self);

/* Default config for a fresh plaintext under `ctx`. */
HIFHE_ERROR BGV_BGVContext_GetDefaultPlaintextConfig(PlaintextConfig *out, const BGVContext *ctx);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_BGV_PLAINTEXT_H */
