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

#ifndef HIFHE_BGV_CIPHERTEXT_H
#define HIFHE_BGV_CIPHERTEXT_H

#include <stdint.h>
#include <stddef.h>
#include "hifhe_err.h"
#include "rlwe/rlwe.h"
#include "bgv/bgv.h"
#include "bgv/plaintext.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HIFHE_CIPHERTEXT_SEED_LEN 4u /* 4 * uint64 = 256 bit */

typedef struct {
    CrtPolyConfig crtConfig;
    uint32_t ciphertextSize; /* number of CrtPoly components (>=2) */
    uint64_t correctionFactor;
    uint64_t seed[HIFHE_CIPHERTEXT_SEED_LEN];
    uint32_t caps; /* HIFHE_CAP_* bits; rides the wire dtype word */
} CiphertextConfig;

typedef struct Ciphertext {
    CiphertextConfig config;
    BGVContext *context;
    uint32_t dataSize; /* == ciphertextSize * rnsbase.size * polyDegree */
    uint64_t *data;
    uint8_t ownsData;
} Ciphertext;

HIFHE_ERROR BGV_CiphertextConfig_Create(CiphertextConfig *out, uint32_t ciphertextSize, uint64_t correctionFactor,
                                        const RnsBase *rnsBase);
HIFHE_ERROR BGV_CiphertextConfig_Destroy(CiphertextConfig *self);
HIFHE_ERROR BGV_CiphertextConfig_Copy(CiphertextConfig *dst, const CiphertextConfig *src);

/* dataSize = ciphertextSize * rnsbase.size * polyDegree */
static inline uint32_t BGV_Ciphertext_CalDataSize(const CiphertextConfig *cfg, const BGVContext *ctx)
{
    return cfg->ciphertextSize * RLWE_CrtPoly_CalDataSize(&cfg->crtConfig, &ctx->rlweContext);
}

HIFHE_ERROR BGV_Ciphertext_Create(Ciphertext *out, const CiphertextConfig *cfg, BGVContext *ctx);
/* As BGV_Ciphertext_Create, but the buffer is left uninitialised: for callers
 * that overwrite every word before reading any. */
HIFHE_ERROR BGV_Ciphertext_CreateUninit(Ciphertext *out, const CiphertextConfig *cfg, BGVContext *ctx);
/* Zeroed size-2 NTT ciphertext over `base`. The shape key switching writes
 * into, and the one relinearize and rotate build around it. */
HIFHE_ERROR BGV_Ciphertext_CreateSize2Ntt(Ciphertext *out, uint64_t correctionFactor, const RnsBase *base,
                                          BGVContext *ctx);
HIFHE_ERROR BGV_Ciphertext_Copy(Ciphertext *dst, const Ciphertext *src);
HIFHE_ERROR BGV_Ciphertext_Destroy(Ciphertext *self);

/* Access one component polynomial. `out` is a view (does NOT own data). */
HIFHE_ERROR BGV_Ciphertext_GetCrtPolyAt(CrtPoly *out, uint32_t index, const Ciphertext *self);

/* ----- component-wise arithmetic -----
 * Walk the components, defer to rlwe/crt_ops. `out` may alias an operand.
 * Shape only; correctionFactor is the caller's. */
HIFHE_ERROR BGV_Ciphertext_Add(Ciphertext *out, const Ciphertext *a, const Ciphertext *b);
HIFHE_ERROR BGV_Ciphertext_Neg(Ciphertext *out, const Ciphertext *a);
HIFHE_ERROR BGV_Ciphertext_MulScalar(Ciphertext *out, const Ciphertext *a, uint64_t x);
/* Every component times one polynomial, i.e. ct*pt. */
HIFHE_ERROR BGV_Ciphertext_MulCrtPoly(Ciphertext *out, const Ciphertext *a, const CrtPoly *p);
/* out[index] += p */
HIFHE_ERROR BGV_Ciphertext_AddCrtPolyAt(Ciphertext *self, uint32_t index, const CrtPoly *p);
/* out[index] = p */
HIFHE_ERROR BGV_Ciphertext_SetCrtPolyAt(Ciphertext *self, uint32_t index, const CrtPoly *p);

HIFHE_ERROR BGV_BGVContext_GetDefaultCiphertextConfig(CiphertextConfig *out, const BGVContext *ctx);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_BGV_CIPHERTEXT_H */
