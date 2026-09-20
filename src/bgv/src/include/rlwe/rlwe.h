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

/*
 * RLWE layer: RNS polynomials over Z_q[x]/(x^N+1).
 *
 *   RnsPoly: one modulus q, N coefficients or NTT slots
 *   CrtPoly: one polynomial under several q_i
 *
 * `dtype` says which domain the data is in: HIFHE_POLY or HIFHE_NTT.
 *
 *   RnsPoly.dataSize = polyDegree
 *   CrtPoly.dataSize = rnsbase.size * polyDegree
 */

#ifndef HIFHE_RLWE_RLWE_H
#define HIFHE_RLWE_RLWE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "hifhe_err.h"
#include "basic/vector.h"
#include "basic/context.h"
#include "kernel/modulus.h"
#include "kernel/ntt.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Poly form: coefficient (standard) vs NTT (evaluation-point) domain. */
typedef enum {
    HIFHE_POLY = 0,
    HIFHE_NTT  = 1,
} PolyForm;

/* RNS base = list of prime moduli. */
typedef ModulusVector RnsBase;

/* Parameters that fully describe an R_q polynomial ring. */
typedef struct {
    uint32_t       defaultCiphertextSize;
    uint32_t       polyDegree;
    ModulusVector  cipherMod;         /* main chain q_0, q_1, ... */
} RlweParameter;

/* Runtime context. Holds parameters + all pre-computation tables so hot
 * paths never allocate. Owned by the top-level BgvContext bag. */
typedef struct {
    BgvContext      seedCtx;          /* 32-byte seed store */
    RlweParameter  *parameter;

    /* Per-modulus NTT tables, sized == cipherMod.size and populated by
     * RLWE_RlweContext_BuildWithTables. tableBuf[i] is one contiguous
     * HIFHE_NTT_TABLE_WORDS(polyDegree) block holding the twiddle arrays for
     * modulus i. Each entry carries its own Barrett constant. */
    NttTables      *nttTables;
    uint64_t      **tableBuf;
    /* Ownership of the blocks above. 1: allocated here and freed with the
     * context. 0: supplied by the caller, so Destroy drops the pointers and
     * frees nothing. Applies to all blocks or none. */
    uint8_t         ownsTableBuf;
    uint32_t        tablesCount;      /* == cipherMod.size once built */

    RnsBase         cipherRnsBase;    /* copy of parameter->cipherMod for convenience */
} RlweContext;

/* ----- RnsPoly ----- */
typedef struct {
    Modulus  modulus;
    PolyForm dtype;
} RnsPolyConfig;

typedef struct RnsPoly {
    RnsPolyConfig config;
    RlweContext  *context;
    uint32_t      dataSize;   /* == context->parameter->polyDegree */
    uint64_t     *data;       /* size = dataSize; heap-owned unless aliased */
    uint8_t       ownsData;
} RnsPoly;

/* ----- CrtPoly ----- */
typedef struct {
    RnsBase  rnsbase;
    PolyForm dtype;
} CrtPolyConfig;

typedef struct CrtPoly {
    CrtPolyConfig config;
    RlweContext  *context;
    uint32_t      dataSize;   /* == rnsbase.size * polyDegree */
    uint64_t     *data;       /* heap-owned unless aliased */
    uint8_t       ownsData;
    /* The config carries its own allocation (the rnsbase vector), which a
     * component view shares with its parent rather than copying. Destroy
     * frees the config only when this is set. */
    uint8_t       ownsConfig;
} CrtPoly;

/* CalDataSize chain. static inline so the arithmetic folds at compile time. */
static inline uint32_t RLWE_RnsPoly_CalDataSize(const RnsPolyConfig *cfg,
                                                const RlweContext *ctx)
{
    (void)cfg;
    return ctx->parameter->polyDegree;
}
static inline uint32_t RLWE_CrtPoly_CalDataSize(const CrtPolyConfig *cfg,
                                                const RlweContext *ctx)
{
    return cfg->rnsbase.size * RLWE_RnsPoly_CalDataSize(NULL, ctx);
}

/* ----- RlweParameter helpers ----- */
HIFHE_ERROR RLWE_RlweParameter_Create (RlweParameter *out,
                                      uint32_t defaultCiphertextSize,
                                      uint32_t polyDegree,
                                      const ModulusVector *cipherMod);
HIFHE_ERROR RLWE_RlweParameter_Destroy(RlweParameter *self);
HIFHE_ERROR RLWE_RlweParameter_Copy   (RlweParameter *dst, const RlweParameter *src);

/* ----- RlweContext ----- */
HIFHE_ERROR RLWE_RlweContext_Destroy(RlweContext *self);

/* ----- CrtPoly ----- */
HIFHE_ERROR RLWE_CrtPoly_Create        (CrtPoly *out,
                                       const CrtPolyConfig *cfg, RlweContext *ctx);
HIFHE_ERROR RLWE_CrtPoly_CreateFromExist(CrtPoly *out,
                                       uint64_t *data, uint32_t size,
                                       const CrtPolyConfig *cfg, RlweContext *ctx);
HIFHE_ERROR RLWE_CrtPoly_Copy          (CrtPoly *dst, const CrtPoly *src);
HIFHE_ERROR RLWE_CrtPoly_Destroy       (CrtPoly *self);
HIFHE_ERROR RLWE_CrtPoly_GetRnsPolyAt  (RnsPoly *out, uint32_t index,
                                       const CrtPoly *self);

/* CrtPolyConfig helpers. */
HIFHE_ERROR RLWE_CrtPolyConfig_Copy   (CrtPolyConfig *dst, const CrtPolyConfig *src);
HIFHE_ERROR RLWE_CrtPolyConfig_Destroy(CrtPolyConfig *self);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_RLWE_RLWE_H */
