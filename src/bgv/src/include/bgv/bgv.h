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

/* BGV parameters and context. The context owns the RlweContext and the
 * plainMod NTT tables used for slot packing. */

#ifndef HIFHE_BGV_BGV_H
#define HIFHE_BGV_BGV_H

#include <stdint.h>
#include <stddef.h>
#include "hifhe_err.h"
#include "kernel/modulus.h"
#include "basic/vector.h"
#include "rlwe/rlwe.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Numeric defaults reused by presets and BGVParameter constructors. */
#define HIFHE_BGV_DEFAULT_CORRECTION_FACTOR   1u
#define HIFHE_BGV_DEFAULT_PLAIN_MOD           65537ull
#define HIFHE_BGV_DEFAULT_RELIN_DNUM          1u
#define HIFHE_BGV_DEFAULT_SECURITY_LEVEL      128u
#define HIFHE_BGV_DEFAULT_CIPHERTEXT_SIZE     2u

/* ---- Capability block ----
 * Bits on PlaintextConfig / CiphertextConfig, in memory only. The wire
 * dtype word stays a bare PolyForm. */
#define HIFHE_CAP_NONE     0x000000u
#define HIFHE_CAP_LUT      0x000001u   /* payload rides the slot encoder */
#define HIFHE_CAP_SLOT_MAP 0x000002u   /* slot index map applied on top */
#define HIFHE_CAP_MASK     0xffffffu

typedef struct {
    RlweParameter rlweParameter;
    Modulus       plainMod;
    uint64_t      correctionFactor;
} BGVParameter;

typedef struct {
    RlweContext   rlweContext;
    BGVParameter *bgvParameter;

    /* One contiguous HIFHE_NTT_TABLE_WORDS(polyDegree) block of plainMod
     * twiddles, populated on demand by BGV_BGVContext_EnsurePlainNtt. */
    uint64_t     *ptTableBuf;
    /* Ownership of the block above. 1: allocated here and freed with the
     * context. 0: supplied by the caller, so Destroy drops the pointer. */
    uint8_t       ownsPtTableBuf;
    /* Valid while ptNttReady is 1. */
    NttTables     ptNtt;
    uint8_t       ptNttReady;

    /* slotMap[i] = plaintext-NTT position of logical slot i. Built on
     * demand, read only when useSlotMap is set. */
    Uint32Vector  slotMap;
    uint8_t       slotMapReady;
    /* 0 (default): slot i at NTT position i, the predecessor's layout.
     * 1: apply the map, which makes a rotation a cyclic shift. */
    uint8_t       useSlotMap;
} BGVContext;

/* Build the plainMod NTT tables. HIFHE_PARAM_INVALID if t != 1 mod 2N. */
HIFHE_ERROR BGV_BGVContext_EnsurePlainNtt(BGVContext *ctx);
/* As EnsurePlainNtt, with the table supplied by the caller. table holds
 * HIFHE_NTT_TABLE_WORDS(polyDegree) uint64 in the layout Kernel_Ntt_BuildTables
 * produces. It is neither copied nor freed. NULL computes the table. */
HIFHE_ERROR BGV_BGVContext_EnsurePlainNttWith(BGVContext *ctx, uint64_t *table);

/* Build the slot index map. Needs the plainMod NTT tables, so it fails
 * wherever EnsurePlainNtt does. */
HIFHE_ERROR BGV_BGVContext_EnsureSlotMap(BGVContext *ctx);

/* Parameter helpers. */
HIFHE_ERROR BGV_BGVParameter_Create (BGVParameter *out,
                                    Modulus plainMod,
                                    uint64_t correctionFactor,
                                    uint32_t defaultCiphertextSize,
                                    uint32_t polyDegree,
                                    const ModulusVector *cipherMod);
HIFHE_ERROR BGV_BGVParameter_Destroy(BGVParameter *self);
HIFHE_ERROR BGV_BGVParameter_Copy   (BGVParameter *dst, const BGVParameter *src);

/* Context lifecycle. */
HIFHE_ERROR BGV_BGVContext_Create (BGVContext *out, BGVParameter *param);
/* As Create, with the ciphertext-side twiddle blocks supplied by the caller.
 * cipherTables[i] covers cipherMod.data[i]. The blocks must outlive the
 * context. NULL computes them. */
HIFHE_ERROR BGV_BGVContext_CreateWithTables(BGVContext *out, BGVParameter *param,
                                          uint64_t *const *cipherTables);
HIFHE_ERROR BGV_BGVContext_Destroy(BGVContext *self);

/* Accessors. Pointer-only, no copy semantics; caller must not free. */
static inline uint32_t BGV_BGVContext_GetPolyDegree(const BGVContext *ctx)
{
    return ctx ? ctx->bgvParameter->rlweParameter.polyDegree : 0;
}
static inline uint8_t BGV_BGVContext_GetUseSlotMap(const BGVContext *ctx)
{
    return ctx ? ctx->useSlotMap : 0u;
}
static inline void BGV_BGVContext_SetUseSlotMap(BGVContext *ctx, uint8_t on)
{
    if (ctx != NULL) ctx->useSlotMap = on ? 1u : 0u;
}

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_BGV_BGV_H */
