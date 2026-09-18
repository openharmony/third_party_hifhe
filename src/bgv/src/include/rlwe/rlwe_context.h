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

/* RlweContext helpers too heavy for rlwe.h's static inlines. */

#ifndef HIFHE_RLWE_CONTEXT_H
#define HIFHE_RLWE_CONTEXT_H

#include "hifhe_err.h"
#include "rlwe/rlwe.h"
#include "kernel/ntt.h"
#include "kernel/modulus.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Build a context, with the twiddle blocks optionally supplied by the caller.
 * tables[i] covers cipherMod.data[i] and holds HIFHE_NTT_TABLE_WORDS(polyDegree)
 * uint64 in the layout Kernel_Ntt_BuildTables produces. The context points at
 * them without copying or freeing, so they must outlive it. NULL computes
 * every table locally. */
HIFHE_ERROR RLWE_RlweContext_BuildWithTables(RlweContext *out, RlweParameter *param,
                                           uint64_t *const *tables);

/* Access the precomputed NTT or Barrett table for one modulus. The returned
 * pointer is owned by ctx. Do not free it. */
const NttTables    *RLWE_RlweContext_GetNttTablesByModulus (const RlweContext *ctx, Modulus q);
const BarrettConst *RLWE_RlweContext_GetBarrettByModulus   (const RlweContext *ctx, Modulus q);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_RLWE_CONTEXT_H */
