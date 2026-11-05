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

/* Single-modulus polynomial arithmetic; operands share RnsPoly's modulus. */

#ifndef HIFHE_RLWE_RNS_OPS_H
#define HIFHE_RLWE_RNS_OPS_H

#include "hifhe_err.h"
#include "rlwe/rlwe.h"

#ifdef __cplusplus
extern "C" {
#endif

HIFHE_ERROR RLWE_RnsPoly_Add(RnsPoly *out, const RnsPoly *a, const RnsPoly *b);
HIFHE_ERROR RLWE_RnsPoly_Sub(RnsPoly *out, const RnsPoly *a, const RnsPoly *b);
HIFHE_ERROR RLWE_RnsPoly_Neg(RnsPoly *out, const RnsPoly *a);
/* Coefficient-wise product (NTT-domain multiply for two HIFHE_NTT polys). */
HIFHE_ERROR RLWE_RnsPoly_MulDot(RnsPoly *out, const RnsPoly *a, const RnsPoly *b);
/* out += a * b, coefficient-wise. */
HIFHE_ERROR RLWE_RnsPoly_MulDotAcc(RnsPoly *out, const RnsPoly *a, const RnsPoly *b);
/* out = a * x, x reduced here. */
HIFHE_ERROR RLWE_RnsPoly_MulScalar(RnsPoly *out, const RnsPoly *a, uint64_t x);
/* `v[0..dataSize)` signed, mapped into [0, q). */
HIFHE_ERROR RLWE_RnsPoly_SetSigned(RnsPoly *self, const int64_t *v);
HIFHE_ERROR RLWE_RnsPoly_ToNtt(RnsPoly *self);
HIFHE_ERROR RLWE_RnsPoly_ToPoly(RnsPoly *self);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_RLWE_RNS_OPS_H */
