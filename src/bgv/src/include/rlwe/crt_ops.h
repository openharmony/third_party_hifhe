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

/* CRT/RNS polynomial arithmetic, composed over RnsPoly. */

#ifndef HIFHE_RLWE_CRT_OPS_H
#define HIFHE_RLWE_CRT_OPS_H

#include "hifhe_err.h"
#include "rlwe/rlwe.h"

#ifdef __cplusplus
extern "C" {
#endif

HIFHE_ERROR RLWE_CrtPoly_Add(CrtPoly *out, const CrtPoly *a, const CrtPoly *b);
HIFHE_ERROR RLWE_CrtPoly_Sub(CrtPoly *out, const CrtPoly *a, const CrtPoly *b);
HIFHE_ERROR RLWE_CrtPoly_Neg(CrtPoly *out, const CrtPoly *a);
HIFHE_ERROR RLWE_CrtPoly_MulDot(CrtPoly *out, const CrtPoly *a, const CrtPoly *b);
/* out += a * b, coefficient-wise per limb. */
HIFHE_ERROR RLWE_CrtPoly_MulDotAcc(CrtPoly *out, const CrtPoly *a, const CrtPoly *b);
/* out = a * x, the same scalar reduced against each limb. */
HIFHE_ERROR RLWE_CrtPoly_MulScalar(CrtPoly *out, const CrtPoly *a, uint64_t x);
/* out = a * x[i] in limb i, for factors too wide for one word. */
HIFHE_ERROR RLWE_CrtPoly_MulScalarPerLimb(CrtPoly *out, const CrtPoly *a, const uint64_t *xPerLimb);
/* Copy coefficients into `dst`'s existing storage. Works on a view. */
HIFHE_ERROR RLWE_CrtPoly_Assign(CrtPoly *dst, const CrtPoly *src);
/* One signed length-N vector into every limb, mapped into [0, q_i).
 * Leaves the poly in coefficient form. */
HIFHE_ERROR RLWE_CrtPoly_SetSigned(CrtPoly *self, const int64_t *v);

/* Convert between coefficient and NTT domains. Both polys must share
 * base + N. */
HIFHE_ERROR RLWE_CrtPoly_ToNtt(CrtPoly *self);
HIFHE_ERROR RLWE_CrtPoly_ToPoly(CrtPoly *self);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_RLWE_CRT_OPS_H */
