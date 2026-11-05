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

/* BGV homomorphic operations over (context, relinKeys?, galoisKeys?). */

#ifndef HIFHE_BGV_EVALUATOR_H
#define HIFHE_BGV_EVALUATOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "hifhe_err.h"
#include "bgv/bgv.h"
#include "bgv/plaintext.h"
#include "bgv/ciphertext.h"
#include "bgv/keys.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    BGVContext *context; /* not owned */
    const RelinKeys *relinKeys; /* not owned; may be NULL */
    const GaloisKeys *galoisKeys; /* not owned; may be NULL */
} Evaluator;

HIFHE_ERROR BGV_Evaluator_Create(Evaluator *self, BGVContext *ctx, const RelinKeys *rlk, const GaloisKeys *glk);
HIFHE_ERROR BGV_Evaluator_Destroy(Evaluator *self);

/* ---- unary ---- */
HIFHE_ERROR BGV_Evaluator_Neg(Ciphertext *out, const Ciphertext *a, const Evaluator *self);

/* ---- add ---- */
HIFHE_ERROR BGV_Evaluator_AddCtCt(Ciphertext *out, const Ciphertext *a, const Ciphertext *b, const Evaluator *self);
HIFHE_ERROR BGV_Evaluator_AddCtPt(Ciphertext *out, const Ciphertext *a, const Plaintext *b, const Evaluator *self);

/* ---- multiply ---- */
HIFHE_ERROR BGV_Evaluator_MulCtPt(Ciphertext *out, const Ciphertext *a, const Plaintext *b, const Evaluator *self);
HIFHE_ERROR BGV_Evaluator_MulCtScalar(Ciphertext *out, const Ciphertext *a, uint64_t x, const Evaluator *self);
/* ct*ct: produces a size-3 ciphertext; call Relinearize afterwards. */
HIFHE_ERROR BGV_Evaluator_MulCtCt(Ciphertext *out, const Ciphertext *a, const Ciphertext *b, const Evaluator *self);

HIFHE_ERROR BGV_Evaluator_Relinearize(Ciphertext *out, const Ciphertext *in, const Evaluator *self);

/* ---- rotation (Galois) ----
 * sigma_k: X -> X^k, k = 3^step mod 2N. Effect on the slots depends on
 * BGVContext::useSlotMap:
 *   off  slot j is at zeta^(2*brv(j)+1), so bit-reversal scrambles the
 *        shift. N=2048: slot 0 -> slot 1365 for +1.
 *   on   2 x (N/2) matrix; +1 shifts each row left, rows never mix, step
 *        N/2 is the identity. Row swap is sigma_{-1}, via RotateByElt(2N-1).
 */
/* k = 3^step mod 2N, inverted for a negative step. 3 generates
 * (Z/2NZ)* / <-1> for power-of-two N. */
uint64_t BGV_GaloisEltForStep(int32_t step, uint32_t N);
HIFHE_ERROR BGV_Evaluator_RotateByStep(Ciphertext *out, const Ciphertext *in, int32_t steps, const Evaluator *self);
HIFHE_ERROR BGV_Evaluator_RotateByElt(Ciphertext *out, const Ciphertext *in, uint64_t galoisElt, const Evaluator *self);

/* ---- level ops ---- */
HIFHE_ERROR BGV_Evaluator_ModSwitch(Ciphertext *out, const Ciphertext *in, const Evaluator *self);

/* ---- rerandomization ---- */
HIFHE_ERROR BGV_Evaluator_Rerandomize(Ciphertext *out, const Ciphertext *in, const Evaluator *self);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_BGV_EVALUATOR_H */
