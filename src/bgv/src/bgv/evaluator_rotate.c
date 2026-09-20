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
 * Rotation via the Galois automorphism sigma_k: X -> X^k, k odd.
 *
 * sigma_k maps a ciphertext under s to one under sigma_k(s),
 * c1 is switched back with the galois key at k:
 *
 *   out.c0 = sigma_k(c0) + ks(sigma_k(c1)).c0
 *   out.c1 =               ks(sigma_k(c1)).c1
 *
 * Under slot encoding this permutes slots;
 * under direct-coefficient encoding it permutes coefficients with sign.
 */

#include <string.h>
#include "bsl_sal.h"
#include "bgv/evaluator.h"
#include "bgv/ciphertext.h"
#include "bgv/keys.h"
#include "bgv/keyswitch.h"
#include "kernel/modulus.h"
#include "rlwe/rlwe.h"
#include "rlwe/crt_ops.h"
#include "rlwe/rlwe_context.h"

/* Galois element for a signed slot step: k = 3^step mod 2N. g = 3 generates
 * (Z/2NZ)* / <-1> for power-of-two N, matching SEAL / OpenFHE. */
uint64_t BGV_GaloisEltForStep(int32_t step, uint32_t N)
{
    uint64_t twoN = 2u * (uint64_t)N;
    if (step == 0) return 1u;
    uint64_t mag = (step > 0) ? (uint64_t)step : (uint64_t)(-(int64_t)step);
    uint64_t k = Kernel_PowMod(3u, mag, twoN);
    /* k is odd and twoN is a power of two, so the inverse exists. */
    return (step > 0) ? k : Kernel_ModInv(k, twoN);
}

/* sigma_k on one CrtPoly component, COEFF form.
 * idx = (j*k) mod 2N; idx >= N flips sign and subtracts N. */
static HIFHE_ERROR PermuteCoeffPoly(uint64_t *dst, const uint64_t *src,
                                   uint32_t N, Modulus q, uint64_t k)
{
    /* j -> (j*k mod 2N) mod N is a bijection on Z_N for odd k,
     * so the loop writes every dst slot and needs no pre-clear.
     *
     * 2N is a power of two, so the reduction is a mask.
     * idx advances by k per step, which removes the multiply. */
    const uint64_t twoN = 2u * (uint64_t)N;
    const uint64_t mask = twoN - 1u;
    uint64_t idx = 0u;
    for (uint32_t j = 0; j < N; ++j) {
        uint64_t at = idx;
        uint64_t v = src[j];
        if (at >= N) {
            at -= N;
            v = (v == 0u) ? 0u : (q - v);
        }
        dst[at] = v;
        idx = (idx + k) & mask;
    }
    return HIFHE_SUCCESS;
}

/* sigma_k on one ciphertext component. In and out in NTT form. */
static HIFHE_ERROR PermuteComponent(uint64_t *comp, uint64_t k, BGVContext *ctx)
{
    uint32_t L = ctx->rlweContext.cipherRnsBase.size;
    uint32_t N = ctx->rlweContext.parameter->polyDegree;
    /* Build a temp CrtPoly view, ToPoly, permute, ToNtt. */
    CrtPoly view;
    CrtPolyConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    int32_t r = Uint64Vector_Create(&cfg.rnsbase, ctx->rlweContext.cipherRnsBase.data, L);
    if (r != HIFHE_SUCCESS) return r;
    cfg.dtype = HIFHE_NTT;
    r = RLWE_CrtPoly_CreateFromExist(&view, comp, L * N, &cfg, &ctx->rlweContext);
    Uint64Vector_Destroy(&cfg.rnsbase);
    if (r != HIFHE_SUCCESS) return r;
    r = RLWE_CrtPoly_ToPoly(&view);
    if (r != HIFHE_SUCCESS) { RLWE_CrtPoly_Destroy(&view); return r; }

    Uint64Vector scratch;
    r = Uint64Vector_Create(&scratch, NULL, N);
    if (r != HIFHE_SUCCESS) { RLWE_CrtPoly_Destroy(&view); return r; }
    for (uint32_t i = 0; i < L; ++i) {
        Modulus q = ctx->rlweContext.cipherRnsBase.data[i];
        memcpy(scratch.data, comp + i * N, N * sizeof(uint64_t));
        PermuteCoeffPoly(comp + i * N, scratch.data, N, q, k);
    }
    Uint64Vector_Destroy(&scratch);

    r = RLWE_CrtPoly_ToNtt(&view);
    RLWE_CrtPoly_Destroy(&view);
    return r;
}

HIFHE_ERROR BGV_Evaluator_RotateByElt(Ciphertext *out, const Ciphertext *in,
                                    uint64_t galoisElt, const Evaluator *self)
{
    if (out == NULL || in == NULL || self == NULL) return HIFHE_NULL_INPUT;
    if (self->galoisKeys == NULL) return HIFHE_NO_GALOIS_KEY;
    if (in->config.ciphertextSize != 2u) return HIFHE_CT_DEGREE_MISMATCH;
    const GaloisKeyPiece *gk = BGV_GaloisKeys_GetByElt(self->galoisKeys, galoisElt);
    if (gk == NULL) return HIFHE_NO_GALOIS_KEY;

    BGVContext *ctx = self->context;
    uint32_t L = in->config.crtConfig.rnsbase.size;
    uint32_t N = ctx->rlweContext.parameter->polyDegree;
    /* Same level constraint as relinearize. */
    if (L != gk->rnsSize) return HIFHE_PARAM_INVALID;

    /* Deep copy in to out, then permute each component in place. */
    int32_t r = BGV_Ciphertext_Destroy(out);
    if (r != HIFHE_SUCCESS) return r;
    r = BGV_Ciphertext_Copy(out, in);
    if (r != HIFHE_SUCCESS) return r;
    for (uint32_t k = 0; k < 2u; ++k) {
        r = PermuteComponent(out->data + k * L * N, galoisElt, ctx);
        if (r != HIFHE_SUCCESS) { BGV_Ciphertext_Destroy(out); return r; }
    }

    /* Key-switch the (permuted) c1 back under s. */
    CrtPoly c1;
    r = BGV_Ciphertext_GetCrtPolyAt(&c1, 1u, out);
    if (r != HIFHE_SUCCESS) { BGV_Ciphertext_Destroy(out); return r; }

    Ciphertext delta;
    r = BGV_Ciphertext_CreateSize2Ntt(&delta, out->config.correctionFactor,
                                      &out->config.crtConfig.rnsbase, ctx);
    if (r != HIFHE_SUCCESS) { BGV_Ciphertext_Destroy(out); return r; }

    r = BGV_KeySwitch_Run(&delta, &c1, gk->pieces, gk->rnsSize, gk->digits, ctx);
    if (r != HIFHE_SUCCESS) { BGV_Ciphertext_Destroy(&delta); BGV_Ciphertext_Destroy(out); return r; }

    /* out.c0 <- out.c0 + delta.c0;  out.c1 <- delta.c1  (replace, not add) */
    CrtPoly d0, d1;
    r = BGV_Ciphertext_GetCrtPolyAt(&d0, 0u, &delta);
    if (r == HIFHE_SUCCESS) r = BGV_Ciphertext_AddCrtPolyAt(out, 0u, &d0);
    if (r == HIFHE_SUCCESS) r = BGV_Ciphertext_GetCrtPolyAt(&d1, 1u, &delta);
    if (r == HIFHE_SUCCESS) r = BGV_Ciphertext_SetCrtPolyAt(out, 1u, &d1);
    BGV_Ciphertext_Destroy(&delta);
    return r;
}

HIFHE_ERROR BGV_Evaluator_RotateByStep(Ciphertext *out, const Ciphertext *in,
                                     int32_t steps, const Evaluator *self)
{
    if (in == NULL) return HIFHE_NULL_INPUT;
    uint32_t N = in->context->rlweContext.parameter->polyDegree;
    uint64_t k = BGV_GaloisEltForStep(steps, N);
    return BGV_Evaluator_RotateByElt(out, in, k, self);
}

