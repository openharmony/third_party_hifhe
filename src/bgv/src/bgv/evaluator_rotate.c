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
#include "hifhe_mem.h"
#include "hifhe_err_internal.h"
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
    if (step == 0) {
        return 1u;
    }
    uint64_t mag = (step > 0) ? (uint64_t)step : (uint64_t)(-(int64_t)step);
    uint64_t k = Kernel_PowMod(3u, mag, twoN);
    /* k is odd and twoN is a power of two, so the inverse exists. */
    return (step > 0) ? k : Kernel_ModInv(k, twoN);
}

static uint32_t BitRev(uint32_t x, uint32_t bits)
{
    uint32_t r = 0u;
    for (uint32_t i = 0; i < bits; ++i) {
        r = (r << 1) | (x & 1u);
        x >>= 1;
    }
    return r;
}

/*
 * sigma_k in the NTT domain is a pure permutation. Slot i of the forward
 * transform holds a(psi^(2*brv(i)+1)); sigma_k(a) evaluated there is
 * a(psi^(k*(2*brv(i)+1))), which is another slot of the same transform.
 * So perm[i] = brv(((k*(2*brv(i)+1) mod 2N) - 1) / 2), with no inverse or
 * forward transform on either component.
 */
static HIFHE_ERROR BuildNttPermutation(uint32_t *perm, uint32_t N, uint64_t k)
{
    uint32_t logN = 0u;
    for (uint32_t v = N; v > 1u; v >>= 1) {
        logN++;
    }
    const uint64_t mask = 2u * (uint64_t)N - 1u;
    for (uint32_t i = 0; i < N; ++i) {
        uint64_t e = ((uint64_t)(2u * BitRev(i, logN) + 1u) * (k & mask)) & mask;
        perm[i] = BitRev((uint32_t)(e >> 1), logN);
    }
    return HIFHE_SUCCESS;
}

/* sigma_k on one ciphertext component in NTT form, in place. */
static void PermuteComponentNtt(uint64_t *comp, uint64_t *scratch, const uint32_t *perm, uint32_t L, uint32_t N)
{
    for (uint32_t i = 0; i < L; ++i) {
        uint64_t *limb = comp + (size_t)i * N;
        memcpy(scratch, limb, N * sizeof(uint64_t));
        for (uint32_t j = 0; j < N; ++j) {
            limb[j] = scratch[perm[j]];
        }
    }
}

HIFHE_ERROR BGV_Evaluator_RotateByElt(Ciphertext *out, const Ciphertext *in, uint64_t galoisElt, const Evaluator *self)
{
    if (out == NULL || in == NULL || self == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (self->galoisKeys == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NO_GALOIS_KEY);
        return HIFHE_NO_GALOIS_KEY;
    }
    if (in->config.ciphertextSize != 2u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_CT_DEGREE_MISMATCH);
        return HIFHE_CT_DEGREE_MISMATCH;
    }
    const GaloisKeyPiece *gk = BGV_GaloisKeys_GetByElt(self->galoisKeys, galoisElt);
    if (gk == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NO_GALOIS_KEY);
        return HIFHE_NO_GALOIS_KEY;
    }

    BGVContext *ctx = self->context;
    uint32_t L = in->config.crtConfig.rnsbase.size;
    uint32_t N = ctx->rlweContext.parameter->polyDegree;
    /* Same level constraint as relinearize. */
    if (L != gk->rnsSize) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }

    if (in->config.crtConfig.dtype != HIFHE_NTT) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    if ((galoisElt & 1u) == 0u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }

    uint32_t *perm = (uint32_t *)HifheMalloc(N * (uint32_t)sizeof(uint32_t));
    uint64_t *scratch = (uint64_t *)HifheMalloc(N * (uint32_t)sizeof(uint64_t));
    if (perm == NULL || scratch == NULL) {
        HifheFree(perm);
        HifheFree(scratch);
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    (void)BuildNttPermutation(perm, N, galoisElt);

    /* Deep copy in to out, then permute each component in place. */
    int32_t r = BGV_Ciphertext_Destroy(out);
    if (r == HIFHE_SUCCESS) {
        r = BGV_Ciphertext_Copy(out, in);
    }
    if (r == HIFHE_SUCCESS) {
        for (uint32_t k = 0; k < 2u; ++k) {
            PermuteComponentNtt(out->data + (size_t)k * L * N, scratch, perm, L, N);
        }
    }
    HifheFree(perm);
    HifheFree(scratch);
    if (r != HIFHE_SUCCESS) {
        return r;
    }

    /* Key-switch the (permuted) c1 back under s. */
    CrtPoly c1;
    r = BGV_Ciphertext_GetCrtPolyAt(&c1, 1u, out);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(out);
        return r;
    }

    Ciphertext delta;
    r = BGV_Ciphertext_CreateSize2Ntt(&delta, out->config.correctionFactor, &out->config.crtConfig.rnsbase, ctx);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(out);
        return r;
    }

    r = BGV_KeySwitch_Run(&delta, &c1, gk->pieces, gk->rnsSize, gk->digits, ctx);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(&delta);
        BGV_Ciphertext_Destroy(out);
        return r;
    }

    /* out.c0 <- out.c0 + delta.c0;  out.c1 <- delta.c1  (replace, not add) */
    CrtPoly d0, d1;
    r = BGV_Ciphertext_GetCrtPolyAt(&d0, 0u, &delta);
    if (r == HIFHE_SUCCESS) {
        r = BGV_Ciphertext_AddCrtPolyAt(out, 0u, &d0);
    }
    if (r == HIFHE_SUCCESS) {
        r = BGV_Ciphertext_GetCrtPolyAt(&d1, 1u, &delta);
    }
    if (r == HIFHE_SUCCESS) {
        r = BGV_Ciphertext_SetCrtPolyAt(out, 1u, &d1);
    }
    BGV_Ciphertext_Destroy(&delta);
    return r;
}

HIFHE_ERROR BGV_Evaluator_RotateByStep(Ciphertext *out, const Ciphertext *in, int32_t steps, const Evaluator *self)
{
    if (in == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    uint32_t N = in->context->rlweContext.parameter->polyDegree;
    uint64_t k = BGV_GaloisEltForStep(steps, N);
    return BGV_Evaluator_RotateByElt(out, in, k, self);
}
