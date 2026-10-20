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
 * Key switching; see bgv/keyswitch.h for the gadget.
 *
 *   1. inv-NTT polyNtt to coefficient form
 *   2. lift each limb:  y_i[k] = p_i[k] * qhat_i^-1 mod q_i
 *   3. split y_i into base-2^16 digits (each < 2^16, so it embeds
 *      unchanged into every limb)
 *   4. NTT each digit polynomial and accumulate digit * kswPiece(i, j)
 */

#include <string.h>
#include "bsl_sal.h"
#include "bgv/keyswitch.h"
#include "bgv/keys.h"
#include "bgv/ciphertext.h"
#include "kernel/modulus.h"
#include "kernel/ntt.h"
#include "rlwe/rlwe.h"
#include "rlwe/crt_ops.h"
#include "rlwe/rns_ops.h"
#include "rlwe/rlwe_context.h"

/* Adds (digit*kswPiece.c0, digit*kswPiece.c1) to (out.c0, out.c1).
 * `digitNtt` is one CrtPoly in NTT form. */
static HIFHE_ERROR BGV_KeySwitch_ApplyDigit(Ciphertext *out, const CrtPoly *digitNtt,
                                          const Ciphertext *kswPiece, BGVContext *ctx)
{
    if (out == NULL || digitNtt == NULL || kswPiece == NULL || ctx == NULL) return HIFHE_NULL_INPUT;
    for (uint32_t k = 0; k < 2u; ++k) {
        CrtPoly kv, ov;
        int32_t r = BGV_Ciphertext_GetCrtPolyAt(&kv, k, kswPiece);
        if (r != HIFHE_SUCCESS) return r;
        r = BGV_Ciphertext_GetCrtPolyAt(&ov, k, out);
        if (r != HIFHE_SUCCESS) return r;
        r = RLWE_CrtPoly_MulDotAcc(&ov, digitNtt, &kv);
        if (r != HIFHE_SUCCESS) return r;
    }
    return HIFHE_SUCCESS;
}

/* prod_{m != skip} base[m] mod q. */
static uint64_t QHatMod(const RnsBase *base, uint32_t skip, Modulus q)
{
    uint64_t acc = 1u % q;
    for (uint32_t m = 0; m < base->size; ++m) {
        if (m == skip) continue;
        acc = Kernel_MulMod(acc, base->data[m] % q, q);
    }
    return acc;
}

HIFHE_ERROR BGV_KeySwitch_GadgetFactor(uint64_t *out, const RnsBase *base,
                                     uint32_t limbIndex, uint32_t digit)
{
    if (out == NULL || base == NULL) return HIFHE_NULL_INPUT;
    if (limbIndex >= base->size) return HIFHE_PARAM_INVALID;
    for (uint32_t l = 0; l < base->size; ++l) {
        Modulus ql = base->data[l];
        uint64_t acc = QHatMod(base, limbIndex, ql);
        if (digit > 0u) {
            uint64_t tPow = Kernel_PowMod(BGV_KSW_T % ql, (uint64_t)digit, ql);
            acc = Kernel_MulMod(acc, tPow, ql);
        }
        out[l] = acc;
    }
    return HIFHE_SUCCESS;
}

/* qhat_i^-1 mod q_i, with qhat_i = prod_{m != i} q_m. */
static uint64_t QHatInvModQi(const RnsBase *base, uint32_t i)
{
    Modulus qi = base->data[i];
    return Kernel_ModInv(QHatMod(base, i, qi), qi);
}

HIFHE_ERROR BGV_KeySwitch_Run(Ciphertext *out, const CrtPoly *polyNtt,
                            const Ciphertext *kswPieces,
                            uint32_t rnsSize, uint32_t digits,
                            BGVContext *ctx)
{
    if (out == NULL || polyNtt == NULL || kswPieces == NULL || ctx == NULL) return HIFHE_NULL_INPUT;
    if (out->config.ciphertextSize != 2u) return HIFHE_CT_DEGREE_MISMATCH;

    const RnsBase *base = &ctx->rlweContext.cipherRnsBase;
    uint32_t L = base->size;
    uint32_t N = ctx->rlweContext.parameter->polyDegree;
    /* The gadget bakes in qhat_i for a fixed chain, so relinearize / rotate
     * before mod-switching. */
    if (rnsSize != L || digits == 0u) return HIFHE_PARAM_INVALID;
    if (polyNtt->config.rnsbase.size != L) return HIFHE_PARAM_INVALID;

    memset(out->data, 0, out->dataSize * sizeof(uint64_t));

    /* Coefficient-form copy of the target factor. */
    CrtPoly polyCoeff;
    memset(&polyCoeff, 0, sizeof(polyCoeff));
    int32_t r = RLWE_CrtPoly_Copy(&polyCoeff, polyNtt);
    if (r != HIFHE_SUCCESS) return r;
    r = RLWE_CrtPoly_ToPoly(&polyCoeff);
    if (r != HIFHE_SUCCESS) {
        RLWE_CrtPoly_Destroy(&polyCoeff);
        return r;
    }

    /* Reusable digit polynomial over the whole chain. */
    CrtPoly digitPoly;
    memset(&digitPoly, 0, sizeof(digitPoly));
    r = RLWE_CrtPoly_Copy(&digitPoly, &polyCoeff);
    if (r != HIFHE_SUCCESS) {
        RLWE_CrtPoly_Destroy(&polyCoeff);
        return r;
    }

    Uint64Vector lifted;
    r = Uint64Vector_Create(&lifted, NULL, N);
    if (r != HIFHE_SUCCESS) {
        RLWE_CrtPoly_Destroy(&digitPoly);
        RLWE_CrtPoly_Destroy(&polyCoeff);
        return r;
    }
    uint64_t *y = lifted.data;

    for (uint32_t i = 0; i < L && r == HIFHE_SUCCESS; ++i) {
        uint64_t qhatInv = QHatInvModQi(base, i);
        if (qhatInv == 0u && L > 1u) {
            r = HIFHE_INTERNAL;
            break;
        }
        RnsPoly srcLimb, yLimb;
        r = RLWE_CrtPoly_GetRnsPolyAt(&srcLimb, i, &polyCoeff);
        if (r != HIFHE_SUCCESS) break;
        yLimb = srcLimb;
        yLimb.data = y;
        r = RLWE_RnsPoly_MulScalar(&yLimb, &srcLimb, (L == 1u) ? 1u : qhatInv);
        if (r != HIFHE_SUCCESS) break;

        for (uint32_t j = 0; j < digits; ++j) {
            uint32_t shift = j * BGV_KSW_LOG_T;
            for (uint32_t l = 0; l < L; ++l) {
                uint64_t *dst = digitPoly.data + l * N;
                for (uint32_t k = 0; k < N; ++k) {
                    /* digit < 2^16 <= q_l, so no reduction is needed. */
                    dst[k] = (shift >= 64u) ? 0u : ((y[k] >> shift) & BGV_KSW_MASK);
                }
            }
            digitPoly.config.dtype = HIFHE_POLY;
            r = RLWE_CrtPoly_ToNtt(&digitPoly);
            if (r != HIFHE_SUCCESS) break;
            r = BGV_KeySwitch_ApplyDigit(out, &digitPoly, &kswPieces[i * digits + j], ctx);
            if (r != HIFHE_SUCCESS) break;
        }
    }

    Uint64Vector_Destroy(&lifted);
    RLWE_CrtPoly_Destroy(&digitPoly);
    RLWE_CrtPoly_Destroy(&polyCoeff);
    return r;
}

