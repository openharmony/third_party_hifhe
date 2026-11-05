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
 *   3. split y_i into base-2^logT digits, reduced into every limb (a digit
 *      below the smallest modulus embeds unchanged)
 *   4. NTT each digit polynomial and accumulate digit * kswPiece(i, j)
 */

#include <stdbool.h>
#include <string.h>
#include "hifhe_mem.h"
#include "hifhe_err_internal.h"
#include "bgv/keyswitch.h"
#include "bgv/params_check.h"
#include "bgv/keys.h"
#include "bgv/ciphertext.h"
#include "kernel/modulus.h"
#include "kernel/ntt.h"
#include "rlwe/rlwe.h"
#include "rlwe/crt_ops.h"
#include "rlwe/rns_ops.h"
#include "rlwe/rlwe_context.h"

/* Upper bound on how many products below q^2 fit in an unsigned 128-bit
 * accumulator on top of one already-reduced residue. */
static uint64_t LazyTermLimit(Modulus q)
{
    uint64_t qm1 = q - 1u;
    Uint128 room = Kernel_U128Sub(Kernel_U128Make(UINT64_MAX, UINT64_MAX), Kernel_U128From64(qm1));
    Uint128 n = Kernel_U128Div(room, Kernel_U128Mul(qm1, qm1));
    return (n.hi != 0u) ? UINT64_MAX : n.lo;
}

/* Reduce every accumulator of limb l to [0, q_l). The result stays in the
 * accumulator, so later terms keep adding on top of it. */
static void FoldLimb(Uint128 *acc, uint32_t N, const BarrettConst *bc)
{
    for (uint32_t k = 0; k < N; ++k) {
        acc[k] = Kernel_U128From64(Kernel_BarrettReduce128Inl(acc[k].hi, acc[k].lo, bc));
    }
}

/* prod_{m != skip} base[m] mod q. */
static uint64_t QHatMod(const RnsBase *base, uint32_t skip, Modulus q)
{
    uint64_t acc = 1u % q;
    for (uint32_t m = 0; m < base->size; ++m) {
        if (m == skip) {
            continue;
        }
        acc = Kernel_MulMod(acc, base->data[m] % q, q);
    }
    return acc;
}

static uint32_t BitLen(uint64_t v)
{
    uint32_t bits = 0u;
    for (; v > 0u; v >>= 1) {
        bits++;
    }
    return bits;
}

uint32_t BGV_KeySwitch_LogT(const RnsBase *base, uint32_t digits)
{
    uint32_t widest = 1u;
    if (base != NULL) {
        for (uint32_t i = 0; i < base->size; ++i) {
            uint32_t b = BitLen(base->data[i]);
            if (b > widest) {
                widest = b;
            }
        }
    }
    if (digits == 0u) {
        digits = 1u;
    }
    return (widest + digits - 1u) / digits;
}

uint32_t BGV_KeySwitch_DefaultDigits(const RnsBase *base, uint32_t polyDegree, Modulus plainMod)
{
    uint32_t legacy = (BGV_KeySwitch_LogT(base, 1u) + BGV_KSW_LOG_T - 1u) / BGV_KSW_LOG_T;
    if (base == NULL || base->size < 3u) {
        return legacy;
    }
    uint32_t L = base->size;
    uint32_t logQ = 0u;
    for (uint32_t i = 0; i < L; ++i) {
        logQ += BitLen(base->data[i]) - 1u; /* floor */
    }
    uint32_t lastBits = BitLen(base->data[L - 1u]);
    uint32_t tBits = BitLen(plainMod);
    uint32_t spend = lastBits + tBits + BGV_KSW_NOISE_MARGIN_BITS;
    if (logQ <= spend) {
        return legacy;
    }
    uint32_t allowed = logQ - spend;
    for (uint32_t d = 1u; d < legacy; ++d) {
        /* sqrt(N * L * d) rounded up, plus 3 bits for the error tail. */
        uint32_t spread = (Kernel_Log2Ceil((uint64_t)polyDegree * L * d) + 1u) / 2u;
        uint32_t est = tBits + BGV_KeySwitch_LogT(base, d) + spread + 3u;
        if (est <= allowed) {
            return d;
        }
    }
    return legacy;
}

HIFHE_ERROR BGV_KeySwitch_GadgetFactor(uint64_t *out, const RnsBase *base, uint32_t limbIndex, uint32_t digit,
                                       uint32_t logT)
{
    if (out == NULL || base == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (limbIndex >= base->size) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    if (logT == 0u || logT >= 64u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    for (uint32_t l = 0; l < base->size; ++l) {
        Modulus ql = base->data[l];
        uint64_t acc = QHatMod(base, limbIndex, ql);
        if (digit > 0u) {
            uint64_t tPow = Kernel_PowMod((1ull << logT) % ql, (uint64_t)digit, ql);
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

/*
 * The L * digits products for one output coefficient are summed in 128 bits
 * and reduced once at the end, instead of a Barrett reduction and a modular
 * add per digit. Every product is below q_l^2, so a 44-bit chain never comes
 * close to the 128-bit bound; wider limbs fold early (LazyTermLimit).
 */
HIFHE_ERROR BGV_KeySwitch_Run(Ciphertext *out, const CrtPoly *polyNtt, const Ciphertext *kswPieces, uint32_t rnsSize,
                              uint32_t digits, BGVContext *ctx)
{
    if (out == NULL || polyNtt == NULL || kswPieces == NULL || ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (out->config.ciphertextSize != 2u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_CT_DEGREE_MISMATCH);
        return HIFHE_CT_DEGREE_MISMATCH;
    }

    const RnsBase *base = &ctx->rlweContext.cipherRnsBase;
    uint32_t L = base->size;
    uint32_t N = ctx->rlweContext.parameter->polyDegree;
    /* The gadget bakes in qhat_i for a fixed chain, so relinearize / rotate
     * before mod-switching. */
    if (rnsSize != L || digits == 0u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    if (polyNtt->config.rnsbase.size != L) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    if (out->config.crtConfig.rnsbase.size != L) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }

    const BarrettConst *bcs[HIFHE_BGV_MAX_CHAIN_LEN];
    uint64_t limit = UINT64_MAX;
    if (L > HIFHE_BGV_MAX_CHAIN_LEN) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    for (uint32_t l = 0; l < L; ++l) {
        bcs[l] = RLWE_RlweContext_GetBarrettByModulus(&ctx->rlweContext, base->data[l]);
        if (bcs[l] == NULL) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_INTERNAL);
            return HIFHE_INTERNAL;
        }
        uint64_t lim = LazyTermLimit(base->data[l]);
        if (lim < limit) {
            limit = lim;
        }
    }
    if (limit == 0u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_INTERNAL);
        return HIFHE_INTERNAL;
    }

    uint32_t logT = BGV_KeySwitch_LogT(base, digits);
    if (logT == 0u || logT >= 64u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    const uint64_t digitMask = (1ull << logT) - 1u;
    /* A digit below every modulus embeds unchanged; a wider one (a single
     * digit spanning a limb larger than its neighbours) is reduced per limb. */
    bool reduceDigits = false;
    for (uint32_t l = 0; l < L; ++l) {
        if (base->data[l] <= digitMask) {
            reduceDigits = true;
        }
    }

    /* Coefficient-form copy of the target factor. */
    CrtPoly polyCoeff;
    memset(&polyCoeff, 0, sizeof(polyCoeff));
    int32_t r = RLWE_CrtPoly_Copy(&polyCoeff, polyNtt);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
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

    /* acc[0] and acc[1] for out.c0 / out.c1, limb-major like the ciphertext. */
    size_t accWords = (size_t)2u * L * N;
    Uint128 *acc = (Uint128 *)HifheCalloc((uint32_t)accWords, (uint32_t)sizeof(Uint128));
    if (acc == NULL) {
        Uint64Vector_Destroy(&lifted);
        RLWE_CrtPoly_Destroy(&digitPoly);
        RLWE_CrtPoly_Destroy(&polyCoeff);
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    uint64_t pending = 0u; /* products added since the last fold */

    for (uint32_t i = 0; i < L && r == HIFHE_SUCCESS; ++i) {
        uint64_t qhatInv = QHatInvModQi(base, i);
        if (qhatInv == 0u && L > 1u) {
            r = HIFHE_INTERNAL;
            break;
        }
        RnsPoly srcLimb, yLimb;
        r = RLWE_CrtPoly_GetRnsPolyAt(&srcLimb, i, &polyCoeff);
        if (r != HIFHE_SUCCESS) {
            break;
        }
        yLimb = srcLimb;
        yLimb.data = y;
        r = RLWE_RnsPoly_MulScalar(&yLimb, &srcLimb, (L == 1u) ? 1u : qhatInv);
        if (r != HIFHE_SUCCESS) {
            break;
        }

        for (uint32_t j = 0; j < digits; ++j) {
            const Ciphertext *piece = &kswPieces[i * digits + j];
            if (piece->config.ciphertextSize < 2u || piece->config.crtConfig.rnsbase.size != L) {
                r = HIFHE_PARAM_INVALID;
                break;
            }
            uint32_t shift = j * logT;
            for (uint32_t l = 0; l < L; ++l) {
                uint64_t *dst = digitPoly.data + l * N;
                if (shift >= 64u) {
                    memset(dst, 0, N * sizeof(uint64_t));
                } else if (!reduceDigits) {
                    for (uint32_t k = 0; k < N; ++k) {
                        dst[k] = (y[k] >> shift) & digitMask;
                    }
                } else {
                    for (uint32_t k = 0; k < N; ++k) {
                        dst[k] = Kernel_BarrettReduce64Inl((y[k] >> shift) & digitMask, bcs[l]);
                    }
                }
            }
            digitPoly.config.dtype = HIFHE_POLY;
            r = RLWE_CrtPoly_ToNtt(&digitPoly);
            if (r != HIFHE_SUCCESS) {
                break;
            }

            if (pending == limit) {
                for (uint32_t l = 0; l < 2u * L; ++l) {
                    FoldLimb(acc + (size_t)l * N, N, bcs[l % L]);
                }
                pending = 0u;
            }
            for (uint32_t c = 0; c < 2u; ++c) {
                const uint64_t *kc = piece->data + (size_t)c * L * N;
                Uint128 *ac = acc + (size_t)c * L * N;
                for (uint32_t l = 0; l < L; ++l) {
                    const uint64_t *d = digitPoly.data + (size_t)l * N;
                    const uint64_t *kv = kc + (size_t)l * N;
                    Uint128 *av = ac + (size_t)l * N;
                    for (uint32_t k = 0; k < N; ++k) {
                        av[k] = Kernel_U128MulAdd(av[k], d[k], kv[k]);
                    }
                }
            }
            pending++;
        }
    }

    if (r == HIFHE_SUCCESS) {
        for (uint32_t l = 0; l < 2u * L; ++l) {
            const Uint128 *av = acc + (size_t)l * N;
            uint64_t *ov = out->data + (size_t)l * N;
            for (uint32_t k = 0; k < N; ++k) {
                ov[k] = Kernel_BarrettReduce128Inl(av[k].hi, av[k].lo, bcs[l % L]);
            }
        }
    }

    HifheFree(acc);
    Uint64Vector_Destroy(&lifted);
    RLWE_CrtPoly_Destroy(&digitPoly);
    RLWE_CrtPoly_Destroy(&polyCoeff);
    return r;
}
