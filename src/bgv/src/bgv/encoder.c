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
 * BGV encoder. Slot packing always: inverse negacyclic NTT mod t,
 * hence t = 1 mod 2N. BGVContext.useSlotMap places slot i:
 *
 *   0 (default)  at NTT position i, the predecessor's layout
 *   1            at slotMap[i], laying the slots out as a 2 x (N/2) matrix
 *
 * Encode leaves the plaintext on the full cipher base in NTT form. Decode
 * reverses it, recovers each coefficient as the signed integer its RNS
 * residues represent, and divides out the plaintext scale factor.
 */

#include <string.h>
#include "bsl_sal.h"
#include "bgv/encoder.h"
#include "bgv/plaintext.h"
#include "bgv/bgv.h"
#include "bgv/params_check.h"
#include "kernel/modulus.h"
#include "kernel/ntt.h"
#include "rlwe/rlwe.h"
#include "rlwe/crt_ops.h"

HIFHE_ERROR BGV_Encoder_Create(Encoder *out, BGVContext *ctx)
{
    if (out == NULL || ctx == NULL) return HIFHE_NULL_INPUT;
    out->context = ctx;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_Encoder_Destroy(Encoder *self)
{
    if (self == NULL) return HIFHE_NULL_INPUT;
    self->context = NULL;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_Encoder_Encode(Plaintext *out, const uint64_t *msg, uint32_t slotCount,
                             const Encoder *self)
{
    if (out == NULL || msg == NULL || self == NULL) return HIFHE_NULL_INPUT;
    BGVContext *ctx = self->context;
    uint32_t N = ctx->rlweContext.parameter->polyDegree;
    if (slotCount != N) return HIFHE_PARAM_INVALID;

    uint8_t useMap = BGV_BGVContext_GetUseSlotMap(ctx);
    int32_t pr = useMap ? BGV_BGVContext_EnsureSlotMap(ctx)
                        : BGV_BGVContext_EnsurePlainNtt(ctx);
    if (pr != HIFHE_SUCCESS) return pr;

    /* data == NULL: allocate with the default config. Else reuse. */
    if (out->data == NULL) {
        PlaintextConfig cfg;
        int32_t r = BGV_BGVContext_GetDefaultPlaintextConfig(&cfg, ctx);
        if (r != HIFHE_SUCCESS) return r;
        r = BGV_Plaintext_Create(out, &cfg, ctx);
        BGV_PlaintextConfig_Destroy(&cfg);
        if (r != HIFHE_SUCCESS) return r;
    }

    Modulus t = ctx->bgvParameter->plainMod;
    uint32_t L = out->config.crtConfig.rnsbase.size;

    /* Coefficient vector in [0, t), built once and replicated into limbs. */
    Uint64Vector coeff;
    int32_t cr = Uint64Vector_Create(&coeff, NULL, N);
    if (cr != HIFHE_SUCCESS) return cr;
    if (useMap) {
        const uint32_t *map = ctx->slotMap.data;
        for (uint32_t j = 0; j < N; ++j) coeff.data[map[j]] = msg[j] % t;
    } else {
        for (uint32_t j = 0; j < N; ++j) coeff.data[j] = msg[j] % t;
    }
    cr = Kernel_Ntt_Inverse(coeff.data, &ctx->ptNtt);
    if (cr != HIFHE_SUCCESS) {
        Uint64Vector_Destroy(&coeff);
        return cr;
    }

    for (uint32_t i = 0; i < L; ++i) {
        /* coeff[j] < t < q_i, so the residue is the value itself. */
        memcpy(out->data + i * N, coeff.data, N * sizeof(uint64_t));
    }
    Uint64Vector_Destroy(&coeff);

    out->config.crtConfig.dtype = HIFHE_POLY;
    out->config.scaleFactor     = 1u;
    out->config.caps            = HIFHE_CAP_LUT | (useMap ? HIFHE_CAP_SLOT_MAP : 0u);

    /* Move to the NTT domain. */
    CrtPoly view;
    int32_t r = RLWE_CrtPoly_CreateFromExist(&view, out->data, out->dataSize,
                                             &out->config.crtConfig, &ctx->rlweContext);
    if (r != HIFHE_SUCCESS) return r;
    r = RLWE_CrtPoly_ToNtt(&view);
    /* view is an alias; Destroy only reclaims its config. */
    RLWE_CrtPoly_Destroy(&view);
    if (r != HIFHE_SUCCESS) return r;
    out->config.crtConfig.dtype = HIFHE_NTT;
    return HIFHE_SUCCESS;
}

/* Recover, per coefficient, the small signed integer z the RNS residues
 * encode, reduced to [0, t).
 *
 *   z = sum_i y_i * qhat_i - v*Q,   y_i = [c_i * qhat_i^-1]_{q_i}
 *   v = floor(sum_i y_i / q_i)
 *
 * The fractional part of that sum is z/Q, which decides the sign. Q is never
 * formed: only Q mod t is needed, and v comes off a long-double accumulation
 * of y_i/q_i.
 */
static HIFHE_ERROR CrtCenteredModT(uint64_t *out, const uint64_t *data,
                                  const RnsBase *base, uint32_t N, Modulus t)
{
    uint32_t L = base->size;
    if (L == 0u || L > HIFHE_BGV_MAX_CHAIN_LEN) return HIFHE_PARAM_INVALID;

    uint64_t qhatModT[HIFHE_BGV_MAX_CHAIN_LEN];
    ModulusWide recip[HIFHE_BGV_MAX_CHAIN_LEN];   /* floor(2^96 / q_i) */
    ShoupConst qhatInvSc[HIFHE_BGV_MAX_CHAIN_LEN];
    ShoupConst qhatModTSc[HIFHE_BGV_MAX_CHAIN_LEN];
    BarrettConst tBarrett;
    uint64_t qModT = 1u % t;

    int32_t br = Kernel_BarrettConst_Init(&tBarrett, t);
    if (br != HIFHE_SUCCESS) return br;

    for (uint32_t i = 0; i < L; ++i) {
        Modulus qi = base->data[i];
        uint64_t prodModQi = 1u % qi;
        uint64_t prodModT  = 1u % t;
        for (uint32_t m = 0; m < L; ++m) {
            if (m == i) continue;
            prodModQi = Kernel_MulMod(prodModQi, base->data[m] % qi, qi);
            prodModT  = Kernel_MulMod(prodModT,  base->data[m] % t,  t);
        }
        uint64_t qhatInv = (L == 1u) ? 1u : Kernel_ModInv(prodModQi, qi);
        if (qhatInv == 0u && L > 1u) return HIFHE_INTERNAL;
        qhatModT[i] = prodModT;
        qModT = Kernel_MulMod(qModT, qi % t, t);

        /* Multipliers used by the coefficient loop are fixed per limb, so
         * each carries a Shoup constant. */
        if (Kernel_ShoupConst_Init(&qhatInvSc[i], qhatInv, qi) != HIFHE_SUCCESS ||
            Kernel_ShoupConst_Init(&qhatModTSc[i], qhatModT[i], t) != HIFHE_SUCCESS) {
            return HIFHE_INTERNAL;
        }
        /* Held at full width: parameter validation admits moduli from 20
         * bits, whose reciprocal does not fit a word. y < q_i keeps the
         * product below 2^96 either way. */
        recip[i] = (((ModulusWide)1u) << 96) / (ModulusWide)qi;
    }

    /*
     * The fractional part of sum_i y_i / q_i decides the sign. Above one half
     * means the representative lies in the upper half of [0, Q) and stands
     * for a negative number.
     *
     * The sum is accumulated in 128-bit fixed point with 96 fractional bits.
     * y_i * floor(2^96 / q_i) understates y_i * 2^96 / q_i by less than
     * y_i < q_i, so the total error stays below L * 2^-48. That is well
     * inside the noise margin and is identical on every target. A long double
     * accumulator would be 80-bit only on x86 and would lose precision or run
     * in soft float elsewhere.
     */
    for (uint32_t j = 0; j < N; ++j) {
        ModulusWide frac = 0;
        uint64_t acc = 0u;
        for (uint32_t i = 0; i < L; ++i) {
            uint64_t y = (L == 1u) ? data[j]
                                   : Kernel_ShoupMulMod(data[i * N + j], &qhatInvSc[i]);
            frac += (ModulusWide)y * recip[i];
            acc += Kernel_ShoupMulMod(Kernel_BarrettReduce64(y, &tBarrett), &qhatModTSc[i]);
            if (acc >= t) acc -= t;   /* Both addends are below t. */
        }
        uint64_t v = (uint64_t)(frac >> 96);
        uint64_t z = (acc + t - Kernel_MulMod(v % t, qModT, t)) % t;
        /* Fractional part above one half means the residues stand for z - Q. */
        if ((frac & (((ModulusWide)1u << 96) - 1u)) > ((ModulusWide)1u << 95)) {
            z = (z + t - qModT) % t;
        }
        out[j] = z;
    }
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_Encoder_Decode(uint64_t *msg, uint32_t slotCount,
                             const Plaintext *pt, const Encoder *self)
{
    if (msg == NULL || pt == NULL || self == NULL) return HIFHE_NULL_INPUT;
    BGVContext *ctx = self->context;
    uint32_t N = ctx->rlweContext.parameter->polyDegree;
    if (slotCount != N) return HIFHE_PARAM_INVALID;

    /* Decode as encoded, not as the context reads now. */
    bool useMap = (pt->config.caps & HIFHE_CAP_SLOT_MAP) != 0u;
    int32_t pr = useMap ? BGV_BGVContext_EnsureSlotMap(ctx)
                        : BGV_BGVContext_EnsurePlainNtt(ctx);
    if (pr != HIFHE_SUCCESS) return pr;

    /* Work on a coefficient-form copy. */
    Plaintext tmp;
    memset(&tmp, 0, sizeof(tmp));
    int32_t r = BGV_Plaintext_Copy(&tmp, pt);
    if (r != HIFHE_SUCCESS) return r;
    CrtPoly view;
    r = RLWE_CrtPoly_CreateFromExist(&view, tmp.data, tmp.dataSize,
                                     &tmp.config.crtConfig, &ctx->rlweContext);
    if (r != HIFHE_SUCCESS) {
        BGV_Plaintext_Destroy(&tmp);
        return r;
    }
    r = RLWE_CrtPoly_ToPoly(&view);
    RLWE_CrtPoly_Destroy(&view);
    if (r != HIFHE_SUCCESS) {
        BGV_Plaintext_Destroy(&tmp);
        return r;
    }

    Modulus t = ctx->bgvParameter->plainMod;
    r = CrtCenteredModT(msg, tmp.data, &tmp.config.crtConfig.rnsbase, N, t);
    BGV_Plaintext_Destroy(&tmp);
    if (r != HIFHE_SUCCESS) return r;

    /* Undo the accumulated BGV scale factor. */
    uint64_t scale = pt->config.scaleFactor % t;
    if (scale != 1u) {
        uint64_t inv = Kernel_ModInv(scale, t);
        if (inv == 0u) return HIFHE_PARAM_INVALID;
        for (uint32_t j = 0; j < N; ++j) msg[j] = Kernel_MulMod(msg[j], inv, t);
    }

    r = Kernel_Ntt_Forward(msg, &ctx->ptNtt);
    if (r != HIFHE_SUCCESS) return r;
    if (useMap) {
        Uint64Vector gathered;
        r = Uint64Vector_Create(&gathered, msg, N);
        if (r != HIFHE_SUCCESS) return r;
        const uint32_t *map = ctx->slotMap.data;
        for (uint32_t j = 0; j < N; ++j) msg[j] = gathered.data[map[j]];
        Uint64Vector_Destroy(&gathered);
    }
    return HIFHE_SUCCESS;
}

