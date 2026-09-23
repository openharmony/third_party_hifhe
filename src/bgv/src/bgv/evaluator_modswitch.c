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
 * Mod-switch: drop q_last = q_{L-1} from the chain.
 *
 * Per component, c' = (c - delta) / q_last with delta = c (mod q_last) and
 * delta = 0 (mod t), so the message survives mod t and the division is
 * exact. Writing delta = u * t:
 *
 *   u    = c_last * t^-1              (mod q_last), centred
 *   c'_i = (c_i - u*t) * q_last^-1    (mod q_i)
 *
 * The correction factor becomes f * q_last^-1 mod t.
 *
 * delta = u*t can exceed 64 bits, so it is only ever formed inside a
 * ModulusWide product reduced against the target limb.
 */

#include <string.h>
#include "bsl_sal.h"
#include "bgv/evaluator.h"
#include "bgv/ciphertext.h"
#include "kernel/modulus.h"
#include "rlwe/rlwe.h"
#include "rlwe/crt_ops.h"

HIFHE_ERROR BGV_Evaluator_ModSwitch(Ciphertext *out, const Ciphertext *in,
                                  const Evaluator *self)
{
    if (out == NULL || in == NULL || self == NULL) return HIFHE_NULL_INPUT;
    if (in->context == NULL || in->data == NULL) return HIFHE_NULL_INPUT;

    BGVContext *ctx = self->context;
    uint32_t L = in->config.crtConfig.rnsbase.size;
    if (L <= 1u) return HIFHE_MODSWITCH_EXHAUSTED;

    uint32_t N = ctx->rlweContext.parameter->polyDegree;
    uint32_t K = in->config.ciphertextSize;
    Modulus  t = ctx->bgvParameter->plainMod;
    const uint64_t *chain = in->config.crtConfig.rnsbase.data;
    Modulus qLast = chain[L - 1u];

    uint64_t invT = Kernel_ModInv(t % qLast, qLast);
    if (invT == 0u) return HIFHE_PARAM_INVALID;      /* t must be coprime to q_last */
    uint64_t invQLastModT = Kernel_ModInv(qLast % t, t);
    if (invQLastModT == 0u) return HIFHE_PARAM_INVALID;

    /* Coefficient-domain working copy of `in`. */
    Ciphertext work;
    memset(&work, 0, sizeof(work));
    int32_t r = BGV_Ciphertext_Copy(&work, in);
    if (r != HIFHE_SUCCESS) return r;
    for (uint32_t k = 0; k < K; ++k) {
        CrtPoly comp;
        r = BGV_Ciphertext_GetCrtPolyAt(&comp, k, &work);
        if (r != HIFHE_SUCCESS) {
            BGV_Ciphertext_Destroy(&work);
            return r;
        }
        r = RLWE_CrtPoly_ToPoly(&comp);
        if (r != HIFHE_SUCCESS) {
            BGV_Ciphertext_Destroy(&work);
            return r;
        }
    }

    /* Output on the truncated chain, in coefficient form. */
    uint32_t outL = L - 1u;
    RnsBase outBase;
    memset(&outBase, 0, sizeof(outBase));
    r = Uint64Vector_Create(&outBase, chain, outL);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(&work);
        return r;
    }

    CiphertextConfig cfg;
    uint64_t newFactor = Kernel_MulMod(in->config.correctionFactor % t, invQLastModT, t);
    r = BGV_CiphertextConfig_Create(&cfg, K, newFactor, &outBase);
    Uint64Vector_Destroy(&outBase);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(&work);
        return r;
    }
    cfg.crtConfig.dtype = HIFHE_POLY;
    cfg.caps            = in->config.caps;
    memcpy(cfg.seed, in->config.seed, sizeof(cfg.seed));

    BGV_Ciphertext_Destroy(out);
    r = BGV_Ciphertext_Create(out, &cfg, ctx);
    BGV_CiphertextConfig_Destroy(&cfg);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(&work);
        return r;
    }

    uint64_t halfQLast = qLast >> 1;
    for (uint32_t k = 0; k < K; ++k) {
        const uint64_t *last = work.data + (k * L + outL) * N;
        for (uint32_t i = 0; i < outL; ++i) {
            Modulus qi = chain[i];
            uint64_t invQLast = Kernel_ModInv(qLast % qi, qi);
            if (invQLast == 0u) {
                BGV_Ciphertext_Destroy(&work);
                BGV_Ciphertext_Destroy(out);
                return HIFHE_PARAM_INVALID;
            }
            uint64_t tModQi = t % qi;
            const uint64_t *src = work.data + (k * L + i) * N;
            uint64_t *dst = out->data + (k * outL + i) * N;
            for (uint32_t j = 0; j < N; ++j) {
                uint64_t u = Kernel_MulMod(last[j], invT, qLast);
                /* Centre u so |delta| stays small. */
                uint64_t mag;
                bool negative;
                if (u > halfQLast) {
                    mag = qLast - u;
                    negative = true;
                }
                else {
                    mag = u;
                    negative = false;
                }
                uint64_t deltaModQi = Kernel_MulMod(mag % qi, tModQi, qi);
                if (negative && deltaModQi != 0u) deltaModQi = qi - deltaModQi;
                uint64_t diff = src[j] + qi - deltaModQi;
                if (diff >= qi) diff -= qi;
                dst[j] = Kernel_MulMod(diff, invQLast, qi);
            }
        }
    }
    BGV_Ciphertext_Destroy(&work);

    /* Back to the NTT domain the rest of the pipeline expects. */
    for (uint32_t k = 0; k < K; ++k) {
        CrtPoly comp;
        r = BGV_Ciphertext_GetCrtPolyAt(&comp, k, out);
        if (r != HIFHE_SUCCESS) {
            BGV_Ciphertext_Destroy(out);
            return r;
        }
        r = RLWE_CrtPoly_ToNtt(&comp);
        if (r != HIFHE_SUCCESS) {
            BGV_Ciphertext_Destroy(out);
            return r;
        }
    }
    out->config.crtConfig.dtype = HIFHE_NTT;
    return HIFHE_SUCCESS;
}

