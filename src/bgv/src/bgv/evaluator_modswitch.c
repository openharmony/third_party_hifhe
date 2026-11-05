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
 * delta = u*t can exceed 64 bits, so it is only ever formed reduced
 * against the target limb.
 *
 * Everything but delta is linear, so the work stays in the NTT domain: only
 * the dropped limb goes to coefficient form (to read off u), and delta is
 * transformed once into each surviving limb. That is K inverse and
 * K*(L-1) forward transforms, against K*L inverse and K*(L-1) forward when
 * the whole ciphertext round-trips through coefficient form.
 */

#include <string.h>
#include "hifhe_mem.h"
#include "hifhe_err_internal.h"
#include "bgv/evaluator.h"
#include "bgv/ciphertext.h"
#include "kernel/modulus.h"
#include "rlwe/rlwe.h"
#include "rlwe/crt_ops.h"
#include "rlwe/rlwe_context.h"
#include "kernel/ntt.h"
#include "bgv/params_check.h"

HIFHE_ERROR BGV_Evaluator_ModSwitch(Ciphertext *out, const Ciphertext *in, const Evaluator *self)
{
    if (out == NULL || in == NULL || self == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (in->context == NULL || in->data == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }

    BGVContext *ctx = self->context;
    uint32_t L = in->config.crtConfig.rnsbase.size;
    if (L <= 1u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MODSWITCH_EXHAUSTED);
        return HIFHE_MODSWITCH_EXHAUSTED;
    }

    uint32_t N = ctx->rlweContext.parameter->polyDegree;
    uint32_t K = in->config.ciphertextSize;
    Modulus t = ctx->bgvParameter->plainMod;
    const uint64_t *chain = in->config.crtConfig.rnsbase.data;
    Modulus qLast = chain[L - 1u];

    uint64_t invT = Kernel_ModInv(t % qLast, qLast);
    if (invT == 0u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID; /* t must be coprime to q_last */
    }
    uint64_t invQLastModT = Kernel_ModInv(qLast % t, t);
    if (invQLastModT == 0u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }

    /* NTT-domain view of `in`; a coefficient-form input is converted once. */
    Ciphertext work;
    memset(&work, 0, sizeof(work));
    const Ciphertext *src = in;
    int32_t r = HIFHE_SUCCESS;
    if (in->config.crtConfig.dtype != HIFHE_NTT) {
        r = BGV_Ciphertext_Copy(&work, in);
        for (uint32_t k = 0; k < K && r == HIFHE_SUCCESS; ++k) {
            CrtPoly comp;
            r = BGV_Ciphertext_GetCrtPolyAt(&comp, k, &work);
            if (r == HIFHE_SUCCESS) {
                r = RLWE_CrtPoly_ToNtt(&comp);
            }
        }
        if (r != HIFHE_SUCCESS) {
            BGV_Ciphertext_Destroy(&work);
            return r;
        }
        src = &work;
    }

    /* Output on the truncated chain, in NTT form. */
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
    cfg.crtConfig.dtype = HIFHE_NTT;
    cfg.caps = in->config.caps;
    memcpy(cfg.seed, in->config.seed, sizeof(cfg.seed));

    Ciphertext res;
    memset(&res, 0, sizeof(res));
    r = BGV_Ciphertext_Create(&res, &cfg, ctx);
    BGV_CiphertextConfig_Destroy(&cfg);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(&work);
        return r;
    }

    /* Per-limb constants, all fixed multipliers. */
    ShoupConst invQLastSc[HIFHE_BGV_MAX_CHAIN_LEN];
    ShoupConst tSc[HIFHE_BGV_MAX_CHAIN_LEN];
    const BarrettConst *bc[HIFHE_BGV_MAX_CHAIN_LEN];
    const NttTables *tbl[HIFHE_BGV_MAX_CHAIN_LEN];
    const NttTables *lastTbl = RLWE_RlweContext_GetNttTablesByModulus(&ctx->rlweContext, qLast);
    ShoupConst invTSc;
    if (L > HIFHE_BGV_MAX_CHAIN_LEN || lastTbl == NULL ||
        Kernel_ShoupConst_Init(&invTSc, invT, qLast) != HIFHE_SUCCESS) {
        r = HIFHE_INTERNAL;
    }
    for (uint32_t i = 0; i < outL && r == HIFHE_SUCCESS; ++i) {
        Modulus qi = chain[i];
        uint64_t invQLast = Kernel_ModInv(qLast % qi, qi);
        tbl[i] = RLWE_RlweContext_GetNttTablesByModulus(&ctx->rlweContext, qi);
        bc[i] = RLWE_RlweContext_GetBarrettByModulus(&ctx->rlweContext, qi);
        if (invQLast == 0u) {
            r = HIFHE_PARAM_INVALID;
        } else if (tbl[i] == NULL || bc[i] == NULL) {
            r = HIFHE_INTERNAL;
        } else if (Kernel_ShoupConst_Init(&invQLastSc[i], invQLast, qi) != HIFHE_SUCCESS ||
                   Kernel_ShoupConst_Init(&tSc[i], t % qi, qi) != HIFHE_SUCCESS) {
            r = HIFHE_INTERNAL;
        }
    }

    /* u (signed, |u| <= q_last / 2) and one limb of delta, reused per
     * component and target limb. */
    int64_t *u = NULL;
    uint64_t *buf = NULL;
    if (r == HIFHE_SUCCESS) {
        u = (int64_t *)HifheMalloc(N * (uint32_t)sizeof(int64_t));
        buf = (uint64_t *)HifheMalloc(N * (uint32_t)sizeof(uint64_t));
        if (u == NULL || buf == NULL) {
            r = HIFHE_MEMORY_ERROR;
        }
    }

    uint64_t halfQLast = qLast >> 1;
    for (uint32_t k = 0; k < K && r == HIFHE_SUCCESS; ++k) {
        memcpy(buf, src->data + ((size_t)k * L + outL) * N, N * sizeof(uint64_t));
        r = Kernel_Ntt_Inverse(buf, lastTbl);
        if (r != HIFHE_SUCCESS) {
            break;
        }
        for (uint32_t j = 0; j < N; ++j) {
            uint64_t v = Kernel_ShoupMulModInl(buf[j], &invTSc);
            /* Centre u so |delta| stays small. */
            u[j] = (v > halfQLast) ? -(int64_t)(qLast - v) : (int64_t)v;
        }
        for (uint32_t i = 0; i < outL && r == HIFHE_SUCCESS; ++i) {
            Modulus qi = chain[i];
            for (uint32_t j = 0; j < N; ++j) {
                int64_t uj = u[j];
                uint64_t mag = (uj < 0) ? (uint64_t)(-uj) : (uint64_t)uj;
                uint64_t d = Kernel_ShoupMulModInl(Kernel_BarrettReduce64Inl(mag, bc[i]), &tSc[i]);
                buf[j] = (uj < 0 && d != 0u) ? qi - d : d;
            }
            r = Kernel_Ntt_Forward(buf, tbl[i]);
            if (r != HIFHE_SUCCESS) {
                break;
            }
            const uint64_t *ci = src->data + ((size_t)k * L + i) * N;
            uint64_t *dst = res.data + ((size_t)k * outL + i) * N;
            for (uint32_t j = 0; j < N; ++j) {
                uint64_t diff = ci[j] + qi - buf[j];
                if (diff >= qi) {
                    diff -= qi;
                }
                dst[j] = Kernel_ShoupMulModInl(diff, &invQLastSc[i]);
            }
        }
    }

    HifheFree(u);
    HifheFree(buf);
    BGV_Ciphertext_Destroy(&work);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(&res);
        return r;
    }
    /* Swap in only once complete, so `out` may alias `in`. */
    BGV_Ciphertext_Destroy(out);
    *out = res;
    return HIFHE_SUCCESS;
}
