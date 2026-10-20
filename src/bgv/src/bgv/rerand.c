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
 * Rerandomize: fresh independent noise on every component.
 *
 *   c_k += t * NTT(e_k),  e_k small
 *
 * Decrypt evaluates sum_k c_k * s^k, so the injected term carries t and
 * vanishes mod t at decode. No public key needed.
 */

#include <string.h>
#include "bsl_sal.h"
#include "basic/vector.h"
#include "bgv/evaluator.h"
#include "bgv/ciphertext.h"
#include "kernel/sampler.h"
#include "rlwe/crt_ops.h"

#define RERAND_NOISE_ETA 2u

HIFHE_ERROR BGV_Evaluator_Rerandomize(Ciphertext *out, const Ciphertext *in,
                                    const Evaluator *self)
{
    if (out == NULL || in == NULL || self == NULL) return HIFHE_NULL_INPUT;
    if (in->config.ciphertextSize < 2u) return HIFHE_CT_DEGREE_MISMATCH;

    BGV_Ciphertext_Destroy(out);
    int32_t r = BGV_Ciphertext_Copy(out, in);
    if (r != HIFHE_SUCCESS) return r;

    BGVContext *ctx = out->context;
    uint32_t N = ctx->rlweContext.parameter->polyDegree;
    Modulus  t = ctx->bgvParameter->plainMod;

    Int64Vector e;
    r = Int64Vector_Create(&e, NULL, N);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(out);
        return r;
    }

    CrtPoly noise;
    memset(&noise, 0, sizeof(noise));
    r = RLWE_CrtPoly_Create(&noise, &out->config.crtConfig, &ctx->rlweContext);
    if (r != HIFHE_SUCCESS) {
        Int64Vector_Cleanse(&e);
        BGV_Ciphertext_Destroy(out);
        return r;
    }

    for (uint32_t k = 0; k < out->config.ciphertextSize; ++k) {
        /* DRBG, not the context seed: a seeded stream replays. */
        BgvEntropy src = BgvEntropy_Drbg();
        r = Kernel_Sampler_CBD(e.data, N, RERAND_NOISE_ETA, &src);
        if (r != HIFHE_SUCCESS) break;
        r = RLWE_CrtPoly_SetSigned(&noise, e.data);
        if (r != HIFHE_SUCCESS) break;
        r = RLWE_CrtPoly_ToNtt(&noise);
        if (r != HIFHE_SUCCESS) break;
        r = RLWE_CrtPoly_MulScalar(&noise, &noise, t);
        if (r != HIFHE_SUCCESS) break;
        r = BGV_Ciphertext_AddCrtPolyAt(out, k, &noise);
        if (r != HIFHE_SUCCESS) break;
    }

    RLWE_CrtPoly_Destroy(&noise);
    Int64Vector_Cleanse(&e);
    if (r != HIFHE_SUCCESS) BGV_Ciphertext_Destroy(out);
    return r;
}
