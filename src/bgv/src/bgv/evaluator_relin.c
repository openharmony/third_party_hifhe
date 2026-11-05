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
 * Relinearize: fold size-3 (c0, c1, c2) back to size 2 by key-switching c2.
 * With (d0, d1) = BGV_KeySwitch_Run(c2),
 *   (c0 + d0) + (c1 + d1)*s  ~  c0 + c1*s + c2*s^2
 */

#include <string.h>
#include "hifhe_err_internal.h"
#include "bgv/evaluator.h"
#include "bgv/ciphertext.h"
#include "rlwe/crt_ops.h"
#include "bgv/keys.h"
#include "bgv/keyswitch.h"
#include "kernel/modulus.h"

HIFHE_ERROR BGV_Evaluator_Relinearize(Ciphertext *out, const Ciphertext *in, const Evaluator *self)
{
    if (out == NULL || in == NULL || self == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (self->relinKeys == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NO_RELIN_KEY);
        return HIFHE_NO_RELIN_KEY;
    }
    if (in->config.ciphertextSize != 3u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_CT_DEGREE_MISMATCH);
        return HIFHE_CT_DEGREE_MISMATCH;
    }

    BGVContext *ctx = self->context;
    uint32_t L = in->config.crtConfig.rnsbase.size;
    /* The gadget bakes in its chain: relinearize before mod-switching. */
    if (L != self->relinKeys->rnsSize) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }

    /* Size-2 output, same shape and correction factor. */
    BGV_Ciphertext_Destroy(out);
    int32_t r = BGV_Ciphertext_CreateSize2Ntt(out, in->config.correctionFactor, &in->config.crtConfig.rnsbase, ctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    /* The constructor zeroes caps; decode picks its layout from them, and
     * every other transform carries them across. */
    out->config.caps = in->config.caps;

    /* View c2 as a CrtPoly and run the key switch. */
    CrtPoly c2;
    r = BGV_Ciphertext_GetCrtPolyAt(&c2, 2u, in);
    if (r != HIFHE_SUCCESS) {
        return r;
    }

    Ciphertext delta;
    r = BGV_Ciphertext_CreateSize2Ntt(&delta, in->config.correctionFactor, &in->config.crtConfig.rnsbase, ctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }

    r = BGV_KeySwitch_Run(&delta, &c2, self->relinKeys->pieces, self->relinKeys->rnsSize, self->relinKeys->digits, ctx);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(&delta);
        return r;
    }

    /* out = (c0 + delta.c0, c1 + delta.c1). `in` is size 3, delta size 2. */
    for (uint32_t k = 0; k < 2u && r == HIFHE_SUCCESS; ++k) {
        CrtPoly iv, dv, ov;
        r = BGV_Ciphertext_GetCrtPolyAt(&iv, k, in);
        if (r != HIFHE_SUCCESS) {
            break;
        }
        r = BGV_Ciphertext_GetCrtPolyAt(&dv, k, &delta);
        if (r != HIFHE_SUCCESS) {
            break;
        }
        r = BGV_Ciphertext_GetCrtPolyAt(&ov, k, out);
        if (r != HIFHE_SUCCESS) {
            break;
        }
        r = RLWE_CrtPoly_Add(&ov, &iv, &dv);
    }
    BGV_Ciphertext_Destroy(&delta);
    return r;
}
