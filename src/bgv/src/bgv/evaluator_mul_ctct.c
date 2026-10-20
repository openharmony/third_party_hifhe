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
 * ct * ct, a polynomial product in s: a size-m by a size-n ciphertext gives
 * size m+n-1, out[i+j] += a[i]*b[j]. Two fresh ciphertexts give size 3,
 * which Relinearize collapses to 2; size-2 by size-3 gives size 4, which
 * decryption handles through BGV_SecretKey_GetPow(s, 3).
 *
 * Both operands must be in NTT form; the output is too.
 */

#include <string.h>
#include "bsl_sal.h"
#include "bgv/evaluator.h"
#include "bgv/ciphertext.h"
#include "rlwe/crt_ops.h"
#include "kernel/modulus.h"

HIFHE_ERROR BGV_Evaluator_MulCtCt(Ciphertext *out, const Ciphertext *a, const Ciphertext *b,
                                const Evaluator *self)
{
    if (out == NULL || a == NULL || b == NULL || self == NULL) return HIFHE_NULL_INPUT;
    if (a->context != b->context) return HIFHE_PARAM_INVALID;
    uint32_t ma = a->config.ciphertextSize;
    uint32_t mb = b->config.ciphertextSize;
    if (ma < 2u || mb < 2u) return HIFHE_CT_DEGREE_MISMATCH;
    if (a->config.crtConfig.dtype != HIFHE_NTT || b->config.crtConfig.dtype != HIFHE_NTT) {
        return HIFHE_PARAM_INVALID;
    }
    uint32_t L = a->config.crtConfig.rnsbase.size;
    if (L != b->config.crtConfig.rnsbase.size) return HIFHE_PARAM_INVALID;
    uint32_t mOut = ma + mb - 1u;

    CiphertextConfig cfg;
    int32_t r = BGV_CiphertextConfig_Create(&cfg, mOut,
                                            a->config.correctionFactor,
                                            &a->config.crtConfig.rnsbase);
    if (r != HIFHE_SUCCESS) return r;
    cfg.crtConfig.dtype = HIFHE_NTT;
    cfg.caps            = a->config.caps;
    Ciphertext prod;
    r = BGV_Ciphertext_Create(&prod, &cfg, a->context);
    BGV_CiphertextConfig_Destroy(&cfg);
    if (r != HIFHE_SUCCESS) return r;
    /* Create zeroes the buffer, as the accumulation below needs. */

    for (uint32_t ia = 0; ia < ma && r == HIFHE_SUCCESS; ++ia) {
        for (uint32_t ib = 0; ib < mb; ++ib) {
            CrtPoly av, bv, ov;
            r = BGV_Ciphertext_GetCrtPolyAt(&av, ia, a);           if (r != HIFHE_SUCCESS) break;
            r = BGV_Ciphertext_GetCrtPolyAt(&bv, ib, b);           if (r != HIFHE_SUCCESS) break;
            r = BGV_Ciphertext_GetCrtPolyAt(&ov, ia + ib, &prod);  if (r != HIFHE_SUCCESS) break;
            r = RLWE_CrtPoly_MulDotAcc(&ov, &av, &bv);
            if (r != HIFHE_SUCCESS) break;
        }
    }
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(&prod);
        return r;
    }
    /* correctionFactor accumulates multiplicatively in BGV. */
    prod.config.correctionFactor =
        (uint64_t)(((ModulusWide)a->config.correctionFactor
                    * (ModulusWide)b->config.correctionFactor)
                   % (ModulusWide)a->context->bgvParameter->plainMod);

    /* Swap in only once complete, so `out` may alias an operand. */
    BGV_Ciphertext_Destroy(out);
    *out = prod;
    return HIFHE_SUCCESS;
}

