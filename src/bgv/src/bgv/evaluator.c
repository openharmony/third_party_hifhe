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
 * Evaluator lifecycle and the ops that stay within a size-2 ciphertext.
 * ct*ct / relin / rotate / mod-switch / rerand have their own files.
 */

#include <string.h>
#include "bsl_sal.h"
#include "bgv/evaluator.h"
#include "bgv/ciphertext.h"
#include "bgv/plaintext.h"
#include "rlwe/crt_ops.h"
#include "kernel/modulus.h"

/* ---- lifecycle ---- */

HIFHE_ERROR BGV_Evaluator_Create(Evaluator *self, BGVContext *ctx,
                               const RelinKeys *rlk, const GaloisKeys *glk)
{
    if (self == NULL || ctx == NULL) return HIFHE_NULL_INPUT;
    self->context   = ctx;
    self->relinKeys = rlk;
    self->galoisKeys= glk;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_Evaluator_Destroy(Evaluator *self)
{
    if (self == NULL) return HIFHE_NULL_INPUT;
    self->context   = NULL;
    self->relinKeys = NULL;
    self->galoisKeys= NULL;
    return HIFHE_SUCCESS;
}

/* ---- helpers ---- */

static HIFHE_ERROR SameShapeCt(const Ciphertext *a, const Ciphertext *b)
{
    if (a == NULL || b == NULL) return HIFHE_NULL_INPUT;
    if (a->context != b->context) return HIFHE_PARAM_INVALID;
    if (a->config.ciphertextSize != b->config.ciphertextSize) return HIFHE_CT_DEGREE_MISMATCH;
    if (a->config.crtConfig.rnsbase.size != b->config.crtConfig.rnsbase.size) return HIFHE_PARAM_INVALID;
    if (a->config.crtConfig.dtype != b->config.crtConfig.dtype) return HIFHE_PARAM_INVALID;
    return HIFHE_SUCCESS;
}

static HIFHE_ERROR EnsureOutShape(Ciphertext *out, const Ciphertext *ref, uint32_t ciphertextSize)
{
    if (out->data == NULL || out->config.ciphertextSize != ciphertextSize
        || out->config.crtConfig.rnsbase.size != ref->config.crtConfig.rnsbase.size) {
        BGV_Ciphertext_Destroy(out);
        CiphertextConfig cfg;
        int32_t r = BGV_CiphertextConfig_Create(&cfg, ciphertextSize,
                                                ref->config.correctionFactor,
                                                &ref->config.crtConfig.rnsbase);
        if (r != HIFHE_SUCCESS) return r;
        cfg.crtConfig.dtype = ref->config.crtConfig.dtype;
        cfg.caps            = ref->config.caps;
        r = BGV_Ciphertext_Create(out, &cfg, ref->context);
        BGV_CiphertextConfig_Destroy(&cfg);
        return r;
    }
    out->config.correctionFactor = ref->config.correctionFactor;
    out->config.crtConfig.dtype  = ref->config.crtConfig.dtype;
    out->config.caps             = ref->config.caps;
    return HIFHE_SUCCESS;
}

/* ---- scale reconciliation ---- */

/* Bring two scale factors onto one before an additive op.
 *   x1 = f2 * f1^-1   moves operand 1 onto f2
 *   x2 = f1 * f2^-1   moves operand 2 onto f1
 * Picks whichever is smaller once centred around ptMod/2, since it also
 * scales that operand's noise. `*isFirstEle` is true when operand 1 is the
 * one scaled. HIFHE_PARAM_INVALID if a factor is not invertible. */
static HIFHE_ERROR BGV_Evaluator_MakeScaleFactorSame(bool *isFirstEle, uint64_t *x,
                                                   uint64_t f1, uint64_t f2, uint64_t ptMod)
{
    if (isFirstEle == NULL || x == NULL) return HIFHE_NULL_INPUT;
    if (ptMod < 2u) return HIFHE_PARAM_INVALID;

    uint64_t invF1 = Kernel_ModInv(f1 % ptMod, ptMod);
    uint64_t invF2 = Kernel_ModInv(f2 % ptMod, ptMod);
    if (invF1 == 0u || invF2 == 0u) return HIFHE_PARAM_INVALID;

    uint64_t x1 = Kernel_MulMod(f2 % ptMod, invF1, ptMod);   /* scales operand 1 onto f2 */
    uint64_t x2 = Kernel_MulMod(f1 % ptMod, invF2, ptMod);   /* scales operand 2 onto f1 */

    uint64_t half = ptMod >> 1;
    uint64_t absX1 = (x1 > half) ? (ptMod - x1) : x1;
    uint64_t absX2 = (x2 > half) ? (ptMod - x2) : x2;

    if (absX1 < absX2) {
        *isFirstEle = true;
        *x = x1;
    }
    else {
        *isFirstEle = false;
        *x = x2;
    }
    return HIFHE_SUCCESS;
}

/* ---- unary ---- */

HIFHE_ERROR BGV_Evaluator_Neg(Ciphertext *out, const Ciphertext *a, const Evaluator *self)
{
    if (out == NULL || a == NULL || self == NULL) return HIFHE_NULL_INPUT;
    int32_t r = EnsureOutShape(out, a, a->config.ciphertextSize);
    if (r != HIFHE_SUCCESS) return r;
    return BGV_Ciphertext_Neg(out, a);
}

/* ---- ciphertext + ciphertext ---- */

HIFHE_ERROR BGV_Evaluator_AddCtCt(Ciphertext *out, const Ciphertext *a, const Ciphertext *b,
                                const Evaluator *self)
{
    if (self == NULL) return HIFHE_NULL_INPUT;
    int32_t r = SameShapeCt(a, b);
    if (r != HIFHE_SUCCESS) return r;

    Modulus  t  = a->context->bgvParameter->plainMod;
    uint64_t f1 = a->config.correctionFactor;
    uint64_t f2 = b->config.correctionFactor;

    /* Different scales cannot be added directly; move the cheaper one. */
    bool scaleFirst = false;
    uint64_t x = 1u;
    if ((f1 % t) != (f2 % t)) {
        r = BGV_Evaluator_MakeScaleFactorSame(&scaleFirst, &x, f1, f2, t);
        if (r != HIFHE_SUCCESS) return r;
    }

    /* `scaled` is whichever operand needs the multiplier; `plain` the other. */
    const Ciphertext *scaled = scaleFirst ? a : b;
    const Ciphertext *plain  = scaleFirst ? b : a;

    /* `out` is written before `plain` is read, so an aliased `plain` would be
     * added to itself (and EnsureOutShape could free it outright on a shape
     * change). Build into a temporary in that case and move it in. */
    Ciphertext tmp;
    memset(&tmp, 0, sizeof(tmp));
    Ciphertext *dst = (out == plain) ? &tmp : out;

    r = EnsureOutShape(dst, plain, a->config.ciphertextSize);
    if (r == HIFHE_SUCCESS) r = BGV_Ciphertext_MulScalar(dst, scaled, x);
    if (r == HIFHE_SUCCESS) r = BGV_Ciphertext_Add(dst, dst, plain);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(&tmp);
        return r;
    }

    dst->config.correctionFactor = plain->config.correctionFactor;
    if (dst == &tmp) {
        BGV_Ciphertext_Destroy(out);
        *out = tmp;
    }
    return HIFHE_SUCCESS;
}

/* ---- ciphertext + plaintext ---- */

HIFHE_ERROR BGV_Evaluator_AddCtPt(Ciphertext *out, const Ciphertext *a, const Plaintext *b,
                                const Evaluator *self)
{
    if (out == NULL || a == NULL || b == NULL || self == NULL) return HIFHE_NULL_INPUT;
    if (a->context != b->context) return HIFHE_PARAM_INVALID;
    if (a->config.crtConfig.rnsbase.size != b->config.crtConfig.rnsbase.size) {
        return HIFHE_PARAM_INVALID;
    }
    int32_t r = EnsureOutShape(out, a, a->config.ciphertextSize);
    if (r != HIFHE_SUCCESS) return r;
    Modulus t = a->context->bgvParameter->plainMod;

    /* Only the plaintext moves; rescaling the ciphertext grows its noise. */
    uint64_t x = 1u;
    uint64_t f1 = a->config.correctionFactor % t;
    uint64_t f2 = b->config.scaleFactor % t;
    if (f1 != f2) {
        uint64_t invF2 = Kernel_ModInv(f2, t);
        if (invF2 == 0u) return HIFHE_PARAM_INVALID;
        x = Kernel_MulMod(f1, invF2, t);
    }

    /* Copy a into out (all components), then add pt to component 0. */
    memcpy(out->data, a->data, a->dataSize * sizeof(uint64_t));

    CrtPoly pt;
    r = BGV_Plaintext_GetCrtPoly(&pt, b);
    if (r != HIFHE_SUCCESS) return r;

    if (x == 1u) {
        return BGV_Ciphertext_AddCrtPolyAt(out, 0u, &pt);
    }

    CrtPoly scaled;
    r = RLWE_CrtPoly_Create(&scaled, &pt.config, &a->context->rlweContext);
    if (r != HIFHE_SUCCESS) return r;
    r = RLWE_CrtPoly_MulScalar(&scaled, &pt, x);
    if (r == HIFHE_SUCCESS) r = BGV_Ciphertext_AddCrtPolyAt(out, 0u, &scaled);
    RLWE_CrtPoly_Destroy(&scaled);
    return r;
}

/* ---- ciphertext * plaintext ---- */

HIFHE_ERROR BGV_Evaluator_MulCtPt(Ciphertext *out, const Ciphertext *a, const Plaintext *b,
                                const Evaluator *self)
{
    if (out == NULL || a == NULL || b == NULL || self == NULL) return HIFHE_NULL_INPUT;
    if (a->context != b->context) return HIFHE_PARAM_INVALID;
    if (a->config.crtConfig.rnsbase.size != b->config.crtConfig.rnsbase.size) {
        return HIFHE_PARAM_INVALID;
    }
    int32_t r = EnsureOutShape(out, a, a->config.ciphertextSize);
    if (r != HIFHE_SUCCESS) return r;

    CrtPoly pt;
    r = BGV_Plaintext_GetCrtPoly(&pt, b);
    if (r != HIFHE_SUCCESS) return r;
    r = BGV_Ciphertext_MulCrtPoly(out, a, &pt);
    if (r != HIFHE_SUCCESS) return r;

    /* Scales multiply, as for ct*ct. */
    Modulus t = a->context->bgvParameter->plainMod;
    out->config.correctionFactor =
        Kernel_MulMod(a->config.correctionFactor % t, b->config.scaleFactor % t, t);
    return HIFHE_SUCCESS;
}

/* ---- ciphertext * scalar (in Z_t) ---- */

HIFHE_ERROR BGV_Evaluator_MulCtScalar(Ciphertext *out, const Ciphertext *a, uint64_t x,
                                    const Evaluator *self)
{
    if (out == NULL || a == NULL || self == NULL) return HIFHE_NULL_INPUT;
    int32_t r = EnsureOutShape(out, a, a->config.ciphertextSize);
    if (r != HIFHE_SUCCESS) return r;
    /* The scalar lives in the plaintext space. Reducing it first keeps a
     * multiple of q from collapsing the ciphertext to zero, and spends less
     * of the noise budget. */
    return BGV_Ciphertext_MulScalar(out, a, x % a->context->bgvParameter->plainMod);
}

