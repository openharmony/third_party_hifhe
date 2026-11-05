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
 * BGV encryption / decryption, symmetric and asymmetric, plus the
 * zero-encryption family internal code uses (Encrypt = EncryptZero* + m).
 *
 * Everything is elementwise over q_i in the NTT domain.
 */

#include <string.h>
#include "hifhe_mem.h"
#include "hifhe_err_internal.h"
#include "bgv/encryptor.h"
#include "bgv/encoder.h"
#include "bgv/params_check.h"
#include "bgv/plaintext.h"
#include "bgv/ciphertext.h"
#include "bgv/keys.h"
#include "kernel/sampler.h"
#include "kernel/modulus.h"
#include "kernel/ntt.h"
#include "rlwe/rlwe.h"
#include "rlwe/rlwe_context.h"
#include "rlwe/rns_ops.h"
#include "rlwe/crt_ops.h"

/* An empty CrtPoly over the whole cipher chain, in `dtype` form. */
static HIFHE_ERROR MakeChainCrtPoly(CrtPoly *out, BGVContext *ctx, PolyForm dtype)
{
    CrtPolyConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    int32_t r =
        Uint64Vector_Create(&cfg.rnsbase, ctx->rlweContext.cipherRnsBase.data, ctx->rlweContext.cipherRnsBase.size);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    cfg.dtype = dtype;
    r = RLWE_CrtPoly_Create(out, &cfg, &ctx->rlweContext);
    Uint64Vector_Destroy(&cfg.rnsbase);
    return r;
}

static HIFHE_ERROR SampleUniformCrtNtt(CrtPoly *out, BGVContext *ctx, const BgvEntropy *src)
{
    int32_t r = MakeChainCrtPoly(out, ctx, HIFHE_NTT);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    uint32_t N = ctx->rlweContext.parameter->polyDegree;
    for (uint32_t i = 0; i < out->config.rnsbase.size; ++i) {
        Modulus q = out->config.rnsbase.data[i];
        r = Kernel_Sampler_UniformModQ(out->data + i * N, N, q, i, src);
        if (r != HIFHE_SUCCESS) {
            RLWE_CrtPoly_Destroy(out);
            return r;
        }
    }
    return HIFHE_SUCCESS;
}

static HIFHE_ERROR SampleSmallCrtNtt(CrtPoly *out, BGVContext *ctx, const BgvEntropy *src, bool ternary)
{
    int32_t r = MakeChainCrtPoly(out, ctx, HIFHE_POLY);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    uint32_t N = ctx->rlweContext.parameter->polyDegree;
    Int64Vector scratch;
    r = Int64Vector_Create(&scratch, NULL, N);
    if (r != HIFHE_SUCCESS) {
        RLWE_CrtPoly_Destroy(out);
        return r;
    }
    r = ternary ? Kernel_Sampler_Ternary(scratch.data, N, src) : Kernel_Sampler_CBD(scratch.data, N, 2u, src);
    if (r != HIFHE_SUCCESS) {
        Int64Vector_Cleanse(&scratch);
        RLWE_CrtPoly_Destroy(out);
        return r;
    }
    r = RLWE_CrtPoly_SetSigned(out, scratch.data);
    Int64Vector_Cleanse(&scratch);
    if (r != HIFHE_SUCCESS) {
        RLWE_CrtPoly_Destroy(out);
        return r;
    }
    r = RLWE_CrtPoly_ToNtt(out);
    if (r != HIFHE_SUCCESS) {
        RLWE_CrtPoly_Destroy(out);
        return r;
    }
    return HIFHE_SUCCESS;
}

/* ---------------- lifecycle ---------------- */

HIFHE_ERROR BGV_Encryptor_CreateFromSecret(Encryptor *self, const SecretKey *sk, BGVContext *ctx)
{
    if (self == NULL || sk == NULL || ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    self->context = ctx;
    self->pk = NULL;
    self->sk = sk;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_Encryptor_CreateFromPublic(Encryptor *self, const PublicKey *pk, const SecretKey *sk, BGVContext *ctx)
{
    if (self == NULL || pk == NULL || ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    self->context = ctx;
    self->pk = pk;
    self->sk = sk;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_Encryptor_Destroy(Encryptor *self)
{
    if (self == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    self->context = NULL;
    self->pk = NULL;
    self->sk = NULL;
    return HIFHE_SUCCESS;
}

/* ---------------- helpers over q_i ---------------- */

/* Produce a fresh ciphertext of the correct default shape. */
static HIFHE_ERROR MakeZeroCiphertext(Ciphertext *out, BGVContext *ctx)
{
    CiphertextConfig cfg;
    int32_t r = BGV_BGVContext_GetDefaultCiphertextConfig(&cfg, ctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    r = BGV_Ciphertext_Create(out, &cfg, ctx);
    BGV_CiphertextConfig_Destroy(&cfg);
    return r;
}

/* ---------------- zero-encryption (symmetric) ---------------- */

/* Core: given `a` and `e` (both in NTT form under cipher base), build
 * ct = (-a*s + t*e, a). */
static HIFHE_ERROR SymCoreFromAE(Ciphertext *out, const CrtPoly *a, const CrtPoly *e, const CrtPoly *sk_ntt,
                                 BGVContext *ctx)
{
    int32_t r = MakeZeroCiphertext(out, ctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    Modulus t = ctx->bgvParameter->plainMod;

    CrtPoly c0, c1;
    r = BGV_Ciphertext_GetCrtPolyAt(&c0, 0u, out);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    r = BGV_Ciphertext_GetCrtPolyAt(&c1, 1u, out);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }

    /* c1 holds a*s while c0 = t*e - a*s is built, then takes a. */
    r = RLWE_CrtPoly_MulScalar(&c0, e, t);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    r = RLWE_CrtPoly_MulDot(&c1, a, sk_ntt);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    r = RLWE_CrtPoly_Sub(&c0, &c0, &c1);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    r = RLWE_CrtPoly_Assign(&c1, a);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    return HIFHE_SUCCESS;
err:
    BGV_Ciphertext_Destroy(out);
    return r;
}

HIFHE_ERROR BGV_Encryptor_EncryptZeroSymmetric(Ciphertext *out, const SecretKey *sk, const Encryptor *self)
{
    if (out == NULL || sk == NULL || self == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    /* Never the context seed: it would repeat `a` and fix the ciphertext.
     * The seed is for key derivation. */
    BgvEntropy src = BgvEntropy_Drbg();
    CrtPoly a, e, sk_view;
    int32_t r = RLWE_CrtPoly_CreateFromExist(&sk_view, sk->data, sk->dataSize, &sk->config.crtConfig,
                                             &self->context->rlweContext);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    r = SampleUniformCrtNtt(&a, self->context, &src);
    if (r != HIFHE_SUCCESS) {
        RLWE_CrtPoly_Destroy(&sk_view);
        return r;
    }
    r = SampleSmallCrtNtt(&e, self->context, &src, false);
    if (r != HIFHE_SUCCESS) {
        RLWE_CrtPoly_Destroy(&a);
        RLWE_CrtPoly_Destroy(&sk_view);
        return r;
    }
    r = SymCoreFromAE(out, &a, &e, &sk_view, self->context);
    RLWE_CrtPoly_Destroy(&a);
    RLWE_CrtPoly_Destroy(&e);
    RLWE_CrtPoly_Destroy(&sk_view);
    return r;
}

/* ---------------- zero-encryption (asymmetric) ---------------- */

/* Core: given (pk0, pk1) and (u, e0, e1) all in NTT form, build
 *   c0 = pk0*u + t*e0
 *   c1 = pk1*u + t*e1
 */
static HIFHE_ERROR AsymCoreFromNoise(Ciphertext *out, const CrtPoly *pk0, const CrtPoly *pk1, const CrtPoly *u,
                                     const CrtPoly *e0, const CrtPoly *e1, BGVContext *ctx)
{
    int32_t r = MakeZeroCiphertext(out, ctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    Modulus t = ctx->bgvParameter->plainMod;
    CrtPoly c0, c1;
    r = BGV_Ciphertext_GetCrtPolyAt(&c0, 0u, out);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    r = BGV_Ciphertext_GetCrtPolyAt(&c1, 1u, out);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }

    /* c_k = t*e_k then += pk_k*u, so no scratch poly. */
    r = RLWE_CrtPoly_MulScalar(&c0, e0, t);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    r = RLWE_CrtPoly_MulDotAcc(&c0, pk0, u);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    r = RLWE_CrtPoly_MulScalar(&c1, e1, t);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    r = RLWE_CrtPoly_MulDotAcc(&c1, pk1, u);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    return HIFHE_SUCCESS;
err:
    BGV_Ciphertext_Destroy(out);
    return r;
}

HIFHE_ERROR BGV_Encryptor_EncryptZeroAsymmetric(Ciphertext *out, const PublicKey *pk, const Encryptor *self)
{
    if (out == NULL || pk == NULL || self == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    /* DRBG: under one seed u, e0 and e1 would come back identical. */
    BgvEntropy src = BgvEntropy_Drbg();
    CrtPoly u, e0, e1, pk0, pk1;
    int32_t r = SampleSmallCrtNtt(&u, self->context, &src, true);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    r = SampleSmallCrtNtt(&e0, self->context, &src, false);
    if (r != HIFHE_SUCCESS) {
        RLWE_CrtPoly_Destroy(&u);
        return r;
    }
    r = SampleSmallCrtNtt(&e1, self->context, &src, false);
    if (r != HIFHE_SUCCESS) {
        RLWE_CrtPoly_Destroy(&u);
        RLWE_CrtPoly_Destroy(&e0);
        return r;
    }
    r = BGV_Ciphertext_GetCrtPolyAt(&pk0, 0u, pk);
    if (r != HIFHE_SUCCESS) {
        goto done;
    }
    r = BGV_Ciphertext_GetCrtPolyAt(&pk1, 1u, pk);
    if (r != HIFHE_SUCCESS) {
        goto done;
    }
    r = AsymCoreFromNoise(out, &pk0, &pk1, &u, &e0, &e1, self->context);
done:
    RLWE_CrtPoly_Destroy(&u);
    RLWE_CrtPoly_Destroy(&e0);
    RLWE_CrtPoly_Destroy(&e1);
    return r;
}

/* c0 <- c0 + m mod q_i, elementwise. Adopts the plaintext's scale factor and
 * capability bits. */
static HIFHE_ERROR AddPtToC0(Ciphertext *ct, const Plaintext *pt)
{
    if (pt->config.crtConfig.rnsbase.size != ct->config.crtConfig.rnsbase.size) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    uint32_t N = ct->context->rlweContext.parameter->polyDegree;
    for (uint32_t i = 0; i < ct->config.crtConfig.rnsbase.size; ++i) {
        Modulus q = ct->config.crtConfig.rnsbase.data[i];
        uint64_t *c0slice = ct->data + i * N;
        const uint64_t *ptslice = pt->data + i * N;
        for (uint32_t j = 0; j < N; ++j) {
            uint64_t s = c0slice[j] + ptslice[j];
            if (s >= q) {
                s -= q;
            }
            c0slice[j] = s;
        }
    }
    ct->config.correctionFactor = pt->config.scaleFactor;
    ct->config.caps = pt->config.caps;
    return HIFHE_SUCCESS;
}

/* ---------------- non-zero encryption ---------------- */

HIFHE_ERROR BGV_Encryptor_EncryptSymmetric(Ciphertext *out, const Plaintext *pt, const Encryptor *self)
{
    if (out == NULL || pt == NULL || self == NULL || self->sk == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    int32_t r = BGV_Encryptor_EncryptZeroSymmetric(out, self->sk, self);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    r = AddPtToC0(out, pt);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(out);
        return r;
    }
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_Encryptor_EncryptAsymmetric(Ciphertext *out, const Plaintext *pt, const Encryptor *self)
{
    if (out == NULL || pt == NULL || self == NULL || self->pk == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    int32_t r = BGV_Encryptor_EncryptZeroAsymmetric(out, self->pk, self);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    r = AddPtToC0(out, pt);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(out);
        return r;
    }
    return HIFHE_SUCCESS;
}

/* ---------------- decryption ---------------- */

/* acc = acc * sp + ck mod q over one limb: one Horner step. All inputs are
 * reduced, so the sum needs one masked subtraction. */
static void HornerStep(uint64_t *acc, const uint64_t *ck, const uint64_t *sp, const BarrettConst *bc, uint32_t N)
{
    Modulus q = bc->q;
    for (uint32_t j = 0; j < N; ++j) {
        uint64_t v = Kernel_BarrettMulModInl(acc[j], sp[j], bc) + ck[j];
        acc[j] = Kernel_CondSubInl(v, q);
    }
}

/*
 * The phase c0 + c1*s + ... + c[K-1]*s^(K-1) never leaves this function. It
 * is linear in s, so a caller holding a ciphertext could solve it for the
 * key. The output is the plaintext polynomial z = [phase]_Q mod t instead,
 * over the ciphertext's whole chain: every limb holds NTT_{q_i}(z), which is
 * the representation encoding produces, so the result decodes and encrypts
 * again exactly as an encoded plaintext does.
 *
 * The phase is evaluated by Horner's rule, one multiply-add per component, so
 * the work is linear in ciphertextSize and no power of s is materialised.
 * It lives in a scratch buffer that is wiped before return.
 */
HIFHE_ERROR BGV_Encryptor_Decrypt(Plaintext *out, const Ciphertext *ct, const Encryptor *self)
{
    if (out == NULL || ct == NULL || self == NULL || self->sk == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    uint32_t N = self->context->rlweContext.parameter->polyDegree;
    uint32_t L = ct->config.crtConfig.rnsbase.size;
    uint32_t sz = ct->config.ciphertextSize;
    if (sz < 2u || sz > HIFHE_BGV_MAX_CIPHERTEXT_SIZE) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_CT_DEGREE_MISMATCH);
        return HIFHE_CT_DEGREE_MISMATCH;
    }
    /* Both operands are multiplied as NTT values below. A coefficient-form
     * input would decrypt to nonsense and still report success. */
    if (ct->config.crtConfig.dtype != HIFHE_NTT || self->sk->config.crtConfig.dtype != HIFHE_NTT) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    if (L == 0u || L > HIFHE_BGV_MAX_CHAIN_LEN) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }

    const BarrettConst *bc[HIFHE_BGV_MAX_CHAIN_LEN];
    const NttTables *tbl[HIFHE_BGV_MAX_CHAIN_LEN];
    for (uint32_t i = 0; i < L; ++i) {
        Modulus q = ct->config.crtConfig.rnsbase.data[i];
        bc[i] = RLWE_RlweContext_GetBarrettByModulus(&self->context->rlweContext, q);
        tbl[i] = RLWE_RlweContext_GetNttTablesByModulus(&self->context->rlweContext, q);
        if (bc[i] == NULL || tbl[i] == NULL) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_INTERNAL);
            return HIFHE_INTERNAL;
        }
    }

    /* The plaintext inherits the ciphertext's RNS base, scale factor and
     * capability bits. */
    PlaintextConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    int32_t rc = Uint64Vector_Create(&cfg.crtConfig.rnsbase, ct->config.crtConfig.rnsbase.data, L);
    if (rc != HIFHE_SUCCESS) {
        return rc;
    }
    cfg.crtConfig.dtype = HIFHE_NTT;
    cfg.scaleFactor = ct->config.correctionFactor;
    cfg.caps = ct->config.caps;
    BGV_Plaintext_Destroy(out);
    /* Written in full below before it is read. */
    rc = BGV_Plaintext_CreateUninit(out, &cfg, self->context);
    BGV_PlaintextConfig_Destroy(&cfg);
    if (rc != HIFHE_SUCCESS) {
        return rc;
    }

    size_t phaseWords = (size_t)L * N;
    uint64_t *phase = (uint64_t *)HifheMalloc((uint32_t)(phaseWords * sizeof(uint64_t)));
    if (phase == NULL) {
        BGV_Plaintext_Destroy(out);
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }

    /* Phase per limb, then back to coefficient form for the reduction. */
    const uint64_t *sk = self->sk->data;
    for (uint32_t i = 0; i < L && rc == HIFHE_SUCCESS; ++i) {
        uint64_t *acc = phase + (size_t)i * N;
        memcpy(acc, ct->data + ((size_t)(sz - 1u) * L + i) * N, N * sizeof(uint64_t));
        for (uint32_t k = sz - 1u; k-- > 0u;) {
            HornerStep(acc, ct->data + ((size_t)k * L + i) * N, sk + (size_t)i * N, bc[i], N);
        }
        rc = Kernel_Ntt_Inverse(acc, tbl[i]);
    }
    if (rc == HIFHE_SUCCESS) {
        rc = BGV_Encoder_CrtCenteredModT(out->data, phase, &ct->config.crtConfig.rnsbase, N,
                                         self->context->bgvParameter->plainMod);
    }
    if (rc == HIFHE_SUCCESS && L == 1u) {
        /* Decoding reads a single limb as centred mod q_0, so a value above
         * q_0 / 2 (possible only when t > q_0 / 2) would come back as
         * value - q_0. Store value + q_0 - t instead: congruent mod t, and
         * centred to value - t. Branch-free, since value is secret. */
        Modulus q = ct->config.crtConfig.rnsbase.data[0];
        Modulus t = self->context->bgvParameter->plainMod;
        for (uint32_t j = 0; j < N; ++j) {
            uint64_t over = 0u - (uint64_t)(out->data[j] > (q >> 1));
            out->data[j] += (q - t) & over;
        }
    }
    for (uint32_t i = 1u; i < L && rc == HIFHE_SUCCESS; ++i) {
        memcpy(out->data + (size_t)i * N, out->data, N * sizeof(uint64_t));
    }
    /* z < t < q_i, so the same coefficients are valid under every limb. */
    for (uint32_t i = 0; i < L && rc == HIFHE_SUCCESS; ++i) {
        rc = Kernel_Ntt_Forward(out->data + (size_t)i * N, tbl[i]);
    }
    HifheCleanse(phase, (uint32_t)(phaseWords * sizeof(uint64_t)));
    HifheFree(phase);
    if (rc != HIFHE_SUCCESS) {
        HifheCleanse(out->data, out->dataSize * (uint32_t)sizeof(uint64_t));
        BGV_Plaintext_Destroy(out);
        return rc;
    }
    out->config.crtConfig.dtype = HIFHE_NTT;
    return HIFHE_SUCCESS;
}
