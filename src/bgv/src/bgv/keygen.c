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
 * BGV key generation.
 *
 *   s  ternary, fixed Hamming weight polyDegree/2, stored NTT-form
 *   pk = (b, a),  a uniform in R_q,  b = -a*s + t*e
 *
 * Relin / galois keys use the gadget in bgv/keyswitch.h: piece (i, j)
 * encrypts T^j * qhat_i * target, laid out [i * digits + j]. target is
 * s^2 for relin, sigma_k(s) for the galois key at k.
 *
 * Randomness comes from basic/rand.c: a seeded BgvContext gives
 * byte-identical keys, an unseeded one falls back to the DRBG.
 */

#include <string.h>
#include "bsl_sal.h"
#include "bgv/keygen.h"
#include "bgv/keys.h"
#include "bgv/ciphertext.h"
#include "bgv/plaintext.h"
#include "bgv/keyswitch.h"
#include "bgv/params_check.h"
#include "kernel/sampler.h"
#include "kernel/ntt.h"
#include "kernel/modulus.h"
#include "rlwe/rlwe.h"
#include "rlwe/crt_ops.h"
#include "rlwe/rlwe_context.h"
#include "rlwe/rns_ops.h"

/* Number of base-2^16 digits needed to decompose a value < q. */
uint32_t BGV_BV_DnumForModulus(Modulus q)
{
    uint32_t bits = 0u;
    for (uint64_t v = q; v > 0u; v >>= 1) bits++;
    if (bits == 0u) return 1u;
    return (bits + BGV_KSW_LOG_T - 1u) / BGV_KSW_LOG_T;
}

uint32_t BGV_BV_DigitsForBase(const RnsBase *base)
{
    if (base == NULL || base->size == 0u) return 1u;
    uint32_t widest = 1u;
    for (uint32_t i = 0; i < base->size; ++i) {
        uint32_t d = BGV_BV_DnumForModulus(base->data[i]);
        if (d > widest) widest = d;
    }
    return widest;
}

/* ---- Small helpers ---- */

/* Secret-derived polynomials (s in coefficient form, s^2) otherwise stay
 * readable in freed memory. Views own nothing and must not be wiped: their
 * storage is the secret key itself. */
static void CleanseAndDestroy(CrtPoly *p)
{
    if (p->ownsData && p->data != NULL && p->dataSize > 0u) {
        BSL_SAL_CleanseData(p->data, p->dataSize * (uint32_t)sizeof(uint64_t));
    }
    RLWE_CrtPoly_Destroy(p);
}

static HIFHE_ERROR SampleUniformCrtNtt(CrtPoly *out, BGVContext *ctx,
                                     const BgvEntropy *src)
{
    /* Uniform in the NTT domain; NTT is a bijection, so this is uniform. */
    CrtPolyConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    int32_t r = Uint64Vector_Create(&cfg.rnsbase, ctx->rlweContext.cipherRnsBase.data,
                                    ctx->rlweContext.cipherRnsBase.size);
    if (r != HIFHE_SUCCESS) return r;
    cfg.dtype = HIFHE_NTT;
    r = RLWE_CrtPoly_Create(out, &cfg, &ctx->rlweContext);
    Uint64Vector_Destroy(&cfg.rnsbase);
    if (r != HIFHE_SUCCESS) return r;

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

/* Secret-key coefficient distribution. SECRET_FIXED_WEIGHT matches the
 * predecessor: polyDegree/4 at +1, the same at -1, rest zero, shuffled.
 * CBD is kept for error polynomials. */
#define BGV_SECRET_WEIGHT(polyDegree)  ((polyDegree) >> 1)

/* Sample a small poly (CBD-2 by default) into a CrtPoly, COEFF form. */
static HIFHE_ERROR SampleSmallCrtCoeff(CrtPoly *out, BGVContext *ctx,
                                     const BgvEntropy *src, bool ternary)
{
    CrtPolyConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    int32_t r = Uint64Vector_Create(&cfg.rnsbase, ctx->rlweContext.cipherRnsBase.data,
                                    ctx->rlweContext.cipherRnsBase.size);
    if (r != HIFHE_SUCCESS) return r;
    cfg.dtype = HIFHE_POLY;
    r = RLWE_CrtPoly_Create(out, &cfg, &ctx->rlweContext);
    Uint64Vector_Destroy(&cfg.rnsbase);
    if (r != HIFHE_SUCCESS) return r;

    uint32_t N = ctx->rlweContext.parameter->polyDegree;
    Int64Vector scratch;
    r = Int64Vector_Create(&scratch, NULL, N);
    if (r != HIFHE_SUCCESS) {
        RLWE_CrtPoly_Destroy(out);
        return r;
    }
    if (ternary) {
        r = Kernel_Sampler_TernaryFixedWeight(scratch.data, N,
                                              BGV_SECRET_WEIGHT(N), src);
    } else {
        r = Kernel_Sampler_CBD(scratch.data, N, 2u, src);
    }
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
    return HIFHE_SUCCESS;
}

/* ---- KeyGenerator lifecycle ---- */

HIFHE_ERROR BGV_KeyGenerator_Create(KeyGenerator *out, BGVContext *ctx)
{
    if (out == NULL || ctx == NULL) return HIFHE_NULL_INPUT;
    memset(out, 0, sizeof(*out));
    out->context = ctx;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_KeyGenerator_Destroy(KeyGenerator *self)
{
    if (self == NULL) return HIFHE_NULL_INPUT;
    BGV_SecretKey_Free(&self->sk);
    self->context = NULL;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_KeyGenerator_GenSecretKey(KeyGenerator *self)
{
    if (self == NULL || self->context == NULL) return HIFHE_NULL_INPUT;
    BGV_SecretKey_Free(&self->sk);

    /* Sample ternary secret into a coefficient-form CrtPoly, then NTT. */
    CrtPoly poly;
    const uint8_t *seed = BgvContext_GetSeed(&self->context->rlweContext.seedCtx);
    BgvLabel lbl;
    BgvEntropy src = BgvEntropy_Seeded(seed, seed ? HIFHE_CTX_SEED_LEN : 0u,
                                       BgvLabel_Build(&lbl, "sk", NULL, 0u, NULL));
    int32_t r = SampleSmallCrtCoeff(&poly, self->context, &src, true);
    if (r != HIFHE_SUCCESS) return r;
    r = RLWE_CrtPoly_ToNtt(&poly);
    if (r != HIFHE_SUCCESS) {
        CleanseAndDestroy(&poly);
        return r;
    }

    /* SecretKey = Plaintext. The buffer already came from
     * RLWE_CrtPoly_Create, so hand it over rather than allocating again. */
    self->sk = BGV_SecretKey_New();
    if (self->sk == NULL) {
        CleanseAndDestroy(&poly);
        return HIFHE_MEMORY_ERROR;
    }
    r = BGV_Plaintext_CreateFromCrtPoly(self->sk, &poly, 1u, self->context);
    if (r != HIFHE_SUCCESS) {
        BGV_SecretKey_Free(&self->sk);
        CleanseAndDestroy(&poly);
        return r;
    }
    return HIFHE_SUCCESS;
}

/* Core encryption of `target` (NTT form, cipher base), giving
 *   b = -a*s + t*e + shift*target,  a
 * used as one keyswitch-key piece or as a public key. `shiftPerLimb` carries
 * the gadget factor already reduced mod each q_l, since T^j * qhat_i
 * generally exceeds 64 bits. NULL gives a plain pk / ct-of-zero. */
static HIFHE_ERROR MakeKeyPiece(Ciphertext *out,
                              const CrtPoly *sk_ntt,
                              const CrtPoly *target_ntt,
                              const uint64_t *shiftPerLimb,
                              BGVContext *ctx,
                              const uint8_t *seed, uint32_t seedLen,
                              const char *path, const uint64_t *idx, uint32_t nIdx)
{
    CiphertextConfig cfg;
    int32_t r = BGV_CiphertextConfig_Create(&cfg, 2u, ctx->bgvParameter->correctionFactor,
                                            &ctx->rlweContext.cipherRnsBase);
    if (r != HIFHE_SUCCESS) return r;
    r = BGV_Ciphertext_Create(out, &cfg, ctx);
    BGV_CiphertextConfig_Destroy(&cfg);
    if (r != HIFHE_SUCCESS) return r;

    Modulus t = ctx->bgvParameter->plainMod;

    /* Sibling labels under this piece's path: no two pieces, no two roles
     * share a stream. */
    BgvLabel lblA, lblE;
    BgvEntropy srcA = BgvEntropy_Seeded(seed, seedLen,
                                        BgvLabel_Build(&lblA, path, idx, nIdx, "a"));
    BgvEntropy srcE = BgvEntropy_Seeded(seed, seedLen,
                                        BgvLabel_Build(&lblE, path, idx, nIdx, "e"));

    /* a: uniform in NTT. */
    CrtPoly a;
    r = SampleUniformCrtNtt(&a, ctx, &srcA);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(out);
        return r;
    }

    /* e: small (CBD-2), then NTT. */
    CrtPoly e;
    r = SampleSmallCrtCoeff(&e, ctx, &srcE, false);
    if (r != HIFHE_SUCCESS) {
        RLWE_CrtPoly_Destroy(&a);
        BGV_Ciphertext_Destroy(out);
        return r;
    }
    r = RLWE_CrtPoly_ToNtt(&e);
    if (r != HIFHE_SUCCESS) {
        RLWE_CrtPoly_Destroy(&a);
        RLWE_CrtPoly_Destroy(&e);
        BGV_Ciphertext_Destroy(out);
        return r;
    }

    /* b0 = t*e - a*s [+ shift*target], b1 = a.
     * b1 is scratch until b0 is done. */
    CrtPoly b0, b1;
    r = BGV_Ciphertext_GetCrtPolyAt(&b0, 0u, out);
    if (r != HIFHE_SUCCESS) goto cleanup;
    r = BGV_Ciphertext_GetCrtPolyAt(&b1, 1u, out);
    if (r != HIFHE_SUCCESS) goto cleanup;

    r = RLWE_CrtPoly_MulScalar(&b0, &e, t);            if (r != HIFHE_SUCCESS) goto cleanup;
    r = RLWE_CrtPoly_MulDot(&b1, &a, sk_ntt);          if (r != HIFHE_SUCCESS) goto cleanup;
    r = RLWE_CrtPoly_Sub(&b0, &b0, &b1);               if (r != HIFHE_SUCCESS) goto cleanup;
    if (shiftPerLimb != NULL && target_ntt != NULL) {
        r = RLWE_CrtPoly_MulScalarPerLimb(&b1, target_ntt, shiftPerLimb);
        if (r != HIFHE_SUCCESS) goto cleanup;
        r = RLWE_CrtPoly_Add(&b0, &b0, &b1);
        if (r != HIFHE_SUCCESS) goto cleanup;
    }
    r = RLWE_CrtPoly_Assign(&b1, &a);
cleanup:
    RLWE_CrtPoly_Destroy(&a);
    RLWE_CrtPoly_Destroy(&e);
    if (r != HIFHE_SUCCESS) BGV_Ciphertext_Destroy(out);
    return r;
}

HIFHE_ERROR BGV_KeyGenerator_GenPublicKey(PublicKey *out, const KeyGenerator *self)
{
    if (out == NULL || self == NULL || self->sk == NULL) return HIFHE_NULL_INPUT;
    /* pk = enc_of_zero under sk: b = -a*s + t*e, a. */
    CrtPoly sk_view;
    int32_t r = RLWE_CrtPoly_CreateFromExist(&sk_view, self->sk->data, self->sk->dataSize,
                                             &self->sk->config.crtConfig, &self->context->rlweContext);
    if (r != HIFHE_SUCCESS) return r;
    const uint8_t *seed = BgvContext_GetSeed(&self->context->rlweContext.seedCtx);
    r = MakeKeyPiece(out, &sk_view, NULL, NULL, self->context,
                     seed, seed ? HIFHE_CTX_SEED_LEN : 0u, "pk", NULL, 0u);
    RLWE_CrtPoly_Destroy(&sk_view);
    return r;
}

HIFHE_ERROR BGV_KeyGenerator_GenRelinKey(RelinKeys *out, uint32_t digits,
                                       const KeyGenerator *self)
{
    if (out == NULL || self == NULL || self->sk == NULL) return HIFHE_NULL_INPUT;
    /* Non-owning view onto sk_ntt, live until the last MakeKeyPiece. */
    CrtPoly sk_view;
    int32_t r = RLWE_CrtPoly_CreateFromExist(&sk_view, self->sk->data, self->sk->dataSize,
                                             &self->sk->config.crtConfig, &self->context->rlweContext);
    if (r != HIFHE_SUCCESS) return r;

    /* Compute s^2 in NTT form. */
    CrtPoly sk_sq;
    memset(&sk_sq, 0, sizeof(sk_sq));
    r = RLWE_CrtPoly_Copy(&sk_sq, &sk_view);
    if (r != HIFHE_SUCCESS) {
        RLWE_CrtPoly_Destroy(&sk_view);
        return r;
    }
    r = RLWE_CrtPoly_MulDot(&sk_sq, &sk_sq, &sk_sq);
    if (r != HIFHE_SUCCESS) {
        CleanseAndDestroy(&sk_sq);
        RLWE_CrtPoly_Destroy(&sk_view);
        return r;
    }

    const RnsBase *base = &self->context->rlweContext.cipherRnsBase;
    uint32_t L = base->size;
    uint32_t required = BGV_BV_DigitsForBase(base);
    if (digits == 0u) digits = required;
    /* Below `required` the decomposition silently loses its high digits;
     * above BGV_KSW_MAX_DIGITS the piece count L * digits wraps uint32 and
     * the generation loop writes past the allocation. */
    if (digits < required || digits > BGV_KSW_MAX_DIGITS) {
        CleanseAndDestroy(&sk_sq);
        RLWE_CrtPoly_Destroy(&sk_view);
        return HIFHE_PARAM_INVALID;
    }
    r = BGV_RelinKeys_Create(out, L, digits, self->context);
    if (r != HIFHE_SUCCESS) {
        CleanseAndDestroy(&sk_sq);
        RLWE_CrtPoly_Destroy(&sk_view);
        return r;
    }

    const uint8_t *seed = BgvContext_GetSeed(&self->context->rlweContext.seedCtx);
    uint64_t gadget[HIFHE_BGV_MAX_CHAIN_LEN];
    for (uint32_t i = 0; i < L; ++i) {
        for (uint32_t j = 0; j < digits; ++j) {
            r = BGV_KeySwitch_GadgetFactor(gadget, base, i, j);
            if (r == HIFHE_SUCCESS) {
                const uint64_t idx[2] = { (uint64_t)i, (uint64_t)j };
                r = MakeKeyPiece(&out->pieces[i * digits + j], &sk_view, &sk_sq, gadget,
                                 self->context, seed, seed ? HIFHE_CTX_SEED_LEN : 0u,
                                 "relin", idx, 2u);
            }
            if (r != HIFHE_SUCCESS) {
                CleanseAndDestroy(&sk_sq); RLWE_CrtPoly_Destroy(&sk_view);
                BGV_RelinKeys_Destroy(out);
                return r;
            }
        }
    }
    CleanseAndDestroy(&sk_sq);
    RLWE_CrtPoly_Destroy(&sk_view);
    return HIFHE_SUCCESS;
}

/* sigma_k(s): substitute X -> X^k, k odd and coprime to 2N.
 * Returns a fresh CrtPoly in POLY form. */
static HIFHE_ERROR ApplyGaloisToCoeffPoly(CrtPoly *out, const CrtPoly *in, uint64_t k, uint32_t N)
{
    if (out == NULL || in == NULL) return HIFHE_NULL_INPUT;
    /* `in` is POLY form. Destination index is (j*k) mod 2N; landing in
     * [N, 2N) maps to the top half and flips sign. */
    int32_t r = RLWE_CrtPoly_Copy(out, in);
    if (r != HIFHE_SUCCESS) return r;
    memset(out->data, 0, out->dataSize * sizeof(uint64_t));

    for (uint32_t i = 0; i < in->config.rnsbase.size; ++i) {
        Modulus q = in->config.rnsbase.data[i];
        const uint64_t *src = in->data + i * N;
        uint64_t *dst = out->data + i * N;
        /* 2N is a power of two, so the reduction is a mask. The index
         * advances by k per step instead of being multiplied. */
        const uint64_t mask = 2u * (uint64_t)N - 1u;
        uint64_t walk = 0u;
        for (uint32_t j = 0; j < N; ++j) {
            uint64_t idx = walk;
            walk = (walk + k) & mask;
            uint64_t v = src[j];
            if (idx >= N) {
                idx -= N;
                v = (v == 0u) ? 0u : (q - v);   /* sign flip */
            }
            dst[idx] = v;
        }
    }
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_KeyGenerator_GenGaloisKeys(GaloisKeys *out,
                                         const uint64_t *elts, uint32_t count,
                                         const KeyGenerator *self)
{
    if (out == NULL || self == NULL || self->sk == NULL || elts == NULL) return HIFHE_NULL_INPUT;
    uint32_t N = self->context->rlweContext.parameter->polyDegree;
    /* sigma_k permutes coefficients only for odd k below 2N. An even element
     * sends two sources to one destination and leaves the rest of the
     * polynomial zeroed, so the key would rotate to garbage without error. */
    for (uint32_t i = 0; i < count; ++i) {
        if ((elts[i] & 1u) == 0u || elts[i] >= 2u * (uint64_t)N) return HIFHE_PARAM_INVALID;
    }

    /* The Galois permutation needs sk in coefficient form; inverse-NTT a copy. */
    CrtPoly sk_view;
    int32_t r = RLWE_CrtPoly_CreateFromExist(&sk_view, self->sk->data, self->sk->dataSize,
                                             &self->sk->config.crtConfig, &self->context->rlweContext);
    if (r != HIFHE_SUCCESS) return r;
    CrtPoly sk_coeff;
    memset(&sk_coeff, 0, sizeof(sk_coeff));
    r = RLWE_CrtPoly_Copy(&sk_coeff, &sk_view);
    RLWE_CrtPoly_Destroy(&sk_view);
    if (r != HIFHE_SUCCESS) return r;
    r = RLWE_CrtPoly_ToPoly(&sk_coeff);
    if (r != HIFHE_SUCCESS) {
        CleanseAndDestroy(&sk_coeff);
        return r;
    }

    BGV_GaloisKeys_Destroy(out);
    r = BGV_GaloisKeys_Create(out, self->context);
    if (r != HIFHE_SUCCESS) {
        CleanseAndDestroy(&sk_coeff);
        return r;
    }

    r = BGV_GaloisKeys_CreateEntries(out, count);
    if (r != HIFHE_SUCCESS) {
        CleanseAndDestroy(&sk_coeff);
        return r;
    }

    /* MakeKeyPiece needs sk in NTT form for the -a*s term. */
    CrtPoly sk_ntt_view;
    r = RLWE_CrtPoly_CreateFromExist(&sk_ntt_view, self->sk->data, self->sk->dataSize,
                                     &self->sk->config.crtConfig, &self->context->rlweContext);
    if (r != HIFHE_SUCCESS) {
        CleanseAndDestroy(&sk_coeff); BGV_GaloisKeys_Destroy(out);
        return r;
    }

    const RnsBase *base = &self->context->rlweContext.cipherRnsBase;
    uint32_t L = base->size;
    uint32_t digits = BGV_BV_DigitsForBase(base);
    const uint8_t *seed = BgvContext_GetSeed(&self->context->rlweContext.seedCtx);
    uint64_t gadget[HIFHE_BGV_MAX_CHAIN_LEN];

    for (uint32_t i = 0; i < count; ++i) {
        uint64_t k = elts[i];
        CrtPoly target;
        memset(&target, 0, sizeof(target));
        r = ApplyGaloisToCoeffPoly(&target, &sk_coeff, k, N);
        if (r != HIFHE_SUCCESS) goto giveup;
        r = RLWE_CrtPoly_ToNtt(&target);
        if (r != HIFHE_SUCCESS) {
            RLWE_CrtPoly_Destroy(&target);
            goto giveup;
        }

        r = BGV_GaloisKeyPiece_Create(&out->entries[i], k, L, digits);
        if (r != HIFHE_SUCCESS) {
            RLWE_CrtPoly_Destroy(&target);
            goto giveup;
        }
        for (uint32_t li = 0; li < L; ++li) {
            for (uint32_t j = 0; j < digits; ++j) {
                r = BGV_KeySwitch_GadgetFactor(gadget, base, li, j);
                if (r == HIFHE_SUCCESS) {
                    const uint64_t idx[3] = { k, (uint64_t)li, (uint64_t)j };
                    r = MakeKeyPiece(&out->entries[i].pieces[li * digits + j],
                                     &sk_ntt_view, &target, gadget,
                                     self->context, seed, seed ? HIFHE_CTX_SEED_LEN : 0u,
                                     "galois", idx, 3u);
                }
                if (r != HIFHE_SUCCESS) {
                    RLWE_CrtPoly_Destroy(&target);
                    goto giveup;
                }
            }
        }
        RLWE_CrtPoly_Destroy(&target);
    }
    RLWE_CrtPoly_Destroy(&sk_ntt_view);
    CleanseAndDestroy(&sk_coeff);
    return HIFHE_SUCCESS;

giveup:
    RLWE_CrtPoly_Destroy(&sk_ntt_view);
    CleanseAndDestroy(&sk_coeff);
    BGV_GaloisKeys_Destroy(out);
    return r;
}

