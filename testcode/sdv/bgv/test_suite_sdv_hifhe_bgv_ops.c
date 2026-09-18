/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 */

/* BEGIN_HEADER */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "crypt_errno.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "bsl_params.h"
#include "crypt_eal_rand.h"
#include "crypt_algid.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_init.h"
#include "crypt_types.h"
#include "crypt_params_key.h"

#include "hifhe_provider.h"
#include "hifhe_types.h"
#include "bgv_local.h"
#include "bgv/keys.h"
#include "bgv/encoder.h"
#include "bgv/encryptor.h"
#include "bgv/evaluator.h"
#include "bgv/ciphertext.h"
#include "bgv/plaintext.h"
#include "hifhe_err.h"
/* White-box reach into the module under test: recovering a sampled secret
 * from its wire needs the kernel transform and the modular helpers. */
#include "kernel/modulus.h"
#include "kernel/sampler.h"
#include "basic/rand.h"
#include "kernel/ntt.h"
#include "crypto_test_util.h"
#include "test.h"
/* END_HEADER */

#define HIFHE_N 2048u

static CRYPT_EAL_PkeyCtx *BgvNewCtx(int32_t preset)
{
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(
        NULL, HIFHE_PKEY_BGV, CRYPT_EAL_PKEY_CIPHER_OPERATE, HIFHE_PROVIDER_ATTR);
    if (ctx == NULL) return NULL;
    if (CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &preset, sizeof(preset)) != HIFHE_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return NULL;
    }
    return ctx;
}

/* Shape of one parameter set, as reported through the EAL ctrl surface. */
typedef struct {
    uint32_t n;        /* polyDegree == slot count */
    uint32_t ptLen;    /* plaintext wire length */
    uint32_t ctLen;    /* ciphertext wire length */
    uint32_t msgLen;   /* message vector bytes */
    uint32_t level;    /* RNS chain length */
    uint64_t t;        /* plaintext modulus */
} BgvDims;

static int BgvDimsGet(CRYPT_EAL_PkeyCtx *ctx, BgvDims *d)
{
    memset(d, 0, sizeof(*d));
    if (CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &d->n, sizeof(d->n)) != HIFHE_SUCCESS ||
        CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &d->ptLen, sizeof(d->ptLen)) != HIFHE_SUCCESS ||
        CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &d->ctLen, sizeof(d->ctLen)) != HIFHE_SUCCESS ||
        CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN, &d->msgLen, sizeof(d->msgLen)) != HIFHE_SUCCESS ||
        CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_LEVEL, &d->level, sizeof(d->level)) != HIFHE_SUCCESS ||
        CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD, &d->t, sizeof(d->t)) != HIFHE_SUCCESS) {
        return -1;
    }
    return 0;
}

static int BgvEncode(CRYPT_EAL_PkeyCtx *ctx, const uint64_t *msg, uint32_t msgLen,
                     uint8_t *pt, uint32_t cap, uint32_t *ptLen)
{
    BSL_Param in[] = {
        {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, (void *)(uintptr_t)msg, msgLen, 0},
        BSL_PARAM_END
    };
    uint32_t out = cap;
    if (CRYPT_EAL_PkeyHEMsgEncode(ctx, in, pt, &out) != HIFHE_SUCCESS) return -1;
    *ptLen = out;
    return 0;
}

static int BgvDecode(CRYPT_EAL_PkeyCtx *ctx, const uint8_t *pt, uint32_t ptLen,
                     uint64_t *msg, uint32_t msgLen)
{
    BSL_Param in[] = {
        {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, (void *)(uintptr_t)pt, ptLen, 0},
        BSL_PARAM_END
    };
    uint32_t out = msgLen;
    if (CRYPT_EAL_PkeyHEMsgDecode(ctx, in, (uint8_t *)msg, &out) != HIFHE_SUCCESS) return -1;
    return 0;
}

/* Encrypt-decrypt roundtrip via the EAL surface. */
static int RunEncDec(int32_t preset)
{
    int rc = -1;
    CRYPT_EAL_PkeyCtx *ctx = BgvNewCtx(preset);
    if (ctx == NULL) return -1;
    if (CRYPT_EAL_PkeyGen(ctx) != HIFHE_SUCCESS) goto out;

    BgvDims d;
    if (BgvDimsGet(ctx, &d) != 0) goto out;
    uint32_t ptLen = d.ptLen, ctLen = d.ctLen, msgLen = d.msgLen;

    uint64_t *msgIn  = (uint64_t *)BSL_SAL_Malloc(msgLen);
    uint64_t *msgOut = (uint64_t *)BSL_SAL_Malloc(msgLen);
    uint8_t  *pt     = (uint8_t *)BSL_SAL_Malloc(ptLen);
    uint8_t  *ct     = (uint8_t *)BSL_SAL_Malloc(ctLen);
    uint8_t  *pt2    = (uint8_t *)BSL_SAL_Malloc(ptLen);
    if (!msgIn || !msgOut || !pt || !ct || !pt2) goto cleanup;

    for (uint32_t i = 0; i < d.n; ++i) msgIn[i] = (uint64_t)((i * 7u + 3u) % 100u);

    BSL_Param encIn[] = {
        {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, msgIn, msgLen, 0},
        BSL_PARAM_END
    };
    uint32_t out = ptLen;
    if (CRYPT_EAL_PkeyHEMsgEncode(ctx, encIn, pt, &out) != HIFHE_SUCCESS) goto cleanup;
    uint32_t ptRealLen = out;
    out = ctLen;
    if (CRYPT_EAL_PkeyEncrypt(ctx, pt, ptRealLen, ct, &out) != HIFHE_SUCCESS) goto cleanup;
    uint32_t ctRealLen = out;
    out = ptLen;
    if (CRYPT_EAL_PkeyDecrypt(ctx, ct, ctRealLen, pt2, &out) != HIFHE_SUCCESS) goto cleanup;
    uint32_t pt2Len = out;

    BSL_Param decIn[] = {
        {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, pt2, pt2Len, 0},
        BSL_PARAM_END
    };
    out = msgLen;
    if (CRYPT_EAL_PkeyHEMsgDecode(ctx, decIn, (uint8_t *)msgOut, &out) != HIFHE_SUCCESS) goto cleanup;

    for (uint32_t i = 0; i < d.n; ++i) {
        if (msgOut[i] != msgIn[i]) goto cleanup;
    }
    rc = 0;
cleanup:
    BSL_SAL_Free(msgIn); BSL_SAL_Free(msgOut);
    BSL_SAL_Free(pt); BSL_SAL_Free(ct); BSL_SAL_Free(pt2);
out:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return rc;
}

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_ENCDEC_DEFAULT_TC001
* @title  Encrypt-decrypt roundtrip under HIFHE_BGV_DEFAULT.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_ENCDEC_DEFAULT_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    TestMemInit();
    TestRandInit();
    ASSERT_EQ(RunEncDec(HIFHE_BGV_DEFAULT), 0);
EXIT:
    ;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_ENCDEC_17BIT_TC001
* @title  Encrypt-decrypt roundtrip under HIFHE_BGV_2048_48_17BIT.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_ENCDEC_17BIT_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    TestMemInit();
    TestRandInit();
    ASSERT_EQ(RunEncDec(HIFHE_BGV_2048_48_17BIT), 0);
EXIT:
    ;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_HEADD_CTPT_TC001
* @title  HEAdd(ct, pt) then decrypt matches msg1 + msg2 mod t.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_HEADD_CTPT_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m1 = NULL, *m2 = NULL, *mo = NULL;
    uint8_t *pt1 = NULL, *pt2 = NULL, *ct1 = NULL, *ctSum = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    uint32_t ptLen = 0u, ctLen = 0u, msgLen = 0u;
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &ptLen, sizeof(ptLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN, &msgLen, sizeof(msgLen));
    m1  = (uint64_t *)BSL_SAL_Malloc(msgLen);
    m2  = (uint64_t *)BSL_SAL_Malloc(msgLen);
    mo  = (uint64_t *)BSL_SAL_Malloc(msgLen);
    pt1 = (uint8_t *)BSL_SAL_Malloc(ptLen);
    pt2 = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ct1 = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ctSum = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ASSERT_TRUE(m1 && m2 && mo && pt1 && pt2 && ct1 && ctSum && ptOut);

    for (uint32_t i = 0; i < HIFHE_N; ++i) { m1[i] = (i % 50u); m2[i] = ((i * 3u + 1u) % 50u); }

    BSL_Param encM1[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m1, msgLen, 0}, BSL_PARAM_END };
    BSL_Param encM2[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m2, msgLen, 0}, BSL_PARAM_END };
    uint32_t out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encM1, pt1, &out), HIFHE_SUCCESS);
    uint32_t pt1L = out;
    out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encM2, pt2, &out), HIFHE_SUCCESS);
    uint32_t pt2L = out;
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt1, pt1L, ct1, &out), HIFHE_SUCCESS);
    uint32_t ct1L = out;

    BSL_Param addIn[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
        {HIFHE_PARAM_BGV_PLAINTEXT,   BSL_PARAM_TYPE_OCTETS, pt2, pt2L, 0},
        BSL_PARAM_END
    };
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEAdd(ctx, addIn, ctSum, &out), HIFHE_SUCCESS);
    uint32_t ctSumL = out;

    out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctSum, ctSumL, ptOut, &out), HIFHE_SUCCESS);
    uint32_t ptOutL = out;

    BSL_Param decIn[] = { {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, ptOut, ptOutL, 0}, BSL_PARAM_END };
    out = msgLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(ctx, decIn, (uint8_t *)mo, &out), HIFHE_SUCCESS);

    uint64_t plainMod = 0u;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD, &plainMod, sizeof(plainMod)), HIFHE_SUCCESS);
    for (uint32_t i = 0; i < 64u; ++i) {
        uint64_t expected = (m1[i] + m2[i]) % plainMod;
        ASSERT_EQ(mo[i], expected);
    }
EXIT:
    BSL_SAL_Free(m1); BSL_SAL_Free(m2); BSL_SAL_Free(mo);
    BSL_SAL_Free(pt1); BSL_SAL_Free(pt2); BSL_SAL_Free(ct1); BSL_SAL_Free(ctSum); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_HEADD_NEG_TC001
* @title  HEAdd with NEGATE marker computes -ct; decrypt matches (-m) mod t.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_HEADD_NEG_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL, *mo = NULL;
    uint8_t *pt = NULL, *ct = NULL, *ctNeg = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    uint32_t ptLen = 0u, ctLen = 0u, msgLen = 0u;
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &ptLen, sizeof(ptLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN, &msgLen, sizeof(msgLen));
    m = (uint64_t *)BSL_SAL_Malloc(msgLen);
    mo = (uint64_t *)BSL_SAL_Malloc(msgLen);
    pt = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ct = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ctNeg = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ASSERT_TRUE(m && mo && pt && ct && ctNeg && ptOut);

    for (uint32_t i = 0; i < HIFHE_N; ++i) m[i] = ((i * 5u) % 40u) + 1u;

    BSL_Param encIn[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m, msgLen, 0}, BSL_PARAM_END };
    uint32_t out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encIn, pt, &out), HIFHE_SUCCESS);
    uint32_t ptL = out;
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct, &out), HIFHE_SUCCESS);
    uint32_t ctL = out;

    uint8_t marker = 1u;
    BSL_Param negIn[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct, ctL, 0},
        {HIFHE_PARAM_BGV_NEGATE,      BSL_PARAM_TYPE_OCTETS, &marker, 1, 0},
        BSL_PARAM_END
    };
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEAdd(ctx, negIn, ctNeg, &out), HIFHE_SUCCESS);
    uint32_t ctNegL = out;

    out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctNeg, ctNegL, ptOut, &out), HIFHE_SUCCESS);
    uint32_t ptOutL = out;

    BSL_Param decIn[] = { {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, ptOut, ptOutL, 0}, BSL_PARAM_END };
    out = msgLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(ctx, decIn, (uint8_t *)mo, &out), HIFHE_SUCCESS);

    uint64_t plainMod = 0u;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD, &plainMod, sizeof(plainMod)), HIFHE_SUCCESS);
    for (uint32_t i = 0; i < 64u; ++i) {
        uint64_t expected = (plainMod - (m[i] % plainMod)) % plainMod;
        ASSERT_EQ(mo[i], expected);
    }
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(mo);
    BSL_SAL_Free(pt); BSL_SAL_Free(ct); BSL_SAL_Free(ctNeg); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_HEMUL_CTPT_TC001
* @title  HEMul(ct, pt) then decrypt matches m1 * m2 mod t.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_HEMUL_CTPT_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m1 = NULL, *m2 = NULL, *mo = NULL;
    uint8_t *pt1 = NULL, *pt2 = NULL, *ct1 = NULL, *ctMul = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    uint32_t ptLen = 0u, ctLen = 0u, msgLen = 0u;
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &ptLen, sizeof(ptLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN, &msgLen, sizeof(msgLen));
    m1 = (uint64_t *)BSL_SAL_Malloc(msgLen);
    m2 = (uint64_t *)BSL_SAL_Malloc(msgLen);
    mo = (uint64_t *)BSL_SAL_Malloc(msgLen);
    pt1 = (uint8_t *)BSL_SAL_Malloc(ptLen);
    pt2 = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ct1 = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ctMul = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ASSERT_TRUE(m1 && m2 && mo && pt1 && pt2 && ct1 && ctMul && ptOut);

    /* Constant polynomials only, so the product is a scalar multiply with no
     * cross-coefficient terms from the negacyclic wrap. */
    for (uint32_t i = 0; i < HIFHE_N; ++i) { m1[i] = (i == 0u) ? 5u : 0u; m2[i] = (i == 0u) ? 3u : 0u; }

    BSL_Param encM1[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m1, msgLen, 0}, BSL_PARAM_END };
    BSL_Param encM2[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m2, msgLen, 0}, BSL_PARAM_END };
    uint32_t out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encM1, pt1, &out), HIFHE_SUCCESS);
    uint32_t pt1L = out;
    out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encM2, pt2, &out), HIFHE_SUCCESS);
    uint32_t pt2L = out;
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt1, pt1L, ct1, &out), HIFHE_SUCCESS);
    uint32_t ct1L = out;

    BSL_Param mulIn[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
        {HIFHE_PARAM_BGV_PLAINTEXT,   BSL_PARAM_TYPE_OCTETS, pt2, pt2L, 0},
        BSL_PARAM_END
    };
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMul(ctx, mulIn, ctMul, &out), HIFHE_SUCCESS);
    uint32_t ctMulL = out;

    out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctMul, ctMulL, ptOut, &out), HIFHE_SUCCESS);
    uint32_t ptOutL = out;

    BSL_Param decIn[] = { {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, ptOut, ptOutL, 0}, BSL_PARAM_END };
    out = msgLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(ctx, decIn, (uint8_t *)mo, &out), HIFHE_SUCCESS);

    uint64_t plainMod = 0u;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD, &plainMod, sizeof(plainMod)), HIFHE_SUCCESS);
    /* Constant polynomial: m1 * m2 in coefficient 0, zero elsewhere. */
    ASSERT_EQ(mo[0], (5u * 3u) % plainMod);
EXIT:
    BSL_SAL_Free(m1); BSL_SAL_Free(m2); BSL_SAL_Free(mo);
    BSL_SAL_Free(pt1); BSL_SAL_Free(pt2); BSL_SAL_Free(ct1); BSL_SAL_Free(ctMul); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_ERR_MODSWITCH_EXHAUSTED_TC001
* @title  ModSwitch on a single-modulus preset returns MODSWITCH_EXHAUSTED.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_ERR_MODSWITCH_EXHAUSTED_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL;
    uint8_t *pt = NULL, *ct = NULL, *ctOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    uint32_t ptLen = 0u, ctLen = 0u, msgLen = 0u;
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &ptLen, sizeof(ptLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN, &msgLen, sizeof(msgLen));
    m = (uint64_t *)BSL_SAL_Malloc(msgLen);
    pt = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ct = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ctOut = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ASSERT_TRUE(m && pt && ct && ctOut);

    for (uint32_t i = 0; i < HIFHE_N; ++i) m[i] = 1u;
    BSL_Param encIn[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m, msgLen, 0}, BSL_PARAM_END };
    uint32_t out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encIn, pt, &out), HIFHE_SUCCESS);
    uint32_t ptL = out;
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct, &out), HIFHE_SUCCESS);
    uint32_t ctL = out;

    BSL_Param msIn[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct,    ctL,   0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ctOut, ctLen, 0},
        BSL_PARAM_END
    };
    int32_t rc = CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_HE_MODSWITCH, msIn, 0u);
    ASSERT_EQ(rc, HIFHE_MODSWITCH_EXHAUSTED);
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(pt); BSL_SAL_Free(ct); BSL_SAL_Free(ctOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEEDED_KEYGEN_TC001
* @title  Two ctxs with the same 32-byte seed produce byte-identical sk/pk.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEEDED_KEYGEN_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *a = NULL, *b = NULL;
    uint8_t seed[HIFHE_BGV_SEED_LEN];
    uint8_t *pkA = NULL, *pkB = NULL;

    TestMemInit();
    TestRandInit();
    for (uint32_t i = 0; i < HIFHE_BGV_SEED_LEN; ++i) seed[i] = (uint8_t)(0x5au + i);

    a = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    b = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(a && b);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(a, HIFHE_CTRL_BGV_SET_SEED, seed, HIFHE_BGV_SEED_LEN), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(b, HIFHE_CTRL_BGV_SET_SEED, seed, HIFHE_BGV_SEED_LEN), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(a), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(b), HIFHE_SUCCESS);

    uint32_t pkLen = 0u;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(a, HIFHE_CTRL_BGV_GET_PUBKEY_LEN, &pkLen, sizeof(pkLen)), HIFHE_SUCCESS);
    pkA = (uint8_t *)BSL_SAL_Malloc(pkLen);
    pkB = (uint8_t *)BSL_SAL_Malloc(pkLen);
    ASSERT_TRUE(pkA && pkB);

    BSL_Param getA[] = { {HIFHE_PARAM_BGV_PUBKEY, BSL_PARAM_TYPE_OCTETS, pkA, pkLen, 0}, BSL_PARAM_END };
    BSL_Param getB[] = { {HIFHE_PARAM_BGV_PUBKEY, BSL_PARAM_TYPE_OCTETS, pkB, pkLen, 0}, BSL_PARAM_END };
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(a, getA), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(b, getB), HIFHE_SUCCESS);
    ASSERT_EQ(getA[0].useLen, getB[0].useLen);
    ASSERT_EQ(memcmp(pkA, pkB, getA[0].useLen), 0);
EXIT:
    BSL_SAL_Free(pkA); BSL_SAL_Free(pkB);
    CRYPT_EAL_PkeyFreeCtx(a); CRYPT_EAL_PkeyFreeCtx(b);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_HEMUL_CTCT_RELIN_TC001
* @title  HEMul(ct, ct) with relin key auto-collapses size-3 to size-2 and decrypts to m1 * m2 mod t.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_HEMUL_CTCT_RELIN_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m1 = NULL, *m2 = NULL, *mo = NULL;
    uint8_t *pt1 = NULL, *pt2 = NULL, *ct1 = NULL, *ct2 = NULL, *ctMul = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GEN_RELIN_KEY, NULL, 0), HIFHE_SUCCESS);

    uint32_t ptLen = 0u, ctLen = 0u, msgLen = 0u;
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN,  &ptLen,  sizeof(ptLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen,  sizeof(ctLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN,        &msgLen, sizeof(msgLen));
    /* HEMul(ct*ct) internally builds a size-3 ciphertext before relin;
     * allocate a larger scratch so serialize/deserialize of the size-3
     * intermediate doesn't overflow. */
    uint32_t ctLenBig = ctLen * 3u;
    m1 = (uint64_t *)BSL_SAL_Malloc(msgLen);
    m2 = (uint64_t *)BSL_SAL_Malloc(msgLen);
    mo = (uint64_t *)BSL_SAL_Malloc(msgLen);
    pt1 = (uint8_t *)BSL_SAL_Malloc(ptLen);
    pt2 = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ct1 = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ct2 = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ctMul = (uint8_t *)BSL_SAL_Malloc(ctLenBig);
    ptOut = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ASSERT_TRUE(m1 && m2 && mo && pt1 && pt2 && ct1 && ct2 && ctMul && ptOut);

    /* Constant polynomials so we can predict the polynomial product. */
    for (uint32_t i = 0; i < HIFHE_N; ++i) { m1[i] = (i == 0u) ? 7u : 0u; m2[i] = (i == 0u) ? 11u : 0u; }

    BSL_Param encM1[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m1, msgLen, 0}, BSL_PARAM_END };
    BSL_Param encM2[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m2, msgLen, 0}, BSL_PARAM_END };
    uint32_t out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encM1, pt1, &out), HIFHE_SUCCESS);
    uint32_t pt1L = out;
    out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encM2, pt2, &out), HIFHE_SUCCESS);
    uint32_t pt2L = out;
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt1, pt1L, ct1, &out), HIFHE_SUCCESS);
    uint32_t ct1L = out;
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt2, pt2L, ct2, &out), HIFHE_SUCCESS);
    uint32_t ct2L = out;

    BSL_Param mulIn[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ct2, ct2L, 0},
        BSL_PARAM_END
    };
    out = ctLenBig;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMul(ctx, mulIn, ctMul, &out), HIFHE_SUCCESS);
    uint32_t ctMulL = out;

    out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctMul, ctMulL, ptOut, &out), HIFHE_SUCCESS);
    uint32_t ptOutL = out;

    BSL_Param decIn[] = { {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, ptOut, ptOutL, 0}, BSL_PARAM_END };
    out = msgLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(ctx, decIn, (uint8_t *)mo, &out), HIFHE_SUCCESS);

    uint64_t plainMod = 0u;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD, &plainMod, sizeof(plainMod)), HIFHE_SUCCESS);
    /* Constant polynomial: m1 * m2 in coefficient 0, zero elsewhere. */
    ASSERT_EQ(mo[0], (7u * 11u) % plainMod);
    /* constant x constant stays at coefficient 0 */
    ASSERT_EQ(mo[1], 0u);
    ASSERT_EQ(mo[7], 0u);
    ASSERT_EQ(mo[HIFHE_N - 1u], 0u);
EXIT:
    BSL_SAL_Free(m1); BSL_SAL_Free(m2); BSL_SAL_Free(mo);
    BSL_SAL_Free(pt1); BSL_SAL_Free(pt2); BSL_SAL_Free(ct1); BSL_SAL_Free(ct2);
    BSL_SAL_Free(ctMul); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_HIFHE_BGV_MULTIMOD_ENCDEC_TC001
* @title  Encrypt-decrypt roundtrip on a 2-limb RNS chain (4096 / 44x2).
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_MULTIMOD_ENCDEC_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    TestMemInit();
    TestRandInit();
    ASSERT_EQ(RunEncDec(HIFHE_BGV_4096_44x2_17BIT), 0);
EXIT:
    ;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_MULTIMOD_LEVEL_TC001
* @title  A multi-modulus preset reports its chain length through GET_LEVEL.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_MULTIMOD_LEVEL_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    TestMemInit();
    TestRandInit();

    ctx = BgvNewCtx(HIFHE_BGV_4096_44x2_17BIT);
    ASSERT_TRUE(ctx != NULL);
    BgvDims d;
    ASSERT_EQ(BgvDimsGet(ctx, &d), 0);
    ASSERT_EQ(d.n, 4096u);
    ASSERT_EQ(d.level, 2u);
    ASSERT_EQ(d.t, 65537u);
    /* Wire length must account for the serialized RNS base, one u64 per
     * limb, on top of the fixed body header. */
    ASSERT_EQ(d.ptLen, 12u + 8u + 4u + 4u + 4u + 2u * 8u + 2u * 4096u * 8u);
    ASSERT_EQ(d.ctLen, 12u + 4u + 8u + 32u + 4u + 4u + 4u + 2u * 8u + 2u * 2u * 4096u * 8u);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_MODSWITCH_TC001
* @title  ModSwitch drops one limb, preserves the message, and reports
*         EXHAUSTED once the chain is down to a single modulus.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_MODSWITCH_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL, *mo = NULL;
    uint8_t *pt = NULL, *ct = NULL, *ctMs = NULL, *ctMs2 = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_4096_44x2_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    BgvDims d;
    ASSERT_EQ(BgvDimsGet(ctx, &d), 0);
    m     = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    mo    = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    pt    = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ct    = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ctMs  = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ctMs2 = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ASSERT_TRUE(m && mo && pt && ct && ctMs && ctMs2 && ptOut);

    for (uint32_t i = 0; i < d.n; ++i) m[i] = (uint64_t)((i * 11u + 4u) % 97u);

    uint32_t ptL = 0u;
    ASSERT_EQ(BgvEncode(ctx, m, d.msgLen, pt, d.ptLen, &ptL), 0);
    uint32_t out = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct, &out), HIFHE_SUCCESS);
    uint32_t ctL = out;

    BSL_Param msIn[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct,   ctL,     0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ctMs, d.ctLen, 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_HE_MODSWITCH, msIn, 0u), HIFHE_SUCCESS);
    uint32_t ctMsL = msIn[1].useLen;
    /* One limb fewer: the ciphertext body shrinks by 8 (rnsBase entry) plus
     * 2 components * polyDegree * 8 bytes of payload. */
    ASSERT_EQ(ctMsL, ctL - 8u - 2u * d.n * 8u);

    out = d.ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctMs, ctMsL, ptOut, &out), HIFHE_SUCCESS);
    ASSERT_EQ(BgvDecode(ctx, ptOut, out, mo, d.msgLen), 0);
    for (uint32_t i = 0; i < d.n; ++i) {
        ASSERT_EQ(mo[i], m[i] % d.t);
    }

    /* Chain is down to one modulus now. */
    BSL_Param ms2In[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ctMs,  ctMsL,   0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ctMs2, d.ctLen, 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_HE_MODSWITCH, ms2In, 0u),
              HIFHE_MODSWITCH_EXHAUSTED);
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(mo); BSL_SAL_Free(pt);
    BSL_SAL_Free(ct); BSL_SAL_Free(ctMs); BSL_SAL_Free(ctMs2); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_MULTIMOD_MUL_RELIN_TC001
* @title  ct*ct + relinearize over a 2-limb chain exercises the RNS x BV
*         gadget (q-hat_i factors), not just the single-limb degenerate case.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_MULTIMOD_MUL_RELIN_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m1 = NULL, *m2 = NULL, *mo = NULL;
    uint8_t *pt1 = NULL, *pt2 = NULL, *ct1 = NULL, *ct2 = NULL, *ctMul = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_4096_44x2_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GEN_RELIN_KEY, NULL, 0), HIFHE_SUCCESS);

    BgvDims d;
    ASSERT_EQ(BgvDimsGet(ctx, &d), 0);
    uint32_t ctBig = d.ctLen * 3u;
    m1 = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    m2 = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    mo = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    pt1 = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    pt2 = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ct1 = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ct2 = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ctMul = (uint8_t *)BSL_SAL_Malloc(ctBig);
    ptOut = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ASSERT_TRUE(m1 && m2 && mo && pt1 && pt2 && ct1 && ct2 && ctMul && ptOut);

    /* Constant polynomials, so the ring product is a plain scalar product. */
    for (uint32_t i = 0; i < d.n; ++i) { m1[i] = (i == 0u) ? 9u : 0u; m2[i] = (i == 0u) ? 13u : 0u; }

    uint32_t pt1L = 0u, pt2L = 0u;
    ASSERT_EQ(BgvEncode(ctx, m1, d.msgLen, pt1, d.ptLen, &pt1L), 0);
    ASSERT_EQ(BgvEncode(ctx, m2, d.msgLen, pt2, d.ptLen, &pt2L), 0);
    uint32_t out = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt1, pt1L, ct1, &out), HIFHE_SUCCESS);
    uint32_t ct1L = out;
    out = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt2, pt2L, ct2, &out), HIFHE_SUCCESS);
    uint32_t ct2L = out;

    BSL_Param mulIn[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ct2, ct2L, 0},
        BSL_PARAM_END
    };
    out = ctBig;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMul(ctx, mulIn, ctMul, &out), HIFHE_SUCCESS);
    uint32_t ctMulL = out;

    out = d.ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctMul, ctMulL, ptOut, &out), HIFHE_SUCCESS);
    ASSERT_EQ(BgvDecode(ctx, ptOut, out, mo, d.msgLen), 0);

    ASSERT_EQ(mo[0], (9u * 13u) % d.t);
    ASSERT_EQ(mo[1], 0u);
    ASSERT_EQ(mo[d.n - 1u], 0u);
EXIT:
    BSL_SAL_Free(m1); BSL_SAL_Free(m2); BSL_SAL_Free(mo);
    BSL_SAL_Free(pt1); BSL_SAL_Free(pt2); BSL_SAL_Free(ct1); BSL_SAL_Free(ct2);
    BSL_SAL_Free(ctMul); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SLOT_MAP_ENCDEC_TC001
* @title  The slot index map is off by default, switches the slot layout when
*         turned on, and still round-trips.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SLOT_MAP_ENCDEC_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL, *mo = NULL;
    uint8_t *ptMapped = NULL, *ptPlain = NULL, *ct = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    BgvDims d;
    ASSERT_EQ(BgvDimsGet(ctx, &d), 0);
    m        = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    mo       = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    ptMapped = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ptPlain    = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ct       = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ptOut    = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ASSERT_TRUE(m && mo && ptMapped && ptPlain && ct && ptOut);

    for (uint32_t i = 0; i < d.n; ++i) m[i] = (uint64_t)((i * 13u + 2u) % 91u);

    /* Off by default: slot i sits at plaintext-NTT position i, which is the
     * layout the predecessor encoder produced. */
    uint32_t flag = 0xffu;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_SLOT_MAP, &flag, sizeof(flag)), HIFHE_SUCCESS);
    ASSERT_EQ(flag, 0u);
    uint32_t ptPlainL = 0u;
    ASSERT_EQ(BgvEncode(ctx, m, d.msgLen, ptPlain, d.ptLen, &ptPlainL), 0);

    /* Turn it on: subsequent encodes scatter the slots through the map. */
    flag = 1u;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_SET_SLOT_MAP, &flag, sizeof(flag)), HIFHE_SUCCESS);
    flag = 0xffu;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_SLOT_MAP, &flag, sizeof(flag)), HIFHE_SUCCESS);
    ASSERT_EQ(flag, 1u);

    uint32_t ptMappedL = 0u;
    ASSERT_EQ(BgvEncode(ctx, m, d.msgLen, ptMapped, d.ptLen, &ptMappedL), 0);

    /* Back off for the round trip below. */
    flag = 0u;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_SET_SLOT_MAP, &flag, sizeof(flag)), HIFHE_SUCCESS);
    /* Same length, different bytes: the map actually moved the slots. */
    ASSERT_EQ(ptPlainL, ptMappedL);
    ASSERT_TRUE(memcmp(ptPlain, ptMapped, ptPlainL) != 0);
    /* The encoder choice must NOT show up in the wire's dtype word: that
     * word carries a bare PolyForm, and the predecessor provider casts it
     * straight to its enum. Plaintext body starts at 12, the word sits
     * after scale(8) + N(4) + rns(4), and HIFHE_NTT is 1. */
    for (uint32_t b = 0; b < 4u; ++b) {
        uint8_t expect = (b == 0u) ? 0x01u : 0x00u;
        ASSERT_EQ(ptPlain[12 + 8 + 4 + 4 + b], expect);
        ASSERT_EQ(ptMapped[12 + 8 + 4 + 4 + b], expect);
    }

    uint32_t out = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, ptPlain, ptPlainL, ct, &out), HIFHE_SUCCESS);
    uint32_t ctL = out;
    out = d.ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ct, ctL, ptOut, &out), HIFHE_SUCCESS);
    ASSERT_EQ(BgvDecode(ctx, ptOut, out, mo, d.msgLen), 0);
    for (uint32_t i = 0; i < d.n; ++i) {
        ASSERT_EQ(mo[i], m[i]);
    }
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(mo);
    BSL_SAL_Free(ptMapped); BSL_SAL_Free(ptPlain); BSL_SAL_Free(ct); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_LUT_SLOTWISE_MUL_TC001
* @title  With the LUT encoder on, ct*pt multiplies slot-by-slot instead of
*         convolving coefficients - the point of the batching transform.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_LUT_SLOTWISE_MUL_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m1 = NULL, *m2 = NULL, *mo = NULL;
    uint8_t *pt1 = NULL, *pt2 = NULL, *ct1 = NULL, *ctMul = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);


    BgvDims d;
    ASSERT_EQ(BgvDimsGet(ctx, &d), 0);
    m1 = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    m2 = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    mo = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    pt1 = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    pt2 = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ct1 = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ctMul = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ASSERT_TRUE(m1 && m2 && mo && pt1 && pt2 && ct1 && ctMul && ptOut);

    for (uint32_t i = 0; i < d.n; ++i) {
        m1[i] = (uint64_t)(i % 23u) + 1u;
        m2[i] = (uint64_t)(i % 17u) + 2u;
    }

    uint32_t pt1L = 0u, pt2L = 0u;
    ASSERT_EQ(BgvEncode(ctx, m1, d.msgLen, pt1, d.ptLen, &pt1L), 0);
    ASSERT_EQ(BgvEncode(ctx, m2, d.msgLen, pt2, d.ptLen, &pt2L), 0);
    uint32_t out = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt1, pt1L, ct1, &out), HIFHE_SUCCESS);
    uint32_t ct1L = out;

    BSL_Param mulIn[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
        {HIFHE_PARAM_BGV_PLAINTEXT,   BSL_PARAM_TYPE_OCTETS, pt2, pt2L, 0},
        BSL_PARAM_END
    };
    out = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMul(ctx, mulIn, ctMul, &out), HIFHE_SUCCESS);
    uint32_t ctMulL = out;

    out = d.ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctMul, ctMulL, ptOut, &out), HIFHE_SUCCESS);
    ASSERT_EQ(BgvDecode(ctx, ptOut, out, mo, d.msgLen), 0);

    for (uint32_t i = 0; i < d.n; ++i) {
        ASSERT_EQ(mo[i], (m1[i] * m2[i]) % d.t);
    }
EXIT:
    BSL_SAL_Free(m1); BSL_SAL_Free(m2); BSL_SAL_Free(mo);
    BSL_SAL_Free(pt1); BSL_SAL_Free(pt2); BSL_SAL_Free(ct1);
    BSL_SAL_Free(ctMul); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SCALE_RECONCILE_TC001
* @title  Adding ciphertexts whose scale factors differ goes through
*         MakeScaleFactorSame; the sum decodes to m1/k + m2 mod t.
* @brief  The wire format puts the plaintext scale factor at body offset 0,
*         i.e. byte 12, so the test can declare a scale of k on an otherwise
*         normal plaintext and check the reconciliation end to end.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SCALE_RECONCILE_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m1 = NULL, *m2 = NULL, *mo = NULL;
    uint8_t *pt1 = NULL, *pt2 = NULL, *ct1 = NULL, *ct2 = NULL, *ctSum = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    BgvDims d;
    ASSERT_EQ(BgvDimsGet(ctx, &d), 0);
    m1 = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    m2 = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    mo = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    pt1 = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    pt2 = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ct1 = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ct2 = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ctSum = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ASSERT_TRUE(m1 && m2 && mo && pt1 && pt2 && ct1 && ct2 && ctSum && ptOut);

    const uint64_t k = 3u;              /* declared scale of the first operand */
    for (uint32_t i = 0; i < d.n; ++i) { m1[i] = 6u; m2[i] = 5u; }

    uint32_t pt1L = 0u, pt2L = 0u;
    ASSERT_EQ(BgvEncode(ctx, m1, d.msgLen, pt1, d.ptLen, &pt1L), 0);
    ASSERT_EQ(BgvEncode(ctx, m2, d.msgLen, pt2, d.ptLen, &pt2L), 0);
    /* Overwrite the pt1 scale factor (little-endian u64 at body offset 0). */
    for (uint32_t b = 0; b < 8u; ++b) pt1[12u + b] = (uint8_t)((k >> (8u * b)) & 0xffu);

    uint32_t out = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt1, pt1L, ct1, &out), HIFHE_SUCCESS);
    uint32_t ct1L = out;
    out = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt2, pt2L, ct2, &out), HIFHE_SUCCESS);
    uint32_t ct2L = out;

    BSL_Param addIn[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ct2, ct2L, 0},
        BSL_PARAM_END
    };
    out = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEAdd(ctx, addIn, ctSum, &out), HIFHE_SUCCESS);
    uint32_t ctSumL = out;

    out = d.ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctSum, ctSumL, ptOut, &out), HIFHE_SUCCESS);
    ASSERT_EQ(BgvDecode(ctx, ptOut, out, mo, d.msgLen), 0);

    /* Operand 1 carries 6 at scale 3, i.e. the value 2; operand 2 carries 5
     * at scale 1. Their sum is 7 in every slot. */
    for (uint32_t i = 0; i < 64u; ++i) {
        ASSERT_EQ(mo[i], 7u);
    }
EXIT:
    BSL_SAL_Free(m1); BSL_SAL_Free(m2); BSL_SAL_Free(mo);
    BSL_SAL_Free(pt1); BSL_SAL_Free(pt2); BSL_SAL_Free(ct1); BSL_SAL_Free(ct2);
    BSL_SAL_Free(ctSum); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_PARAM_CHECK_TC001
* @title  Parameter admissibility checks reject a non-power-of-two ring, an
*         over-long RNS chain, and a modulus budget past the security limit.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_PARAM_CHECK_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    TestMemInit();
    TestRandInit();

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, HIFHE_PKEY_BGV,
                                       CRYPT_EAL_PKEY_CIPHER_OPERATE, HIFHE_PROVIDER_ATTR);
    ASSERT_TRUE(ctx != NULL);

    /* 1000 is not a supported ring degree. */
    uint32_t badDegree = 1000u;
    uint32_t plainBits = 17u;
    uint32_t bits1[1] = { 48u };
    BSL_Param p1[] = {
        {HIFHE_PARAM_BGV_POLY_DEGREE,     BSL_PARAM_TYPE_UINT32, &badDegree, sizeof(badDegree), 0},
        {HIFHE_PARAM_BGV_PLAIN_MOD_BIT,   BSL_PARAM_TYPE_UINT32, &plainBits, sizeof(plainBits), 0},
        {HIFHE_PARAM_BGV_CIPHER_MOD_BITS, BSL_PARAM_TYPE_OCTETS, bits1, sizeof(bits1), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeySetParaEx(ctx, p1), HIFHE_PARAM_INVALID);

    /* Chain longer than HIFHE_BGV_MAX_CHAIN_LEN (8). */
    uint32_t degree = 8192u;
    uint32_t bits9[9] = { 24u, 24u, 24u, 24u, 24u, 24u, 24u, 24u, 24u };
    BSL_Param p2[] = {
        {HIFHE_PARAM_BGV_POLY_DEGREE,     BSL_PARAM_TYPE_UINT32, &degree,    sizeof(degree),    0},
        {HIFHE_PARAM_BGV_PLAIN_MOD_BIT,   BSL_PARAM_TYPE_UINT32, &plainBits, sizeof(plainBits), 0},
        {HIFHE_PARAM_BGV_CIPHER_MOD_BITS, BSL_PARAM_TYPE_OCTETS, bits9,      sizeof(bits9),     0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeySetParaEx(ctx, p2), HIFHE_PARAM_INVALID);

    /* Accepted at SetPara, rejected at context build: 4 x 44 = 176 bits is
     * far past the 54-bit budget for N = 2048 at 128-bit security. */
    uint32_t small = 2048u;
    uint32_t bits4[4] = { 44u, 44u, 44u, 44u };
    BSL_Param p3[] = {
        {HIFHE_PARAM_BGV_POLY_DEGREE,     BSL_PARAM_TYPE_UINT32, &small,     sizeof(small),     0},
        {HIFHE_PARAM_BGV_PLAIN_MOD_BIT,   BSL_PARAM_TYPE_UINT32, &plainBits, sizeof(plainBits), 0},
        {HIFHE_PARAM_BGV_CIPHER_MOD_BITS, BSL_PARAM_TYPE_OCTETS, bits4,      sizeof(bits4),     0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeySetParaEx(ctx, p3), HIFHE_SUCCESS);
    uint32_t degOut = 0u;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &degOut, sizeof(degOut)),
              HIFHE_SUCCESS);
    ASSERT_EQ(degOut, 2048u);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_PARAM_INVALID);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SK_POW3_TC001
* @title  A ciphertext that reaches size 4 decrypts through s^3.
* @brief  With no relinearization key in play, ct*ct leaves a size-3
*         ciphertext and multiplying that by a third ciphertext leaves a
*         size 4 one, whose decryption evaluates c0 + c1*s + c2*s^2 + c3*s^3.
*         Runs on the 2-limb 4096 preset because a triple product's noise
*         does not fit under a single 48-bit modulus. Messages are constant
*         polynomials so the ring product is a plain scalar product.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SK_POW3_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m1 = NULL, *m2 = NULL, *m3 = NULL, *mo = NULL;
    uint8_t *pt1 = NULL, *pt2 = NULL, *pt3 = NULL;
    uint8_t *ct1 = NULL, *ct2 = NULL, *ct3 = NULL;
    uint8_t *ctSq = NULL, *ctCube = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_4096_44x2_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);
    /* Deliberately no HIFHE_CTRL_BGV_GEN_RELIN_KEY: the products must stay wide. */

    BgvDims d;
    ASSERT_EQ(BgvDimsGet(ctx, &d), 0);
    uint32_t ctWide = d.ctLen * 4u;
    m1 = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    m2 = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    m3 = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    mo = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    pt1 = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    pt2 = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    pt3 = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ct1 = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ct2 = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ct3 = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ctSq   = (uint8_t *)BSL_SAL_Malloc(ctWide);
    ctCube = (uint8_t *)BSL_SAL_Malloc(ctWide);
    ptOut  = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ASSERT_TRUE(m1 && m2 && m3 && mo && pt1 && pt2 && pt3);
    ASSERT_TRUE(ct1 && ct2 && ct3 && ctSq && ctCube && ptOut);

    for (uint32_t i = 0; i < d.n; ++i) {
        m1[i] = (i == 0u) ? 3u : 0u;
        m2[i] = (i == 0u) ? 5u : 0u;
        m3[i] = (i == 0u) ? 7u : 0u;
    }

    uint32_t pt1L = 0u, pt2L = 0u, pt3L = 0u;
    ASSERT_EQ(BgvEncode(ctx, m1, d.msgLen, pt1, d.ptLen, &pt1L), 0);
    ASSERT_EQ(BgvEncode(ctx, m2, d.msgLen, pt2, d.ptLen, &pt2L), 0);
    ASSERT_EQ(BgvEncode(ctx, m3, d.msgLen, pt3, d.ptLen, &pt3L), 0);

    uint32_t out = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt1, pt1L, ct1, &out), HIFHE_SUCCESS);
    uint32_t ct1L = out;
    out = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt2, pt2L, ct2, &out), HIFHE_SUCCESS);
    uint32_t ct2L = out;
    out = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt3, pt3L, ct3, &out), HIFHE_SUCCESS);
    uint32_t ct3L = out;

    /* ct1 * ct2 -> size 3 (one extra component over a fresh ciphertext). */
    BSL_Param mul12[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ct2, ct2L, 0},
        BSL_PARAM_END
    };
    out = ctWide;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMul(ctx, mul12, ctSq, &out), HIFHE_SUCCESS);
    uint32_t ctSqL = out;
    /* Body grows by exactly one component's worth of payload. */
    ASSERT_EQ(ctSqL, ct1L + d.level * d.n * 8u);

    /* (ct1*ct2) * ct3 -> size 4, the case that needs s^3. */
    BSL_Param mul3[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ctSq, ctSqL, 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ct3,  ct3L,  0},
        BSL_PARAM_END
    };
    out = ctWide;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMul(ctx, mul3, ctCube, &out), HIFHE_SUCCESS);
    uint32_t ctCubeL = out;
    ASSERT_EQ(ctCubeL, ct1L + 2u * d.level * d.n * 8u);

    out = d.ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctCube, ctCubeL, ptOut, &out), HIFHE_SUCCESS);
    ASSERT_EQ(BgvDecode(ctx, ptOut, out, mo, d.msgLen), 0);

    ASSERT_EQ(mo[0], (3u * 5u * 7u) % d.t);
    ASSERT_EQ(mo[1], 0u);
    ASSERT_EQ(mo[d.n - 1u], 0u);
EXIT:
    BSL_SAL_Free(m1); BSL_SAL_Free(m2); BSL_SAL_Free(m3); BSL_SAL_Free(mo);
    BSL_SAL_Free(pt1); BSL_SAL_Free(pt2); BSL_SAL_Free(pt3);
    BSL_SAL_Free(ct1); BSL_SAL_Free(ct2); BSL_SAL_Free(ct3);
    BSL_SAL_Free(ctSq); BSL_SAL_Free(ctCube); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_DUPCTX_DEEP_TC001
* @title  DupCtx produces a fully independent context, keys included.
* @brief  Duplicates a context that already holds a keypair, a relin key and
*         a galois key, then frees the source and keeps working with the
*         duplicate alone: encrypt, ct*ct with relinearization, rotate, and
*         decrypt all have to succeed against memory the source used to own.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_DUPCTX_DEEP_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *src = NULL, *dup = NULL;
    uint8_t *pkSrc = NULL, *pkDup = NULL;
    uint64_t *m1 = NULL, *m2 = NULL, *mo = NULL;
    uint8_t *pt1 = NULL, *pt2 = NULL, *ct1 = NULL, *ct2 = NULL;
    uint8_t *ctMul = NULL, *ctRot = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();

    src = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(src != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(src), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(src, HIFHE_CTRL_BGV_GEN_RELIN_KEY, NULL, 0), HIFHE_SUCCESS);
    int32_t steps[1] = { 1 };
    BSL_Param genGk[] = {
        {HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_OCTETS, steps, sizeof(steps), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(src, HIFHE_CTRL_BGV_GEN_GALOIS_KEYS, genGk, 0), HIFHE_SUCCESS);

    dup = CRYPT_EAL_PkeyDupCtx(src);
    ASSERT_TRUE(dup != NULL);

    /* The duplicate carries the same public key, not a freshly drawn one. */
    BgvDims d;
    ASSERT_EQ(BgvDimsGet(dup, &d), 0);
    uint32_t pkLen = 0u;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(src, HIFHE_CTRL_BGV_GET_PUBKEY_LEN, &pkLen, sizeof(pkLen)),
              HIFHE_SUCCESS);
    pkSrc = (uint8_t *)BSL_SAL_Malloc(pkLen);
    pkDup = (uint8_t *)BSL_SAL_Malloc(pkLen);
    ASSERT_TRUE(pkSrc && pkDup);
    BSL_Param getSrc[] = {{HIFHE_PARAM_BGV_PUBKEY, BSL_PARAM_TYPE_OCTETS, pkSrc, pkLen, 0},
                          BSL_PARAM_END};
    BSL_Param getDup[] = {{HIFHE_PARAM_BGV_PUBKEY, BSL_PARAM_TYPE_OCTETS, pkDup, pkLen, 0},
                          BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(src, getSrc), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(dup, getDup), HIFHE_SUCCESS);
    ASSERT_EQ(getSrc[0].useLen, getDup[0].useLen);
    ASSERT_EQ(memcmp(pkSrc, pkDup, getSrc[0].useLen), 0);

    /* Drop the source. Everything below runs on the duplicate's own memory. */
    CRYPT_EAL_PkeyFreeCtx(src);
    src = NULL;

    uint32_t ctBig = d.ctLen * 3u;
    m1 = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    m2 = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    mo = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    pt1 = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    pt2 = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ct1 = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ct2 = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ctMul = (uint8_t *)BSL_SAL_Malloc(ctBig);
    ctRot = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ASSERT_TRUE(m1 && m2 && mo && pt1 && pt2 && ct1 && ct2 && ctMul && ctRot && ptOut);

    /* Every slot carries the same value, which makes the rotation check
     * below independent of which permutation the Galois element induces --
     * this case is about the keys surviving the copy, not about rotation
     * semantics. A broken key would still show up: the result would be
     * noise, not a uniform vector. */
    for (uint32_t i = 0; i < d.n; ++i) { m1[i] = 6u; m2[i] = 4u; }

    uint32_t pt1L = 0u, pt2L = 0u;
    ASSERT_EQ(BgvEncode(dup, m1, d.msgLen, pt1, d.ptLen, &pt1L), 0);
    ASSERT_EQ(BgvEncode(dup, m2, d.msgLen, pt2, d.ptLen, &pt2L), 0);
    uint32_t out = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(dup, pt1, pt1L, ct1, &out), HIFHE_SUCCESS);
    uint32_t ct1L = out;
    out = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(dup, pt2, pt2L, ct2, &out), HIFHE_SUCCESS);
    uint32_t ct2L = out;

    /* Relin key survived the copy: the product collapses back to size 2. */
    BSL_Param mulIn[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ct2, ct2L, 0},
        BSL_PARAM_END
    };
    out = ctBig;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMul(dup, mulIn, ctMul, &out), HIFHE_SUCCESS);
    uint32_t ctMulL = out;
    ASSERT_EQ(ctMulL, ct1L);

    out = d.ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(dup, ctMul, ctMulL, ptOut, &out), HIFHE_SUCCESS);
    ASSERT_EQ(BgvDecode(dup, ptOut, out, mo, d.msgLen), 0);
    ASSERT_EQ(mo[0], (6u * 4u) % d.t);

    /* Galois key survived too. */
    BSL_Param rotIn[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1,  BSL_PARAM_TYPE_OCTETS, ct1,   ct1L,          0},
        {HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_OCTETS, steps, sizeof(steps), 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2,  BSL_PARAM_TYPE_OCTETS, ctRot, d.ctLen,       0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(dup, HIFHE_CTRL_BGV_HE_ROTATE_STEP, rotIn, 0), HIFHE_SUCCESS);
    out = d.ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(dup, ctRot, rotIn[2].useLen, ptOut, &out), HIFHE_SUCCESS);
    ASSERT_EQ(BgvDecode(dup, ptOut, out, mo, d.msgLen), 0);
    /* A uniform vector is fixed by any slot permutation, so every slot must
     * still read 6 -- and must do so all the way across, not just at 0. */
    for (uint32_t i = 0; i < d.n; ++i) {
        ASSERT_EQ(mo[i], 6u);
    }
EXIT:
    BSL_SAL_Free(pkSrc); BSL_SAL_Free(pkDup);
    BSL_SAL_Free(m1); BSL_SAL_Free(m2); BSL_SAL_Free(mo);
    BSL_SAL_Free(pt1); BSL_SAL_Free(pt2); BSL_SAL_Free(ct1); BSL_SAL_Free(ct2);
    BSL_SAL_Free(ctMul); BSL_SAL_Free(ctRot); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(dup);
    CRYPT_EAL_PkeyFreeCtx(src);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_WIRE_DOMAIN_TC001
* @title  The wire carries Montgomery-scaled words and a bare dtype, which
*         is what makes a buffer interchangeable with the predecessor.
* @brief  Encodes the all-ones slot vector under the LUT encoder. In the slot
*         domain that is the transform of the constant polynomial, so the
*         coefficient vector is delta_0 and the q-domain NTT of delta_0 is all
*         ones -- meaning every payload word must come out as exactly the
*         scaling factor the format applies. The predecessor's transform fuses
*         R = 2^64 mod q into its output, so that factor is R, and a constant
*         payload pins it without any permutation ambiguity.
*
*         Also checks the header the other implementation insists on: its
*         magic, version 1, and a dtype word holding nothing but the PolyForm
*         (its reader casts that word straight to its enum, so the capability
*         bits this library tracks in memory must not appear there).
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_WIRE_DOMAIN_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL, *mo = NULL;
    uint8_t *pt = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    BgvDims d;
    ASSERT_EQ(BgvDimsGet(ctx, &d), 0);
    m  = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    mo = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    pt = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ASSERT_TRUE(m && mo && pt);
    for (uint32_t i = 0; i < d.n; ++i) m[i] = 1u;

    uint32_t ptL = 0u;
    ASSERT_EQ(BgvEncode(ctx, m, d.msgLen, pt, d.ptLen, &ptL), 0);

    /* ---- header ---- */
    ASSERT_EQ(pt[0], 'H'); ASSERT_EQ(pt[1], 'L'); ASSERT_EQ(pt[2], 'G'); ASSERT_EQ(pt[3], 0x00u);
    ASSERT_EQ(pt[8],  0x01u);   /* version 1, little endian */
    ASSERT_EQ(pt[9],  0x00u);
    ASSERT_EQ(pt[10], 0x03u);   /* type PLAINTEXT */
    ASSERT_EQ(pt[11], 0x00u);

    /* ---- body descriptor: scale(8) | N(4) | rns(4) | dtype(4) ---- */
    const uint8_t *b = pt + 12;
    uint64_t scale = 0u; memcpy(&scale, b, 8);
    uint32_t nWire = 0u, rns = 0u, dword = 0u;
    memcpy(&nWire, b + 8,  4);
    memcpy(&rns,   b + 12, 4);
    memcpy(&dword, b + 16, 4);
    ASSERT_EQ(scale, 1u);
    ASSERT_EQ(nWire, d.n);
    ASSERT_EQ(rns, d.level);
    ASSERT_EQ(dword, 1u);       /* bare HIFHE_NTT, no capability bits */

    /* ---- payload: every word is the scaling factor ---- */
    uint64_t q0 = 0u;
    memcpy(&q0, b + 20, 8);
    ASSERT_EQ(q0, 281474976694273ull);
    /* R = 2^64 mod q0 for this modulus. */
    const uint64_t kR = 1073676288ull;
    const uint8_t *data = b + 20 + 8u * rns;
    for (uint32_t i = 0; i < d.n; ++i) {
        uint64_t w = 0u;
        memcpy(&w, data + 8u * i, 8);
        ASSERT_EQ(w, kR);
    }

    /* ---- and it still round-trips through our own reader ---- */
    ASSERT_EQ(BgvDecode(ctx, pt, ptL, mo, d.msgLen), 0);
    for (uint32_t i = 0; i < d.n; ++i) {
        ASSERT_EQ(mo[i], 1u);
    }
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(mo); BSL_SAL_Free(pt);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SECRET_WEIGHT_TC001
* @title  The seeded secret key is a fixed-weight ternary vector, which is
*         what lets the predecessor derive the same key from the same seed.
* @brief  Recovers the secret from its own wire: the private key is a
*         plaintext-shaped payload in the NTT domain, so an inverse transform
*         under q gets the coefficients back. They must be exactly
*         polyDegree/4 at +1, the same number at -1, and the rest zero -- not
*         merely small. A refactor that swapped the distribution for an
*         independent per-coefficient draw would still decrypt fine and would
*         still be reproducible from a seed; it would just silently stop
*         agreeing with the other implementation, which is why the shape is
*         pinned here rather than left to the cross-implementation demo.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SECRET_WEIGHT_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t *prv = NULL;
    uint64_t *coeff = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);

    uint8_t seed[HIFHE_BGV_SEED_LEN];
    for (uint32_t i = 0; i < HIFHE_BGV_SEED_LEN; ++i) seed[i] = (uint8_t)(0x31u + i);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_SET_SEED, seed, HIFHE_BGV_SEED_LEN),
              HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    uint32_t prvLen = 0u;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PRVKEY_LEN, &prvLen, sizeof(prvLen)),
              HIFHE_SUCCESS);
    prv = (uint8_t *)BSL_SAL_Malloc(prvLen);
    ASSERT_TRUE(prv != NULL);
    BSL_Param g[] = {{HIFHE_PARAM_BGV_PRVKEY, BSL_PARAM_TYPE_OCTETS, prv, prvLen, 0},
                     BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(ctx, g), HIFHE_SUCCESS);

    /* Body: scale(8) | N(4) | rns(4) | dtype(4) | rnsBase(8*rns) | data. */
    const uint8_t *b = prv + 12;
    uint32_t n = 0u, rns = 0u, dtype = 0u;
    uint64_t q = 0u;
    memcpy(&n,     b + 8,  4);
    memcpy(&rns,   b + 12, 4);
    memcpy(&dtype, b + 16, 4);
    memcpy(&q,     b + 20, 8);
    ASSERT_EQ(n, 2048u);
    ASSERT_EQ(rns, 1u);
    ASSERT_EQ(dtype, 1u);            /* NTT form */

    /* Undo the wire's Montgomery scaling, then inverse-transform limb 0. */
    coeff = (uint64_t *)BSL_SAL_Malloc(n * sizeof(uint64_t));
    ASSERT_TRUE(coeff != NULL);
    const uint8_t *data = b + 20 + 8u * rns;
    uint64_t rInv = Kernel_ModInv((uint64_t)((((ModulusWide)1u) << 64) % (ModulusWide)q), q);
    ASSERT_TRUE(rInv != 0u);
    for (uint32_t i = 0; i < n; ++i) {
        uint64_t w = 0u;
        memcpy(&w, data + 8u * i, 8);
        coeff[i] = Kernel_MulMod(w % q, rInv, q);
    }

    /* One call fills the table struct from one buffer. */
    NttTables tbl;
    uint64_t *tblBuf = (uint64_t *)BSL_SAL_Malloc(
        (uint32_t)(HIFHE_NTT_TABLE_WORDS(n) * sizeof(uint64_t)));
    ASSERT_TRUE(tblBuf != NULL);
    memset(&tbl, 0, sizeof(tbl));
    ASSERT_EQ(Kernel_Ntt_BuildTables(&tbl, tblBuf, q, n), HIFHE_SUCCESS);
    ASSERT_EQ(Kernel_Ntt_Inverse(coeff, &tbl), HIFHE_SUCCESS);

    uint32_t plus = 0u, minus = 0u, zero = 0u, other = 0u;
    for (uint32_t i = 0; i < n; ++i) {
        if (coeff[i] == 1u)          plus++;
        else if (coeff[i] == q - 1u) minus++;   /* -1 mod q */
        else if (coeff[i] == 0u)     zero++;
        else                         other++;
    }
    BSL_SAL_Free(tblBuf);

    ASSERT_EQ(other, 0u);
    ASSERT_EQ(plus,  n / 4u);
    ASSERT_EQ(minus, n / 4u);
    ASSERT_EQ(zero,  n / 2u);
EXIT:
    BSL_SAL_Free(prv); BSL_SAL_Free(coeff);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_DROPIN_CALLING_CONVENTION_TC001
* @title  A caller written against the predecessor provider works unchanged.
* @brief  Drives the whole pipeline the way that caller does, which differs
*         from this library's own conventions in three places, all of which
*         have to be accepted for a .so swap to be transparent:
*
*           - no encoder selection. The predecessor always slot-packs with no
*             index map, so that has to be what a caller gets without asking:
*             slot packing unconditionally, and the slot map off. Either
*             difference would silently decode to the wrong values.
*           - HEMsgDecode takes the plaintext to decode under the MSG key,
*             not PLAINTEXT.
*           - HEAdd takes its ciphertext operands under the generic
*             CRYPT_PARAM_PKEY_HE_CIPHERTEXT* keys.
*
*         Verified against the real thing separately -- the predecessor's own
*         demo binary, unrecompiled, runs on this library with only the .so
*         swapped -- but that needs both trees, so the conventions are pinned
*         here where the suite can see them.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_DROPIN_CALLING_CONVENTION_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL, *mo = NULL;
    uint8_t *pt = NULL, *ct = NULL, *ctNeg = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    /* Deliberately no encoder ctrl: the defaults must already be the
     * predecessor's layout. */
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    uint32_t sm = 0xffu;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_SLOT_MAP, &sm, sizeof(sm)), HIFHE_SUCCESS);
    ASSERT_EQ(sm, 0u);

    BgvDims d;
    ASSERT_EQ(BgvDimsGet(ctx, &d), 0);
    m     = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    mo    = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    pt    = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ct    = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ctNeg = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ASSERT_TRUE(m && mo && pt && ct && ctNeg && ptOut);
    for (uint32_t i = 0; i < d.n; ++i) m[i] = (i % 7u) + 1u;

    /* encode: MSG in, plaintext out -- the shared convention. */
    BSL_Param encIn[] = {
        {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m, d.msgLen, 0},
        BSL_PARAM_END
    };
    uint32_t out = d.ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encIn, pt, &out), HIFHE_SUCCESS);
    uint32_t ptL = out;

    out = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct, &out), HIFHE_SUCCESS);
    uint32_t ctL = out;

    /* negate, with the operand under the generic key rather than ours. */
    uint8_t marker = 1u;
    BSL_Param negIn[] = {
        {CRYPT_PARAM_PKEY_HE_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct, ctL, 0},
        {HIFHE_PARAM_BGV_NEGATE,           BSL_PARAM_TYPE_OCTETS, &marker, 1, 0},
        BSL_PARAM_END
    };
    out = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEAdd(ctx, negIn, ctNeg, &out), HIFHE_SUCCESS);
    uint32_t negL = out;

    out = d.ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctNeg, negL, ptOut, &out), HIFHE_SUCCESS);
    uint32_t ptOutL = out;

    /* decode: plaintext handed in under MSG, the predecessor's convention. */
    BSL_Param decIn[] = {
        {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, ptOut, ptOutL, 0},
        BSL_PARAM_END
    };
    out = d.msgLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(ctx, decIn, (uint8_t *)mo, &out), HIFHE_SUCCESS);

    for (uint32_t i = 0; i < d.n; ++i) {
        uint64_t want = (d.t - (m[i] % d.t)) % d.t;
        ASSERT_EQ(mo[i], want);
    }
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(mo); BSL_SAL_Free(pt);
    BSL_SAL_Free(ct); BSL_SAL_Free(ctNeg); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_HE_RERANDOMIZE_TC001
* @title  Rerandomize preserves the message and changes the ciphertext.
* @brief  Noise goes on every component as t*e_k, so decode is unaffected.
*         The op takes no public key, so a secret-key-only ctx can run it.
*         Two calls on the same input must differ, which is what catches a
*         seeded stream being replayed instead of drawing fresh.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_HE_RERANDOMIZE_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL, *mo = NULL;
    uint8_t *pt = NULL, *ct = NULL, *ctR1 = NULL, *ctR2 = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    uint32_t ptLen = 0u, ctLen = 0u, msgLen = 0u;
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &ptLen, sizeof(ptLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN, &msgLen, sizeof(msgLen));
    m     = (uint64_t *)BSL_SAL_Malloc(msgLen);
    mo    = (uint64_t *)BSL_SAL_Malloc(msgLen);
    pt    = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ct    = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ctR1  = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ctR2  = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ASSERT_TRUE(m && mo && pt && ct && ctR1 && ctR2 && ptOut);

    for (uint32_t i = 0; i < HIFHE_N; ++i) m[i] = (uint64_t)(i % 97u);
    BSL_Param encIn[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m, msgLen, 0}, BSL_PARAM_END };
    uint32_t out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encIn, pt, &out), HIFHE_SUCCESS);
    uint32_t ptL = out;
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct, &out), HIFHE_SUCCESS);
    uint32_t ctL = out;

    BSL_Param rr1[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct,   ctL,   0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ctR1, ctLen, 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_HE_RERANDOMIZE, rr1, 0u), HIFHE_SUCCESS);
    uint32_t r1Len = rr1[1].useLen;

    BSL_Param rr2[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct,   ctL,   0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ctR2, ctLen, 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_HE_RERANDOMIZE, rr2, 0u), HIFHE_SUCCESS);

    ASSERT_EQ(r1Len, ctL);
    ASSERT_TRUE(memcmp(ctR1, ct, ctL) != 0);
    ASSERT_TRUE(memcmp(ctR1, ctR2, ctL) != 0);

    out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctR1, r1Len, ptOut, &out), HIFHE_SUCCESS);
    uint32_t ptOutL = out;

    BSL_Param decIn[] = { {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, ptOut, ptOutL, 0}, BSL_PARAM_END };
    out = msgLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(ctx, decIn, (uint8_t *)mo, &out), HIFHE_SUCCESS);
    ASSERT_EQ(memcmp(mo, m, msgLen), 0);
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(mo); BSL_SAL_Free(pt);
    BSL_SAL_Free(ct); BSL_SAL_Free(ctR1); BSL_SAL_Free(ctR2); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_DEFAULT_CHAIN_TC001
* @title  The default preset resolves to its named modulus, on the wire.
* @brief  The default preset pins its chain instead of taking whatever the
*         Proth walk reaches first, so the ring is fixed by the header. The
*         value is read back out of a serialized ciphertext rather than
*         through a ctrl, which also pins the body layout: rnsBase sits at
*         12 + 4 + 8 + 32 + 4 + 4 + 4.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_DEFAULT_CHAIN_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL;
    uint8_t *pt = NULL, *ct = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_DEFAULT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    uint32_t ptLen = 0u, ctLen = 0u, msgLen = 0u, level = 0u;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_LEVEL, &level, sizeof(level)), HIFHE_SUCCESS);
    ASSERT_EQ(level, 1u);
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &ptLen, sizeof(ptLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN, &msgLen, sizeof(msgLen));
    m  = (uint64_t *)BSL_SAL_Malloc(msgLen);
    pt = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ct = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ASSERT_TRUE(m && pt && ct);
    for (uint32_t i = 0; i < HIFHE_N; ++i) m[i] = 1u;

    BSL_Param enc[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m, msgLen, 0}, BSL_PARAM_END };
    uint32_t out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, enc, pt, &out), HIFHE_SUCCESS);
    uint32_t ptL = out;
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct, &out), HIFHE_SUCCESS);
    ASSERT_TRUE(out > 76u);

    uint32_t rnsSize = 0u;
    uint64_t q0 = 0u;
    memcpy(&rnsSize, ct + 60, sizeof(rnsSize));
    memcpy(&q0, ct + 68, sizeof(q0));
    ASSERT_EQ(rnsSize, 1u);
    ASSERT_EQ(q0, 140786965118977ull);
    ASSERT_EQ((q0 - 1u) % (2u * HIFHE_N), 0u);
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(pt); BSL_SAL_Free(ct);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEED_SCOPE_TC001
* @title  A context seed fixes the keys and nothing else.
* @brief  The seed exists so two parties derive the same key material. It must
*         not reach encryption: if it did, one message would encrypt to one
*         ciphertext forever, and u, e0, e1 would all be the same polynomial
*         because they run the same sampler. Encrypts the same message twice
*         under one seeded context and requires the buffers to differ while
*         both still decrypt.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEED_SCOPE_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL, *mo = NULL;
    uint8_t *pt = NULL, *ct1 = NULL, *ct2 = NULL, *ptOut = NULL;
    uint8_t seed[HIFHE_BGV_SEED_LEN];

    TestMemInit();
    TestRandInit();
    for (uint32_t i = 0; i < HIFHE_BGV_SEED_LEN; ++i) seed[i] = (uint8_t)(0x31u + i);

    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_SET_SEED, seed, HIFHE_BGV_SEED_LEN), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    uint32_t ptLen = 0u, ctLen = 0u, msgLen = 0u;
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &ptLen, sizeof(ptLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN, &msgLen, sizeof(msgLen));
    m     = (uint64_t *)BSL_SAL_Malloc(msgLen);
    mo    = (uint64_t *)BSL_SAL_Malloc(msgLen);
    pt    = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ct1   = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ct2   = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ASSERT_TRUE(m && mo && pt && ct1 && ct2 && ptOut);
    for (uint32_t i = 0; i < HIFHE_N; ++i) m[i] = (uint64_t)(i % 23u);

    BSL_Param enc[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m, msgLen, 0}, BSL_PARAM_END };
    uint32_t out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, enc, pt, &out), HIFHE_SUCCESS);
    uint32_t ptL = out;

    uint32_t l1 = ctLen, l2 = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct1, &l1), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct2, &l2), HIFHE_SUCCESS);
    ASSERT_EQ(l1, l2);
    ASSERT_TRUE(memcmp(ct1, ct2, l1) != 0);

    out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ct2, l2, ptOut, &out), HIFHE_SUCCESS);
    BSL_Param decIn[] = { {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, ptOut, out, 0}, BSL_PARAM_END };
    uint32_t mlen = msgLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(ctx, decIn, (uint8_t *)mo, &mlen), HIFHE_SUCCESS);
    ASSERT_EQ(memcmp(mo, m, msgLen), 0);
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(mo); BSL_SAL_Free(pt);
    BSL_SAL_Free(ct1); BSL_SAL_Free(ct2); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_KEY_DOMAIN_SEP_TC001
* @title  Every seeded key draw lands on its own stream.
* @brief  Key material is seeded, so the labels are what keep the draws apart.
*         Without them every relin piece takes the same a and the same e, and
*         the public key takes them too, which collapses the gadget: two
*         pieces would differ only by their known shift factor. Requires all
*         relin pieces to be pairwise distinct and distinct from the pk.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_KEY_DOMAIN_SEP_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_BGV_Ctx *inner = NULL;
    uint8_t seed[HIFHE_BGV_SEED_LEN];

    TestMemInit();
    TestRandInit();
    for (uint32_t i = 0; i < HIFHE_BGV_SEED_LEN; ++i) seed[i] = (uint8_t)(0x77u + i);

    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_SET_SEED, seed, HIFHE_BGV_SEED_LEN), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GEN_RELIN_KEY, NULL, 0u), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_INNER_CTX, &inner, sizeof(inner)), HIFHE_SUCCESS);
    ASSERT_TRUE(inner != NULL);

    const RelinKeys *rk = &inner->bgv.relinKeys;
    ASSERT_TRUE(rk->dnum >= 2u);
    uint32_t sz = rk->pieces[0].dataSize;
    ASSERT_TRUE(sz > 0u && (sz % 2u) == 0u);

    /* Compare c1, which is `a` verbatim. c0 carries the gadget shift, so it
     * differs between pieces even when the randomness is shared, and a
     * whole-buffer compare would pass while the streams collide. */
    uint32_t half = sz / 2u;
    for (uint32_t i = 0; i < rk->dnum; ++i) {
        ASSERT_EQ(rk->pieces[i].dataSize, sz);
        for (uint32_t j = i + 1u; j < rk->dnum; ++j) {
            ASSERT_TRUE(memcmp(rk->pieces[i].data + half, rk->pieces[j].data + half,
                               half * sizeof(uint64_t)) != 0);
        }
    }
    ASSERT_TRUE(inner->bgv.havePk);
    ASSERT_EQ(inner->bgv.pk.dataSize, sz);
    ASSERT_TRUE(memcmp(inner->bgv.pk.data + half, rk->pieces[0].data + half,
                       half * sizeof(uint64_t)) != 0);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* Bit-reverse over `bits` bits, matching the NTT's output ordering. */
static uint32_t RotBitRev(uint32_t x, uint32_t bits)
{
    uint32_t r = 0u;
    for (uint32_t i = 0; i < bits; ++i) {
        if ((x >> i) & 1u) r |= 1u << (bits - 1u - i);
    }
    return r;
}

/* Slot j evaluates at zeta^(2*brv(j)+1). sigma_k multiplies that exponent,
 * so out[j] takes the value that was in the slot at exponent k*(2*brv(j)+1). */
static uint32_t RotSrcSlot(uint32_t j, uint64_t k, uint32_t n, uint32_t logn)
{
    uint64_t twoN = 2ull * (uint64_t)n;
    uint64_t m = (k * (2ull * (uint64_t)RotBitRev(j, logn) + 1ull)) % twoN;
    return RotBitRev((uint32_t)((m - 1ull) / 2ull), logn);
}

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_ROTATE_SLOT_PERM_TC001
* @title  Slot-mode rotation is sigma_k, not a cyclic shift of the slots.
* @brief  The existing rotate test runs with the LUT off, so it only covers
*         coefficient semantics and says nothing about slots. This drives an
*         increasing vector and one-hot vectors through +1 and -1 with the LUT
*         on, and checks every output slot against the permutation sigma_k
*         induces. It also pins the landmark a caller would trip over: at
*         N=2048 slot 0 lands in slot 1365 after +1, not slot 1. Adding a
*         slot-index map to Encode/Decode would change these numbers, which is
*         the point of asserting them.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_ROTATE_SLOT_PERM_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL, *mo = NULL;
    uint8_t *pt = NULL, *ct = NULL, *ctR = NULL, *ptOut = NULL;
    const uint32_t LOGN = 11u;   /* HIFHE_N == 2048 */

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HIFHE_N, 1u << LOGN);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);
    int32_t steps[2] = { 1, -1 };
    BSL_Param gk[] = { {HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_OCTETS, steps, sizeof(steps), 0},
                       BSL_PARAM_END };
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GEN_GALOIS_KEYS, gk, 0u), HIFHE_SUCCESS);

    uint32_t ptLen = 0u, ctLen = 0u, msgLen = 0u;
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &ptLen, sizeof(ptLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN, &msgLen, sizeof(msgLen));
    m     = (uint64_t *)BSL_SAL_Malloc(msgLen);
    mo    = (uint64_t *)BSL_SAL_Malloc(msgLen);
    pt    = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ct    = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ctR   = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ASSERT_TRUE(m && mo && pt && ct && ctR && ptOut);

    /* k for step -1 is the inverse of 3 mod 2N; 2N is small, so search it. */
    uint64_t twoN = 2ull * HIFHE_N;
    uint64_t kInv = 0u;
    for (uint64_t v = 1u; v < twoN; v += 2u) {
        if ((3ull * v) % twoN == 1ull) { kInv = v; break; }
    }
    ASSERT_TRUE(kInv != 0u);

    for (uint32_t pass = 0; pass < 2u; ++pass) {
        int32_t st = steps[pass];
        uint64_t k = (pass == 0u) ? 3ull : kInv;

        /* increasing vector: checks the whole permutation at once */
        for (uint32_t i = 0; i < HIFHE_N; ++i) m[i] = (uint64_t)(i + 1u);
        BSL_Param enc[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m, msgLen, 0}, BSL_PARAM_END };
        uint32_t out = ptLen;
        ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, enc, pt, &out), HIFHE_SUCCESS);
        uint32_t ptL = out;
        out = ctLen;
        ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct, &out), HIFHE_SUCCESS);
        uint32_t ctL = out;

        BSL_Param rot[] = {
            {HIFHE_PARAM_BGV_CIPHERTEXT1,  BSL_PARAM_TYPE_OCTETS, ct,  ctL,        0},
            {HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_INT32,  &st, sizeof(st), 0},
            {HIFHE_PARAM_BGV_CIPHERTEXT2,  BSL_PARAM_TYPE_OCTETS, ctR, ctLen,      0},
            BSL_PARAM_END
        };
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_HE_ROTATE_STEP, rot, 0u), HIFHE_SUCCESS);
        out = ptLen;
        ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctR, rot[2].useLen, ptOut, &out), HIFHE_SUCCESS);
        BSL_Param dec[] = { {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, ptOut, out, 0},
                            BSL_PARAM_END };
        uint32_t ml = msgLen;
        ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(ctx, dec, (uint8_t *)mo, &ml), HIFHE_SUCCESS);

        for (uint32_t j = 0; j < HIFHE_N; ++j) {
            ASSERT_EQ(mo[j], m[RotSrcSlot(j, k, HIFHE_N, LOGN)]);
        }
        /* not a cyclic shift: a shift would put m[j-1] (or m[j+1]) at j */
        ASSERT_TRUE(mo[1] != m[0]);
    }

    /* one-hot landmarks for step +1 */
    static const uint32_t kSrc[4] = { 0u, 1u, 2u, 3u };
    static const uint32_t kDst[4] = { 1365u, 1364u, 1366u, 1367u };
    for (uint32_t c = 0; c < 4u; ++c) {
        for (uint32_t i = 0; i < HIFHE_N; ++i) m[i] = 0u;
        m[kSrc[c]] = 1234u;
        BSL_Param enc[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m, msgLen, 0}, BSL_PARAM_END };
        uint32_t out = ptLen;
        ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, enc, pt, &out), HIFHE_SUCCESS);
        uint32_t ptL = out;
        out = ctLen;
        ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct, &out), HIFHE_SUCCESS);
        uint32_t ctL = out;
        int32_t st = 1;
        BSL_Param rot[] = {
            {HIFHE_PARAM_BGV_CIPHERTEXT1,  BSL_PARAM_TYPE_OCTETS, ct,  ctL,        0},
            {HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_INT32,  &st, sizeof(st), 0},
            {HIFHE_PARAM_BGV_CIPHERTEXT2,  BSL_PARAM_TYPE_OCTETS, ctR, ctLen,      0},
            BSL_PARAM_END
        };
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_HE_ROTATE_STEP, rot, 0u), HIFHE_SUCCESS);
        out = ptLen;
        ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctR, rot[2].useLen, ptOut, &out), HIFHE_SUCCESS);
        BSL_Param dec[] = { {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, ptOut, out, 0},
                            BSL_PARAM_END };
        uint32_t ml = msgLen;
        ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(ctx, dec, (uint8_t *)mo, &ml), HIFHE_SUCCESS);

        uint32_t hits = 0u, where = 0u;
        for (uint32_t i = 0; i < HIFHE_N; ++i) {
            if (mo[i] != 0u) { hits++; where = i; }
        }
        ASSERT_EQ(hits, 1u);
        ASSERT_EQ(where, kDst[c]);
        ASSERT_EQ(mo[where], 1234u);
    }
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(mo); BSL_SAL_Free(pt);
    BSL_SAL_Free(ct); BSL_SAL_Free(ctR); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SLOT_MAP_ROTATE_TC001
* @title  With the slot map on, a rotation is a cyclic shift of the slots.
* @brief  The map lays the slots out as a 2 x (N/2) matrix, so step +1 shifts
*         each row left by one and wraps at the row boundary, step -1 shifts
*         right, and the two rows never mix. Swapping the rows is a different
*         automorphism (sigma_{-1}, Galois element 2N-1) and is checked here
*         too, since a caller reaching for "rotate by N/2" would otherwise get
*         the identity. Drives an increasing vector so every slot is checked,
*         plus one-hots on the row boundaries.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SLOT_MAP_ROTATE_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL, *mo = NULL;
    uint8_t *pt = NULL, *ct = NULL, *ctR = NULL, *ptOut = NULL;
    const uint32_t HALF = HIFHE_N / 2u;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    uint32_t on = 1u;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_SET_SLOT_MAP, &on, sizeof(on)), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    /* One call: a second GEN_GALOIS_KEYS replaces the whole set rather than
     * adding to it, so every element this case needs goes in together.
     * Step +1 resolves to element 3 and step -1 to its inverse mod 2N. */
    uint64_t twoN = 2ull * HIFHE_N;
    uint64_t inv3 = 0u;
    for (uint64_t v = 1u; v < twoN; v += 2u) {
        if ((3ull * v) % twoN == 1ull) { inv3 = v; break; }
    }
    ASSERT_TRUE(inv3 != 0u);
    int32_t steps[2] = { 1, -1 };
    uint64_t elts[3] = { 3ull, inv3, twoN - 1ull };   /* +1, -1, sigma_{-1} */
    BSL_Param gk[] = { {HIFHE_PARAM_BGV_GALOIS_ELTS, BSL_PARAM_TYPE_OCTETS, elts, sizeof(elts), 0},
                       BSL_PARAM_END };
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GEN_GALOIS_KEYS, gk, 0u), HIFHE_SUCCESS);

    uint32_t ptLen = 0u, ctLen = 0u, msgLen = 0u;
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &ptLen, sizeof(ptLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN, &msgLen, sizeof(msgLen));
    m     = (uint64_t *)BSL_SAL_Malloc(msgLen);
    mo    = (uint64_t *)BSL_SAL_Malloc(msgLen);
    pt    = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ct    = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ctR   = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ASSERT_TRUE(m && mo && pt && ct && ctR && ptOut);
    for (uint32_t i = 0; i < HIFHE_N; ++i) m[i] = (uint64_t)(i + 1u);

    /* encode + encrypt once; every case below rotates this ciphertext */
    BSL_Param enc[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m, msgLen, 0}, BSL_PARAM_END };
    uint32_t out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, enc, pt, &out), HIFHE_SUCCESS);
    uint32_t ptL = out;
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct, &out), HIFHE_SUCCESS);
    uint32_t ctL = out;

    for (uint32_t c = 0; c < 3u; ++c) {
        int32_t st = 0;
        BSL_Param rot[4];
        rot[0] = (BSL_Param){HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct, ctL, 0};
        if (c < 2u) {
            st = steps[c];
            rot[1] = (BSL_Param){HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_INT32, &st, sizeof(st), 0};
        } else {
            rot[1] = (BSL_Param){HIFHE_PARAM_BGV_GALOIS_ELTS, BSL_PARAM_TYPE_OCTETS,
                                 &elts[2], sizeof(elts[2]), 0};
        }
        rot[2] = (BSL_Param){HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ctR, ctLen, 0};
        rot[3] = (BSL_Param)BSL_PARAM_END;
        int32_t cmd = (c < 2u) ? HIFHE_CTRL_BGV_HE_ROTATE_STEP : HIFHE_CTRL_BGV_HE_ROTATE_ELT;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, cmd, rot, 0u), HIFHE_SUCCESS);

        out = ptLen;
        ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctR, rot[2].useLen, ptOut, &out), HIFHE_SUCCESS);
        BSL_Param dec[] = { {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, ptOut, out, 0},
                            BSL_PARAM_END };
        uint32_t ml = msgLen;
        ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(ctx, dec, (uint8_t *)mo, &ml), HIFHE_SUCCESS);

        for (uint32_t i = 0; i < HALF; ++i) {
            uint32_t src0, src1;
            if (c == 0u) {            /* +1: left shift inside each row */
                src0 = (i + 1u) % HALF;
                src1 = src0 + HALF;
            } else if (c == 1u) {     /* -1: right shift inside each row */
                src0 = (i + HALF - 1u) % HALF;
                src1 = src0 + HALF;
            } else {                  /* sigma_{-1}: rows swap, column kept */
                src0 = i + HALF;
                src1 = i;
            }
            ASSERT_EQ(mo[i],        m[src0]);
            ASSERT_EQ(mo[i + HALF], m[src1]);
        }
    }
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(mo); BSL_SAL_Free(pt);
    BSL_SAL_Free(ct); BSL_SAL_Free(ctR); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* ============================================================================
 * Rotation, BGV level.
 *
 * The cases above drive rotation through the EAL surface. These reach past it
 * with HIFHE_CTRL_BGV_GET_INNER_CTX and call BGV_Evaluator_RotateBy* directly, so
 * an evaluator fault is not masked by the adapter and both layers are pinned
 * to one definition of the permutation.
 * ========================================================================= */

/* State a BGV-level rotation case needs, taken from a provider context that
 * has already generated a key. */
typedef struct {
    CRYPT_EAL_PkeyCtx *outer;
    CRYPT_BGV_Ctx   *inner;
    BGVContext        *bctx;
    Encoder            enc;
    Encryptor          encryptor;
    Evaluator          ev;
    GaloisKeys         glk;
    uint32_t           n;
    uint64_t           t;
    uint8_t            haveEnc, haveEncryptor, haveEv, haveGlk;
} BgvRotEnv;

static void BgvRotEnvFree(BgvRotEnv *e)
{
    if (e->haveEv)        BGV_Evaluator_Destroy(&e->ev);
    if (e->haveGlk)       BGV_GaloisKeys_Destroy(&e->glk);
    if (e->haveEncryptor) BGV_Encryptor_Destroy(&e->encryptor);
    if (e->haveEnc)       BGV_Encoder_Destroy(&e->enc);
    if (e->outer != NULL) CRYPT_EAL_PkeyFreeCtx(e->outer);
    memset(e, 0, sizeof(*e));
}

/* 3^step mod 2N, the Galois element a step maps to. Negative steps use the
 * inverse of 3, found by search because 2N is small. */
static uint64_t RotEltForStep(int32_t step, uint32_t n)
{
    uint64_t twoN = 2ull * (uint64_t)n;
    uint32_t reps = (step >= 0) ? (uint32_t)step : (uint32_t)(-step);
    uint64_t k = 1ull;
    for (uint32_t i = 0; i < reps; ++i) {
        k = (k * 3ull) % twoN;
    }
    if (step < 0) {
        uint64_t inv = 0u;
        for (uint64_t v = 1u; v < twoN; v += 2u) {
            if ((k * v) % twoN == 1ull) { inv = v; break; }
        }
        k = inv;
    }
    return k;
}

/* Build the environment and derive Galois keys for `elts`. Returns 0 on
 * success. The caller frees with BgvRotEnvFree either way. */
static int BgvRotEnvInit(BgvRotEnv *e, const uint64_t *elts, uint32_t count)
{
    memset(e, 0, sizeof(*e));
    e->outer = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    if (e->outer == NULL) return -1;
    if (CRYPT_EAL_PkeyGen(e->outer) != HIFHE_SUCCESS) return -1;
    if (CRYPT_EAL_PkeyCtrl(e->outer, HIFHE_CTRL_BGV_GET_INNER_CTX,
                           &e->inner, sizeof(e->inner)) != HIFHE_SUCCESS) {
        return -1;
    }
    if (e->inner == NULL || e->inner->bgv.haveContext == 0u ||
        e->inner->bgv.haveKeygen == 0u) {
        return -1;
    }
    e->bctx = &e->inner->bgv.context;
    e->n = BGV_BGVContext_GetPolyDegree(e->bctx);
    e->t = e->bctx->bgvParameter->plainMod;

    if (BGV_Encoder_Create(&e->enc, e->bctx) != HIFHE_SUCCESS) return -1;
    e->haveEnc = 1u;

    const SecretKey *sk = e->inner->bgv.keygen.sk;
    if (sk == NULL) return -1;
    if (BGV_Encryptor_CreateFromSecret(&e->encryptor, sk, e->bctx) != HIFHE_SUCCESS) {
        return -1;
    }
    e->haveEncryptor = 1u;

    if (BGV_KeyGenerator_GenGaloisKeys(&e->glk, elts, count,
                                       &e->inner->bgv.keygen) != HIFHE_SUCCESS) {
        return -1;
    }
    e->haveGlk = 1u;

    if (BGV_Evaluator_Create(&e->ev, e->bctx, NULL, &e->glk) != HIFHE_SUCCESS) return -1;
    e->haveEv = 1u;
    return 0;
}

/* Encode and symmetric-encrypt `msg` into `ct`. */
static int BgvRotEncrypt(BgvRotEnv *e, const uint64_t *msg, Ciphertext *ct)
{
    Plaintext pt;
    memset(&pt, 0, sizeof(pt));
    if (BGV_Encoder_Encode(&pt, msg, e->n, &e->enc) != HIFHE_SUCCESS) return -1;
    int rc = (BGV_Encryptor_EncryptSymmetric(ct, &pt, &e->encryptor) == HIFHE_SUCCESS)
                 ? 0 : -1;
    BGV_Plaintext_Destroy(&pt);
    return rc;
}

/* Decrypt and decode `ct` into `msg`. */
static int BgvRotDecrypt(BgvRotEnv *e, const Ciphertext *ct, uint64_t *msg)
{
    Plaintext pt;
    memset(&pt, 0, sizeof(pt));
    if (BGV_Encryptor_Decrypt(&pt, ct, &e->encryptor) != HIFHE_SUCCESS) return -1;
    int rc = (BGV_Encoder_Decode(msg, e->n, &pt, &e->enc) == HIFHE_SUCCESS) ? 0 : -1;
    BGV_Plaintext_Destroy(&pt);
    return rc;
}

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_ROTATE_STEP_TC001
* @title  BGV_Evaluator_RotateByStep applies sigma_k at the library level.
* @brief  Encodes, encrypts, rotates and decrypts entirely through the BGV
*         API, then checks every output slot against the permutation sigma_k
*         induces. Covers +1 and -1. ROTATE_SLOT_PERM_TC001 asserts the same
*         permutation through the EAL surface, so the two layers are held to
*         one definition.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_ROTATE_STEP_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    BgvRotEnv e;
    memset(&e, 0, sizeof(e));
    uint64_t *m = NULL, *mo = NULL;
    const uint32_t LOGN = 11u;
    const int32_t steps[2] = {1, -1};
    uint64_t elts[2];

    TestMemInit();
    TestRandInit();

    /* Keys for both directions up front. */
    uint32_t probeN = HIFHE_N;
    elts[0] = RotEltForStep(steps[0], probeN);
    elts[1] = RotEltForStep(steps[1], probeN);
    ASSERT_EQ(BgvRotEnvInit(&e, elts, 2u), 0);
    ASSERT_EQ(e.n, probeN);

    m  = (uint64_t *)BSL_SAL_Malloc(e.n * sizeof(uint64_t));
    mo = (uint64_t *)BSL_SAL_Malloc(e.n * sizeof(uint64_t));
    ASSERT_TRUE(m != NULL && mo != NULL);
    for (uint32_t i = 0; i < e.n; ++i) {
        m[i] = (uint64_t)(i + 1u) % e.t;
    }

    for (uint32_t s = 0; s < 2u; ++s) {
        Ciphertext ct, ctR;
        memset(&ct, 0, sizeof(ct));
        memset(&ctR, 0, sizeof(ctR));
        ASSERT_EQ(BgvRotEncrypt(&e, m, &ct), 0);
        ASSERT_EQ(BGV_Evaluator_RotateByStep(&ctR, &ct, steps[s], &e.ev), HIFHE_SUCCESS);
        ASSERT_EQ(BgvRotDecrypt(&e, &ctR, mo), 0);
        BGV_Ciphertext_Destroy(&ct);
        BGV_Ciphertext_Destroy(&ctR);

        for (uint32_t j = 0; j < e.n; ++j) {
            uint32_t src = RotSrcSlot(j, elts[s], e.n, LOGN);
            ASSERT_EQ(mo[j], m[src]);
        }
    }
EXIT:
    BgvRotEnvFree(&e);
    BSL_SAL_Free(m);
    BSL_SAL_Free(mo);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_ROTATE_ELT_TC001
* @title  RotateByElt agrees with RotateByStep, and sigma_{-1} is an involution.
* @brief  RotateByElt(3) must equal RotateByStep(+1) because a step is defined
*         as k = 3^step. Separately, the element 2N-1 is sigma_{-1}, which is
*         its own inverse: applying it twice returns the original slots. That
*         element is not reachable through RotateByStep, so only this entry
*         point covers it.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_ROTATE_ELT_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    BgvRotEnv e;
    memset(&e, 0, sizeof(e));
    uint64_t *m = NULL, *viaStep = NULL, *viaElt = NULL, *twice = NULL;
    uint64_t elts[2];

    TestMemInit();
    TestRandInit();

    uint64_t negOne = 2ull * (uint64_t)HIFHE_N - 1ull;
    elts[0] = 3ull;          /* == 3^1, the +1 step */
    elts[1] = negOne;        /* sigma_{-1}, row swap under the slot map */
    ASSERT_EQ(BgvRotEnvInit(&e, elts, 2u), 0);

    m       = (uint64_t *)BSL_SAL_Malloc(e.n * sizeof(uint64_t));
    viaStep = (uint64_t *)BSL_SAL_Malloc(e.n * sizeof(uint64_t));
    viaElt  = (uint64_t *)BSL_SAL_Malloc(e.n * sizeof(uint64_t));
    twice   = (uint64_t *)BSL_SAL_Malloc(e.n * sizeof(uint64_t));
    ASSERT_TRUE(m != NULL && viaStep != NULL && viaElt != NULL && twice != NULL);
    for (uint32_t i = 0; i < e.n; ++i) {
        m[i] = (uint64_t)((i * 5u) + 7u) % e.t;
    }

    Ciphertext ct, a, b, c;
    memset(&ct, 0, sizeof(ct));
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    memset(&c, 0, sizeof(c));
    ASSERT_EQ(BgvRotEncrypt(&e, m, &ct), 0);

    ASSERT_EQ(BGV_Evaluator_RotateByStep(&a, &ct, 1, &e.ev), HIFHE_SUCCESS);
    ASSERT_EQ(BgvRotDecrypt(&e, &a, viaStep), 0);
    ASSERT_EQ(BGV_Evaluator_RotateByElt(&b, &ct, 3ull, &e.ev), HIFHE_SUCCESS);
    ASSERT_EQ(BgvRotDecrypt(&e, &b, viaElt), 0);
    for (uint32_t j = 0; j < e.n; ++j) {
        ASSERT_EQ(viaStep[j], viaElt[j]);
    }

    /* sigma_{-1} twice is the identity. */
    BGV_Ciphertext_Destroy(&a);
    memset(&a, 0, sizeof(a));
    ASSERT_EQ(BGV_Evaluator_RotateByElt(&a, &ct, negOne, &e.ev), HIFHE_SUCCESS);
    ASSERT_EQ(BGV_Evaluator_RotateByElt(&c, &a, negOne, &e.ev), HIFHE_SUCCESS);
    ASSERT_EQ(BgvRotDecrypt(&e, &c, twice), 0);
    for (uint32_t j = 0; j < e.n; ++j) {
        ASSERT_EQ(twice[j], m[j]);
    }

    BGV_Ciphertext_Destroy(&ct);
    BGV_Ciphertext_Destroy(&a);
    BGV_Ciphertext_Destroy(&b);
    BGV_Ciphertext_Destroy(&c);
EXIT:
    BgvRotEnvFree(&e);
    BSL_SAL_Free(m);
    BSL_SAL_Free(viaStep);
    BSL_SAL_Free(viaElt);
    BSL_SAL_Free(twice);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_ROTATE_COMPOSE_TC001
* @title  Rotations compose additively and +s then -s is the identity.
* @brief  sigma_a . sigma_b == sigma_(ab), so rotating by 1 then 2 must land
*         where rotating by 3 does, and rotating by +2 then -2 must return the
*         original slots. Both hold only if the key switch that follows each
*         permutation preserves the plaintext exactly, which a single rotation
*         cannot show.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_ROTATE_COMPOSE_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    BgvRotEnv e;
    memset(&e, 0, sizeof(e));
    uint64_t *m = NULL, *chained = NULL, *direct = NULL, *back = NULL;
    uint64_t elts[4];

    TestMemInit();
    TestRandInit();

    elts[0] = RotEltForStep(1, HIFHE_N);
    elts[1] = RotEltForStep(2, HIFHE_N);
    elts[2] = RotEltForStep(3, HIFHE_N);
    elts[3] = RotEltForStep(-2, HIFHE_N);
    ASSERT_EQ(BgvRotEnvInit(&e, elts, 4u), 0);

    m       = (uint64_t *)BSL_SAL_Malloc(e.n * sizeof(uint64_t));
    chained = (uint64_t *)BSL_SAL_Malloc(e.n * sizeof(uint64_t));
    direct  = (uint64_t *)BSL_SAL_Malloc(e.n * sizeof(uint64_t));
    back    = (uint64_t *)BSL_SAL_Malloc(e.n * sizeof(uint64_t));
    ASSERT_TRUE(m != NULL && chained != NULL && direct != NULL && back != NULL);
    for (uint32_t i = 0; i < e.n; ++i) {
        m[i] = (uint64_t)((i * 13u) + 2u) % e.t;
    }

    Ciphertext ct, r1, r12, r3, rBack;
    memset(&ct, 0, sizeof(ct));
    memset(&r1, 0, sizeof(r1));
    memset(&r12, 0, sizeof(r12));
    memset(&r3, 0, sizeof(r3));
    memset(&rBack, 0, sizeof(rBack));
    ASSERT_EQ(BgvRotEncrypt(&e, m, &ct), 0);

    ASSERT_EQ(BGV_Evaluator_RotateByStep(&r1, &ct, 1, &e.ev), HIFHE_SUCCESS);
    ASSERT_EQ(BGV_Evaluator_RotateByStep(&r12, &r1, 2, &e.ev), HIFHE_SUCCESS);
    ASSERT_EQ(BgvRotDecrypt(&e, &r12, chained), 0);

    ASSERT_EQ(BGV_Evaluator_RotateByStep(&r3, &ct, 3, &e.ev), HIFHE_SUCCESS);
    ASSERT_EQ(BgvRotDecrypt(&e, &r3, direct), 0);
    for (uint32_t j = 0; j < e.n; ++j) {
        ASSERT_EQ(chained[j], direct[j]);
    }

    /* +2 then -2 returns the original. */
    Ciphertext r2;
    memset(&r2, 0, sizeof(r2));
    ASSERT_EQ(BGV_Evaluator_RotateByStep(&r2, &ct, 2, &e.ev), HIFHE_SUCCESS);
    ASSERT_EQ(BGV_Evaluator_RotateByStep(&rBack, &r2, -2, &e.ev), HIFHE_SUCCESS);
    ASSERT_EQ(BgvRotDecrypt(&e, &rBack, back), 0);
    for (uint32_t j = 0; j < e.n; ++j) {
        ASSERT_EQ(back[j], m[j]);
    }
    BGV_Ciphertext_Destroy(&r2);

    BGV_Ciphertext_Destroy(&ct);
    BGV_Ciphertext_Destroy(&r1);
    BGV_Ciphertext_Destroy(&r12);
    BGV_Ciphertext_Destroy(&r3);
    BGV_Ciphertext_Destroy(&rBack);
EXIT:
    BgvRotEnvFree(&e);
    BSL_SAL_Free(m);
    BSL_SAL_Free(chained);
    BSL_SAL_Free(direct);
    BSL_SAL_Free(back);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_ROTATE_ERR_TC001
* @title  RotateBy* rejects null arguments, unkeyed elements and even elements.
* @brief  A Galois element only has a key if it was asked for at generation
*         time, so a step outside the generated set must fail rather than
*         return a ciphertext nothing can decrypt. An even element can never
*         have one: it is not invertible mod 2N, so no automorphism uses it.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_ROTATE_ERR_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    BgvRotEnv e;
    memset(&e, 0, sizeof(e));
    uint64_t *m = NULL;
    uint64_t elts[1];

    TestMemInit();
    TestRandInit();

    elts[0] = RotEltForStep(1, HIFHE_N);      /* +1 only */
    ASSERT_EQ(BgvRotEnvInit(&e, elts, 1u), 0);

    m = (uint64_t *)BSL_SAL_Malloc(e.n * sizeof(uint64_t));
    ASSERT_TRUE(m != NULL);
    for (uint32_t i = 0; i < e.n; ++i) {
        m[i] = (uint64_t)(i % 17u);
    }

    Ciphertext ct, out;
    memset(&ct, 0, sizeof(ct));
    memset(&out, 0, sizeof(out));
    ASSERT_EQ(BgvRotEncrypt(&e, m, &ct), 0);

    /* Null arguments. */
    ASSERT_TRUE(BGV_Evaluator_RotateByStep(NULL, &ct, 1, &e.ev) != HIFHE_SUCCESS);
    ASSERT_TRUE(BGV_Evaluator_RotateByStep(&out, NULL, 1, &e.ev) != HIFHE_SUCCESS);
    ASSERT_TRUE(BGV_Evaluator_RotateByStep(&out, &ct, 1, NULL) != HIFHE_SUCCESS);
    ASSERT_TRUE(BGV_Evaluator_RotateByElt(&out, &ct, 3ull, NULL) != HIFHE_SUCCESS);

    /* Step 2 was never keyed. */
    ASSERT_EQ(BGV_Evaluator_RotateByStep(&out, &ct, 2, &e.ev), HIFHE_NO_GALOIS_KEY);

    /* Even elements are not invertible mod 2N, so none is ever keyed. */
    ASSERT_TRUE(BGV_Evaluator_RotateByElt(&out, &ct, 4ull, &e.ev) != HIFHE_SUCCESS);

    /* The keyed step still works after the failures. */
    ASSERT_EQ(BGV_Evaluator_RotateByStep(&out, &ct, 1, &e.ev), HIFHE_SUCCESS);
    BGV_Ciphertext_Destroy(&out);
    BGV_Ciphertext_Destroy(&ct);
EXIT:
    BgvRotEnvFree(&e);
    BSL_SAL_Free(m);
}
/* END_CASE */

/* ============================================================================
 * Rotation, provider level.
 * ========================================================================= */

/* Generate Galois keys for `steps` on a provider context. */
static int BgvGenGaloisSteps(CRYPT_EAL_PkeyCtx *ctx, const int32_t *steps, uint32_t count)
{
    BSL_Param gk[] = {
        {HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_OCTETS, (void *)(uintptr_t)steps,
         count * (uint32_t)sizeof(int32_t), 0},
        BSL_PARAM_END
    };
    return (CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GEN_GALOIS_KEYS, gk, 0u) == HIFHE_SUCCESS)
               ? 0 : -1;
}

/* Rotate `ct` by `step` through the ctrl surface. */
static int BgvRotateStep(CRYPT_EAL_PkeyCtx *ctx, const uint8_t *ct, uint32_t ctLen,
                           int32_t step, uint8_t *out, uint32_t cap, uint32_t *outLen)
{
    int32_t s = step;
    BSL_Param rot[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1,  BSL_PARAM_TYPE_OCTETS, (void *)(uintptr_t)ct, ctLen, 0},
        {HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_INT32,  &s, (uint32_t)sizeof(s), 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2,  BSL_PARAM_TYPE_OCTETS, out, cap, 0},
        BSL_PARAM_END
    };
    if (CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_HE_ROTATE_STEP, rot, 0u) != HIFHE_SUCCESS) {
        return -1;
    }
    *outLen = rot[2].useLen;
    return 0;
}

/* Rotate `ct` by an explicit Galois element through the ctrl surface. */
static int BgvRotateElt(CRYPT_EAL_PkeyCtx *ctx, const uint8_t *ct, uint32_t ctLen,
                          uint64_t elt, uint8_t *out, uint32_t cap, uint32_t *outLen)
{
    uint64_t k = elt;
    BSL_Param rot[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, (void *)(uintptr_t)ct, ctLen, 0},
        {HIFHE_PARAM_BGV_GALOIS_ELTS, BSL_PARAM_TYPE_OCTETS, &k, (uint32_t)sizeof(k), 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, out, cap, 0},
        BSL_PARAM_END
    };
    if (CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_HE_ROTATE_ELT, rot, 0u) != HIFHE_SUCCESS) {
        return -1;
    }
    *outLen = rot[2].useLen;
    return 0;
}

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_ROTATE_ELT_CTRL_TC001
* @title  HIFHE_CTRL_BGV_HE_ROTATE_ELT agrees with HIFHE_CTRL_BGV_HE_ROTATE_STEP.
* @brief  The element form is the only way to reach automorphisms that are not
*         a power of 3, so it has its own ctrl. Rotating by element 3 must
*         produce the same slots as rotating by step 1, and decryption must
*         succeed on the result.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_ROTATE_ELT_CTRL_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL, *byStep = NULL, *byElt = NULL;
    uint8_t *pt = NULL, *ct = NULL, *ctA = NULL, *ctB = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    BgvDims d;
    ASSERT_EQ(BgvDimsGet(ctx, &d), 0);
    int32_t steps[1] = {1};
    ASSERT_EQ(BgvGenGaloisSteps(ctx, steps, 1u), 0);

    m      = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    byStep = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    byElt  = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    pt     = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ptOut  = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ct     = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ctA    = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ctB    = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ASSERT_TRUE(m && byStep && byElt && pt && ptOut && ct && ctA && ctB);
    for (uint32_t i = 0; i < d.n; ++i) {
        m[i] = (uint64_t)(i + 1u) % d.t;
    }

    uint32_t ptL = 0u, outLen = d.ctLen;
    ASSERT_EQ(BgvEncode(ctx, m, d.msgLen, pt, d.ptLen, &ptL), 0);
    outLen = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct, &outLen), HIFHE_SUCCESS);
    uint32_t ctL = outLen;

    uint32_t aLen = 0u, bLen = 0u;
    ASSERT_EQ(BgvRotateStep(ctx, ct, ctL, 1, ctA, d.ctLen, &aLen), 0);
    ASSERT_EQ(BgvRotateElt(ctx, ct, ctL, 3ull, ctB, d.ctLen, &bLen), 0);

    outLen = d.ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctA, aLen, ptOut, &outLen), HIFHE_SUCCESS);
    ASSERT_EQ(BgvDecode(ctx, ptOut, outLen, byStep, d.msgLen), 0);
    outLen = d.ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctB, bLen, ptOut, &outLen), HIFHE_SUCCESS);
    ASSERT_EQ(BgvDecode(ctx, ptOut, outLen, byElt, d.msgLen), 0);

    for (uint32_t j = 0; j < d.n; ++j) {
        ASSERT_EQ(byStep[j], byElt[j]);
    }
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(byStep); BSL_SAL_Free(byElt);
    BSL_SAL_Free(pt); BSL_SAL_Free(ptOut);
    BSL_SAL_Free(ct); BSL_SAL_Free(ctA); BSL_SAL_Free(ctB);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_ROTATE_MULTI_STEP_TC001
* @title  One GEN_GALOIS_KEYS call covers every step it was given.
* @brief  Galois keys are generated per element, and the ctrl takes an array.
*         Asking for four steps at once must key all four: each is exercised
*         against the permutation it should induce, so a key stored under the
*         wrong element is caught rather than silently producing garbage on
*         one step only.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_ROTATE_MULTI_STEP_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL, *mo = NULL;
    uint8_t *pt = NULL, *ct = NULL, *ctR = NULL, *ptOut = NULL;
    const uint32_t LOGN = 11u;
    const int32_t steps[4] = {1, 2, -1, 7};

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    BgvDims d;
    ASSERT_EQ(BgvDimsGet(ctx, &d), 0);
    ASSERT_EQ(d.n, HIFHE_N);
    ASSERT_EQ(BgvGenGaloisSteps(ctx, steps, 4u), 0);

    m     = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    mo    = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    pt    = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ct    = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ctR   = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ASSERT_TRUE(m && mo && pt && ptOut && ct && ctR);
    for (uint32_t i = 0; i < d.n; ++i) {
        m[i] = (uint64_t)((i * 3u) + 11u) % d.t;
    }

    uint32_t ptL = 0u, outLen = d.ctLen;
    ASSERT_EQ(BgvEncode(ctx, m, d.msgLen, pt, d.ptLen, &ptL), 0);
    outLen = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct, &outLen), HIFHE_SUCCESS);
    uint32_t ctL = outLen;

    for (uint32_t s = 0; s < 4u; ++s) {
        uint32_t rLen = 0u;
        ASSERT_EQ(BgvRotateStep(ctx, ct, ctL, steps[s], ctR, d.ctLen, &rLen), 0);
        outLen = d.ptLen;
        ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctR, rLen, ptOut, &outLen), HIFHE_SUCCESS);
        ASSERT_EQ(BgvDecode(ctx, ptOut, outLen, mo, d.msgLen), 0);

        uint64_t k = RotEltForStep(steps[s], d.n);
        for (uint32_t j = 0; j < d.n; ++j) {
            ASSERT_EQ(mo[j], m[RotSrcSlot(j, k, d.n, LOGN)]);
        }
    }
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(mo);
    BSL_SAL_Free(pt); BSL_SAL_Free(ptOut);
    BSL_SAL_Free(ct); BSL_SAL_Free(ctR);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_ROTATE_NO_KEY_TC001
* @title  Rotating without Galois keys fails and leaves the output untouched.
* @brief  Rotation needs a key switch, so a context that never generated
*         Galois keys cannot rotate. The ctrl must report it rather than
*         emitting a ciphertext that decrypts to noise, and it must not write
*         into the output buffer on the way out.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_ROTATE_NO_KEY_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL;
    uint8_t *pt = NULL, *ct = NULL, *ctR = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    BgvDims d;
    ASSERT_EQ(BgvDimsGet(ctx, &d), 0);

    m   = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    pt  = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ct  = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ctR = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ASSERT_TRUE(m && pt && ct && ctR);
    for (uint32_t i = 0; i < d.n; ++i) {
        m[i] = (uint64_t)(i % 23u);
    }
    memset(ctR, 0xA5, d.ctLen);

    uint32_t ptL = 0u, outLen = d.ctLen;
    ASSERT_EQ(BgvEncode(ctx, m, d.msgLen, pt, d.ptLen, &ptL), 0);
    outLen = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct, &outLen), HIFHE_SUCCESS);
    uint32_t ctL = outLen;

    int32_t step = 1;
    BSL_Param rot[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1,  BSL_PARAM_TYPE_OCTETS, ct, ctL, 0},
        {HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_INT32,  &step, (uint32_t)sizeof(step), 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2,  BSL_PARAM_TYPE_OCTETS, ctR, d.ctLen, 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_HE_ROTATE_STEP, rot, 0u),
              HIFHE_NO_GALOIS_KEY);
    for (uint32_t i = 0; i < d.ctLen; ++i) {
        ASSERT_EQ(ctR[i], 0xA5u);
    }

    /* Generating the key makes the same call succeed. */
    int32_t steps[1] = {1};
    ASSERT_EQ(BgvGenGaloisSteps(ctx, steps, 1u), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_HE_ROTATE_STEP, rot, 0u), HIFHE_SUCCESS);
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(pt);
    BSL_SAL_Free(ct); BSL_SAL_Free(ctR);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_ROTATE_ADD_COMMUTE_TC001
* @title  Rotation is linear: rot(a + b) equals rot(a) + rot(b).
* @brief  sigma_k is a ring automorphism, so it commutes with addition. This
*         is the property a caller relies on when rotating partial sums, and
*         it exercises rotation on a ciphertext that is itself the output of
*         another homomorphic operation rather than a fresh encryption.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_ROTATE_ADD_COMMUTE_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *ma = NULL, *mb = NULL, *lhs = NULL, *rhs = NULL;
    uint8_t *pta = NULL, *ptb = NULL, *ptOut = NULL;
    uint8_t *cta = NULL, *ctb = NULL, *ctSum = NULL;
    uint8_t *rotSum = NULL, *rotA = NULL, *rotB = NULL, *sumRot = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    BgvDims d;
    ASSERT_EQ(BgvDimsGet(ctx, &d), 0);
    int32_t steps[1] = {1};
    ASSERT_EQ(BgvGenGaloisSteps(ctx, steps, 1u), 0);

    ma = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    mb = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    lhs = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    rhs = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    pta = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ptb = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    cta = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ctb = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ctSum = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    rotSum = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    rotA = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    rotB = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    sumRot = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ASSERT_TRUE(ma && mb && lhs && rhs && pta && ptb && ptOut);
    ASSERT_TRUE(cta && ctb && ctSum && rotSum && rotA && rotB && sumRot);

    for (uint32_t i = 0; i < d.n; ++i) {
        ma[i] = (uint64_t)((i * 5u) + 1u) % d.t;
        mb[i] = (uint64_t)((i * 9u) + 4u) % d.t;
    }

    uint32_t la = 0u, lb = 0u, outLen = 0u;
    ASSERT_EQ(BgvEncode(ctx, ma, d.msgLen, pta, d.ptLen, &la), 0);
    ASSERT_EQ(BgvEncode(ctx, mb, d.msgLen, ptb, d.ptLen, &lb), 0);
    outLen = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pta, la, cta, &outLen), HIFHE_SUCCESS);
    uint32_t ctaLen = outLen;
    outLen = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, ptb, lb, ctb, &outLen), HIFHE_SUCCESS);
    uint32_t ctbLen = outLen;

    /* rot(a + b) */
    BSL_Param addIn[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, cta, ctaLen, 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ctb, ctbLen, 0},
        BSL_PARAM_END
    };
    outLen = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEAdd(ctx, addIn, ctSum, &outLen), HIFHE_SUCCESS);
    uint32_t sumLen = outLen;
    uint32_t rotSumLen = 0u;
    ASSERT_EQ(BgvRotateStep(ctx, ctSum, sumLen, 1, rotSum, d.ctLen, &rotSumLen), 0);
    outLen = d.ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, rotSum, rotSumLen, ptOut, &outLen), HIFHE_SUCCESS);
    ASSERT_EQ(BgvDecode(ctx, ptOut, outLen, lhs, d.msgLen), 0);

    /* rot(a) + rot(b) */
    uint32_t rotALen = 0u, rotBLen = 0u;
    ASSERT_EQ(BgvRotateStep(ctx, cta, ctaLen, 1, rotA, d.ctLen, &rotALen), 0);
    ASSERT_EQ(BgvRotateStep(ctx, ctb, ctbLen, 1, rotB, d.ctLen, &rotBLen), 0);
    BSL_Param addRot[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, rotA, rotALen, 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, rotB, rotBLen, 0},
        BSL_PARAM_END
    };
    outLen = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEAdd(ctx, addRot, sumRot, &outLen), HIFHE_SUCCESS);
    uint32_t sumRotLen = outLen;
    outLen = d.ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, sumRot, sumRotLen, ptOut, &outLen), HIFHE_SUCCESS);
    ASSERT_EQ(BgvDecode(ctx, ptOut, outLen, rhs, d.msgLen), 0);

    for (uint32_t j = 0; j < d.n; ++j) {
        ASSERT_EQ(lhs[j], rhs[j]);
        ASSERT_EQ(lhs[j], (ma[RotSrcSlot(j, 3ull, d.n, 11u)] +
                           mb[RotSrcSlot(j, 3ull, d.n, 11u)]) % d.t);
    }
EXIT:
    BSL_SAL_Free(ma); BSL_SAL_Free(mb); BSL_SAL_Free(lhs); BSL_SAL_Free(rhs);
    BSL_SAL_Free(pta); BSL_SAL_Free(ptb); BSL_SAL_Free(ptOut);
    BSL_SAL_Free(cta); BSL_SAL_Free(ctb); BSL_SAL_Free(ctSum);
    BSL_SAL_Free(rotSum); BSL_SAL_Free(rotA); BSL_SAL_Free(rotB); BSL_SAL_Free(sumRot);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

static int32_t FailingRand(uint8_t *buf, uint32_t len)
{
    (void)buf;
    (void)len;
    return -1;
}

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SK_DRBG_FAIL_TC001
* @title  A DRBG failure while sampling the secret key is reported.
* @brief  The fixed-weight shuffle reads every swap position from the random
*         stream. A failed read must fail GenSecretKey. Absorbing it leaves
*         each position at 0, which yields the same secret key on every call.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SK_DRBG_FAIL_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_BGV_Ctx *inner = NULL;
    int32_t r = HIFHE_SUCCESS;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_INNER_CTX, &inner, sizeof(inner)),
              HIFHE_SUCCESS);
    ASSERT_TRUE(inner != NULL);

    CRYPT_EAL_SetRandCallBack(FailingRand);
    r = BGV_KeyGenerator_GenSecretKey(&inner->bgv.keygen);
    TestRandInit();
    ASSERT_TRUE(r != HIFHE_SUCCESS);
    ASSERT_TRUE(inner->bgv.keygen.sk == NULL);
EXIT:
    TestRandInit();
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

static void *NoMalloc(uint32_t size)
{
    (void)size;
    return NULL;
}

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_CONFIG_COPY_OOM_TC001
* @title  RLWE_CrtPolyConfig_Copy reports an allocation failure.
* @brief  Every CrtPoly, plaintext and ciphertext config is built through this
*         copy. A swallowed failure leaves an empty RNS base behind a success
*         code, and every per-limb loop over it then does nothing.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_CONFIG_COPY_OOM_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    uint64_t base[2] = {97u, 193u};
    CrtPolyConfig src;
    CrtPolyConfig dst;
    int32_t r = HIFHE_SUCCESS;
    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));
    src.rnsbase.data = base;
    src.rnsbase.size = 2u;
    src.dtype = HIFHE_NTT;

    TestMemInit();
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, NoMalloc), BSL_SUCCESS);
    r = RLWE_CrtPolyConfig_Copy(&dst, &src);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, NULL);
    ASSERT_EQ(r, HIFHE_MEMORY_ERROR);
    ASSERT_EQ(dst.rnsbase.size, 0u);

    ASSERT_EQ(RLWE_CrtPolyConfig_Copy(&dst, &src), HIFHE_SUCCESS);
    ASSERT_EQ(dst.rnsbase.size, 2u);
    ASSERT_EQ(dst.rnsbase.data[1], 193u);
EXIT:
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, NULL);
    RLWE_CrtPolyConfig_Destroy(&dst);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_RERAND_SK_ONLY_TC001
* @title  Rerandomize runs on a context that holds only the secret key.
* @brief  The context is loaded through SetPrvKey and never sees a public key.
*         Encrypt goes symmetric, and rerandomize must not ask for pk.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_RERAND_SK_ONLY_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *full = NULL, *skOnly = NULL;
    CRYPT_BGV_Ctx *inner = NULL;
    uint8_t *prv = NULL, *pt = NULL, *ct = NULL, *ctR = NULL, *ptOut = NULL;
    uint64_t *m = NULL, *mo = NULL;
    BgvDims d;
    memset(&d, 0, sizeof(d));

    TestMemInit();
    TestRandInit();
    full = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    skOnly = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(full != NULL && skOnly != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(full), HIFHE_SUCCESS);

    uint32_t prvLen = 0u;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(full, HIFHE_CTRL_BGV_GET_PRVKEY_LEN, &prvLen, sizeof(prvLen)),
              HIFHE_SUCCESS);
    prv = (uint8_t *)BSL_SAL_Malloc(prvLen);
    ASSERT_TRUE(prv != NULL);
    BSL_Param g[] = {{HIFHE_PARAM_BGV_PRVKEY, BSL_PARAM_TYPE_OCTETS, prv, prvLen, 0},
                     BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(full, g), HIFHE_SUCCESS);
    BSL_Param s[] = {{HIFHE_PARAM_BGV_PRVKEY, BSL_PARAM_TYPE_OCTETS, prv, g[0].useLen, 0},
                     BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(skOnly, s), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(skOnly, HIFHE_CTRL_BGV_GET_INNER_CTX, &inner, sizeof(inner)),
              HIFHE_SUCCESS);
    ASSERT_TRUE(inner != NULL);
    ASSERT_TRUE(!inner->bgv.havePk);

    ASSERT_EQ(BgvDimsGet(skOnly, &d), 0);
    m     = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    mo    = (uint64_t *)BSL_SAL_Malloc(d.msgLen);
    pt    = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ct    = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ctR   = (uint8_t *)BSL_SAL_Malloc(d.ctLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(d.ptLen);
    ASSERT_TRUE(m && mo && pt && ct && ctR && ptOut);
    for (uint32_t i = 0; i < d.n; ++i) m[i] = (uint64_t)(i % 97u);

    uint32_t ptL = 0u;
    ASSERT_EQ(BgvEncode(skOnly, m, d.msgLen, pt, d.ptLen, &ptL), 0);
    uint32_t out = d.ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(skOnly, pt, ptL, ct, &out), HIFHE_SUCCESS);
    uint32_t ctL = out;

    BSL_Param rr[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct,  ctL,     0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ctR, d.ctLen, 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(skOnly, HIFHE_CTRL_BGV_HE_RERANDOMIZE, rr, 0u), HIFHE_SUCCESS);
    ASSERT_EQ(rr[1].useLen, ctL);
    ASSERT_TRUE(memcmp(ctR, ct, ctL) != 0);

    out = d.ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(skOnly, ctR, rr[1].useLen, ptOut, &out), HIFHE_SUCCESS);
    ASSERT_EQ(BgvDecode(skOnly, ptOut, out, mo, d.msgLen), 0);
    ASSERT_EQ(memcmp(mo, m, d.msgLen), 0);
EXIT:
    BSL_SAL_Free(prv); BSL_SAL_Free(m); BSL_SAL_Free(mo); BSL_SAL_Free(pt);
    BSL_SAL_Free(ct); BSL_SAL_Free(ctR); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(full);
    CRYPT_EAL_PkeyFreeCtx(skOnly);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_CT_WIRE_SIZE_OVERFLOW_TC001
* @title  A ciphertext whose component count wraps the size arithmetic is rejected.
* @brief  ciphertextSize comes off the wire and is multiplied out in uint32 to
*         size the allocation. A count that wraps that product allocates far
*         less than the read loop writes, so the blob must be refused.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_CT_WIRE_SIZE_OVERFLOW_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL;
    uint8_t *pt = NULL, *ct = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    uint32_t ptLen = 0u, ctLen = 0u, msgLen = 0u;
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN,  &ptLen,  sizeof(ptLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen,  sizeof(ctLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN,        &msgLen, sizeof(msgLen));
    m     = (uint64_t *)BSL_SAL_Malloc(msgLen);
    pt    = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ct    = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ASSERT_TRUE(m && pt && ct && ptOut);
    for (uint32_t i = 0; i < HIFHE_N; ++i) m[i] = (uint64_t)(i % 7u);

    BSL_Param encM[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m, msgLen, 0}, BSL_PARAM_END };
    uint32_t out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encM, pt, &out), HIFHE_SUCCESS);
    uint32_t ptL = out;
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct, &out), HIFHE_SUCCESS);
    uint32_t ctL = out;

    /* ciphertextSize sits directly after the 12-byte header. 2097153 * 2048
     * is 2^32 + 2048, so the uint32 product collapses to one polynomial. */
    uint32_t bad = 2097153u;
    ct[12] = (uint8_t)(bad & 0xffu);
    ct[13] = (uint8_t)((bad >> 8) & 0xffu);
    ct[14] = (uint8_t)((bad >> 16) & 0xffu);
    ct[15] = (uint8_t)((bad >> 24) & 0xffu);

    out = ptLen;
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(ctx, ct, ctL, ptOut, &out) != HIFHE_SUCCESS);
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(pt); BSL_SAL_Free(ct); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_PRVKEY_SHORT_CHAIN_TC001
* @title  A private key carrying fewer limbs than the context is rejected.
* @brief  Decryption indexes the key across the ciphertext's whole chain, so a
*         short key would be read past its allocation.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_PRVKEY_SHORT_CHAIN_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *src = NULL, *dst = NULL;
    uint8_t *sk = NULL;

    TestMemInit();
    TestRandInit();
    /* A two-limb chain, so a one-limb key is genuinely short. */
    src = BgvNewCtx(HIFHE_BGV_4096_44x2_17BIT);
    dst = BgvNewCtx(HIFHE_BGV_4096_44x2_17BIT);
    ASSERT_TRUE(src != NULL && dst != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(src), HIFHE_SUCCESS);

    uint32_t skLen = 0u;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(src, HIFHE_CTRL_BGV_GET_PRVKEY_LEN, &skLen, sizeof(skLen)),
              HIFHE_SUCCESS);
    sk = (uint8_t *)BSL_SAL_Malloc(skLen);
    ASSERT_TRUE(sk != NULL);
    BSL_Param g[] = { {HIFHE_PARAM_BGV_PRVKEY, BSL_PARAM_TYPE_OCTETS, sk, skLen, 0}, BSL_PARAM_END };
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(src, g), HIFHE_SUCCESS);
    uint32_t used = g[0].useLen;

    /* rns follows header(12) + scale(8) + N(4). Claim one limb instead of two. */
    sk[24] = 1u; sk[25] = 0u; sk[26] = 0u; sk[27] = 0u;

    BSL_Param s[] = { {HIFHE_PARAM_BGV_PRVKEY, BSL_PARAM_TYPE_OCTETS, sk, used, 0}, BSL_PARAM_END };
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrvEx(dst, s) != HIFHE_SUCCESS);
EXIT:
    BSL_SAL_Free(sk);
    CRYPT_EAL_PkeyFreeCtx(src);
    CRYPT_EAL_PkeyFreeCtx(dst);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_RELIN_DNUM_SMALL_TC001
* @title  A relinDnum below what the chain needs still relinearizes correctly.
* @brief  The gadget splits each limb into base-2^16 digits. Fewer digits than
*         the widest limb needs drops its high end, and the product decrypts to
*         garbage with no error reported.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_RELIN_DNUM_SMALL_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m1 = NULL, *m2 = NULL, *mo = NULL;
    uint8_t *pt1 = NULL, *pt2 = NULL, *ct1 = NULL, *ct2 = NULL, *ctMul = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    /* 48-bit limbs need three base-2^16 digits; ask for two. */
    CRYPT_BGV_Ctx *inner = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_INNER_CTX, &inner, sizeof(inner)),
              HIFHE_SUCCESS);
    ASSERT_TRUE(inner != NULL);
    inner->para.relinDnum = 2u;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GEN_RELIN_KEY, NULL, 0), HIFHE_SUCCESS);

    uint32_t ptLen = 0u, ctLen = 0u, msgLen = 0u;
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN,  &ptLen,  sizeof(ptLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen,  sizeof(ctLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN,        &msgLen, sizeof(msgLen));
    uint32_t ctLenBig = ctLen * 3u;
    m1 = (uint64_t *)BSL_SAL_Malloc(msgLen);
    m2 = (uint64_t *)BSL_SAL_Malloc(msgLen);
    mo = (uint64_t *)BSL_SAL_Malloc(msgLen);
    pt1 = (uint8_t *)BSL_SAL_Malloc(ptLen);
    pt2 = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ct1 = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ct2 = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ctMul = (uint8_t *)BSL_SAL_Malloc(ctLenBig);
    ptOut = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ASSERT_TRUE(m1 && m2 && mo && pt1 && pt2 && ct1 && ct2 && ctMul && ptOut);

    for (uint32_t i = 0; i < HIFHE_N; ++i) { m1[i] = (i == 0u) ? 7u : 0u; m2[i] = (i == 0u) ? 11u : 0u; }

    BSL_Param encM1[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m1, msgLen, 0}, BSL_PARAM_END };
    BSL_Param encM2[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m2, msgLen, 0}, BSL_PARAM_END };
    uint32_t out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encM1, pt1, &out), HIFHE_SUCCESS);
    uint32_t pt1L = out;
    out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encM2, pt2, &out), HIFHE_SUCCESS);
    uint32_t pt2L = out;
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt1, pt1L, ct1, &out), HIFHE_SUCCESS);
    uint32_t ct1L = out;
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt2, pt2L, ct2, &out), HIFHE_SUCCESS);
    uint32_t ct2L = out;

    BSL_Param mulIn[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ct2, ct2L, 0},
        BSL_PARAM_END
    };
    out = ctLenBig;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMul(ctx, mulIn, ctMul, &out), HIFHE_SUCCESS);
    uint32_t ctMulL = out;
    out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctMul, ctMulL, ptOut, &out), HIFHE_SUCCESS);
    uint32_t ptOutL = out;
    BSL_Param decIn[] = { {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, ptOut, ptOutL, 0}, BSL_PARAM_END };
    out = msgLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(ctx, decIn, (uint8_t *)mo, &out), HIFHE_SUCCESS);

    uint64_t plainMod = 0u;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD, &plainMod, sizeof(plainMod)),
              HIFHE_SUCCESS);
    ASSERT_EQ(mo[0], (7u * 11u) % plainMod);
    ASSERT_EQ(mo[1], 0u);
EXIT:
    BSL_SAL_Free(m1); BSL_SAL_Free(m2); BSL_SAL_Free(mo);
    BSL_SAL_Free(pt1); BSL_SAL_Free(pt2);
    BSL_SAL_Free(ct1); BSL_SAL_Free(ct2); BSL_SAL_Free(ctMul); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_RELIN_DNUM_HUGE_TC001
* @title  An out-of-range relinDnum is refused instead of wrapping the piece count.
* @brief  The gadget array is rnsSize * digits entries. On a two-limb chain a
*         digit count near 2^31 wraps that product to two, and generation then
*         writes well past the allocation.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_RELIN_DNUM_HUGE_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_4096_44x2_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    CRYPT_BGV_Ctx *inner = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_INNER_CTX, &inner, sizeof(inner)),
              HIFHE_SUCCESS);
    ASSERT_TRUE(inner != NULL);
    inner->para.relinDnum = 0x80000001u;
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GEN_RELIN_KEY, NULL, 0) != HIFHE_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_GALOIS_EVEN_ELT_TC001
* @title  Galois key generation refuses an even element.
* @brief  sigma_k permutes coefficients only for odd k. An even element makes
*         two sources land on one destination, so the key would rotate to
*         garbage rather than fail.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_GALOIS_EVEN_ELT_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    GaloisKeys glk;
    memset(&glk, 0, sizeof(glk));

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);
    CRYPT_BGV_Ctx *inner = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_INNER_CTX, &inner, sizeof(inner)),
              HIFHE_SUCCESS);
    ASSERT_TRUE(inner != NULL);

    uint64_t even[1] = { 4ull };
    ASSERT_TRUE(BGV_KeyGenerator_GenGaloisKeys(&glk, even, 1u, &inner->bgv.keygen)
                != HIFHE_SUCCESS);
    /* An element at or past 2N is equally unusable. */
    uint64_t past[1] = { 2ull * HIFHE_N + 3ull };
    ASSERT_TRUE(BGV_KeyGenerator_GenGaloisKeys(&glk, past, 1u, &inner->bgv.keygen)
                != HIFHE_SUCCESS);
    /* An odd element in range still works. */
    uint64_t good[1] = { 3ull };
    ASSERT_EQ(BGV_KeyGenerator_GenGaloisKeys(&glk, good, 1u, &inner->bgv.keygen),
              HIFHE_SUCCESS);
EXIT:
    BGV_GaloisKeys_Destroy(&glk);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SETPRV_FAIL_KEEPS_KEY_TC001
* @title  A rejected private-key import leaves the previous key working.
* @brief  The import used to free the old key before parsing, so a malformed
*         blob left an empty key that later decryptions dereferenced.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SETPRV_FAIL_KEEPS_KEY_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL, *mo = NULL;
    uint8_t *pt = NULL, *ct = NULL, *ptOut = NULL, *bad = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    uint32_t ptLen = 0u, ctLen = 0u, msgLen = 0u, skLen = 0u;
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN,  &ptLen,  sizeof(ptLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen,  sizeof(ctLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN,        &msgLen, sizeof(msgLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PRVKEY_LEN,     &skLen,  sizeof(skLen));
    m = (uint64_t *)BSL_SAL_Malloc(msgLen);
    mo = (uint64_t *)BSL_SAL_Malloc(msgLen);
    pt = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ct = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(ptLen);
    bad = (uint8_t *)BSL_SAL_Malloc(skLen);
    ASSERT_TRUE(m && mo && pt && ct && ptOut && bad);
    for (uint32_t i = 0; i < HIFHE_N; ++i) m[i] = (uint64_t)(i % 13u);

    BSL_Param encM[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m, msgLen, 0}, BSL_PARAM_END };
    uint32_t out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encM, pt, &out), HIFHE_SUCCESS);
    uint32_t ptL = out;
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct, &out), HIFHE_SUCCESS);
    uint32_t ctL = out;

    /* A blob with a wrecked header must be refused. */
    memset(bad, 0xa5, skLen);
    BSL_Param s[] = { {HIFHE_PARAM_BGV_PRVKEY, BSL_PARAM_TYPE_OCTETS, bad, skLen, 0}, BSL_PARAM_END };
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrvEx(ctx, s) != HIFHE_SUCCESS);

    /* The key the context already held must still decrypt. */
    out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ct, ctL, ptOut, &out), HIFHE_SUCCESS);
    uint32_t ptOutL = out;
    BSL_Param decIn[] = { {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, ptOut, ptOutL, 0}, BSL_PARAM_END };
    out = msgLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(ctx, decIn, (uint8_t *)mo, &out), HIFHE_SUCCESS);
    for (uint32_t i = 0; i < 16u; ++i) ASSERT_EQ(mo[i], m[i]);
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(mo); BSL_SAL_Free(pt);
    BSL_SAL_Free(ct); BSL_SAL_Free(ptOut); BSL_SAL_Free(bad);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_ADDCTCT_ALIAS_TC001
* @title  AddCtCt(&a, &a, &b) yields a + b.
* @brief  The output is written before the second operand is read, so an
*         output aliasing that operand used to add it to itself.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_ADDCTCT_ALIAS_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    BgvRotEnv e;
    memset(&e, 0, sizeof(e));
    uint64_t *m1 = NULL, *m2 = NULL, *mo = NULL;

    TestMemInit();
    TestRandInit();
    uint64_t elts[1];
    elts[0] = RotEltForStep(1, HIFHE_N);
    ASSERT_EQ(BgvRotEnvInit(&e, elts, 1u), 0);

    m1 = (uint64_t *)BSL_SAL_Malloc(e.n * sizeof(uint64_t));
    m2 = (uint64_t *)BSL_SAL_Malloc(e.n * sizeof(uint64_t));
    mo = (uint64_t *)BSL_SAL_Malloc(e.n * sizeof(uint64_t));
    ASSERT_TRUE(m1 && m2 && mo);
    for (uint32_t i = 0; i < e.n; ++i) { m1[i] = (uint64_t)(i % 11u); m2[i] = (uint64_t)(i % 5u); }

    Ciphertext a, b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    ASSERT_EQ(BgvRotEncrypt(&e, m1, &a), 0);
    ASSERT_EQ(BgvRotEncrypt(&e, m2, &b), 0);

    /* Output aliases the first operand. */
    ASSERT_EQ(BGV_Evaluator_AddCtCt(&a, &a, &b, &e.ev), HIFHE_SUCCESS);
    ASSERT_EQ(BgvRotDecrypt(&e, &a, mo), 0);
    for (uint32_t i = 0; i < e.n; ++i) {
        ASSERT_EQ(mo[i], (m1[i] + m2[i]) % e.t);
    }
    BGV_Ciphertext_Destroy(&a);
    BGV_Ciphertext_Destroy(&b);
EXIT:
    BgvRotEnvFree(&e);
    BSL_SAL_Free(m1); BSL_SAL_Free(m2); BSL_SAL_Free(mo);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_REGEN_CLEARS_EVAL_KEYS_TC001
* @title  Generating a new key pair drops the keys derived from the old secret.
* @brief  A relinearization key built for the previous secret would otherwise
*         still be used, and the product would decrypt to garbage.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_REGEN_CLEARS_EVAL_KEYS_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m1 = NULL, *m2 = NULL, *mo = NULL;
    uint8_t *pt1 = NULL, *pt2 = NULL, *ct1 = NULL, *ct2 = NULL, *ctMul = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GEN_RELIN_KEY, NULL, 0), HIFHE_SUCCESS);
    /* Second key pair: the relin key above belongs to the first secret. */
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    uint32_t ptLen = 0u, ctLen = 0u, msgLen = 0u;
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN,  &ptLen,  sizeof(ptLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen,  sizeof(ctLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN,        &msgLen, sizeof(msgLen));
    uint32_t ctLenBig = ctLen * 3u;
    m1 = (uint64_t *)BSL_SAL_Malloc(msgLen);
    m2 = (uint64_t *)BSL_SAL_Malloc(msgLen);
    mo = (uint64_t *)BSL_SAL_Malloc(msgLen);
    pt1 = (uint8_t *)BSL_SAL_Malloc(ptLen);
    pt2 = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ct1 = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ct2 = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ctMul = (uint8_t *)BSL_SAL_Malloc(ctLenBig);
    ptOut = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ASSERT_TRUE(m1 && m2 && mo && pt1 && pt2 && ct1 && ct2 && ctMul && ptOut);
    for (uint32_t i = 0; i < HIFHE_N; ++i) { m1[i] = (i == 0u) ? 6u : 0u; m2[i] = (i == 0u) ? 9u : 0u; }

    BSL_Param encM1[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m1, msgLen, 0}, BSL_PARAM_END };
    BSL_Param encM2[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m2, msgLen, 0}, BSL_PARAM_END };
    uint32_t out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encM1, pt1, &out), HIFHE_SUCCESS);
    uint32_t pt1L = out;
    out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encM2, pt2, &out), HIFHE_SUCCESS);
    uint32_t pt2L = out;
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt1, pt1L, ct1, &out), HIFHE_SUCCESS);
    uint32_t ct1L = out;
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt2, pt2L, ct2, &out), HIFHE_SUCCESS);
    uint32_t ct2L = out;

    BSL_Param mulIn[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct1, ct1L, 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ct2, ct2L, 0},
        BSL_PARAM_END
    };
    out = ctLenBig;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMul(ctx, mulIn, ctMul, &out), HIFHE_SUCCESS);
    uint32_t ctMulL = out;
    out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctMul, ctMulL, ptOut, &out), HIFHE_SUCCESS);
    uint32_t ptOutL = out;
    BSL_Param decIn[] = { {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, ptOut, ptOutL, 0}, BSL_PARAM_END };
    out = msgLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(ctx, decIn, (uint8_t *)mo, &out), HIFHE_SUCCESS);

    uint64_t plainMod = 0u;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD, &plainMod, sizeof(plainMod)),
              HIFHE_SUCCESS);
    ASSERT_EQ(mo[0], (6u * 9u) % plainMod);
EXIT:
    BSL_SAL_Free(m1); BSL_SAL_Free(m2); BSL_SAL_Free(mo);
    BSL_SAL_Free(pt1); BSL_SAL_Free(pt2);
    BSL_SAL_Free(ct1); BSL_SAL_Free(ct2); BSL_SAL_Free(ctMul); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SETPARA_RESETS_TC001
* @title  Switching parameters rebuilds the ring instead of reusing the old one.
* @brief  Bgv_BuildContext returns early once a context exists, so a context
*         built at one degree kept serving while the ctrl surface reported the
*         newly requested one.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SETPARA_RESETS_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL, *mo = NULL;
    uint8_t *pt = NULL, *ct = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    uint32_t deg = 0u;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &deg, sizeof(deg)),
              HIFHE_SUCCESS);
    ASSERT_EQ(deg, HIFHE_N);

    /* Move to a wider ring after the first one was already built. */
    int32_t preset = HIFHE_BGV_4096_44x2_17BIT;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &preset, sizeof(preset)),
              HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    uint32_t ptLen = 0u, ctLen = 0u, msgLen = 0u;
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN,  &ptLen,  sizeof(ptLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen,  sizeof(ctLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN,        &msgLen, sizeof(msgLen));
    /* The ring actually in use must be the one just requested. */
    ASSERT_EQ(msgLen, 4096u * (uint32_t)sizeof(uint64_t));

    m = (uint64_t *)BSL_SAL_Malloc(msgLen);
    mo = (uint64_t *)BSL_SAL_Malloc(msgLen);
    pt = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ct = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ASSERT_TRUE(m && mo && pt && ct && ptOut);
    for (uint32_t i = 0; i < 4096u; ++i) m[i] = (uint64_t)(i % 19u);

    BSL_Param encM[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m, msgLen, 0}, BSL_PARAM_END };
    uint32_t out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encM, pt, &out), HIFHE_SUCCESS);
    uint32_t ptL = out;
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct, &out), HIFHE_SUCCESS);
    uint32_t ctL = out;
    out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ct, ctL, ptOut, &out), HIFHE_SUCCESS);
    uint32_t ptOutL = out;
    BSL_Param decIn[] = { {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, ptOut, ptOutL, 0}, BSL_PARAM_END };
    out = msgLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(ctx, decIn, (uint8_t *)mo, &out), HIFHE_SUCCESS);
    for (uint32_t i = 0; i < 32u; ++i) ASSERT_EQ(mo[i], m[i]);
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(mo); BSL_SAL_Free(pt);
    BSL_SAL_Free(ct); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_MULSCALAR_REDUCE_TC001
* @title  A scalar at or above the ciphertext modulus still multiplies in Z_t.
* @brief  The scalar belongs to the plaintext space. Passed straight into
*         arithmetic mod q, a multiple of q zeroed the ciphertext instead of
*         scaling the message.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_MULSCALAR_REDUCE_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL, *mo = NULL;
    uint8_t *pt = NULL, *ct = NULL, *ctMul = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_2048_48_17BIT);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    CRYPT_BGV_Ctx *inner = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_INNER_CTX, &inner, sizeof(inner)),
              HIFHE_SUCCESS);
    ASSERT_TRUE(inner != NULL && inner->bgv.haveContext != 0u);
    uint64_t q = inner->bgv.context.rlweContext.cipherRnsBase.data[0];
    uint64_t t = inner->bgv.context.bgvParameter->plainMod;
    ASSERT_TRUE(q > 1u && t > 1u);

    uint32_t ptLen = 0u, ctLen = 0u, msgLen = 0u;
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN,  &ptLen,  sizeof(ptLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen,  sizeof(ctLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN,        &msgLen, sizeof(msgLen));
    m = (uint64_t *)BSL_SAL_Malloc(msgLen);
    mo = (uint64_t *)BSL_SAL_Malloc(msgLen);
    pt = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ct = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ctMul = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ASSERT_TRUE(m && mo && pt && ct && ctMul && ptOut);
    for (uint32_t i = 0; i < HIFHE_N; ++i) m[i] = (i == 0u) ? 5u : 0u;

    BSL_Param encM[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m, msgLen, 0}, BSL_PARAM_END };
    uint32_t out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encM, pt, &out), HIFHE_SUCCESS);
    uint32_t ptL = out;
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct, &out), HIFHE_SUCCESS);
    uint32_t ctL = out;

    /* q is a multiple of the ciphertext modulus, so unreduced it wipes the
     * ciphertext; in Z_t it is q mod t. */
    uint64_t scalar = q;
    BSL_Param mulIn[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct, ctL, 0},
        {HIFHE_PARAM_BGV_CONSTANT,    BSL_PARAM_TYPE_OCTETS, &scalar, (uint32_t)sizeof(scalar), 0},
        BSL_PARAM_END
    };
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMul(ctx, mulIn, ctMul, &out), HIFHE_SUCCESS);
    uint32_t ctMulL = out;
    out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ctMul, ctMulL, ptOut, &out), HIFHE_SUCCESS);
    uint32_t ptOutL = out;
    BSL_Param decIn[] = { {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, ptOut, ptOutL, 0}, BSL_PARAM_END };
    out = msgLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(ctx, decIn, (uint8_t *)mo, &out), HIFHE_SUCCESS);
    ASSERT_EQ(mo[0], (5u * (q % t)) % t);
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(mo); BSL_SAL_Free(pt);
    BSL_SAL_Free(ct); BSL_SAL_Free(ctMul); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SEEDED_LIMB_INDEP_TC001
* @title  Seeded uniform sampling draws an independent stream per RNS limb.
* @brief  Every limb used to be sampled from the same (seed, label) with the
*         refill counter restarting, so limbs of equal width received the same
*         candidates and their residues coincided far more often than chance.
*         Independent limbs collide with probability about N / q.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SEEDED_LIMB_INDEP_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;

    TestMemInit();
    TestRandInit();
    ctx = BgvNewCtx(HIFHE_BGV_4096_44x2_17BIT);
    ASSERT_TRUE(ctx != NULL);
    uint8_t seed[HIFHE_BGV_SEED_LEN];
    for (uint32_t i = 0; i < HIFHE_BGV_SEED_LEN; ++i) seed[i] = (uint8_t)(0x2bu + i);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_SET_SEED, seed, HIFHE_BGV_SEED_LEN),
              HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    CRYPT_BGV_Ctx *inner = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_INNER_CTX, &inner, sizeof(inner)),
              HIFHE_SUCCESS);
    ASSERT_TRUE(inner != NULL && inner->bgv.havePk != 0u);

    const Ciphertext *pk = &inner->bgv.pk;
    uint32_t n   = BGV_BGVContext_GetPolyDegree(&inner->bgv.context);
    uint32_t rns = pk->config.crtConfig.rnsbase.size;
    ASSERT_EQ(rns, 2u);
    /* c1 is the uniform polynomial itself, laid out [component][limb][coeff]. */
    const uint64_t *a0 = pk->data + (1u * rns + 0u) * n;
    const uint64_t *a1 = pk->data + (1u * rns + 1u) * n;
    uint32_t same = 0u;
    for (uint32_t j = 0; j < n; ++j) {
        if (a0[j] == a1[j]) same++;
    }
    ASSERT_TRUE(same <= 4u);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_FIXED_WEIGHT_ODD_TC001
* @title  A fixed-weight ternary draw with odd weight has exactly that weight.
* @brief  Filling two equal halves with +1 and -1 yields weight - 1 nonzeros
*         when the weight is odd.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_FIXED_WEIGHT_ODD_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    int64_t *v = NULL;

    TestMemInit();
    TestRandInit();
    v = (int64_t *)BSL_SAL_Malloc(64u * (uint32_t)sizeof(int64_t));
    ASSERT_TRUE(v != NULL);

    BgvEntropy src = BgvEntropy_Drbg();
    for (uint32_t w = 1u; w <= 9u; w += 2u) {
        ASSERT_EQ(Kernel_Sampler_TernaryFixedWeight(v, 64u, w, &src), HIFHE_SUCCESS);
        uint32_t nz = 0u;
        for (uint32_t i = 0; i < 64u; ++i) {
            if (v[i] != 0) nz++;
        }
        ASSERT_EQ(nz, w);
    }
    /* Even weights, which is what the callers use, keep working. */
    ASSERT_EQ(Kernel_Sampler_TernaryFixedWeight(v, 64u, 8u, &src), HIFHE_SUCCESS);
    uint32_t nzEven = 0u;
    for (uint32_t i = 0; i < 64u; ++i) {
        if (v[i] != 0) nzEven++;
    }
    ASSERT_EQ(nzEven, 8u);
EXIT:
    BSL_SAL_Free(v);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SMALL_CIPHER_MOD_TC001
* @title  A ciphertext modulus the validator admits also decodes.
* @brief  Parameter validation accepts moduli from 20 bits, but the decoder
*         held floor(2^96 / q) in a word and refused anything under 33 bits,
*         so an accepted parameter set failed at decode time.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SMALL_CIPHER_MOD_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t *m = NULL, *mo = NULL;
    uint8_t *pt = NULL, *ct = NULL, *ptOut = NULL;

    TestMemInit();
    TestRandInit();
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, HIFHE_PKEY_BGV,
                                       CRYPT_EAL_PKEY_CIPHER_OPERATE, HIFHE_PROVIDER_ATTR);
    ASSERT_TRUE(ctx != NULL);

    uint32_t degree = 2048u;
    uint32_t plainBit = 17u;
    uint32_t bits[1] = { 30u };          /* under the old 33-bit decoder floor */
    BSL_Param params[] = {
        {HIFHE_PARAM_BGV_POLY_DEGREE,     BSL_PARAM_TYPE_UINT32, &degree,   sizeof(degree), 0},
        {HIFHE_PARAM_BGV_PLAIN_MOD_BIT,   BSL_PARAM_TYPE_UINT32, &plainBit, sizeof(plainBit), 0},
        {HIFHE_PARAM_BGV_CIPHER_MOD_BITS, BSL_PARAM_TYPE_OCTETS, bits,      sizeof(bits), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeySetParaEx(ctx, params), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

    uint32_t ptLen = 0u, ctLen = 0u, msgLen = 0u;
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN,  &ptLen,  sizeof(ptLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen,  sizeof(ctLen));
    CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_MSG_LEN,        &msgLen, sizeof(msgLen));
    m = (uint64_t *)BSL_SAL_Malloc(msgLen);
    mo = (uint64_t *)BSL_SAL_Malloc(msgLen);
    pt = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ct = (uint8_t *)BSL_SAL_Malloc(ctLen);
    ptOut = (uint8_t *)BSL_SAL_Malloc(ptLen);
    ASSERT_TRUE(m && mo && pt && ct && ptOut);
    for (uint32_t i = 0; i < HIFHE_N; ++i) m[i] = (uint64_t)(i % 23u);

    BSL_Param encM[] = { {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, m, msgLen, 0}, BSL_PARAM_END };
    uint32_t out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encM, pt, &out), HIFHE_SUCCESS);
    uint32_t ptL = out;
    out = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptL, ct, &out), HIFHE_SUCCESS);
    uint32_t ctL = out;
    out = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ct, ctL, ptOut, &out), HIFHE_SUCCESS);
    uint32_t ptOutL = out;
    BSL_Param decIn[] = { {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, ptOut, ptOutL, 0}, BSL_PARAM_END };
    out = msgLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(ctx, decIn, (uint8_t *)mo, &out), HIFHE_SUCCESS);
    for (uint32_t i = 0; i < 32u; ++i) ASSERT_EQ(mo[i], m[i]);
EXIT:
    BSL_SAL_Free(m); BSL_SAL_Free(mo); BSL_SAL_Free(pt);
    BSL_SAL_Free(ct); BSL_SAL_Free(ptOut);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */
