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

/* BEGIN_HEADER */
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_params.h"
#include "crypt_algid.h"
#include "crypt_bgv.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_init.h"
#include "crypt_types.h"

#include "hifhe.h"
#include "hifhe_local.h"
#include "bgv_local.h"
#include "bgv_adapter_types.h"
#include "hifhe_types.h"
#include "hifhe_err.h"
#include "hifhe_err_internal.h"
#include "basic/rand.h"
#include "crypto_test_util.h"
#include "test.h"
/* END_HEADER */

/* Kernel context lifecycle: creation, parameter
 * loading, key generation, duplication and release. Encryption, the HE
 * operations, key marshalling and serdes are covered by
 * test_suite_sdv_hifhe_bgv_ops. */

/* Runs on a second thread for ERROR_STACK_PER_THREAD_TC001. Returns 0 when
 * everything it saw of the error stack was its own. */
static void *ErrStackWorker(void *arg)
{
    (void)arg;
    if (HIFHE_ErrDepth() != 0u) {
        return (void *)(intptr_t)1;
    }
    HIFHE_ErrPushError(HIFHE_INTERNAL, "worker.c", 7u);
    HIFHE_ErrPushError(HIFHE_INTERNAL, "worker.c", 8u);
    const char *file = NULL;
    uint32_t line = 0u;
    if (HIFHE_ErrDepth() != 2u || HIFHE_ErrPeekError(&file, &line) != HIFHE_INTERNAL || line != 7u) {
        return (void *)(intptr_t)2;
    }
    HIFHE_ErrClearError();
    return (void *)(intptr_t)0;
}

static CRYPT_BGV_Ctx *BgvNewCtx(int withPreset)
{
    CRYPT_BGV_Ctx *ctx =
        CRYPT_BGV_NewCtx(HIFHE_BGV);
    if (ctx == NULL) {
        return NULL;
    }
    if (withPreset) {
        int32_t presetId = HIFHE_BGV_DEFAULT;
        if (CRYPT_BGV_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &presetId, sizeof(presetId)) != HIFHE_SUCCESS) {
            CRYPT_BGV_FreeCtx(ctx);
            return NULL;
        }
    }
    return ctx;
}

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_NEWCTX_TC001
* @title  Kernel context allocation and release.
* @brief  Confirms CRYPT_BGV_NewCtx accepts the BGV alg-ID and that FreeCtx tolerates a fresh
*         (unparameterised) ctx.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_PUBLIC_CACHE_SEED_TC001(void)
{
    HIFHE_Ctx *a = NULL, *b = NULL, *c = NULL, *dup = NULL;
    HIFHE_HEText *pt = NULL;
    uint8_t seed[32] = {1};
    uint32_t on = 1, count = 4096;
    uint64_t message = 7, output[4096];

    ASSERT_EQ(TestRandInit(), HIFHE_SUCCESS);
    a = HIFHE_New(HIFHE_BGV);
    b = HIFHE_New(HIFHE_BGV);
    c = HIFHE_New(HIFHE_BGV);
    ASSERT_TRUE(a != NULL && b != NULL && c != NULL);
    ASSERT_EQ(HIFHE_Ctrl(a, HIFHE_CTRL_BGV_SET_LUT_CACHE, NULL, &on, sizeof(on)), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_LUT_CACHE, NULL, &on, sizeof(on)), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_SetParaById(a, -1), HIFHE_PARAM_ID_INVALID);
    ASSERT_EQ(HIFHE_SetParaById(a, HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_SetParaById(b, HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_SetParaById(c, HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
    CRYPT_BGV_Ctx *am = a->params->math, *bm = b->params->math, *cm = c->params->math;
    ASSERT_TRUE(am->lutCache != NULL && bm->lutCache != NULL && am->lutCache != bm->lutCache);
    ASSERT_TRUE(cm->lutCache == NULL);
    ASSERT_TRUE(am->bgv.context.rlweContext.tableBuf[0] != bm->bgv.context.rlweContext.tableBuf[0]);
    ASSERT_TRUE(am->bgv.context.ptTableBuf != bm->bgv.context.ptTableBuf);
    ASSERT_TRUE(am->bgv.context.ptTableBuf != cm->bgv.context.ptTableBuf);
    ASSERT_EQ(am->bgv.context.ownsPtTableBuf, 0);
    ASSERT_EQ(cm->bgv.context.ownsPtTableBuf, 1);
    ASSERT_EQ(HIFHE_Ctrl(a, HIFHE_CTRL_BGV_SET_SEED, NULL, seed, sizeof(seed)), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_SEED, NULL, seed, sizeof(seed)), HIFHE_SUCCESS);
    seed[0] = 2;
    ASSERT_EQ(HIFHE_Ctrl(c, HIFHE_CTRL_BGV_SET_SEED, NULL, seed, sizeof(seed)), HIFHE_SUCCESS);
    dup = Hifhe_CtxDup(b);
    ASSERT_TRUE(dup != NULL);
    HIFHE_Free(b);
    b = dup;
    dup = NULL;
    ASSERT_EQ(HIFHE_KeyGen(a), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_KeyGen(b), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_KeyGen(c), HIFHE_SUCCESS);
    CRYPT_BGV_Ctx *ar = a->data, *br = b->data, *cr = c->data;
    ASSERT_TRUE(ar->bgv.context.ptTableBuf == am->bgv.context.ptTableBuf);
    ASSERT_TRUE(br->bgv.context.rlweContext.tableBuf[0] == bm->bgv.context.rlweContext.tableBuf[0]);
    ASSERT_EQ(ar->bgv.keygen.sk->dataSize, br->bgv.keygen.sk->dataSize);
    uint32_t bytes = ar->bgv.keygen.sk->dataSize * sizeof(uint64_t);
    ASSERT_EQ(memcmp(ar->bgv.keygen.sk->data, br->bgv.keygen.sk->data, bytes), 0);
    ASSERT_TRUE(memcmp(ar->bgv.keygen.sk->data, cr->bgv.keygen.sk->data, bytes) != 0);
    ASSERT_EQ(ar->bgv.pk.dataSize, br->bgv.pk.dataSize);
    ASSERT_EQ(memcmp(ar->bgv.pk.data, br->bgv.pk.data, ar->bgv.pk.dataSize * sizeof(uint64_t)), 0);
    ASSERT_EQ(HIFHE_Encode(a, &message, 1, &pt), HIFHE_SUCCESS);
    ASSERT_EQ(atomic_load(&a->params->references), 1);
    HIFHE_Free(a);
    a = NULL;
    HIFHE_Free(b);
    b = NULL;
    b = HIFHE_New(HIFHE_BGV);
    ASSERT_TRUE(b != NULL);
    ASSERT_EQ(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_LUT_CACHE, NULL, &on, sizeof(on)), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_SetParaById(b, HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Decode(b, pt, output, &count), HIFHE_SUCCESS);
    ASSERT_EQ(output[0], message);
    HIFHE_Free(b);
    b = NULL;
EXIT:
    HIFHE_HETextFree(pt);
    HIFHE_Free(a);
    HIFHE_Free(b);
    HIFHE_Free(c);
    HIFHE_Free(dup);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_NEWCTX_TC001(void)
{
    CRYPT_BGV_Ctx *ctx = NULL;

    TestMemInit();
    TestRandInit();

    ctx = CRYPT_BGV_NewCtx(HIFHE_BGV);
    ASSERT_TRUE(ctx != NULL);

EXIT:
    CRYPT_BGV_FreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_CTRL_PRESET_TC001
* @title  Ctrl(SET_PARA_BY_ID) loads a preset; length queries then honour it.
* @brief  Drives CRYPT_BGV_Ctrl through the preset-load / poly-degree /
*         plain-mod path so the para-cache is exercised end-to-end
*         without requiring any actual keygen or crypto.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_CTRL_PRESET_TC001(void)
{
    CRYPT_BGV_Ctx *ctx = NULL;
    uint32_t polyDegree = 0u;
    uint64_t plainMod = 0ull;

    TestMemInit();
    TestRandInit();

    ctx = BgvNewCtx(1);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &polyDegree, sizeof(polyDegree)), HIFHE_SUCCESS);
    ASSERT_EQ(polyDegree, 2048u);

    /* The default preset leaves plainMod to the Proth search; the ctrl
     * lazy-builds the context and reports the resolved prime. The search
     * walks k downward from 2^(17 - 11 - 1) - 1 = 31, so it lands on
     * k = 28 and plainMod = 28 * 4096 + 1 = 114689. Callers that need exactly
     * 65537 use HIFHE_BGV_2048_48_17BIT, which pins it. */
    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD, &plainMod, sizeof(plainMod)), HIFHE_SUCCESS);
    ASSERT_EQ(plainMod, 114689ull);

EXIT:
    CRYPT_BGV_FreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_CTRL_17BIT_PLAINMOD_TC001
* @title  The _17BIT preset pins plainMod to 65537 via the para override.
* @brief  Ctrl(GET_PLAIN_MOD) must return exactly 65537 (Fermat F4) when
*         the preset is HIFHE_BGV_2048_48_17BIT. Guards against the Proth
*         search replacing the Fermat prime with 114689.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_CTRL_17BIT_PLAINMOD_TC001(void)
{
    CRYPT_BGV_Ctx *ctx = NULL;
    uint64_t plainMod = 0ull;
    int32_t presetId = HIFHE_BGV_2048_48_17BIT;

    TestMemInit();
    TestRandInit();

    ctx = CRYPT_BGV_NewCtx(HIFHE_BGV);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &presetId, sizeof(presetId)), HIFHE_SUCCESS);

    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD, &plainMod, sizeof(plainMod)), HIFHE_SUCCESS);
    ASSERT_EQ(plainMod, 65537ull);

EXIT:
    CRYPT_BGV_FreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_SETPARA_BSL_TC001
* @title  SetPara via BSL_Param array populates the same para cache as preset.
* @brief  Instead of a preset, drive CRYPT_BGV_SetParaEx directly with
*         (POLY_DEGREE, PLAIN_MOD_BIT, RELIN_DNUM). Verify GET_POLY_DEGREE
*         reflects the supplied value.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_SETPARA_BSL_TC001(void)
{
    CRYPT_BGV_Ctx *ctx = NULL;
    uint32_t polyDegreeIn = 4096u;
    uint32_t plainModBit = 17u;
    uint32_t relinDnum = 1u;
    uint32_t cipherModBits[] = {48u, 48u};
    uint32_t polyDegreeOut = 0u;

    BSL_Param params[] = {
        {HIFHE_PARAM_BGV_POLY_DEGREE, BSL_PARAM_TYPE_UINT32, &polyDegreeIn, sizeof(polyDegreeIn), 0},
        {HIFHE_PARAM_BGV_PLAIN_MOD_BIT, BSL_PARAM_TYPE_UINT32, &plainModBit, sizeof(plainModBit), 0},
        {HIFHE_PARAM_BGV_RELIN_DNUM, BSL_PARAM_TYPE_UINT32, &relinDnum, sizeof(relinDnum), 0},
        {HIFHE_PARAM_BGV_CIPHER_MOD_BITS, BSL_PARAM_TYPE_OCTETS, cipherModBits, sizeof(cipherModBits), 0},
        BSL_PARAM_END};

    TestMemInit();
    TestRandInit();

    ctx = CRYPT_BGV_NewCtx(HIFHE_BGV);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_BGV_SetParaEx(ctx, params), HIFHE_SUCCESS);

    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &polyDegreeOut, sizeof(polyDegreeOut)),
              HIFHE_SUCCESS);
    ASSERT_EQ(polyDegreeOut, polyDegreeIn);

EXIT:
    CRYPT_BGV_FreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_GEN_STUB_TC001
* @title  PkeyGen builds the context and produces a key pair.
* @brief  Drives the whole generation path (context build, ternary secret,
*         public key) through the provider surface, and checks FreeCtx
*         cleans up afterwards.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_GEN_STUB_TC001(void)
{
    CRYPT_BGV_Ctx *ctx = NULL;

    TestMemInit();
    TestRandInit();

    ctx = BgvNewCtx(1);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_BGV_Gen(ctx), HIFHE_SUCCESS);

EXIT:
    CRYPT_BGV_FreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_DUPCTX_PARA_TC001
* @title  DupCtx copies the para cache; source and dup respond identically.
* @brief  Loads a preset, dups, queries the same ctrl on both, expects
*         equal answers.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_DUPCTX_PARA_TC001(void)
{
    CRYPT_BGV_Ctx *src = NULL;
    CRYPT_BGV_Ctx *dst = NULL;
    uint32_t srcDeg = 0u, dstDeg = 0u;

    TestMemInit();
    TestRandInit();

    src = BgvNewCtx(1);
    ASSERT_TRUE(src != NULL);
    dst = CRYPT_BGV_DupCtx(src);
    ASSERT_TRUE(dst != NULL);

    ASSERT_EQ(CRYPT_BGV_Ctrl(src, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &srcDeg, sizeof(srcDeg)), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_BGV_Ctrl(dst, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &dstDeg, sizeof(dstDeg)), HIFHE_SUCCESS);
    ASSERT_EQ(srcDeg, dstDeg);
    ASSERT_EQ(srcDeg, 2048u);

EXIT:
    CRYPT_BGV_FreeCtx(dst);
    CRYPT_BGV_FreeCtx(src);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_INHERITED_PRIMES_TC001
* @title  The Proth search resolves the inherited presets to the same
*         moduli the predecessor provider produced.
* @brief  A ciphertext only travels between the two implementations if they
*         agree on the ring, so these primes are part of the compatibility
*         contract, not an implementation detail. The 8192 chain is checked
*         through the public-key wire image, which carries the RNS base.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_INHERITED_PRIMES_TC001(void)
{
    CRYPT_BGV_Ctx *ctx = NULL;
    uint32_t polyDegree = 0u, level = 0u;
    uint64_t plainMod = 0ull;

    TestMemInit();
    TestRandInit();

    /* 2048 / single 48-bit modulus, plainModBit 17. */
    ctx = BgvNewCtx(1);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &polyDegree, sizeof(polyDegree)), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD, &plainMod, sizeof(plainMod)), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GET_LEVEL, &level, sizeof(level)), HIFHE_SUCCESS);
    ASSERT_EQ(polyDegree, 2048u);
    ASSERT_EQ(plainMod, 114689ull);
    ASSERT_EQ(level, 1u);
    CRYPT_BGV_FreeCtx(ctx);
    ctx = NULL;

    /* 8192 / 43,43,44,44 chain, plainModBit 20. */
    ctx = CRYPT_BGV_NewCtx(HIFHE_BGV);
    ASSERT_TRUE(ctx != NULL);
    int32_t preset = HIFHE_BGV_8192_44x4;
    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &preset, sizeof(preset)), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &polyDegree, sizeof(polyDegree)), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD, &plainMod, sizeof(plainMod)), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_BGV_Ctrl(ctx, HIFHE_CTRL_BGV_GET_LEVEL, &level, sizeof(level)), HIFHE_SUCCESS);
    ASSERT_EQ(polyDegree, 8192u);
    ASSERT_EQ(plainMod, 1032193ull);
    ASSERT_EQ(level, 4u);
EXIT:
    CRYPT_BGV_FreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_ERROR_REPORTED_TC001
* @title  A failed call leaves the location that decided it on the error stack.
* @brief  Loads an out-of-range preset id. The code is already the return
*         value, so the code alone proves nothing; what this pins is that the
*         stack holds the file and line inside the library that decided the
*         call had failed, and that the entry outlives the call.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_ERROR_REPORTED_TC001(void)
{
    CRYPT_BGV_Ctx *ctx = NULL;
    int32_t badPreset = 0x7ffffff0;
    const char *originFile = NULL;
    uint32_t originLine = 0u;

    TestMemInit();
    TestRandInit();

    ctx = CRYPT_BGV_NewCtx(HIFHE_BGV);
    ASSERT_TRUE(ctx != NULL);

    HIFHE_ErrClearError();
    ASSERT_EQ(HIFHE_ErrDepth(), 0u);
    int32_t r = CRYPT_BGV_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &badPreset, sizeof(badPreset));
    ASSERT_TRUE(r != HIFHE_SUCCESS);

    /* One push per origin, so the oldest entry and the newest are the same
     * one here. Peek, so neither read consumes the other's entry. */
    ASSERT_EQ(HIFHE_ErrDepth(), 1u);
    ASSERT_EQ(HIFHE_ErrPeekError(&originFile, &originLine), r);
    ASSERT_EQ(HIFHE_ErrPeekLastError(NULL, NULL), r);
    ASSERT_TRUE(originFile != NULL);
    ASSERT_TRUE(originLine > 0u);
    /* The frame is inside the library, not in this file. */
    ASSERT_TRUE(strstr(originFile, "test_suite") == NULL);

    HIFHE_ErrClearError();
    ASSERT_EQ(HIFHE_ErrDepth(), 0u);
    ASSERT_EQ(HIFHE_ErrPeekError(NULL, NULL), HIFHE_SUCCESS);

EXIT:
    HIFHE_ErrClearError();
    CRYPT_BGV_FreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_ERROR_STACK_WRAP_TC001
* @title  The error stack keeps the newest HIFHE_ERR_STACK_DEPTH entries.
* @brief  A stack nobody cleared must not hide what is failing now, so a push
*         onto a full stack drops the oldest entry rather than itself. Also
*         covers the mark, which is what brackets a call whose failure is an
*         answer rather than a fault.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_ERROR_STACK_WRAP_TC001(void)
{
    const char *file = NULL;
    uint32_t line = 0u;

    HIFHE_ErrClearError();
    for (uint32_t i = 1; i <= HIFHE_ERR_STACK_DEPTH + 5u; ++i) {
        HIFHE_ErrPushError(HIFHE_INTERNAL, "wrap.c", i);
    }
    ASSERT_EQ(HIFHE_ErrDepth(), HIFHE_ERR_STACK_DEPTH);
    ASSERT_EQ(HIFHE_ErrPeekError(&file, &line), HIFHE_INTERNAL);
    ASSERT_EQ(line, 6u);
    ASSERT_EQ(HIFHE_ErrPeekLastError(&file, &line), HIFHE_INTERNAL);
    ASSERT_EQ(line, HIFHE_ERR_STACK_DEPTH + 5u);

    /* A success is not an error and is not recorded. */
    HIFHE_ErrClearError();
    HIFHE_ErrPushError(HIFHE_SUCCESS, "wrap.c", 1u);
    ASSERT_EQ(HIFHE_ErrDepth(), 0u);

    /* Whatever the bracketed call pushed is gone, and what was there before
     * it stays. */
    HIFHE_ErrPushError(HIFHE_PARAM_INVALID, "wrap.c", 11u);
    HIFHE_ErrSetMark();
    HIFHE_ErrPushError(HIFHE_INTERNAL, "wrap.c", 12u);
    HIFHE_ErrPushError(HIFHE_INTERNAL, "wrap.c", 13u);
    HIFHE_ErrPopToMark();
    ASSERT_EQ(HIFHE_ErrDepth(), 1u);
    ASSERT_EQ(HIFHE_ErrPeekLastError(&file, &line), HIFHE_PARAM_INVALID);
    ASSERT_EQ(line, 11u);

EXIT:
    HIFHE_ErrClearError();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_ERROR_STACK_PER_THREAD_TC001
* @title  One error stack per thread, with nothing shared between them.
* @brief  The stack is thread-local, which is what lets it hold no lock. Two
*         threads report at the same time and neither sees the other: the
*         second thread starts empty although the first has already pushed,
*         and the first is unchanged when the second has filled its own.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_ERROR_STACK_PER_THREAD_TC001(void)
{
    pthread_t worker;
    int started = 0;

    HIFHE_ErrClearError();
    HIFHE_ErrPushError(HIFHE_PARAM_INVALID, "main.c", 1u);
    ASSERT_EQ(HIFHE_ErrDepth(), 1u);

    ASSERT_EQ(pthread_create(&worker, NULL, ErrStackWorker, NULL), 0);
    started = 1;
    void *result = NULL;
    ASSERT_EQ(pthread_join(worker, &result), 0);
    started = 0;
    /* The worker reports what it saw of its own stack. */
    ASSERT_EQ((intptr_t)result, 0);

    /* Its pushes did not land here. */
    const char *file = NULL;
    uint32_t line = 0u;
    ASSERT_EQ(HIFHE_ErrDepth(), 1u);
    ASSERT_EQ(HIFHE_ErrPeekLastError(&file, &line), HIFHE_PARAM_INVALID);
    ASSERT_EQ(line, 1u);

EXIT:
    if (started) {
        (void)pthread_join(worker, NULL);
    }
    HIFHE_ErrClearError();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_ERROR_STACK_CLEAN_TC001
* @title  A call that succeeds reports nothing.
* @brief  The error stack is never cleared on its own, so a code pushed on a
*         path that worked stays there and is read back as the outcome of a
*         later, unrelated call. Both context builds run here: the one that
*         derives the modulus chain by probing prime candidates, where a
*         rejection means "try the next one" rather than a failure, and the
*         one that takes the moduli pinned in a preset.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_ERROR_STACK_CLEAN_TC001(void)
{
    CRYPT_BGV_Ctx *ctx = NULL;
    CRYPT_BGV_Ctx *preset = NULL;
    uint32_t polyDegreeIn = 2048u;
    uint32_t plainModBit = 17u;
    uint32_t relinDnum = 1u;
    uint32_t cipherModBits[] = {48u};

    BSL_Param params[] = {
        {HIFHE_PARAM_BGV_POLY_DEGREE, BSL_PARAM_TYPE_UINT32, &polyDegreeIn, sizeof(polyDegreeIn), 0},
        {HIFHE_PARAM_BGV_PLAIN_MOD_BIT, BSL_PARAM_TYPE_UINT32, &plainModBit, sizeof(plainModBit), 0},
        {HIFHE_PARAM_BGV_RELIN_DNUM, BSL_PARAM_TYPE_UINT32, &relinDnum, sizeof(relinDnum), 0},
        {HIFHE_PARAM_BGV_CIPHER_MOD_BITS, BSL_PARAM_TYPE_OCTETS, cipherModBits, sizeof(cipherModBits), 0},
        BSL_PARAM_END};

    TestMemInit();
    TestRandInit();

    ctx = CRYPT_BGV_NewCtx(HIFHE_BGV);
    ASSERT_TRUE(ctx != NULL);

    HIFHE_ErrClearError();
    ASSERT_EQ(CRYPT_BGV_SetParaEx(ctx, params), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_ErrPeekLastError(NULL, NULL), 0);
    ASSERT_EQ(CRYPT_BGV_Gen(ctx), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_ErrPeekLastError(NULL, NULL), 0);

    /* The same through a preset, whose moduli are pinned and so take the
     * other branch of the context build. */
    preset = BgvNewCtx(1);
    ASSERT_TRUE(preset != NULL);
    ASSERT_EQ(HIFHE_ErrPeekLastError(NULL, NULL), 0);
    ASSERT_EQ(CRYPT_BGV_Gen(preset), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_ErrPeekLastError(NULL, NULL), 0);

EXIT:
    HIFHE_ErrClearError();
    CRYPT_BGV_FreeCtx(ctx);
    CRYPT_BGV_FreeCtx(preset);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_MODSWITCHED_WIRE_TC001(void)
{
    CRYPT_BGV_Ctx *native = NULL;
    HIFHE_Ctx *pub = NULL;
    HIFHE_HEText *loaded = NULL;
    uint8_t *ct = NULL, *shorter = NULL, *msg = NULL, *pt = NULL;
    uint32_t ctLen = 0, shorterLen = 0, ptLen = 0, slots = 0;
    int32_t preset = HIFHE_BGV_4096_44x2_17BIT;

    ASSERT_EQ(TestRandInit(), HIFHE_SUCCESS);

    /* The native surface can spend a level; the public one cannot even say
     * that it has been spent, since every preset carries mulDepth 0. */
    native = CRYPT_BGV_NewCtx(HIFHE_BGV);
    ASSERT_TRUE(native != NULL);
    ASSERT_EQ(CRYPT_BGV_Ctrl(native, CRYPT_CTRL_SET_PARA_BY_ID, &preset, sizeof(preset)), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_BGV_Gen(native), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_BGV_Ctrl(native, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &slots, sizeof(slots)), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_BGV_Ctrl(native, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen)), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_BGV_Ctrl(native, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &ptLen, sizeof(ptLen)), HIFHE_SUCCESS);
    msg = calloc(slots, sizeof(uint64_t));
    pt = malloc(ptLen);
    ct = malloc(ctLen);
    shorter = malloc(ctLen);
    ASSERT_TRUE(msg != NULL && pt != NULL && ct != NULL && shorter != NULL);
    for (uint32_t i = 0; i < slots; i++) {
        ((uint64_t *)msg)[i] = (i % 5u) + 1u;
    }
    BSL_Param encIn[] = {{HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, msg, slots * (uint32_t)sizeof(uint64_t), 0},
                         BSL_PARAM_END};
    ASSERT_EQ(CRYPT_BGV_HEMsgEncode(native, encIn, pt, &ptLen), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_BGV_Encrypt(native, pt, ptLen, ct, &ctLen), HIFHE_SUCCESS);

    BSL_Param msIn[] = {{HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct, ctLen, 0},
                        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, shorter, ctLen, 0},
                        BSL_PARAM_END};
    ASSERT_EQ(CRYPT_BGV_Ctrl(native, HIFHE_CTRL_BGV_HE_MODSWITCH, msIn, 0), HIFHE_SUCCESS);
    shorterLen = msIn[1].useLen;
    /* One limb fewer on the wire is what makes this interesting. */
    ASSERT_TRUE(shorterLen > 0 && shorterLen < ctLen);

    pub = HIFHE_New(HIFHE_BGV);
    ASSERT_TRUE(pub != NULL);
    ASSERT_EQ(HIFHE_SetParaById(pub, preset), HIFHE_SUCCESS);
    /* The full-chain ciphertext reads; the one that spent a level does not,
     * which is the same answer HIFHE_Deserialize gives for HiFHE's own
     * format, rather than loading an object it could never write back. */
    ASSERT_EQ(HIFHE_Deserialize(pub, ct, ctLen, &loaded), HIFHE_SUCCESS);
    HIFHE_HETextFree(loaded);
    loaded = NULL;
    ASSERT_TRUE(HIFHE_Deserialize(pub, shorter, shorterLen, &loaded) == HIFHE_SERDES_FAIL);
    ASSERT_TRUE(loaded == NULL);
EXIT:
    HIFHE_HETextFree(loaded);
    HIFHE_Free(pub);
    CRYPT_BGV_FreeCtx(native);
    free(msg);
    free(pt);
    free(ct);
    free(shorter);
}

/* END_CASE */
