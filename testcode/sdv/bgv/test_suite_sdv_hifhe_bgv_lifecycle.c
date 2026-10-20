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
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_params.h"
#include "crypt_algid.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_init.h"
#include "crypt_types.h"

#include "hifhe_provider.h"
#include "hifhe_types.h"
#include "hifhe_err.h"
#include "crypto_test_util.h"
#include "test.h"
/* END_HEADER */

/* Context lifecycle through the provider surface: creation, parameter
 * loading, key generation, duplication and release. Encryption, the HE
 * operations, key marshalling and serdes are covered by
 * test_suite_sdv_hifhe_bgv_ops. */

static CRYPT_EAL_PkeyCtx *BgvNewCtx(int withPreset)
{
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(
        NULL, HIFHE_PKEY_BGV, CRYPT_EAL_PKEY_CIPHER_OPERATE, HIFHE_PROVIDER_ATTR);
    if (ctx == NULL) {
        return NULL;
    }
    if (withPreset) {
        int32_t presetId = HIFHE_BGV_DEFAULT;
        if (CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID,
                               &presetId, sizeof(presetId)) != HIFHE_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(ctx);
            return NULL;
        }
    }
    return ctx;
}

/* @
* @test  SDV_CRYPTO_HIFHE_BGV_NEWCTX_TC001
* @title  Provider-mediated CRYPT_BGV_NewCtx + CRYPT_BGV_FreeCtx round trip.
* @brief  Confirms the BGV alg-ID is discoverable through
*         CRYPT_EAL_ProviderPkeyNewCtx and that FreeCtx tolerates a fresh
*         (unparameterised) ctx.
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_NEWCTX_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;

    TestMemInit();
    TestRandInit();

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(
        NULL, HIFHE_PKEY_BGV, CRYPT_EAL_PKEY_CIPHER_OPERATE, HIFHE_PROVIDER_ATTR);
    ASSERT_TRUE(ctx != NULL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
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
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint32_t polyDegree = 0u;
    uint64_t plainMod = 0ull;

    TestMemInit();
    TestRandInit();

    ctx = BgvNewCtx(1);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE,
                                 &polyDegree, sizeof(polyDegree)),
              HIFHE_SUCCESS);
    ASSERT_EQ(polyDegree, 2048u);

    /* The default preset leaves plainMod to the Proth search; the ctrl
     * lazy-builds the context and reports the resolved prime. The search
     * walks k downward from 2^(17 - 11 - 1) - 1 = 31, so it lands on
     * k = 28 and plainMod = 28 * 4096 + 1 = 114689. Callers that need exactly
     * 65537 use HIFHE_BGV_2048_48_17BIT, which pins it. */
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD,
                                 &plainMod, sizeof(plainMod)),
              HIFHE_SUCCESS);
    ASSERT_EQ(plainMod, 114689ull);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
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
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint64_t plainMod = 0ull;
    int32_t presetId = HIFHE_BGV_2048_48_17BIT;

    TestMemInit();
    TestRandInit();

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(
        NULL, HIFHE_PKEY_BGV, CRYPT_EAL_PKEY_CIPHER_OPERATE, HIFHE_PROVIDER_ATTR);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID,
                                 &presetId, sizeof(presetId)),
              HIFHE_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD,
                                 &plainMod, sizeof(plainMod)),
              HIFHE_SUCCESS);
    ASSERT_EQ(plainMod, 65537ull);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
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
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint32_t polyDegreeIn = 4096u;
    uint32_t plainModBit  = 17u;
    uint32_t relinDnum    = 1u;
    uint32_t cipherModBits[] = { 48u, 48u };
    uint32_t polyDegreeOut = 0u;

    BSL_Param params[] = {
        {HIFHE_PARAM_BGV_POLY_DEGREE,     BSL_PARAM_TYPE_UINT32,
         &polyDegreeIn, sizeof(polyDegreeIn), 0},
        {HIFHE_PARAM_BGV_PLAIN_MOD_BIT,   BSL_PARAM_TYPE_UINT32,
         &plainModBit,  sizeof(plainModBit),  0},
        {HIFHE_PARAM_BGV_RELIN_DNUM,      BSL_PARAM_TYPE_UINT32,
         &relinDnum,    sizeof(relinDnum),    0},
        {HIFHE_PARAM_BGV_CIPHER_MOD_BITS, BSL_PARAM_TYPE_OCTETS,
         cipherModBits, sizeof(cipherModBits), 0},
        BSL_PARAM_END
    };

    TestMemInit();
    TestRandInit();

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(
        NULL, HIFHE_PKEY_BGV, CRYPT_EAL_PKEY_CIPHER_OPERATE, HIFHE_PROVIDER_ATTR);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaEx(ctx, params), HIFHE_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE,
                                 &polyDegreeOut, sizeof(polyDegreeOut)),
              HIFHE_SUCCESS);
    ASSERT_EQ(polyDegreeOut, polyDegreeIn);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
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
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;

    TestMemInit();
    TestRandInit();

    ctx = BgvNewCtx(1);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
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
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *src = NULL;
    CRYPT_EAL_PkeyCtx *dst = NULL;
    uint32_t srcDeg = 0u, dstDeg = 0u;

    TestMemInit();
    TestRandInit();

    src = BgvNewCtx(1);
    ASSERT_TRUE(src != NULL);
    dst = CRYPT_EAL_PkeyDupCtx(src);
    ASSERT_TRUE(dst != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(src, HIFHE_CTRL_BGV_GET_POLY_DEGREE,
                                 &srcDeg, sizeof(srcDeg)), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(dst, HIFHE_CTRL_BGV_GET_POLY_DEGREE,
                                 &dstDeg, sizeof(dstDeg)), HIFHE_SUCCESS);
    ASSERT_EQ(srcDeg, dstDeg);
    ASSERT_EQ(srcDeg, 2048u);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(dst);
    CRYPT_EAL_PkeyFreeCtx(src);
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
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_BGV) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint32_t polyDegree = 0u, level = 0u;
    uint64_t plainMod = 0ull;

    TestMemInit();
    TestRandInit();

    /* 2048 / single 48-bit modulus, plainModBit 17. */
    ctx = BgvNewCtx(1);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &polyDegree, sizeof(polyDegree)),
              HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD, &plainMod, sizeof(plainMod)),
              HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_LEVEL, &level, sizeof(level)), HIFHE_SUCCESS);
    ASSERT_EQ(polyDegree, 2048u);
    ASSERT_EQ(plainMod, 114689ull);
    ASSERT_EQ(level, 1u);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    ctx = NULL;

    /* 8192 / 43,43,44,44 chain, plainModBit 20. */
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, HIFHE_PKEY_BGV,
                                       CRYPT_EAL_PKEY_CIPHER_OPERATE, HIFHE_PROVIDER_ATTR);
    ASSERT_TRUE(ctx != NULL);
    int32_t preset = HIFHE_BGV_8192_44x4;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &preset, sizeof(preset)),
              HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &polyDegree, sizeof(polyDegree)),
              HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAIN_MOD, &plainMod, sizeof(plainMod)),
              HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_LEVEL, &level, sizeof(level)), HIFHE_SUCCESS);
    ASSERT_EQ(polyDegree, 8192u);
    ASSERT_EQ(plainMod, 1032193ull);
    ASSERT_EQ(level, 4u);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */
