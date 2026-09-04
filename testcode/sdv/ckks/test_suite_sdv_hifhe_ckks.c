/*
 * Copyright (c) 2026 openHiTLS. All Rights Reserved.
 * HiFHE is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

/* BEGIN_HEADER */
#include <complex.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

#include "bsl_params.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "crypt_util_rand.h"
#include "hifhe_err.h"
#include "hifhe_provider.h"
#include "hifhe_types.h"
/* END_HEADER */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_CKKS_ROUNDTRIP_API_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_CKKS) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t *cipher = NULL;
    TestMemInit();
    CRYPT_RandRegistEx(TestSimpleRandEx);

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, HIFHE_PKEY_CKKS,
        CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=hifhe");
    ASSERT_TRUE(ctx != NULL);

    uint32_t n = 16;
    uint32_t qBits = 50;
    uint32_t pBits = 20;
    uint32_t sigmaMilli = 3200;
    uint32_t slots = 2;
    BSL_Param params[] = {
        {HIFHE_PARAM_CKKS_N, BSL_PARAM_TYPE_UINT32, &n, sizeof(n), 0},
        {HIFHE_PARAM_CKKS_Q_BITS, BSL_PARAM_TYPE_UINT32, &qBits, sizeof(qBits), 0},
        {HIFHE_PARAM_CKKS_P_BITS, BSL_PARAM_TYPE_UINT32, &pBits, sizeof(pBits), 0},
        {HIFHE_PARAM_CKKS_SIGMA_MILLI, BSL_PARAM_TYPE_UINT32, &sigmaMilli, sizeof(sigmaMilli), 0},
        {HIFHE_PARAM_CKKS_SLOTS, BSL_PARAM_TYPE_UINT32, &slots, sizeof(slots), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeySetParaEx(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);

    double complex input[] = {1.25 + 0.5 * I, -2.0 + 0.75 * I};
    uint32_t cipherLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, (const uint8_t *)input, sizeof(input), NULL, &cipherLen),
        HIFHE_BUFFER_TOO_SMALL);
    cipher = malloc(cipherLen);
    ASSERT_TRUE(cipher != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, (const uint8_t *)input, sizeof(input), cipher, &cipherLen),
        CRYPT_SUCCESS);

    double complex output[2] = {0};
    uint32_t outputLen = sizeof(output);
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, cipher, cipherLen, (uint8_t *)output, &outputLen), CRYPT_SUCCESS);
    ASSERT_EQ(outputLen, sizeof(output));
    ASSERT_TRUE(cabs(input[0] - output[0]) < 0.05);
    ASSERT_TRUE(cabs(input[1] - output[1]) < 0.05);

EXIT:
    free(cipher);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_CKKS_INVALID_PARAM_API_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_CKKS) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, HIFHE_PKEY_CKKS,
        CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=hifhe");
    ASSERT_TRUE(ctx != NULL);

    uint32_t n = 15;
    uint32_t qBits = 50;
    uint32_t pBits = 20;
    uint32_t sigmaMilli = 3200;
    uint32_t slots = 2;
    BSL_Param params[] = {
        {HIFHE_PARAM_CKKS_N, BSL_PARAM_TYPE_UINT32, &n, sizeof(n), 0},
        {HIFHE_PARAM_CKKS_Q_BITS, BSL_PARAM_TYPE_UINT32, &qBits, sizeof(qBits), 0},
        {HIFHE_PARAM_CKKS_P_BITS, BSL_PARAM_TYPE_UINT32, &pBits, sizeof(pBits), 0},
        {HIFHE_PARAM_CKKS_SIGMA_MILLI, BSL_PARAM_TYPE_UINT32, &sigmaMilli, sizeof(sigmaMilli), 0},
        {HIFHE_PARAM_CKKS_SLOTS, BSL_PARAM_TYPE_UINT32, &slots, sizeof(slots), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeySetParaEx(ctx, params), HIFHE_INVALID_ARGUMENT);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_CKKS_KEY_IMPORT_API_TC001(void)
{
    if ((HIFHE_GetFeatures() & HIFHE_FEATURE_CKKS) == 0) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *keyCtx = NULL;
    CRYPT_EAL_PkeyCtx *encCtx = NULL;
    CRYPT_EAL_PkeyCtx *decCtx = NULL;
    uint8_t *pub = NULL;
    uint8_t *prv = NULL;
    uint8_t *cipher = NULL;
    uint32_t n = 16;
    uint32_t qBits = 50;
    uint32_t pBits = 20;
    uint32_t sigmaMilli = 3200;
    uint32_t slots = 2;
    BSL_Param params[] = {
        {HIFHE_PARAM_CKKS_N, BSL_PARAM_TYPE_UINT32, &n, sizeof(n), 0},
        {HIFHE_PARAM_CKKS_Q_BITS, BSL_PARAM_TYPE_UINT32, &qBits, sizeof(qBits), 0},
        {HIFHE_PARAM_CKKS_P_BITS, BSL_PARAM_TYPE_UINT32, &pBits, sizeof(pBits), 0},
        {HIFHE_PARAM_CKKS_SIGMA_MILLI, BSL_PARAM_TYPE_UINT32, &sigmaMilli, sizeof(sigmaMilli), 0},
        {HIFHE_PARAM_CKKS_SLOTS, BSL_PARAM_TYPE_UINT32, &slots, sizeof(slots), 0},
        BSL_PARAM_END
    };
    CRYPT_RandRegistEx(TestSimpleRandEx);

    keyCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, HIFHE_PKEY_CKKS,
        CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=hifhe");
    encCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, HIFHE_PKEY_CKKS,
        CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=hifhe");
    decCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, HIFHE_PKEY_CKKS,
        CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=hifhe");
    ASSERT_TRUE(keyCtx != NULL && encCtx != NULL && decCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaEx(keyCtx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaEx(encCtx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaEx(decCtx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(keyCtx), CRYPT_SUCCESS);

    BSL_Param pubParam[] = {
        {HIFHE_PARAM_CKKS_PUBKEY, BSL_PARAM_TYPE_OCTETS, NULL, 0, 0},
        BSL_PARAM_END
    };
    BSL_Param prvParam[] = {
        {HIFHE_PARAM_CKKS_PRVKEY, BSL_PARAM_TYPE_OCTETS, NULL, 0, 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(keyCtx, pubParam), HIFHE_BUFFER_TOO_SMALL);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(keyCtx, prvParam), HIFHE_BUFFER_TOO_SMALL);
    pub = malloc(pubParam[0].useLen);
    prv = malloc(prvParam[0].useLen);
    ASSERT_TRUE(pub != NULL && prv != NULL);
    pubParam[0].value = pub;
    pubParam[0].valueLen = pubParam[0].useLen;
    prvParam[0].value = prv;
    prvParam[0].valueLen = prvParam[0].useLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(keyCtx, pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(keyCtx, prvParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(encCtx, pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(decCtx, prvParam), CRYPT_SUCCESS);

    double complex input[] = {0.25 - 0.5 * I, 3.0 + 1.25 * I};
    uint32_t cipherLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(encCtx, (const uint8_t *)input, sizeof(input), NULL, &cipherLen),
        HIFHE_BUFFER_TOO_SMALL);
    cipher = malloc(cipherLen);
    ASSERT_TRUE(cipher != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(encCtx, (const uint8_t *)input, sizeof(input), cipher, &cipherLen),
        CRYPT_SUCCESS);
    double complex output[2] = {0};
    uint32_t outputLen = sizeof(output);
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(decCtx, cipher, cipherLen, (uint8_t *)output, &outputLen), CRYPT_SUCCESS);
    ASSERT_TRUE(cabs(input[0] - output[0]) < 0.05);
    ASSERT_TRUE(cabs(input[1] - output[1]) < 0.05);

EXIT:
    free(cipher);
    free(prv);
    free(pub);
    CRYPT_EAL_PkeyFreeCtx(decCtx);
    CRYPT_EAL_PkeyFreeCtx(encCtx);
    CRYPT_EAL_PkeyFreeCtx(keyCtx);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */
