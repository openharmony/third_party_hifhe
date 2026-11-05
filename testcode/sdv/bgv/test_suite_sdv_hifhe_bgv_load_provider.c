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
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hifhe.h"
#include "crypt_eal_init.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_provider.h"
#include "crypt_params_key.h"
#include "crypt_errno.h"
#include "test.h"
/* END_HEADER */

/* What the shared library offers a consumer: the provider entry point the
 * loader calls, and the native API. */
static const char *const PUBLIC_SYMBOLS[] = {
    "CRYPT_EAL_ProviderInit",
    "HIFHE_New",
    "HIFHE_Free",
    "HIFHE_SetParaById",
    "HIFHE_Ctrl",
    "HIFHE_KeyGen",
    "HIFHE_HETextFree",
    "HIFHE_Encode",
    "HIFHE_Encrypt",
    "HIFHE_Add",
    "HIFHE_Mul",
    "HIFHE_Decrypt",
    "HIFHE_Decode",
    "HIFHE_Serialize",
    "HIFHE_Deserialize",
    "HIFHE_ExportPubKey",
    "HIFHE_ExportPrvKey",
    "HIFHE_ImportPubKey",
    "HIFHE_ImportPrvKey",
    "HIFHE_SetMemFuncs",
    "HIFHE_ErrPeekError",
    "HIFHE_ErrPeekLastError",
};

/* One name from each layer inside the library. All are global in the archive
 * and none belongs in the dynamic table. */
static const char *const PRIVATE_SYMBOLS[] = {
    "Kernel_U128DivU64", "Kernel_ModInv",   "Kernel_BarrettConst_Init",
    "Bgv_HEMsgEncode",   "Hifhe_HETextNew", "HifheCalloc",
};

/* One round of use: a context from the provider in libCtx, a key, and a
 * message through encode, encrypt, decrypt and decode. */
static int32_t ProviderRound(CRYPT_EAL_LibCtx *libCtx, int paramId, uint64_t message)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t *pt = NULL, *ct = NULL, *back = NULL;
    uint64_t out[4096];
    uint32_t ptLen = 0, ctLen = 0, degree = 0, len = 0, outLen = 0;
    int32_t ret = -1;

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, HIFHE_BGV, CRYPT_EAL_PKEY_CIPHER_OPERATE, HIFHE_PROVIDER_ATTR);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, (CRYPT_PKEY_ParaId)paramId), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &ptLen, sizeof(ptLen)), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen)), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &degree, sizeof(degree)), HIFHE_SUCCESS);
    ASSERT_TRUE(degree > 0 && degree <= sizeof(out) / sizeof(out[0]));

    pt = malloc(ptLen);
    ct = malloc(ctLen);
    back = malloc(ptLen);
    ASSERT_TRUE(pt != NULL && ct != NULL && back != NULL);

    BSL_Param encode[] = {{HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, &message, sizeof(message), 0}, BSL_PARAM_END};
    len = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encode, pt, &len), HIFHE_SUCCESS);
    len = ctLen;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptLen, ct, &len), HIFHE_SUCCESS);
    len = ptLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ct, ctLen, back, &len), HIFHE_SUCCESS);

    BSL_Param decode[] = {{HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, back, len, 0}, BSL_PARAM_END};
    outLen = degree * (uint32_t)sizeof(out[0]);
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(ctx, decode, (uint8_t *)out, &outLen), HIFHE_SUCCESS);
    ASSERT_EQ(outLen, degree * (uint32_t)sizeof(out[0]));
    ASSERT_EQ(out[0], message);
    for (uint32_t i = 1; i < degree; i++) {
        ASSERT_EQ(out[i], 0);
    }
    ret = 0;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    free(pt);
    free(ct);
    free(back);
    return ret;
}

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_PROVIDER_SYMBOLS_TC001(void)
{
    void *handle = NULL;
    char file[512];
    const char *path = getenv("HIFHE_PROVIDER_PATH");

    ASSERT_TRUE(path != NULL);
    int written = snprintf(file, sizeof(file), "%s/libhifhe.so", path);
    ASSERT_TRUE(written > 0 && (size_t)written < sizeof(file));

    /* RTLD_NOW, so a relocation the library cannot resolve fails the load
     * rather than the first call. */
    handle = dlopen(file, RTLD_NOW | RTLD_LOCAL);
    ASSERT_TRUE_AND_LOG(file, handle != NULL);
    for (size_t i = 0; i < sizeof(PUBLIC_SYMBOLS) / sizeof(PUBLIC_SYMBOLS[0]); i++) {
        ASSERT_TRUE_AND_LOG(PUBLIC_SYMBOLS[i], dlsym(handle, PUBLIC_SYMBOLS[i]) != NULL);
    }
    for (size_t i = 0; i < sizeof(PRIVATE_SYMBOLS) / sizeof(PRIVATE_SYMBOLS[0]); i++) {
        ASSERT_TRUE_AND_LOG(PRIVATE_SYMBOLS[i], dlsym(handle, PRIVATE_SYMBOLS[i]) == NULL);
    }
EXIT:
    if (handle != NULL) {
        dlclose(handle);
    }
}

/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_PROVIDER_LIBCTX_TC001(int paramId)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    bool loaded = false;
    const char *path = getenv("HIFHE_PROVIDER_PATH");

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL), HIFHE_SUCCESS);
    ASSERT_TRUE(path != NULL);

    /* Twice, so an unload leaves the next load able to start over. */
    for (uint32_t round = 0; round < 2; round++) {
        libCtx = CRYPT_EAL_LibCtxNew();
        ASSERT_TRUE(libCtx != NULL);
        ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, path), HIFHE_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_LIBSO, "hifhe", NULL, NULL), HIFHE_SUCCESS);
        loaded = true;
        ASSERT_EQ(ProviderRound(libCtx, paramId, 7 + round), 0);
        ASSERT_EQ(CRYPT_EAL_ProviderUnload(libCtx, BSL_SAL_LIB_FMT_LIBSO, "hifhe"), HIFHE_SUCCESS);
        loaded = false;
        CRYPT_EAL_LibCtxFree(libCtx);
        libCtx = NULL;
    }
EXIT:
    if (loaded && CRYPT_EAL_ProviderUnload(libCtx, BSL_SAL_LIB_FMT_LIBSO, "hifhe") != HIFHE_SUCCESS) {
        RecordFailure("CRYPT_EAL_ProviderUnload", __FILE__);
    }
    CRYPT_EAL_LibCtxFree(libCtx);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
}

/* END_CASE */
