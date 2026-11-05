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
#include <stdint.h>
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

/* The fixed part of HiFHE's own wire format, ahead of the algorithm's body.
 * The cases below reach into that body by offset. */
#define WIRE_HEADER 44u

static uint8_t *Serialized(const HIFHE_Ctx *ctx, const HIFHE_HEText *text, uint32_t *len)
{
    *len = 0;
    if (HIFHE_Serialize(ctx, text, NULL, len) != HIFHE_BUFFER_TOO_SMALL) {
        return NULL;
    }
    uint8_t *bytes = malloc(*len);
    if (bytes == NULL) {
        return NULL;
    }
    if (HIFHE_Serialize(ctx, text, bytes, len) != HIFHE_SUCCESS) {
        free(bytes);
        return NULL;
    }
    return bytes;
}

static uint32_t Get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void Put32(uint8_t *p, uint32_t value)
{
    for (uint32_t i = 0; i < 4; i++) {
        p[i] = (uint8_t)(value >> (8 * i));
    }
}

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_CONTEXT_CTRL_PROVIDER_TC001(int cmd)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL, *dup = NULL;
    uint8_t *pt = NULL, *ct = NULL, *decoded = NULL;
    uint8_t seed[32] = {1};
    uint32_t value = 1, ptLen = 0, ctLen = 0;
    uint64_t output[4096], message = 7;
    void *arg = cmd == HIFHE_CTRL_BGV_SET_SEED ? (void *)seed : (void *)&value;
    uint32_t argLen = cmd == HIFHE_CTRL_BGV_SET_SEED ? sizeof(seed) : sizeof(value);
    bool loaded = false;
    const char *path = getenv("HIFHE_PROVIDER_PATH");

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL), HIFHE_SUCCESS);
    ASSERT_TRUE(path != NULL);
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(NULL, path), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(NULL, BSL_SAL_LIB_FMT_LIBSO, "hifhe", NULL, NULL), HIFHE_SUCCESS);
    loaded = true;
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, HIFHE_BGV, CRYPT_EAL_PKEY_CIPHER_OPERATE, HIFHE_PROVIDER_ATTR);
    ASSERT_TRUE(ctx != NULL);
    if (cmd != HIFHE_CTRL_BGV_SET_LUT_CACHE) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, cmd, arg, argLen), HIFHE_PARAM_NOT_SET);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, (CRYPT_PKEY_ParaId)HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, cmd, arg, argLen), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, cmd, NULL, argLen), HIFHE_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, cmd, arg, argLen - 1), HIFHE_INVALID_LENGTH);
    if (cmd == HIFHE_CTRL_BGV_SET_LUT_CACHE) {
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, (CRYPT_PKEY_ParaId)HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, cmd, arg, argLen), HIFHE_BAD_STATE);
    }
    dup = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(dup != NULL);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    ctx = dup;
    dup = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), HIFHE_SUCCESS);
    if (cmd == HIFHE_CTRL_BGV_SET_SEED) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, cmd, arg, argLen), HIFHE_BAD_STATE);
    }
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &ptLen, sizeof(ptLen)), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen)), HIFHE_SUCCESS);
    uint32_t ptCapacity = ptLen, ctCapacity = ctLen;
    pt = malloc(ptLen);
    decoded = malloc(ptLen);
    ct = malloc(ctLen);
    ASSERT_TRUE(pt != NULL && decoded != NULL && ct != NULL);
    BSL_Param encode[] = {{HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, &message, sizeof(message), 0}, BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(ctx, encode, pt, &ptLen), HIFHE_SUCCESS);
    ASSERT_EQ(ptLen, ptCapacity);
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(ctx, pt, ptLen, ct, &ctLen), HIFHE_SUCCESS);
    ASSERT_EQ(ctLen, ctCapacity);
    if (cmd == HIFHE_CTRL_BGV_GET_POLY_DEGREE) {
        ASSERT_EQ(value, 4096);
    } else if (cmd == HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN) {
        ASSERT_EQ(value, ptLen);
    } else if (cmd == HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN) {
        ASSERT_EQ(value, ctLen);
    }
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(ctx, ct, ctLen, decoded, &ptCapacity), HIFHE_SUCCESS);
    BSL_Param decode[] = {{HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, decoded, ptCapacity, 0}, BSL_PARAM_END};
    uint32_t outLen = sizeof(output);
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(ctx, decode, (uint8_t *)output, &outLen), HIFHE_SUCCESS);
    ASSERT_EQ(outLen, sizeof(output));
    for (uint32_t i = 0; i < 4096; i++) {
        ASSERT_EQ(output[i], i == 0 ? message : 0);
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(dup);
    free(pt);
    free(ct);
    free(decoded);
    if (loaded) {
        if (CRYPT_EAL_ProviderUnload(NULL, BSL_SAL_LIB_FMT_LIBSO, "hifhe") != HIFHE_SUCCESS) {
            RecordFailure("CRYPT_EAL_ProviderUnload", __FILE__);
        }
    }
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_PROVIDER_TC001(void)
{
    HIFHE_Ctx *a = NULL;
    CRYPT_EAL_PkeyCtx *b = NULL;
    HIFHE_HEText *pt = NULL, *ct = NULL, *r = NULL, *decoded = NULL;
    uint8_t *ctWire = NULL, *ptWire = NULL, *result = NULL;
    uint64_t *out = NULL;
    bool loaded = false;
    const char *path = getenv("HIFHE_PROVIDER_PATH");

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL), HIFHE_SUCCESS);
    ASSERT_TRUE(path != NULL);
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(NULL, path), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(NULL, BSL_SAL_LIB_FMT_LIBSO, "hifhe", NULL, NULL), HIFHE_SUCCESS);
    loaded = true;
    a = HIFHE_New(HIFHE_BGV);
    ASSERT_TRUE(a != NULL);
    ASSERT_EQ(HIFHE_SetParaById(a, HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_KeyGen(a), HIFHE_SUCCESS);
    b = CRYPT_EAL_ProviderPkeyNewCtx(NULL, HIFHE_BGV, CRYPT_EAL_PKEY_CIPHER_OPERATE, HIFHE_PROVIDER_ATTR);
    ASSERT_TRUE(b != NULL);
    BSL_Param unsupported[] = {BSL_PARAM_END};
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaEx(b, unsupported) == CRYPT_EAL_ALG_NOT_SUPPORT);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPubEx(b, unsupported) == CRYPT_EAL_ALG_NOT_SUPPORT);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrvEx(b, unsupported) == CRYPT_EAL_ALG_NOT_SUPPORT);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPubEx(b, unsupported) == CRYPT_EAL_ALG_NOT_SUPPORT);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrvEx(b, unsupported) == CRYPT_EAL_ALG_NOT_SUPPORT);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(b, (CRYPT_PKEY_ParaId)HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
    uint32_t bits = UINT32_MAX;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(b, CRYPT_CTRL_GET_BITS, &bits, sizeof(bits)), HIFHE_NOT_SUPPORTED);
    ASSERT_EQ(bits, UINT32_MAX);
    ASSERT_EQ(CRYPT_EAL_PkeyGetKeyBits(b), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyGetKeyLen(b), 0);
    uint64_t values[] = {1, 2, 3, 4};
    uint64_t bucket[] = {1, 4, 2, 6};
    ASSERT_EQ(HIFHE_Encode(a, values, 4, &pt), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(a, pt, &ct), HIFHE_SUCCESS);
    uint32_t ctLen = 0, ptLen = 0, resultLen = 0;
    ctWire = Serialized(a, ct, &ctLen);
    ASSERT_TRUE(ctWire != NULL);
    BSL_Param encode[] = {{HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, bucket, sizeof(bucket), 0}, BSL_PARAM_END};
    uint64_t invalid = 65537;
    BSL_Param bad[] = {{HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, &invalid, sizeof(invalid), 0}, BSL_PARAM_END};
    ASSERT_TRUE(CRYPT_EAL_PkeyHEMsgEncode(b, bad, NULL, &ptLen) == HIFHE_VALUE_OUT_OF_RANGE);
    invalid = (UINT64_C(1) << 32) + 1;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(b, bad, NULL, &ptLen), HIFHE_VALUE_OUT_OF_RANGE);
    invalid = UINT64_MAX;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(b, bad, NULL, &ptLen), HIFHE_VALUE_OUT_OF_RANGE);
    ASSERT_TRUE(CRYPT_EAL_PkeyHEMsgEncode(b, encode, NULL, &ptLen) == HIFHE_BUFFER_TOO_SMALL);
    ptWire = malloc(ptLen);
    ASSERT_TRUE(ptWire != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(b, encode, ptWire, &ptLen), HIFHE_SUCCESS);
    BSL_Param wrongKind[] = {{CRYPT_PARAM_PKEY_HE_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ptWire, ptLen, 0},
                             {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, ptWire, ptLen, 0},
                             BSL_PARAM_END};
    ASSERT_TRUE(CRYPT_EAL_PkeyHEAdd(b, wrongKind, NULL, &resultLen) == HIFHE_TEXT_TYPE_MISMATCH);
    uint8_t negative = 1;
    BSL_Param input[] = {{CRYPT_PARAM_PKEY_HE_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ctWire, ctLen, 0},
                         {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, ptWire, ptLen, 0},
                         {HIFHE_PARAM_BGV_NEGATE, BSL_PARAM_TYPE_OCTETS, &negative, 1, 0},
                         BSL_PARAM_END};
    ASSERT_TRUE(CRYPT_EAL_PkeyHEAdd(b, input, NULL, &resultLen) == HIFHE_BUFFER_TOO_SMALL);
    result = malloc(resultLen);
    ASSERT_TRUE(result != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyHEAdd(b, input, result, &resultLen), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Deserialize(a, result, resultLen, &r), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Decrypt(a, r, &decoded), HIFHE_SUCCESS);
    uint32_t count = 4096;
    out = calloc(count, sizeof(*out));
    ASSERT_TRUE(out != NULL);
    ASSERT_EQ(HIFHE_Decode(a, decoded, out, &count), HIFHE_SUCCESS);
    ASSERT_TRUE(out[0] == 0 && out[1] == 2 && out[2] == 65536 && out[3] == 2);
    BSL_Param square[] = {{CRYPT_PARAM_PKEY_HE_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ctWire, ctLen, 0},
                          {CRYPT_PARAM_PKEY_HE_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, ctWire, ctLen, 0},
                          BSL_PARAM_END};
    ASSERT_TRUE(CRYPT_EAL_PkeyHEMul(b, square, NULL, &resultLen) == HIFHE_NOT_SUPPORTED);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(b);
    HIFHE_Free(a);
    HIFHE_HETextFree(pt);
    HIFHE_HETextFree(ct);
    HIFHE_HETextFree(r);
    HIFHE_HETextFree(decoded);
    free(ctWire);
    free(ptWire);
    free(result);
    free(out);
    if (loaded) {
        if (CRYPT_EAL_ProviderUnload(NULL, BSL_SAL_LIB_FMT_LIBSO, "hifhe") != HIFHE_SUCCESS) {
            RecordFailure("CRYPT_EAL_ProviderUnload", __FILE__);
        }
    }
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_PROVIDER_MUL_SIZE_TC001(int components)
{
    HIFHE_Ctx *a = NULL;
    CRYPT_EAL_PkeyCtx *b = NULL;
    HIFHE_HEText *pt = NULL, *ct = NULL, *product = NULL, *decoded = NULL;
    uint8_t *ptWire = NULL, *ctWire = NULL, *wide = NULL, *result = NULL;
    bool loaded = false;
    const char *path = getenv("HIFHE_PROVIDER_PATH");

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL), HIFHE_SUCCESS);
    ASSERT_TRUE(path != NULL);
    ASSERT_TRUE(components >= 2 && components <= 8);
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(NULL, path), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(NULL, BSL_SAL_LIB_FMT_LIBSO, "hifhe", NULL, NULL), HIFHE_SUCCESS);
    loaded = true;
    a = HIFHE_New(HIFHE_BGV);
    ASSERT_TRUE(a != NULL);
    ASSERT_EQ(HIFHE_SetParaById(a, HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_KeyGen(a), HIFHE_SUCCESS);
    b = CRYPT_EAL_ProviderPkeyNewCtx(NULL, HIFHE_BGV, CRYPT_EAL_PKEY_CIPHER_OPERATE, HIFHE_PROVIDER_ATTR);
    ASSERT_TRUE(b != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(b, (CRYPT_PKEY_ParaId)HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);

    uint64_t values[] = {0, 1, 7, 65536};
    ASSERT_EQ(HIFHE_Encode(a, values, 4, &pt), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(a, pt, &ct), HIFHE_SUCCESS);
    uint32_t ptLen = 0, ctLen = 0;
    ptWire = Serialized(a, pt, &ptLen);
    ctWire = Serialized(a, ct, &ctLen);
    ASSERT_TRUE(ptWire != NULL && ctWire != NULL);
    ASSERT_TRUE(ctLen > WIRE_HEADER + 64u);
    ASSERT_EQ(Get32(ctWire + WIRE_HEADER + 8), 2);
    uint32_t slots = Get32(ctWire + WIRE_HEADER + 52), limbs = Get32(ctWire + WIRE_HEADER + 56);
    ASSERT_EQ(slots, 4096);
    ASSERT_EQ(limbs, 2);
    uint32_t wideLen = ctLen + ((uint32_t)components - 2) * slots * limbs * sizeof(uint64_t);
    wide = calloc(wideLen, 1);
    ASSERT_TRUE(wide != NULL);
    /* Zero extra components preserve the encrypted message. */
    memcpy(wide, ctWire, ctLen);
    Put32(wide + 12, wideLen);
    Put32(wide + WIRE_HEADER + 8, (uint32_t)components);

    BSL_Param input[] = {{CRYPT_PARAM_PKEY_HE_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, wide, wideLen, 0},
                         {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, ptWire, ptLen, 0},
                         BSL_PARAM_END};
    uint32_t required = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMul(b, input, NULL, &required), HIFHE_BUFFER_TOO_SMALL);
    ASSERT_TRUE(required > 0);
    result = malloc(required);
    ASSERT_TRUE(result != NULL);
    uint32_t shortLen = required - 1;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMul(b, input, result, &shortLen), HIFHE_BUFFER_TOO_SMALL);
    ASSERT_EQ(shortLen, required);
    uint32_t resultLen = required;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMul(b, input, result, &resultLen), HIFHE_SUCCESS);
    ASSERT_EQ(resultLen, required);
    ASSERT_EQ(resultLen, wideLen);
    ASSERT_EQ(Get32(result + WIRE_HEADER + 8), (uint32_t)components);

    ASSERT_EQ(HIFHE_Deserialize(a, result, resultLen, &product), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Decrypt(a, product, &decoded), HIFHE_SUCCESS);
    uint64_t output[4096];
    uint32_t count = 4096;
    ASSERT_EQ(HIFHE_Decode(a, decoded, output, &count), HIFHE_SUCCESS);
    ASSERT_EQ(count, slots);
    for (uint32_t i = 0; i < count; i++) {
        uint64_t expected = i < 4 ? values[i] * values[i] % 65537 : 0;
        ASSERT_EQ(output[i], expected);
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(b);
    HIFHE_HETextFree(pt);
    HIFHE_HETextFree(ct);
    HIFHE_HETextFree(product);
    HIFHE_HETextFree(decoded);
    HIFHE_Free(a);
    free(ptWire);
    free(ctWire);
    free(wide);
    free(result);
    if (loaded) {
        if (CRYPT_EAL_ProviderUnload(NULL, BSL_SAL_LIB_FMT_LIBSO, "hifhe") != HIFHE_SUCCESS) {
            RecordFailure("CRYPT_EAL_ProviderUnload", __FILE__);
        }
    }
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_NATIVE_PROVIDER_INTEROP_TC001(void)
{
    HIFHE_Ctx *client = NULL;
    CRYPT_EAL_PkeyCtx *server = NULL;
    HIFHE_HEText *plain = NULL, *cipher = NULL, *reply = NULL, *answer = NULL;
    uint8_t *request = NULL, *response = NULL, *work = NULL, *plainWire = NULL;
    uint64_t query[] = {5, 7, 11, 65536}, decoded[4096] = {0};
    uint64_t bucket[] = {5, 2, 19, 1}, factor[] = {3, 2, 4, 5};
    uint32_t expected[] = {0, 65527, 32, 10};
    uint32_t plainCapacity = 0, cipherCapacity = 0;
    bool loaded = false;
    const char *path = getenv("HIFHE_PROVIDER_PATH");

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL), HIFHE_SUCCESS);
    ASSERT_TRUE(path != NULL);
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(NULL, path), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(NULL, BSL_SAL_LIB_FMT_LIBSO, "hifhe", NULL, NULL), HIFHE_SUCCESS);
    loaded = true;
    client = HIFHE_New(HIFHE_BGV);
    server = CRYPT_EAL_ProviderPkeyNewCtx(NULL, HIFHE_BGV, CRYPT_EAL_PKEY_CIPHER_OPERATE, HIFHE_PROVIDER_ATTR);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(HIFHE_SetParaById(client, HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(server, (CRYPT_PKEY_ParaId)HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_KeyGen(client), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(client, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, NULL, &plainCapacity, sizeof(plainCapacity)),
        HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(client, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, NULL, &cipherCapacity, sizeof(cipherCapacity)),
        HIFHE_SUCCESS);
    plainWire = malloc(plainCapacity);
    request = malloc(cipherCapacity);
    response = malloc(cipherCapacity);
    work = malloc(cipherCapacity);
    ASSERT_TRUE(plainWire != NULL && request != NULL && response != NULL && work != NULL);

    /* Native client encrypts once and sends ciphertext bytes. */
    ASSERT_EQ(HIFHE_Encode(client, query, 4, &plain), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(client, plain, &cipher), HIFHE_SUCCESS);
    uint32_t requestLen = cipherCapacity;
    ASSERT_EQ(HIFHE_Serialize(client, cipher, request, &requestLen), HIFHE_SUCCESS);

    /* Keyless Provider server computes (bucket - query) * factor, then adds noise. */
    uint32_t unusedLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(server, request, requestLen, NULL, &unusedLen), HIFHE_KEY_NOT_SET);
    BSL_Param encodeBucket[] = {
        {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, bucket, sizeof(bucket), 0}, BSL_PARAM_END};
    uint32_t plainLen = plainCapacity;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(server, encodeBucket, plainWire, &plainLen), HIFHE_SUCCESS);
    uint8_t negate = 1;
    BSL_Param subtract[] = {
        {CRYPT_PARAM_PKEY_HE_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, request, requestLen, 0},
        {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, plainWire, plainLen, 0},
        {HIFHE_PARAM_BGV_NEGATE, BSL_PARAM_TYPE_OCTETS, &negate, sizeof(negate), 0}, BSL_PARAM_END};
    uint32_t responseLen = cipherCapacity;
    ASSERT_EQ(CRYPT_EAL_PkeyHEAdd(server, subtract, response, &responseLen), HIFHE_SUCCESS);
    BSL_Param encodeFactor[] = {
        {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, factor, sizeof(factor), 0}, BSL_PARAM_END};
    plainLen = plainCapacity;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(server, encodeFactor, plainWire, &plainLen), HIFHE_SUCCESS);
    BSL_Param multiply[] = {
        {CRYPT_PARAM_PKEY_HE_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, response, responseLen, 0},
        {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, plainWire, plainLen, 0}, BSL_PARAM_END};
    uint32_t workLen = cipherCapacity;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMul(server, multiply, work, &workLen), HIFHE_SUCCESS);
    BSL_Param noise[] = {
        {CRYPT_PARAM_PKEY_HE_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, work, workLen, 0},
        {CRYPT_PARAM_PKEY_HE_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, response, cipherCapacity, 0}, BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(server, HIFHE_CTRL_BGV_RERANDOMIZE, noise, 0), HIFHE_SUCCESS);
    responseLen = noise[1].useLen;

    ASSERT_EQ(HIFHE_Deserialize(client, response, responseLen, &reply), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Decrypt(client, reply, &answer), HIFHE_SUCCESS);
    uint32_t count = 4096;
    ASSERT_EQ(HIFHE_Decode(client, answer, decoded, &count), HIFHE_SUCCESS);
    ASSERT_EQ(count, 4096);
    for (uint32_t i = 0; i < count; i++) {
        ASSERT_EQ(decoded[i], i < 4 ? expected[i] : 0);
    }
EXIT:
    HIFHE_HETextFree(plain);
    HIFHE_HETextFree(cipher);
    HIFHE_HETextFree(reply);
    HIFHE_HETextFree(answer);
    HIFHE_Free(client);
    CRYPT_EAL_PkeyFreeCtx(server);
    free(request);
    free(response);
    free(work);
    free(plainWire);
    if (loaded) {
        if (CRYPT_EAL_ProviderUnload(NULL, BSL_SAL_LIB_FMT_LIBSO, "hifhe") != HIFHE_SUCCESS) {
            RecordFailure("CRYPT_EAL_ProviderUnload", __FILE__);
        }
    }
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_PROVIDER_NATIVE_INTEROP_TC001(void)
{
    CRYPT_EAL_PkeyCtx *client = NULL;
    HIFHE_Ctx *server = NULL;
    HIFHE_HEText *received = NULL, *bucketPlain = NULL, *difference = NULL, *factorPlain = NULL;
    HIFHE_HEText *product = NULL, *result = NULL, *unexpected = NULL;
    uint8_t *plainWire = NULL, *request = NULL, *response = NULL;
    uint64_t query[] = {5, 7, 11, 65536}, decoded[4096] = {0};
    uint64_t bucket[] = {5, 2, 19, 1}, factor[] = {3, 2, 4, 5};
    uint32_t expected[] = {0, 65527, 32, 10};
    uint32_t plainCapacity = 0, cipherCapacity = 0;
    bool loaded = false;
    const char *path = getenv("HIFHE_PROVIDER_PATH");

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL), HIFHE_SUCCESS);
    ASSERT_TRUE(path != NULL);
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(NULL, path), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(NULL, BSL_SAL_LIB_FMT_LIBSO, "hifhe", NULL, NULL), HIFHE_SUCCESS);
    loaded = true;
    client = CRYPT_EAL_ProviderPkeyNewCtx(NULL, HIFHE_BGV, CRYPT_EAL_PKEY_CIPHER_OPERATE, HIFHE_PROVIDER_ATTR);
    server = HIFHE_New(HIFHE_BGV);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(client, (CRYPT_PKEY_ParaId)HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_SetParaById(server, HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(client), HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(client, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &plainCapacity, sizeof(plainCapacity)),
        HIFHE_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(client, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &cipherCapacity, sizeof(cipherCapacity)),
        HIFHE_SUCCESS);
    plainWire = malloc(plainCapacity);
    request = malloc(cipherCapacity);
    response = malloc(cipherCapacity);
    ASSERT_TRUE(plainWire != NULL && request != NULL && response != NULL);

    /* Provider client encrypts once; Encrypt returns ciphertext bytes. */
    BSL_Param encode[] = {
        {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, query, sizeof(query), 0}, BSL_PARAM_END};
    uint32_t plainLen = plainCapacity;
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgEncode(client, encode, plainWire, &plainLen), HIFHE_SUCCESS);
    uint32_t requestLen = cipherCapacity;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(client, plainWire, plainLen, request, &requestLen), HIFHE_SUCCESS);

    /* Keyless native server computes with objects and serializes the response. */
    ASSERT_EQ(HIFHE_Deserialize(server, request, requestLen, &received), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Decrypt(server, received, &unexpected), HIFHE_KEY_NOT_SET);
    ASSERT_EQ(HIFHE_Encode(server, bucket, 4, &bucketPlain), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(server, HIFHE_CTRL_BGV_SET_NEGATE, received, NULL, 0), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Add(server, received, bucketPlain, &difference), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encode(server, factor, 4, &factorPlain), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Mul(server, difference, factorPlain, &product), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(server, HIFHE_CTRL_BGV_RERANDOMIZE, product, &result, sizeof(result)), HIFHE_SUCCESS);
    uint32_t responseLen = cipherCapacity;
    ASSERT_EQ(HIFHE_Serialize(server, result, response, &responseLen), HIFHE_SUCCESS);

    plainLen = plainCapacity;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(client, response, responseLen, plainWire, &plainLen), HIFHE_SUCCESS);
    BSL_Param decode[] = {
        {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, plainWire, plainLen, 0}, BSL_PARAM_END};
    uint32_t decodedLen = sizeof(decoded);
    ASSERT_EQ(CRYPT_EAL_PkeyHEMsgDecode(client, decode, (uint8_t *)decoded, &decodedLen), HIFHE_SUCCESS);
    ASSERT_EQ(decodedLen, sizeof(decoded));
    for (uint32_t i = 0; i < 4096; i++) {
        ASSERT_EQ(decoded[i], i < 4 ? expected[i] : 0);
    }
EXIT:
    HIFHE_HETextFree(received);
    HIFHE_HETextFree(bucketPlain);
    HIFHE_HETextFree(difference);
    HIFHE_HETextFree(factorPlain);
    HIFHE_HETextFree(product);
    HIFHE_HETextFree(result);
    HIFHE_HETextFree(unexpected);
    HIFHE_Free(server);
    CRYPT_EAL_PkeyFreeCtx(client);
    free(plainWire);
    free(request);
    free(response);
    if (loaded) {
        if (CRYPT_EAL_ProviderUnload(NULL, BSL_SAL_LIB_FMT_LIBSO, "hifhe") != HIFHE_SUCCESS) {
            RecordFailure("CRYPT_EAL_ProviderUnload", __FILE__);
        }
    }
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
}
/* END_CASE */
