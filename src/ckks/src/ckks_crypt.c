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

#include <complex.h>
#include <string.h>

#include "bsl_sal.h"
#include "crypt_ckks.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "hifhe_err.h"
#include "ckks_local.h"

static int32_t CKKS_SampleBinary(void *libCtx, BN_BigNum **poly, uint32_t N)
{
    BN_BigNum *random = BN_Create(N);
    if (poly == NULL || random == NULL) {
        BN_Destroy(random);
        return poly == NULL ? CRYPT_NULL_INPUT : CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BN_RandEx(libCtx, random, N, BN_RAND_TOP_NOBIT, BN_RAND_BOTTOM_NOBIT);
    for (uint32_t i = 0; ret == CRYPT_SUCCESS && i < N; i++) {
        ret = BN_SetLimb(poly[i], BN_GetBit(random, i) ? 1 : 0);
    }
    BN_Destroy(random);
    return ret;
}

static int32_t CKKS_PubEnc(const CRYPT_CKKS_Ctx *ctx, const CRYPT_CKKS_Poly *plaintext,
    CRYPT_CKKS_Poly *c0, CRYPT_CKKS_Poly *c1)
{
    if (ctx == NULL || ctx->para == NULL || ctx->pubKey == NULL || plaintext == NULL ||
        c0 == NULL || c1 == NULL) {
        return CRYPT_NULL_INPUT;
    }
    uint32_t N = ctx->para->N;
    CRYPT_CKKS_Poly *v = CKKS_NewPoly(N);
    CRYPT_CKKS_Poly *e0 = CKKS_NewPoly(N);
    CRYPT_CKKS_Poly *e1 = CKKS_NewPoly(N);
    CRYPT_CKKS_Poly *temp = CKKS_NewPoly(N);
    BN_Optimizer *optimizer = BN_OptimizerCreate();
    int32_t ret = CRYPT_MEM_ALLOC_FAIL;
    if (v == NULL || e0 == NULL || e1 == NULL || temp == NULL || optimizer == NULL) {
        goto EXIT;
    }
    BN_OptimizerSetLibCtx(ctx->libCtx, optimizer);
    if ((ret = CKKS_SampleBinary(ctx->libCtx, v->coeffs, N)) != CRYPT_SUCCESS ||
        (ret = CKKS_SampleGauss(ctx->libCtx, e0->coeffs, N, ctx->para->sigma,
            ctx->para->Q, optimizer)) != CRYPT_SUCCESS ||
        (ret = CKKS_SampleGauss(ctx->libCtx, e1->coeffs, N, ctx->para->sigma,
            ctx->para->Q, optimizer)) != CRYPT_SUCCESS ||
        (ret = CKKS_PolyMult(temp->coeffs, v->coeffs, ctx->pubKey->bx, N,
            ctx->para->Q, optimizer)) != CRYPT_SUCCESS ||
        (ret = CKKS_PolyAdd(c0->coeffs, temp->coeffs, e0->coeffs, N,
            ctx->para->Q, optimizer)) != CRYPT_SUCCESS ||
        (ret = CKKS_PolyAdd(c0->coeffs, c0->coeffs, plaintext->coeffs, N,
            ctx->para->Q, optimizer)) != CRYPT_SUCCESS ||
        (ret = CKKS_PolyMult(temp->coeffs, v->coeffs, ctx->pubKey->ax, N,
            ctx->para->Q, optimizer)) != CRYPT_SUCCESS ||
        (ret = CKKS_PolyAdd(c1->coeffs, temp->coeffs, e1->coeffs, N,
            ctx->para->Q, optimizer)) != CRYPT_SUCCESS) {
        goto EXIT;
    }

EXIT:
    CKKS_FreePoly(v);
    CKKS_FreePoly(e0);
    CKKS_FreePoly(e1);
    CKKS_FreePoly(temp);
    BN_OptimizerDestroy(optimizer);
    return ret;
}

static int32_t CKKS_PrvDec(const CRYPT_CKKS_Ctx *ctx, const CRYPT_CKKS_Poly *c0,
    const CRYPT_CKKS_Poly *c1, CRYPT_CKKS_Poly *plaintext)
{
    if (ctx == NULL || ctx->para == NULL || ctx->prvKey == NULL || c0 == NULL ||
        c1 == NULL || plaintext == NULL) {
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CKKS_Poly *temp = CKKS_NewPoly(ctx->para->N);
    BN_Optimizer *optimizer = BN_OptimizerCreate();
    int32_t ret = CRYPT_MEM_ALLOC_FAIL;
    if (temp != NULL && optimizer != NULL) {
        BN_OptimizerSetLibCtx(ctx->libCtx, optimizer);
        ret = CKKS_PolyMult(temp->coeffs, c1->coeffs, ctx->prvKey->sx,
            ctx->para->N, ctx->para->Q, optimizer);
        if (ret == CRYPT_SUCCESS) {
            ret = CKKS_PolyAdd(plaintext->coeffs, c0->coeffs, temp->coeffs,
                ctx->para->N, ctx->para->Q, optimizer);
        }
    }
    CKKS_FreePoly(temp);
    BN_OptimizerDestroy(optimizer);
    return ret;
}

static int32_t CKKS_SerializeCiphertext(const CRYPT_CKKS_Poly *c0, const CRYPT_CKKS_Poly *c1,
    uint8_t *out, uint32_t *outLen)
{
    uint32_t c0Len = 0;
    uint32_t c1Len = 0;
    (void)CKKS_PolyToBytes(c0->coeffs, c0->N, NULL, &c0Len);
    (void)CKKS_PolyToBytes(c1->coeffs, c1->N, NULL, &c1Len);
    uint32_t required = 12 + c0Len + c1Len;
    if (out == NULL || *outLen < required) {
        *outLen = required;
        return HIFHE_BUFFER_TOO_SMALL;
    }
    memcpy(out, &c0Len, sizeof(c0Len));
    memcpy(out + 4, &c1Len, sizeof(c1Len));
    memcpy(out + 8, "CKKS", 4);
    uint32_t len = c0Len;
    int32_t ret = CKKS_PolyToBytes(c0->coeffs, c0->N, out + 12, &len);
    if (ret == CRYPT_SUCCESS) {
        len = c1Len;
        ret = CKKS_PolyToBytes(c1->coeffs, c1->N, out + 12 + c0Len, &len);
    }
    if (ret == CRYPT_SUCCESS) {
        *outLen = required;
    }
    return ret;
}

static int32_t CKKS_DeserializeCiphertext(uint32_t N, const uint8_t *data, uint32_t dataLen,
    CRYPT_CKKS_Poly *c0, CRYPT_CKKS_Poly *c1)
{
    if (data == NULL || c0 == NULL || c1 == NULL || dataLen < 12 || memcmp(data + 8, "CKKS", 4) != 0) {
        return HIFHE_DECODE_ERROR;
    }
    uint32_t c0Len = 0;
    uint32_t c1Len = 0;
    memcpy(&c0Len, data, sizeof(c0Len));
    memcpy(&c1Len, data + 4, sizeof(c1Len));
    if (c0Len > dataLen - 12 || c1Len != dataLen - 12 - c0Len) {
        return HIFHE_DECODE_ERROR;
    }
    int32_t ret = CKKS_BytesToPoly(data + 12, c0Len, c0->coeffs, N);
    if (ret == CRYPT_SUCCESS) {
        ret = CKKS_BytesToPoly(data + 12 + c0Len, c1Len, c1->coeffs, N);
    }
    return ret;
}

int32_t CRYPT_CKKS_EncryptEx(CRYPT_CKKS_Ctx *ctx, const double complex *input, uint32_t slots,
    uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || ctx->para == NULL || ctx->pubKey == NULL || input == NULL || outLen == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (slots == 0 || slots > ctx->para->slots) {
        return HIFHE_INVALID_ARGUMENT;
    }
    uint32_t maxPolyLen = ctx->para->N * (sizeof(uint32_t) + (ctx->para->qBits + 7) / 8);
    uint32_t maxCipherLen = 12 + 2 * maxPolyLen;
    if (out == NULL || *outLen < maxCipherLen) {
        *outLen = maxCipherLen;
        return HIFHE_BUFFER_TOO_SMALL;
    }

    CRYPT_CKKS_Poly *plaintext = CKKS_NewPoly(ctx->para->N);
    CRYPT_CKKS_Poly *c0 = CKKS_NewPoly(ctx->para->N);
    CRYPT_CKKS_Poly *c1 = CKKS_NewPoly(ctx->para->N);
    int32_t ret = CRYPT_MEM_ALLOC_FAIL;
    if (plaintext == NULL || c0 == NULL || c1 == NULL) {
        goto EXIT;
    }
    ret = CKKS_Encode(ctx, input, slots, plaintext);
    if (ret == CRYPT_SUCCESS) {
        ret = CKKS_PubEnc(ctx, plaintext, c0, c1);
    }
    if (ret == CRYPT_SUCCESS) {
        ret = CKKS_SerializeCiphertext(c0, c1, out, outLen);
    }

EXIT:
    CKKS_FreePoly(plaintext);
    CKKS_FreePoly(c0);
    CKKS_FreePoly(c1);
    return ret;
}

int32_t CRYPT_CKKS_DecryptEx(CRYPT_CKKS_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    double complex *output, uint32_t *slots)
{
    if (ctx == NULL || ctx->para == NULL || ctx->prvKey == NULL || data == NULL ||
        output == NULL || slots == NULL) {
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CKKS_Poly *c0 = CKKS_NewPoly(ctx->para->N);
    CRYPT_CKKS_Poly *c1 = CKKS_NewPoly(ctx->para->N);
    CRYPT_CKKS_Poly *plaintext = CKKS_NewPoly(ctx->para->N);
    int32_t ret = CRYPT_MEM_ALLOC_FAIL;
    if (c0 == NULL || c1 == NULL || plaintext == NULL) {
        goto EXIT;
    }
    ret = CKKS_DeserializeCiphertext(ctx->para->N, data, dataLen, c0, c1);
    if (ret == CRYPT_SUCCESS) {
        ret = CKKS_PrvDec(ctx, c0, c1, plaintext);
    }
    if (ret == CRYPT_SUCCESS) {
        ret = CKKS_Decode(ctx, plaintext, output, slots);
    }

EXIT:
    CKKS_FreePoly(c0);
    CKKS_FreePoly(c1);
    CKKS_FreePoly(plaintext);
    return ret;
}

int32_t CRYPT_CKKS_Encrypt(CRYPT_CKKS_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen)
{
    if (data == NULL || dataLen == 0 || dataLen % sizeof(double complex) != 0) {
        return HIFHE_INVALID_ARGUMENT;
    }
    uint32_t slots = dataLen / sizeof(double complex);
    double complex *values = BSL_SAL_Malloc(dataLen);
    if (values == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    memcpy(values, data, dataLen);
    int32_t ret = CRYPT_CKKS_EncryptEx(ctx, values, slots, out, outLen);
    BSL_SAL_Free(values);
    return ret;
}

int32_t CRYPT_CKKS_Decrypt(CRYPT_CKKS_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || ctx->para == NULL || outLen == NULL) {
        return CRYPT_NULL_INPUT;
    }
    uint32_t required = ctx->para->slots * sizeof(double complex);
    if (out == NULL || *outLen < required) {
        *outLen = required;
        return HIFHE_BUFFER_TOO_SMALL;
    }
    uint32_t slots = ctx->para->slots;
    int32_t ret = CRYPT_CKKS_DecryptEx(ctx, data, dataLen, (double complex *)out, &slots);
    if (ret == CRYPT_SUCCESS) {
        *outLen = slots * sizeof(double complex);
    }
    return ret;
}

int32_t CRYPT_CKKS_Ctrl(CRYPT_CKKS_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (opt == CRYPT_CTRL_GET_BITS) {
        if (val == NULL || len != sizeof(uint32_t)) {
            return CRYPT_NULL_INPUT;
        }
        *(uint32_t *)val = CRYPT_CKKS_GetBits(ctx);
        return CRYPT_SUCCESS;
    }
    return HIFHE_NOT_SUPPORTED;
}
