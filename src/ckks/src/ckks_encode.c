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
#include <float.h>
#include <math.h>
#include <stdlib.h>

#include "bsl_sal.h"
#include "crypt_ckks.h"
#include "crypt_errno.h"
#include "hifhe_err.h"
#include "ckks_local.h"

int32_t CKKS_InitFFTParams(CRYPT_CKKS_Para *para)
{
    if (para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    uint32_t rootCount = (para->N << 1) + 1;
    para->ksiPows = BSL_SAL_Malloc(rootCount * sizeof(double complex));
    para->rotGroup = BSL_SAL_Malloc((para->N >> 1) * sizeof(uint32_t));
    if (para->ksiPows == NULL || para->rotGroup == NULL) {
        BSL_SAL_Free(para->ksiPows);
        BSL_SAL_Free(para->rotGroup);
        para->ksiPows = NULL;
        para->rotGroup = NULL;
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint32_t M = para->N << 1;
    for (uint32_t i = 0; i <= M; i++) {
        double angle = 2.0 * CKKS_PI * i / M;
        para->ksiPows[i] = cos(angle) + I * sin(angle);
    }
    uint32_t power = 1;
    for (uint32_t i = 0; i < para->N / 2; i++) {
        para->rotGroup[i] = power;
        power = (power * 5) % M;
    }
    return CRYPT_SUCCESS;
}

static int32_t CKKS_ScaleUp(double value, uint32_t scaleBits, BN_BigNum *result)
{
    if (result == NULL || !isfinite(value)) {
        return HIFHE_INVALID_ARGUMENT;
    }
    double scaled = ldexp(value, (int)scaleBits);
    if (!isfinite(scaled) || fabs(scaled) > (double)INT64_MAX) {
        return HIFHE_INVALID_ARGUMENT;
    }
    int64_t rounded = (int64_t)llround(scaled);
    uint64_t magnitude = rounded < 0 ? (uint64_t)(-(rounded + 1)) + 1 : (uint64_t)rounded;
    int32_t ret = BN_SetLimb(result, (BN_UINT)magnitude);
    if (ret == CRYPT_SUCCESS && rounded < 0) {
        ret = BN_SetSign(result, true);
    }
    return ret;
}

static int32_t CKKS_ScaleDown(const BN_BigNum *value, const BN_BigNum *modulus,
    uint32_t scaleBits, double *result)
{
    if (value == NULL || modulus == NULL || result == NULL) {
        return CRYPT_NULL_INPUT;
    }
    BN_BigNum *centered = BN_Dup(value);
    BN_BigNum *half = BN_Create(CKKS_BN_WORK_BITS);
    if (centered == NULL || half == NULL) {
        BN_Destroy(centered);
        BN_Destroy(half);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BN_Rshift(half, modulus, 1);
    if (ret == CRYPT_SUCCESS && BN_Cmp(centered, half) > 0) {
        ret = BN_Sub(centered, centered, modulus);
    }
    if (ret == CRYPT_SUCCESS) {
        char *decimal = BN_Bn2Dec(centered);
        if (decimal == NULL) {
            ret = CRYPT_MEM_ALLOC_FAIL;
        } else {
            *result = ldexp(strtod(decimal, NULL), -(int)scaleBits);
            BSL_SAL_Free(decimal);
        }
    }
    BN_Destroy(centered);
    BN_Destroy(half);
    return ret;
}

int32_t CKKS_Encode(const CRYPT_CKKS_Ctx *ctx, const double complex *input, uint32_t slots,
    CRYPT_CKKS_Poly *plaintext)
{
    if (ctx == NULL || ctx->para == NULL || input == NULL || plaintext == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (slots == 0 || slots > ctx->para->slots || plaintext->N != ctx->para->N) {
        return HIFHE_INVALID_ARGUMENT;
    }

    uint32_t half = ctx->para->N / 2;
    uint32_t gap = half / slots;
    for (uint32_t i = 0; i < slots; i++) {
        int32_t ret = CKKS_ScaleUp(creal(input[i]), ctx->para->pBits, plaintext->coeffs[i * gap]);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        ret = CKKS_ScaleUp(cimag(input[i]), ctx->para->pBits, plaintext->coeffs[half + i * gap]);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}

int32_t CKKS_Decode(const CRYPT_CKKS_Ctx *ctx, const CRYPT_CKKS_Poly *plaintext,
    double complex *output, uint32_t *slots)
{
    if (ctx == NULL || ctx->para == NULL || plaintext == NULL || output == NULL || slots == NULL) {
        return CRYPT_NULL_INPUT;
    }
    uint32_t count = *slots < ctx->para->slots ? *slots : ctx->para->slots;
    if (count == 0) {
        return HIFHE_BUFFER_TOO_SMALL;
    }
    uint32_t half = ctx->para->N / 2;
    uint32_t gap = half / ctx->para->slots;
    for (uint32_t i = 0; i < count; i++) {
        double realPart = 0;
        double imagPart = 0;
        int32_t ret = CKKS_ScaleDown(plaintext->coeffs[i * gap], ctx->para->Q,
            ctx->para->pBits, &realPart);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        ret = CKKS_ScaleDown(plaintext->coeffs[half + i * gap], ctx->para->Q,
            ctx->para->pBits, &imagPart);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        output[i] = realPart + I * imagPart;
    }
    *slots = count;
    return CRYPT_SUCCESS;
}
