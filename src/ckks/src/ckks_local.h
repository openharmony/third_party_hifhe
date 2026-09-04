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

#ifndef CKKS_LOCAL_H
#define CKKS_LOCAL_H

#include <complex.h>
#include <stdint.h>

#include "crypt_bn.h"
#include "crypt_ckks.h"
#include "sal_atomic.h"

#define CKKS_BN_WORK_BITS 256

struct CKKS_Para {
    uint32_t N;
    uint32_t qBits;
    uint32_t pBits;
    double sigma;
    uint32_t slots;
    BN_BigNum *Q;
    BN_BigNum *P;
    double complex *ksiPows;
    uint32_t *rotGroup;
};

typedef struct {
    BN_BigNum **sx;
    uint32_t N;
} CRYPT_CKKS_PrvKey;

typedef struct {
    BN_BigNum **ax;
    BN_BigNum **bx;
    uint32_t N;
} CRYPT_CKKS_PubKey;

typedef struct {
    BN_BigNum **coeffs;
    uint32_t N;
} CRYPT_CKKS_Poly;

struct CKKS_Ctx {
    CRYPT_CKKS_Para *para;
    CRYPT_CKKS_PrvKey *prvKey;
    CRYPT_CKKS_PubKey *pubKey;
    BSL_SAL_RefCount references;
    void *libCtx;
};

CRYPT_CKKS_PrvKey *CKKS_NewPrvKey(uint32_t N);
CRYPT_CKKS_PubKey *CKKS_NewPubKey(uint32_t N);
void CKKS_FreePrvKey(CRYPT_CKKS_PrvKey *prvKey);
void CKKS_FreePubKey(CRYPT_CKKS_PubKey *pubKey);
CRYPT_CKKS_Para *CRYPT_CKKS_DupPara(const CRYPT_CKKS_Para *para);

CRYPT_CKKS_Poly *CKKS_NewPoly(uint32_t N);
void CKKS_FreePoly(CRYPT_CKKS_Poly *poly);
void CKKS_CoeffsDestroy(BN_BigNum **coeffs, uint32_t N);
int32_t CKKS_SampleGauss(void *libCtx, BN_BigNum **coeffs, uint32_t N, double sigma,
    const BN_BigNum *Q, BN_Optimizer *optimizer);
int32_t CKKS_SampleUniform(void *libCtx, BN_BigNum **coeffs, uint32_t N, const BN_BigNum *Q);
int32_t CKKS_SampleTernary(void *libCtx, BN_BigNum **coeffs, uint32_t N);
int32_t CKKS_PolyAdd(BN_BigNum **result, BN_BigNum **a, BN_BigNum **b, uint32_t N,
    const BN_BigNum *Q, BN_Optimizer *optimizer);
int32_t CKKS_PolySub(BN_BigNum **result, BN_BigNum **a, BN_BigNum **b, uint32_t N,
    const BN_BigNum *Q, BN_Optimizer *optimizer);
int32_t CKKS_PolyMult(BN_BigNum **result, BN_BigNum **a, BN_BigNum **b, uint32_t N,
    const BN_BigNum *Q, BN_Optimizer *optimizer);
int32_t CKKS_PolyToBytes(BN_BigNum **coeffs, uint32_t N, uint8_t *out, uint32_t *outLen);
int32_t CKKS_BytesToPoly(const uint8_t *data, uint32_t dataLen, BN_BigNum **coeffs, uint32_t N);

int32_t CKKS_InitFFTParams(CRYPT_CKKS_Para *para);
int32_t CKKS_Encode(const CRYPT_CKKS_Ctx *ctx, const double complex *input, uint32_t slots,
    CRYPT_CKKS_Poly *pt);
int32_t CKKS_Decode(const CRYPT_CKKS_Ctx *ctx, const CRYPT_CKKS_Poly *pt,
    double complex *out, uint32_t *slots);

#endif
