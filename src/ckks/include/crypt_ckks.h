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

#ifndef CRYPT_CKKS_H
#define CRYPT_CKKS_H

#include <complex.h>
#include <stdint.h>

#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CKKS_MAX_N 16384
#define CKKS_MIN_N 8
#define CKKS_MAX_LOGQ 60
#define CKKS_MIN_LOGQ 30
#define CKKS_DEFAULT_SIGMA 3.2
#define CKKS_PI 3.14159265358979323846

typedef struct CKKS_Ctx CRYPT_CKKS_Ctx;
typedef struct CKKS_Para CRYPT_CKKS_Para;

typedef struct {
    uint32_t N;
    uint32_t qBits;
    uint32_t pBits;
    double sigma;
    uint32_t slots;
} CRYPT_CkksPara;

CRYPT_CKKS_Ctx *CRYPT_CKKS_NewCtx(void);
CRYPT_CKKS_Ctx *CRYPT_CKKS_NewCtxEx(void *libCtx);
CRYPT_CKKS_Ctx *CRYPT_CKKS_DupCtx(const CRYPT_CKKS_Ctx *ctx);
void CRYPT_CKKS_FreeCtx(CRYPT_CKKS_Ctx *ctx);

CRYPT_CKKS_Para *CRYPT_CKKS_NewPara(const CRYPT_CkksPara *para);
void CRYPT_CKKS_FreePara(CRYPT_CKKS_Para *para);
int32_t CRYPT_CKKS_SetPara(CRYPT_CKKS_Ctx *ctx, const CRYPT_CkksPara *para);
int32_t CRYPT_CKKS_SetParaEx(CRYPT_CKKS_Ctx *ctx, const BSL_Param *para);
uint32_t CRYPT_CKKS_GetBits(const CRYPT_CKKS_Ctx *ctx);

int32_t CRYPT_CKKS_Gen(CRYPT_CKKS_Ctx *ctx);
int32_t CRYPT_CKKS_SetPrvKeyEx(CRYPT_CKKS_Ctx *ctx, const BSL_Param *param);
int32_t CRYPT_CKKS_SetPubKeyEx(CRYPT_CKKS_Ctx *ctx, const BSL_Param *param);
int32_t CRYPT_CKKS_GetPrvKeyEx(const CRYPT_CKKS_Ctx *ctx, BSL_Param *param);
int32_t CRYPT_CKKS_GetPubKeyEx(const CRYPT_CKKS_Ctx *ctx, BSL_Param *param);

int32_t CRYPT_CKKS_Encrypt(CRYPT_CKKS_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen);
int32_t CRYPT_CKKS_Decrypt(CRYPT_CKKS_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen);
int32_t CRYPT_CKKS_EncryptEx(CRYPT_CKKS_Ctx *ctx, const double complex *values, uint32_t slots,
    uint8_t *out, uint32_t *outLen);
int32_t CRYPT_CKKS_DecryptEx(CRYPT_CKKS_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    double complex *values, uint32_t *slots);

int32_t CRYPT_CKKS_Ctrl(CRYPT_CKKS_Ctx *ctx, int32_t opt, void *val, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
