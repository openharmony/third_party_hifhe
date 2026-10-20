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

#include <string.h>

#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_ckks.h"
#include "crypt_errno.h"
#include "hifhe_err.h"
#include "hifhe_types.h"
#include "ckks_local.h"

static void CKKS_FreeKeys(CRYPT_CKKS_Ctx *ctx)
{
    CKKS_FreePrvKey(ctx->prvKey);
    CKKS_FreePubKey(ctx->pubKey);
    ctx->prvKey = NULL;
    ctx->pubKey = NULL;
}

CRYPT_CKKS_Ctx *CRYPT_CKKS_NewCtx(void)
{
    CRYPT_CKKS_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_CKKS_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    if (BSL_SAL_ReferencesInit(&ctx->references) != 0) {
        BSL_SAL_Free(ctx);
        return NULL;
    }
    return ctx;
}

CRYPT_CKKS_Ctx *CRYPT_CKKS_NewCtxEx(void *libCtx)
{
    CRYPT_CKKS_Ctx *ctx = CRYPT_CKKS_NewCtx();
    if (ctx != NULL) {
        ctx->libCtx = libCtx;
    }
    return ctx;
}

static CRYPT_CKKS_PrvKey *CKKS_DupPrvKey(const CRYPT_CKKS_PrvKey *key)
{
    if (key == NULL) {
        return NULL;
    }
    CRYPT_CKKS_PrvKey *copy = CKKS_NewPrvKey(key->N);
    if (copy == NULL) {
        return NULL;
    }
    for (uint32_t i = 0; i < key->N; i++) {
        BN_Destroy(copy->sx[i]);
        copy->sx[i] = BN_Dup(key->sx[i]);
        if (copy->sx[i] == NULL) {
            CKKS_FreePrvKey(copy);
            return NULL;
        }
    }
    return copy;
}

static CRYPT_CKKS_PubKey *CKKS_DupPubKey(const CRYPT_CKKS_PubKey *key)
{
    if (key == NULL) {
        return NULL;
    }
    CRYPT_CKKS_PubKey *copy = CKKS_NewPubKey(key->N);
    if (copy == NULL) {
        return NULL;
    }
    for (uint32_t i = 0; i < key->N; i++) {
        BN_Destroy(copy->ax[i]);
        BN_Destroy(copy->bx[i]);
        copy->ax[i] = BN_Dup(key->ax[i]);
        copy->bx[i] = BN_Dup(key->bx[i]);
        if (copy->ax[i] == NULL || copy->bx[i] == NULL) {
            CKKS_FreePubKey(copy);
            return NULL;
        }
    }
    return copy;
}

CRYPT_CKKS_Para *CRYPT_CKKS_DupPara(const CRYPT_CKKS_Para *para)
{
    if (para == NULL) {
        return NULL;
    }
    CRYPT_CKKS_Para *copy = BSL_SAL_Calloc(1, sizeof(CRYPT_CKKS_Para));
    if (copy == NULL) {
        return NULL;
    }
    copy->N = para->N;
    copy->qBits = para->qBits;
    copy->pBits = para->pBits;
    copy->sigma = para->sigma;
    copy->slots = para->slots;
    copy->Q = BN_Dup(para->Q);
    copy->P = BN_Dup(para->P);
    uint32_t rootCount = (para->N << 1) + 1;
    copy->ksiPows = BSL_SAL_Malloc(rootCount * sizeof(double complex));
    copy->rotGroup = BSL_SAL_Malloc((para->N >> 1) * sizeof(uint32_t));
    if (copy->Q == NULL || copy->P == NULL || copy->ksiPows == NULL || copy->rotGroup == NULL) {
        CRYPT_CKKS_FreePara(copy);
        return NULL;
    }
    memcpy(copy->ksiPows, para->ksiPows, rootCount * sizeof(double complex));
    memcpy(copy->rotGroup, para->rotGroup, (para->N >> 1) * sizeof(uint32_t));
    return copy;
}

CRYPT_CKKS_Ctx *CRYPT_CKKS_DupCtx(const CRYPT_CKKS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    CRYPT_CKKS_Ctx *copy = CRYPT_CKKS_NewCtxEx(ctx->libCtx);
    if (copy == NULL) {
        return NULL;
    }
    if (ctx->para != NULL) {
        copy->para = CRYPT_CKKS_DupPara(ctx->para);
        if (copy->para == NULL) {
            goto ERR;
        }
    }
    if (ctx->prvKey != NULL) {
        copy->prvKey = CKKS_DupPrvKey(ctx->prvKey);
        if (copy->prvKey == NULL) {
            goto ERR;
        }
    }
    if (ctx->pubKey != NULL) {
        copy->pubKey = CKKS_DupPubKey(ctx->pubKey);
        if (copy->pubKey == NULL) {
            goto ERR;
        }
    }
    return copy;

ERR:
    CRYPT_CKKS_FreeCtx(copy);
    return NULL;
}

void CRYPT_CKKS_FreeCtx(CRYPT_CKKS_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    int references = 0;
    (void)BSL_SAL_AtomicDownReferences(&ctx->references, &references);
    if (references > 0) {
        return;
    }
    BSL_SAL_ReferencesFree(&ctx->references);
    CKKS_FreeKeys(ctx);
    CRYPT_CKKS_FreePara(ctx->para);
    BSL_SAL_Free(ctx);
}

static int32_t CKKS_CheckPara(const CRYPT_CkksPara *para)
{
    if (para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (para->N < CKKS_MIN_N || para->N > CKKS_MAX_N || (para->N & (para->N - 1)) != 0 ||
        para->qBits < CKKS_MIN_LOGQ || para->qBits > CKKS_MAX_LOGQ || para->pBits == 0 ||
        para->pBits >= para->qBits || para->sigma <= 0.0 || para->slots == 0 ||
        para->slots > para->N / 2 || (para->slots & (para->slots - 1)) != 0) {
        return HIFHE_INVALID_ARGUMENT;
    }
    return CRYPT_SUCCESS;
}

CRYPT_CKKS_Para *CRYPT_CKKS_NewPara(const CRYPT_CkksPara *para)
{
    int32_t ret = CKKS_CheckPara(para);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    CRYPT_CKKS_Para *result = BSL_SAL_Calloc(1, sizeof(CRYPT_CKKS_Para));
    if (result == NULL) {
        return NULL;
    }
    result->N = para->N;
    result->qBits = para->qBits;
    result->pBits = para->pBits;
    result->sigma = para->sigma;
    result->slots = para->slots;
    result->Q = BN_Create(para->qBits + 1);
    result->P = BN_Create(para->pBits + 1);
    if (result->Q == NULL || result->P == NULL || BN_SetBit(result->Q, para->qBits) != CRYPT_SUCCESS ||
        BN_SetBit(result->P, para->pBits) != CRYPT_SUCCESS || CKKS_InitFFTParams(result) != CRYPT_SUCCESS) {
        CRYPT_CKKS_FreePara(result);
        return NULL;
    }
    return result;
}

void CRYPT_CKKS_FreePara(CRYPT_CKKS_Para *para)
{
    if (para == NULL) {
        return;
    }
    BN_Destroy(para->Q);
    BN_Destroy(para->P);
    BSL_SAL_Free(para->ksiPows);
    BSL_SAL_Free(para->rotGroup);
    BSL_SAL_Free(para);
}

int32_t CRYPT_CKKS_SetPara(CRYPT_CKKS_Ctx *ctx, const CRYPT_CkksPara *para)
{
    if (ctx == NULL || para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CKKS_CheckPara(para);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_CKKS_Para *newPara = CRYPT_CKKS_NewPara(para);
    if (newPara == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CKKS_FreeKeys(ctx);
    CRYPT_CKKS_FreePara(ctx->para);
    ctx->para = newPara;
    return CRYPT_SUCCESS;
}

static int32_t CKKS_GetUint32(const BSL_Param *params, int32_t key, uint32_t *value)
{
    const BSL_Param *param = BSL_PARAM_FindConstParam(params, key);
    uint32_t len = sizeof(*value);
    if (param == NULL || BSL_PARAM_GetValue(param, key, BSL_PARAM_TYPE_UINT32, value, &len) != 0) {
        return HIFHE_INVALID_ARGUMENT;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CKKS_SetParaEx(CRYPT_CKKS_Ctx *ctx, const BSL_Param *params)
{
    if (ctx == NULL || params == NULL) {
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CkksPara para = {0};
    uint32_t sigmaMilli = 0;
    if (CKKS_GetUint32(params, HIFHE_PARAM_CKKS_N, &para.N) != CRYPT_SUCCESS ||
        CKKS_GetUint32(params, HIFHE_PARAM_CKKS_Q_BITS, &para.qBits) != CRYPT_SUCCESS ||
        CKKS_GetUint32(params, HIFHE_PARAM_CKKS_P_BITS, &para.pBits) != CRYPT_SUCCESS ||
        CKKS_GetUint32(params, HIFHE_PARAM_CKKS_SIGMA_MILLI, &sigmaMilli) != CRYPT_SUCCESS ||
        CKKS_GetUint32(params, HIFHE_PARAM_CKKS_SLOTS, &para.slots) != CRYPT_SUCCESS) {
        return HIFHE_INVALID_ARGUMENT;
    }
    para.sigma = (double)sigmaMilli / 1000.0;
    return CRYPT_CKKS_SetPara(ctx, &para);
}

uint32_t CRYPT_CKKS_GetBits(const CRYPT_CKKS_Ctx *ctx)
{
    return (ctx == NULL || ctx->para == NULL) ? 0 : ctx->para->qBits;
}

CRYPT_CKKS_PrvKey *CKKS_NewPrvKey(uint32_t N)
{
    CRYPT_CKKS_PrvKey *key = BSL_SAL_Calloc(1, sizeof(CRYPT_CKKS_PrvKey));
    if (key == NULL) {
        return NULL;
    }
    key->N = N;
    key->sx = BSL_SAL_Calloc(N, sizeof(BN_BigNum *));
    if (key->sx == NULL) {
        CKKS_FreePrvKey(key);
        return NULL;
    }
    for (uint32_t i = 0; i < N; i++) {
        key->sx[i] = BN_Create(CKKS_BN_WORK_BITS);
        if (key->sx[i] == NULL) {
            CKKS_FreePrvKey(key);
            return NULL;
        }
    }
    return key;
}

CRYPT_CKKS_PubKey *CKKS_NewPubKey(uint32_t N)
{
    CRYPT_CKKS_PubKey *key = BSL_SAL_Calloc(1, sizeof(CRYPT_CKKS_PubKey));
    if (key == NULL) {
        return NULL;
    }
    key->N = N;
    key->ax = BSL_SAL_Calloc(N, sizeof(BN_BigNum *));
    key->bx = BSL_SAL_Calloc(N, sizeof(BN_BigNum *));
    if (key->ax == NULL || key->bx == NULL) {
        CKKS_FreePubKey(key);
        return NULL;
    }
    for (uint32_t i = 0; i < N; i++) {
        key->ax[i] = BN_Create(CKKS_BN_WORK_BITS);
        key->bx[i] = BN_Create(CKKS_BN_WORK_BITS);
        if (key->ax[i] == NULL || key->bx[i] == NULL) {
            CKKS_FreePubKey(key);
            return NULL;
        }
    }
    return key;
}

void CKKS_FreePrvKey(CRYPT_CKKS_PrvKey *key)
{
    if (key == NULL) {
        return;
    }
    if (key->sx != NULL) {
        for (uint32_t i = 0; i < key->N; i++) {
            BN_Destroy(key->sx[i]);
        }
    }
    BSL_SAL_Free(key->sx);
    BSL_SAL_Free(key);
}

void CKKS_FreePubKey(CRYPT_CKKS_PubKey *key)
{
    if (key == NULL) {
        return;
    }
    for (uint32_t i = 0; i < key->N; i++) {
        if (key->ax != NULL) {
            BN_Destroy(key->ax[i]);
        }
        if (key->bx != NULL) {
            BN_Destroy(key->bx[i]);
        }
    }
    BSL_SAL_Free(key->ax);
    BSL_SAL_Free(key->bx);
    BSL_SAL_Free(key);
}

int32_t CRYPT_CKKS_Gen(CRYPT_CKKS_Ctx *ctx)
{
    if (ctx == NULL || ctx->para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    uint32_t N = ctx->para->N;
    int32_t ret = CRYPT_MEM_ALLOC_FAIL;
    CRYPT_CKKS_PrvKey *prv = CKKS_NewPrvKey(N);
    CRYPT_CKKS_PubKey *pub = CKKS_NewPubKey(N);
    CRYPT_CKKS_Poly *error = CKKS_NewPoly(N);
    CRYPT_CKKS_Poly *product = CKKS_NewPoly(N);
    BN_Optimizer *optimizer = BN_OptimizerCreate();
    if (prv == NULL || pub == NULL || error == NULL || product == NULL || optimizer == NULL) {
        goto EXIT;
    }
    BN_OptimizerSetLibCtx(ctx->libCtx, optimizer);
    if ((ret = CKKS_SampleTernary(ctx->libCtx, prv->sx, N)) != CRYPT_SUCCESS ||
        (ret = CKKS_SampleUniform(ctx->libCtx, pub->ax, N, ctx->para->Q)) != CRYPT_SUCCESS ||
        (ret = CKKS_SampleGauss(ctx->libCtx, error->coeffs, N, ctx->para->sigma,
            ctx->para->Q, optimizer)) != CRYPT_SUCCESS ||
        (ret = CKKS_PolyMult(product->coeffs, pub->ax, prv->sx, N,
            ctx->para->Q, optimizer)) != CRYPT_SUCCESS ||
        (ret = CKKS_PolySub(pub->bx, error->coeffs, product->coeffs, N,
            ctx->para->Q, optimizer)) != CRYPT_SUCCESS) {
        goto EXIT;
    }
    CKKS_FreeKeys(ctx);
    ctx->prvKey = prv;
    ctx->pubKey = pub;
    prv = NULL;
    pub = NULL;

EXIT:
    CKKS_FreePrvKey(prv);
    CKKS_FreePubKey(pub);
    CKKS_FreePoly(error);
    CKKS_FreePoly(product);
    BN_OptimizerDestroy(optimizer);
    return ret;
}

static int32_t CKKS_GetConstOctets(const BSL_Param *params, int32_t key, const uint8_t **data, uint32_t *len)
{
    const BSL_Param *param = BSL_PARAM_FindConstParam(params, key);
    if (param == NULL || param->valueType != BSL_PARAM_TYPE_OCTETS || param->value == NULL) {
        return HIFHE_INVALID_ARGUMENT;
    }
    *data = param->value;
    *len = param->valueLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CKKS_GetPrvKeyEx(const CRYPT_CKKS_Ctx *ctx, BSL_Param *params)
{
    if (ctx == NULL || params == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (ctx->prvKey == NULL) {
        return HIFHE_KEY_NOT_SET;
    }
    BSL_Param *param = BSL_PARAM_FindParam(params, HIFHE_PARAM_CKKS_PRVKEY);
    if (param == NULL || param->valueType != BSL_PARAM_TYPE_OCTETS) {
        return HIFHE_INVALID_ARGUMENT;
    }
    uint32_t len = param->valueLen;
    int32_t ret = CKKS_PolyToBytes(ctx->prvKey->sx, ctx->prvKey->N, param->value, &len);
    param->useLen = len;
    return ret;
}

int32_t CRYPT_CKKS_GetPubKeyEx(const CRYPT_CKKS_Ctx *ctx, BSL_Param *params)
{
    if (ctx == NULL || params == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (ctx->pubKey == NULL) {
        return HIFHE_KEY_NOT_SET;
    }
    BSL_Param *param = BSL_PARAM_FindParam(params, HIFHE_PARAM_CKKS_PUBKEY);
    if (param == NULL || param->valueType != BSL_PARAM_TYPE_OCTETS) {
        return HIFHE_INVALID_ARGUMENT;
    }
    uint32_t aLen = 0;
    uint32_t bLen = 0;
    (void)CKKS_PolyToBytes(ctx->pubKey->ax, ctx->pubKey->N, NULL, &aLen);
    (void)CKKS_PolyToBytes(ctx->pubKey->bx, ctx->pubKey->N, NULL, &bLen);
    uint32_t required = sizeof(uint32_t) + aLen + bLen;
    param->useLen = required;
    if (param->value == NULL || param->valueLen < required) {
        return HIFHE_BUFFER_TOO_SMALL;
    }
    uint8_t *out = param->value;
    memcpy(out, &aLen, sizeof(aLen));
    uint32_t capacity = aLen;
    int32_t ret = CKKS_PolyToBytes(ctx->pubKey->ax, ctx->pubKey->N, out + sizeof(aLen), &capacity);
    if (ret == CRYPT_SUCCESS) {
        capacity = bLen;
        ret = CKKS_PolyToBytes(ctx->pubKey->bx, ctx->pubKey->N, out + sizeof(aLen) + aLen, &capacity);
    }
    return ret;
}

int32_t CRYPT_CKKS_SetPrvKeyEx(CRYPT_CKKS_Ctx *ctx, const BSL_Param *params)
{
    if (ctx == NULL || params == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        return HIFHE_INVALID_ARGUMENT;
    }
    const uint8_t *data = NULL;
    uint32_t len = 0;
    int32_t ret = CKKS_GetConstOctets(params, HIFHE_PARAM_CKKS_PRVKEY, &data, &len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_CKKS_PrvKey *key = CKKS_NewPrvKey(ctx->para->N);
    if (key == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CKKS_BytesToPoly(data, len, key->sx, key->N);
    if (ret != CRYPT_SUCCESS) {
        CKKS_FreePrvKey(key);
        return ret;
    }
    CKKS_FreePrvKey(ctx->prvKey);
    ctx->prvKey = key;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CKKS_SetPubKeyEx(CRYPT_CKKS_Ctx *ctx, const BSL_Param *params)
{
    if (ctx == NULL || params == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        return HIFHE_INVALID_ARGUMENT;
    }
    const uint8_t *data = NULL;
    uint32_t len = 0;
    int32_t ret = CKKS_GetConstOctets(params, HIFHE_PARAM_CKKS_PUBKEY, &data, &len);
    if (ret != CRYPT_SUCCESS || len < sizeof(uint32_t)) {
        return HIFHE_DECODE_ERROR;
    }
    uint32_t aLen = 0;
    memcpy(&aLen, data, sizeof(aLen));
    if (aLen > len - sizeof(aLen)) {
        return HIFHE_DECODE_ERROR;
    }
    CRYPT_CKKS_PubKey *key = CKKS_NewPubKey(ctx->para->N);
    if (key == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CKKS_BytesToPoly(data + sizeof(aLen), aLen, key->ax, key->N);
    if (ret == CRYPT_SUCCESS) {
        ret = CKKS_BytesToPoly(data + sizeof(aLen) + aLen, len - sizeof(aLen) - aLen, key->bx, key->N);
    }
    if (ret != CRYPT_SUCCESS) {
        CKKS_FreePubKey(key);
        return ret;
    }
    CKKS_FreePubKey(ctx->pubKey);
    ctx->pubKey = key;
    return CRYPT_SUCCESS;
}
