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

/* EAL entry points; dispatch to Bgv_* and BgvCtrl_Dispatch. */

#include <string.h>
#include "bsl_sal.h"
#include "crypt_types.h"

#include "bgv_local.h"

void *CRYPT_BGV_NewCtx(int32_t algId)
{
    if (algId != HIFHE_PKEY_BGV) return NULL;
    CRYPT_BGV_Ctx *ctx = (CRYPT_BGV_Ctx *)BSL_SAL_Calloc(1u, sizeof(CRYPT_BGV_Ctx));
    if (ctx == NULL) return NULL;
    ctx->algId = algId;
    ctx->role  = HIFHE_ROLE_UNINIT;
    BgvUserPara_Init(&ctx->para);
    return ctx;
}

void *CRYPT_BGV_NewCtxWithCache(int32_t algId, BgvUserPara **cache)
{
    if (cache == NULL) return NULL;
    CRYPT_BGV_Ctx *ctx = (CRYPT_BGV_Ctx *)CRYPT_BGV_NewCtx(algId);
    if (ctx == NULL) return NULL;
    if (*cache == NULL) {
        BgvUserPara *fresh = (BgvUserPara *)BSL_SAL_Malloc((uint32_t)sizeof(BgvUserPara));
        if (fresh == NULL) {
            CRYPT_BGV_FreeCtx(ctx);
            return NULL;
        }
        BgvUserPara_Init(fresh);
        *cache = fresh;
    }
    /* Held for the context's lifetime. CRYPT_BGV_FreeCtx does not free it. */
    ctx->lutCache = *cache;
    return ctx;
}

void CRYPT_BGV_FreeCache(BgvUserPara *cache)
{
    if (cache == NULL) return;
    BgvUserPara_Clear(cache);
    BSL_SAL_Free(cache);
}

void CRYPT_BGV_FreeCtx(CRYPT_BGV_Ctx *ctx)
{
    if (ctx == NULL) return;
    Bgv_FreeState(&ctx->bgv);
    BgvUserPara_Clear(&ctx->para);
    BSL_SAL_Free(ctx);
}

/* Deep copy ctx */
CRYPT_BGV_Ctx *CRYPT_BGV_DupCtx(CRYPT_BGV_Ctx *src)
{
    if (src == NULL) return NULL;
    /* Also deep copy cached table */
    CRYPT_BGV_Ctx *dst = (CRYPT_BGV_Ctx *)CRYPT_BGV_NewCtx(src->algId);
    if (dst == NULL) return NULL;
    if (BgvUserPara_Copy(&dst->para, &src->para) != HIFHE_SUCCESS) {
        CRYPT_BGV_FreeCtx(dst);
        return NULL;
    }
    if (Bgv_DupState(&dst->bgv, &src->bgv) != HIFHE_SUCCESS) {
        CRYPT_BGV_FreeCtx(dst);
        return NULL;
    }
    dst->role = src->role;
    return dst;
}

int32_t CRYPT_BGV_SetParaEx(CRYPT_BGV_Ctx *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) return HIFHE_NULL_INPUT;
    int32_t r = BgvUserPara_ParseFromBSL(&ctx->para, param);
    if (r != HIFHE_SUCCESS) return r;
    /* Bgv_BuildContext returns early once a context exists, so anything built
     * on the previous parameters would keep being used while the ctrl surface
     * reports the new ring. */
    Bgv_FreeState(&ctx->bgv);
    ctx->role = HIFHE_ROLE_PARA;
    return HIFHE_SUCCESS;
}

int32_t BgvCtrl_Dispatch(CRYPT_BGV_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen);
int32_t CRYPT_BGV_Ctrl(CRYPT_BGV_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL) return HIFHE_NULL_INPUT;
    return BgvCtrl_Dispatch(ctx, cmd, val, valLen);
}

int32_t CRYPT_BGV_Gen(CRYPT_BGV_Ctx *ctx)
{
    return Bgv_Gen(ctx);
}

int32_t CRYPT_BGV_GetPubKeyEx(CRYPT_BGV_Ctx *ctx, BSL_Param *param) { return Bgv_GetPub(ctx, param); }
int32_t CRYPT_BGV_GetPrvKeyEx(CRYPT_BGV_Ctx *ctx, BSL_Param *param) { return Bgv_GetPrv(ctx, param); }
int32_t CRYPT_BGV_SetPubKeyEx(CRYPT_BGV_Ctx *ctx, BSL_Param *param) { return Bgv_SetPub(ctx, param); }
int32_t CRYPT_BGV_SetPrvKeyEx(CRYPT_BGV_Ctx *ctx, BSL_Param *param) { return Bgv_SetPrv(ctx, param); }

int32_t CRYPT_BGV_Encrypt(CRYPT_BGV_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
                         uint8_t *out, uint32_t *outLen)
{
    return Bgv_Encrypt(ctx, data, dataLen, out, outLen);
}
int32_t CRYPT_BGV_Decrypt(CRYPT_BGV_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
                         uint8_t *out, uint32_t *outLen)
{
    return Bgv_Decrypt(ctx, data, dataLen, out, outLen);
}
int32_t CRYPT_BGV_HEAdd(const CRYPT_BGV_Ctx *ctx, const BSL_Param *input,
                       uint8_t *out, uint32_t *outLen)
{
    return Bgv_HEAdd(ctx, input, out, outLen);
}
int32_t CRYPT_BGV_HEMul(const CRYPT_BGV_Ctx *ctx, const BSL_Param *input,
                       uint8_t *out, uint32_t *outLen)
{
    return Bgv_HEMul(ctx, input, out, outLen);
}
int32_t CRYPT_BGV_HEMsgEncode(const CRYPT_BGV_Ctx *ctx, const BSL_Param *input,
                             uint8_t *out, uint32_t *outLen)
{
    return Bgv_HEMsgEncode(ctx, input, out, outLen);
}
int32_t CRYPT_BGV_HEMsgDecode(const CRYPT_BGV_Ctx *ctx, const BSL_Param *input,
                             uint8_t *out, uint32_t *outLen)
{
    return Bgv_HEMsgDecode(ctx, input, out, outLen);
}

