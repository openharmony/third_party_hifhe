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

#include "hifhe_mem.h"
#include "hifhe_err_internal.h"
#include "crypt_eal_implprovider.h"
#include "hifhe_err.h"
#include "hifhe.h"
#include "hifhe_provider_impl.h"

static CRYPT_EAL_AlgInfo g_hifheKeyMgmtAlgs[] = {
#ifdef HIFHE_ENABLE_BGV
    {HIFHE_BGV, g_hifheKeyMgmtBgv, HIFHE_PROVIDER_ATTR},
#endif
    CRYPT_EAL_ALGINFO_END,
};

static CRYPT_EAL_AlgInfo g_hifheCipher[] = {
#ifdef HIFHE_ENABLE_BGV
    {HIFHE_BGV, g_hifheCipherBgv, HIFHE_PROVIDER_ATTR},
#endif
    CRYPT_EAL_ALGINFO_END,
};

static int32_t HIFHE_ProviderQuery(void *provCtx, int32_t operaId, CRYPT_EAL_AlgInfo **algInfos)
{
    if (provCtx == NULL || algInfos == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (operaId == CRYPT_EAL_OPERAID_KEYMGMT) {
        *algInfos = g_hifheKeyMgmtAlgs;
        return HIFHE_SUCCESS;
    }
    if (operaId == CRYPT_EAL_OPERAID_ASYMCIPHER) {
        *algInfos = g_hifheCipher;
        return HIFHE_SUCCESS;
    }
    HIFHE_ERR_PUSH_ERROR(HIFHE_NOT_SUPPORTED);
    return HIFHE_NOT_SUPPORTED;
}

static void HIFHE_ProviderFree(void *provCtx)
{
    HifheFree(provCtx);
}

static int32_t HIFHE_ProviderCtrl(void *provCtx, int32_t cmd, void *val, uint32_t valLen)
{
    (void)provCtx;
    (void)cmd;
    (void)val;
    (void)valLen;
    return HIFHE_SUCCESS;
}

static CRYPT_EAL_Func g_hifheProviderFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, HIFHE_ProviderQuery},
    {CRYPT_EAL_PROVCB_FREE, HIFHE_ProviderFree},
    {CRYPT_EAL_PROVCB_CTRL, HIFHE_ProviderCtrl},
    CRYPT_EAL_FUNC_END,
};

int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param, CRYPT_EAL_Func *capFuncs,
                               CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    (void)param;
    if (mgrCtx == NULL || capFuncs == NULL || outFuncs == NULL || provCtx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }

    CRYPT_EAL_ProvMgrCtrlCb mgrCtrl = NULL;
    for (uint32_t i = 0; capFuncs[i].id != 0; i++) {
        if (capFuncs[i].id == CRYPT_EAL_CAP_MGRCTXCTRL) {
            mgrCtrl = (CRYPT_EAL_ProvMgrCtrlCb)capFuncs[i].func;
            break;
        }
    }
    if (mgrCtrl == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NOT_SUPPORTED);
        return HIFHE_NOT_SUPPORTED;
    }

    HIFHE_ProvCtx *ctx = HifheCalloc(1, sizeof(HIFHE_ProvCtx));
    if (ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    int32_t ret = mgrCtrl(mgrCtx, CRYPT_EAL_MGR_GETLIBCTX, &ctx->libCtx, 0);
    if (ret != HIFHE_SUCCESS) {
        HifheFree(ctx);
        return ret;
    }
    ctx->handle = mgrCtx;
    *outFuncs = g_hifheProviderFuncs;
    *provCtx = ctx;
    return HIFHE_SUCCESS;
}
