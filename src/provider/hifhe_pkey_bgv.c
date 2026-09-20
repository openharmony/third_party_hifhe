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

#include "hifhe_config.h"

#ifdef HIFHE_BGV
#include "crypt_bgv.h"
#include "crypt_eal_implprovider.h"
#include "hifhe_provider.h"
#include "hifhe_provider_impl.h"

static void *HIFHE_PkeyNewCtxBgv(void *provCtx, int32_t algId)
{
    (void)provCtx;
    if (algId != HIFHE_PKEY_BGV) {
        return NULL;
    }
    return CRYPT_BGV_NewCtx(algId);
}

const CRYPT_EAL_Func g_hifheKeyMgmtBgv[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)HIFHE_PkeyNewCtxBgv},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, (CRYPT_EAL_ImplPkeyMgmtSetParam)CRYPT_BGV_SetParaEx},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)CRYPT_BGV_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)CRYPT_BGV_SetPrvKeyEx},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)CRYPT_BGV_SetPubKeyEx},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)CRYPT_BGV_GetPrvKeyEx},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)CRYPT_BGV_GetPubKeyEx},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)CRYPT_BGV_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_BGV_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)CRYPT_BGV_FreeCtx},
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func g_hifheCipherBgv[] = {
    {CRYPT_EAL_IMPLPKEYCIPHER_ENCRYPT, (CRYPT_EAL_ImplPkeyEncrypt)CRYPT_BGV_Encrypt},
    {CRYPT_EAL_IMPLPKEYCIPHER_DECRYPT, (CRYPT_EAL_ImplPkeyDecrypt)CRYPT_BGV_Decrypt},
    {CRYPT_EAL_IMPLPKEYCIPHER_HEADD, (CRYPT_EAL_ImplPkeyHEAdd)CRYPT_BGV_HEAdd},
    {CRYPT_EAL_IMPLPKEYCIPHER_HEMUL, (CRYPT_EAL_ImplPkeyHEMul)CRYPT_BGV_HEMul},
    {CRYPT_EAL_IMPLPKEYCIPHER_MSG_ENCODE, (CRYPT_EAL_ImplPkeyHEMsgEncode)CRYPT_BGV_HEMsgEncode},
    {CRYPT_EAL_IMPLPKEYCIPHER_MSG_DECODE, (CRYPT_EAL_ImplPkeyHEMsgDecode)CRYPT_BGV_HEMsgDecode},
    CRYPT_EAL_FUNC_END
};
#endif
