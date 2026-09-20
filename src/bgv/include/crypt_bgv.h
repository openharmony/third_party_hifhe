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

#ifndef CRYPT_HIFHE_H
#define CRYPT_HIFHE_H

#include <stdint.h>
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BGV_Ctx CRYPT_BGV_Ctx;

/* ----- lifecycle ------------------------------------------------------ */

/* Parameter set and the NTT tables derived from it. Opaque here, defined in
 * bgv_local.h. Created and released through the calls below. */
typedef struct BgvUserPara BgvUserPara;

void   *CRYPT_BGV_NewCtx(int32_t algId);

/* As NewCtx, with the context taking its NTT tables from *cache instead of
 * computing them. A context build then costs a few pointer stores rather than
 * a root-of-unity search and a twiddle fill per modulus.
 *
 * If *cache is NULL an empty handle is allocated and returned through it. The
 * handle stays empty until the first context built from it settles its
 * parameters. A non-NULL *cache is reused as is.
 *
 * The handle belongs to the caller. It must outlive every context created
 * from it and is released with CRYPT_BGV_FreeCache. Contexts sharing a handle must
 * agree on their parameters. One that does not match computes its own
 * tables. */
void   *CRYPT_BGV_NewCtxWithCache(int32_t algId, BgvUserPara **cache);
void    CRYPT_BGV_FreeCache(BgvUserPara *cache);
void    CRYPT_BGV_FreeCtx(CRYPT_BGV_Ctx *ctx);
CRYPT_BGV_Ctx *CRYPT_BGV_DupCtx(CRYPT_BGV_Ctx *src);

/* ----- configuration -------------------------------------------------- */

int32_t CRYPT_BGV_SetParaEx(CRYPT_BGV_Ctx *ctx, const BSL_Param *param);
int32_t CRYPT_BGV_Ctrl   (CRYPT_BGV_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen);

/* ----- key generation ------------------------------------------------- */

int32_t CRYPT_BGV_Gen(CRYPT_BGV_Ctx *ctx);

int32_t CRYPT_BGV_GetPubKeyEx(CRYPT_BGV_Ctx *ctx, BSL_Param *param);
int32_t CRYPT_BGV_GetPrvKeyEx(CRYPT_BGV_Ctx *ctx, BSL_Param *param);
int32_t CRYPT_BGV_SetPubKeyEx(CRYPT_BGV_Ctx *ctx, BSL_Param *param);
int32_t CRYPT_BGV_SetPrvKeyEx(CRYPT_BGV_Ctx *ctx, BSL_Param *param);

/* ----- encryption / decryption --------------------------------------- */

int32_t CRYPT_BGV_Encrypt(CRYPT_BGV_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
                         uint8_t *out, uint32_t *outLen);
int32_t CRYPT_BGV_Decrypt(CRYPT_BGV_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
                         uint8_t *out, uint32_t *outLen);

/* ----- homomorphic operations (dispatch by BSL_Param keys) ----------- */

int32_t CRYPT_BGV_HEAdd      (const CRYPT_BGV_Ctx *ctx, const BSL_Param *input,
                             uint8_t *out, uint32_t *outLen);
int32_t CRYPT_BGV_HEMul      (const CRYPT_BGV_Ctx *ctx, const BSL_Param *input,
                             uint8_t *out, uint32_t *outLen);

/* ----- message <-> plaintext codec ------------------------------------ */

int32_t CRYPT_BGV_HEMsgEncode(const CRYPT_BGV_Ctx *ctx, const BSL_Param *input,
                             uint8_t *out, uint32_t *outLen);
int32_t CRYPT_BGV_HEMsgDecode(const CRYPT_BGV_Ctx *ctx, const BSL_Param *input,
                             uint8_t *out, uint32_t *outLen);

#ifdef __cplusplus
}
#endif

#endif /* CRYPT_HIFHE_H */
