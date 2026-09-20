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

#ifndef BGV_LOCAL_H
#define BGV_LOCAL_H

#include <stdint.h>
#include "bsl_params.h"
#include "hifhe_types.h"
#include "hifhe_err.h"
#include "hifhe_provider.h"

#include "crypt_bgv.h"
#include "bgv/bgv.h"
#include "bgv/keygen.h"
#include "bgv/keys.h"
#include "bgv/params_check.h"
#include "basic/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Role state machine.
 *   UNINIT   -> after NewCtx (no para yet)
 *   PARA     -> after SetPara or Ctrl(SET_PARA_BY_ID) (context can be
 *               built lazily by a length query)
 *   KEYPAIR  -> after Gen or SetPrv (sk + pk available)
 *   EVAL     -> after SetPub only (pk available, no sk) */
typedef enum {
    HIFHE_ROLE_UNINIT  = 0,
    HIFHE_ROLE_PARA    = 1,
    HIFHE_ROLE_KEYPAIR = 2,
    HIFHE_ROLE_EVAL    = 3,
} BgvRole;

/* User-supplied parameter cache (holds a copy until BuildContext runs).
 * `set` flips true once SetPara / preset has populated the cache. */
struct BgvUserPara {
    uint32_t     polyDegree;
    uint32_t     plainModBit;
    uint64_t     correctionFactor;
    uint32_t     relinDnum;
    Uint32Vector cipherModBit;   /* owned; empty until a preset or SetPara fills it */
    Uint64Vector cipherMod;      /* owned; when non-empty it overrides the search */
    uint64_t     plainMod;       /* override when non-zero */
    uint8_t      set;

    /* NTT tables for the moduli these parameters resolve to. The fields
     * above determine the whole parameter set, so the tables have a fixed
     * shape and are stored inline. Filled by the first context built from
     * this para and read by every later one. See CRYPT_BGV_NewCtxWithCache. */
    uint32_t     lutPolyDegree;
    uint32_t     lutLimbs;
    Modulus      lutCipherMod[HIFHE_BGV_MAX_CHAIN_LEN];
    Modulus      lutPlainMod;
    /* One allocation holding lutLimbs ciphertext blocks followed by the
     * plaintext block, HIFHE_NTT_TABLE_WORDS(lutPolyDegree) uint64 each. The
     * block is contiguous so it can be read or written in one operation. */
    uint64_t    *lutBlob;
};

/* Bag of lazily-built BGV objects. */
typedef struct {
    BGVParameter  params;
    BGVContext    context;
    KeyGenerator  keygen;
    PublicKey     pk;
    RelinKeys     relinKeys;
    GaloisKeys    galoisKeys;

    uint8_t  haveParams;
    uint8_t  haveContext;
    uint8_t  haveKeygen;
    uint8_t  havePk;
    uint8_t  haveRelin;
    uint8_t  haveGalois;
} BgvState;

struct BGV_Ctx {
    int32_t      algId;         /* HIFHE_PKEY_BGV */
    BgvRole      role;
    BgvUserPara  para;
    /* Source of this context's NTT tables. NULL means it computes its own.
     * Otherwise a caller-owned handle shared with every context created from
     * it. Not freed here. See CRYPT_BGV_NewCtxWithCache. */
    BgvUserPara *lutCache;
    BgvState  bgv;
};

/* ----- BgvUserPara helpers (hifhe_para.c) ----- */
void       BgvUserPara_Init      (BgvUserPara *p);
void       BgvUserPara_Clear     (BgvUserPara *p);
HIFHE_ERROR BgvUserPara_Copy      (BgvUserPara *dst, const BgvUserPara *src);
HIFHE_ERROR BgvUserPara_ParseFromBSL(BgvUserPara *p, const BSL_Param *param);
HIFHE_ERROR BgvUserPara_LoadPreset(BgvUserPara *p, int32_t presetId);
/* Fill p's NTT tables for the moduli param resolved to. Idempotent. A call
 * whose parameters match the tables already held computes nothing. */
HIFHE_ERROR BgvUserPara_EnsureLut(BgvUserPara *p, const BGVParameter *param);
/* Block for the i-th ciphertext modulus, or for the plaintext modulus.
 * Returns NULL when the cache is empty or holds different parameters. */
uint64_t *BgvUserPara_CipherLut(const BgvUserPara *p, uint32_t index);
uint64_t *BgvUserPara_PlainLut (const BgvUserPara *p);

/* ----- BGV state helpers (hifhe_bgv_adapter.c) ----- */
void       Bgv_FreeState(BgvState *st);
/* Deep-copy every built object in `src` into `dst` (`dst` must be zeroed).
 * Will rebuild the context (including NTT tables), and re-point every copied
 * key and ciphertext at the new context.  */
HIFHE_ERROR Bgv_DupState (BgvState *dst, const BgvState *src);
HIFHE_ERROR Bgv_BuildContext(CRYPT_BGV_Ctx *ctx);
HIFHE_ERROR Bgv_Gen           (CRYPT_BGV_Ctx *ctx);
HIFHE_ERROR Bgv_GenRelinKey   (CRYPT_BGV_Ctx *ctx);
HIFHE_ERROR Bgv_GenGaloisKeys (CRYPT_BGV_Ctx *ctx, const uint64_t *elts, uint32_t count);

HIFHE_ERROR Bgv_GetPub  (CRYPT_BGV_Ctx *ctx, BSL_Param *param);
HIFHE_ERROR Bgv_GetPrv  (CRYPT_BGV_Ctx *ctx, BSL_Param *param);
HIFHE_ERROR Bgv_SetPub  (CRYPT_BGV_Ctx *ctx, BSL_Param *param);
HIFHE_ERROR Bgv_SetPrv  (CRYPT_BGV_Ctx *ctx, BSL_Param *param);

HIFHE_ERROR Bgv_Encrypt (CRYPT_BGV_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
                           uint8_t *out, uint32_t *outLen);
HIFHE_ERROR Bgv_Decrypt (CRYPT_BGV_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
                           uint8_t *out, uint32_t *outLen);

HIFHE_ERROR Bgv_HEAdd       (const CRYPT_BGV_Ctx *ctx, const BSL_Param *input,
                               uint8_t *out, uint32_t *outLen);
HIFHE_ERROR Bgv_HEMul       (const CRYPT_BGV_Ctx *ctx, const BSL_Param *input,
                               uint8_t *out, uint32_t *outLen);
HIFHE_ERROR Bgv_HEMsgEncode (const CRYPT_BGV_Ctx *ctx, const BSL_Param *input,
                               uint8_t *out, uint32_t *outLen);
HIFHE_ERROR Bgv_HEMsgDecode (const CRYPT_BGV_Ctx *ctx, const BSL_Param *input,
                               uint8_t *out, uint32_t *outLen);

HIFHE_ERROR Bgv_HERerand      (CRYPT_BGV_Ctx *ctx, BSL_Param *param);
HIFHE_ERROR Bgv_HEModSwitch   (CRYPT_BGV_Ctx *ctx, BSL_Param *param);
HIFHE_ERROR Bgv_HERelinearize (CRYPT_BGV_Ctx *ctx, BSL_Param *param);
HIFHE_ERROR Bgv_HERotateStep  (CRYPT_BGV_Ctx *ctx, BSL_Param *param);
HIFHE_ERROR Bgv_HERotateElt   (CRYPT_BGV_Ctx *ctx, BSL_Param *param);

HIFHE_ERROR Bgv_GetPubKeyLen    (CRYPT_BGV_Ctx *ctx, uint32_t *outLen);
HIFHE_ERROR Bgv_GetPrvKeyLen    (CRYPT_BGV_Ctx *ctx, uint32_t *outLen);
HIFHE_ERROR Bgv_GetCiphertextLen(CRYPT_BGV_Ctx *ctx, uint32_t *outLen);
HIFHE_ERROR Bgv_GetPlaintextLen (CRYPT_BGV_Ctx *ctx, uint32_t *outLen);
HIFHE_ERROR Bgv_GetMsgLen       (CRYPT_BGV_Ctx *ctx, uint32_t *outLen);

/* ----- SerDes prototypes (hifhe_serdes.c) ----- */
int32_t  BgvSerDes_DumpPlaintext (const Plaintext *pt, uint8_t *buf, uint32_t *bufLen, int32_t algId);
int32_t  BgvSerDes_LoadPlaintext (Plaintext *pt, const uint8_t *buf, uint32_t bufLen, BGVContext *ctx);
int32_t  BgvSerDes_DumpCiphertext(const Ciphertext *ct, uint8_t *buf, uint32_t *bufLen, int32_t algId);
int32_t  BgvSerDes_LoadCiphertext(Ciphertext *ct, const uint8_t *buf, uint32_t bufLen, BGVContext *ctx);
int32_t  BgvSerDes_DumpPubKey    (const PublicKey *pk, uint8_t *buf, uint32_t *bufLen, int32_t algId);
int32_t  BgvSerDes_LoadPubKey    (PublicKey *pk, const uint8_t *buf, uint32_t bufLen, BGVContext *ctx);
int32_t  BgvSerDes_DumpPrvKey    (const SecretKey *sk, uint8_t *buf, uint32_t *bufLen, int32_t algId);
int32_t  BgvSerDes_LoadPrvKey    (SecretKey *sk, const uint8_t *buf, uint32_t bufLen, BGVContext *ctx);
uint32_t BgvSerDes_PlaintextSize (const Plaintext *pt);
uint32_t BgvSerDes_CiphertextSize(const Ciphertext *ct);
/* The same layouts from shape alone, so a length query can answer before the
 * object exists. `dataSize` is the uint64 count: ciphertextSize * rns * N. */
uint32_t BgvSerDes_PlaintextSizeFor (uint32_t rns, uint32_t dataSize);
uint32_t BgvSerDes_CiphertextSizeFor(uint32_t rns, uint32_t dataSize);
uint32_t BgvSerDes_PubKeySize    (const PublicKey *pk);
uint32_t BgvSerDes_PrvKeySize    (const SecretKey *sk);

/* ----- SerDes constants (hifhe_serdes.c) -----
 * The layout is the predecessor provider's, so `version` stays 1 and every
 * field keeps its offset.
 */
#define HIFHE_SERDES_MAGIC           0x00474C48u  /* format tag, emitted */
#define HIFHE_SERDES_MAGIC_ALT       0x00454846u  /* "FHE\0", also accepted */
#define HIFHE_SERDES_VERSION         0x0001
#define HIFHE_SERDES_TYPE_PUBKEY     1
#define HIFHE_SERDES_TYPE_PRVKEY     2
#define HIFHE_SERDES_TYPE_PLAINTEXT  3
#define HIFHE_SERDES_TYPE_CIPHER     4

#ifdef __cplusplus
}
#endif

#endif /* BGV_LOCAL_H */
