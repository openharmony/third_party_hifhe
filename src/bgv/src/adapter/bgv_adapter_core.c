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

/*
 * EAL surface (BSL_Param + byte buffers) <-> BGV objects.
 *
 * Inputs are immutable. If `out` is NULL or *outLen is too small,
 * the required size is written to *outLen and HIFHE_BUFFER_TOO_SMALL returned.
 */

#include <string.h>
#include <stdint.h>
#include "hifhe_mem.h"
#include "hifhe_err_internal.h"
#include "crypt_types.h"
#include "crypt_params_key.h"

#include "bgv_local.h"
#include "bgv/keyswitch.h"
#include "bgv/bgv.h"
#include "bgv/plaintext.h"
#include "bgv/ciphertext.h"
#include "bgv/keys.h"
#include "bgv/keygen.h"
#include "bgv/encoder.h"
#include "bgv/encryptor.h"
#include "bgv/evaluator.h"
#include "kernel/prime.h"

/* ---------------- state teardown ---------------- */

void Bgv_FreeState(BgvState *st)
{
    if (st == NULL) {
        return;
    }
    if (st->haveGalois) {
        BGV_GaloisKeys_Destroy(&st->galoisKeys);
        st->haveGalois = 0u;
    }
    if (st->haveRelin) {
        BGV_RelinKeys_Destroy(&st->relinKeys);
        st->haveRelin = 0u;
    }
    if (st->havePk) {
        BGV_Ciphertext_Destroy(&st->pk);
        st->havePk = 0u;
    }
    if (st->haveKeygen) {
        BGV_KeyGenerator_Destroy(&st->keygen);
        st->haveKeygen = 0u;
    }
    if (st->haveContext) {
        BGV_BGVContext_Destroy(&st->context);
        st->haveContext = 0u;
    }
    if (st->haveParams) {
        BGV_BGVParameter_Destroy(&st->params);
        st->haveParams = 0u;
    }
    memset(st, 0, sizeof(*st));
}

/* ---------------- deep copy ---------------- */
static void RepointCt(Ciphertext *ct, BGVContext *ctx)
{
    if (ct != NULL) {
        ct->context = ctx;
    }
}

static void RepointKeyPieces(Ciphertext *pieces, uint32_t count, BGVContext *ctx)
{
    for (uint32_t i = 0; i < count; ++i) {
        RepointCt(&pieces[i], ctx);
    }
}

HIFHE_ERROR Bgv_DupState(BgvState *dst, const BgvState *src)
{
    if (dst == NULL || src == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    memset(dst, 0, sizeof(*dst));
    if (!src->haveContext) {
        return HIFHE_SUCCESS; /* nothing built yet */
    }

    /* A built context always has parameters behind it. */
    int32_t r = BGV_BGVParameter_Copy(&dst->params, &src->params);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    dst->haveParams = 1u;

    uint64_t *const *tables = src->context.rlweContext.ownsTableBuf != 0 ? NULL : src->context.rlweContext.tableBuf;
    r = BGV_BGVContext_CreateWithTables(&dst->context, &dst->params, tables);
    if (r != HIFHE_SUCCESS) {
        goto fail;
    }
    dst->haveContext = 1u;
    if (src->context.ptNttReady != 0 && src->context.ownsPtTableBuf == 0) {
        r = BGV_BGVContext_EnsurePlainNttWith(&dst->context, src->context.ptTableBuf);
        if (r != HIFHE_SUCCESS) {
            goto fail;
        }
    }
    dst->context.useSlotMap = src->context.useSlotMap;
    /* Context creation zeroes the seed store. Without this the duplicate
     * falls back to the DRBG, and the same seed stops giving the same keys. */
    if (src->context.rlweContext.seedCtx.hasSeed) {
        r = BgvContext_SetSeed(&dst->context.rlweContext.seedCtx, src->context.rlweContext.seedCtx.seed,
                               HIFHE_CTX_SEED_LEN);
        if (r != HIFHE_SUCCESS) {
            goto fail;
        }
    }

    /* Key generator + secret key. */
    if (src->haveKeygen) {
        r = BGV_KeyGenerator_Create(&dst->keygen, &dst->context);
        if (r != HIFHE_SUCCESS) {
            goto fail;
        }
        dst->haveKeygen = 1u;
        if (src->keygen.sk != NULL) {
            dst->keygen.sk = BGV_SecretKey_New();
            if (dst->keygen.sk == NULL) {
                r = HIFHE_MEMORY_ERROR;
                goto fail;
            }
            r = BGV_Plaintext_Copy(dst->keygen.sk, src->keygen.sk);
            if (r != HIFHE_SUCCESS) {
                goto fail;
            }
            dst->keygen.sk->context = &dst->context;
        }
    }

    if (src->havePk) {
        r = BGV_Ciphertext_Copy(&dst->pk, &src->pk);
        if (r != HIFHE_SUCCESS) {
            goto fail;
        }
        RepointCt(&dst->pk, &dst->context);
        dst->havePk = 1u;
    }

    if (src->haveRelin) {
        r = BGV_RelinKeys_Copy(&dst->relinKeys, &src->relinKeys);
        if (r != HIFHE_SUCCESS) {
            goto fail;
        }
        dst->relinKeys.context = &dst->context;
        RepointKeyPieces(dst->relinKeys.pieces, dst->relinKeys.dnum, &dst->context);
        dst->haveRelin = 1u;
    }

    if (src->haveGalois) {
        r = BGV_GaloisKeys_Copy(&dst->galoisKeys, &src->galoisKeys);
        if (r != HIFHE_SUCCESS) {
            goto fail;
        }
        dst->galoisKeys.context = &dst->context;
        for (uint32_t i = 0; i < dst->galoisKeys.count; ++i) {
            RepointKeyPieces(dst->galoisKeys.entries[i].pieces, dst->galoisKeys.entries[i].dnum, &dst->context);
        }
        dst->haveGalois = 1u;
    }

    return HIFHE_SUCCESS;

fail:
    Bgv_FreeState(dst);
    return r;
}

/* ---------------- BuildContext ---------------- */

HIFHE_ERROR Bgv_BuildContext(CRYPT_BGV_Ctx *ctx)
{
    if (ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (!ctx->para.set) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_NOT_SET);
        return HIFHE_PARAM_NOT_SET;
    }
    if (ctx->bgv.haveContext) {
        return HIFHE_SUCCESS;
    }

    BgvUserPara *p = &ctx->para;
    if (p->cipherModBit.data == NULL || p->cipherModBit.size == 0u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    /* Reject bad ring / over-long chain / insufficient modulus
     * before any prime search. */
    int32_t r = BGV_Params_Validate(p->polyDegree, p->plainModBit, p->cipherModBit.data, p->cipherModBit.size,
                                    HIFHE_BGV_DEFAULT_SECURITY_LEVEL);
    if (r != HIFHE_SUCCESS) {
        return r;
    }

    /* Cipher moduli: generate if not specified. */
    ModulusVector cipherMod;
    memset(&cipherMod, 0, sizeof(cipherMod));
    if (p->cipherMod.size != 0u) {
        if (p->cipherMod.size != p->cipherModBit.size) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
            return HIFHE_PARAM_INVALID;
        }
        for (uint32_t i = 0; i < p->cipherMod.size; ++i) {
            /* A pinned modulus still has to carry the ring's transform, and
             * has to be prime: a composite can satisfy q = 1 mod 2N and carry
             * a root, but the table builder inverts by Fermat. */
            uint64_t root = 0u;
            if (!Kernel_Prime_IsPrime(p->cipherMod.data[i]) ||
                Kernel_Prime_PrimitiveRoot2N(&root, p->cipherMod.data[i], p->polyDegree) != HIFHE_SUCCESS) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                return HIFHE_PARAM_INVALID;
            }
        }
        r = Uint64Vector_Create(&cipherMod, p->cipherMod.data, p->cipherMod.size);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
    } else {
        r = Uint64Vector_Create(&cipherMod, NULL, p->cipherModBit.size);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        Modulus avoidBuf[HIFHE_BGV_MAX_CHAIN_LEN];
        uint32_t avoidLen = 0u;
        for (uint32_t i = 0; i < p->cipherModBit.size; ++i) {
            Modulus q = 0u;
            r = Kernel_Prime_FindProth(&q, p->cipherModBit.data[i], p->polyDegree, avoidBuf, avoidLen);
            if (r != HIFHE_SUCCESS) {
                Uint64Vector_Destroy(&cipherMod);
                return r;
            }
            cipherMod.data[i] = q;
            if (avoidLen < HIFHE_BGV_MAX_CHAIN_LEN) {
                avoidBuf[avoidLen++] = q;
            }
        }
    }

    /* Plain modulus. */
    Modulus plainMod = p->plainMod;
    if (plainMod == 0u) {
        r = Kernel_Prime_FindProth(&plainMod, p->plainModBit, p->polyDegree, NULL, 0u);
        if (r != HIFHE_SUCCESS) {
            Uint64Vector_Destroy(&cipherMod);
            return r;
        }
    } else if (!BGV_Params_IsPlainModNttFriendly(plainMod, p->polyDegree)) {
        /* A pinned plainMod must still be Proth for this N,
         * else the LUT encoder has no transform. */
        Uint64Vector_Destroy(&cipherMod);
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }

    /* Build parameter + context. */
    r = BGV_BGVParameter_Create(&ctx->bgv.params, plainMod, p->correctionFactor, HIFHE_BGV_DEFAULT_CIPHERTEXT_SIZE,
                                p->polyDegree, &cipherMod);
    Uint64Vector_Destroy(&cipherMod);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    ctx->bgv.haveParams = 1u;

    /* Initialize cache table. */
    uint64_t *cipherLuts[HIFHE_BGV_MAX_CHAIN_LEN];
    uint64_t *const *cipherArg = NULL;
    const BgvUserPara *lut = NULL;
    if (ctx->lutCache != NULL && BgvUserPara_EnsureLut(ctx->lutCache, &ctx->bgv.params, &lut) == HIFHE_SUCCESS) {
        uint32_t limbs = ctx->bgv.params.rlweParameter.cipherMod.size;
        if (limbs <= HIFHE_BGV_MAX_CHAIN_LEN) {
            cipherArg = cipherLuts;
            for (uint32_t i = 0; i < limbs; ++i) {
                cipherLuts[i] = BgvUserPara_CipherLut(lut, i);
                if (cipherLuts[i] == NULL) {
                    cipherArg = NULL;
                    break;
                }
            }
        }
    }

    r = BGV_BGVContext_CreateWithTables(&ctx->bgv.context, &ctx->bgv.params, cipherArg);
    if (r != HIFHE_SUCCESS) {
        BGV_BGVParameter_Destroy(&ctx->bgv.params);
        ctx->bgv.haveParams = 0u;
        return r;
    }
    ctx->bgv.haveContext = 1u;
    /* Otherwise, build plaintext table on the first encode. */
    if (cipherArg != NULL) {
        uint64_t *ptLut = BgvUserPara_PlainLut(lut);
        if (ptLut != NULL) {
            /* A table that cannot be built now is built on the first encode
             * instead, so this failure is not the caller's. The mark takes the
             * codes it reported back off the stack. */
            HIFHE_ERR_SET_MARK();
            (void)BGV_BGVContext_EnsurePlainNttWith(&ctx->bgv.context, ptLut);
            HIFHE_ERR_POP_TO_MARK();
        }
    }
    return HIFHE_SUCCESS;
}

/* ---------------- key generation ---------------- */

/* pk, relin and galois keys all descend from the secret key; a new secret
 * leaves them describing the old one. */
static void Bgv_ClearDerivedKeys(BgvState *st)
{
    if (st->haveGalois) {
        BGV_GaloisKeys_Destroy(&st->galoisKeys);
        st->haveGalois = 0u;
    }
    if (st->haveRelin) {
        BGV_RelinKeys_Destroy(&st->relinKeys);
        st->haveRelin = 0u;
    }
    if (st->havePk) {
        BGV_Ciphertext_Destroy(&st->pk);
        st->havePk = 0u;
    }
}

HIFHE_ERROR Bgv_Gen(CRYPT_BGV_Ctx *ctx)
{
    int32_t r = Bgv_BuildContext(ctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    /* Create keygen and produce sk + pk. */
    if (!ctx->bgv.haveKeygen) {
        r = BGV_KeyGenerator_Create(&ctx->bgv.keygen, &ctx->bgv.context);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        ctx->bgv.haveKeygen = 1u;
    }
    Bgv_ClearDerivedKeys(&ctx->bgv);
    r = BGV_KeyGenerator_GenSecretKey(&ctx->bgv.keygen);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    r = BGV_KeyGenerator_GenPublicKey(&ctx->bgv.pk, &ctx->bgv.keygen);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    ctx->bgv.havePk = 1u;
    ctx->role = HIFHE_ROLE_KEYPAIR;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR Bgv_GenRelinKey(CRYPT_BGV_Ctx *ctx)
{
    if (ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (!ctx->bgv.haveKeygen || ctx->bgv.keygen.sk == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_KEY_NOT_SET);
        return HIFHE_KEY_NOT_SET;
    }
    if (ctx->bgv.haveRelin) {
        BGV_RelinKeys_Destroy(&ctx->bgv.relinKeys);
        ctx->bgv.haveRelin = 0u;
    }
    /* `relinDnum` is digits per RNS limb, taken as a floor: fewer digits
     * than the chain's default would widen the gadget base past what its
     * noise budget allows, so raise it to BGV_KeySwitch_DefaultDigits. */
    uint32_t need = BGV_KeySwitch_DefaultDigits(&ctx->bgv.context.rlweContext.cipherRnsBase,
                                                ctx->bgv.params.rlweParameter.polyDegree, ctx->bgv.params.plainMod);
    uint32_t digits = ctx->para.relinDnum;
    if (digits < need) {
        digits = need;
    }
    int32_t r = BGV_KeyGenerator_GenRelinKey(&ctx->bgv.relinKeys, digits, &ctx->bgv.keygen);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    ctx->bgv.haveRelin = 1u;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR Bgv_GenGaloisKeys(CRYPT_BGV_Ctx *ctx, const uint64_t *elts, uint32_t count)
{
    if (ctx == NULL || elts == NULL || count == 0u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (!ctx->bgv.haveKeygen || ctx->bgv.keygen.sk == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_KEY_NOT_SET);
        return HIFHE_KEY_NOT_SET;
    }
    if (ctx->bgv.haveGalois) {
        BGV_GaloisKeys_Destroy(&ctx->bgv.galoisKeys);
        ctx->bgv.haveGalois = 0u;
    }
    int32_t r = BGV_KeyGenerator_GenGaloisKeys(&ctx->bgv.galoisKeys, elts, count, &ctx->bgv.keygen);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    ctx->bgv.haveGalois = 1u;
    return HIFHE_SUCCESS;
}

/* ---------------- key marshaling ---------------- */

#ifdef HITLS_PROVIDER
static const BSL_Param *FindParamAny(const BSL_Param *arr, int32_t a, int32_t b)
{
    const BSL_Param *p = BSL_PARAM_FindConstParam(arr, a);
    return (p != NULL) ? p : BSL_PARAM_FindConstParam(arr, b);
}

/* Write a ciphertext into a caller-supplied param slot. The serdes dump
 * reports the required size when the buffer is absent or too small, so the
 * size check lives there. */
static HIFHE_ERROR DumpCtParam(const Ciphertext *ct, BSL_Param *p, int32_t algId)
{
    uint32_t len = p->valueLen;
    int32_t r = BgvSerDes_DumpCiphertext(ct, (uint8_t *)p->value, &len, algId);
    p->useLen = len;
    return r;
}
#endif

/* out == NULL asks for the size, as everywhere else. */
HIFHE_ERROR Bgv_DumpPub(CRYPT_BGV_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    if (ctx == NULL || len == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (!ctx->bgv.havePk) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_KEY_NOT_SET);
        return HIFHE_KEY_NOT_SET;
    }
    return BgvSerDes_DumpPubKey(&ctx->bgv.pk, out, len, ctx->algId);
}

#ifdef HITLS_PROVIDER
HIFHE_ERROR Bgv_GetPub(CRYPT_BGV_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    BSL_Param *p = BSL_PARAM_FindParam(param, HIFHE_PARAM_BGV_PUBKEY);
    if (p == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    uint32_t len = p->valueLen;
    int32_t r = Bgv_DumpPub(ctx, (uint8_t *)p->value, &len);
    p->useLen = len;
    return r;
}
#endif

HIFHE_ERROR Bgv_DumpPrv(CRYPT_BGV_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    if (ctx == NULL || len == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (!ctx->bgv.haveKeygen || ctx->bgv.keygen.sk == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_KEY_NOT_SET);
        return HIFHE_KEY_NOT_SET;
    }
    return BgvSerDes_DumpPrvKey(ctx->bgv.keygen.sk, out, len, ctx->algId);
}

#ifdef HITLS_PROVIDER
HIFHE_ERROR Bgv_GetPrv(CRYPT_BGV_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    BSL_Param *p = BSL_PARAM_FindParam(param, HIFHE_PARAM_BGV_PRVKEY);
    if (p == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    uint32_t len = p->valueLen;
    int32_t r = Bgv_DumpPrv(ctx, (uint8_t *)p->value, &len);
    p->useLen = len;
    return r;
}
#endif

HIFHE_ERROR Bgv_LoadPub(CRYPT_BGV_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    if (ctx == NULL || in == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    int32_t r = Bgv_BuildContext(ctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    /* Load into a fresh key first, so a rejected blob leaves the one the
     * context already holds in place. */
    PublicKey fresh;
    (void)memset(&fresh, 0, sizeof(fresh));
    r = BgvSerDes_LoadPubKey(&fresh, in, len, &ctx->bgv.context);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(&fresh);
        return r;
    }
    if (ctx->bgv.havePk) {
        BGV_Ciphertext_Destroy(&ctx->bgv.pk);
    }
    ctx->bgv.pk = fresh;
    ctx->bgv.havePk = 1u;
    if (ctx->role == HIFHE_ROLE_UNINIT || ctx->role == HIFHE_ROLE_PARA) {
        ctx->role = HIFHE_ROLE_EVAL;
    }
    return HIFHE_SUCCESS;
}

#ifdef HITLS_PROVIDER
HIFHE_ERROR Bgv_SetPub(CRYPT_BGV_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    const BSL_Param *p = BSL_PARAM_FindConstParam(param, HIFHE_PARAM_BGV_PUBKEY);
    if (p == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    return Bgv_LoadPub(ctx, (const uint8_t *)p->value, p->valueLen);
}

HIFHE_ERROR Bgv_SetPrv(CRYPT_BGV_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    const BSL_Param *p = BSL_PARAM_FindConstParam(param, HIFHE_PARAM_BGV_PRVKEY);
    if (p == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    return Bgv_LoadPrv(ctx, (const uint8_t *)p->value, p->valueLen);
}
#endif

HIFHE_ERROR Bgv_LoadPrv(CRYPT_BGV_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    if (ctx == NULL || in == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    int32_t r = Bgv_BuildContext(ctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    if (!ctx->bgv.haveKeygen) {
        r = BGV_KeyGenerator_Create(&ctx->bgv.keygen, &ctx->bgv.context);
        if (r != HIFHE_SUCCESS) {
            return r;
        }
        ctx->bgv.haveKeygen = 1u;
    }
    /* Load into a fresh key first. A rejected blob must leave the context's
     * existing key in place rather than replacing it with an empty one that
     * later decryptions would dereference. */
    SecretKey *fresh = BGV_SecretKey_New();
    if (fresh == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    r = BgvSerDes_LoadPrvKey(fresh, in, len, &ctx->bgv.context);
    if (r != HIFHE_SUCCESS) {
        BGV_SecretKey_Free(&fresh);
        return r;
    }
    Bgv_ClearDerivedKeys(&ctx->bgv);
    BGV_SecretKey_Free(&ctx->bgv.keygen.sk);
    ctx->bgv.keygen.sk = fresh;
    if (ctx->role == HIFHE_ROLE_UNINIT || ctx->role == HIFHE_ROLE_PARA) {
        ctx->role = HIFHE_ROLE_KEYPAIR;
    }
    return HIFHE_SUCCESS;
}

/* ---------------- encrypt / decrypt (wire-in, wire-out) ---------------- */

#ifdef HITLS_PROVIDER
HIFHE_ERROR Bgv_Encrypt(CRYPT_BGV_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || data == NULL || outLen == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (!ctx->bgv.havePk && !(ctx->bgv.haveKeygen && ctx->bgv.keygen.sk != NULL)) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_KEY_NOT_SET);
        return HIFHE_KEY_NOT_SET;
    }
    /* Load pt from wire. */
    Plaintext pt;
    memset(&pt, 0, sizeof(pt));
    int32_t r = BgvSerDes_LoadPlaintext(&pt, data, dataLen, &ctx->bgv.context);
    if (r != HIFHE_SUCCESS) {
        return r;
    }

    /* Encrypt (prefer symmetric when sk is available; fall back to asym). */
    Encryptor enc;
    Ciphertext ct;
    memset(&ct, 0, sizeof(ct));
    if (ctx->bgv.haveKeygen && ctx->bgv.keygen.sk != NULL) {
        r = BGV_Encryptor_CreateFromSecret(&enc, ctx->bgv.keygen.sk, &ctx->bgv.context);
        if (r != HIFHE_SUCCESS) {
            BGV_Plaintext_Destroy(&pt);
            return r;
        }
        r = BGV_Encryptor_EncryptSymmetric(&ct, &pt, &enc);
    } else {
        r = BGV_Encryptor_CreateFromPublic(&enc, &ctx->bgv.pk, NULL, &ctx->bgv.context);
        if (r != HIFHE_SUCCESS) {
            BGV_Plaintext_Destroy(&pt);
            return r;
        }
        r = BGV_Encryptor_EncryptAsymmetric(&ct, &pt, &enc);
    }
    BGV_Encryptor_Destroy(&enc);
    BGV_Plaintext_Destroy(&pt);
    if (r != HIFHE_SUCCESS) {
        return r;
    }

    r = BgvSerDes_DumpCiphertext(&ct, out, outLen, ctx->algId);
    BGV_Ciphertext_Destroy(&ct);
    return r;
}

HIFHE_ERROR Bgv_Decrypt(CRYPT_BGV_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || data == NULL || outLen == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (!ctx->bgv.haveKeygen || ctx->bgv.keygen.sk == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_KEY_NOT_SET);
        return HIFHE_KEY_NOT_SET;
    }
    Ciphertext ct;
    memset(&ct, 0, sizeof(ct));
    int32_t r = BgvSerDes_LoadCiphertext(&ct, data, dataLen, &ctx->bgv.context);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    Encryptor enc;
    r = BGV_Encryptor_CreateFromSecret(&enc, ctx->bgv.keygen.sk, &ctx->bgv.context);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(&ct);
        return r;
    }
    Plaintext pt;
    memset(&pt, 0, sizeof(pt));
    r = BGV_Encryptor_Decrypt(&pt, &ct, &enc);
    BGV_Encryptor_Destroy(&enc);
    BGV_Ciphertext_Destroy(&ct);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    r = BgvSerDes_DumpPlaintext(&pt, out, outLen, ctx->algId);
    BGV_Plaintext_Destroy(&pt);
    return r;
}

/* ---------------- HE ops ---------------- */

static HIFHE_ERROR LoadCtParam(Ciphertext *ct, const BSL_Param *p, BGVContext *ctx)
{
    if (p == NULL || p->value == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    return BgvSerDes_LoadCiphertext(ct, (const uint8_t *)p->value, p->valueLen, ctx);
}
static HIFHE_ERROR LoadPtParam(Plaintext *pt, const BSL_Param *p, BGVContext *ctx)
{
    if (p == NULL || p->value == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    return BgvSerDes_LoadPlaintext(pt, (const uint8_t *)p->value, p->valueLen, ctx);
}

HIFHE_ERROR Bgv_HEAdd(const CRYPT_BGV_Ctx *ctx, const BSL_Param *input, uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || input == NULL || outLen == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (!ctx->bgv.haveContext) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_NOT_SET);
        return HIFHE_PARAM_NOT_SET;
    }

    BGVContext *bctx = (BGVContext *)&ctx->bgv.context;
    const BSL_Param *pC1 = FindParamAny(input, HIFHE_PARAM_BGV_CIPHERTEXT1, CRYPT_PARAM_PKEY_HE_CIPHERTEXT1);
    const BSL_Param *pC2 = FindParamAny(input, HIFHE_PARAM_BGV_CIPHERTEXT2, CRYPT_PARAM_PKEY_HE_CIPHERTEXT2);
    const BSL_Param *pPt = BSL_PARAM_FindConstParam(input, HIFHE_PARAM_BGV_PLAINTEXT);
    const BSL_Param *pNeg = BSL_PARAM_FindConstParam(input, HIFHE_PARAM_BGV_NEGATE);
    if (pC1 == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    /* Exactly one second operand. */
    uint32_t nOperand = (pC2 != NULL ? 1u : 0u) + (pPt != NULL ? 1u : 0u) + (pNeg != NULL ? 1u : 0u);
    if (nOperand != 1u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }

    Ciphertext c1;
    memset(&c1, 0, sizeof(c1));
    int32_t r = LoadCtParam(&c1, pC1, bctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }

    Evaluator ev;
    r = BGV_Evaluator_Create(&ev, bctx, NULL, NULL);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(&c1);
        return r;
    }

    Ciphertext dst;
    memset(&dst, 0, sizeof(dst));
    if (pNeg != NULL) {
        r = BGV_Evaluator_Neg(&dst, &c1, &ev);
    } else if (pC2 != NULL) {
        Ciphertext c2;
        memset(&c2, 0, sizeof(c2));
        r = LoadCtParam(&c2, pC2, bctx);
        if (r == HIFHE_SUCCESS) {
            r = BGV_Evaluator_AddCtCt(&dst, &c1, &c2, &ev);
            BGV_Ciphertext_Destroy(&c2);
        }
    } else {
        Plaintext pt;
        memset(&pt, 0, sizeof(pt));
        r = LoadPtParam(&pt, pPt, bctx);
        if (r == HIFHE_SUCCESS) {
            r = BGV_Evaluator_AddCtPt(&dst, &c1, &pt, &ev);
            BGV_Plaintext_Destroy(&pt);
        }
    }
    BGV_Ciphertext_Destroy(&c1);
    BGV_Evaluator_Destroy(&ev);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(&dst);
        return r;
    }
    r = BgvSerDes_DumpCiphertext(&dst, out, outLen, ctx->algId);
    BGV_Ciphertext_Destroy(&dst);
    return r;
}

HIFHE_ERROR Bgv_HEMul(const CRYPT_BGV_Ctx *ctx, const BSL_Param *input, uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || input == NULL || outLen == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (!ctx->bgv.haveContext) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_NOT_SET);
        return HIFHE_PARAM_NOT_SET;
    }
    BGVContext *bctx = (BGVContext *)&ctx->bgv.context;

    const BSL_Param *pC1 = FindParamAny(input, HIFHE_PARAM_BGV_CIPHERTEXT1, CRYPT_PARAM_PKEY_HE_CIPHERTEXT1);
    const BSL_Param *pC2 = FindParamAny(input, HIFHE_PARAM_BGV_CIPHERTEXT2, CRYPT_PARAM_PKEY_HE_CIPHERTEXT2);
    const BSL_Param *pPt = BSL_PARAM_FindConstParam(input, HIFHE_PARAM_BGV_PLAINTEXT);
    const BSL_Param *pConst = BSL_PARAM_FindConstParam(input, HIFHE_PARAM_BGV_CONSTANT);
    if (pC1 == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    /* Exactly one second operand. */
    uint32_t nOperand = (pC2 != NULL ? 1u : 0u) + (pPt != NULL ? 1u : 0u) + (pConst != NULL ? 1u : 0u);
    if (nOperand != 1u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }

    Ciphertext c1;
    memset(&c1, 0, sizeof(c1));
    int32_t r = LoadCtParam(&c1, pC1, bctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }

    const RelinKeys *rlk = ctx->bgv.haveRelin ? &ctx->bgv.relinKeys : NULL;
    Evaluator ev;
    r = BGV_Evaluator_Create(&ev, bctx, rlk, NULL);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(&c1);
        return r;
    }

    Ciphertext dst;
    memset(&dst, 0, sizeof(dst));
    if (pC2 != NULL) {
        Ciphertext c2;
        memset(&c2, 0, sizeof(c2));
        r = LoadCtParam(&c2, pC2, bctx);
        if (r == HIFHE_SUCCESS) {
            Ciphertext big;
            memset(&big, 0, sizeof(big));
            r = BGV_Evaluator_MulCtCt(&big, &c1, &c2, &ev);
            BGV_Ciphertext_Destroy(&c2);
            if (r == HIFHE_SUCCESS) {
                /* The relin key only collapses s^2, applies to a size-3 product.
                 * Wider products pass through and decrypt via the secret-key powers. 
                 */
                if (rlk != NULL && big.config.ciphertextSize == 3u &&
                    big.config.crtConfig.rnsbase.size == rlk->rnsSize) {
                    r = BGV_Evaluator_Relinearize(&dst, &big, &ev);
                } else {
                    r = BGV_Ciphertext_Copy(&dst, &big);
                }
            }
            BGV_Ciphertext_Destroy(&big);
        }
    } else if (pPt != NULL) {
        Plaintext pt;
        memset(&pt, 0, sizeof(pt));
        r = LoadPtParam(&pt, pPt, bctx);
        if (r == HIFHE_SUCCESS) {
            r = BGV_Evaluator_MulCtPt(&dst, &c1, &pt, &ev);
            BGV_Plaintext_Destroy(&pt);
        }
    } else {
        if (pConst->value == NULL || pConst->valueLen != sizeof(uint64_t)) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
            r = HIFHE_PARAM_INVALID;
        } else {
            uint64_t x;
            memcpy(&x, pConst->value, sizeof(x));
            r = BGV_Evaluator_MulCtScalar(&dst, &c1, x, &ev);
        }
    }
    BGV_Ciphertext_Destroy(&c1);
    BGV_Evaluator_Destroy(&ev);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(&dst);
        return r;
    }
    r = BgvSerDes_DumpCiphertext(&dst, out, outLen, ctx->algId);
    BGV_Ciphertext_Destroy(&dst);
    return r;
}

HIFHE_ERROR Bgv_HEMsgEncode(const CRYPT_BGV_Ctx *ctx, const BSL_Param *input, uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || input == NULL || outLen == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (!ctx->bgv.haveContext) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_NOT_SET);
        return HIFHE_PARAM_NOT_SET;
    }
    BGVContext *bctx = (BGVContext *)&ctx->bgv.context;
    const BSL_Param *pMsg = BSL_PARAM_FindConstParam(input, HIFHE_PARAM_BGV_MSG);
    if (pMsg == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    uint32_t N = bctx->rlweContext.parameter->polyDegree;
    if (pMsg->valueLen != N * sizeof(uint64_t)) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }

    Encoder enc;
    int32_t r = BGV_Encoder_Create(&enc, bctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    /* OCTETS promises no alignment, so only pay for a copy when the
     * caller's buffer is actually misaligned. */
    const uint64_t *msg = (const uint64_t *)pMsg->value;
    uint64_t *msgCopy = NULL;
    if (((uintptr_t)pMsg->value % sizeof(uint64_t)) != 0u) {
        msgCopy = (uint64_t *)HifheMalloc(pMsg->valueLen);
        if (msgCopy == NULL) {
            BGV_Encoder_Destroy(&enc);
            HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
            return HIFHE_MEMORY_ERROR;
        }
        memcpy(msgCopy, pMsg->value, pMsg->valueLen);
        msg = msgCopy;
    }
    Plaintext pt;
    memset(&pt, 0, sizeof(pt));
    r = BGV_Encoder_Encode(&pt, msg, N, &enc);
    BGV_Encoder_Destroy(&enc);
    if (msgCopy != NULL) {
        HifheCleanse(msgCopy, pMsg->valueLen);
        HifheFree(msgCopy);
    }
    if (r != HIFHE_SUCCESS) {
        /* Encode allocates its output before the work that can still fail. */
        BGV_Plaintext_Destroy(&pt);
        return r;
    }

    r = BgvSerDes_DumpPlaintext(&pt, out, outLen, ctx->algId);
    BGV_Plaintext_Destroy(&pt);
    return r;
}

HIFHE_ERROR Bgv_HEMsgDecode(const CRYPT_BGV_Ctx *ctx, const BSL_Param *input, uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || input == NULL || outLen == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (!ctx->bgv.haveContext) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_NOT_SET);
        return HIFHE_PARAM_NOT_SET;
    }
    BGVContext *bctx = (BGVContext *)&ctx->bgv.context;
    /* Prefer PLAINTEXT, which the ctrl path supplies alongside MSG as the
     * output buffer. Fall back to MSG, the predecessor's only input slot. */
    const BSL_Param *pPt = FindParamAny(input, HIFHE_PARAM_BGV_PLAINTEXT, HIFHE_PARAM_BGV_MSG);
    if (pPt == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    Plaintext pt;
    memset(&pt, 0, sizeof(pt));
    int32_t r = BgvSerDes_LoadPlaintext(&pt, (const uint8_t *)pPt->value, pPt->valueLen, bctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    uint32_t N = bctx->rlweContext.parameter->polyDegree;
    uint32_t need = N * (uint32_t)sizeof(uint64_t);
    if (out == NULL || *outLen < need) {
        *outLen = need;
        BGV_Plaintext_Destroy(&pt);
        HIFHE_ERR_PUSH_ERROR(HIFHE_BUFFER_TOO_SMALL);
        return HIFHE_BUFFER_TOO_SMALL;
    }
    Encoder enc;
    r = BGV_Encoder_Create(&enc, bctx);
    if (r != HIFHE_SUCCESS) {
        BGV_Plaintext_Destroy(&pt);
        return r;
    }
    uint64_t *dstMsg = (uint64_t *)out;
    uint64_t *outCopy = NULL;
    if (((uintptr_t)out % sizeof(uint64_t)) != 0u) {
        outCopy = (uint64_t *)HifheMalloc(need);
        if (outCopy == NULL) {
            BGV_Encoder_Destroy(&enc);
            BGV_Plaintext_Destroy(&pt);
            HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
            return HIFHE_MEMORY_ERROR;
        }
        dstMsg = outCopy;
    }
    r = BGV_Encoder_Decode(dstMsg, N, &pt, &enc);
    BGV_Encoder_Destroy(&enc);
    BGV_Plaintext_Destroy(&pt);
    if (r == HIFHE_SUCCESS && outCopy != NULL) {
        memcpy(out, outCopy, need);
    }
    HifheFree(outCopy);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    *outLen = need;
    return HIFHE_SUCCESS;
}

/* ---------------- Length queries used by hifhe_ctrl.c ---------------- */

/* Wire sizes on the full chain, i.e. the worst case for any level. The
 * layouts themselves live in bgv_adapter_serdes.c. */
HIFHE_ERROR Bgv_GetPubKeyLen(CRYPT_BGV_Ctx *ctx, uint32_t *outLen)
{
    if (ctx == NULL || outLen == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    int32_t r = Bgv_BuildContext(ctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    uint32_t N = ctx->bgv.context.rlweContext.parameter->polyDegree;
    uint32_t L = ctx->bgv.context.rlweContext.cipherRnsBase.size;
    uint32_t sz = ctx->bgv.context.bgvParameter->rlweParameter.defaultCiphertextSize;
    *outLen = BgvSerDes_CiphertextSizeFor(L, sz * L * N);
    return HIFHE_SUCCESS;
}

HIFHE_ERROR Bgv_GetPrvKeyLen(CRYPT_BGV_Ctx *ctx, uint32_t *outLen)
{
    if (ctx == NULL || outLen == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    int32_t r = Bgv_BuildContext(ctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    uint32_t N = ctx->bgv.context.rlweContext.parameter->polyDegree;
    uint32_t L = ctx->bgv.context.rlweContext.cipherRnsBase.size;
    *outLen = BgvSerDes_PlaintextSizeFor(L, L * N);
    return HIFHE_SUCCESS;
}

HIFHE_ERROR Bgv_GetCiphertextLen(CRYPT_BGV_Ctx *ctx, uint32_t *outLen)
{
    return Bgv_GetPubKeyLen(ctx, outLen); /* same body layout */
}

HIFHE_ERROR Bgv_GetPlaintextLen(CRYPT_BGV_Ctx *ctx, uint32_t *outLen)
{
    return Bgv_GetPrvKeyLen(ctx, outLen);
}

HIFHE_ERROR Bgv_GetMsgLen(CRYPT_BGV_Ctx *ctx, uint32_t *outLen)
{
    if (ctx == NULL || outLen == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    int32_t r = Bgv_BuildContext(ctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    *outLen = ctx->bgv.context.rlweContext.parameter->polyDegree * (uint32_t)sizeof(uint64_t);
    return HIFHE_SUCCESS;
}

/* ---------------- Special HE ops driven via ctrl ---------------- */

/* HE_MODSWITCH / HE_RELINEARIZE / HE_RERANDOMIZE. `val` is a BSL_Param array
 * carrying {CIPHERTEXT1 in, CIPHERTEXT2 out}. */

/* `arg` carries whatever extra input the op takes, NULL for the ops that
 * take none. */
typedef HIFHE_ERROR (*BgvCtOp)(Ciphertext *dst, const Ciphertext *in, const Evaluator *ev, const void *arg);

static HIFHE_ERROR RunCtOp(CRYPT_BGV_Ctx *ctx, BSL_Param *param, BgvCtOp op, const void *arg, const RelinKeys *rlk,
                           const GaloisKeys *glk)
{
    if (ctx == NULL || param == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    int32_t r = Bgv_BuildContext(ctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    BGVContext *bctx = &ctx->bgv.context;
    const BSL_Param *pIn = BSL_PARAM_FindConstParam(param, HIFHE_PARAM_BGV_CIPHERTEXT1);
    BSL_Param *pOut = BSL_PARAM_FindParam(param, HIFHE_PARAM_BGV_CIPHERTEXT2);
    if (pIn == NULL || pOut == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }

    Ciphertext in;
    memset(&in, 0, sizeof(in));
    r = LoadCtParam(&in, pIn, bctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    Evaluator ev;
    r = BGV_Evaluator_Create(&ev, bctx, rlk, glk);
    if (r != HIFHE_SUCCESS) {
        BGV_Ciphertext_Destroy(&in);
        return r;
    }
    Ciphertext dst;
    memset(&dst, 0, sizeof(dst));
    r = op(&dst, &in, &ev, arg);
    BGV_Evaluator_Destroy(&ev);
    BGV_Ciphertext_Destroy(&in);
    if (r == HIFHE_SUCCESS) {
        r = DumpCtParam(&dst, pOut, ctx->algId);
    }
    BGV_Ciphertext_Destroy(&dst);
    return r;
}

static HIFHE_ERROR OpRerand(Ciphertext *dst, const Ciphertext *in, const Evaluator *ev, const void *arg)
{
    (void)arg;
    return BGV_Evaluator_Rerandomize(dst, in, ev);
}

static HIFHE_ERROR OpModSwitch(Ciphertext *dst, const Ciphertext *in, const Evaluator *ev, const void *arg)
{
    (void)arg;
    return BGV_Evaluator_ModSwitch(dst, in, ev);
}

static HIFHE_ERROR OpRelinearize(Ciphertext *dst, const Ciphertext *in, const Evaluator *ev, const void *arg)
{
    (void)arg;
    return BGV_Evaluator_Relinearize(dst, in, ev);
}

/* `arg` is the galois element. */
static HIFHE_ERROR OpRotate(Ciphertext *dst, const Ciphertext *in, const Evaluator *ev, const void *arg)
{
    return BGV_Evaluator_RotateByElt(dst, in, *(const uint64_t *)arg, ev);
}

HIFHE_ERROR Bgv_HERerand(CRYPT_BGV_Ctx *ctx, BSL_Param *param)
{
    return RunCtOp(ctx, param, OpRerand, NULL, NULL, NULL);
}

HIFHE_ERROR Bgv_HEModSwitch(CRYPT_BGV_Ctx *ctx, BSL_Param *param)
{
    return RunCtOp(ctx, param, OpModSwitch, NULL, NULL, NULL);
}

HIFHE_ERROR Bgv_HERelinearize(CRYPT_BGV_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (!ctx->bgv.haveRelin) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NO_RELIN_KEY);
        return HIFHE_NO_RELIN_KEY;
    }
    return RunCtOp(ctx, param, OpRelinearize, NULL, &ctx->bgv.relinKeys, NULL);
}

/* Rotation ctrl: CIPHERTEXT1 in / CIPHERTEXT2 out plus a scalar step or elt,
 * all in the same BSL_Param array. */
HIFHE_ERROR Bgv_HERotateStep(CRYPT_BGV_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (!ctx->bgv.haveGalois) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NO_GALOIS_KEY);
        return HIFHE_NO_GALOIS_KEY;
    }
    int32_t r = Bgv_BuildContext(ctx);
    if (r != HIFHE_SUCCESS) {
        return r;
    }
    const BSL_Param *pStep = BSL_PARAM_FindConstParam(param, HIFHE_PARAM_BGV_ROTATE_STEPS);
    if (pStep == NULL || pStep->value == NULL || pStep->valueLen < sizeof(int32_t)) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    uint64_t elt =
        BGV_GaloisEltForStep(*(const int32_t *)pStep->value, ctx->bgv.context.rlweContext.parameter->polyDegree);
    return RunCtOp(ctx, param, OpRotate, &elt, NULL, &ctx->bgv.galoisKeys);
}

HIFHE_ERROR Bgv_HERotateElt(CRYPT_BGV_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (!ctx->bgv.haveGalois) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NO_GALOIS_KEY);
        return HIFHE_NO_GALOIS_KEY;
    }
    const BSL_Param *pElt = BSL_PARAM_FindConstParam(param, HIFHE_PARAM_BGV_GALOIS_ELTS);
    if (pElt == NULL || pElt->value == NULL || pElt->valueLen < sizeof(uint64_t)) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    uint64_t elt = *(const uint64_t *)pElt->value;
    return RunCtOp(ctx, param, OpRotate, &elt, NULL, &ctx->bgv.galoisKeys);
}
#endif
