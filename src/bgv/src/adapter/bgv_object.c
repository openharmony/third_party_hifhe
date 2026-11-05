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

#include <limits.h>
#include "hifhe_local.h"
#include "hifhe_err_internal.h"
#include "bgv_local.h"
#include "basic/rand.h"
#include "bgv/encoder.h"
#include "bgv/encryptor.h"
#include "bgv/evaluator.h"
#include "rlwe/crt_ops.h"

typedef struct {
    HifheTextMeta meta;

    union {
        Plaintext plaintext;
        Ciphertext ciphertext;
    } value;
} HifheBgvText;

static void BgvTextFree(void *data)
{
    HifheBgvText *t = data;
    if (t == NULL) {
        return;
    }
    if (t->meta.kind == HIFHE_TEXT_PLAIN) {
        BGV_Plaintext_Destroy(&t->value.plaintext);
    } else {
        BGV_Ciphertext_Destroy(&t->value.ciphertext);
    }
    HifheFree(t);
}

static int32_t FinishText(HifheBgvText *text, int32_t ret, void **out)
{
    if (ret != HIFHE_SUCCESS) {
        BgvTextFree(text);
        return ret;
    }
    if (text->meta.kind == HIFHE_TEXT_PLAIN) {
        text->value.plaintext.context = NULL;
    } else {
        text->value.ciphertext.context = NULL;
    }
    *out = text;
    return HIFHE_SUCCESS;
}

static void BgvCtxFree(void *data)
{
    CRYPT_BGV_FreeCtx(data);
}

static void *BgvCtxDup(void *data, void *libCtx)
{
    (void)libCtx;
    return CRYPT_BGV_DupCtx(data);
}

static int32_t BgvCtxNew(HifheParamSnapshot *p, void *libCtx, void **out)
{
    CRYPT_BGV_Ctx *math = CRYPT_BGV_NewCtx(HIFHE_BGV);
    if (math == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    p->math = math;
    math->lutCache = p->config.useLutCache ? &math->para : NULL;
    int32_t ret = BgvUserPara_LoadPreset(&math->para, p->config.paramId);
    if (ret == HIFHE_SUCCESS) {
        ret = Bgv_BuildContext(math);
    }
    if (ret == HIFHE_SUCCESS) {
        ret = BGV_BGVContext_EnsurePlainNtt(&math->bgv.context);
    }
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    p->config.slots = math->bgv.params.rlweParameter.polyDegree;
    p->config.mulDepth = 0;
    *out = BgvCtxDup(p->math, libCtx);
    return *out == NULL ? HIFHE_MEMORY_ERROR : HIFHE_SUCCESS;
}

static int32_t BgvKeyGen(void *data)
{
    return Bgv_Gen(data);
}

static int32_t RawDump(uint32_t kind, const void *value, uint8_t **bytes, uint32_t *len)
{
    uint32_t n = 0;
    int32_t ret = (kind == HIFHE_TEXT_PLAIN) ? BgvSerDes_DumpPlaintext(value, NULL, &n, HIFHE_BGV) :
                                               BgvSerDes_DumpCiphertext(value, NULL, &n, HIFHE_BGV);
    if (ret != HIFHE_BUFFER_TOO_SMALL) {
        return ret;
    }
    *bytes = HifheMalloc(n);
    if (*bytes == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    ret = (kind == HIFHE_TEXT_PLAIN) ? BgvSerDes_DumpPlaintext(value, *bytes, &n, HIFHE_BGV) :
                                       BgvSerDes_DumpCiphertext(value, *bytes, &n, HIFHE_BGV);
    if (ret != HIFHE_SUCCESS) {
        HifheFree(*bytes);
        *bytes = NULL;
        return ret;
    }
    *len = n;
    return 0;
}

static int32_t LoadBody(uint32_t kind, const uint8_t *in, uint32_t len, void *value, BGVContext *ctx)
{
    if (len > HIFHE_MAX_WIRE - 12) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_LIMIT_EXCEEDED);
        return HIFHE_LIMIT_EXCEEDED;
    }
    uint8_t *raw = HifheCalloc(1, len + 12);
    if (raw == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    Hifhe_Put32(raw, HIFHE_SERDES_MAGIC);
    Hifhe_Put32(raw + 4, (uint32_t)HIFHE_BGV);
    uint32_t type = kind == HIFHE_TEXT_PLAIN ? HIFHE_SERDES_TYPE_PLAINTEXT : HIFHE_SERDES_TYPE_CIPHER;
    Hifhe_Put32(raw + 8, 1u | type << 16);
    memcpy(raw + 12, in, len);
    int32_t ret = type == HIFHE_SERDES_TYPE_PLAINTEXT ? BgvSerDes_LoadPlaintext(value, raw, len + 12, ctx) :
                                                        BgvSerDes_LoadCiphertext(value, raw, len + 12, ctx);
    if (ret == HIFHE_SUCCESS) {
        uint32_t expected =
            type == HIFHE_SERDES_TYPE_PLAINTEXT ? BgvSerDes_PlaintextSize(value) : BgvSerDes_CiphertextSize(value);
        if (expected != len + 12) {
            ret = HIFHE_SERDES_FAIL;
            HIFHE_ERR_PUSH_ERROR(ret);
        }
    }
    HifheCleanse(raw, len + 12);
    HifheFree(raw);
    return ret;
}

static int32_t BgvEncode(const HIFHE_Ctx *ctx, const void *values, uint32_t count, void **out)
{
    CRYPT_BGV_Ctx *math = ctx->params->math;
    uint32_t n = math->bgv.params.rlweParameter.polyDegree;
    for (uint32_t i = 0; i < count; i++) {
        if (((const uint64_t *)values)[i] >= math->bgv.params.plainMod) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_VALUE_OUT_OF_RANGE);
            return HIFHE_VALUE_OUT_OF_RANGE;
        }
    }
    if (out == NULL) {
        return 0;
    }
    uint64_t *msg = HifheCalloc(n, sizeof(*msg));
    HifheBgvText *t = HifheCalloc(1, sizeof(*t));
    if (msg == NULL || t == NULL) {
        HifheFree(msg);
        HifheFree(t);
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    t->meta.kind = HIFHE_TEXT_PLAIN;
    memcpy(msg, values, (size_t)count * sizeof(*msg));
    Encoder enc;
    BGV_Encoder_Create(&enc, &math->bgv.context);
    int32_t ret = BGV_Encoder_Encode(&t->value.plaintext, msg, n, &enc);
    HifheCleanse(msg, n * sizeof(*msg));
    HifheFree(msg);
    return FinishText(t, ret, out);
}

static int32_t BgvDecode(const HIFHE_Ctx *ctx, const void *data, void *values, uint32_t *count)
{
    const HifheBgvText *t = data;
    CRYPT_BGV_Ctx *math = ctx->params->math;
    uint32_t n = math->bgv.params.rlweParameter.polyDegree;
    uint64_t *msg = HifheCalloc(n, sizeof(*msg));
    if (msg == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    Plaintext view = t->value.plaintext;
    view.context = &math->bgv.context;
    Encoder enc;
    BGV_Encoder_Create(&enc, &math->bgv.context);
    int32_t ret = BGV_Encoder_Decode(msg, n, &view, &enc);
    if (ret == HIFHE_SUCCESS) {
        memcpy(values, msg, (size_t)n * sizeof(*msg));
        *count = ctx->params->config.slots;
    }
    HifheCleanse(msg, n * sizeof(*msg));
    HifheFree(msg);
    return ret;
}

static HifheBgvText *CiphertextNew(const HIFHE_Ctx *ctx, const HifheBgvText *input)
{
    HifheBgvText *text = HifheCalloc(1, sizeof(*text));
    if (text == NULL) {
        return NULL;
    }
    text->meta.kind = HIFHE_TEXT_CIPHER;
    memcpy(text->meta.keysetId, input != NULL ? input->meta.keysetId : ctx->keysetId, 16);
    text->meta.depth = input != NULL ? input->meta.depth : 0;
    return text;
}

static int32_t BgvEncrypt(const HIFHE_Ctx *ctx, const void *data, void **out)
{
    const HifheBgvText *plaintext = data;
    CRYPT_BGV_Ctx *runtime = ctx->data;
    HifheBgvText *text = CiphertextNew(ctx, NULL);
    if (text == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    Plaintext view = plaintext->value.plaintext;
    view.context = &runtime->bgv.context;
    Encryptor encryptor;
    BGV_Encryptor_CreateFromPublic(&encryptor, &runtime->bgv.pk, NULL, &runtime->bgv.context);
    int32_t ret = BGV_Encryptor_EncryptAsymmetric(&text->value.ciphertext, &view, &encryptor);
    return FinishText(text, ret, out);
}

static int32_t BgvDecrypt(const HIFHE_Ctx *ctx, const void *data, void **out)
{
    const HifheBgvText *ciphertext = data;
    CRYPT_BGV_Ctx *runtime = ctx->data;
    HifheBgvText *text = HifheCalloc(1, sizeof(*text));
    if (text == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    text->meta.kind = HIFHE_TEXT_PLAIN;
    Ciphertext view = ciphertext->value.ciphertext;
    view.context = &runtime->bgv.context;
    Encryptor encryptor;
    BGV_Encryptor_CreateFromSecret(&encryptor, runtime->bgv.keygen.sk, &runtime->bgv.context);
    int32_t ret = BGV_Encryptor_Decrypt(&text->value.plaintext, &view, &encryptor);
    return FinishText(text, ret, out);
}

static int32_t BgvAdd(const HIFHE_Ctx *ctx, const void *para1, const void *para2, void **out)
{
    const HifheBgvText *a = para1, *b = para2;
    CRYPT_BGV_Ctx *runtime = ctx->data;
    BGVContext *math = &runtime->bgv.context;
    HifheBgvText *text = CiphertextNew(ctx, a);
    if (text == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    Ciphertext av = a->value.ciphertext, negative = {0};
    av.context = math;
    Evaluator evaluator;
    BGV_Evaluator_Create(&evaluator, math, NULL, NULL);
    int32_t ret = HIFHE_SUCCESS;
    if (a->meta.flags != 0) {
        ret = BGV_Evaluator_Neg(&negative, &av, &evaluator);
        if (ret == HIFHE_SUCCESS) {
            av = negative;
        }
    }
    if (ret == HIFHE_SUCCESS) {
        if (b == NULL) {
            ret = BGV_Ciphertext_Copy(&text->value.ciphertext, &av);
        } else if (b->meta.kind == HIFHE_TEXT_CIPHER) {
            Ciphertext bv = b->value.ciphertext;
            bv.context = math;
            ret = BGV_Evaluator_AddCtCt(&text->value.ciphertext, &av, &bv, &evaluator);
            if (b->meta.depth > text->meta.depth) {
                text->meta.depth = b->meta.depth;
            }
        } else {
            Plaintext bv = b->value.plaintext;
            bv.context = math;
            ret = BGV_Evaluator_AddCtPt(&text->value.ciphertext, &av, &bv, &evaluator);
        }
    }
    BGV_Ciphertext_Destroy(&negative);
    return FinishText(text, ret, out);
}

static int32_t BgvMul(const HIFHE_Ctx *ctx, const void *para1, const void *para2, void **out)
{
    const HifheBgvText *a = para1, *b = para2;
    if (b->meta.kind != HIFHE_TEXT_PLAIN) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NOT_SUPPORTED);
        return HIFHE_NOT_SUPPORTED;
    }
    CRYPT_BGV_Ctx *runtime = ctx->data;
    BGVContext *math = &runtime->bgv.context;
    HifheBgvText *text = CiphertextNew(ctx, a);
    if (text == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    Ciphertext av = a->value.ciphertext;
    Plaintext bv = b->value.plaintext;
    av.context = math;
    bv.context = math;
    Evaluator evaluator;
    BGV_Evaluator_Create(&evaluator, math, NULL, NULL);
    int32_t ret = BGV_Evaluator_MulCtPt(&text->value.ciphertext, &av, &bv, &evaluator);
    return FinishText(text, ret, out);
}

static int32_t BgvRerandomize(const HIFHE_Ctx *ctx, const void *data, void **out)
{
    const HifheBgvText *ciphertext = data;
    CRYPT_BGV_Ctx *runtime = ctx->data;
    HifheBgvText *text = CiphertextNew(ctx, ciphertext);
    if (text == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    Ciphertext view = ciphertext->value.ciphertext;
    view.context = &runtime->bgv.context;
    Evaluator evaluator;
    BGV_Evaluator_Create(&evaluator, &runtime->bgv.context, NULL, NULL);
    int32_t ret = BGV_Evaluator_Rerandomize(&text->value.ciphertext, &view, &evaluator);
    return FinishText(text, ret, out);
}

/* The id has to name the keys, not the moment they were made, or a context
 * that regenerates them cannot read what the first one wrote. A seed is the
 * only thing that makes BGV keys reproducible, so it is what the id is
 * derived from, under its own label; without one the keys are unrepeatable
 * and so is the id. */
static int32_t BgvKeysetId(const void *data, uint8_t *id, uint32_t idLen)
{
    const CRYPT_BGV_Ctx *runtime = data;
    const uint8_t *seed = BgvContext_GetSeed(&runtime->bgv.context.rlweContext.seedCtx);
    if (seed == NULL) {
        return BgvRand_Drbg(id, idLen);
    }
    BgvLabel lbl;
    const char *label = BgvLabel_Build(&lbl, "keysetid", NULL, 0u, NULL);
    if (label == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_INTERNAL);
        return HIFHE_INTERNAL;
    }
    return BgvRand_Seeded(seed, HIFHE_CTX_SEED_LEN, (const uint8_t *)label, (uint32_t)strlen(label), id, idLen);
}

/* A text carries no context of its own; serializing needs one, so take a copy
 * of the text and point it at the parameter snapshot's. */
static const void *SerializeView(const HIFHE_Ctx *ctx, const void *data, HifheBgvText *view, uint32_t *rawLen)
{
    *view = *(const HifheBgvText *)data;
    CRYPT_BGV_Ctx *math = ctx->params->math;
    const void *value;
    if (view->meta.kind == HIFHE_TEXT_PLAIN) {
        view->value.plaintext.context = &math->bgv.context;
        value = &view->value.plaintext;
        *rawLen = BgvSerDes_PlaintextSize(value);
    } else {
        view->value.ciphertext.context = &math->bgv.context;
        value = &view->value.ciphertext;
        *rawLen = BgvSerDes_CiphertextSize(value);
    }
    return value;
}

/* The interchange format as the Provider writes it: header included, no HiFHE
 * envelope, so depth and the slot index map are not carried. */
static int32_t BgvSerializeNative(const HIFHE_Ctx *ctx, const void *data, uint8_t *out, uint32_t *len)
{
    HifheBgvText view;
    uint32_t need = 0;
    const void *value = SerializeView(ctx, data, &view, &need);
    /* The reader refuses anything past this, so refuse to write it: what one
     * format accepts the other has to be able to hand back. */
    if (need > HIFHE_MAX_WIRE) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_LIMIT_EXCEEDED);
        return HIFHE_LIMIT_EXCEEDED;
    }
    if (out == NULL || *len < need) {
        *len = need;
        if (out != NULL) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_BUFFER_TOO_SMALL);
        }
        return HIFHE_BUFFER_TOO_SMALL;
    }
    *len = need;
    return view.meta.kind == HIFHE_TEXT_PLAIN ? BgvSerDes_DumpPlaintext(value, out, len, HIFHE_BGV) :
                                                BgvSerDes_DumpCiphertext(value, out, len, HIFHE_BGV);
}

static int32_t BgvSerialize(const HIFHE_Ctx *ctx, const void *data, uint8_t *out, uint32_t *len)
{
    HifheBgvText view;
    uint32_t rawLen = 0;
    const void *value = SerializeView(ctx, data, &view, &rawLen);
    const HifheBgvText *t = &view;
    uint32_t caps = t->meta.kind == HIFHE_TEXT_PLAIN ? t->value.plaintext.config.caps : t->value.ciphertext.config.caps;
    uint32_t need = rawLen - 12 + 8;
    if (out == NULL || *len < need) {
        *len = need;
        if (out != NULL) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_BUFFER_TOO_SMALL);
        }
        return HIFHE_BUFFER_TOO_SMALL;
    }
    uint8_t *raw = NULL;
    int32_t ret = RawDump(t->meta.kind, value, &raw, &rawLen);
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    Hifhe_Put32(out, t->meta.depth);
    Hifhe_Put32(out + 4, caps);
    memcpy(out + 8, raw + 12, rawLen - 12);
    HifheCleanse(raw, rawLen);
    HifheFree(raw);
    *len = need;
    return 0;
}

/* Both readers land here: the body is in, the capability bits and the NTT
 * domain are not. A wire payload may be in coefficient form, and a scale or
 * correction factor that is not invertible modulo t would make decoding
 * undefined, so it is rejected here rather than later. */
static int32_t FinishLoad(HifheBgvText *t, CRYPT_BGV_Ctx *math, uint32_t caps, int32_t ret, void **out)
{
    if (ret == HIFHE_SUCCESS && t->meta.kind == HIFHE_TEXT_PLAIN) {
        Plaintext *pt = &t->value.plaintext;
        pt->config.caps = caps;
        if (pt->config.crtConfig.dtype == HIFHE_POLY) {
            CrtPoly view;
            BGV_Plaintext_GetCrtPoly(&view, pt);
            ret = RLWE_CrtPoly_ToNtt(&view);
            pt->config.crtConfig.dtype = HIFHE_NTT;
        }
        if (ret == HIFHE_SUCCESS &&
            Kernel_ModInv(pt->config.scaleFactor % math->bgv.params.plainMod, math->bgv.params.plainMod) == 0) {
            ret = HIFHE_SERDES_FAIL;
            HIFHE_ERR_PUSH_ERROR(ret);
        }
    } else if (ret == HIFHE_SUCCESS) {
        Ciphertext *ct = &t->value.ciphertext;
        ct->config.caps = caps;
        if (ct->config.crtConfig.dtype == HIFHE_POLY) {
            for (uint32_t i = 0; i < ct->config.ciphertextSize && ret == HIFHE_SUCCESS; i++) {
                CrtPoly view;
                BGV_Ciphertext_GetCrtPolyAt(&view, i, ct);
                ret = RLWE_CrtPoly_ToNtt(&view);
            }
            ct->config.crtConfig.dtype = HIFHE_NTT;
        }
        if (ret == HIFHE_SUCCESS &&
            Kernel_ModInv(ct->config.correctionFactor % math->bgv.params.plainMod, math->bgv.params.plainMod) == 0) {
            ret = HIFHE_SERDES_FAIL;
            HIFHE_ERR_PUSH_ERROR(ret);
        }
    }
    return FinishText(t, ret, out);
}

static int32_t BgvDeserialize(const HIFHE_Ctx *ctx, uint32_t kind, const uint8_t *in, uint32_t len, void **out)
{
    if (len < 8) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_SERDES_FAIL);
        return HIFHE_SERDES_FAIL;
    }
    uint32_t depth = Hifhe_Get32(in), caps = Hifhe_Get32(in + 4);
    if (depth > ctx->params->config.mulDepth || (kind == HIFHE_TEXT_PLAIN && depth != 0) || caps != HIFHE_CAP_LUT) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_SERDES_FAIL);
        return HIFHE_SERDES_FAIL;
    }
    CRYPT_BGV_Ctx *math = ctx->params->math;
    HifheBgvText *t = HifheCalloc(1, sizeof(*t));
    if (t == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    t->meta.kind = kind;
    t->meta.depth = depth;
    void *value = kind == HIFHE_TEXT_PLAIN ? (void *)&t->value.plaintext : &t->value.ciphertext;
    int32_t ret = LoadBody(kind, in + 8, len - 8, value, &math->bgv.context);
    return FinishLoad(t, math, caps, ret, out);
}

/* Magic, version and the declared wire type of an interchange buffer. */
static int32_t NativeHeaderPeek(const uint8_t *in, uint32_t len, uint32_t *type)
{
    if (len < 12u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_SERDES_FAIL);
        return HIFHE_SERDES_FAIL;
    }
    uint32_t magic = Hifhe_Get32(in);
    if (magic != HIFHE_SERDES_MAGIC && magic != HIFHE_SERDES_MAGIC_ALT) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_SERDES_FAIL);
        return HIFHE_SERDES_FAIL;
    }
    uint32_t tag = Hifhe_Get32(in + 8);
    if ((tag & 0xffffu) != HIFHE_SERDES_VERSION) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_VERSION_NOT_SUPPORTED);
        return HIFHE_VERSION_NOT_SUPPORTED;
    }
    *type = tag >> 16;
    return HIFHE_SUCCESS;
}

static int32_t BgvKeyDump(const HIFHE_Ctx *ctx, uint32_t which, uint8_t *out, uint32_t *len)
{
    CRYPT_BGV_Ctx *runtime = ctx->data;
    return which == HIFHE_KEY_PUBLIC ? Bgv_DumpPub(runtime, out, len) : Bgv_DumpPrv(runtime, out, len);
}

/* Each loader reads its own wire type, so a buffer holding the other key, or
 * a ciphertext, is refused there rather than sniffed for here. */
static int32_t BgvKeyLoad(HIFHE_Ctx *ctx, uint32_t which, const uint8_t *in, uint32_t len)
{
    return which == HIFHE_KEY_PUBLIC ? Bgv_LoadPub(ctx->data, in, len) : Bgv_LoadPrv(ctx->data, in, len);
}

/* The interchange format, header included. It declares its kind and carries
 * the modulus chain it is on, but neither the depth already spent nor the
 * capability bits, so depth comes from how much of the chain is left and the
 * payload is read as plain slot encoding. A buffer another implementation
 * wrote names its own algorithm in the header; that field is not checked,
 * because the point of this format is that the bodies agree. */
static int32_t BgvDeserializeNative(const HIFHE_Ctx *ctx, const uint8_t *in, uint32_t len, uint32_t *kind, void **out)
{
    uint32_t type = 0;
    int32_t peek = NativeHeaderPeek(in, len, &type);
    if (peek != HIFHE_SUCCESS) {
        return peek;
    }
    if (type == HIFHE_SERDES_TYPE_PLAINTEXT) {
        *kind = HIFHE_TEXT_PLAIN;
    } else if (type == HIFHE_SERDES_TYPE_CIPHER) {
        *kind = HIFHE_TEXT_CIPHER;
    } else {
        HIFHE_ERR_PUSH_ERROR(HIFHE_TEXT_TYPE_MISMATCH);
        return HIFHE_TEXT_TYPE_MISMATCH;
    }
    CRYPT_BGV_Ctx *math = ctx->params->math;
    HifheBgvText *t = HifheCalloc(1, sizeof(*t));
    if (t == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_MEMORY_ERROR);
        return HIFHE_MEMORY_ERROR;
    }
    t->meta.kind = *kind;
    void *value = *kind == HIFHE_TEXT_PLAIN ? (void *)&t->value.plaintext : &t->value.ciphertext;
    int32_t ret = LoadBody(*kind, in + 12, len - 12, value, &math->bgv.context);
    if (ret == HIFHE_SUCCESS && *kind == HIFHE_TEXT_CIPHER) {
        uint32_t chain = math->bgv.params.rlweParameter.cipherMod.size;
        uint32_t left = t->value.ciphertext.config.crtConfig.rnsbase.size;
        t->meta.depth = chain > left ? chain - left : 0u;
        /* The same bound the HiFHE-format reader applies. Without it a
         * ciphertext that has already spent a level would load here and then
         * be refused on the way back in, the two readers disagreeing about
         * one object. */
        if (t->meta.depth > ctx->params->config.mulDepth) {
            ret = HIFHE_SERDES_FAIL;
            HIFHE_ERR_PUSH_ERROR(ret);
        }
    }
    return FinishLoad(t, math, HIFHE_CAP_LUT, ret, out);
}

static int32_t BgvGetOutputSize(const HIFHE_Ctx *ctx, uint32_t op, const void *data, uint32_t *len)
{
    const HifheBgvText *a = data;
    CRYPT_BGV_Ctx *math = ctx->params->math;
    uint32_t n = math->bgv.params.rlweParameter.polyDegree;
    uint32_t l = math->bgv.params.rlweParameter.cipherMod.size;
    uint32_t k = 2;
    if (a != NULL && a->meta.kind == HIFHE_TEXT_CIPHER) {
        l = a->value.ciphertext.config.crtConfig.rnsbase.size;
        k = a->value.ciphertext.config.ciphertextSize;
    }
    if (op == HIFHE_OP_ENCRYPT) {
        k = 2;
    }
    uint32_t raw = (op == 0 || op == HIFHE_OP_DECRYPT) ? BgvSerDes_PlaintextSizeFor(l, l * n) :
                                                         BgvSerDes_CiphertextSizeFor(l, k * l * n);
    /* The interchange format is the raw dump; HiFHE's own replaces its
     * 12-byte header with a 44-byte one plus 8 bytes of its own state. */
    *len = ctx->wireFormat == HIFHE_WIRE_INTERCHANGE ? raw : HIFHE_WIRE_HEADER + 8 + raw - 12;
    return 0;
}

static int32_t BgvCheckCtrlArgs(const HIFHE_Ctx *ctx, int32_t cmd, const HIFHE_HEText *text, const void *value,
    uint32_t valueLen)
{
    uint32_t expectedLen = sizeof(uint32_t);
    switch (cmd) {
        case HIFHE_CTRL_BGV_RERANDOMIZE:
            return HIFHE_SUCCESS;
        case HIFHE_CTRL_GET_OUTPUT_LEN:
            expectedLen = sizeof(HifheOutputLen);
            break;
        case HIFHE_CTRL_BGV_SET_SEED:
            expectedLen = HIFHE_CTX_SEED_LEN;
            break;
        case HIFHE_CTRL_BGV_SET_LUT_CACHE:
        case HIFHE_CTRL_BGV_SET_WIRE_FORMAT:
        case HIFHE_CTRL_BGV_GET_POLY_DEGREE:
        case HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN:
        case HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN:
            break;
        default:
            HIFHE_ERR_PUSH_ERROR(HIFHE_NOT_SUPPORTED);
            return HIFHE_NOT_SUPPORTED;
    }
    if (cmd != HIFHE_CTRL_GET_OUTPUT_LEN && text != NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_INVALID_ARGUMENT);
        return HIFHE_INVALID_ARGUMENT;
    }
    if (value == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (valueLen != expectedLen) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_INVALID_LENGTH);
        return HIFHE_INVALID_LENGTH;
    }
    if (cmd != HIFHE_CTRL_BGV_SET_LUT_CACHE && cmd != HIFHE_CTRL_BGV_SET_WIRE_FORMAT && ctx->params == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_NOT_SET);
        return HIFHE_PARAM_NOT_SET;
    }
    return HIFHE_SUCCESS;
}

static int32_t BgvCtrl(HIFHE_Ctx *ctx, int32_t cmd, const HIFHE_HEText *text, void *value, uint32_t valueLen)
{
    int32_t ret = BgvCheckCtrlArgs(ctx, cmd, text, value, valueLen);
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }
    switch (cmd) {
        case HIFHE_CTRL_BGV_RERANDOMIZE:
            return BgvRerandomize(ctx, text->data, value);
        case HIFHE_CTRL_GET_OUTPUT_LEN: {
            HifheOutputLen *query = value;
            if (query->op > HIFHE_OP_NOISE) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                return HIFHE_PARAM_INVALID;
            }
            return BgvGetOutputSize(ctx, query->op, text != NULL ? text->data : NULL, &query->len);
        }
        case HIFHE_CTRL_BGV_SET_LUT_CACHE: {
            uint32_t enabled;
            memcpy(&enabled, value, sizeof(enabled));
            if (enabled > 1) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_VALUE_OUT_OF_RANGE);
                return HIFHE_VALUE_OUT_OF_RANGE;
            }
            if (ctx->params != NULL) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_BAD_STATE);
                return HIFHE_BAD_STATE;
            }
            ctx->useLutCache = enabled != 0;
            return HIFHE_SUCCESS;
        }
        case HIFHE_CTRL_BGV_SET_WIRE_FORMAT: {
            uint32_t format;
            memcpy(&format, value, sizeof(format));
            if (format != HIFHE_WIRE_HIFHE && format != HIFHE_WIRE_INTERCHANGE) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_VALUE_OUT_OF_RANGE);
                return HIFHE_VALUE_OUT_OF_RANGE;
            }
            ctx->wireFormat = format;
            return HIFHE_SUCCESS;
        }
        case HIFHE_CTRL_BGV_SET_SEED: {
            if (ctx->keyMask != 0) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_BAD_STATE);
                return HIFHE_BAD_STATE;
            }
            CRYPT_BGV_Ctx *runtime = ctx->data;
            return BgvContext_SetSeed(&runtime->bgv.context.rlweContext.seedCtx, value, valueLen);
        }
        case HIFHE_CTRL_BGV_GET_POLY_DEGREE:
            memcpy(value, &ctx->params->config.slots, sizeof(uint32_t));
            return HIFHE_SUCCESS;
        case HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN:
        case HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN: {
            uint32_t result;
            uint32_t op = cmd == HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN ? 0 : HIFHE_OP_ENCRYPT;
            ret = BgvGetOutputSize(ctx, op, NULL, &result);
            if (ret == HIFHE_SUCCESS) {
                memcpy(value, &result, sizeof(result));
            }
            return ret;
        }
        default:
            HIFHE_ERR_PUSH_ERROR(HIFHE_NOT_SUPPORTED);
            return HIFHE_NOT_SUPPORTED;
    }
}

const HifheAlgMethod g_hifheBgvMethod = {.algId = HIFHE_BGV,
                                         .ctxNew = BgvCtxNew,
                                         .ctxDup = BgvCtxDup,
                                         .ctxFree = BgvCtxFree,
                                         .keyGen = BgvKeyGen,
                                         .ctrl = BgvCtrl,
                                         .encode = BgvEncode,
                                         .decode = BgvDecode,
                                         .encrypt = BgvEncrypt,
                                         .decrypt = BgvDecrypt,
                                         .add = BgvAdd,
                                         .mul = BgvMul,
                                         .serialize = BgvSerialize,
                                         .deserialize = BgvDeserialize,
                                         .serializeNative = BgvSerializeNative,
                                         .deserializeNative = BgvDeserializeNative,
                                         .keysetId = BgvKeysetId,
                                         .keyDump = BgvKeyDump,
                                         .keyLoad = BgvKeyLoad,
                                         .textFree = BgvTextFree};
