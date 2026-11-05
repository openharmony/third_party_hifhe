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

#ifndef HIFHE_LOCAL_H
#define HIFHE_LOCAL_H
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "hifhe.h"
#include "bsl_sal.h"
#include "hifhe_mem.h"
#define HIFHE_KEY_PUBLIC  1u
#define HIFHE_KEY_PRIVATE 2u

#define HIFHE_WIRE_HEADER 44u
#define HIFHE_MAX_WIRE    (64u * 1024u * 1024u)
#define HIFHE_TEXT_PLAIN  4u
#define HIFHE_TEXT_CIPHER 3u
#define HIFHE_OP_ENCRYPT  1u
#define HIFHE_OP_DECRYPT  2u
#define HIFHE_OP_ADD      3u
#define HIFHE_OP_MUL      4u
#define HIFHE_OP_NOISE    5u
#define HIFHE_TEXT_NEGATE 1u

typedef enum {
    HIFHE_CTRL_GET_OUTPUT_LEN = -1,
} HifheInternalCmd;

typedef struct {
    uint32_t op;
    uint32_t len;
} HifheOutputLen;

typedef struct HifheParamSnapshot HifheParamSnapshot;
typedef struct HifheAlgMethod HifheAlgMethod;

typedef struct {
    int32_t paramId;
    uint32_t slots;
    uint32_t mulDepth;
    bool useLutCache;
} HifheParamConfig;

struct HifheParamSnapshot {
    atomic_uint references;
    const HifheAlgMethod *method;
    HifheParamConfig config;
    void *math;
};

struct HIFHE_Ctx {
    const HifheAlgMethod *method;
    HifheParamSnapshot *params;
    void *data;
    void *libCtx;
    uint8_t keysetId[16];
    uint32_t keyMask;
    uint32_t wireFormat;
    bool useLutCache;
};

typedef struct {
    uint32_t kind;
    uint32_t flags;
    uint32_t depth;
    uint8_t keysetId[16];
} HifheTextMeta;

struct HIFHE_HEText {
    /* The preset the text was made under. Every parameter the algorithm
     * derives comes from it, so it is the whole of what has to agree. */
    int32_t paramId;
    const HifheAlgMethod *method;
    /* Every algorithm payload starts with HifheTextMeta. */
    HifheTextMeta *data;
};

struct HifheAlgMethod {
    int32_t algId;
    int32_t (*ctxNew)(HifheParamSnapshot *params, void *libCtx, void **out);
    void *(*ctxDup)(void *data, void *libCtx);
    void (*ctxFree)(void *data);
    int32_t (*keyGen)(void *data);
    int32_t (*ctrl)(HIFHE_Ctx *ctx, int32_t cmd, const HIFHE_HEText *text, void *value, uint32_t valueLen);
    int32_t (*encode)(const HIFHE_Ctx *ctx, const void *values, uint32_t count, void **out);
    int32_t (*decode)(const HIFHE_Ctx *ctx, const void *data, void *values, uint32_t *count);
    int32_t (*encrypt)(const HIFHE_Ctx *ctx, const void *plaintext, void **out);
    int32_t (*decrypt)(const HIFHE_Ctx *ctx, const void *ciphertext, void **out);
    int32_t (*add)(const HIFHE_Ctx *ctx, const void *para1, const void *para2, void **out);
    int32_t (*mul)(const HIFHE_Ctx *ctx, const void *para1, const void *para2, void **out);
    int32_t (*serialize)(const HIFHE_Ctx *ctx, const void *data, uint8_t *out, uint32_t *len);
    int32_t (*deserialize)(const HIFHE_Ctx *ctx, uint32_t kind, const uint8_t *in, uint32_t len, void **out);
    /* The same pair in the interchange format, header included. The reader
     * takes the kind from the buffer, since that format declares it. */
    int32_t (*serializeNative)(const HIFHE_Ctx *ctx, const void *data, uint8_t *out, uint32_t *len);
    int32_t (*deserializeNative)(const HIFHE_Ctx *ctx, const uint8_t *in, uint32_t len, uint32_t *kind, void **out);
    /* Fill idLen bytes naming the key origin of the keys data holds. Derived
     * where those keys can be regenerated, random where they cannot. */
    int32_t (*keysetId)(const void *data, uint8_t *id, uint32_t idLen);
    /* One key in or out, named by a HIFHE_KEY_* bit, always in the
     * interchange format. A buffer holding the other key is rejected. */
    int32_t (*keyDump)(const HIFHE_Ctx *ctx, uint32_t which, uint8_t *out, uint32_t *len);
    int32_t (*keyLoad)(HIFHE_Ctx *ctx, uint32_t which, const uint8_t *in, uint32_t len);
    void (*textFree)(void *data);
};
#ifdef HIFHE_ENABLE_BGV
extern const HifheAlgMethod g_hifheBgvMethod;
#endif
void Hifhe_Put32(uint8_t *out, uint32_t value);
uint32_t Hifhe_Get32(const uint8_t *in);
void Hifhe_ParamRetain(HifheParamSnapshot *params);
void Hifhe_ParamRelease(HifheParamSnapshot *params);
int32_t Hifhe_HETextNew(const HIFHE_Ctx *ctx, void *data, HIFHE_HEText **out);
int32_t Hifhe_CheckCompute(const HIFHE_Ctx *ctx, uint32_t op, const HIFHE_HEText *a, const HIFHE_HEText *b);
int32_t Hifhe_CheckText(const HIFHE_Ctx *ctx, const HIFHE_HEText *text, bool flags);
int32_t Hifhe_SetParam(HIFHE_Ctx *ctx, const HifheParamConfig *param);
HIFHE_Ctx *Hifhe_CtxNew(int32_t algId, void *libCtx);
HIFHE_Ctx *Hifhe_CtxDup(const HIFHE_Ctx *ctx);
#endif
