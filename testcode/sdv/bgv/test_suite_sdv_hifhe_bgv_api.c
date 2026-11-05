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

/* BEGIN_HEADER */
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "hifhe.h"
#include "crypt_eal_init.h"
#include "crypt_eal_rand.h"
#include "test.h"
/* END_HEADER */

/* The fixed part of HiFHE's own wire format, ahead of the algorithm's body.
 * The cases below reach into that body by offset. */
#define WIRE_HEADER 44u

static HIFHE_Ctx *Configured(void)
{
    HIFHE_Ctx *ctx = HIFHE_New(HIFHE_BGV);
    if (ctx == NULL) {
        return NULL;
    }
    if (HIFHE_SetParaById(ctx, HIFHE_BGV_4096_44x2_17BIT) != HIFHE_SUCCESS) {
        HIFHE_Free(ctx);
        return NULL;
    }
    return ctx;
}

static uint8_t *Serialized(const HIFHE_Ctx *ctx, const HIFHE_HEText *text, uint32_t *len)
{
    *len = 0;
    if (HIFHE_Serialize(ctx, text, NULL, len) != HIFHE_BUFFER_TOO_SMALL) {
        return NULL;
    }
    uint8_t *bytes = malloc(*len);
    if (bytes == NULL) {
        return NULL;
    }
    if (HIFHE_Serialize(ctx, text, bytes, len) != HIFHE_SUCCESS) {
        free(bytes);
        return NULL;
    }
    return bytes;
}

/* One fixed seed, so two contexts derive one keypair and one key origin. */
static uint8_t g_wireSeed[32] = {
    0x77, 0x69, 0x72, 0x65, 0x5f, 0x66, 0x6d, 0x74, /* "wire_fmt" */
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
};

static void Put32(uint8_t *out, uint32_t value)
{
    for (uint32_t i = 0; i < 4; i++) {
        out[i] = (uint8_t)(value >> (8 * i));
    }
}

static void *ErrorPeekWorker(void *arg)
{
    const int *options = arg;
    int32_t (*peek)(const char **, uint32_t *) = options[0] == 0 ? HIFHE_ErrPeekError : HIFHE_ErrPeekLastError;
    HIFHE_Ctx *ctx = NULL;
    uint32_t previousLine = 0;
    const char sentinel[] = "unchanged";

    /* A new thread starts with an empty stack without using internal APIs. */
    for (uint32_t phase = 0; phase < 4; phase++) {
        if (phase == 1) {
            ASSERT_EQ(HIFHE_KeyGen(NULL), HIFHE_NULL_INPUT);
        } else if (phase == 2) {
            ASSERT_EQ(HIFHE_SetMemFuncs(NULL, free), HIFHE_PARAM_INVALID);
        } else if (phase == 3) {
            ctx = HIFHE_New(HIFHE_BGV);
            ASSERT_TRUE(ctx != NULL);
            HIFHE_Free(ctx);
            ctx = NULL;
        }
        int32_t expected = phase == 0 ? HIFHE_SUCCESS : HIFHE_NULL_INPUT;
        const char *expectedFile = "hifhe_api.c";
        if (options[0] != 0 && phase >= 2) {
            expected = HIFHE_PARAM_INVALID;
            expectedFile = "hifhe_mem.c";
        }
        for (uint32_t repeat = 0; repeat < 3; repeat++) {
            const char *file = sentinel;
            uint32_t line = UINT32_MAX;
            ASSERT_EQ(peek((options[1] & 1) != 0 ? &file : NULL, (options[1] & 2) != 0 ? &line : NULL), expected);
            if (phase == 0 || (options[1] & 1) == 0) {
                ASSERT_TRUE(file == sentinel);
            } else {
                ASSERT_TRUE(file != NULL);
                ASSERT_EQ(strcmp(file, expectedFile), 0);
            }
            if (phase == 0 || (options[1] & 2) == 0) {
                ASSERT_EQ(line, UINT32_MAX);
            } else {
                ASSERT_TRUE(line > 0 && line < UINT32_MAX);
                if (repeat != 0 || phase == 3 || (phase == 2 && options[0] == 0)) {
                    ASSERT_EQ(line, previousLine);
                }
                previousLine = line;
            }
        }
    }
EXIT:
    HIFHE_Free(ctx);
    return NULL;
}

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_ERROR_PEEK_API_TC001(int last, int outputs)
{
    pthread_t worker;
    int started = 0;
    int options[] = {last, outputs};
    const char *firstFile = NULL, *lastFile = NULL, *file = NULL;
    uint32_t firstLine = 0, lastLine = 0, line = 0;

    ASSERT_EQ(HIFHE_KeyGen(NULL), HIFHE_NULL_INPUT);
    int32_t firstError = HIFHE_ErrPeekError(&firstFile, &firstLine);
    int32_t lastError = HIFHE_ErrPeekLastError(&lastFile, &lastLine);
    ASSERT_TRUE(firstFile != NULL && lastFile != NULL);
    ASSERT_EQ(pthread_create(&worker, NULL, ErrorPeekWorker, options), 0);
    started = 1;
    ASSERT_EQ(pthread_join(worker, NULL), 0);
    started = 0;
    ASSERT_EQ(HIFHE_ErrPeekError(&file, &line), firstError);
    ASSERT_TRUE(file != NULL);
    ASSERT_EQ(strcmp(file, firstFile), 0);
    ASSERT_EQ(line, firstLine);
    ASSERT_EQ(HIFHE_ErrPeekLastError(&file, &line), lastError);
    ASSERT_TRUE(file != NULL);
    ASSERT_EQ(strcmp(file, lastFile), 0);
    ASSERT_EQ(line, lastLine);
EXIT:
    if (started != 0) {
        (void)pthread_join(worker, NULL);
    }
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_CONTEXT_CTRL_API_TC001(int cmd)
{
    HIFHE_Ctx *ctx = NULL;
    HIFHE_HEText *pt = NULL, *ct = NULL, *decoded = NULL;
    uint8_t seed[32] = {1};
    uint32_t value = 1, count = 4096;
    uint64_t output[4096];
    void *arg = cmd == HIFHE_CTRL_BGV_SET_SEED ? (void *)seed : (void *)&value;
    uint32_t argLen = cmd == HIFHE_CTRL_BGV_SET_SEED ? sizeof(seed) : sizeof(value);

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    ctx = HIFHE_New(HIFHE_BGV);
    ASSERT_TRUE(ctx != NULL);
    if (cmd != HIFHE_CTRL_BGV_SET_LUT_CACHE) {
        ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, arg, argLen), HIFHE_PARAM_NOT_SET);
        ASSERT_EQ(HIFHE_SetParaById(ctx, HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
    }
    ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, arg, argLen), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(NULL, cmd, NULL, arg, argLen), HIFHE_NULL_INPUT);
    ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, NULL, argLen), HIFHE_NULL_INPUT);
    ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, arg, argLen - 1), HIFHE_INVALID_LENGTH);
    ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, arg, argLen + 1), HIFHE_INVALID_LENGTH);
    if (cmd == HIFHE_CTRL_BGV_SET_LUT_CACHE) {
        value = 2;
        ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, arg, argLen), HIFHE_VALUE_OUT_OF_RANGE);
        value = 0;
        ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, arg, argLen), HIFHE_SUCCESS);
        value = 1;
        ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, arg, argLen), HIFHE_SUCCESS);
        ASSERT_EQ(HIFHE_SetParaById(ctx, -1), HIFHE_PARAM_ID_INVALID);
        ASSERT_EQ(HIFHE_SetParaById(ctx, HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
        ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, arg, argLen), HIFHE_BAD_STATE);
    }
    ASSERT_EQ(HIFHE_KeyGen(ctx), HIFHE_SUCCESS);
    if (cmd == HIFHE_CTRL_BGV_SET_SEED) {
        ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, NULL, arg, argLen), HIFHE_BAD_STATE);
    }
    uint64_t message = 7;
    uint32_t actual = 0;
    ASSERT_EQ(HIFHE_Encode(ctx, &message, 1, &pt), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(ctx, pt, &ct), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(ctx, cmd, pt, arg, argLen), HIFHE_INVALID_ARGUMENT);
    if (cmd == HIFHE_CTRL_BGV_GET_POLY_DEGREE) {
        ASSERT_EQ(value, 4096);
    } else if (cmd == HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN) {
        ASSERT_EQ(HIFHE_Serialize(ctx, pt, NULL, &actual), HIFHE_BUFFER_TOO_SMALL);
        ASSERT_EQ(value, actual);
    } else if (cmd == HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN) {
        ASSERT_EQ(HIFHE_Serialize(ctx, ct, NULL, &actual), HIFHE_BUFFER_TOO_SMALL);
        ASSERT_EQ(value, actual);
    }
    ASSERT_EQ(HIFHE_Decrypt(ctx, ct, &decoded), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Decode(ctx, decoded, output, &count), HIFHE_SUCCESS);
    ASSERT_EQ(count, 4096);
    for (uint32_t i = 0; i < count; i++) {
        ASSERT_EQ(output[i], i == 0 ? message : 0);
    }
EXIT:
    HIFHE_HETextFree(pt);
    HIFHE_HETextFree(ct);
    HIFHE_HETextFree(decoded);
    HIFHE_Free(ctx);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_WORKFLOW_API_TC001(void)
{
    HIFHE_Ctx *a = NULL, *b = NULL;
    HIFHE_HEText *p = NULL, *c = NULL, *q = NULL, *bp = NULL, *d = NULL, *mp = NULL, *m = NULL;
    HIFHE_HEText *noised = NULL, *reply = NULL, *decoded = NULL;
    uint8_t *wire = NULL;
    uint64_t *values = NULL;
    uint32_t len = 0;

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    a = Configured();
    b = Configured();
    ASSERT_TRUE(a != NULL && b != NULL);
    ASSERT_TRUE(HIFHE_SetParaById(a, HIFHE_BGV_4096_44x2_17BIT) == HIFHE_PARAM_REPEATED_SET);
    ASSERT_EQ(HIFHE_KeyGen(a), HIFHE_SUCCESS);
    uint64_t query[] = {1, 2, 3, 4}, bucket[] = {1, 4, 2, 6}, mask[] = {2, 3, 4, 5};
    ASSERT_EQ(HIFHE_Encode(a, query, 4, &p), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(a, p, &c), HIFHE_SUCCESS);
    wire = Serialized(a, c, &len);
    ASSERT_TRUE(wire != NULL);
    ASSERT_TRUE(len > WIRE_HEADER && memcmp(wire, "HFHE", 4) == 0);
    /* The version says what the rest of the header looks like, so a buffer
     * from an earlier layout is refused rather than read at the wrong
     * offsets. */
    uint8_t version = wire[4];
    wire[4] = 1u;
    ASSERT_TRUE(HIFHE_Deserialize(b, wire, len, &q) == HIFHE_VERSION_NOT_SUPPORTED);
    ASSERT_TRUE(q == NULL);
    wire[4] = version;
    ASSERT_EQ(HIFHE_Deserialize(b, wire, len, &q), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_NEGATE, q, NULL, 0), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encode(b, bucket, 4, &bp), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Add(b, q, bp, &d), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encode(b, mask, 4, &mp), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Mul(b, d, mp, &m), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_RERANDOMIZE, m, &noised, sizeof(noised)), HIFHE_SUCCESS);
    free(wire);
    wire = Serialized(b, noised, &len);
    ASSERT_TRUE(wire != NULL);
    ASSERT_EQ(HIFHE_Deserialize(a, wire, len, &reply), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Decrypt(a, reply, &decoded), HIFHE_SUCCESS);
    uint32_t count = 0;
    ASSERT_TRUE(HIFHE_Decode(a, decoded, NULL, &count) == HIFHE_BUFFER_TOO_SMALL);
    values = calloc(count, sizeof(*values));
    ASSERT_TRUE(values != NULL);
    ASSERT_EQ(HIFHE_Decode(a, decoded, values, &count), HIFHE_SUCCESS);
    ASSERT_TRUE(values[0] == 0 && values[1] == 6 && values[2] == 65533 && values[3] == 10);
    HIFHE_Free(b);
    b = NULL;
    free(wire);
    wire = Serialized(a, noised, &len);
    ASSERT_TRUE(wire != NULL);
EXIT:
    HIFHE_HETextFree(p);
    HIFHE_HETextFree(c);
    HIFHE_HETextFree(q);
    HIFHE_HETextFree(bp);
    HIFHE_HETextFree(d);
    HIFHE_HETextFree(mp);
    HIFHE_HETextFree(m);
    HIFHE_HETextFree(noised);
    HIFHE_HETextFree(reply);
    HIFHE_HETextFree(decoded);
    HIFHE_Free(a);
    HIFHE_Free(b);
    free(values);
    free(wire);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_TRAILING_BYTES_API_TC001(void)
{
    HIFHE_Ctx *ctx = NULL;
    uint8_t *bytes = NULL;
    HIFHE_HEText *p = NULL, *copy = NULL;

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    ctx = Configured();
    ASSERT_TRUE(ctx != NULL);
    uint64_t value = 7;
    uint32_t len = 0;
    ASSERT_EQ(HIFHE_Encode(ctx, &value, 1, &p), HIFHE_SUCCESS);
    ASSERT_TRUE(HIFHE_Serialize(ctx, p, NULL, &len) == HIFHE_BUFFER_TOO_SMALL);
    bytes = calloc(len + 1, 1);
    ASSERT_TRUE(bytes != NULL);
    ASSERT_EQ(HIFHE_Serialize(ctx, p, bytes, &len), HIFHE_SUCCESS);
    len++;
    for (uint32_t i = 0; i < 4; i++) {
        bytes[12 + i] = (uint8_t)(len >> (i * 8));
    }
    ASSERT_TRUE(HIFHE_Deserialize(ctx, bytes, len, &copy) == HIFHE_SERDES_FAIL);
    ASSERT_TRUE(copy == NULL);
EXIT:
    HIFHE_HETextFree(copy);
    HIFHE_HETextFree(p);
    HIFHE_Free(ctx);
    free(bytes);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_OUTPUT_OVERLAP_API_TC001(void)
{
    HIFHE_Ctx *ctx = NULL;
    uint8_t *bytes = NULL;
    uint64_t *values = NULL;
    HIFHE_HEText *pt = NULL;

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    ctx = Configured();
    ASSERT_TRUE(ctx != NULL);
    uint64_t value = 7;
    uint32_t len = 0;
    ASSERT_EQ(HIFHE_Encode(ctx, &value, 1, &pt), HIFHE_SUCCESS);
    ASSERT_TRUE(HIFHE_Serialize(ctx, pt, NULL, &len) == HIFHE_BUFFER_TOO_SMALL);
    bytes = malloc(len);
    ASSERT_TRUE(bytes != NULL);
    uint32_t *outLen = (uint32_t *)bytes;
    *outLen = len;
    ASSERT_TRUE(HIFHE_Serialize(ctx, pt, bytes, outLen) == HIFHE_BUFFER_OVERLAP);
    values = calloc(4096, sizeof(*values));
    ASSERT_TRUE(values != NULL);
    uint32_t *count = (uint32_t *)(values + 4095);
    *count = 4096;
    ASSERT_EQ(HIFHE_Decode(ctx, pt, values, count), HIFHE_BUFFER_OVERLAP);
    ASSERT_EQ(*count, 4096);
EXIT:
    HIFHE_HETextFree(pt);
    HIFHE_Free(ctx);
    free(bytes);
    free(values);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_UINT64_API_TC001(void)
{
    HIFHE_Ctx *ctx = NULL;
    HIFHE_HEText *pt = NULL;
    uint64_t values[] = {0, 1, 65536, 7};
    uint64_t invalid[] = {65537, (UINT64_C(1) << 32) + 1, UINT64_MAX};
    uint64_t *decoded = NULL;
    uint32_t count = 0;

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    ctx = Configured();
    ASSERT_TRUE(ctx != NULL);
    for (uint32_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        ASSERT_EQ(HIFHE_Encode(ctx, &invalid[i], 1, &pt), HIFHE_VALUE_OUT_OF_RANGE);
        ASSERT_TRUE(pt == NULL);
    }
    ASSERT_EQ(HIFHE_Encode(ctx, values, 4, &pt), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Decode(ctx, pt, NULL, &count), HIFHE_BUFFER_TOO_SMALL);
    ASSERT_EQ(count, 4096);
    decoded = malloc((count + 1) * sizeof(*decoded));
    ASSERT_TRUE(decoded != NULL);
    memset(decoded, 0xff, (count + 1) * sizeof(*decoded));
    count--;
    ASSERT_EQ(HIFHE_Decode(ctx, pt, decoded, &count), HIFHE_BUFFER_TOO_SMALL);
    ASSERT_EQ(count, 4096);
    for (uint32_t i = 0; i <= count; i++) {
        ASSERT_TRUE(decoded[i] == UINT64_MAX);
    }
    count++;
    ASSERT_EQ(HIFHE_Decode(ctx, pt, decoded, &count), HIFHE_SUCCESS);
    ASSERT_EQ(count, 4096);
    for (uint32_t i = 0; i < count; i++) {
        ASSERT_EQ(decoded[i], i < 4 ? values[i] : 0);
    }
    ASSERT_TRUE(decoded[count] == UINT64_MAX);
EXIT:
    HIFHE_HETextFree(pt);
    HIFHE_Free(ctx);
    free(decoded);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_PRESET_API_TC001(void)
{
    HIFHE_Ctx *a = NULL, *b = NULL;
    HIFHE_HEText *pt = NULL;

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    ASSERT_TRUE(HIFHE_New(0) == NULL);
    a = HIFHE_New(HIFHE_BGV);
    ASSERT_TRUE(a != NULL);
    ASSERT_TRUE(HIFHE_SetParaById(a, -1) == HIFHE_PARAM_ID_INVALID);
    ASSERT_EQ(HIFHE_SetParaById(a, HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);
    ASSERT_TRUE(HIFHE_SetParaById(a, HIFHE_BGV_8192_44x4_17BIT) == HIFHE_PARAM_REPEATED_SET);
    b = HIFHE_New(HIFHE_BGV);
    ASSERT_TRUE(b != NULL);
    ASSERT_EQ(HIFHE_SetParaById(b, HIFHE_BGV_8192_44x4_17BIT), HIFHE_SUCCESS);
    uint64_t input = 8;
    ASSERT_EQ(HIFHE_Encode(a, &input, 1, &pt), HIFHE_SUCCESS);
    uint32_t len = 0;
    ASSERT_TRUE(HIFHE_Serialize(b, pt, NULL, &len) == HIFHE_PARAM_MISMATCH);
EXIT:
    HIFHE_Free(a);
    HIFHE_Free(b);
    HIFHE_HETextFree(pt);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_CTRL_API_TC001(void)
{
    HIFHE_Ctx *a = NULL, *b = NULL;
    uint8_t *before = NULL, *after = NULL;
    HIFHE_HEText *pt = NULL, *ct = NULL, *result = NULL, *copy = NULL, *noise = NULL;

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    a = Configured();
    b = Configured();
    ASSERT_TRUE(a != NULL && b != NULL);
    ASSERT_EQ(HIFHE_KeyGen(a), HIFHE_SUCCESS);
    uint64_t value = 7;
    uint32_t len = 0, control = 0;
    ASSERT_EQ(HIFHE_Encode(a, &value, 1, &pt), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(a, pt, &ct), HIFHE_SUCCESS);
    ASSERT_TRUE(HIFHE_Serialize(a, ct, NULL, &len) == HIFHE_BUFFER_TOO_SMALL);
    before = malloc(len);
    after = malloc(len);
    ASSERT_TRUE(before != NULL && after != NULL);
    ASSERT_EQ(HIFHE_Serialize(a, ct, before, &len), HIFHE_SUCCESS);
    ASSERT_TRUE(HIFHE_Ctrl(a, (int32_t)0x6A02, ct, NULL, 0) == HIFHE_NOT_SUPPORTED);
    ASSERT_TRUE(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_NEGATE, ct, &control, sizeof(control)) == HIFHE_INVALID_ARGUMENT);
    ASSERT_TRUE(HIFHE_Ctrl(NULL, HIFHE_CTRL_BGV_SET_NEGATE, ct, NULL, 0) == HIFHE_NULL_INPUT);
    ASSERT_TRUE(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_NEGATE, NULL, NULL, 0) == HIFHE_NULL_INPUT);
    ASSERT_TRUE(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_NEGATE, ct, NULL, 1) == HIFHE_INVALID_LENGTH);
    ASSERT_TRUE(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_NEGATE, pt, NULL, 0) == HIFHE_TEXT_TYPE_MISMATCH);
    ASSERT_EQ(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_NEGATE, ct, NULL, 0), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_NEGATE, ct, NULL, 0), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Add(b, ct, pt, &result), HIFHE_SUCCESS);
    uint32_t untouched = len;
    ASSERT_TRUE(HIFHE_Serialize(a, ct, after, &untouched) == HIFHE_BAD_STATE);
    ASSERT_TRUE(untouched == len);
    ASSERT_TRUE(HIFHE_Add(b, ct, pt, &result) == HIFHE_OUTPUT_NOT_EMPTY);
    ASSERT_TRUE(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_RERANDOMIZE, ct, &noise, sizeof(noise)) == HIFHE_BAD_STATE);
    ASSERT_TRUE(noise == NULL);
    ASSERT_EQ(HIFHE_Deserialize(a, before, len, &copy), HIFHE_SUCCESS);
    ASSERT_TRUE(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_RERANDOMIZE, copy, NULL, sizeof(noise)) == HIFHE_NULL_INPUT);
    ASSERT_TRUE(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_RERANDOMIZE, copy, &noise, 0) == HIFHE_INVALID_LENGTH);
    ASSERT_TRUE(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_RERANDOMIZE, pt, &noise, sizeof(noise)) == HIFHE_TEXT_TYPE_MISMATCH);
    ASSERT_TRUE(noise == NULL);
    ASSERT_TRUE(HIFHE_Ctrl(b, HIFHE_CTRL_BGV_RERANDOMIZE, copy, &result, sizeof(result)) == HIFHE_OUTPUT_NOT_EMPTY);
    ASSERT_EQ(HIFHE_Serialize(a, copy, after, &len), HIFHE_SUCCESS);
    ASSERT_TRUE(memcmp(before, after, len) == 0);
EXIT:
    HIFHE_HETextFree(noise);
    HIFHE_HETextFree(pt);
    HIFHE_HETextFree(ct);
    HIFHE_HETextFree(copy);
    HIFHE_HETextFree(result);
    HIFHE_Free(a);
    HIFHE_Free(b);
    free(before);
    free(after);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_COEFFICIENT_API_TC001(void)
{
    HIFHE_Ctx *ctx = NULL;
    uint8_t *wire = NULL;
    uint64_t *values = NULL;
    HIFHE_HEText *pt = NULL, *coeff = NULL, *ct = NULL, *decoded = NULL;

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    ctx = Configured();
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HIFHE_KeyGen(ctx), HIFHE_SUCCESS);
    uint64_t one = 1;
    uint32_t len = 0;
    ASSERT_EQ(HIFHE_Encode(ctx, &one, 1, &pt), HIFHE_SUCCESS);
    ASSERT_TRUE(HIFHE_Serialize(ctx, pt, NULL, &len) == HIFHE_BUFFER_TOO_SMALL);
    wire = malloc(len);
    ASSERT_TRUE(wire != NULL);
    ASSERT_EQ(HIFHE_Serialize(ctx, pt, wire, &len), HIFHE_SUCCESS);
    Put32(wire + WIRE_HEADER + 8 + 16, 0);
    uint32_t dataOffset = WIRE_HEADER + 8 + 20 + 16;
    memset(wire + dataOffset, 0, len - dataOffset);
    wire[dataOffset] = 1;
    wire[dataOffset + 4096 * 8] = 1;
    ASSERT_EQ(HIFHE_Deserialize(ctx, wire, len, &coeff), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(ctx, coeff, &ct), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Decrypt(ctx, ct, &decoded), HIFHE_SUCCESS);
    uint32_t count = 4096;
    values = calloc(count, sizeof(*values));
    ASSERT_TRUE(values != NULL);
    ASSERT_EQ(HIFHE_Decode(ctx, decoded, values, &count), HIFHE_SUCCESS);
    for (uint32_t i = 0; i < count; i++) {
        ASSERT_TRUE(values[i] == 1);
    }
EXIT:
    HIFHE_HETextFree(pt);
    HIFHE_HETextFree(coeff);
    HIFHE_HETextFree(ct);
    HIFHE_HETextFree(decoded);
    HIFHE_Free(ctx);
    free(wire);
    free(values);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_WIRE_INTERCHANGE_API_TC001(void)
{
    HIFHE_Ctx *w = NULL, *r = NULL;
    HIFHE_HEText *pt = NULL, *ct = NULL, *back = NULL, *plain = NULL;
    uint8_t *wire = NULL;
    uint64_t *values = NULL;
    uint32_t len = 0, expect = 0;
    uint32_t interchange = HIFHE_WIRE_INTERCHANGE;
    uint64_t msg[] = {7, 11, 13, 17};

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    w = Configured();
    r = Configured();
    ASSERT_TRUE(w != NULL && r != NULL);
    ASSERT_EQ(HIFHE_Ctrl(w, HIFHE_CTRL_BGV_SET_SEED, NULL, g_wireSeed, sizeof(g_wireSeed)), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(r, HIFHE_CTRL_BGV_SET_SEED, NULL, g_wireSeed, sizeof(g_wireSeed)), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_KeyGen(w), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_KeyGen(r), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(w, HIFHE_CTRL_BGV_SET_WIRE_FORMAT, NULL, &interchange, sizeof(interchange)), HIFHE_SUCCESS);

    /* The length query has to follow the selected format, or a caller sizing a
     * buffer from it writes short. */
    ASSERT_EQ(HIFHE_Ctrl(w, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, NULL, &expect, sizeof(expect)), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encode(w, msg, 4, &pt), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(w, pt, &ct), HIFHE_SUCCESS);
    wire = Serialized(w, ct, &len);
    ASSERT_TRUE(wire != NULL);
    ASSERT_EQ(len, expect);
    /* The interchange header, not HiFHE's own. */
    ASSERT_TRUE(memcmp(wire, "HLG\0", 4) == 0);

    /* A second context, keys of its own from the same seed, reads it. */
    ASSERT_EQ(HIFHE_Deserialize(r, wire, len, &back), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Decrypt(r, back, &plain), HIFHE_SUCCESS);
    uint32_t count = 0;
    ASSERT_TRUE(HIFHE_Decode(r, plain, NULL, &count) == HIFHE_BUFFER_TOO_SMALL);
    values = calloc(count, sizeof(*values));
    ASSERT_TRUE(values != NULL);
    ASSERT_EQ(HIFHE_Decode(r, plain, values, &count), HIFHE_SUCCESS);
    ASSERT_TRUE(values[0] == 7 && values[1] == 11 && values[2] == 13 && values[3] == 17);
EXIT:
    HIFHE_HETextFree(pt);
    HIFHE_HETextFree(ct);
    HIFHE_HETextFree(back);
    HIFHE_HETextFree(plain);
    HIFHE_Free(w);
    HIFHE_Free(r);
    free(wire);
    free(values);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}

/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_KEY_ORIGIN_API_TC001(void)
{
    HIFHE_Ctx *a = NULL, *same = NULL, *other = NULL;
    HIFHE_HEText *pt = NULL, *ct = NULL, *back = NULL, *plain = NULL, *reject = NULL;
    uint8_t *wire = NULL;
    uint64_t *values = NULL;
    uint32_t len = 0;
    uint8_t otherSeed[32];
    uint64_t msg[] = {3, 5, 7, 9};

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    memcpy(otherSeed, g_wireSeed, sizeof(otherSeed));
    otherSeed[0] ^= 0xffu;

    a = Configured();
    same = Configured();
    other = Configured();
    ASSERT_TRUE(a != NULL && same != NULL && other != NULL);
    ASSERT_EQ(HIFHE_Ctrl(a, HIFHE_CTRL_BGV_SET_SEED, NULL, g_wireSeed, sizeof(g_wireSeed)), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(same, HIFHE_CTRL_BGV_SET_SEED, NULL, g_wireSeed, sizeof(g_wireSeed)), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Ctrl(other, HIFHE_CTRL_BGV_SET_SEED, NULL, otherSeed, sizeof(otherSeed)), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_KeyGen(a), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_KeyGen(same), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_KeyGen(other), HIFHE_SUCCESS);

    ASSERT_EQ(HIFHE_Encode(a, msg, 4, &pt), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(a, pt, &ct), HIFHE_SUCCESS);
    wire = Serialized(a, ct, &len);
    ASSERT_TRUE(wire != NULL);
    ASSERT_TRUE(memcmp(wire, "HFHE", 4) == 0);

    /* One seed, one key, one origin: a separate context reads it. */
    ASSERT_EQ(HIFHE_Deserialize(same, wire, len, &back), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Decrypt(same, back, &plain), HIFHE_SUCCESS);
    uint32_t count = 0;
    ASSERT_TRUE(HIFHE_Decode(same, plain, NULL, &count) == HIFHE_BUFFER_TOO_SMALL);
    values = calloc(count, sizeof(*values));
    ASSERT_TRUE(values != NULL);
    ASSERT_EQ(HIFHE_Decode(same, plain, values, &count), HIFHE_SUCCESS);
    ASSERT_TRUE(values[0] == 3 && values[1] == 5 && values[2] == 7 && values[3] == 9);

    /* A different seed is a different key, and the origin still says so. */
    ASSERT_TRUE(HIFHE_Deserialize(other, wire, len, &reject) == HIFHE_KEY_MISMATCH);
    ASSERT_TRUE(reject == NULL);
EXIT:
    HIFHE_HETextFree(pt);
    HIFHE_HETextFree(ct);
    HIFHE_HETextFree(back);
    HIFHE_HETextFree(plain);
    HIFHE_HETextFree(reject);
    HIFHE_Free(a);
    HIFHE_Free(same);
    HIFHE_Free(other);
    free(wire);
    free(values);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}

/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_WIRE_FORMAT_ARGS_API_TC001(void)
{
    HIFHE_Ctx *ctx = NULL, *early = NULL;
    HIFHE_HEText *pt = NULL, *bad = NULL;
    uint8_t *wire = NULL;
    uint32_t len = 0;
    uint32_t format = 2;
    uint64_t msg[] = {1, 2, 3, 4};

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    /* The setting belongs to the context, so it takes before the parameters
     * as readily as after. */
    early = HIFHE_New(HIFHE_BGV);
    ASSERT_TRUE(early != NULL);
    uint32_t interchange = HIFHE_WIRE_INTERCHANGE;
    ASSERT_EQ(HIFHE_Ctrl(early, HIFHE_CTRL_BGV_SET_WIRE_FORMAT, NULL, &interchange, sizeof(interchange)),
              HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_SetParaById(early, HIFHE_BGV_4096_44x2_17BIT), HIFHE_SUCCESS);

    ctx = Configured();
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(HIFHE_Ctrl(ctx, HIFHE_CTRL_BGV_SET_WIRE_FORMAT, NULL, &format, sizeof(format)) ==
                HIFHE_VALUE_OUT_OF_RANGE);
    format = HIFHE_WIRE_INTERCHANGE;
    ASSERT_TRUE(HIFHE_Ctrl(ctx, HIFHE_CTRL_BGV_SET_WIRE_FORMAT, NULL, &format, 1) == HIFHE_INVALID_LENGTH);
    ASSERT_EQ(HIFHE_Ctrl(ctx, HIFHE_CTRL_BGV_SET_WIRE_FORMAT, NULL, &format, sizeof(format)), HIFHE_SUCCESS);

    /* Neither header: still refused, not read as one format or the other. */
    ASSERT_EQ(HIFHE_Encode(ctx, msg, 4, &pt), HIFHE_SUCCESS);
    wire = Serialized(ctx, pt, &len);
    ASSERT_TRUE(wire != NULL && len > 12);
    wire[0] ^= 0xffu;
    ASSERT_TRUE(HIFHE_Deserialize(ctx, wire, len, &bad) == HIFHE_SERDES_FAIL);
    ASSERT_TRUE(bad == NULL);
    /* A truncated interchange header is refused before anything is read. */
    wire[0] ^= 0xffu;
    ASSERT_TRUE(HIFHE_Deserialize(ctx, wire, 11, &bad) == HIFHE_SERDES_FAIL);
    ASSERT_TRUE(bad == NULL);
EXIT:
    HIFHE_HETextFree(pt);
    HIFHE_HETextFree(bad);
    HIFHE_Free(ctx);
    HIFHE_Free(early);
    free(wire);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}

/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HIFHE_BGV_KEY_IO_API_TC001(void)
{
    HIFHE_Ctx *owner = NULL, *reader = NULL, *writer = NULL, *rival = NULL;
    HIFHE_HEText *rpt = NULL, *rct = NULL, *rback = NULL, *rplain = NULL;
    uint8_t *rivalPrv = NULL, *rivalWire = NULL;
    uint32_t rivalLen = 0, rivalPrvLen = 0;
    uint8_t rivalSeed[32];
    HIFHE_HEText *pt = NULL, *ct = NULL, *back = NULL, *plain = NULL;
    HIFHE_HEText *wpt = NULL, *wct = NULL, *oback = NULL, *oplain = NULL;
    uint8_t *pub = NULL, *prv = NULL, *wire = NULL, *fromWriter = NULL;
    uint64_t *values = NULL;
    uint32_t pubLen = 0, prvLen = 0, len = 0, writerLen = 0, query = 0;
    uint64_t msg[] = {21, 22, 23, 24};

    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND), HIFHE_SUCCESS);
    owner = Configured();
    reader = Configured();
    writer = Configured();
    ASSERT_TRUE(owner != NULL && reader != NULL && writer != NULL);

    /* Nothing to export before there are keys. */
    ASSERT_TRUE(HIFHE_ExportPubKey(owner, NULL, &query) == HIFHE_KEY_NOT_SET);
    ASSERT_TRUE(HIFHE_ExportPrvKey(owner, NULL, &query) == HIFHE_KEY_NOT_SET);
    ASSERT_EQ(HIFHE_Ctrl(owner, HIFHE_CTRL_BGV_SET_SEED, NULL, g_wireSeed, sizeof(g_wireSeed)), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_KeyGen(owner), HIFHE_SUCCESS);

    /* Both keys go out in the interchange format, sized by the query. */
    pubLen = 0;
    ASSERT_TRUE(HIFHE_ExportPubKey(owner, NULL, &pubLen) == HIFHE_BUFFER_TOO_SMALL);
    pub = malloc(pubLen);
    ASSERT_TRUE(pub != NULL);
    ASSERT_EQ(HIFHE_ExportPubKey(owner, pub, &pubLen), HIFHE_SUCCESS);
    prvLen = 0;
    ASSERT_TRUE(HIFHE_ExportPrvKey(owner, NULL, &prvLen) == HIFHE_BUFFER_TOO_SMALL);
    prv = malloc(prvLen);
    ASSERT_TRUE(prv != NULL);
    ASSERT_EQ(HIFHE_ExportPrvKey(owner, prv, &prvLen), HIFHE_SUCCESS);
    ASSERT_TRUE(memcmp(pub, "HLG\0", 4) == 0 && memcmp(prv, "HLG\0", 4) == 0);

    /* A ciphertext is not a key, and a broken header is not either. */
    ASSERT_EQ(HIFHE_Encode(owner, msg, 4, &pt), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(owner, pt, &ct), HIFHE_SUCCESS);
    wire = Serialized(owner, ct, &len);
    ASSERT_TRUE(wire != NULL);
    ASSERT_TRUE(HIFHE_ImportPrvKey(reader, prv, 11) == HIFHE_SERDES_FAIL);
    prv[0] ^= 0xffu;
    ASSERT_TRUE(HIFHE_ImportPrvKey(reader, prv, prvLen) == HIFHE_SERDES_FAIL);
    prv[0] ^= 0xffu;
    /* Each call takes one kind of key and nothing else. */
    ASSERT_TRUE(HIFHE_ImportPubKey(reader, prv, prvLen) == HIFHE_SERDES_FAIL);
    ASSERT_TRUE(HIFHE_ImportPrvKey(reader, pub, pubLen) == HIFHE_SERDES_FAIL);
    ASSERT_TRUE(HIFHE_ImportPrvKey(reader, wire, len) == HIFHE_SERDES_FAIL);

    /* The private key alone opens the owner's ciphertext. The reader has no
     * origin of its own once a key is handed to it, so the owner's origin on
     * the wire is nothing to hold it to. */
    ASSERT_EQ(HIFHE_ImportPrvKey(reader, prv, prvLen), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Deserialize(reader, wire, len, &back), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Decrypt(reader, back, &plain), HIFHE_SUCCESS);
    uint32_t count = 0;
    ASSERT_TRUE(HIFHE_Decode(reader, plain, NULL, &count) == HIFHE_BUFFER_TOO_SMALL);
    values = calloc(count, sizeof(*values));
    ASSERT_TRUE(values != NULL);
    ASSERT_EQ(HIFHE_Decode(reader, plain, values, &count), HIFHE_SUCCESS);
    ASSERT_TRUE(values[0] == 21 && values[1] == 22 && values[2] == 23 && values[3] == 24);

    /* The public key alone encrypts, and the owner reads that back. */
    ASSERT_EQ(HIFHE_ImportPubKey(writer, pub, pubLen), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encode(writer, msg, 4, &wpt), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(writer, wpt, &wct), HIFHE_SUCCESS);
    fromWriter = Serialized(writer, wct, &writerLen);
    ASSERT_TRUE(fromWriter != NULL);
    ASSERT_EQ(HIFHE_Deserialize(owner, fromWriter, writerLen, &oback), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Decrypt(owner, oback, &oplain), HIFHE_SUCCESS);
    memset(values, 0, count * sizeof(*values));
    ASSERT_EQ(HIFHE_Decode(owner, oplain, values, &count), HIFHE_SUCCESS);
    ASSERT_TRUE(values[0] == 21 && values[1] == 22 && values[2] == 23 && values[3] == 24);

    /* A public key does not let it decrypt. */
    HIFHE_HETextFree(oplain);
    oplain = NULL;
    ASSERT_TRUE(HIFHE_Decrypt(writer, wct, &oplain) == HIFHE_KEY_NOT_SET);

    /* An import replaces the key, so the origin the context had from its own
     * keygen no longer describes it: a ciphertext under the imported key has
     * to be readable. */
    rival = Configured();
    ASSERT_TRUE(rival != NULL);
    memcpy(rivalSeed, g_wireSeed, sizeof(rivalSeed));
    rivalSeed[1] ^= 0xffu;
    ASSERT_EQ(HIFHE_Ctrl(rival, HIFHE_CTRL_BGV_SET_SEED, NULL, rivalSeed, sizeof(rivalSeed)), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_KeyGen(rival), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encode(rival, msg, 4, &rpt), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Encrypt(rival, rpt, &rct), HIFHE_SUCCESS);
    rivalWire = Serialized(rival, rct, &rivalLen);
    ASSERT_TRUE(rivalWire != NULL);
    rivalPrvLen = 0;
    ASSERT_TRUE(HIFHE_ExportPrvKey(rival, NULL, &rivalPrvLen) == HIFHE_BUFFER_TOO_SMALL);
    rivalPrv = malloc(rivalPrvLen);
    ASSERT_TRUE(rivalPrv != NULL);
    ASSERT_EQ(HIFHE_ExportPrvKey(rival, rivalPrv, &rivalPrvLen), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_ImportPrvKey(owner, rivalPrv, rivalPrvLen), HIFHE_SUCCESS);
    /* That import replaced the secret, so the public key the context generated
     * with the old one is gone and must not still be on offer. */
    ASSERT_TRUE(HIFHE_ExportPubKey(owner, NULL, &query) == HIFHE_KEY_NOT_SET);
    HIFHE_HETextFree(ct);
    ct = NULL;
    ASSERT_TRUE(HIFHE_Encrypt(owner, pt, &ct) == HIFHE_KEY_NOT_SET);
    ASSERT_EQ(HIFHE_Deserialize(owner, rivalWire, rivalLen, &rback), HIFHE_SUCCESS);
    ASSERT_EQ(HIFHE_Decrypt(owner, rback, &rplain), HIFHE_SUCCESS);
    memset(values, 0, count * sizeof(*values));
    ASSERT_EQ(HIFHE_Decode(owner, rplain, values, &count), HIFHE_SUCCESS);
    ASSERT_TRUE(values[0] == 21 && values[1] == 22 && values[2] == 23 && values[3] == 24);
EXIT:
    HIFHE_HETextFree(rpt);
    HIFHE_HETextFree(rct);
    HIFHE_HETextFree(rback);
    HIFHE_HETextFree(rplain);
    HIFHE_Free(rival);
    free(rivalPrv);
    free(rivalWire);
    HIFHE_HETextFree(pt);
    HIFHE_HETextFree(ct);
    HIFHE_HETextFree(back);
    HIFHE_HETextFree(plain);
    HIFHE_HETextFree(wpt);
    HIFHE_HETextFree(wct);
    HIFHE_HETextFree(oback);
    HIFHE_HETextFree(oplain);
    HIFHE_Free(owner);
    HIFHE_Free(reader);
    HIFHE_Free(writer);
    free(pub);
    free(prv);
    free(wire);
    free(fromWriter);
    free(values);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND);
}

/* END_CASE */
