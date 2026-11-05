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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hifhe.h"
#include "crypt_eal_init.h"
#include "crypt_eal_md.h"
#include "crypt_algid.h"

#define SLOTS       4096u
#define FIELD_COUNT 4u

static const char *g_bucket[] = {"123456",   "password", "qwerty",   "letmein", "dragon",  "monkey",
                                 "football", "hunter2",  "iloveyou", "admin",   "welcome", "login",
                                 "starwars", "trustno1", "whatever", "shadow"};

static int32_t Fields(const char *text, uint64_t *values)
{
    uint8_t digest[32];
    uint32_t len = sizeof(digest);
    CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA3_256);
    if (ctx == NULL) {
        return HIFHE_MEMORY_ERROR;
    }
    int32_t ret = CRYPT_EAL_MdInit(ctx);
    if (ret == HIFHE_SUCCESS) {
        ret = CRYPT_EAL_MdUpdate(ctx, (const uint8_t *)text, (uint32_t)strlen(text));
    }
    if (ret == HIFHE_SUCCESS) {
        ret = CRYPT_EAL_MdFinal(ctx, digest, &len);
    }
    CRYPT_EAL_MdFreeCtx(ctx);
    if (ret == HIFHE_SUCCESS) {
        for (uint32_t i = 0; i < FIELD_COUNT; i++) {
            values[i] = (uint32_t)digest[i * 2] << 8 | digest[i * 2 + 1];
        }
    }
    return ret;
}

static HIFHE_Ctx *NewParty(void)
{
    HIFHE_Ctx *ctx = HIFHE_New(HIFHE_BGV);
    if (ctx == NULL) {
        return NULL;
    }
    int32_t ret = HIFHE_SetParaById(ctx, HIFHE_BGV_4096_44x2_17BIT);
    if (ret != HIFHE_SUCCESS) {
        HIFHE_Free(ctx);
        return NULL;
    }
    return ctx;
}

static int32_t SendBytes(HIFHE_Ctx *sender, const HIFHE_HEText *text, HIFHE_Ctx *receiver, HIFHE_HEText **out)
{
    uint32_t len = 0;
    int32_t ret = HIFHE_Serialize(sender, text, NULL, &len);
    if (ret != HIFHE_BUFFER_TOO_SMALL) {
        return ret;
    }
    uint8_t *wire = malloc(len);
    if (wire == NULL) {
        return HIFHE_MEMORY_ERROR;
    }
    ret = HIFHE_Serialize(sender, text, wire, &len);
    if (ret == HIFHE_SUCCESS) {
        ret = HIFHE_Deserialize(receiver, wire, len, out);
    }
    free(wire);
    return ret;
}

static int Query(HIFHE_Ctx *a, HIFHE_Ctx *b, const char *secret, uint32_t *match)
{
    uint64_t *query = calloc(SLOTS, sizeof(*query)), *bucket = calloc(SLOTS, sizeof(*bucket));
    uint64_t *mask = calloc(SLOTS, sizeof(*mask)), *decoded = calloc(SLOTS, sizeof(*decoded));
    HIFHE_HEText *pt = NULL, *ct = NULL, *received = NULL, *bucketPt = NULL, *difference = NULL;
    HIFHE_HEText *maskPt = NULL, *product = NULL, *result = NULL, *reply = NULL, *answer = NULL;
    FILE *random = NULL;
    int success = 0;
    uint64_t fields[FIELD_COUNT];
    if (query == NULL || bucket == NULL || mask == NULL || decoded == NULL) {
        goto done;
    }
    int32_t ret = Fields(secret, fields);
    if (ret != HIFHE_SUCCESS) {
        fprintf(stderr, "Fields(secret, fields): %x\n", (unsigned)ret);
        goto done;
    }
    for (uint32_t i = 0; i < SLOTS; i++) {
        query[i] = fields[i % FIELD_COUNT];
    }
    ret = HIFHE_Encode(a, query, SLOTS, &pt);
    if (ret != HIFHE_SUCCESS) {
        fprintf(stderr, "HIFHE_Encode(a, query, SLOTS, &pt): %x\n", (unsigned)ret);
        goto done;
    }
    ret = HIFHE_Encrypt(a, pt, &ct);
    if (ret != HIFHE_SUCCESS) {
        fprintf(stderr, "HIFHE_Encrypt(a, pt, &ct): %x\n", (unsigned)ret);
        goto done;
    }
    ret = SendBytes(a, ct, b, &received);
    if (ret != HIFHE_SUCCESS) {
        fprintf(stderr, "SendBytes(a, ct, b, &received): %x\n", (unsigned)ret);
        goto done;
    }
    for (uint32_t i = 0; i < sizeof(g_bucket) / sizeof(g_bucket[0]); i++) {
        ret = Fields(g_bucket[i], bucket + i * FIELD_COUNT);
        if (ret != HIFHE_SUCCESS) {
            fprintf(stderr, "Fields(g_bucket[i], bucket + i * FIELD_COUNT): %x\n", (unsigned)ret);
            goto done;
        }
    }
    ret = HIFHE_Encode(b, bucket, SLOTS, &bucketPt);
    if (ret != HIFHE_SUCCESS) {
        fprintf(stderr, "HIFHE_Encode(b, bucket, SLOTS, &bucketPt): %x\n", (unsigned)ret);
        goto done;
    }
    ret = HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_NEGATE, received, NULL, 0);
    if (ret != HIFHE_SUCCESS) {
        fprintf(stderr, "HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_NEGATE, received, NULL, 0): %x\n", (unsigned)ret);
        goto done;
    }
    ret = HIFHE_Add(b, received, bucketPt, &difference);
    if (ret != HIFHE_SUCCESS) {
        fprintf(stderr, "HIFHE_Add(b, received, bucketPt, &difference): %x\n", (unsigned)ret);
        goto done;
    }
    random = fopen("/dev/urandom", "rb");
    if (random == NULL) {
        goto done;
    }
    for (uint32_t i = 0; i < SLOTS; i++) {
        uint16_t value;
        if (fread(&value, sizeof(value), 1, random) != 1) {
            goto done;
        }
        mask[i] = (uint32_t)value + 1;
    }
    ret = HIFHE_Encode(b, mask, SLOTS, &maskPt);
    if (ret != HIFHE_SUCCESS) {
        fprintf(stderr, "HIFHE_Encode(b, mask, SLOTS, &maskPt): %x\n", (unsigned)ret);
        goto done;
    }
    ret = HIFHE_Mul(b, difference, maskPt, &product);
    if (ret != HIFHE_SUCCESS) {
        fprintf(stderr, "HIFHE_Mul(b, difference, maskPt, &product): %x\n", (unsigned)ret);
        goto done;
    }
    ret = HIFHE_Ctrl(b, HIFHE_CTRL_BGV_RERANDOMIZE, product, &result, sizeof(result));
    if (ret != HIFHE_SUCCESS) {
        fprintf(stderr, "HIFHE_Ctrl(b, HIFHE_CTRL_BGV_RERANDOMIZE, product, &result, sizeof(result)): %x\n",
                (unsigned)ret);
        goto done;
    }
    ret = SendBytes(b, result, a, &reply);
    if (ret != HIFHE_SUCCESS) {
        fprintf(stderr, "SendBytes(b, result, a, &reply): %x\n", (unsigned)ret);
        goto done;
    }
    ret = HIFHE_Decrypt(a, reply, &answer);
    if (ret != HIFHE_SUCCESS) {
        fprintf(stderr, "HIFHE_Decrypt(a, reply, &answer): %x\n", (unsigned)ret);
        goto done;
    }
    uint32_t count = SLOTS;
    ret = HIFHE_Decode(a, answer, decoded, &count);
    if (ret != HIFHE_SUCCESS) {
        fprintf(stderr, "HIFHE_Decode(a, answer, decoded, &count): %x\n", (unsigned)ret);
        goto done;
    }
    *match = UINT32_MAX;
    for (uint32_t i = 0; i < sizeof(g_bucket) / sizeof(g_bucket[0]); i++) {
        uint64_t value = 0;
        for (uint32_t j = 0; j < FIELD_COUNT; j++) {
            value |= decoded[i * FIELD_COUNT + j];
        }
        if (value == 0) {
            *match = i;
            break;
        }
    }
    success = 1;
done:
    if (random != NULL) {
        fclose(random);
    }
    HIFHE_HETextFree(pt);
    HIFHE_HETextFree(ct);
    HIFHE_HETextFree(received);
    HIFHE_HETextFree(bucketPt);
    HIFHE_HETextFree(difference);
    HIFHE_HETextFree(maskPt);
    HIFHE_HETextFree(product);
    HIFHE_HETextFree(result);
    HIFHE_HETextFree(reply);
    HIFHE_HETextFree(answer);
    free(query);
    free(bucket);
    free(mask);
    free(decoded);
    return success;
}

int main(void)
{
    if (CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND) != HIFHE_SUCCESS) {
        return 1;
    }
    HIFHE_Ctx *a = NewParty(), *b = NewParty();
    int success = 0;
    uint32_t match;
    if (a == NULL || b == NULL || HIFHE_KeyGen(a) != HIFHE_SUCCESS) {
        goto done;
    }
    if (Query(a, b, "hunter2", &match) == 0 || match != 7) {
        goto done;
    }
    printf("hit: index %u\n", match);
    if (Query(a, b, "not-in-the-leak-bucket", &match) == 0 || match != UINT32_MAX) {
        goto done;
    }
    puts("miss: no match");
    success = 1;
done:
    HIFHE_Free(a);
    HIFHE_Free(b);
    return success != 0 ? 0 : 1;
}
