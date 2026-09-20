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

#include <string.h>
#include "bsl_sal.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_md.h"
#include "crypt_algid.h"
#include "basic/rand.h"

HIFHE_ERROR BgvRand_Drbg(uint8_t *out, uint32_t outLen)
{
    if (out == NULL) return HIFHE_NULL_INPUT;
    if (outLen == 0u) return HIFHE_SUCCESS;
    int32_t r = CRYPT_EAL_Randbytes(out, outLen);
    return (r == 0) ? HIFHE_SUCCESS : HIFHE_INTERNAL;
}

/* One absorbed chunk. An empty or absent chunk is skipped. */
typedef struct {
    const uint8_t *p;
    uint32_t       len;
} ShakeChunk;

/* SHAKE128 over the chunks in order, squeezed into `out`. The absorb order
 * is part of the output, so callers list the chunks in stream order. */
static HIFHE_ERROR Shake128(const ShakeChunk *in, uint32_t nIn,
                            uint8_t *out, uint32_t outLen)
{
    CRYPT_EAL_MdCtx *mctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHAKE128);
    if (mctx == NULL) return HIFHE_INTERNAL;

    HIFHE_ERROR ret = HIFHE_INTERNAL;
    if (CRYPT_EAL_MdInit(mctx) != 0) goto done;
    for (uint32_t i = 0; i < nIn; ++i) {
        if (in[i].p == NULL || in[i].len == 0u) continue;
        if (CRYPT_EAL_MdUpdate(mctx, in[i].p, in[i].len) != 0) goto done;
    }
    if (CRYPT_EAL_MdSqueeze(mctx, out, outLen) != 0) goto done;
    ret = HIFHE_SUCCESS;
done:
    CRYPT_EAL_MdFreeCtx(mctx);
    return ret;
}

HIFHE_ERROR BgvRand_Seeded(const uint8_t *seed, uint32_t seedLen,
                         const uint8_t *ds,   uint32_t dsLen,
                         uint8_t *out,        uint32_t outLen)
{
    if (out == NULL) return HIFHE_NULL_INPUT;
    if (outLen == 0u) return HIFHE_SUCCESS;
    if (seed == NULL || seedLen == 0u) return HIFHE_NULL_INPUT;

    const ShakeChunk in[] = { {seed, seedLen}, {ds, dsLen} };
    return Shake128(in, 2u, out, outLen);
}

/* ---- counter-mode stream ---- */

static uint32_t LabelPut(BgvLabel *l, uint32_t n, const char *str)
{
    for (const char *p = str; *p != '\0'; ++p) {
        if (n + 1u >= HIFHE_DS_MAX) return HIFHE_DS_MAX;
        l->s[n++] = *p;
    }
    return n;
}

const char *BgvLabel_Build(BgvLabel *l, const char *path,
                           const uint64_t *fields, uint32_t nFields,
                           const char *suffix)
{
    if (l == NULL || path == NULL) return NULL;
    uint32_t n = LabelPut(l, 0u, HIFHE_DS_PREFIX);
    n = LabelPut(l, n, path);
    for (uint32_t i = 0; i < nFields; ++i) {
        if (n + 1u >= HIFHE_DS_MAX) return NULL;
        l->s[n++] = '/';
        char digits[20];
        uint32_t d = 0u;
        uint64_t v = fields[i];
        do { digits[d++] = (char)('0' + (v % 10u)); v /= 10u; } while (v != 0u);
        while (d > 0u) {
            if (n + 1u >= HIFHE_DS_MAX) return NULL;
            l->s[n++] = digits[--d];
        }
    }
    if (suffix != NULL) {
        if (n + 1u >= HIFHE_DS_MAX) return NULL;
        l->s[n++] = '/';
        n = LabelPut(l, n, suffix);
    }
    if (n >= HIFHE_DS_MAX) return NULL;
    l->s[n] = '\0';
    return l->s;
}

static HIFHE_ERROR RefillFromSeed(BgvRandStream *s)
{
    uint8_t ctrLE[8];
    for (uint32_t i = 0; i < 8u; ++i) {
        ctrLE[i] = (uint8_t)((s->counter >> (8u * i)) & 0xffu);
    }

    const ShakeChunk in[] = {
        {s->seed, (uint32_t)sizeof(s->seed)},
        {(const uint8_t *)s->label, (uint32_t)strlen(s->label)},
        {ctrLE, (uint32_t)sizeof(ctrLE)},
    };
    HIFHE_ERROR r = Shake128(in, 3u, s->buf, HIFHE_RAND_BLOCK);
    if (r != HIFHE_SUCCESS) return r;

    s->counter++;
    s->bufPos = 0u;
    s->bufLen = HIFHE_RAND_BLOCK;
    return HIFHE_SUCCESS;
}

static HIFHE_ERROR RefillFromDrbg(BgvRandStream *s)
{
    HIFHE_ERROR r = BgvRand_Drbg(s->buf, HIFHE_RAND_DRBG_BLOCK);
    if (r != HIFHE_SUCCESS) return r;
    s->bufPos = 0u;
    s->bufLen = HIFHE_RAND_DRBG_BLOCK;
    return HIFHE_SUCCESS;
}

void BgvRandStream_Init(BgvRandStream *s, const uint8_t *seed, const char *label)
{
    if (s == NULL) return;
    /* buf is left as is. bufLen 0 forces a refill before any byte is served. */
    s->seeded  = 0u;
    s->counter = 0u;
    s->bufPos  = 0u;
    s->bufLen  = 0u;
    s->label[0] = '\0';
    memset(s->seed, 0, sizeof(s->seed));
    if (seed == NULL) return;
    memcpy(s->seed, seed, sizeof(s->seed));
    s->seeded = 1u;
    if (label != NULL) {
        uint32_t n = 0u;
        while (label[n] != '\0' && n + 1u < HIFHE_DS_MAX) { s->label[n] = label[n]; n++; }
        s->label[n] = '\0';
    }
}

HIFHE_ERROR BgvRandStream_Bytes(BgvRandStream *s, uint8_t *out, uint32_t len)
{
    if (s == NULL || out == NULL) return HIFHE_NULL_INPUT;
    while (len > 0u) {
        if (s->bufLen == 0u) {
            HIFHE_ERROR r = s->seeded ? RefillFromSeed(s) : RefillFromDrbg(s);
            if (r != HIFHE_SUCCESS) return r;
        }
        uint32_t take = (len < s->bufLen) ? len : s->bufLen;
        memcpy(out, s->buf + s->bufPos, take);
        s->bufPos += take;
        s->bufLen -= take;
        out += take;
        len  -= take;
    }
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BgvRandStream_U64(BgvRandStream *s, uint64_t *out)
{
    if (out == NULL) return HIFHE_NULL_INPUT;
    uint8_t b[8];
    HIFHE_ERROR r = BgvRandStream_Bytes(s, b, sizeof(b));
    if (r != HIFHE_SUCCESS) return r;
    uint64_t v = 0u;
    for (uint32_t i = 0; i < 8u; ++i) v |= ((uint64_t)b[i]) << (8u * i);
    *out = v;
    return HIFHE_SUCCESS;
}

void BgvRandStream_Cleanse(BgvRandStream *s)
{
    if (s == NULL) return;
    BSL_SAL_CleanseData(s, (uint32_t)sizeof(*s));
}
