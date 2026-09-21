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
 * Sampling primitives. Entropy comes from basic/rand.c:
 *   unseeded   DRBG, CRYPT_EAL_Randbytes
 *   seeded     SHAKE128(seed || label), replays for the same pair
 */

#include <string.h>
#include "bsl_sal.h"
#include "kernel/sampler.h"
#include "basic/rand.h"
#include "basic/vector.h"

/* DRBG when unseeded, else SHAKE(seed || label || suffix). `suffix` keeps
 * successive refills of one draw apart. */
static HIFHE_ERROR DrawBytes(uint8_t *dst, uint32_t nBytes, const BgvEntropy *src,
                           const uint8_t *suffix, uint32_t suffixLen)
{
    if (src == NULL || src->seed == NULL || src->seedLen == 0u) {
        return BgvRand_Drbg(dst, nBytes);
    }
    if (src->label == NULL) return HIFHE_PARAM_INVALID;

    uint8_t ds[HIFHE_DS_MAX + 8u];
    uint32_t n = 0u;
    while (src->label[n] != 0 && n < HIFHE_DS_MAX) { ds[n] = (uint8_t)src->label[n]; n++; }
    for (uint32_t i = 0; i < suffixLen && n < sizeof(ds); ++i) ds[n++] = suffix[i];
    return BgvRand_Seeded(src->seed, src->seedLen, ds, n, dst, nBytes);
}

/* A pool of `nBytes` filled in one draw. Cleansed and destroyed on failure. */
static HIFHE_ERROR DrawPool(Uint8Vector *pool, uint32_t nBytes, const BgvEntropy *src)
{
    int32_t r = Uint8Vector_Create(pool, NULL, nBytes);
    if (r != HIFHE_SUCCESS) return r;
    r = DrawBytes(pool->data, nBytes, src, NULL, 0u);
    if (r != HIFHE_SUCCESS) Uint8Vector_Cleanse(pool);
    return r;
}

/* Uniform mod q by rejection: mask to ceil(log2 q) bits, retry on cand >= q. */
HIFHE_ERROR Kernel_Sampler_UniformModQ(uint64_t *out, uint32_t count, Modulus q,
                                     uint32_t limbIndex, const BgvEntropy *src)
{
    if (out == NULL || q < 2u) return HIFHE_NULL_INPUT;

    uint32_t bytesPerDraw = 8u;
    uint64_t mask = ~0ull;
    /* Smallest mask covering q. */
    uint32_t bits = Kernel_Log2Ceil(q);
    if (bits < 64u) mask = (1ull << bits) - 1u;

    /* Batch entropy so the per-refill SHAKE init amortizes. */
    const uint32_t POOL_BYTES = 512u;
    uint8_t pool[512];
    uint32_t poolFill = 0u;
    uint32_t poolIdx  = 0u;

    /* The refill index rides after the label, so blocks stay distinct. */
    uint32_t refillIdx = 0u;

    for (uint32_t k = 0; k < count; ) {
        if (poolIdx >= poolFill) {
            /* The refill index keeps one draw's blocks apart; the limb index
             * keeps the limbs of a chain apart. The first limb carries no tag,
             * so single-limb material keeps the stream it has always had. */
            uint8_t sfx[8];
            uint32_t sfxLen = 4u;
            for (uint32_t b = 0; b < 4u; ++b) sfx[b] = (uint8_t)(refillIdx >> (8u * b));
            if (limbIndex != 0u) {
                for (uint32_t b = 0; b < 4u; ++b) {
                    sfx[4u + b] = (uint8_t)(limbIndex >> (8u * b));
                }
                sfxLen = 8u;
            }
            refillIdx++;
            int32_t r = DrawBytes(pool, POOL_BYTES, src, sfx, sfxLen);
            if (r != HIFHE_SUCCESS) return r;
            poolFill = POOL_BYTES;
            poolIdx  = 0u;
        }
        if (poolIdx + bytesPerDraw > poolFill) {
            /* Not enough for one draw; force refill. */
            poolIdx = poolFill;
            continue;
        }
        uint64_t cand = 0u;
        for (uint32_t b = 0; b < 8u; ++b) {
            cand |= ((uint64_t)pool[poolIdx + b]) << (8u * b);
        }
        poolIdx += bytesPerDraw;
        cand &= mask;
        if (cand < q) {
            out[k++] = cand;
        }
    }
    BSL_SAL_CleanseData(pool, POOL_BYTES);
    return HIFHE_SUCCESS;
}

HIFHE_ERROR Kernel_Sampler_Ternary(int64_t *out, uint32_t count,
                                 const BgvEntropy *src)
{
    if (out == NULL) return HIFHE_NULL_INPUT;

    /* Two bits per sample: 00, 11 -> 0; 01 -> +1; 10 -> -1.
     * Weights 1/4, 1/2, 1/4 on {-1, 0, +1}. */
    uint32_t needBytes = (count + 3u) / 4u;
    Uint8Vector pool;
    int32_t r = DrawPool(&pool, needBytes, src);
    if (r != HIFHE_SUCCESS) return r;
    const uint8_t *buf = pool.data;

    for (uint32_t i = 0; i < count; ++i) {
        uint8_t byte = buf[i >> 2];
        uint8_t bits = (byte >> ((i & 3u) << 1u)) & 3u;
        switch (bits) {
            case 0: out[i] =  0; break;
            case 1: out[i] =  1; break;
            case 2: out[i] = -1; break;
            default:out[i] =  0; break;
        }
    }
    Uint8Vector_Cleanse(&pool);
    return HIFHE_SUCCESS;
}

HIFHE_ERROR Kernel_Sampler_TernaryFixedWeight(int64_t *out, uint32_t count,
                                            uint32_t weight,
                                            const BgvEntropy *src)
{
    if (out == NULL) return HIFHE_NULL_INPUT;
    if (count == 0u || weight > count) return HIFHE_PARAM_INVALID;

    /* An odd weight puts the extra nonzero on the +1 side. Splitting into two
     * halves alone would leave weight - 1 of them. An even weight, which is
     * what the callers pass, lays out exactly as before. */
    uint32_t pos = (weight + 1u) >> 1;
    uint32_t neg = weight >> 1;
    for (uint32_t i = 0; i < pos; ++i) out[i] = 1;
    for (uint32_t i = 0; i < neg; ++i) out[pos + i] = -1;
    for (uint32_t i = pos + neg; i < count; ++i) out[i] = 0;

    /* This sampler drives the stream directly instead of going through
     * DrawBytes, so it has to enforce the same contract: a seeded draw
     * carries a label, and the stream copies a full seed. */
    if (src != NULL && src->seed != NULL &&
        (src->label == NULL || src->seedLen != HIFHE_RAND_SEED_BYTES)) {
        return HIFHE_PARAM_INVALID;
    }

    /* Fisher-Yates walking down. The i == 1 step swaps a slot with itself
     * but still consumes a word; dropping it shifts every later draw. */
    BgvRandStream stream;
    BgvRandStream_Init(&stream, (src != NULL) ? src->seed : NULL,
                       (src != NULL) ? src->label : NULL);
    HIFHE_ERROR r = HIFHE_SUCCESS;
    for (uint32_t i = count; i > 0u; --i) {
        uint64_t w = 0u;
        r = BgvRandStream_U64(&stream, &w);
        if (r != HIFHE_SUCCESS) break;
        uint64_t j = w % (uint64_t)i;
        int64_t  t = out[i - 1u];
        out[i - 1u] = out[j];
        out[j]      = t;
    }
    BgvRandStream_Cleanse(&stream);
    return r;
}

/* CBD: 2*eta bits per sample, popcount(lo) - popcount(hi). */
HIFHE_ERROR Kernel_Sampler_CBD(int64_t *out, uint32_t count, uint32_t eta,
                             const BgvEntropy *src)
{
    if (out == NULL) return HIFHE_NULL_INPUT;
    if (eta == 0u || eta > 8u) return HIFHE_PARAM_INVALID;

    uint32_t bitsPerSample = 2u * eta;
    uint32_t needBytes = (count * bitsPerSample + 7u) / 8u;
    Uint8Vector pool;
    int32_t r = DrawPool(&pool, needBytes, src);
    if (r != HIFHE_SUCCESS) return r;
    const uint8_t *buf = pool.data;

    uint32_t mask = (1u << eta) - 1u;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t bitOff = i * bitsPerSample;
        uint32_t byteOff = bitOff >> 3;
        uint32_t shift   = bitOff & 7u;
        /* Up to 24 bits; eta <= 8 so bitsPerSample <= 16. */
        uint32_t word = 0u;
        word |= (uint32_t)buf[byteOff];
        if (byteOff + 1u < needBytes) word |= ((uint32_t)buf[byteOff + 1]) << 8;
        if (byteOff + 2u < needBytes) word |= ((uint32_t)buf[byteOff + 2]) << 16;
        word >>= shift;
        uint32_t lo = word & mask;
        uint32_t hi = (word >> eta) & mask;
        /* popcount */
        uint32_t lc = 0u, hc = 0u;
        for (uint32_t b = 0; b < eta; ++b) {
            lc += (lo >> b) & 1u;
            hc += (hi >> b) & 1u;
        }
        out[i] = (int64_t)lc - (int64_t)hc;
    }
    Uint8Vector_Cleanse(&pool);
    return HIFHE_SUCCESS;
}

