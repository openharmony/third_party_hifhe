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
 * Thin RNG facade. Two backends selectable per-call:
 *   - DRBG path:   CRYPT_EAL_Randbytes (thread-safe global DRBG in openhitls)
 *   - Seeded path: CRYPT_EAL_MdCtx(SHAKE128) squeezed from a 32-byte seed
 */

#ifndef HIFHE_BASIC_RAND_H
#define HIFHE_BASIC_RAND_H

#include <stdint.h>
#include <stddef.h>
#include "hifhe_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- domain separation ----
 * A seeded draw is keyed on (seed || label). Two draws under one seed and one
 * label return the same output, so every derived value needs its own label.
 * Bumping the prefix renames all of them at once. */
#define HIFHE_DS_PREFIX  "hifhe/v1/"
#define HIFHE_DS_MAX     72u

typedef struct {
    char s[HIFHE_DS_MAX];
} BgvLabel;

/* HIFHE_DS_PREFIX + path + "/field"... + "/suffix":
 *   sk                       pk/a                  enc/u
 *   relin/<limb>/<digit>/a   galois/<elt>/<limb>/<digit>/e
 * `fields` and `suffix` may be absent. NULL if it would not fit; a seeded
 * draw with a NULL label is rejected, not silently unseparated. */
const char *BgvLabel_Build(BgvLabel *l, const char *path,
                           const uint64_t *fields, uint32_t nFields,
                           const char *suffix);

/* Where a sampler draws from. NULL seed selects the DRBG and ignores
 * `label`; a non-NULL seed requires one. Paired so neither can be forgotten. */
typedef struct {
    const uint8_t *seed;
    uint32_t       seedLen;
    const char    *label;
} BgvEntropy;

/* Draws from the DRBG. */
static inline BgvEntropy BgvEntropy_Drbg(void)
{
    BgvEntropy e = { NULL, 0u, NULL };
    return e;
}

/* Draws from SHAKE128(seed || label). */
static inline BgvEntropy BgvEntropy_Seeded(const uint8_t *seed, uint32_t seedLen,
                                           const char *label)
{
    BgvEntropy e;
    e.seed    = (seed != NULL && seedLen != 0u) ? seed : NULL;
    e.seedLen = (e.seed != NULL) ? seedLen : 0u;
    e.label   = label;
    return e;
}

/* Fill `out[0..outLen)` with uniform bytes drawn from the openhitls DRBG. */
HIFHE_ERROR BgvRand_Drbg   (uint8_t *out, uint32_t outLen);

/* Fill `out[0..outLen)` from a SHAKE128 stream keyed by the 32-byte
 * `seed`, optionally tagged with `dsLen` bytes of domain-separation. */
HIFHE_ERROR BgvRand_Seeded (const uint8_t *seed, uint32_t seedLen,
                           const uint8_t *ds,   uint32_t dsLen,
                           uint8_t *out,        uint32_t outLen);

/* ---- counter-mode stream ----
 * SHAKE128(seed || counter as 8 little-endian bytes), squeezed one rate-sized
 * block at a time, counter incrementing per block. The block size is part of
 * the result: it decides where one block's bytes end and the next begin.
 * A stream without refills HIFHE_RAND_DRBG_BLOCK bytes at a time from DRBG.
 */
#define HIFHE_RAND_BLOCK 168u    /* SHAKE128 rate; also the refill granularity */
#define HIFHE_RAND_SEED_BYTES 32u
/* Refill granularity of the unseeded stream. Sets how often the DRBG is
 * called, never what the caller reads, so it is free to change. */
#define HIFHE_RAND_DRBG_BLOCK 4096u

typedef struct {
    uint8_t  seeded;
    uint8_t  seed[HIFHE_RAND_SEED_BYTES];
    char     label[HIFHE_DS_MAX];
    uint64_t counter;
    uint8_t  buf[HIFHE_RAND_DRBG_BLOCK];  /* seeded refills use the first HIFHE_RAND_BLOCK */
    uint32_t bufPos;
    uint32_t bufLen;
} BgvRandStream;

/* NULL `seed` selects the DRBG; `label` separates streams under one seed. */
void       BgvRandStream_Init (BgvRandStream *s, const uint8_t *seed, const char *label);
HIFHE_ERROR BgvRandStream_Bytes(BgvRandStream *s, uint8_t *out, uint32_t len);
/* The next 8 stream bytes as a little-endian uint64. */
HIFHE_ERROR BgvRandStream_U64  (BgvRandStream *s, uint64_t *out);
/* Wipe the stream, buffered bytes and seed included. Call before it goes out
 * of scope. */
void       BgvRandStream_Cleanse(BgvRandStream *s);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_BASIC_RAND_H */
