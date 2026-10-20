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
 * Miller-Rabin over uint64 plus Proth prime search.
 *
 * Witnesses {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37} are deterministic
 * for n < 3.19e23, which is past 2^64, so every candidate here is decided
 * exactly.
 */

#include <stdbool.h>
#include "kernel/prime.h"
#include "kernel/modulus.h"

static uint64_t MulModU64(uint64_t a, uint64_t b, uint64_t m)
{
    return (uint64_t)(((ModulusWide)a * (ModulusWide)b) % (ModulusWide)m);
}

static uint64_t PowModU64(uint64_t base, uint64_t exp, uint64_t m)
{
    uint64_t r = 1u % m;
    base %= m;
    while (exp > 0u) {
        if (exp & 1u) r = MulModU64(r, base, m);
        base = MulModU64(base, base, m);
        exp >>= 1;
    }
    return r;
}

/* One Miller-Rabin round. `n` odd, `n > 3`. */
static bool MillerRabinWitness(uint64_t n, uint64_t d, uint32_t r, uint64_t a)
{
    if (a % n == 0u) return true;      /* trivial; treat as pass */
    uint64_t x = PowModU64(a, d, n);
    if (x == 1u || x == n - 1u) return true;
    for (uint32_t i = 1; i < r; ++i) {
        x = MulModU64(x, x, n);
        if (x == n - 1u) return true;
    }
    return false;
}

static bool IsPrimeU64(uint64_t n)
{
    if (n < 2u) return false;
    if (n < 4u) return true;                 /* 2, 3 */
    if ((n & 1u) == 0u) return false;

    /* fast reject */
    static const uint32_t kSmall[] = { 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };
    for (uint32_t i = 0; i < sizeof(kSmall)/sizeof(kSmall[0]); ++i) {
        if (n == kSmall[i]) return true;
        if (n % kSmall[i] == 0u) return false;
    }

    /* Decompose n - 1 = d * 2^r. */
    uint64_t d = n - 1u;
    uint32_t r = 0u;
    while ((d & 1u) == 0u) { d >>= 1; r++; }

    static const uint64_t kWit[] = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };
    for (uint32_t i = 0; i < sizeof(kWit)/sizeof(kWit[0]); ++i) {
        if (!MillerRabinWitness(n, d, r, kWit[i])) return false;
    }
    return true;
}

bool Kernel_Prime_IsPrime(uint64_t n)
{
    return IsPrimeU64(n);
}

/* log2 of a power of two. */
static uint32_t LogTwoU64(uint64_t x)
{
    uint32_t r = 0u;
    while ((x >>= 1) != 0u) r++;
    return r;
}

/*
 * Proth search. Candidates q = 2N*k + 1, with k walking down from
 * 2^(bits - log2(N) - 1) - 1 so q is exactly `bits` wide. The start point
 * and the downward direction fix which prime a request lands on, so both
 * match the predecessor generator. Capped at HIFHE_PROTH_MAX_STEPS.
 */
#define HIFHE_PROTH_MAX_STEPS 1000u

HIFHE_ERROR Kernel_Prime_FindProth(Modulus *out,
                                 uint32_t bits, uint32_t polyDegree,
                                 const Modulus *avoid, uint32_t avoidLen)
{
    if (out == NULL) return HIFHE_NULL_INPUT;
    if (bits < 8u || bits > 62u) return HIFHE_PARAM_INVALID;
    if (polyDegree == 0u || (polyDegree & (polyDegree - 1u)) != 0u) {
        return HIFHE_PARAM_INVALID;
    }

    uint32_t logN = LogTwoU64(polyDegree);
    /* Below this the starting k underflows. */
    if (bits < logN + 2u) return HIFHE_PARAM_INVALID;

    uint64_t twoN = (uint64_t)polyDegree * 2u;
    uint64_t k = (1ull << (bits - logN - 1u)) - 1u;

    for (uint32_t step = 0; step < HIFHE_PROTH_MAX_STEPS && k > 0u; ++step, --k) {
        uint64_t cand = twoN * k + 1u;

        bool skip = false;
        for (uint32_t i = 0; i < avoidLen; ++i) {
            if (avoid[i] == cand) {
                skip = true;
                break;
            }
        }
        if (skip) continue;
        if (!IsPrimeU64(cand)) continue;

        uint64_t root = 0u;
        if (Kernel_Prime_PrimitiveRoot2N(&root, cand, polyDegree) != HIFHE_SUCCESS) continue;

        *out = cand;
        return HIFHE_SUCCESS;
    }
    return HIFHE_PARAM_INVALID;
}

/* Primitive 2N-th root of unity in F_q. Assumes q = 1 mod 2N. */
HIFHE_ERROR Kernel_Prime_PrimitiveRoot2N(uint64_t *out, Modulus q, uint32_t polyDegree)
{
    if (out == NULL) return HIFHE_NULL_INPUT;
    if (q < 3u) return HIFHE_PARAM_INVALID;
    uint64_t twoN = (uint64_t)polyDegree * 2u;
    if ((q - 1u) % twoN != 0u) return HIFHE_PARAM_INVALID;
    uint64_t exp = (q - 1u) / twoN;

    /* w = g^exp has order exactly 2N iff w^N == q - 1. */
    for (uint64_t g = 2u; g < 200u; ++g) {
        uint64_t w = PowModU64(g, exp, q);
        if (w <= 1u) continue;
        uint64_t wN = PowModU64(w, polyDegree, q);
        if (wN == q - 1u) {
            *out = w;
            return HIFHE_SUCCESS;
        }
    }
    return HIFHE_PARAM_INVALID;
}

