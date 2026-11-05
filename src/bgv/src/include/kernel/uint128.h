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

/* 128-bit unsigned arithmetic over a pair of 64-bit words.
 *
 * The kernel needs the whole product of two modulus-sized words, which no
 * integer type holds on a 32-bit target such as armv7. The pair below is that
 * carrier everywhere, and these operations are the only code that knows how it
 * is built: one instruction each where the compiler has a 128-bit type, 32-bit
 * limbs where it has not. Define HIFHE_NO_INT128 to take the second path on a
 * target that offers the first, which is how it is tested. */

#ifndef HIFHE_KERNEL_UINT128_H
#define HIFHE_KERNEL_UINT128_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__SIZEOF_INT128__) && !defined(HIFHE_NO_INT128)
#define HIFHE_U128_NATIVE 1
#endif

/* The low word first, then the high word. Conversion to and from the
 * compiler's own 128-bit type goes through the helpers below. */
typedef struct {
    uint64_t lo;
    uint64_t hi;
} Uint128;

static inline Uint128 Kernel_U128Make(uint64_t hi, uint64_t lo)
{
    Uint128 r;
    r.lo = lo;
    r.hi = hi;
    return r;
}

static inline Uint128 Kernel_U128From64(uint64_t v)
{
    return Kernel_U128Make(0u, v);
}

#ifdef HIFHE_U128_NATIVE
/* Every operation below goes through these two, so the generated code is the
 * compiler's own 128-bit arithmetic and nothing is paid for the pair. */
typedef unsigned __int128 Uint128Native;

static inline Uint128Native Kernel_U128ToNative(Uint128 v)
{
    return ((Uint128Native)v.hi << 64) | (Uint128Native)v.lo;
}

static inline Uint128 Kernel_U128FromNative(Uint128Native v)
{
    return Kernel_U128Make((uint64_t)(v >> 64), (uint64_t)v);
}
#endif

/* a * b, both words of it. */
static inline Uint128 Kernel_U128Mul(uint64_t a, uint64_t b)
{
#ifdef HIFHE_U128_NATIVE
    return Kernel_U128FromNative((Uint128Native)a * (Uint128Native)b);
#else
    uint64_t aLo = a & 0xffffffffu;
    uint64_t aHi = a >> 32;
    uint64_t bLo = b & 0xffffffffu;
    uint64_t bHi = b >> 32;
    /* Schoolbook over four half-words. Every accumulation below stays under
     * 2^64: a half-word product is at most 2^64 - 2^33 + 1 and what is carried
     * into it is at most 2^32 - 1. */
    uint64_t t = aLo * bLo;
    uint64_t w0 = t & 0xffffffffu;
    uint64_t carry = t >> 32;

    t = aHi * bLo + carry;
    uint64_t w1 = t & 0xffffffffu;
    uint64_t w2 = t >> 32;

    t = aLo * bHi + w1;
    carry = t >> 32;

    return Kernel_U128Make(aHi * bHi + w2 + carry, (t << 32) + w0);
#endif
}

/* The high word of a * b, which is all the Shoup and Barrett steps want. */
static inline uint64_t Kernel_MulHi64(uint64_t a, uint64_t b)
{
    return Kernel_U128Mul(a, b).hi;
}

static inline Uint128 Kernel_U128Add(Uint128 a, Uint128 b)
{
#ifdef HIFHE_U128_NATIVE
    return Kernel_U128FromNative(Kernel_U128ToNative(a) + Kernel_U128ToNative(b));
#else
    Uint128 r;
    r.lo = a.lo + b.lo;
    r.hi = a.hi + b.hi + (uint64_t)(r.lo < a.lo);
    return r;
#endif
}

static inline Uint128 Kernel_U128AddU64(Uint128 a, uint64_t v)
{
#ifdef HIFHE_U128_NATIVE
    return Kernel_U128FromNative(Kernel_U128ToNative(a) + (Uint128Native)v);
#else
    Uint128 r;
    r.lo = a.lo + v;
    r.hi = a.hi + (uint64_t)(r.lo < v);
    return r;
#endif
}

static inline Uint128 Kernel_U128Sub(Uint128 a, Uint128 b)
{
#ifdef HIFHE_U128_NATIVE
    return Kernel_U128FromNative(Kernel_U128ToNative(a) - Kernel_U128ToNative(b));
#else
    Uint128 r;
    r.lo = a.lo - b.lo;
    r.hi = a.hi - b.hi - (uint64_t)(a.lo < b.lo);
    return r;
#endif
}

/* acc + a * b, the accumulation the lazy key-switch loop runs per coefficient. */
static inline Uint128 Kernel_U128MulAdd(Uint128 acc, uint64_t a, uint64_t b)
{
#ifdef HIFHE_U128_NATIVE
    return Kernel_U128FromNative(Kernel_U128ToNative(acc) + (Uint128Native)a * (Uint128Native)b);
#else
    return Kernel_U128Add(acc, Kernel_U128Mul(a, b));
#endif
}

/* The low 128 bits of a * b, for a multiplier that is itself wider than a word. */
static inline Uint128 Kernel_U128MulU64(Uint128 a, uint64_t b)
{
#ifdef HIFHE_U128_NATIVE
    return Kernel_U128FromNative(Kernel_U128ToNative(a) * (Uint128Native)b);
#else
    Uint128 r = Kernel_U128Mul(a.lo, b);
    r.hi += a.hi * b;
    return r;
#endif
}

/* Shifts by 128 or more are not defined here; every caller shifts by a
 * constant it owns. */
static inline Uint128 Kernel_U128Shl(Uint128 a, uint32_t n)
{
#ifdef HIFHE_U128_NATIVE
    return Kernel_U128FromNative(Kernel_U128ToNative(a) << n);
#else
    if (n == 0u) {
        return a;
    }
    if (n >= 64u) {
        return Kernel_U128Make(a.lo << (n - 64u), 0u);
    }
    return Kernel_U128Make((a.hi << n) | (a.lo >> (64u - n)), a.lo << n);
#endif
}

static inline Uint128 Kernel_U128Shr(Uint128 a, uint32_t n)
{
#ifdef HIFHE_U128_NATIVE
    return Kernel_U128FromNative(Kernel_U128ToNative(a) >> n);
#else
    if (n == 0u) {
        return a;
    }
    if (n >= 64u) {
        return Kernel_U128From64(a.hi >> (n - 64u));
    }
    return Kernel_U128Make(a.hi >> n, (a.lo >> n) | (a.hi << (64u - n)));
#endif
}

/* 1 when a > b, 0 otherwise. Written without a branch because the encoder
 * compares a secret-derived fraction here. */
static inline uint64_t Kernel_U128Gt(Uint128 a, Uint128 b)
{
#ifdef HIFHE_U128_NATIVE
    return (uint64_t)(Kernel_U128ToNative(a) > Kernel_U128ToNative(b));
#else
    uint64_t hiGt = (uint64_t)(a.hi > b.hi);
    uint64_t hiEq = (uint64_t)(a.hi == b.hi);
    return hiGt | (hiEq & (uint64_t)(a.lo > b.lo));
#endif
}

/* The three below need d != 0 and return zero if it is. */
Uint128 Kernel_U128DivU64(Uint128 x, uint64_t d);
uint64_t Kernel_U128ModU64(Uint128 x, uint64_t d);
Uint128 Kernel_U128Div(Uint128 x, Uint128 d);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_KERNEL_UINT128_H */
