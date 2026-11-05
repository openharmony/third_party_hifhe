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

#include "hifhe_err_internal.h"
#include "kernel/modulus.h"

/* Division of a 128-bit value, declared in kernel/uint128.h. Only the setup
 * paths divide, so it is not inline. */

#ifndef HIFHE_U128_NATIVE

/* Leading zero count, without a compiler builtin. */
static uint32_t Nlz64(uint64_t x)
{
    uint32_t n = 0u;
    if (x <= 0x00000000ffffffffu) {
        n += 32u;
        x <<= 32;
    }
    if (x <= 0x0000ffffffffffffu) {
        n += 16u;
        x <<= 16;
    }
    if (x <= 0x00ffffffffffffffu) {
        n += 8u;
        x <<= 8;
    }
    if (x <= 0x0fffffffffffffffu) {
        n += 4u;
        x <<= 4;
    }
    if (x <= 0x3fffffffffffffffu) {
        n += 2u;
        x <<= 2;
    }
    if (x <= 0x7fffffffffffffffu) {
        n += 1u;
    }
    return n;
}

/* (u1:u0) / v for u1 < v and v != 0, so the quotient is one word. Knuth
 * algorithm D over half-words: the divisor is normalised to put its top bit in
 * place, each half of the quotient is estimated from the two leading
 * half-words, and the estimate is at most two too large. */
static uint64_t DivLu(uint64_t u1, uint64_t u0, uint64_t v, uint64_t *rem)
{
    const uint64_t b = (uint64_t)1u << 32; /* half-word base */
    uint32_t s = Nlz64(v);
    uint64_t un64;
    uint64_t un10;

    v <<= s;
    if (s > 0u) {
        un64 = (u1 << s) | (u0 >> (64u - s));
        un10 = u0 << s;
    } else {
        un64 = u1;
        un10 = u0;
    }

    uint64_t vn1 = v >> 32;
    uint64_t vn0 = v & 0xffffffffu;
    uint64_t un1 = un10 >> 32;
    uint64_t un0 = un10 & 0xffffffffu;

    uint64_t q1 = un64 / vn1;
    uint64_t rhat = un64 - q1 * vn1;
    while (q1 >= b || q1 * vn0 > b * rhat + un1) {
        q1--;
        rhat += vn1;
        if (rhat >= b) {
            break;
        }
    }

    uint64_t un21 = un64 * b + un1 - q1 * v;
    uint64_t q0 = un21 / vn1;
    rhat = un21 - q0 * vn1;
    while (q0 >= b || q0 * vn0 > b * rhat + un0) {
        q0--;
        rhat += vn1;
        if (rhat >= b) {
            break;
        }
    }

    *rem = (un21 * b + un0 - q0 * v) >> s;
    return q1 * b + q0;
}

static void DivModU64(Uint128 x, uint64_t d, Uint128 *quo, uint64_t *rem)
{
    if (x.hi < d) {
        *quo = Kernel_U128From64(DivLu(x.hi, x.lo, d, rem));
        return;
    }
    /* Two words of quotient: the high one divides on its own, and its
     * remainder becomes the high half of the second division. */
    uint64_t qHi = x.hi / d;
    uint64_t qLo = DivLu(x.hi % d, x.lo, d, rem);
    *quo = Kernel_U128Make(qHi, qLo);
}

#endif /* HIFHE_U128_NATIVE */

Uint128 Kernel_U128DivU64(Uint128 x, uint64_t d)
{
    if (d == 0u) {
        return Kernel_U128From64(0u);
    }
#ifdef HIFHE_U128_NATIVE
    return Kernel_U128FromNative(Kernel_U128ToNative(x) / (Uint128Native)d);
#else
    Uint128 quo;
    uint64_t rem;
    DivModU64(x, d, &quo, &rem);
    return quo;
#endif
}

uint64_t Kernel_U128ModU64(Uint128 x, uint64_t d)
{
    if (d == 0u) {
        return 0u;
    }
#ifdef HIFHE_U128_NATIVE
    return (uint64_t)(Kernel_U128ToNative(x) % (Uint128Native)d);
#else
    Uint128 quo;
    uint64_t rem;
    DivModU64(x, d, &quo, &rem);
    return rem;
#endif
}

Uint128 Kernel_U128Div(Uint128 x, Uint128 d)
{
    if (d.hi == 0u) {
        return Kernel_U128DivU64(x, d.lo);
    }
#ifdef HIFHE_U128_NATIVE
    return Kernel_U128FromNative(Kernel_U128ToNative(x) / Kernel_U128ToNative(d));
#else
    /* Restoring division, one bit of quotient per step. A divisor wider than a
     * word is only divided once per key-switch limb, so the 128 steps cost
     * nothing worth a faster estimate. */
    Uint128 quo = Kernel_U128From64(0u);
    Uint128 rem = Kernel_U128From64(0u);
    for (uint32_t i = 128u; i-- > 0u;) {
        uint64_t bit = ((i >= 64u) ? (x.hi >> (i - 64u)) : (x.lo >> i)) & 1u;
        rem = Kernel_U128Shl(rem, 1u);
        rem.lo |= bit;
        quo = Kernel_U128Shl(quo, 1u);
        if (Kernel_U128Gt(d, rem) == 0u) {
            rem = Kernel_U128Sub(rem, d);
            quo.lo |= 1u;
        }
    }
    return quo;
#endif
}

uint32_t Kernel_Log2Ceil(uint64_t x)
{
    if (x <= 1u) {
        return 0u;
    }
    uint32_t r = 0u;
    uint64_t v = x - 1u;
    while (v > 0u) {
        v >>= 1;
        r++;
    }
    return r;
}

HIFHE_ERROR Kernel_BarrettConst_Init(BarrettConst *out, Modulus q)
{
    if (out == NULL || q < 2u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    out->q = q;
    out->qBits = Kernel_Log2Ceil(q);
    /* ratio = floor((2^128 - 1) / q), which equals floor(2^128 / q) for q >= 3. */
    Uint128 r = Kernel_U128DivU64(Kernel_U128Make(UINT64_MAX, UINT64_MAX), q);
    out->ratioLo = r.lo;
    out->ratioHi = r.hi;
    return HIFHE_SUCCESS;
}

/* Straightforward 64x64 -> 128 -> mod q, no precomputation. */
uint64_t Kernel_MulMod(uint64_t a, uint64_t b, Modulus q)
{
    return Kernel_U128ModU64(Kernel_U128Mul(a, b), q);
}

uint64_t Kernel_PowMod(uint64_t a, uint64_t e, Modulus q)
{
    if (q <= 1u) {
        return 0u;
    }
    uint64_t base = a % q;
    uint64_t acc = 1u % q;
    while (e > 0u) {
        if ((e & 1u) != 0u) {
            acc = Kernel_MulMod(acc, base, q);
        }
        base = Kernel_MulMod(base, base, q);
        e >>= 1;
    }
    return acc;
}

uint64_t Kernel_ModInv(uint64_t a, Modulus q)
{
    if (q <= 1u) {
        return 0u;
    }
    uint64_t r0 = q, r1 = a % q;
    /* Bezout coefficient of r_i, carried as its residue mod q rather than as
     * a signed value, which keeps every step inside a word. */
    uint64_t s0 = 0u, s1 = 1u % q;
    while (r1 != 0u) {
        uint64_t quo = r0 / r1;
        uint64_t r2 = r0 - quo * r1;
        uint64_t sub = Kernel_MulMod(quo % q, s1, q);
        uint64_t s2 = s0 - sub;
        s2 += q & (0u - (uint64_t)(s0 < sub));
        r0 = r1;
        r1 = r2;
        s0 = s1;
        s1 = s2;
    }
    if (r0 != 1u) {
        return 0u; /* not invertible */
    }
    return s0;
}

/*
 * Both reductions estimate floor(x / q) as the top word of x * ratio, where
 * ratio = floor(2^128 / q). That product is wider than 128 bits, so it is
 * accumulated from the partial products that reach the top word. Forming
 * x * ratio directly overflows and gives a wrong quotient for x above roughly
 * 2^(128 - qBits).
 *
 * ratio is a floor, so qhat never exceeds the true quotient and the remainder
 * is never negative. The correction loop runs at most twice.
 */

/* Barrett reduce a 64-bit input mod q. */
uint64_t Kernel_BarrettReduce64(uint64_t x, const BarrettConst *bc)
{
    return Kernel_BarrettReduce64Inl(x, bc);
}

uint64_t Kernel_BarrettReduce128(uint64_t xHi, uint64_t xLo, const BarrettConst *bc)
{
    return Kernel_BarrettReduce128Inl(xHi, xLo, bc);
}

HIFHE_ERROR Kernel_ShoupConst_Init(ShoupConst *out, uint64_t operand, Modulus q)
{
    if (out == NULL || q < 2u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    if (operand >= q) {
        operand %= q;
    }
    out->q = q;
    out->operand = operand;
    /* quotient = floor((operand << 64) / q) */
    out->quotient = Kernel_U128DivU64(Kernel_U128Make(operand, 0u), q).lo;
    return HIFHE_SUCCESS;
}

/* Shoup fast mul-mod. Preconditions: operand < q, x < q, q < 2^63. */
uint64_t Kernel_ShoupMulMod(uint64_t x, const ShoupConst *sc)
{
    return Kernel_ShoupMulModInl(x, sc);
}
