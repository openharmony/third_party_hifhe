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

#include "kernel/modulus.h"

uint32_t Kernel_Log2Ceil(uint64_t x)
{
    if (x <= 1u) return 0u;
    uint32_t r = 0u;
    uint64_t v = x - 1u;
    while (v > 0u) { v >>= 1; r++; }
    return r;
}

HIFHE_ERROR Kernel_BarrettConst_Init(BarrettConst *out, Modulus q)
{
    if (out == NULL || q < 2u) return HIFHE_PARAM_INVALID;
    out->q = q;
    out->qBits = Kernel_Log2Ceil(q);
    /* ratio = floor((2^128 - 1) / q), which equals floor(2^128 / q) for q >= 3. */
    ModulusWide num = (~(ModulusWide)0);           /* 2^128 - 1 */
    ModulusWide r = num / (ModulusWide)q;
    out->ratioLo = (uint64_t)r;
    out->ratioHi = (uint64_t)(r >> 64);
    return HIFHE_SUCCESS;
}

/* Straightforward 64x64 -> 128 -> mod q, no precomputation. */
uint64_t Kernel_MulMod(uint64_t a, uint64_t b, Modulus q)
{
    return (uint64_t)(((ModulusWide)a * (ModulusWide)b) % (ModulusWide)q);
}

uint64_t Kernel_PowMod(uint64_t a, uint64_t e, Modulus q)
{
    if (q <= 1u) return 0u;
    uint64_t base = a % q;
    uint64_t acc  = 1u % q;
    while (e > 0u) {
        if ((e & 1u) != 0u) acc = Kernel_MulMod(acc, base, q);
        base = Kernel_MulMod(base, base, q);
        e >>= 1;
    }
    return acc;
}

uint64_t Kernel_ModInv(uint64_t a, Modulus q)
{
    if (q <= 1u) return 0u;
    uint64_t r0 = q, r1 = a % q;
    /* Bezout coefficient of r1, signed, in [-q, q]. */
    __int128 s0 = 0, s1 = 1;
    while (r1 != 0u) {
        uint64_t quo = r0 / r1;
        uint64_t r2  = r0 - quo * r1;
        __int128 s2  = s0 - (__int128)quo * s1;
        r0 = r1; r1 = r2;
        s0 = s1; s1 = s2;
    }
    if (r0 != 1u) return 0u;            /* not invertible */
    __int128 inv = s0 % (__int128)q;
    if (inv < 0) inv += (__int128)q;
    return (uint64_t)inv;
}

/*
 * Both reductions estimate floor(x / q) as the top word of x * ratio, where
 * ratio = floor(2^128 / q). That product is wider than ModulusWide, so it is
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
    ModulusWide acc = (ModulusWide)x * (ModulusWide)bc->ratioHi;
    acc += ((ModulusWide)x * (ModulusWide)bc->ratioLo) >> 64;
    uint64_t qhat = (uint64_t)(acc >> 64);
    uint64_t r = x - qhat * bc->q;
    while (r >= bc->q) r -= bc->q;
    return r;
}

uint64_t Kernel_BarrettReduce128(uint64_t xHi, uint64_t xLo, const BarrettConst *bc)
{
    ModulusWide acc = (ModulusWide)xHi * (ModulusWide)bc->ratioHi;
    acc += ((ModulusWide)xHi * (ModulusWide)bc->ratioLo) >> 64;
    acc += ((ModulusWide)xLo * (ModulusWide)bc->ratioHi) >> 64;
    uint64_t qhat = (uint64_t)acc;
    uint64_t r = xLo - qhat * bc->q;
    while (r >= bc->q) r -= bc->q;
    return r;
}

HIFHE_ERROR Kernel_ShoupConst_Init(ShoupConst *out, uint64_t operand, Modulus q)
{
    if (out == NULL || q < 2u) return HIFHE_PARAM_INVALID;
    if (operand >= q) operand %= q;
    out->q = q;
    out->operand = operand;
    /* quotient = floor((operand << 64) / q) */
    ModulusWide num = ((ModulusWide)operand) << 64;
    out->quotient = (uint64_t)(num / (ModulusWide)q);
    return HIFHE_SUCCESS;
}

/* Shoup fast mul-mod. Preconditions: operand < q, x < q, q < 2^63. */
uint64_t Kernel_ShoupMulMod(uint64_t x, const ShoupConst *sc)
{
    /* high 64 bits of x * quotient */
    uint64_t qHat = (uint64_t)(((ModulusWide)x * (ModulusWide)sc->quotient) >> 64);
    uint64_t r = x * sc->operand - qHat * sc->q;
    if (r >= sc->q) r -= sc->q;
    return r;
}

