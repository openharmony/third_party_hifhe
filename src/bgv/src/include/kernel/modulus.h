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

/* Modulus type and modular arithmetic primitives. */

#ifndef HIFHE_KERNEL_MODULUS_H
#define HIFHE_KERNEL_MODULUS_H

#include <stdint.h>
#include <stddef.h>
#include "hifhe_err.h"
#include "kernel/uint128.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t Modulus;

/* Barrett constant: ratio = floor(2^128 / q), kept as two words.
 * Populated at BGVContext build time. */
typedef struct {
    Modulus q;
    uint64_t ratioLo; /* low  64 bits of floor(2^128 / q) */
    uint64_t ratioHi; /* high 64 bits */
    uint32_t qBits; /* ceil(log2(q)); useful for lazy-reduction bounds */
} BarrettConst;

/* Shoup constant: quotient = floor((m << 64) / q). Turns mul-mod into one
 * 128-bit mul plus a conditional subtraction. Populated lazily per (m, q). */
typedef struct {
    Modulus q;
    uint64_t operand;
    uint64_t quotient;
} ShoupConst;

HIFHE_ERROR Kernel_BarrettConst_Init(BarrettConst *out, Modulus q);
uint64_t Kernel_BarrettReduce64(uint64_t x, const BarrettConst *bc);
uint64_t Kernel_BarrettReduce128(uint64_t xHi, uint64_t xLo, const BarrettConst *bc);

HIFHE_ERROR Kernel_ShoupConst_Init(ShoupConst *out, uint64_t operand, Modulus q);
uint64_t Kernel_ShoupMulMod(uint64_t x, const ShoupConst *sc);

/* Straightforward mul-mod, no precomputation. Divides, so it is for setup. */
uint64_t Kernel_MulMod(uint64_t a, uint64_t b, Modulus q);

/* a^e mod q via square-and-multiply. */
uint64_t Kernel_PowMod(uint64_t a, uint64_t e, Modulus q);

/* Extended Euclid. Returns 0 when gcd(a, q) != 1. For the moduli shipped
 * here (primes, or t coprime to q) 0 always means failure. */
uint64_t Kernel_ModInv(uint64_t a, Modulus q);

/* ceil(log2(x)), the bit count of x - 1. 0 for x <= 1. */
uint32_t Kernel_Log2Ceil(uint64_t x);

/* Inline bodies of the reductions above, for hot loops. The exported
 * functions wrap these; without LTO a cross-file call per coefficient costs
 * more than the arithmetic. */
/* r - q when r >= q, r otherwise, selected by mask and not by branch. Every
 * reduction below ends in these, and their inputs are secret-derived. */
static inline uint64_t Kernel_CondSubInl(uint64_t r, uint64_t q)
{
    return r - (q & (0u - (uint64_t)(r >= q)));
}

/* x mod q, for any x. ratio >= 2^128/q - 1 and the one truncated term below
 * cost less than two whole quotient steps together, so qhat is q or q-1 off
 * the true quotient and r < 2q: one correction, always taken or not. */
static inline uint64_t Kernel_BarrettReduce64Inl(uint64_t x, const BarrettConst *bc)
{
    Uint128 acc = Kernel_U128Mul(x, bc->ratioHi);
    acc = Kernel_U128AddU64(acc, Kernel_MulHi64(x, bc->ratioLo));
    uint64_t qhat = acc.hi;
    uint64_t r = x - qhat * bc->q;
    return Kernel_CondSubInl(r, bc->q);
}

/* (xHi, xLo) mod q, for xHi * 2^64 + xLo < q * 2^64. Every column carrying
 * into the 2^128 word is kept, so qhat is floor(x * ratio / 2^128) exactly;
 * ratio is one short of 2^128 / q at worst, which leaves r < 2q and one
 * correction. */
static inline uint64_t Kernel_BarrettReduce128Inl(uint64_t xHi, uint64_t xLo, const BarrettConst *bc)
{
    Uint128 acc = Kernel_U128From64(Kernel_MulHi64(xLo, bc->ratioLo));
    acc = Kernel_U128Add(acc, Kernel_U128Mul(xLo, bc->ratioHi));
    acc = Kernel_U128Add(acc, Kernel_U128Mul(xHi, bc->ratioLo));
    uint64_t qhat = acc.hi + xHi * bc->ratioHi;
    uint64_t r = xLo - qhat * bc->q;
    return Kernel_CondSubInl(r, bc->q);
}

/* a * b mod q through the Barrett constant; a, b < q. */
static inline uint64_t Kernel_BarrettMulModInl(uint64_t a, uint64_t b, const BarrettConst *bc)
{
    Uint128 p = Kernel_U128Mul(a, b);
    return Kernel_BarrettReduce128Inl(p.hi, p.lo, bc);
}

static inline uint64_t Kernel_ShoupMulModInl(uint64_t x, const ShoupConst *sc)
{
    uint64_t qHat = Kernel_MulHi64(x, sc->quotient);
    uint64_t r = x * sc->operand - qHat * sc->q;
    return Kernel_CondSubInl(r, sc->q);
}

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_KERNEL_MODULUS_H */
