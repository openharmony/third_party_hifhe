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
 * Negacyclic NTT over Z_q[x]/(x^N+1), q = 1 mod 2N.
 * Forward maps natural order to bit-reversed order. Inverse is the reverse
 * and applies N^-1.
 *
 * Butterflies use Shoup multiplication. Each twiddle w is stored with
 * floor(w * 2^64 / q), which replaces the modular reduction with two
 * multiplications and a conditional subtraction. Intermediate values stay in
 * [0, 4q) and are reduced once at the end. Requires q < 2^62.
 *
 * NttTables points at twiddle arrays owned by the caller.
 */

#ifndef HIFHE_KERNEL_NTT_H
#define HIFHE_KERNEL_NTT_H

#include <stdint.h>
#include <stddef.h>
#include "hifhe_err.h"
#include "kernel/modulus.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Buffer layout for one modulus: four arrays of polyDegree (roots, invRoots,
 * rootsQuot, invRootsQuot) followed by the scalars nInvModQ and nInvQuot. */
#define HIFHE_NTT_TABLE_ARRAYS 4u
#define HIFHE_NTT_TABLE_WORDS(polyDegree) ((size_t)(polyDegree) * HIFHE_NTT_TABLE_ARRAYS + 2u)

/* roots and invRoots are in bit-reversed order. The Quot arrays hold the
 * matching Shoup quotients. nInvModQ is N^-1 mod q, applied in the last
 * inverse layer. */
typedef struct {
    Modulus  q;
    uint32_t polyDegree;   /* N (power of two) */
    uint32_t logN;         /* log2(N) */
    const uint64_t *roots;         /* size N: bit-reversed forward twiddles */
    const uint64_t *invRoots;      /* size N: bit-reversed inverse twiddles */
    const uint64_t *rootsQuot;     /* size N: floor(roots[k] * 2^64 / q) */
    const uint64_t *invRootsQuot;  /* size N: floor(invRoots[k] * 2^64 / q) */
    uint64_t  nInvModQ;
    uint64_t  nInvQuot;    /* Shoup quotient for nInvModQ */
    BarrettConst  barrett;
} NttTables;

/* Forward, in-place. In: coefficients < q. Out: bit-reversed NTT form. */
HIFHE_ERROR Kernel_Ntt_Forward (uint64_t *poly, const NttTables *tbl);

/* Inverse. In: bit-reversed NTT form. Out: coefficients < q. */
HIFHE_ERROR Kernel_Ntt_Inverse (uint64_t *poly, const NttTables *tbl);

/* Compute the tables for (q, polyDegree) into buf and fill tbl.
 * buf holds HIFHE_NTT_TABLE_WORDS(polyDegree) uint64. The caller owns it and
 * must keep it alive while tbl is in use. */
HIFHE_ERROR Kernel_Ntt_BuildTables(NttTables *tbl, uint64_t *buf,
                                 Modulus q, uint32_t polyDegree);

/* Fill tbl from tables buf already holds. Computes only the Barrett constant.
 * buf is neither copied nor freed. */
HIFHE_ERROR Kernel_Ntt_AttachTables(NttTables *tbl, const uint64_t *buf,
                                  Modulus q, uint32_t polyDegree);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_KERNEL_NTT_H */
