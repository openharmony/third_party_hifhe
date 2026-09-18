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

/* Proth prime search (q = 1 mod 2N). Build-time only. */

#ifndef HIFHE_KERNEL_PRIME_H
#define HIFHE_KERNEL_PRIME_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "hifhe_err.h"
#include "kernel/modulus.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Find a `bits`-wide prime q = 1 mod 2*polyDegree, skipping anything in
 * `avoid[0..avoidLen)`. HIFHE_PARAM_INVALID if the search is exhausted. */
HIFHE_ERROR Kernel_Prime_FindProth(Modulus *out,
                                 uint32_t bits, uint32_t polyDegree,
                                 const Modulus *avoid, uint32_t avoidLen);

/* Deterministic over the whole uint64 range. */
bool Kernel_Prime_IsPrime(uint64_t n);

/* Primitive 2N-th root of unity in F_q. HIFHE_PARAM_INVALID if none. */
HIFHE_ERROR Kernel_Prime_PrimitiveRoot2N(uint64_t *out,
                                       Modulus q, uint32_t polyDegree);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_KERNEL_PRIME_H */
