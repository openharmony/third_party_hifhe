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

/* Samplers used by keygen / encrypt. Entropy comes from basic/rand.h. */

#ifndef HIFHE_KERNEL_SAMPLER_H
#define HIFHE_KERNEL_SAMPLER_H

#include <stdint.h>
#include <stddef.h>
#include "hifhe_err.h"
#include "basic/rand.h"
#include "kernel/modulus.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Entropy arrives as an BgvEntropy, so a seeded draw always carries a label.
 * Two draws under the same (seed, label) return the same output. */

/* Uniform mod q into `out[0..count)`. `limbIndex` separates the seeded
 * streams of one chain: without it every limb replays the same candidates and
 * the residues come out correlated instead of independent. */
HIFHE_ERROR Kernel_Sampler_UniformModQ(uint64_t *out, uint32_t count, Modulus q, uint32_t limbIndex,
                                       const BgvEntropy *src);

/* Ternary secret, `count` outputs into `out[0..count)` in signed int64. */
HIFHE_ERROR Kernel_Sampler_Ternary(int64_t *out, uint32_t count, const BgvEntropy *src);

/* Fixed-Hamming-weight ternary: weight/2 entries +1, weight/2 entries -1,
 * rest 0, then shuffled. Construction order matters for seeded replay:
 * +1 block, -1 block, then Fisher-Yates walking i from `count` down to 1,
 * swapping i-1 with a uniform j in [0, i).
 * `weight` rounds down to even; weight > count is rejected. */
HIFHE_ERROR Kernel_Sampler_TernaryFixedWeight(int64_t *out, uint32_t count, uint32_t weight, const BgvEntropy *src);

/* CBD(eta) noise into `out[0..count)`, signed int64. */
HIFHE_ERROR Kernel_Sampler_CBD(int64_t *out, uint32_t count, uint32_t eta, const BgvEntropy *src);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_KERNEL_SAMPLER_H */
