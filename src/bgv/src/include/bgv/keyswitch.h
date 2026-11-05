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
 * Key switching, shared by Relinearize and Rotate.
 *
 *   p   = sum_i y_i * qhat_i        (mod Q),  qhat_i = prod_{m != i} q_m
 *   y_i = [p_i * qhat_i^-1]_{q_i}
 *   y_i = sum_j d_{i,j} * T^j       (T = 2^logT, d < T)
 *
 * The base follows from the digit count: logT = ceil(widest limb bits /
 * digits) (BGV_KeySwitch_LogT), so any digit count from 1 up covers the
 * limb. Fewer digits mean fewer transforms but more key-switch noise, which
 * grows with T; BGV_KeySwitch_DefaultDigits picks the count.
 *
 * piece(i, j) encrypts T^j * qhat_i * target, so summing d_{i,j} * piece(i, j)
 * gives an encryption of p * target. L = 1 gives qhat_0 = 1, i.e. plain BV.
 */

#ifndef HIFHE_BGV_KEYSWITCH_H
#define HIFHE_BGV_KEYSWITCH_H

#include <stdint.h>
#include "hifhe_err.h"
#include "bgv/bgv.h"
#include "bgv/ciphertext.h"
#include "bgv/keys.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Digit width of the historic fixed gadget, and the fallback base: the
 * widest a digit is allowed to be when the chain has no noise to spare. */
#define BGV_KSW_LOG_T 16u
/* A limb is at most 64 bits, so no further base-2^16 digit can be nonzero. */
#define BGV_KSW_MAX_DIGITS ((64u + BGV_KSW_LOG_T - 1u) / BGV_KSW_LOG_T)
/* Bits of budget, beyond one limb and the plaintext modulus, that the
 * default digit count leaves above the estimated key-switch noise. */
#define BGV_KSW_NOISE_MARGIN_BITS 10u

/* Digit width for `digits` digits per limb over `base`. */
uint32_t BGV_KeySwitch_LogT(const RnsBase *base, uint32_t digits);

/* Default digits per limb for a chain. A single- or two-limb chain keeps the
 * base-2^16 gadget. A longer one takes the fewest digits whose estimated
 * key-switch noise, t * T * sqrt(N * L * digits) with slack, stays below
 * Q / (q_last * t * 2^BGV_KSW_NOISE_MARGIN_BITS): the switched ciphertext
 * keeps more than a limb of budget, and one mod-switch after the
 * relinearization or rotation brings the term down to rounding level. */
uint32_t BGV_KeySwitch_DefaultDigits(const RnsBase *base, uint32_t polyDegree, Modulus plainMod);

/* `polyNtt` is the target factor: c2 for relin, sigma_k(c1) for rotate.
 * `kswPieces` is the gadget array, indexed [i * digits + j]. `out` must be a
 * size-2 ciphertext on the full chain; it is zeroed, then accumulated into.
 * The caller folds it back into its running (c0, c1). */
HIFHE_ERROR BGV_KeySwitch_Run(Ciphertext *out, const CrtPoly *polyNtt, const Ciphertext *kswPieces, uint32_t rnsSize,
                              uint32_t digits, BGVContext *ctx);

/* gadgetPerLimb[l] = (2^logT)^digit * q-hat_i mod q_l, for l over the whole chain.
 * Shared with keygen, which needs the same factor to build piece (i, digit).
 * `out` must have room for `base->size` entries. */
HIFHE_ERROR BGV_KeySwitch_GadgetFactor(uint64_t *out, const RnsBase *base, uint32_t limbIndex, uint32_t digit,
                                       uint32_t logT);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_BGV_KEYSWITCH_H */
