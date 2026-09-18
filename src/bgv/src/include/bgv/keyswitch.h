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
 *   y_i = sum_j d_{i,j} * T^j       (T = 2^16, d < T)
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

/* Base-T digit width, shared with keygen. */
#define BGV_KSW_LOG_T   16u
#define BGV_KSW_T       (1ull << BGV_KSW_LOG_T)
#define BGV_KSW_MASK    ((1ull << BGV_KSW_LOG_T) - 1u)
/* A limb is at most 64 bits, so no further digit can be nonzero. */
#define BGV_KSW_MAX_DIGITS ((64u + BGV_KSW_LOG_T - 1u) / BGV_KSW_LOG_T)

/* `polyNtt` is the target factor: c2 for relin, sigma_k(c1) for rotate.
 * `kswPieces` is the gadget array, indexed [i * digits + j]. `out` must be a
 * size-2 ciphertext on the full chain; it is zeroed, then accumulated into.
 * The caller folds it back into its running (c0, c1). */
HIFHE_ERROR BGV_KeySwitch_Run(Ciphertext *out, const CrtPoly *polyNtt,
                            const Ciphertext *kswPieces,
                            uint32_t rnsSize, uint32_t digits,
                            BGVContext *ctx);

/* gadgetPerLimb[l] = T^digit * q-hat_i mod q_l, for l over the whole chain.
 * Shared with keygen, which needs the same factor to build piece (i, digit).
 * `out` must have room for `base->size` entries. */
HIFHE_ERROR BGV_KeySwitch_GadgetFactor(uint64_t *out, const RnsBase *base,
                                     uint32_t limbIndex, uint32_t digit);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_BGV_KEYSWITCH_H */
