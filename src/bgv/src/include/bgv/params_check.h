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

/* BGV parameter admissibility. The max-modulus-bits tables are the
 * HomomorphicEncryption.org estimates for a ternary secret. */

#ifndef HIFHE_BGV_PARAMS_CHECK_H
#define HIFHE_BGV_PARAMS_CHECK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "hifhe_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Longest RNS chain the library will build. Bounds the avoid-list used by
 * the Proth search and the per-limb scratch in key switching. */
#define HIFHE_BGV_MAX_CHAIN_LEN   8u
#define HIFHE_BGV_MIN_CIPHER_BITS 20u
/* 59 is the ceiling the Proth search works within, so validation and
 * generation agree on where the band ends. */
#define HIFHE_BGV_MAX_CIPHER_BITS 59u
#define HIFHE_BGV_MIN_PLAIN_BITS   2u
#define HIFHE_BGV_MAX_PLAIN_BITS  59u

/* N must be a power of two in [1024, 32768], the range covered by the
 * security tables and the Proth search. */
bool BGV_Params_IsPolyDegreeSupported (uint32_t polyDegree);
bool BGV_Params_IsPlainModBitSupported(uint32_t bits);
bool BGV_Params_IsCipherModBitSupported(uint32_t bits);
bool BGV_Params_IsChainLenSupported   (uint32_t chainLen);

/* Max total ciphertext-modulus bits for a ternary secret. Returns 0 for an
 * unsupported (polyDegree, securityLevel) pair. */
uint32_t BGV_Params_HEMaxBitsTernaryClassical(uint32_t polyDegree, uint32_t securityLevel);

/* Full combination check. Returns HIFHE_SUCCESS or HIFHE_PARAM_INVALID.
 * `securityLevel` of 0 falls back to HIFHE_BGV_DEFAULT_SECURITY_LEVEL. */
HIFHE_ERROR BGV_Params_Validate(uint32_t polyDegree,
                              uint32_t plainModBit,
                              const uint32_t *cipherModBit,
                              uint32_t chainLen,
                              uint32_t securityLevel);

/* A pinned plaintext modulus must be NTT-friendly for this ring
 * (t = 1 mod 2N) so the batching (LUT) encoder can transform under it. */
bool BGV_Params_IsPlainModNttFriendly(uint64_t plainMod, uint32_t polyDegree);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_BGV_PARAMS_CHECK_H */
