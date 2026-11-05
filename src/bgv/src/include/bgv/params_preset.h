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

/* HIFHE_BGV_PRESET -> BGVParameter seed values. */

#ifndef HIFHE_BGV_PARAMS_PRESET_H
#define HIFHE_BGV_PARAMS_PRESET_H

#include <stdint.h>
#include "hifhe_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t polyDegree;
    uint32_t plainModBit; /* used only when plainMod == 0 */
    uint64_t plainMod; /* if non-zero, overrides Proth search */
    uint64_t correctionFactor;
    uint32_t relinDnum;
    const uint32_t *cipherModBit; /* cipherModBit like {44,45...} */
    uint32_t cipherModBitSize;
    const uint64_t *cipherMod; /* cipherMod, primes of each bit */
    uint32_t cipherModSize;
} BgvPresetPara;

/* Fill `out` from a preset ID. `out->cipherModBit` points into loader-owned
 * storage: do not free it, and copy the slice to outlive the loader. */
HIFHE_ERROR BGV_Preset_Load(BgvPresetPara *out, int32_t presetId);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_BGV_PARAMS_PRESET_H */
