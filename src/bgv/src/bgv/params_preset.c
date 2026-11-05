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

/* Preset tables. Cipher-mod bit slices are static const; BGV_Preset_Load
 * returns pointers into them (loader-owned, do not free). */

#include <stddef.h>
#include "hifhe_err_internal.h"
#include "hifhe_types.h"
#include "hifhe_err.h"
#include "bgv/params_preset.h"
#include "bgv/bgv.h"

/* ---- 2048 / 48-bit single-slice presets ---- */
static const uint32_t kCipherBits_2048_48[] = {48u};
/* The default preset names its modulus rather than taking whatever the Proth
 * walk reaches first, so the ring is fixed by the header and not by the
 * search's starting point. 48 bits, 1 mod 4096, inside the 54-bit budget
 * that N=2048 has at the 128-bit level. */
static const uint64_t kCipherMod_default[] = {140786965118977ull};
/* ---- 4096 / 2 x 44-bit chain ---- */
static const uint32_t kCipherBits_4096_44x2[] = {44u, 44u};
/* ---- 8192 / 4-limb chain. Widths are 43,43,44,44 rather than a flat 44:
 * this is the chain the "44x4" preset has always carried, and the name is
 * kept so an existing caller's preset id still means the same ring. ---- */
static const uint32_t kCipherBits_8192_44x4[] = {43u, 43u, 44u, 44u};

HIFHE_ERROR BGV_Preset_Load(BgvPresetPara *out, int32_t presetId)
{
    if (out == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    /* Zero the struct so callers reading un-set fields see 0. */
    out->polyDegree = 0u;
    out->plainModBit = 0u;
    out->plainMod = 0ull;
    out->correctionFactor = HIFHE_BGV_DEFAULT_CORRECTION_FACTOR;
    out->relinDnum = HIFHE_BGV_DEFAULT_RELIN_DNUM;
    out->cipherModBit = NULL;
    out->cipherModBitSize = 0u;
    out->cipherMod = NULL;
    out->cipherModSize = 0u;

    switch (presetId) {
        case HIFHE_BGV_DEFAULT:
            out->polyDegree = 2048u;
            out->plainModBit = 17u;
            out->plainMod = 0ull; /* fall back to Proth search */
            out->cipherModBit = kCipherBits_2048_48;
            out->cipherModBitSize = (uint32_t)(sizeof(kCipherBits_2048_48) / sizeof(uint32_t));
            out->cipherMod = kCipherMod_default;
            out->cipherModSize = (uint32_t)(sizeof(kCipherMod_default) / sizeof(uint64_t));
            return HIFHE_SUCCESS;

        case HIFHE_BGV_2048_48:
            out->polyDegree = 2048u;
            out->plainModBit = 17u;
            out->plainMod = 0ull; /* fall back to Proth search */
            out->cipherModBit = kCipherBits_2048_48;
            out->cipherModBitSize = (uint32_t)(sizeof(kCipherBits_2048_48) / sizeof(uint32_t));
            return HIFHE_SUCCESS;

        case HIFHE_BGV_8192_44x4:
            out->polyDegree = 8192u;
            out->plainModBit = 20u;
            out->plainMod = 0ull; /* fall back to Proth search */
            out->cipherModBit = kCipherBits_8192_44x4;
            out->cipherModBitSize = (uint32_t)(sizeof(kCipherBits_8192_44x4) / sizeof(uint32_t));
            return HIFHE_SUCCESS;

        case HIFHE_BGV_2048_48_17BIT:
            /* F4 = 65537 bypasses the Proth search. NTT-friendly for
         * polyDegree <= 32768, since 65536 = 2^16. */
            out->polyDegree = 2048u;
            out->plainModBit = 17u;
            out->plainMod = 65537ull;
            out->cipherModBit = kCipherBits_2048_48;
            out->cipherModBitSize = (uint32_t)(sizeof(kCipherBits_2048_48) / sizeof(uint32_t));
            return HIFHE_SUCCESS;

        case HIFHE_BGV_4096_44x2_17BIT:
            out->polyDegree = 4096u;
            out->plainModBit = 17u;
            out->plainMod = 65537ull;
            out->cipherModBit = kCipherBits_4096_44x2;
            out->cipherModBitSize = (uint32_t)(sizeof(kCipherBits_4096_44x2) / sizeof(uint32_t));
            return HIFHE_SUCCESS;

        case HIFHE_BGV_8192_44x4_17BIT:
            /* Same ring as HIFHE_BGV_8192_44x4, with the plaintext modulus
         * pinned to 65537 instead of Proth-searched. */
            out->polyDegree = 8192u;
            out->plainModBit = 17u;
            out->plainMod = 65537ull;
            out->cipherModBit = kCipherBits_8192_44x4;
            out->cipherModBitSize = (uint32_t)(sizeof(kCipherBits_8192_44x4) / sizeof(uint32_t));
            return HIFHE_SUCCESS;

        default:
            HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_ID_INVALID);
            return HIFHE_PARAM_ID_INVALID;
    }
}
