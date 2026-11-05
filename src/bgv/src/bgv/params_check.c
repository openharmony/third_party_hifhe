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

#include "hifhe_err_internal.h"
#include "bgv/params_check.h"
#include "bgv/bgv.h"

/* Index of polyDegree in the security tables, -1 if unsupported. */
static int32_t DegreeSlot(uint32_t polyDegree)
{
    switch (polyDegree) {
        case 1024:
            return 0;
        case 2048:
            return 1;
        case 4096:
            return 2;
        case 8192:
            return 3;
        case 16384:
            return 4;
        case 32768:
            return 5;
        default:
            return -1;
    }
}

static int32_t LevelSlot(uint32_t securityLevel)
{
    switch (securityLevel) {
        case 128:
            return 0;
        case 192:
            return 1;
        case 256:
            return 2;
        default:
            return -1;
    }
}

/* [securityLevel][polyDegree] max total modulus bits, ternary secret. */
static const uint32_t kMaxBitsClassical[3][6] = {
    /* 128 */ {27, 54, 109, 218, 438, 881},
    /* 192 */ {19, 37, 75, 152, 305, 611},
    /* 256 */ {14, 29, 58, 118, 237, 476},
};

bool BGV_Params_IsPolyDegreeSupported(uint32_t polyDegree)
{
    return DegreeSlot(polyDegree) >= 0;
}

static bool BGV_Params_IsSecurityLevelSupported(uint32_t securityLevel)
{
    return LevelSlot(securityLevel) >= 0;
}

bool BGV_Params_IsPlainModBitSupported(uint32_t bits)
{
    return bits >= HIFHE_BGV_MIN_PLAIN_BITS && bits <= HIFHE_BGV_MAX_PLAIN_BITS;
}

bool BGV_Params_IsCipherModBitSupported(uint32_t bits)
{
    return bits >= HIFHE_BGV_MIN_CIPHER_BITS && bits <= HIFHE_BGV_MAX_CIPHER_BITS;
}

bool BGV_Params_IsChainLenSupported(uint32_t chainLen)
{
    return chainLen >= 1u && chainLen <= HIFHE_BGV_MAX_CHAIN_LEN;
}

uint32_t BGV_Params_HEMaxBitsTernaryClassical(uint32_t polyDegree, uint32_t securityLevel)
{
    int32_t d = DegreeSlot(polyDegree);
    int32_t l = LevelSlot(securityLevel);
    if (d < 0 || l < 0) {
        return 0u;
    }
    return kMaxBitsClassical[l][d];
}

bool BGV_Params_IsPlainModNttFriendly(uint64_t plainMod, uint32_t polyDegree)
{
    if (plainMod < 2u || polyDegree == 0u) {
        return false;
    }
    return ((plainMod - 1u) % (2u * (uint64_t)polyDegree)) == 0u;
}

HIFHE_ERROR BGV_Params_Validate(uint32_t polyDegree, uint32_t plainModBit, const uint32_t *cipherModBit,
                                uint32_t chainLen, uint32_t securityLevel)
{
    if (cipherModBit == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (securityLevel == 0u) {
        securityLevel = HIFHE_BGV_DEFAULT_SECURITY_LEVEL;
    }

    if (!BGV_Params_IsPolyDegreeSupported(polyDegree)) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    if (!BGV_Params_IsSecurityLevelSupported(securityLevel)) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    if (!BGV_Params_IsPlainModBitSupported(plainModBit)) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    if (!BGV_Params_IsChainLenSupported(chainLen)) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }

    /* A `b`-bit Proth prime is 2N*k + 1 with k < 2^(b - log2(N) - 1), so
     * b < log2(N) + 2 has no candidate. */
    uint32_t logN = 0u;
    for (uint32_t v = polyDegree; v > 1u; v >>= 1) {
        logN++;
    }
    if (plainModBit < logN + 2u) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }

    uint32_t total = 0u;
    uint32_t minCipherBits = HIFHE_BGV_MAX_CIPHER_BITS;
    for (uint32_t i = 0; i < chainLen; ++i) {
        if (!BGV_Params_IsCipherModBitSupported(cipherModBit[i])) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
            return HIFHE_PARAM_INVALID;
        }
        if (cipherModBit[i] < logN + 2u) {
            HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
            return HIFHE_PARAM_INVALID;
        }
        total += cipherModBit[i];
        if (cipherModBit[i] < minCipherBits) {
            minCipherBits = cipherModBit[i];
        }
    }
    /* Every limb must leave room above plainMod. */
    if (plainModBit >= minCipherBits) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }

    uint32_t maxBits = BGV_Params_HEMaxBitsTernaryClassical(polyDegree, securityLevel);
    if (maxBits == 0u || total > maxBits) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }

    return HIFHE_SUCCESS;
}
