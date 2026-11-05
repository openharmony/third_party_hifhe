/*
 * Copyright (c) 2026 openHiTLS. All Rights Reserved.
 * HiFHE is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef HIFHE_TYPES_H
#define HIFHE_TYPES_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque algorithm context owning its parameters and keys; release with HIFHE_Free. */
typedef struct HIFHE_Ctx HIFHE_Ctx;
/** Opaque plaintext/ciphertext owning its data; release with HIFHE_HETextFree, even after its context is freed. */
typedef struct HIFHE_HEText HIFHE_HEText;

/** Allocator installed with HIFHE_SetMemFuncs. A zero length is never requested. */
typedef void *(*HIFHE_MallocFunc)(uint32_t len);
/** Deallocator installed with HIFHE_SetMemFuncs. A NULL pointer is never passed. */
typedef void (*HIFHE_FreeFunc)(void *ptr);

/** Algorithm identifiers for HIFHE_New and CRYPT_EAL_ProviderPkeyNewCtx. */
typedef enum {
    HIFHE_BGV = (int32_t)0x89000002u,
} HIFHE_ALG_ID;

#ifdef HITLS_PROVIDER
/* Provider attribute, passed to CRYPT_EAL_ProviderPkeyNewCtx. */
#define HIFHE_PROVIDER_ATTR "provider=hifhe"

#define HIFHE_PARAM_BASE             100000

#define HIFHE_PARAM_BGV_BASE      (HIFHE_PARAM_BASE + 100)
/**
 * HE message encoding input: BSL_PARAM_TYPE_OCTETS with count host-order uint64_t slots.
 * valueLen = count * sizeof(uint64_t); 1 <= count <= N; each value is below the plaintext modulus.
 */
#define HIFHE_PARAM_BGV_MSG       (HIFHE_PARAM_BGV_BASE + 8)
/** HEAdd only: BSL_PARAM_TYPE_OCTETS containing one uint8_t equal to 1; negate the first ciphertext. */
#define HIFHE_PARAM_BGV_NEGATE    (HIFHE_PARAM_BGV_BASE + 9)
/** BSL_PARAM_TYPE_OCTETS containing a serialized plaintext for message decoding or HEAdd/HEMul. */
#define HIFHE_PARAM_BGV_PLAINTEXT (HIFHE_PARAM_BGV_BASE + 11)
#endif

/**
 * Wire formats for HIFHE_CTRL_BGV_SET_WIRE_FORMAT. HIFHE_Deserialize reads
 * both whichever is selected; the setting only decides what is written.
 */
#define HIFHE_WIRE_HIFHE       0u /* HiFHE's own: carries the preset, the depth and the key origin. */
#define HIFHE_WIRE_INTERCHANGE 1u /* The 12-byte-header format the Provider reads. */

#define HIFHE_PRESET_BGV_BASE 100000

/** BGV preset identifiers for HIFHE_SetParaById; these are not algorithm identifiers. */
typedef enum {
    HIFHE_BGV_DEFAULT = HIFHE_PRESET_BGV_BASE + 0, /* Same parameters as HIFHE_BGV_2048_48. */
    HIFHE_BGV_2048_48 = HIFHE_PRESET_BGV_BASE + 1,
    HIFHE_BGV_8192_44x4 = HIFHE_PRESET_BGV_BASE + 2,
    /* 2048, 48-bit cipher, plainMod 65537. */
    HIFHE_BGV_2048_48_17BIT = HIFHE_PRESET_BGV_BASE + 3,
    /* 4096, 2 x 44-bit, plainMod 65537. */
    HIFHE_BGV_4096_44x2_17BIT = HIFHE_PRESET_BGV_BASE + 4,
    /* 8192, 4 x 44-bit, plainMod 65537. */
    HIFHE_BGV_8192_44x4_17BIT = HIFHE_PRESET_BGV_BASE + 5,
} HIFHE_BGV_PRESET;

/**
 * Native HIFHE_Ctrl commands. Argument sizes below are in bytes.
 * Length queries describe objects at the configured preset level; use
 * HIFHE_Serialize(ctx, object, NULL, &len) for an existing object's exact size.
 * Provider PkeyCtrl forwards the LUT, seed, degree, and length commands with
 * args = value and len = valueLen. RERANDOMIZE has a separate Provider layout below.
 * Provider negation uses HIFHE_PARAM_BGV_NEGATE in HEAdd, not a SET_NEGATE ctrl call.
 */
typedef enum {
    /**
     * Add noise to a ciphertext, creating a new object; no key is required.
     * text: input ciphertext without a negate flag; value: HIFHE_HEText ** with *value == NULL;
     * valueLen: sizeof(HIFHE_HEText *). Free the result with HIFHE_HETextFree.
     * This does not bootstrap the ciphertext or reset its noise budget.
     * It does not hide the relation to the input or provide circuit privacy.
     * Provider: args is a BSL_Param array containing CRYPT_PARAM_PKEY_HE_CIPHERTEXT1
     * (input bytes) and CRYPT_PARAM_PKEY_HE_CIPHERTEXT2 (output buffer), both OCTETS,
     * followed by BSL_PARAM_END; pass len = 0. Output useLen receives the actual/required size.
     */
    HIFHE_CTRL_BGV_RERANDOMIZE = 100001,
    /**
     * Mark text, a ciphertext, for negation when passed as para1 to HIFHE_Add.
     * value: NULL; valueLen: 0. This sets a flag, not a toggle or immediate arithmetic operation.
     * The input stays marked; the Add result is unmarked.
     * Decrypt, Mul, Serialize, and RERANDOMIZE reject marked inputs.
     */
    HIFHE_CTRL_BGV_SET_NEGATE = 100002,
    /**
     * Set the context's precomputed-table cache before HIFHE_SetParaById.
     * text: NULL; value: uint32_t * containing 0 (disabled, default) or 1 (enabled);
     * valueLen: sizeof(uint32_t). Returns HIFHE_BAD_STATE after parameters are configured.
     */
    HIFHE_CTRL_BGV_SET_LUT_CACHE = 100003,
    /**
     * Serialized size of a fresh two-component ciphertext.
     * text = NULL; value = uint32_t * output; valueLen = sizeof(uint32_t).
     */
    HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN = 100004,
    /** Serialized plaintext size: text = NULL, value = uint32_t * output, valueLen = sizeof(uint32_t). */
    HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN = 100005,
    /** Ring degree, also the BGV slot count: text = NULL, value = uint32_t * output, valueLen = sizeof(uint32_t). */
    HIFHE_CTRL_BGV_GET_POLY_DEGREE = 100006,
    /**
     * Set the BGV seed after parameter configuration and before key generation.
     * text: NULL; value: 32 seed bytes, copied by the call; valueLen: 32.
     * Returns HIFHE_BAD_STATE if keys have already been generated.
     * A seed also makes the key origin reproducible: keys generated from one
     * seed carry one origin, so a ciphertext serialized by one context
     * deserializes into another that holds the same seed.
     */
    HIFHE_CTRL_BGV_SET_SEED = 100007,
    /**
     * Select the format HIFHE_Serialize writes.
     * text: NULL; value: uint32_t * containing HIFHE_WIRE_HIFHE (the default)
     * or HIFHE_WIRE_INTERCHANGE; valueLen: sizeof(uint32_t).
     * Accepted before or after HIFHE_SetParaById, since the setting belongs to
     * the context rather than to its parameters. Applies from the next call;
     * existing objects are unaffected.
     */
    HIFHE_CTRL_BGV_SET_WIRE_FORMAT = 100008,
} HIFHE_CMD;

#ifdef __cplusplus
}
#endif
#endif
