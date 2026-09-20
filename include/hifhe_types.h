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

#define HIFHE_PARAM_BASE 5400
#define HIFHE_PARAM_CKKS_N (HIFHE_PARAM_BASE + 1)
#define HIFHE_PARAM_CKKS_Q_BITS (HIFHE_PARAM_BASE + 2)
#define HIFHE_PARAM_CKKS_P_BITS (HIFHE_PARAM_BASE + 3)
#define HIFHE_PARAM_CKKS_SIGMA_MILLI (HIFHE_PARAM_BASE + 4)
#define HIFHE_PARAM_CKKS_SLOTS (HIFHE_PARAM_BASE + 5)
#define HIFHE_PARAM_CKKS_PUBKEY (HIFHE_PARAM_BASE + 6)
#define HIFHE_PARAM_CKKS_PRVKEY (HIFHE_PARAM_BASE + 7)

/* ----- BGV ----- */
#define HIFHE_PARAM_BGV_BASE (HIFHE_PARAM_BASE + 100)
#define HIFHE_PARAM_BGV_POLY_DEGREE (HIFHE_PARAM_BGV_BASE + 1)
#define HIFHE_PARAM_BGV_CIPHER_MOD_BITS (HIFHE_PARAM_BGV_BASE + 2)
#define HIFHE_PARAM_BGV_PLAIN_MOD_BIT (HIFHE_PARAM_BGV_BASE + 3)
#define HIFHE_PARAM_BGV_CORRECTION_FACTOR (HIFHE_PARAM_BGV_BASE + 4)
#define HIFHE_PARAM_BGV_RELIN_DNUM (HIFHE_PARAM_BGV_BASE + 5)
#define HIFHE_PARAM_BGV_PUBKEY (HIFHE_PARAM_BGV_BASE + 6)
#define HIFHE_PARAM_BGV_PRVKEY (HIFHE_PARAM_BGV_BASE + 7)
#define HIFHE_PARAM_BGV_MSG (HIFHE_PARAM_BGV_BASE + 8)
#define HIFHE_PARAM_BGV_NEGATE (HIFHE_PARAM_BGV_BASE + 9)
#define HIFHE_PARAM_BGV_CONSTANT (HIFHE_PARAM_BGV_BASE + 10)
#define HIFHE_PARAM_BGV_PLAINTEXT (HIFHE_PARAM_BGV_BASE + 11)
#define HIFHE_PARAM_BGV_CIPHERTEXT1 (HIFHE_PARAM_BGV_BASE + 12)
#define HIFHE_PARAM_BGV_CIPHERTEXT2 (HIFHE_PARAM_BGV_BASE + 13)
#define HIFHE_PARAM_BGV_RELIN_KEY (HIFHE_PARAM_BGV_BASE + 14)
#define HIFHE_PARAM_BGV_GALOIS_KEYS (HIFHE_PARAM_BGV_BASE + 15)
#define HIFHE_PARAM_BGV_ROTATE_STEPS (HIFHE_PARAM_BGV_BASE + 16)
#define HIFHE_PARAM_BGV_GALOIS_ELTS (HIFHE_PARAM_BGV_BASE + 17)

/* Deterministic seed length, HIFHE_CTRL_BGV_SET_SEED. */
#define HIFHE_BGV_SEED_LEN 32u

#define HIFHE_CTRL_BGV_BASE (int32_t)0x6900

typedef enum {
    HIFHE_CTRL_BGV_GET_PUBKEY_LEN = HIFHE_CTRL_BGV_BASE + 0,
    HIFHE_CTRL_BGV_GET_PRVKEY_LEN = HIFHE_CTRL_BGV_BASE + 1,
    HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN = HIFHE_CTRL_BGV_BASE + 2,
    HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN = HIFHE_CTRL_BGV_BASE + 3,
    HIFHE_CTRL_BGV_GET_MSG_LEN = HIFHE_CTRL_BGV_BASE + 4,
    HIFHE_CTRL_BGV_GET_POLY_DEGREE = HIFHE_CTRL_BGV_BASE + 5,
    HIFHE_CTRL_BGV_GET_PLAIN_MOD = HIFHE_CTRL_BGV_BASE + 6,
    /* val is CRYPT_BGV_Ctx **. Escape hatch past the EAL dispatch. */
    HIFHE_CTRL_BGV_GET_INNER_CTX = HIFHE_CTRL_BGV_BASE + 7,
    /* Install a seed by:
     * uint8_t seed[HIFHE_BGV_SEED_LEN];
     * CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_SET_SEED, seed, sizeof(seed));
     * Same seed and preset give byte-identical sk, pk, relin and galois keys.
     * Call after the preset and before Gen. */
    HIFHE_CTRL_BGV_SET_SEED = HIFHE_CTRL_BGV_BASE + 8,
    /* Add fresh plainMod-preserving noise by:
     * BSL_Param p[] = {
     *     {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct, ctLen, 0},
     *     {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, out, cap, 0},
     *     BSL_PARAM_END
     * };
     * CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_HE_RERANDOMIZE, p, 0);
     * p[1].useLen holds the bytes written. */
    HIFHE_CTRL_BGV_HE_RERANDOMIZE = HIFHE_CTRL_BGV_BASE + 9,
    HIFHE_CTRL_BGV_GET_RELIN_KEY_LEN = HIFHE_CTRL_BGV_BASE + 10,
    HIFHE_CTRL_BGV_GET_GALOIS_KEYS_LEN = HIFHE_CTRL_BGV_BASE + 11,
    /* Ciphertext modulus chain length. */
    HIFHE_CTRL_BGV_GET_LEVEL = HIFHE_CTRL_BGV_BASE + 12,
    /* val NULL, valLen 0. */
    HIFHE_CTRL_BGV_GEN_RELIN_KEY = HIFHE_CTRL_BGV_BASE + 13,
    /* Derive galois keys by:
     * int32_t steps[] = {1, -1};
     * BSL_Param p[] = {
     *     {HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_OCTETS, steps,
     *      (uint32_t)sizeof(steps), 0},
     *     BSL_PARAM_END
     * };
     * CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GEN_GALOIS_KEYS, p, 0);
     * HIFHE_PARAM_BGV_GALOIS_ELTS (uint64_t[]) names the elements directly. */
    HIFHE_CTRL_BGV_GEN_GALOIS_KEYS = HIFHE_CTRL_BGV_BASE + 14,
    /* Drop the last modulus of the chain. Same BSL_Param shape as
     * HIFHE_CTRL_BGV_HE_RERANDOMIZE. */
    HIFHE_CTRL_BGV_HE_MODSWITCH = HIFHE_CTRL_BGV_BASE + 15,
    /* Size 3 to size 2 with the relin key. Same shape as HE_RERANDOMIZE. */
    HIFHE_CTRL_BGV_HE_RELINEARIZE = HIFHE_CTRL_BGV_BASE + 16,
    /* Rotate by:
     * int32_t step = 1;
     * BSL_Param p[] = {
     *     {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct, ctLen, 0},
     *     {HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_INT32, &step,
     *      (uint32_t)sizeof(step), 0},
     *     {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, out, cap, 0},
     *     BSL_PARAM_END
     * };
     * CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_HE_ROTATE_STEP, p, 0); */
    HIFHE_CTRL_BGV_HE_ROTATE_STEP = HIFHE_CTRL_BGV_BASE + 17,
    /* As HE_ROTATE_STEP with HIFHE_PARAM_BGV_GALOIS_ELTS (uint64_t[1]) in
     * place of the step. Reaches elements that are not a power of 3. */
    HIFHE_CTRL_BGV_HE_ROTATE_ELT = HIFHE_CTRL_BGV_BASE + 18,
    /* val is uint32_t *. 1 applies the slot index map in encode and decode. */
    HIFHE_CTRL_BGV_SET_SLOT_MAP = HIFHE_CTRL_BGV_BASE + 21,
    HIFHE_CTRL_BGV_GET_SLOT_MAP = HIFHE_CTRL_BGV_BASE + 22,
} HIFHE_CTRL_BGV_TYPE;

#define HIFHE_PRESET_BGV_BASE (int32_t)0x6500

/* Pass to CRYPT_EAL_PkeyCtrl with CRYPT_CTRL_SET_PARA_BY_ID. */
typedef enum {
    HIFHE_BGV_DEFAULT = HIFHE_PRESET_BGV_BASE + 0, /* = HIFHE_BGV_2048_48 */
    HIFHE_BGV_2048_48 = HIFHE_PRESET_BGV_BASE + 1,
    HIFHE_BGV_8192_44x4 = HIFHE_PRESET_BGV_BASE + 2,
    /* 2048, 48-bit cipher, plainMod 65537. */
    HIFHE_BGV_2048_48_17BIT = HIFHE_PRESET_BGV_BASE + 3,
    /* 4096, 2 x 44-bit, plainMod 65537. */
    HIFHE_BGV_4096_44x2_17BIT = HIFHE_PRESET_BGV_BASE + 4,
    /* 8192, 4 x 44-bit, plainMod 65537. */
    HIFHE_BGV_8192_44x4_17BIT = HIFHE_PRESET_BGV_BASE + 5,
} HIFHE_BGV_PRESET;

#ifdef __cplusplus
}
#endif

#endif
