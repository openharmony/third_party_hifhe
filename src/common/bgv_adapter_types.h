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

#ifndef HIFHE_BGV_ADAPTER_TYPES_H
#define HIFHE_BGV_ADAPTER_TYPES_H

#include <stdint.h>
#include "hifhe_types.h"

#ifdef __cplusplus
extern "C" {
#endif


/* ----- BGV ----- */
#define HIFHE_PARAM_BGV_PUBKEY    (HIFHE_PARAM_BGV_BASE + 6)
#define HIFHE_PARAM_BGV_PRVKEY    (HIFHE_PARAM_BGV_BASE + 7)
#define HIFHE_PARAM_BGV_POLY_DEGREE       (HIFHE_PARAM_BGV_BASE + 1)
#define HIFHE_PARAM_BGV_CIPHER_MOD_BITS   (HIFHE_PARAM_BGV_BASE + 2)
#define HIFHE_PARAM_BGV_PLAIN_MOD_BIT     (HIFHE_PARAM_BGV_BASE + 3)
#define HIFHE_PARAM_BGV_CORRECTION_FACTOR (HIFHE_PARAM_BGV_BASE + 4)
#define HIFHE_PARAM_BGV_RELIN_DNUM        (HIFHE_PARAM_BGV_BASE + 5)
#define HIFHE_PARAM_BGV_CONSTANT          (HIFHE_PARAM_BGV_BASE + 10)
#define HIFHE_PARAM_BGV_CIPHERTEXT1       (HIFHE_PARAM_BGV_BASE + 12)
#define HIFHE_PARAM_BGV_CIPHERTEXT2       (HIFHE_PARAM_BGV_BASE + 13)
#define HIFHE_PARAM_BGV_RELIN_KEY         (HIFHE_PARAM_BGV_BASE + 14)
#define HIFHE_PARAM_BGV_GALOIS_KEYS       (HIFHE_PARAM_BGV_BASE + 15)
#define HIFHE_PARAM_BGV_ROTATE_STEPS      (HIFHE_PARAM_BGV_BASE + 16)
#define HIFHE_PARAM_BGV_GALOIS_ELTS       (HIFHE_PARAM_BGV_BASE + 17)

/* Deterministic seed length, HIFHE_CTRL_BGV_SET_SEED. */
#define HIFHE_BGV_SEED_LEN 32u

#define HIFHE_CTRL_BGV_BASE (int32_t)0x6900

typedef enum {
    HIFHE_CTRL_BGV_GET_PUBKEY_LEN = HIFHE_CTRL_BGV_BASE + 0,
    HIFHE_CTRL_BGV_GET_PRVKEY_LEN = HIFHE_CTRL_BGV_BASE + 1,
    HIFHE_CTRL_BGV_GET_MSG_LEN = HIFHE_CTRL_BGV_BASE + 4,
    HIFHE_CTRL_BGV_GET_PLAIN_MOD = HIFHE_CTRL_BGV_BASE + 6,
    /* val is CRYPT_BGV_Ctx **. Escape hatch past the EAL dispatch. */
    HIFHE_CTRL_BGV_GET_INNER_CTX = HIFHE_CTRL_BGV_BASE + 7,
    /* Add fresh plainMod-preserving noise by:
     * BSL_Param p[] = {
     *     {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ct, ctLen, 0},
     *     {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, out, cap, 0},
     *     BSL_PARAM_END
     * };
     * CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_RERANDOMIZE, p, 0);
     * p[1].useLen holds the bytes written.
     * This refreshes the noise, not the ciphertext: it needs no key, and it
     * leaves out - in a small multiple of plainMod, so anyone holding both
     * ciphertexts can pair them. Unlinkability needs a fresh encryption. */

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
     * HIFHE_CTRL_BGV_RERANDOMIZE. */
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



#ifdef __cplusplus
}
#endif

#endif
