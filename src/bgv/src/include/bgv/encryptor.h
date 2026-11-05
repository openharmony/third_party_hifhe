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

/* BGV encryption / decryption over (context, pk?, sk?). */

#ifndef HIFHE_BGV_ENCRYPTOR_H
#define HIFHE_BGV_ENCRYPTOR_H

#include <stdint.h>
#include <stddef.h>
#include "hifhe_err.h"
#include "bgv/bgv.h"
#include "bgv/plaintext.h"
#include "bgv/ciphertext.h"
#include "bgv/keys.h"
#include "rlwe/rlwe.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    BGVContext *context; /* not owned */
    const PublicKey *pk; /* not owned; may be NULL for sym-only */
    const SecretKey *sk; /* not owned; may be NULL for asym-only */
} Encryptor;

HIFHE_ERROR BGV_Encryptor_CreateFromSecret(Encryptor *self, const SecretKey *sk, BGVContext *ctx);
HIFHE_ERROR BGV_Encryptor_CreateFromPublic(Encryptor *self, const PublicKey *pk, const SecretKey *sk, /* may be NULL */
                                           BGVContext *ctx);
HIFHE_ERROR BGV_Encryptor_Destroy(Encryptor *self);

/* ---- Zero-encryption ---- */
HIFHE_ERROR BGV_Encryptor_EncryptZeroSymmetric(Ciphertext *out, const SecretKey *sk, const Encryptor *self);
HIFHE_ERROR BGV_Encryptor_EncryptZeroAsymmetric(Ciphertext *out, const PublicKey *pk, const Encryptor *self);

/* ---- Non-zero encryption ---- */
HIFHE_ERROR BGV_Encryptor_EncryptSymmetric(Ciphertext *out, const Plaintext *pt, const Encryptor *self);
HIFHE_ERROR BGV_Encryptor_EncryptAsymmetric(Ciphertext *out, const Plaintext *pt, const Encryptor *self);

/* ---- Decryption ---- */
HIFHE_ERROR BGV_Encryptor_Decrypt(Plaintext *out, const Ciphertext *ct, const Encryptor *self);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_BGV_ENCRYPTOR_H */
