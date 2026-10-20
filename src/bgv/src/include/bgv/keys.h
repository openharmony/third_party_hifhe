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
 * SecretKey  = Plaintext    (one CrtPoly)
 * PublicKey  = Ciphertext   (2 components)
 * RelinKeys  = Ciphertext[rnsSize * digits]
 * GaloisKeys = galoisElt -> Ciphertext[rnsSize * digits]
 */

#ifndef HIFHE_BGV_KEYS_H
#define HIFHE_BGV_KEYS_H

#include <stdint.h>
#include <stddef.h>
#include "hifhe_err.h"
#include "bgv/plaintext.h"
#include "bgv/ciphertext.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Plaintext   SecretKey;
typedef struct PlaintextConfig SecretKeyConfig;
typedef struct Ciphertext  PublicKey;

/* Aliases onto the underlying Plaintext / Ciphertext helpers. */
#define BGV_SecretKey_Create       BGV_Plaintext_Create
#define BGV_SecretKey_Copy         BGV_Plaintext_Copy
#define BGV_SecretKey_Destroy      BGV_Plaintext_Destroy
#define BGV_PublicKey_Create       BGV_Ciphertext_Create
#define BGV_PublicKey_Copy         BGV_Ciphertext_Copy
#define BGV_PublicKey_Destroy      BGV_Ciphertext_Destroy

/* Empty secret key handle. Polynomial storage is filled in by keygen, a
 * wire load, or a copy. */
SecretKey *BGV_SecretKey_New (void);
/* Destroy contents, release the handle, and NULL the caller's pointer. */
void       BGV_SecretKey_Free(SecretKey **self);

/* ---- secret-key powers ----
 * Decrypting a size-K ciphertext evaluates c_0 + c_1*s + ... + c_{K-1}*s^(K-1):
 * size 3 needs s^2, size 4 needs s^3. The key is NTT-form, so this is one
 * modular power per slot. `out` is created here on the key's own RNS base
 * and destroyed by the caller. power >= 1; power 1 returns a copy. */
HIFHE_ERROR BGV_SecretKey_GetPow(CrtPoly *out, const SecretKey *sk, uint32_t power);

/* ---- Switch-key gadget shape ----
 * rnsSize * digits pieces, laid out pieces[i * digits + j]. Limb i carries
 * qhat_i = prod_{m != i} q_m, digit j carries T^j = 2^(16j). A single-limb
 * chain gives qhat_0 = 1, i.e. plain BV. */
typedef struct {
    uint32_t     dnum;             /* total pieces == rnsSize * digits */
    uint32_t     rnsSize;          /* chain length the gadget was built for */
    uint32_t     digits;           /* base-2^16 digits per limb */
    Ciphertext  *pieces;           /* dnum-entry array */
    BGVContext  *context;
} RelinKeys;

HIFHE_ERROR BGV_RelinKeys_Create (RelinKeys *out, uint32_t rnsSize, uint32_t digits,
                                 BGVContext *ctx);
HIFHE_ERROR BGV_RelinKeys_Copy   (RelinKeys *dst, const RelinKeys *src);
HIFHE_ERROR BGV_RelinKeys_Destroy(RelinKeys *self);

/* ---- Galois keys ---- */
typedef struct {
    uint64_t     galoisElt;
    Ciphertext  *pieces;
    uint32_t     dnum;             /* total pieces == rnsSize * digits */
    uint32_t     rnsSize;
    uint32_t     digits;
} GaloisKeyPiece;

typedef struct {
    uint32_t         count;
    GaloisKeyPiece  *entries;
    BGVContext      *context;
} GaloisKeys;

HIFHE_ERROR BGV_GaloisKeys_Create   (GaloisKeys *out, BGVContext *ctx);
/* Allocate the entry table; count is known only after steps resolve to
 * Galois elements. */
HIFHE_ERROR BGV_GaloisKeys_CreateEntries(GaloisKeys *self, uint32_t count);
/* Allocate one entry's gadget array. */
HIFHE_ERROR BGV_GaloisKeyPiece_Create(GaloisKeyPiece *out, uint64_t galoisElt,
                                    uint32_t rnsSize, uint32_t digits);
HIFHE_ERROR BGV_GaloisKeys_Copy     (GaloisKeys *dst, const GaloisKeys *src);
HIFHE_ERROR BGV_GaloisKeys_Destroy  (GaloisKeys *self);
/* Lookup by Galois element. Points into `self->entries`, do not free.
 * NULL if absent. */
const GaloisKeyPiece *BGV_GaloisKeys_GetByElt(const GaloisKeys *self, uint64_t elt);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_BGV_KEYS_H */
