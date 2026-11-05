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

/* Produces SecretKey / PublicKey / RelinKeys / GaloisKeys. */

#ifndef HIFHE_BGV_KEYGEN_H
#define HIFHE_BGV_KEYGEN_H

#include <stdint.h>
#include <stddef.h>
#include "hifhe_err.h"
#include "bgv/bgv.h"
#include "bgv/keys.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    BGVContext *context; /* not owned */
    SecretKey *sk; /* owned when non-NULL */
} KeyGenerator;

HIFHE_ERROR BGV_KeyGenerator_Create(KeyGenerator *out, BGVContext *ctx);
HIFHE_ERROR BGV_KeyGenerator_Destroy(KeyGenerator *self);

/* Draw sk from the ternary distribution using ctx's seed / DRBG. */
HIFHE_ERROR BGV_KeyGenerator_GenSecretKey(KeyGenerator *self);

/* Derive pk = (-a*s + e, a) from the current secret key. */
HIFHE_ERROR BGV_KeyGenerator_GenPublicKey(PublicKey *out, const KeyGenerator *self);

/* Relin key from sk^2. `digits` = gadget digits per limb (the base widens to
 * cover the widest limb), 0 picks BGV_KeySwitch_DefaultDigits. Holds
 * chainLen * digits pieces. */
HIFHE_ERROR BGV_KeyGenerator_GenRelinKey(RelinKeys *out, uint32_t digits, const KeyGenerator *self);

/* Digits needed to cover the widest limb of a chain in base 2^16: the
 * historic fixed gadget, and the count BGV_KeySwitch_DefaultDigits falls
 * back to. */
uint32_t BGV_BV_DigitsForBase(const RnsBase *base);

/* Derive galois keys for the supplied Galois elements. */
HIFHE_ERROR BGV_KeyGenerator_GenGaloisKeys(GaloisKeys *out, const uint64_t *elts, uint32_t count,
                                           const KeyGenerator *self);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_BGV_KEYGEN_H */
