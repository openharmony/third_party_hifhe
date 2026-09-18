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

/* Message slots <-> plaintext polynomial. */

#ifndef HIFHE_BGV_ENCODER_H
#define HIFHE_BGV_ENCODER_H

#include <stdint.h>
#include "hifhe_err.h"
#include "bgv/bgv.h"
#include "bgv/plaintext.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    BGVContext *context;   /* not owned */
} Encoder;

HIFHE_ERROR BGV_Encoder_Create (Encoder *out, BGVContext *ctx);
HIFHE_ERROR BGV_Encoder_Destroy(Encoder *self);

/* msg[0..slotCount), each < plainMod. slotCount == polyDegree. */
HIFHE_ERROR BGV_Encoder_Encode(Plaintext *out, const uint64_t *msg, uint32_t slotCount,
                             const Encoder *self);

HIFHE_ERROR BGV_Encoder_Decode(uint64_t *msg, uint32_t slotCount,
                             const Plaintext *pt, const Encoder *self);

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_BGV_ENCODER_H */
