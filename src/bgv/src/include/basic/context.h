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

#ifndef HIFHE_BASIC_CONTEXT_H
#define HIFHE_BASIC_CONTEXT_H

#include <stdint.h>
#include <stddef.h>
#include "hifhe_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HIFHE_CTX_SEED_LEN 32u

typedef struct {
    uint8_t seed[HIFHE_CTX_SEED_LEN];
    uint8_t hasSeed;
} BgvContext;

void BgvContext_Init(BgvContext *ctx);
HIFHE_ERROR BgvContext_SetSeed(BgvContext *ctx, const uint8_t *seed, uint32_t seedLen);
void BgvContext_ClearSeed(BgvContext *ctx);

static inline const uint8_t *BgvContext_GetSeed(const BgvContext *ctx)
{
    return (ctx != NULL && ctx->hasSeed) ? ctx->seed : NULL;
}

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_BASIC_CONTEXT_H */
