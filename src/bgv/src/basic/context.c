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

#include <string.h>
#include "hifhe_mem.h"
#include "hifhe_err_internal.h"
#include "basic/context.h"

void BgvContext_Init(BgvContext *ctx)
{
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
}

HIFHE_ERROR BgvContext_SetSeed(BgvContext *ctx, const uint8_t *seed, uint32_t seedLen)
{
    if (ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }
    if (seed == NULL) {
        BgvContext_ClearSeed(ctx);
        return HIFHE_SUCCESS;
    }
    if (seedLen != HIFHE_CTX_SEED_LEN) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
        return HIFHE_PARAM_INVALID;
    }
    memcpy(ctx->seed, seed, HIFHE_CTX_SEED_LEN);
    ctx->hasSeed = 1u;
    return HIFHE_SUCCESS;
}

void BgvContext_ClearSeed(BgvContext *ctx)
{
    if (ctx == NULL) {
        return;
    }
    HifheCleanse(ctx->seed, HIFHE_CTX_SEED_LEN);
    ctx->hasSeed = 0u;
}
