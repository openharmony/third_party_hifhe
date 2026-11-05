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

#ifndef HIFHE_PROVIDER_IMPL_H
#define HIFHE_PROVIDER_IMPL_H

#include "crypt_eal_provider.h"

typedef struct {
    void *handle;
    void *libCtx;
} HIFHE_ProvCtx;

#ifdef HIFHE_ENABLE_BGV
extern const CRYPT_EAL_Func g_hifheKeyMgmtBgv[];
extern const CRYPT_EAL_Func g_hifheCipherBgv[];
#endif
#endif
