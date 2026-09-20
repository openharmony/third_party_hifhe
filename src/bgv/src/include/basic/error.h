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

#ifndef HIFHE_BASIC_ERROR_H
#define HIFHE_BASIC_ERROR_H

#include "hifhe_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Debug print: printf only when HIFHE_DEBUG is set. */
#include <stdio.h>
#ifdef HIFHE_DEBUG
#define HIFHE_PRINT(...) printf(__VA_ARGS__)
#else
#define HIFHE_PRINT(...) ((void)((0) ? printf(__VA_ARGS__) : 0))
#endif

/* Early-return helpers. DO NOT depend on openhitls'
 * GOTO_ERR_IF from crypt_utils.h */
#define HIFHE_RETURN_IF(cond, ret)      do { if (cond) { return (ret); } } while (0)
#define HIFHE_RETURN_IF_ERR(expr)       do { int32_t _r = (expr); if (_r != HIFHE_SUCCESS) { return _r; } } while (0)
#define HIFHE_GOTO_ERR(retVar, errCode, label) \
    do { (retVar) = (errCode); goto label; } while (0)
#define HIFHE_GOTO_ERR_IF(cond, retVar, errCode, label) \
    do { if (cond) { (retVar) = (errCode); goto label; } } while (0)

#ifdef __cplusplus
}
#endif

#endif /* HIFHE_BASIC_ERROR_H */
