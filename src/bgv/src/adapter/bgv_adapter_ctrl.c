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
#include "hifhe_err_internal.h"
#include "crypt_types.h"

#include "bgv_local.h"
#include "bgv/evaluator.h"

#ifdef HITLS_PROVIDER
int32_t BgvCtrl_Dispatch(CRYPT_BGV_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL) {
        HIFHE_ERR_PUSH_ERROR(HIFHE_NULL_INPUT);
        return HIFHE_NULL_INPUT;
    }

    switch (cmd) {
        case CRYPT_CTRL_SET_PARA_BY_ID: {
            if (val == NULL || valLen != sizeof(int32_t)) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                return HIFHE_PARAM_INVALID;
            }
            int32_t presetId = *(const int32_t *)val;
            int32_t r = BgvUserPara_LoadPreset(&ctx->para, presetId);
            if (r == HIFHE_SUCCESS) {
                /* Same reason as CRYPT_BGV_SetParaEx: drop the old ring's state. */
                Bgv_FreeState(&ctx->bgv);
                ctx->role = HIFHE_ROLE_PARA;
            }
            return r;
        }

        case HIFHE_CTRL_BGV_GET_POLY_DEGREE: {
            if (val == NULL || valLen != sizeof(uint32_t)) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                return HIFHE_PARAM_INVALID;
            }
            if (!ctx->para.set) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_NOT_SET);
                return HIFHE_PARAM_NOT_SET;
            }
            *(uint32_t *)val = ctx->para.polyDegree;
            return HIFHE_SUCCESS;
        }

        case HIFHE_CTRL_BGV_GET_PLAIN_MOD: {
            if (val == NULL || valLen != sizeof(uint64_t)) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                return HIFHE_PARAM_INVALID;
            }
            if (!ctx->para.set) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_NOT_SET);
                return HIFHE_PARAM_NOT_SET;
            }
            if (ctx->para.plainMod != 0ull) {
                *(uint64_t *)val = ctx->para.plainMod;
                return HIFHE_SUCCESS;
            }
            int32_t r = Bgv_BuildContext(ctx);
            if (r != HIFHE_SUCCESS) {
                return r;
            }
            *(uint64_t *)val = ctx->bgv.context.bgvParameter->plainMod;
            return HIFHE_SUCCESS;
        }

        case HIFHE_CTRL_BGV_GET_INNER_CTX: {
            if (val == NULL || valLen != sizeof(CRYPT_BGV_Ctx *)) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                return HIFHE_PARAM_INVALID;
            }
            *(CRYPT_BGV_Ctx **)val = ctx;
            return HIFHE_SUCCESS;
        }

        case HIFHE_CTRL_BGV_GET_PUBKEY_LEN: {
            if (val == NULL || valLen != sizeof(uint32_t)) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                return HIFHE_PARAM_INVALID;
            }
            return Bgv_GetPubKeyLen(ctx, (uint32_t *)val);
        }
        case HIFHE_CTRL_BGV_GET_PRVKEY_LEN: {
            if (val == NULL || valLen != sizeof(uint32_t)) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                return HIFHE_PARAM_INVALID;
            }
            return Bgv_GetPrvKeyLen(ctx, (uint32_t *)val);
        }
        case HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN: {
            if (val == NULL || valLen != sizeof(uint32_t)) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                return HIFHE_PARAM_INVALID;
            }
            return Bgv_GetCiphertextLen(ctx, (uint32_t *)val);
        }
        case HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN: {
            if (val == NULL || valLen != sizeof(uint32_t)) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                return HIFHE_PARAM_INVALID;
            }
            return Bgv_GetPlaintextLen(ctx, (uint32_t *)val);
        }
        case HIFHE_CTRL_BGV_GET_MSG_LEN: {
            if (val == NULL || valLen != sizeof(uint32_t)) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                return HIFHE_PARAM_INVALID;
            }
            return Bgv_GetMsgLen(ctx, (uint32_t *)val);
        }

        case HIFHE_CTRL_BGV_GET_LEVEL: {
            if (val == NULL || valLen != sizeof(uint32_t)) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                return HIFHE_PARAM_INVALID;
            }
            int32_t r = Bgv_BuildContext(ctx);
            if (r != HIFHE_SUCCESS) {
                return r;
            }
            *(uint32_t *)val = ctx->bgv.context.rlweContext.cipherRnsBase.size;
            return HIFHE_SUCCESS;
        }

        case HIFHE_CTRL_BGV_GET_RELIN_KEY_LEN:
        case HIFHE_CTRL_BGV_GET_GALOIS_KEYS_LEN:
            /* Depends on how many pieces / how many elements are present.
         * Return 0 with success for a not-yet-generated key
         * so the caller can distinguish "empty" from "error". */
            if (val == NULL || valLen != sizeof(uint32_t)) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                return HIFHE_PARAM_INVALID;
            }
            *(uint32_t *)val = 0u;
            return HIFHE_SUCCESS;

        case HIFHE_CTRL_BGV_SET_SEED: {
            if (val == NULL || valLen != HIFHE_CTX_SEED_LEN) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                return HIFHE_PARAM_INVALID;
            }
            int32_t r = Bgv_BuildContext(ctx);
            if (r != HIFHE_SUCCESS) {
                return r;
            }
            return BgvContext_SetSeed(&ctx->bgv.context.rlweContext.seedCtx, (const uint8_t *)val, valLen);
        }

        case HIFHE_CTRL_BGV_SET_SLOT_MAP: {
            if (val == NULL || valLen != sizeof(uint32_t)) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                return HIFHE_PARAM_INVALID;
            }
            int32_t r = Bgv_BuildContext(ctx);
            if (r != HIFHE_SUCCESS) {
                return r;
            }
            uint32_t on = *(const uint32_t *)val;
            if (on > 1u) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                return HIFHE_PARAM_INVALID;
            }
            if (on != 0u) {
                /* Lazy build. */
                r = BGV_BGVContext_EnsureSlotMap(&ctx->bgv.context);
                if (r != HIFHE_SUCCESS) {
                    return r;
                }
            }
            BGV_BGVContext_SetUseSlotMap(&ctx->bgv.context, (uint8_t)on);
            return HIFHE_SUCCESS;
        }
        case HIFHE_CTRL_BGV_GET_SLOT_MAP: {
            if (val == NULL || valLen != sizeof(uint32_t)) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                return HIFHE_PARAM_INVALID;
            }
            int32_t r = Bgv_BuildContext(ctx);
            if (r != HIFHE_SUCCESS) {
                return r;
            }
            *(uint32_t *)val = BGV_BGVContext_GetUseSlotMap(&ctx->bgv.context);
            return HIFHE_SUCCESS;
        }

        case HIFHE_CTRL_BGV_GEN_RELIN_KEY:
            return Bgv_GenRelinKey(ctx);

        case HIFHE_CTRL_BGV_GEN_GALOIS_KEYS: {
            /* `val` is a BSL_Param array carrying either HIFHE_ROTATE_STEPS
         * (int32_t[]) or HIFHE_GALOIS_ELTS (uint64_t[]). */
            if (val == NULL) {
                HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                return HIFHE_PARAM_INVALID;
            }
            BSL_Param *arr = (BSL_Param *)val;
            BSL_Param *pElts = NULL, *pSteps = NULL;
            for (BSL_Param *p = arr; p->key != 0; ++p) {
                if (p->key == HIFHE_PARAM_BGV_GALOIS_ELTS) {
                    pElts = p;
                }
                if (p->key == HIFHE_PARAM_BGV_ROTATE_STEPS) {
                    pSteps = p;
                }
            }
            int32_t r = Bgv_BuildContext(ctx);
            if (r != HIFHE_SUCCESS) {
                return r;
            }
            uint32_t N = ctx->bgv.context.rlweContext.parameter->polyDegree;
            /* There are only N distinct odd Galois elements mod 2N, so a longer
         * list is malformed. Refuse it before anything is sized from it: the
         * step list is widened to 64-bit elements, and every entry costs a
         * full set of key-switching keys. */
            if (pElts != NULL && pElts->value != NULL) {
                uint32_t count = pElts->valueLen / (uint32_t)sizeof(uint64_t);
                if (count == 0u || count > N) {
                    HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                    return HIFHE_PARAM_INVALID;
                }
                return Bgv_GenGaloisKeys(ctx, (const uint64_t *)pElts->value, count);
            }
            if (pSteps != NULL && pSteps->value != NULL) {
                uint32_t count = pSteps->valueLen / (uint32_t)sizeof(int32_t);
                if (count == 0u || count > N) {
                    HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
                    return HIFHE_PARAM_INVALID;
                }
                Uint64Vector eltVec;
                r = Uint64Vector_Create(&eltVec, NULL, count);
                if (r != HIFHE_SUCCESS) {
                    return r;
                }
                const int32_t *steps = (const int32_t *)pSteps->value;
                for (uint32_t i = 0; i < count; ++i) {
                    eltVec.data[i] = BGV_GaloisEltForStep(steps[i], N);
                }
                r = Bgv_GenGaloisKeys(ctx, eltVec.data, count);
                Uint64Vector_Destroy(&eltVec);
                return r;
            }
            HIFHE_ERR_PUSH_ERROR(HIFHE_PARAM_INVALID);
            return HIFHE_PARAM_INVALID;
        }

        case HIFHE_CTRL_BGV_RERANDOMIZE:
            return Bgv_HERerand(ctx, (BSL_Param *)val);
        case HIFHE_CTRL_BGV_HE_MODSWITCH:
            return Bgv_HEModSwitch(ctx, (BSL_Param *)val);
        case HIFHE_CTRL_BGV_HE_RELINEARIZE:
            return Bgv_HERelinearize(ctx, (BSL_Param *)val);

        case HIFHE_CTRL_BGV_HE_ROTATE_STEP:
            return Bgv_HERotateStep(ctx, (BSL_Param *)val);
        case HIFHE_CTRL_BGV_HE_ROTATE_ELT:
            return Bgv_HERotateElt(ctx, (BSL_Param *)val);

        default:
            HIFHE_ERR_PUSH_ERROR(HIFHE_NOT_SUPPORTED);
            return HIFHE_NOT_SUPPORTED;
    }
}
#endif
