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

/* Parameter cache consumed by Bgv_BuildContext. */

#include <stdbool.h>
#include <string.h>
#include "bsl_sal.h"
#include "kernel/ntt.h"

#include "bgv_local.h"
#include "bgv/params_preset.h"

void BgvUserPara_Init(BgvUserPara *p)
{
    if (p == NULL) return;
    memset(p, 0, sizeof(*p));
    p->correctionFactor = HIFHE_BGV_DEFAULT_CORRECTION_FACTOR;
    p->relinDnum        = HIFHE_BGV_DEFAULT_RELIN_DNUM;
}

void BgvUserPara_Clear(BgvUserPara *p)
{
    if (p == NULL) return;
    Uint32Vector_Destroy(&p->cipherModBit);
    Uint64Vector_Destroy(&p->cipherMod);
    /* Frees the tables. Every context must be destroyed.
     * Run Bgv_FreeState(*ctx) first. */
    if (p->lutBlob != NULL) {
        BSL_SAL_Free(p->lutBlob);
    }
    memset(p, 0, sizeof(*p));
}

/* True when the tables held match what `param` needs. */
static bool LutMatches(const BgvUserPara *p, const BGVParameter *param)
{
    const ModulusVector *cipherMod = &param->rlweParameter.cipherMod;
    if (p->lutBlob == NULL) return false;
    if (p->lutPolyDegree != param->rlweParameter.polyDegree ||
        p->lutLimbs != cipherMod->size ||
        p->lutPlainMod != param->plainMod) {
        return false;
    }
    for (uint32_t i = 0; i < p->lutLimbs; ++i) {
        if (p->lutCipherMod[i] != cipherMod->data[i]) return false;
    }
    return true;
}

HIFHE_ERROR BgvUserPara_EnsureLut(BgvUserPara *p, const BGVParameter *param)
{
    if (p == NULL || param == NULL) return HIFHE_NULL_INPUT;
    if (LutMatches(p, param)) return HIFHE_SUCCESS;

    const ModulusVector *cipherMod = &param->rlweParameter.cipherMod;
    uint32_t L = cipherMod->size;
    uint32_t N = param->rlweParameter.polyDegree;
    if (L == 0u || L > HIFHE_BGV_MAX_CHAIN_LEN || N == 0u || param->plainMod == 0u) {
        return HIFHE_PARAM_INVALID;
    }

    /* Every context built on this cache borrows pointers into the blob, so
     * freeing it here would leave them dangling. Report the mismatch instead;
     * Bgv_BuildContext then gives this context its own tables. */
    if (p->lutBlob != NULL) return HIFHE_PARAM_INVALID;

    size_t stride = HIFHE_NTT_TABLE_WORDS(N);
    uint64_t *blob = (uint64_t *)BSL_SAL_Malloc(
        (uint32_t)(((size_t)L + 1u) * stride * sizeof(uint64_t)));
    if (blob == NULL) return HIFHE_MEMORY_ERROR;

    NttTables scratch;
    for (uint32_t i = 0; i < L; ++i) {
        int32_t r = Kernel_Ntt_BuildTables(&scratch, blob + (size_t)i * stride,
                                           cipherMod->data[i], N);
        if (r != HIFHE_SUCCESS) { BSL_SAL_Free(blob); return r; }
        p->lutCipherMod[i] = cipherMod->data[i];
    }
    int32_t r = Kernel_Ntt_BuildTables(&scratch, blob + (size_t)L * stride,
                                       param->plainMod, N);
    if (r != HIFHE_SUCCESS) { BSL_SAL_Free(blob); return r; }

    p->lutBlob       = blob;
    p->lutPolyDegree = N;
    p->lutLimbs      = L;
    p->lutPlainMod   = param->plainMod;
    return HIFHE_SUCCESS;
}

uint64_t *BgvUserPara_CipherLut(const BgvUserPara *p, uint32_t index)
{
    if (p == NULL || p->lutBlob == NULL || index >= p->lutLimbs) {
        return NULL;
    }
    return p->lutBlob + (size_t)index * HIFHE_NTT_TABLE_WORDS(p->lutPolyDegree);
}

uint64_t *BgvUserPara_PlainLut(const BgvUserPara *p)
{
    if (p == NULL || p->lutBlob == NULL) return NULL;
    return p->lutBlob + (size_t)p->lutLimbs * HIFHE_NTT_TABLE_WORDS(p->lutPolyDegree);
}

HIFHE_ERROR BgvUserPara_Copy(BgvUserPara *dst, const BgvUserPara *src)
{
    if (dst == NULL || src == NULL) return HIFHE_NULL_INPUT;
    BgvUserPara_Clear(dst);
    *dst = *src;
    memset(&dst->cipherModBit, 0, sizeof(dst->cipherModBit));
    memset(&dst->cipherMod, 0, sizeof(dst->cipherMod));
    /* Shallow cache copy */
    dst->lutBlob = NULL;
    dst->lutLimbs = 0u;
    dst->lutPolyDegree = 0u;
    int32_t r = Uint32Vector_Create(&dst->cipherModBit,
                                    src->cipherModBit.data, src->cipherModBit.size);
    if (r != HIFHE_SUCCESS) return r;
    if (src->cipherMod.size == 0u) return HIFHE_SUCCESS;
    return Uint64Vector_Create(&dst->cipherMod,
                               src->cipherMod.data, src->cipherMod.size);
}

HIFHE_ERROR BgvUserPara_ParseFromBSL(BgvUserPara *p, const BSL_Param *param)
{
    if (p == NULL || param == NULL) return HIFHE_NULL_INPUT;

    /* Reset the para bag; the caller may re-SetPara across a lifetime. */
    BgvUserPara_Clear(p);
    BgvUserPara_Init(p);

    for (const BSL_Param *cur = param; cur->key != 0; ++cur) {
        switch (cur->key) {
            case HIFHE_PARAM_BGV_POLY_DEGREE:
                if (cur->valueLen != sizeof(uint32_t) || cur->value == NULL) {
                    return HIFHE_PARAM_INVALID;
                }
                p->polyDegree = *(const uint32_t *)cur->value;
                break;
            case HIFHE_PARAM_BGV_PLAIN_MOD_BIT:
                if (cur->valueLen != sizeof(uint32_t) || cur->value == NULL) {
                    return HIFHE_PARAM_INVALID;
                }
                p->plainModBit = *(const uint32_t *)cur->value;
                break;
            case HIFHE_PARAM_BGV_CORRECTION_FACTOR:
                if (cur->valueLen != sizeof(uint64_t) || cur->value == NULL) {
                    return HIFHE_PARAM_INVALID;
                }
                p->correctionFactor = *(const uint64_t *)cur->value;
                break;
            case HIFHE_PARAM_BGV_RELIN_DNUM:
                if (cur->valueLen != sizeof(uint32_t) || cur->value == NULL) {
                    return HIFHE_PARAM_INVALID;
                }
                p->relinDnum = *(const uint32_t *)cur->value;
                break;
            case HIFHE_PARAM_BGV_CIPHER_MOD_BITS: {
                if (cur->value == NULL || cur->valueLen == 0
                    || cur->valueLen % sizeof(uint32_t) != 0) {
                    return HIFHE_PARAM_INVALID;
                }
                uint32_t n = cur->valueLen / (uint32_t)sizeof(uint32_t);
                Uint32Vector_Destroy(&p->cipherModBit);
                int32_t vr = Uint32Vector_Create(&p->cipherModBit,
                                                 (const uint32_t *)cur->value, n);
                if (vr != HIFHE_SUCCESS) return vr;
                break;
            }
            default:
                /* Unknown keys are ignored; SetPara is best-effort. */
                break;
        }
    }

    if (!BGV_Params_IsPolyDegreeSupported(p->polyDegree)) {
        return HIFHE_PARAM_INVALID;
    }
    if (p->cipherModBit.size != 0u
        && !BGV_Params_IsChainLenSupported(p->cipherModBit.size)) {
        return HIFHE_PARAM_INVALID;
    }
    p->set = 1u;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BgvUserPara_LoadPreset(BgvUserPara *p, int32_t presetId)
{
    if (p == NULL) return HIFHE_NULL_INPUT;
    BgvPresetPara preset;
    int32_t ret = BGV_Preset_Load(&preset, presetId);
    if (ret != HIFHE_SUCCESS) {
        return ret;
    }

    BgvUserPara_Clear(p);
    BgvUserPara_Init(p);
    p->polyDegree       = preset.polyDegree;
    p->plainModBit      = preset.plainModBit;
    p->plainMod         = preset.plainMod;
    p->correctionFactor = preset.correctionFactor;
    p->relinDnum        = preset.relinDnum;

    if (preset.cipherModBit != NULL && preset.cipherModBitSize > 0) {
        ret = Uint32Vector_Create(&p->cipherModBit,
                                  preset.cipherModBit, preset.cipherModBitSize);
        if (ret != HIFHE_SUCCESS) return ret;
    }
    if (preset.cipherMod != NULL && preset.cipherModSize > 0) {
        ret = Uint64Vector_Create(&p->cipherMod,
                                  preset.cipherMod, preset.cipherModSize);
        if (ret != HIFHE_SUCCESS) return ret;
    }
    p->set = 1u;
    return HIFHE_SUCCESS;
}
