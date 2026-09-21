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
#include "bsl_sal.h"
#include "bgv/keys.h"
#include "kernel/modulus.h"
#include "rlwe/rlwe.h"

SecretKey *BGV_SecretKey_New(void)
{
    return (SecretKey *)BSL_SAL_Calloc(1u, (uint32_t)sizeof(SecretKey));
}

void BGV_SecretKey_Free(SecretKey **self)
{
    if (self == NULL || *self == NULL) return;
    BGV_Plaintext_Destroy(*self);
    BSL_SAL_Free(*self);
    *self = NULL;
}

/* s^power, slot-wise since the key is NTT-form. The result rides on the
 * key's own RNS base. */
HIFHE_ERROR BGV_SecretKey_GetPow(CrtPoly *out, const SecretKey *sk, uint32_t power)
{
    if (out == NULL || sk == NULL) return HIFHE_NULL_INPUT;
    if (sk->context == NULL || sk->data == NULL) return HIFHE_NULL_INPUT;
    if (power == 0u) return HIFHE_PARAM_INVALID;
    if (sk->config.crtConfig.dtype != HIFHE_NTT) return HIFHE_PARAM_INVALID;

    int32_t r = RLWE_CrtPoly_Create(out, &sk->config.crtConfig, &sk->context->rlweContext);
    if (r != HIFHE_SUCCESS) return r;
    if (out->dataSize != sk->dataSize) {
        RLWE_CrtPoly_Destroy(out);
        return HIFHE_PARAM_INVALID;
    }

    uint32_t N = sk->context->rlweContext.parameter->polyDegree;
    uint32_t L = sk->config.crtConfig.rnsbase.size;
    for (uint32_t i = 0; i < L; ++i) {
        Modulus q = sk->config.crtConfig.rnsbase.data[i];
        const uint64_t *src = sk->data + i * N;
        uint64_t *dst = out->data + i * N;
        if (power == 1u) {
            memcpy(dst, src, N * sizeof(uint64_t));
            continue;
        }
        /* Square-and-multiply. Repeated multiplication is marginally cheaper
         * at the powers a well-formed ciphertext needs, but the component
         * count arrives on the wire and decryption asks for every power up to
         * it, which makes a linear cost per power quadratic in the input. */
        for (uint32_t j = 0; j < N; ++j) {
            dst[j] = Kernel_PowMod(src[j], power, q);
        }
    }
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_RelinKeys_Create(RelinKeys *out, uint32_t rnsSize, uint32_t digits,
                               BGVContext *ctx)
{
    if (out == NULL || ctx == NULL || rnsSize == 0u || digits == 0u) return HIFHE_NULL_INPUT;
    memset(out, 0, sizeof(*out));
    uint32_t dnum = rnsSize * digits;
    out->pieces = (Ciphertext *)BSL_SAL_Calloc(dnum, (uint32_t)sizeof(Ciphertext));
    if (out->pieces == NULL) return HIFHE_MEMORY_ERROR;
    out->dnum    = dnum;
    out->rnsSize = rnsSize;
    out->digits  = digits;
    out->context = ctx;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_RelinKeys_Copy(RelinKeys *dst, const RelinKeys *src)
{
    if (dst == NULL || src == NULL) return HIFHE_NULL_INPUT;
    BGV_RelinKeys_Destroy(dst);
    int32_t r = BGV_RelinKeys_Create(dst, src->rnsSize, src->digits, src->context);
    if (r != HIFHE_SUCCESS) return r;
    for (uint32_t i = 0; i < src->dnum; ++i) {
        r = BGV_Ciphertext_Copy(&dst->pieces[i], &src->pieces[i]);
        if (r != HIFHE_SUCCESS) {
            BGV_RelinKeys_Destroy(dst);
            return r;
        }
    }
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_RelinKeys_Destroy(RelinKeys *self)
{
    if (self == NULL) return HIFHE_NULL_INPUT;
    if (self->pieces != NULL) {
        for (uint32_t i = 0; i < self->dnum; ++i) {
            BGV_Ciphertext_Destroy(&self->pieces[i]);
        }
        BSL_SAL_Free(self->pieces);
    }
    self->pieces  = NULL;
    self->dnum    = 0u;
    self->rnsSize = 0u;
    self->digits  = 0u;
    self->context = NULL;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_GaloisKeys_Create(GaloisKeys *out, BGVContext *ctx)
{
    if (out == NULL || ctx == NULL) return HIFHE_NULL_INPUT;
    memset(out, 0, sizeof(*out));
    out->context = ctx;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_GaloisKeys_CreateEntries(GaloisKeys *self, uint32_t count)
{
    if (self == NULL || count == 0u) return HIFHE_NULL_INPUT;
    if (self->entries != NULL) return HIFHE_KEY_REPEATED_SET;
    self->entries = (GaloisKeyPiece *)BSL_SAL_Calloc(count, (uint32_t)sizeof(GaloisKeyPiece));
    if (self->entries == NULL) return HIFHE_MEMORY_ERROR;
    self->count = count;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_GaloisKeyPiece_Create(GaloisKeyPiece *out, uint64_t galoisElt,
                                    uint32_t rnsSize, uint32_t digits)
{
    if (out == NULL || rnsSize == 0u || digits == 0u) return HIFHE_NULL_INPUT;
    uint32_t dnum = rnsSize * digits;
    out->pieces = (Ciphertext *)BSL_SAL_Calloc(dnum, (uint32_t)sizeof(Ciphertext));
    if (out->pieces == NULL) return HIFHE_MEMORY_ERROR;
    out->galoisElt = galoisElt;
    out->dnum      = dnum;
    out->rnsSize   = rnsSize;
    out->digits    = digits;
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_GaloisKeys_Copy(GaloisKeys *dst, const GaloisKeys *src)
{
    if (dst == NULL || src == NULL) return HIFHE_NULL_INPUT;
    BGV_GaloisKeys_Destroy(dst);
    int32_t r = BGV_GaloisKeys_Create(dst, src->context);
    if (r != HIFHE_SUCCESS) return r;
    if (src->count == 0u || src->entries == NULL) return HIFHE_SUCCESS;
    r = BGV_GaloisKeys_CreateEntries(dst, src->count);
    if (r != HIFHE_SUCCESS) return r;
    for (uint32_t i = 0; i < src->count; ++i) {
        const GaloisKeyPiece *s = &src->entries[i];
        r = BGV_GaloisKeyPiece_Create(&dst->entries[i], s->galoisElt, s->rnsSize, s->digits);
        if (r != HIFHE_SUCCESS) {
            BGV_GaloisKeys_Destroy(dst);
            return r;
        }
        for (uint32_t j = 0; j < s->dnum; ++j) {
            r = BGV_Ciphertext_Copy(&dst->entries[i].pieces[j], &s->pieces[j]);
            if (r != HIFHE_SUCCESS) {
                BGV_GaloisKeys_Destroy(dst);
                return r;
            }
        }
    }
    return HIFHE_SUCCESS;
}

HIFHE_ERROR BGV_GaloisKeys_Destroy(GaloisKeys *self)
{
    if (self == NULL) return HIFHE_NULL_INPUT;
    if (self->entries != NULL) {
        for (uint32_t i = 0; i < self->count; ++i) {
            GaloisKeyPiece *p = &self->entries[i];
            if (p->pieces != NULL) {
                for (uint32_t j = 0; j < p->dnum; ++j) {
                    BGV_Ciphertext_Destroy(&p->pieces[j]);
                }
                BSL_SAL_Free(p->pieces);
            }
        }
        BSL_SAL_Free(self->entries);
    }
    self->entries = NULL;
    self->count   = 0u;
    self->context = NULL;
    return HIFHE_SUCCESS;
}

const GaloisKeyPiece *BGV_GaloisKeys_GetByElt(const GaloisKeys *self, uint64_t elt)
{
    if (self == NULL) return NULL;
    for (uint32_t i = 0; i < self->count; ++i) {
        if (self->entries[i].galoisElt == elt) return &self->entries[i];
    }
    return NULL;
}

