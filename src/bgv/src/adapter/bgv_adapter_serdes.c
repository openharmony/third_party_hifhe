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
 * Wire format, byte-identical to the previous EAL provider's.
 *
 *   header (12)
 *     magic(4) | algId(4) | version(2) | type(2)
 *
 *   plaintext / private key
 *     scaleFactor(8) | polyDegree(4) | rnsSize(4) | dtype(4)
 *     | rnsBase[rnsSize](8) | data[rnsSize * polyDegree](8)
 *
 *   ciphertext / public key
 *     ciphertextSize(4) | correctionFactor(8) | seed[4](8)
 *     | polyDegree(4) | rnsSize(4) | dtype(4)
 *     | rnsBase[rnsSize](8) | data[ciphertextSize * rnsSize * polyDegree](8)
 *
 * Little-endian throughout; dtype is a bare PolyForm.
 *
 * HIFHE_NTT data is stored in the Montgomery domain, per limb:
 *   wire = R * value mod q,  R = 2^64 mod q
 * HIFHE_POLY data is unscaled. Reads reduce first: incoming words may be
 * un-reduced up to 4q.
 */

#include <string.h>
#include "bsl_sal.h"
#include "bgv_local.h"
#include "bgv/plaintext.h"
#include "bgv/ciphertext.h"
#include "bgv/keys.h"
#include "rlwe/rlwe.h"

/* ---- little-endian byte helpers ---- */
static void PutU16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
}
static void PutU32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; ++i) p[i] = (uint8_t)((v >> (8 * i)) & 0xffu);
}
static void PutU64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)((v >> (8 * i)) & 0xffu);
}
static uint16_t GetU16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static uint32_t GetU32(const uint8_t *p)
{
    uint32_t r = 0u;
    for (int i = 0; i < 4; ++i) r |= ((uint32_t)p[i]) << (8 * i);
    return r;
}
static uint64_t GetU64(const uint8_t *p)
{
    uint64_t r = 0u;
    for (int i = 0; i < 8; ++i) r |= ((uint64_t)p[i]) << (8 * i);
    return r;
}

#define WIRE_HEADER_BYTES 12u

/* ---- Montgomery domain conversion ----
 * Per-limb factors for one RNS base. `mul[i]` scales an internal word into
 * the wire domain, `inv[i]` back out. Both are identity for coefficient-form
 * payloads, which the wire stores unscaled. */
typedef struct {
    Modulus  q[HIFHE_BGV_MAX_CHAIN_LEN];
    uint64_t r[HIFHE_BGV_MAX_CHAIN_LEN];      /* 2^64 mod q_i */
    uint64_t rInv[HIFHE_BGV_MAX_CHAIN_LEN];
    /* r and rInv are fixed for a whole payload, each carries a Shoup constant.
     * Costs L divisions at init instead of one per coefficient. */
    ShoupConst rSc[HIFHE_BGV_MAX_CHAIN_LEN];
    ShoupConst rInvSc[HIFHE_BGV_MAX_CHAIN_LEN];
    uint32_t size;
    bool     scaled;    /* false: pass words through untouched */
} DomainFactors;

static HIFHE_ERROR DomainFactors_Init(DomainFactors *f, const RnsBase *base, PolyForm dtype)
{
    if (f == NULL || base == NULL) return HIFHE_NULL_INPUT;
    if (base->size == 0u || base->size > HIFHE_BGV_MAX_CHAIN_LEN) return HIFHE_SERDES_FAIL;
    f->size   = base->size;
    f->scaled = (dtype == HIFHE_NTT);
    for (uint32_t i = 0; i < base->size; ++i) {
        Modulus qi = base->data[i];
        if (qi < 2u) return HIFHE_SERDES_FAIL;
        f->q[i]    = qi;
        f->r[i]    = (uint64_t)((((ModulusWide)1u) << 64) % (ModulusWide)qi);
        f->rInv[i] = Kernel_ModInv(f->r[i], qi);
        if (f->scaled && f->rInv[i] == 0u) return HIFHE_SERDES_FAIL;
        if (Kernel_ShoupConst_Init(&f->rSc[i], f->r[i], qi) != HIFHE_SUCCESS ||
            Kernel_ShoupConst_Init(&f->rInvSc[i], f->rInv[i], qi) != HIFHE_SUCCESS) {
            return HIFHE_SERDES_FAIL;
        }
    }
    return HIFHE_SUCCESS;
}

/* internal (plain Z_q) -> wire (Montgomery) */
static uint64_t ToWireWord(const DomainFactors *f, uint32_t limb, uint64_t v)
{
    if (!f->scaled) return v;
    return Kernel_ShoupMulMod(v, &f->rSc[limb]);
}

/* wire (Montgomery, possibly un-reduced up to 4q) -> internal (plain Z_q) */
static uint64_t FromWireWord(const DomainFactors *f, uint32_t limb, uint64_t v)
{
    uint64_t reduced = (v >= f->q[limb]) ? (v % f->q[limb]) : v;
    if (!f->scaled) return reduced;
    return Kernel_ShoupMulMod(reduced, &f->rInvSc[limb]);
}

static HIFHE_ERROR WriteHeader(uint8_t *buf, uint32_t bufLen, int32_t algId, uint16_t type,
                              uint32_t *offset)
{
    if (bufLen < WIRE_HEADER_BYTES) return HIFHE_BUFFER_TOO_SMALL;
    PutU32(buf,     HIFHE_SERDES_MAGIC);
    PutU32(buf + 4, (uint32_t)algId);
    PutU16(buf + 8, (uint16_t)HIFHE_SERDES_VERSION);
    PutU16(buf + 10, type);
    *offset = WIRE_HEADER_BYTES;
    return HIFHE_SUCCESS;
}

static HIFHE_ERROR ReadHeader(const uint8_t *buf, uint32_t bufLen, uint16_t expectType,
                             int32_t *outAlgId, uint32_t *offset)
{
    if (bufLen < WIRE_HEADER_BYTES) return HIFHE_SERDES_FAIL;
    uint32_t magic = GetU32(buf);
    if (magic != HIFHE_SERDES_MAGIC && magic != HIFHE_SERDES_MAGIC_ALT) {
        return HIFHE_SERDES_FAIL;
    }
    if (GetU16(buf + 8) != HIFHE_SERDES_VERSION) return HIFHE_SERDES_FAIL;
    if (GetU16(buf + 10) != expectType) return HIFHE_SERDES_FAIL;
    if (outAlgId != NULL) *outAlgId = (int32_t)GetU32(buf + 4);
    *offset = WIRE_HEADER_BYTES;
    return HIFHE_SUCCESS;
}

/* Carried base: a prefix of the context chain;
 * only mod-switch shortens it from the tail. */
static HIFHE_ERROR CheckRnsPrefix(const uint64_t *carried, uint32_t carriedSize,
                                 const BGVContext *ctx)
{
    const RnsBase *chain = &ctx->rlweContext.cipherRnsBase;
    if (carriedSize == 0u || carriedSize > chain->size) return HIFHE_SERDES_FAIL;
    for (uint32_t i = 0; i < carriedSize; ++i) {
        if (carried[i] != chain->data[i]) return HIFHE_SERDES_FAIL;
    }
    return HIFHE_SUCCESS;
}

/* ---- Plaintext body ---- */

/* scale(8) | N(4) | rns(4) | dtype(4) | rnsBase(8*rns) | data(8*dataSize) */
static uint32_t PtBodyBytesFor(uint32_t rns, uint32_t dataSize)
{
    return 8u + 4u + 4u + 4u
           + rns * (uint32_t)sizeof(uint64_t)
           + dataSize * (uint32_t)sizeof(uint64_t);
}

static uint32_t PtBodyBytes(const Plaintext *pt)
{
    return PtBodyBytesFor(pt->config.crtConfig.rnsbase.size, pt->dataSize);
}

uint32_t BgvSerDes_PlaintextSizeFor(uint32_t rns, uint32_t dataSize)
{
    return WIRE_HEADER_BYTES + PtBodyBytesFor(rns, dataSize);
}

uint32_t BgvSerDes_PlaintextSize(const Plaintext *pt)
{
    if (pt == NULL) return 0u;
    return WIRE_HEADER_BYTES + PtBodyBytes(pt);
}

static HIFHE_ERROR WritePtBody(uint8_t *buf, uint32_t bufLen, uint32_t *off, const Plaintext *pt)
{
    if (pt->context == NULL || pt->data == NULL) return HIFHE_SERDES_FAIL;
    uint32_t need = PtBodyBytes(pt);
    if (bufLen - *off < need) return HIFHE_BUFFER_TOO_SMALL;
    uint32_t N   = BGV_BGVContext_GetPolyDegree(pt->context);
    uint32_t rns = pt->config.crtConfig.rnsbase.size;

    DomainFactors f;
    int32_t r = DomainFactors_Init(&f, &pt->config.crtConfig.rnsbase,
                                   pt->config.crtConfig.dtype);
    if (r != HIFHE_SUCCESS) return r;

    PutU64(buf + *off, pt->config.scaleFactor); *off += 8u;
    PutU32(buf + *off, N);                      *off += 4u;
    PutU32(buf + *off, rns);                    *off += 4u;
    PutU32(buf + *off, (uint32_t)pt->config.crtConfig.dtype); *off += 4u;
    for (uint32_t i = 0; i < rns; ++i) {
        PutU64(buf + *off, pt->config.crtConfig.rnsbase.data[i]); *off += 8u;
    }
    for (uint32_t i = 0; i < rns; ++i) {
        const uint64_t *slice = pt->data + i * N;
        for (uint32_t j = 0; j < N; ++j) {
            PutU64(buf + *off, ToWireWord(&f, i, slice[j])); *off += 8u;
        }
    }
    return HIFHE_SUCCESS;
}

static HIFHE_ERROR ReadPtBody(const uint8_t *buf, uint32_t bufLen, uint32_t *off,
                             Plaintext *pt, BGVContext *ctx)
{
    if (bufLen - *off < 20u) return HIFHE_SERDES_FAIL;
    uint64_t scale = GetU64(buf + *off); *off += 8u;
    uint32_t N     = GetU32(buf + *off); *off += 4u;
    uint32_t rns   = GetU32(buf + *off); *off += 4u;
    uint32_t dword = GetU32(buf + *off); *off += 4u;
    if (N != BGV_BGVContext_GetPolyDegree(ctx)) return HIFHE_SERDES_FAIL;
    if (rns == 0u || rns > ctx->rlweContext.cipherRnsBase.size) return HIFHE_SERDES_FAIL;
    if (dword != (uint32_t)HIFHE_POLY && dword != (uint32_t)HIFHE_NTT) {
        return HIFHE_SERDES_FAIL;
    }
    if (bufLen - *off < rns * 8u) return HIFHE_SERDES_FAIL;

    uint64_t rnsStack[HIFHE_BGV_MAX_CHAIN_LEN];
    for (uint32_t i = 0; i < rns; ++i) { rnsStack[i] = GetU64(buf + *off); *off += 8u; }
    int32_t r = CheckRnsPrefix(rnsStack, rns, ctx);
    if (r != HIFHE_SUCCESS) return r;

    PlaintextConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    r = Uint64Vector_Create(&cfg.crtConfig.rnsbase, rnsStack, rns);
    if (r != HIFHE_SUCCESS) return r;
    cfg.crtConfig.dtype = (PolyForm)dword;
    cfg.scaleFactor     = scale;
    /* Capabilities are a context property, not a wire field. */
    cfg.caps            = HIFHE_CAP_LUT |
                          (BGV_BGVContext_GetUseSlotMap(ctx) ? HIFHE_CAP_SLOT_MAP : 0u);

    DomainFactors f;
    r = DomainFactors_Init(&f, &cfg.crtConfig.rnsbase, cfg.crtConfig.dtype);
    if (r != HIFHE_SUCCESS) { BGV_PlaintextConfig_Destroy(&cfg); return r; }

    BGV_Plaintext_Destroy(pt);
    r = BGV_Plaintext_Create(pt, &cfg, ctx);
    BGV_PlaintextConfig_Destroy(&cfg);
    if (r != HIFHE_SUCCESS) return r;

    uint32_t want = pt->dataSize * (uint32_t)sizeof(uint64_t);
    if (bufLen - *off < want) { BGV_Plaintext_Destroy(pt); return HIFHE_SERDES_FAIL; }
    for (uint32_t i = 0; i < rns; ++i) {
        uint64_t *slice = pt->data + i * N;
        for (uint32_t j = 0; j < N; ++j) {
            slice[j] = FromWireWord(&f, i, GetU64(buf + *off)); *off += 8u;
        }
    }
    return HIFHE_SUCCESS;
}

/* ---- Ciphertext body ---- */

/* ctSize(4) | corr(8) | seed(32) | N(4) | rns(4) | dtype(4)
 * | rnsBase(8*rns) | data(8*dataSize) */
static uint32_t CtBodyBytesFor(uint32_t rns, uint32_t dataSize)
{
    return 4u + 8u + (HIFHE_CIPHERTEXT_SEED_LEN * 8u) + 4u + 4u + 4u
           + rns * (uint32_t)sizeof(uint64_t)
           + dataSize * (uint32_t)sizeof(uint64_t);
}

static uint32_t CtBodyBytes(const Ciphertext *ct)
{
    return CtBodyBytesFor(ct->config.crtConfig.rnsbase.size, ct->dataSize);
}

uint32_t BgvSerDes_CiphertextSizeFor(uint32_t rns, uint32_t dataSize)
{
    return WIRE_HEADER_BYTES + CtBodyBytesFor(rns, dataSize);
}

uint32_t BgvSerDes_CiphertextSize(const Ciphertext *ct)
{
    if (ct == NULL) return 0u;
    return WIRE_HEADER_BYTES + CtBodyBytes(ct);
}

static HIFHE_ERROR WriteCtBody(uint8_t *buf, uint32_t bufLen, uint32_t *off, const Ciphertext *ct)
{
    if (ct->context == NULL || ct->data == NULL) return HIFHE_SERDES_FAIL;
    uint32_t need = CtBodyBytes(ct);
    if (bufLen - *off < need) return HIFHE_BUFFER_TOO_SMALL;
    uint32_t N   = BGV_BGVContext_GetPolyDegree(ct->context);
    uint32_t rns = ct->config.crtConfig.rnsbase.size;

    DomainFactors f;
    int32_t r = DomainFactors_Init(&f, &ct->config.crtConfig.rnsbase,
                                   ct->config.crtConfig.dtype);
    if (r != HIFHE_SUCCESS) return r;

    PutU32(buf + *off, ct->config.ciphertextSize);   *off += 4u;
    PutU64(buf + *off, ct->config.correctionFactor); *off += 8u;
    for (uint32_t i = 0; i < HIFHE_CIPHERTEXT_SEED_LEN; ++i) {
        PutU64(buf + *off, ct->config.seed[i]);      *off += 8u;
    }
    PutU32(buf + *off, N);   *off += 4u;
    PutU32(buf + *off, rns); *off += 4u;
    PutU32(buf + *off, (uint32_t)ct->config.crtConfig.dtype); *off += 4u;
    for (uint32_t i = 0; i < rns; ++i) {
        PutU64(buf + *off, ct->config.crtConfig.rnsbase.data[i]); *off += 8u;
    }
    for (uint32_t k = 0; k < ct->config.ciphertextSize; ++k) {
        for (uint32_t i = 0; i < rns; ++i) {
            const uint64_t *slice = ct->data + (k * rns + i) * N;
            for (uint32_t j = 0; j < N; ++j) {
                PutU64(buf + *off, ToWireWord(&f, i, slice[j])); *off += 8u;
            }
        }
    }
    return HIFHE_SUCCESS;
}

static HIFHE_ERROR ReadCtBody(const uint8_t *buf, uint32_t bufLen, uint32_t *off,
                             Ciphertext *ct, BGVContext *ctx)
{
    uint32_t fixed = 4u + 8u + HIFHE_CIPHERTEXT_SEED_LEN * 8u + 4u + 4u + 4u;
    if (bufLen - *off < fixed) return HIFHE_SERDES_FAIL;
    uint32_t sz  = GetU32(buf + *off); *off += 4u;
    uint64_t crf = GetU64(buf + *off); *off += 8u;
    uint64_t seed[HIFHE_CIPHERTEXT_SEED_LEN];
    for (uint32_t i = 0; i < HIFHE_CIPHERTEXT_SEED_LEN; ++i) {
        seed[i] = GetU64(buf + *off); *off += 8u;
    }
    uint32_t N     = GetU32(buf + *off); *off += 4u;
    uint32_t rns   = GetU32(buf + *off); *off += 4u;
    uint32_t dword = GetU32(buf + *off); *off += 4u;
    if (sz == 0u) return HIFHE_SERDES_FAIL;
    if (N != BGV_BGVContext_GetPolyDegree(ctx)) return HIFHE_SERDES_FAIL;
    if (rns == 0u || rns > ctx->rlweContext.cipherRnsBase.size) return HIFHE_SERDES_FAIL;
    if (dword != (uint32_t)HIFHE_POLY && dword != (uint32_t)HIFHE_NTT) {
        return HIFHE_SERDES_FAIL;
    }
    /* ciphertextSize arrives on the wire and CalDataSize multiplies it out in
     * uint32, so a crafted shape wraps that product and allocates less than
     * the copy loop writes. Measuring the body in 64 bits rejects those, and
     * ties the allocation to the input length. */
    uint64_t bodyBytes = (uint64_t)rns * 8u +
                         (uint64_t)sz * (uint64_t)rns * (uint64_t)N * sizeof(uint64_t);
    if (bodyBytes > (uint64_t)(bufLen - *off)) return HIFHE_SERDES_FAIL;

    uint64_t rnsStack[HIFHE_BGV_MAX_CHAIN_LEN];
    for (uint32_t i = 0; i < rns; ++i) { rnsStack[i] = GetU64(buf + *off); *off += 8u; }
    int32_t r = CheckRnsPrefix(rnsStack, rns, ctx);
    if (r != HIFHE_SUCCESS) return r;

    RnsBase base;
    memset(&base, 0, sizeof(base));
    r = Uint64Vector_Create(&base, rnsStack, rns);
    if (r != HIFHE_SUCCESS) return r;

    CiphertextConfig cfg;
    r = BGV_CiphertextConfig_Create(&cfg, sz, crf, &base);
    Uint64Vector_Destroy(&base);
    if (r != HIFHE_SUCCESS) return r;
    memcpy(cfg.seed, seed, sizeof(seed));
    cfg.crtConfig.dtype = (PolyForm)dword;
    cfg.caps            = HIFHE_CAP_LUT |
                          (BGV_BGVContext_GetUseSlotMap(ctx) ? HIFHE_CAP_SLOT_MAP : 0u);

    DomainFactors f;
    r = DomainFactors_Init(&f, &cfg.crtConfig.rnsbase, cfg.crtConfig.dtype);
    if (r != HIFHE_SUCCESS) { BGV_CiphertextConfig_Destroy(&cfg); return r; }

    BGV_Ciphertext_Destroy(ct);
    r = BGV_Ciphertext_Create(ct, &cfg, ctx);
    BGV_CiphertextConfig_Destroy(&cfg);
    if (r != HIFHE_SUCCESS) return r;

    uint32_t want = ct->dataSize * (uint32_t)sizeof(uint64_t);
    if (bufLen - *off < want) { BGV_Ciphertext_Destroy(ct); return HIFHE_SERDES_FAIL; }
    for (uint32_t k = 0; k < sz; ++k) {
        for (uint32_t i = 0; i < rns; ++i) {
            uint64_t *slice = ct->data + (k * rns + i) * N;
            for (uint32_t j = 0; j < N; ++j) {
                slice[j] = FromWireWord(&f, i, GetU64(buf + *off)); *off += 8u;
            }
        }
    }
    return HIFHE_SUCCESS;
}

/* ---- Public API ---- */

static int32_t DumpPtTyped(const Plaintext *pt, uint8_t *buf, uint32_t *bufLen,
                           int32_t algId, uint16_t type)
{
    if (pt == NULL || bufLen == NULL) return HIFHE_NULL_INPUT;
    uint32_t need = BgvSerDes_PlaintextSize(pt);
    if (buf == NULL || *bufLen < need) { *bufLen = need; return HIFHE_BUFFER_TOO_SMALL; }
    uint32_t off = 0u;
    int32_t r = WriteHeader(buf, *bufLen, algId, type, &off);
    if (r != HIFHE_SUCCESS) return r;
    r = WritePtBody(buf, *bufLen, &off, pt);
    if (r != HIFHE_SUCCESS) return r;
    *bufLen = off;
    return HIFHE_SUCCESS;
}

static int32_t DumpCtTyped(const Ciphertext *ct, uint8_t *buf, uint32_t *bufLen,
                           int32_t algId, uint16_t type)
{
    if (ct == NULL || bufLen == NULL) return HIFHE_NULL_INPUT;
    uint32_t need = BgvSerDes_CiphertextSize(ct);
    if (buf == NULL || *bufLen < need) { *bufLen = need; return HIFHE_BUFFER_TOO_SMALL; }
    uint32_t off = 0u;
    int32_t r = WriteHeader(buf, *bufLen, algId, type, &off);
    if (r != HIFHE_SUCCESS) return r;
    r = WriteCtBody(buf, *bufLen, &off, ct);
    if (r != HIFHE_SUCCESS) return r;
    *bufLen = off;
    return HIFHE_SUCCESS;
}

int32_t BgvSerDes_DumpPlaintext(const Plaintext *pt, uint8_t *buf, uint32_t *bufLen, int32_t algId)
{
    return DumpPtTyped(pt, buf, bufLen, algId, HIFHE_SERDES_TYPE_PLAINTEXT);
}

int32_t BgvSerDes_LoadPlaintext(Plaintext *pt, const uint8_t *buf, uint32_t bufLen,
                                BGVContext *context)
{
    if (pt == NULL || buf == NULL || context == NULL) return HIFHE_NULL_INPUT;
    uint32_t off = 0u;
    int32_t r = ReadHeader(buf, bufLen, HIFHE_SERDES_TYPE_PLAINTEXT, NULL, &off);
    if (r != HIFHE_SUCCESS) return r;
    return ReadPtBody(buf, bufLen, &off, pt, context);
}

int32_t BgvSerDes_DumpCiphertext(const Ciphertext *ct, uint8_t *buf, uint32_t *bufLen, int32_t algId)
{
    return DumpCtTyped(ct, buf, bufLen, algId, HIFHE_SERDES_TYPE_CIPHER);
}

int32_t BgvSerDes_LoadCiphertext(Ciphertext *ct, const uint8_t *buf, uint32_t bufLen,
                                 BGVContext *context)
{
    if (ct == NULL || buf == NULL || context == NULL) return HIFHE_NULL_INPUT;
    uint32_t off = 0u;
    int32_t r = ReadHeader(buf, bufLen, HIFHE_SERDES_TYPE_CIPHER, NULL, &off);
    if (r != HIFHE_SUCCESS) return r;
    return ReadCtBody(buf, bufLen, &off, ct, context);
}

/* PublicKey / PrivateKey reuse the Ciphertext / Plaintext bodies under a
 * distinct wire type. */

uint32_t BgvSerDes_PubKeySize(const PublicKey *pk) { return BgvSerDes_CiphertextSize(pk); }
uint32_t BgvSerDes_PrvKeySize(const SecretKey *sk) { return BgvSerDes_PlaintextSize(sk); }

int32_t BgvSerDes_DumpPubKey(const PublicKey *pk, uint8_t *buf, uint32_t *bufLen, int32_t algId)
{
    return DumpCtTyped(pk, buf, bufLen, algId, HIFHE_SERDES_TYPE_PUBKEY);
}

int32_t BgvSerDes_LoadPubKey(PublicKey *pk, const uint8_t *buf, uint32_t bufLen, BGVContext *context)
{
    if (pk == NULL || buf == NULL || context == NULL) return HIFHE_NULL_INPUT;
    uint32_t off = 0u;
    int32_t r = ReadHeader(buf, bufLen, HIFHE_SERDES_TYPE_PUBKEY, NULL, &off);
    if (r != HIFHE_SUCCESS) return r;
    return ReadCtBody(buf, bufLen, &off, pk, context);
}

int32_t BgvSerDes_DumpPrvKey(const SecretKey *sk, uint8_t *buf, uint32_t *bufLen, int32_t algId)
{
    return DumpPtTyped(sk, buf, bufLen, algId, HIFHE_SERDES_TYPE_PRVKEY);
}

int32_t BgvSerDes_LoadPrvKey(SecretKey *sk, const uint8_t *buf, uint32_t bufLen, BGVContext *context)
{
    if (sk == NULL || buf == NULL || context == NULL) return HIFHE_NULL_INPUT;
    uint32_t off = 0u;
    int32_t r = ReadHeader(buf, bufLen, HIFHE_SERDES_TYPE_PRVKEY, NULL, &off);
    if (r != HIFHE_SUCCESS) return r;
    /* Decryption indexes the key over the ciphertext's whole chain, so a key
     * carrying fewer limbs would be read past its allocation. The rns field
     * follows scale(8) and N(4). */
    if (bufLen - off < 20u ||
        GetU32(buf + off + 12u) != context->rlweContext.cipherRnsBase.size) {
        return HIFHE_SERDES_FAIL;
    }
    return ReadPtBody(buf, bufLen, &off, sk, context);
}

