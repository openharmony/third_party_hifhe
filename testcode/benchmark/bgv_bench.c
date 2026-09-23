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
 * Benchmarks for BGV, in two modules.
 *
 * Kernel measures the transforms and the modular arithmetic under them, with
 * serialization and key management out of the picture. It is the view to
 * optimise against: the numbers the Bgv module reports move only as far as
 * these do. The transforms run in place with no reset between iterations; a
 * forward NTT's output is a valid forward NTT input because every element
 * stays below q, so repeating it does identical work, and a reset would add a
 * memcpy the library never performs.
 *
 * Bgv measures what a caller going through CRYPT_BGV_* pays. Every context is
 * created through CRYPT_BGV_NewCtxWithCache against one handle held for the
 * life of the process, so the NTT tables are computed once and every later
 * setUp reads them, which keeps table construction out of the per-operation
 * rows. Each figure includes the wire encoding on both ends because this
 * surface takes and returns serialized buffers; for the cheap operations that
 * overhead dominates the number.
 */

#include <stdlib.h>
#include <string.h>

#include "hifhe_types.h"
#include "hifhe_provider.h"
#include "hifhe_err.h"
#include "crypt_bgv.h"
#include "crypt_types.h"
#include "bsl_params.h"
#include "bsl_sal.h"
#include "bgv/params_preset.h"
#include "kernel/modulus.h"
#include "kernel/ntt.h"
#include "kernel/prime.h"
#include "rlwe/rlwe.h"
#include "rlwe/rlwe_context.h"
#include "rlwe/rns_ops.h"

#include "benchmark.h"

/* Both modules walk the same parameter sets. */
static const int32_t g_benchPresets[] = {
    HIFHE_BGV_2048_48_17BIT,
    HIFHE_BGV_4096_44x2_17BIT,
    HIFHE_BGV_8192_44x4_17BIT,
};

/* ================ Kernel: transforms and modular arithmetic ============ */

#define KERNEL_MAX_LIMBS 8u

typedef struct {
    uint32_t      polyDegree;
    uint32_t      limbs;
    Modulus       cipherQ;        /* limb 0, the one the transforms use */
    Modulus       plainT;
    RlweParameter param;
    RlweContext   rlwe;           /* owns the ciphertext-side twiddle tables */

    NttTables     plainTbl;
    Uint64Vector  plainTable;    /* HIFHE_NTT_TABLE_WORDS(N) */

    Uint64Vector  work;           /* one polynomial, cipher side */
    Uint64Vector  workPlain;
    Uint64Vector  scratchTable;   /* table-build destination */

    RnsPoly       a, b, c;        /* pointwise operands */
} KernelState;

/* Resolve a preset to its concrete moduli the same way Bgv_BuildContext
 * does, so the benchmark uses the moduli production uses. */
static int32_t ResolveModuli(const BgvPresetPara *preset, Modulus *cipher,
                             uint32_t *cipherLen, Modulus *plain)
{
    uint32_t len = preset->cipherModBitSize;
    if (len == 0u || len > KERNEL_MAX_LIMBS) {
        return HIFHE_PARAM_INVALID;
    }
    if (preset->cipherMod != NULL && preset->cipherModSize == len) {
        for (uint32_t i = 0; i < len; ++i) {
            cipher[i] = preset->cipherMod[i];
        }
    } else {
        for (uint32_t i = 0; i < len; ++i) {
            Modulus q = 0u;
            int32_t r = Kernel_Prime_FindProth(&q, preset->cipherModBit[i],
                                               preset->polyDegree, cipher, i);
            if (r != HIFHE_SUCCESS) {
                return r;
            }
            cipher[i] = q;
        }
    }
    *cipherLen = len;

    if (preset->plainMod != 0u) {
        *plain = preset->plainMod;
        return HIFHE_SUCCESS;
    }
    return Kernel_Prime_FindProth(plain, preset->plainModBit, preset->polyDegree, NULL, 0u);
}

static void KernelTearDown(void *ctx)
{
    KernelState *st = (KernelState *)ctx;
    if (st == NULL) {
        return;
    }
    RLWE_RnsPoly_Destroy(&st->a);
    RLWE_RnsPoly_Destroy(&st->b);
    RLWE_RnsPoly_Destroy(&st->c);
    Uint64Vector_Destroy(&st->scratchTable);
    Uint64Vector_Destroy(&st->workPlain);
    Uint64Vector_Destroy(&st->work);
    Uint64Vector_Destroy(&st->plainTable);
    RLWE_RlweContext_Destroy(&st->rlwe);
    RLWE_RlweParameter_Destroy(&st->param);
    BSL_SAL_Free(st);
}

static int32_t KernelSetUp(void **ctx, int32_t presetId)
{
    BgvPresetPara preset;
    int32_t r = BGV_Preset_Load(&preset, presetId);
    if (r != HIFHE_SUCCESS) {
        return r;
    }

    Modulus cipher[KERNEL_MAX_LIMBS] = {0};
    Modulus plain = 0u;
    uint32_t limbs = 0u;
    r = ResolveModuli(&preset, cipher, &limbs, &plain);
    if (r != HIFHE_SUCCESS) {
        return r;
    }

    KernelState *st = (KernelState *)BSL_SAL_Calloc(1u, (uint32_t)sizeof(KernelState));
    if (st == NULL) {
        return HIFHE_MEMORY_ERROR;
    }
    uint32_t n = preset.polyDegree;
    st->polyDegree = n;
    st->limbs      = limbs;
    st->cipherQ    = cipher[0];
    st->plainT     = plain;

    ModulusVector chain;
    r = Uint64Vector_Create(&chain, cipher, limbs);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    r = RLWE_RlweParameter_Create(&st->param, 2u, n, &chain);
    Uint64Vector_Destroy(&chain);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    r = RLWE_RlweContext_BuildWithTables(&st->rlwe, &st->param, NULL);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }

    /* Plaintext-side tables, built the way BGV_BGVContext_EnsurePlainNtt
     * does. One call fills the struct from one buffer. */
    r = Uint64Vector_Create(&st->plainTable, NULL, (uint32_t)HIFHE_NTT_TABLE_WORDS(n));
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    r = Kernel_Ntt_BuildTables(&st->plainTbl, st->plainTable.data, plain, n);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }

    r = Uint64Vector_Create(&st->work, NULL, n);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    r = Uint64Vector_Create(&st->workPlain, NULL, n);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    r = Uint64Vector_Create(&st->scratchTable, NULL, (uint32_t)HIFHE_NTT_TABLE_WORDS(n));
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    for (uint32_t i = 0; i < n; ++i) {
        st->work.data[i]      = ((uint64_t)i * 2654435761u + 12345u) % st->cipherQ;
        st->workPlain.data[i] = ((uint64_t)i * 7919u + 3u) % st->plainT;
    }

    RnsPolyConfig cfg = {.modulus = st->cipherQ, .dtype = HIFHE_NTT};
    r = RLWE_RnsPoly_Create(&st->a, &cfg, &st->rlwe);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    r = RLWE_RnsPoly_Create(&st->b, &cfg, &st->rlwe);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    r = RLWE_RnsPoly_Create(&st->c, &cfg, &st->rlwe);
    if (r != HIFHE_SUCCESS) {
        goto err;
    }
    for (uint32_t i = 0; i < n; ++i) {
        st->a.data[i] = st->work.data[i];
        st->b.data[i] = (st->work.data[i] + 7u) % st->cipherQ;
    }

    *ctx = st;
    return HIFHE_SUCCESS;

err:
    KernelTearDown(st);
    return r;
}

/* ---------------- operations ---------------- */

static int32_t KernelNttForward(void *ctx, const BenchExecOptions *opts)
{
    KernelState *st = (KernelState *)ctx;
    const NttTables *tbl = RLWE_RlweContext_GetNttTablesByModulus(&st->rlwe, st->cipherQ);
    if (tbl == NULL) {
        return HIFHE_INTERNAL;
    }
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN_VA(Kernel_Ntt_Forward(st->work.data, tbl), rc, HIFHE_SUCCESS,
                 st->polyDegree, opts, "%s NttForward(cipher)",
                 BenchPresetName(opts->presetId));
    return rc;
}

static int32_t KernelNttInverse(void *ctx, const BenchExecOptions *opts)
{
    KernelState *st = (KernelState *)ctx;
    const NttTables *tbl = RLWE_RlweContext_GetNttTablesByModulus(&st->rlwe, st->cipherQ);
    if (tbl == NULL) {
        return HIFHE_INTERNAL;
    }
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN_VA(Kernel_Ntt_Inverse(st->work.data, tbl), rc, HIFHE_SUCCESS,
                 st->polyDegree, opts, "%s NttInverse(cipher)",
                 BenchPresetName(opts->presetId));
    return rc;
}

static int32_t KernelPlainNttForward(void *ctx, const BenchExecOptions *opts)
{
    KernelState *st = (KernelState *)ctx;
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN_VA(Kernel_Ntt_Forward(st->workPlain.data, &st->plainTbl), rc, HIFHE_SUCCESS,
                 st->polyDegree, opts, "%s PlainNttForward",
                 BenchPresetName(opts->presetId));
    return rc;
}

static int32_t KernelPlainNttInverse(void *ctx, const BenchExecOptions *opts)
{
    KernelState *st = (KernelState *)ctx;
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN_VA(Kernel_Ntt_Inverse(st->workPlain.data, &st->plainTbl), rc, HIFHE_SUCCESS,
                 st->polyDegree, opts, "%s PlainNttInverse",
                 BenchPresetName(opts->presetId));
    return rc;
}

/* Cost of building the twiddle tables for one modulus. */
static int32_t KernelTableBuild(void *ctx, const BenchExecOptions *opts)
{
    KernelState *st = (KernelState *)ctx;
    NttTables scratch;
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN_VA(Kernel_Ntt_BuildTables(&scratch, st->scratchTable.data,
                                        st->cipherQ, st->polyDegree),
                 rc, HIFHE_SUCCESS, st->polyDegree, opts, "%s TableBuild(cipher)",
                 BenchPresetName(opts->presetId));
    return rc;
}

/* Pointwise product over one limb, the inner loop of ct * ct. */
static int32_t KernelMulDot(void *ctx, const BenchExecOptions *opts)
{
    KernelState *st = (KernelState *)ctx;
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN_VA(RLWE_RnsPoly_MulDot(&st->c, &st->a, &st->b), rc, HIFHE_SUCCESS,
                 st->polyDegree, opts, "%s MulDot(1 limb)",
                 BenchPresetName(opts->presetId));
    return rc;
}

static int32_t KernelAddDot(void *ctx, const BenchExecOptions *opts)
{
    KernelState *st = (KernelState *)ctx;
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN_VA(RLWE_RnsPoly_Add(&st->c, &st->a, &st->b), rc, HIFHE_SUCCESS,
                 st->polyDegree, opts, "%s Add(1 limb)",
                 BenchPresetName(opts->presetId));
    return rc;
}

DEFINE_HIFHE_OPS(Kernel,
    DEFINE_OPER(HIFHE_BENCH_NTT,   KernelNttForward),
    DEFINE_OPER(HIFHE_BENCH_INTT,  KernelNttInverse),
    DEFINE_OPER(HIFHE_BENCH_NTT,   KernelPlainNttForward),
    DEFINE_OPER(HIFHE_BENCH_INTT,  KernelPlainNttInverse),
    DEFINE_OPER(HIFHE_BENCH_TABLE, KernelTableBuild),
    DEFINE_OPER(HIFHE_BENCH_ARITH, KernelMulDot),
    DEFINE_OPER(HIFHE_BENCH_ARITH, KernelAddDot));

DEFINE_BENCH_CTX_TIMES(Kernel, g_benchPresets, SIZEOF(g_benchPresets), 2000u);

/* ================ Bgv: the CRYPT_BGV_* surface ========================= */

int32_t BgvBenchBuildAndDrop(int32_t presetId);
void    BgvBenchReleaseCache(void);

/* One handle for the whole run. The tables are a function of the preset and
 * every module below uses the same few presets. */
static BgvUserPara *g_lutCache = NULL;

void BgvBenchReleaseCache(void)
{
    if (g_lutCache != NULL) {
        CRYPT_BGV_FreeCache(g_lutCache);
        g_lutCache = NULL;
    }
}

typedef struct {
    CRYPT_BGV_Ctx *hifhe;
    int32_t   presetId;
    uint32_t  n;
    uint32_t  level;
    uint32_t  msgLen;
    uint32_t  ptCap;
    uint32_t  ctCap;
    uint32_t  bigCap;      /* a size-3 product needs more than ctCap */

    uint64_t *msg;
    uint64_t *msgOut;
    uint8_t  *pt;
    uint32_t  ptLen;
    uint8_t  *ptOut;
    uint8_t  *ct;
    uint32_t  ctLen;
    uint8_t  *ct3;         /* size-3 product, captured before the relin key */
    uint32_t  ct3Len;
    uint8_t  *out;

    bool      haveRelin;
    bool      haveGalois;
} BgvState;

static void BgvTearDown(void *ctx)
{
    BgvState *st = (BgvState *)ctx;
    if (st == NULL) return;
    BSL_SAL_FREE(st->msg);
    BSL_SAL_FREE(st->msgOut);
    BSL_SAL_FREE(st->pt);
    BSL_SAL_FREE(st->ptOut);
    BSL_SAL_FREE(st->ct);
    BSL_SAL_FREE(st->ct3);
    BSL_SAL_FREE(st->out);
    if (st->hifhe != NULL) CRYPT_BGV_FreeCtx(st->hifhe);
    BSL_SAL_Free(st);
}

static int32_t BgvSetUp(void **ctx, int32_t presetId)
{
    BgvState *st = (BgvState *)BSL_SAL_Calloc(1u, (uint32_t)sizeof(BgvState));
    if (st == NULL) return HIFHE_MEMORY_ERROR;
    st->presetId = presetId;

    st->hifhe = (CRYPT_BGV_Ctx *)CRYPT_BGV_NewCtxWithCache(HIFHE_PKEY_BGV, &g_lutCache);
    if (st->hifhe == NULL) {
        BgvTearDown(st);
        return HIFHE_MEMORY_ERROR;
    }

    int32_t id = presetId;
    int32_t r = CRYPT_BGV_Ctrl(st->hifhe, CRYPT_CTRL_SET_PARA_BY_ID, &id, sizeof(id));
    if (r != HIFHE_SUCCESS) goto err;
    r = CRYPT_BGV_Gen(st->hifhe);
    if (r != HIFHE_SUCCESS) goto err;

    (void)CRYPT_BGV_Ctrl(st->hifhe, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &st->n, sizeof(st->n));
    (void)CRYPT_BGV_Ctrl(st->hifhe, HIFHE_CTRL_BGV_GET_LEVEL, &st->level, sizeof(st->level));
    (void)CRYPT_BGV_Ctrl(st->hifhe, HIFHE_CTRL_BGV_GET_MSG_LEN, &st->msgLen, sizeof(st->msgLen));
    (void)CRYPT_BGV_Ctrl(st->hifhe, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &st->ptCap, sizeof(st->ptCap));
    (void)CRYPT_BGV_Ctrl(st->hifhe, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &st->ctCap, sizeof(st->ctCap));
    if (st->n == 0u || st->msgLen == 0u || st->ptCap == 0u || st->ctCap == 0u) {
        r = HIFHE_INTERNAL;
        goto err;
    }
    st->bigCap = st->ctCap * 2u;

    st->msg    = (uint64_t *)BSL_SAL_Malloc(st->msgLen);
    st->msgOut = (uint64_t *)BSL_SAL_Malloc(st->msgLen);
    st->pt     = (uint8_t *)BSL_SAL_Malloc(st->ptCap);
    st->ptOut  = (uint8_t *)BSL_SAL_Malloc(st->ptCap);
    st->ct     = (uint8_t *)BSL_SAL_Malloc(st->ctCap);
    st->ct3    = (uint8_t *)BSL_SAL_Malloc(st->bigCap);
    st->out    = (uint8_t *)BSL_SAL_Malloc(st->bigCap);
    if (st->msg == NULL || st->msgOut == NULL || st->pt == NULL || st->ptOut == NULL ||
        st->ct == NULL || st->ct3 == NULL || st->out == NULL) {
        r = HIFHE_MEMORY_ERROR;
        goto err;
    }
    for (uint32_t i = 0; i < st->n; ++i) st->msg[i] = i % 50u;

    BSL_Param enc[] = {
        {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, st->msg, st->msgLen, 0},
        BSL_PARAM_END
    };
    uint32_t len = st->ptCap;
    r = CRYPT_BGV_HEMsgEncode(st->hifhe, enc, st->pt, &len);
    if (r != HIFHE_SUCCESS) goto err;
    st->ptLen = len;

    len = st->ctCap;
    r = CRYPT_BGV_Encrypt(st->hifhe, st->pt, st->ptLen, st->ct, &len);
    if (r != HIFHE_SUCCESS) goto err;
    st->ctLen = len;

    /* Take the size-3 product before the relin key exists. HEMul relinearizes
     * once there is one, after which this surface cannot produce a size-3
     * ciphertext. */
    BSL_Param mul[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, st->ct, st->ctLen, 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, st->ct, st->ctLen, 0},
        BSL_PARAM_END
    };
    len = st->bigCap;
    if (CRYPT_BGV_HEMul(st->hifhe, mul, st->ct3, &len) == HIFHE_SUCCESS) st->ct3Len = len;

    st->haveRelin = (CRYPT_BGV_Ctrl(st->hifhe, HIFHE_CTRL_BGV_GEN_RELIN_KEY, NULL, 0) == HIFHE_SUCCESS);
    int32_t steps[] = {1};
    BSL_Param gk[] = {
        {HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_OCTETS, steps, (uint32_t)sizeof(steps), 0},
        BSL_PARAM_END
    };
    st->haveGalois = (CRYPT_BGV_Ctrl(st->hifhe, HIFHE_CTRL_BGV_GEN_GALOIS_KEYS, gk, 0) == HIFHE_SUCCESS);

    *ctx = st;
    return HIFHE_SUCCESS;

err:
    BgvTearDown(st);
    return r;
}

static void SkipRow(const char *what, uint32_t slots, const char *why)
{
    printf("%-38s, %8u, %12s, %14s, %14s, %14s   (%s)\n",
           what, slots, "-", "-", "-", "-", why);
}

/* ---------------- operations ---------------- */

static int32_t BgvKeyGen(void *ctx, const BenchExecOptions *opts)
{
    BgvState *st = (BgvState *)ctx;
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN_VA(CRYPT_BGV_Gen(st->hifhe), rc, HIFHE_SUCCESS, st->n, opts,
                 "%s KeyGen", BenchPresetName(opts->presetId));
    return rc;
}

static int32_t BgvEncode(void *ctx, const BenchExecOptions *opts)
{
    BgvState *st = (BgvState *)ctx;
    BSL_Param enc[] = {
        {HIFHE_PARAM_BGV_MSG, BSL_PARAM_TYPE_OCTETS, st->msg, st->msgLen, 0},
        BSL_PARAM_END
    };
    uint32_t len;
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN_VA((len = st->ptCap, CRYPT_BGV_HEMsgEncode(st->hifhe, enc, st->ptOut, &len)),
                 rc, HIFHE_SUCCESS, st->n, opts, "%s Encode",
                 BenchPresetName(opts->presetId));
    return rc;
}

static int32_t BgvDecode(void *ctx, const BenchExecOptions *opts)
{
    BgvState *st = (BgvState *)ctx;
    BSL_Param dec[] = {
        {HIFHE_PARAM_BGV_PLAINTEXT, BSL_PARAM_TYPE_OCTETS, st->pt, st->ptLen, 0},
        BSL_PARAM_END
    };
    uint32_t len;
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN_VA((len = st->msgLen,
                  CRYPT_BGV_HEMsgDecode(st->hifhe, dec, (uint8_t *)st->msgOut, &len)),
                 rc, HIFHE_SUCCESS, st->n, opts, "%s Decode",
                 BenchPresetName(opts->presetId));
    return rc;
}

static int32_t BgvEncrypt(void *ctx, const BenchExecOptions *opts)
{
    BgvState *st = (BgvState *)ctx;
    uint32_t len;
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN_VA((len = st->ctCap,
                  CRYPT_BGV_Encrypt(st->hifhe, st->pt, st->ptLen, st->out, &len)),
                 rc, HIFHE_SUCCESS, st->n, opts, "%s Encrypt",
                 BenchPresetName(opts->presetId));
    return rc;
}

static int32_t BgvDecrypt(void *ctx, const BenchExecOptions *opts)
{
    BgvState *st = (BgvState *)ctx;
    uint32_t len;
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN_VA((len = st->ptCap,
                  CRYPT_BGV_Decrypt(st->hifhe, st->ct, st->ctLen, st->ptOut, &len)),
                 rc, HIFHE_SUCCESS, st->n, opts, "%s Decrypt",
                 BenchPresetName(opts->presetId));
    return rc;
}

static int32_t BgvAddCtCt(void *ctx, const BenchExecOptions *opts)
{
    BgvState *st = (BgvState *)ctx;
    BSL_Param in[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, st->ct, st->ctLen, 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, st->ct, st->ctLen, 0},
        BSL_PARAM_END
    };
    uint32_t len;
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN_VA((len = st->ctCap, CRYPT_BGV_HEAdd(st->hifhe, in, st->out, &len)),
                 rc, HIFHE_SUCCESS, st->n, opts, "%s AddCtCt",
                 BenchPresetName(opts->presetId));
    return rc;
}

static int32_t BgvAddCtPt(void *ctx, const BenchExecOptions *opts)
{
    BgvState *st = (BgvState *)ctx;
    BSL_Param in[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, st->ct, st->ctLen, 0},
        {HIFHE_PARAM_BGV_PLAINTEXT,   BSL_PARAM_TYPE_OCTETS, st->pt, st->ptLen, 0},
        BSL_PARAM_END
    };
    uint32_t len;
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN_VA((len = st->ctCap, CRYPT_BGV_HEAdd(st->hifhe, in, st->out, &len)),
                 rc, HIFHE_SUCCESS, st->n, opts, "%s AddCtPt",
                 BenchPresetName(opts->presetId));
    return rc;
}

static int32_t BgvMulCtPt(void *ctx, const BenchExecOptions *opts)
{
    BgvState *st = (BgvState *)ctx;
    BSL_Param in[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, st->ct, st->ctLen, 0},
        {HIFHE_PARAM_BGV_PLAINTEXT,   BSL_PARAM_TYPE_OCTETS, st->pt, st->ptLen, 0},
        BSL_PARAM_END
    };
    uint32_t len;
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN_VA((len = st->ctCap, CRYPT_BGV_HEMul(st->hifhe, in, st->out, &len)),
                 rc, HIFHE_SUCCESS, st->n, opts, "%s MulCtPt",
                 BenchPresetName(opts->presetId));
    return rc;
}

static int32_t BgvMulCtCt(void *ctx, const BenchExecOptions *opts)
{
    BgvState *st = (BgvState *)ctx;
    BSL_Param in[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, st->ct, st->ctLen, 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, st->ct, st->ctLen, 0},
        BSL_PARAM_END
    };
    uint32_t cap = st->bigCap, len;
    int32_t rc = HIFHE_SUCCESS;
    /* With a relin key installed HEMul relinearizes before returning, so this
     * row covers the product plus a key switch. */
    BENCH_RUN_VA((len = cap, CRYPT_BGV_HEMul(st->hifhe, in, st->out, &len)),
                 rc, HIFHE_SUCCESS, st->n, opts, "%s MulCtCt%s",
                 BenchPresetName(opts->presetId), st->haveRelin ? "(+relin)" : "");
    return rc;
}

static int32_t BgvRelinearize(void *ctx, const BenchExecOptions *opts)
{
    BgvState *st = (BgvState *)ctx;
    char header[128];
    snprintf(header, sizeof(header), "%s Relinearize", BenchPresetName(opts->presetId));
    if (!st->haveRelin || st->ct3Len == 0u) {
        SkipRow(header, st->n, "no relin key");
        return HIFHE_SUCCESS;
    }
    BSL_Param in[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, st->ct3, st->ct3Len, 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, st->out, st->ctCap,  0},
        BSL_PARAM_END
    };
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN(CRYPT_BGV_Ctrl(st->hifhe, HIFHE_CTRL_BGV_HE_RELINEARIZE, in, 0u),
              rc, HIFHE_SUCCESS, st->n, opts, header);
    return rc;
}

static int32_t BgvRotate(void *ctx, const BenchExecOptions *opts)
{
    BgvState *st = (BgvState *)ctx;
    char header[128];
    snprintf(header, sizeof(header), "%s Rotate(step 1)", BenchPresetName(opts->presetId));
    if (!st->haveGalois) {
        SkipRow(header, st->n, "no galois key");
        return HIFHE_SUCCESS;
    }
    int32_t step = 1;
    BSL_Param in[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1,  BSL_PARAM_TYPE_OCTETS, st->ct,  st->ctLen, 0},
        {HIFHE_PARAM_BGV_ROTATE_STEPS, BSL_PARAM_TYPE_INT32,  &step, (uint32_t)sizeof(step), 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2,  BSL_PARAM_TYPE_OCTETS, st->out, st->ctCap, 0},
        BSL_PARAM_END
    };
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN(CRYPT_BGV_Ctrl(st->hifhe, HIFHE_CTRL_BGV_HE_ROTATE_STEP, in, 0u),
              rc, HIFHE_SUCCESS, st->n, opts, header);
    return rc;
}

static int32_t BgvModSwitch(void *ctx, const BenchExecOptions *opts)
{
    BgvState *st = (BgvState *)ctx;
    char header[128];
    snprintf(header, sizeof(header), "%s ModSwitch", BenchPresetName(opts->presetId));
    if (st->level < 2u) {
        SkipRow(header, st->n, "single-limb chain");
        return HIFHE_SUCCESS;
    }
    BSL_Param in[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, st->ct,  st->ctLen, 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, st->out, st->ctCap, 0},
        BSL_PARAM_END
    };
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN(CRYPT_BGV_Ctrl(st->hifhe, HIFHE_CTRL_BGV_HE_MODSWITCH, in, 0u),
              rc, HIFHE_SUCCESS, st->n, opts, header);
    return rc;
}

static int32_t BgvRerandomize(void *ctx, const BenchExecOptions *opts)
{
    BgvState *st = (BgvState *)ctx;
    BSL_Param in[] = {
        {HIFHE_PARAM_BGV_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, st->ct,  st->ctLen, 0},
        {HIFHE_PARAM_BGV_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, st->out, st->ctCap, 0},
        BSL_PARAM_END
    };
    int32_t rc = HIFHE_SUCCESS;
    BENCH_RUN_VA(CRYPT_BGV_Ctrl(st->hifhe, HIFHE_CTRL_BGV_HE_RERANDOMIZE, in, 0u),
                 rc, HIFHE_SUCCESS, st->n, opts, "%s Rerandomize",
                 BenchPresetName(opts->presetId));
    return rc;
}

/* Context creation on its own. With a filled cache this is what a caller pays
 * to open a context. */
static int32_t BgvCtxBuild(void *ctx, const BenchExecOptions *opts)
{
    BgvState *st = (BgvState *)ctx;
    int32_t rc = HIFHE_SUCCESS;
    int32_t id = opts->presetId;
    BENCH_RUN_VA(BgvBenchBuildAndDrop(id), rc, HIFHE_SUCCESS, st->n, opts,
                 "%s CtxCreate+Free", BenchPresetName(opts->presetId));
    return rc;
}

int32_t BgvBenchBuildAndDrop(int32_t presetId)
{
    CRYPT_BGV_Ctx *c = (CRYPT_BGV_Ctx *)CRYPT_BGV_NewCtxWithCache(HIFHE_PKEY_BGV, &g_lutCache);
    if (c == NULL) return HIFHE_MEMORY_ERROR;
    int32_t id = presetId;
    int32_t r = CRYPT_BGV_Ctrl(c, CRYPT_CTRL_SET_PARA_BY_ID, &id, sizeof(id));
    if (r == HIFHE_SUCCESS) {
        /* SetPara only records the preset. Asking for a wire length forces
         * Bgv_BuildContext, which is the work being measured.
         * GET_POLY_DEGREE would answer from the parameter cache instead. */
        uint32_t len = 0u;
        r = CRYPT_BGV_Ctrl(c, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &len, sizeof(len));
    }
    CRYPT_BGV_FreeCtx(c);
    return r;
}

DEFINE_HIFHE_OPS(Bgv,
    DEFINE_OPER(HIFHE_BENCH_CTXBUILD,  BgvCtxBuild),
    DEFINE_OPER(HIFHE_BENCH_KEYGEN,    BgvKeyGen),
    DEFINE_OPER(HIFHE_BENCH_ENCODE,    BgvEncode),
    DEFINE_OPER(HIFHE_BENCH_DECODE,    BgvDecode),
    DEFINE_OPER(HIFHE_BENCH_ENCRYPT,   BgvEncrypt),
    DEFINE_OPER(HIFHE_BENCH_DECRYPT,   BgvDecrypt),
    DEFINE_OPER(HIFHE_BENCH_ADD,       BgvAddCtCt),
    DEFINE_OPER(HIFHE_BENCH_ADD,       BgvAddCtPt),
    DEFINE_OPER(HIFHE_BENCH_MUL,       BgvMulCtPt),
    DEFINE_OPER(HIFHE_BENCH_MUL,       BgvMulCtCt),
    DEFINE_OPER(HIFHE_BENCH_RELIN,     BgvRelinearize),
    DEFINE_OPER(HIFHE_BENCH_ROTATE,    BgvRotate),
    DEFINE_OPER(HIFHE_BENCH_MODSWITCH, BgvModSwitch),
    DEFINE_OPER(HIFHE_BENCH_RERAND,    BgvRerandomize));

DEFINE_BENCH_CTX_TIMES(Bgv, g_benchPresets, SIZEOF(g_benchPresets), 200u);
