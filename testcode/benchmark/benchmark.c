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

/* Benchmark driver. Parses options, initialises the DRBG and walks the
 * registry. */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hifhe_types.h"
#include "hifhe_provider.h"
#include "hifhe_err.h"
#include "kernel/ntt.h"

#include "crypt_eal_init.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "bsl_sal.h"

#include "benchmark.h"
#include "benchmark_registry.h"

/* Defined in bgv_bench.c. Releases the shared table handle at shutdown. */
void BgvBenchReleaseCache(void);

enum {
    BENCHMARK_COUNT =
#define COUNT_BENCH(name) +1
        0 BENCHMARK_LIST(COUNT_BENCH)
#undef COUNT_BENCH
};

static const BenchCtx *g_benchs[BENCHMARK_COUNT];
static uint32_t g_benchFailureCount = 0u;

static void InitBenchRegistry(void)
{
    size_t index = 0;
#define REGISTER_BENCH(name) g_benchs[index++] = BenchmarkGet##name();
    BENCHMARK_LIST(REGISTER_BENCH)
#undef REGISTER_BENCH
}

typedef struct {
    const char *s;
    int32_t     id;
} StrIdMap;

static const StrIdMap g_presetMap[] = {
    {"bgv-default",         HIFHE_BGV_DEFAULT},
    {"bgv-2048-48",         HIFHE_BGV_2048_48},
    {"bgv-2048-48-17bit",   HIFHE_BGV_2048_48_17BIT},
    {"bgv-4096-44x2-17bit", HIFHE_BGV_4096_44x2_17BIT},
    {"bgv-8192-44x4",       HIFHE_BGV_8192_44x4},
    {"bgv-8192-44x4-17bit", HIFHE_BGV_8192_44x4_17BIT},
};

const char *BenchPresetName(int32_t presetId)
{
    for (size_t i = 0; i < SIZEOF(g_presetMap); i++) {
        if (g_presetMap[i].id == presetId) {
            return g_presetMap[i].s;
        }
    }
    return "unknown";
}

static int32_t PresetStr2Id(const char *str)
{
    for (size_t i = 0; i < SIZEOF(g_presetMap); i++) {
        if (strcasecmp(g_presetMap[i].s, str) == 0) {
            return g_presetMap[i].id;
        }
    }
    return -1;
}

typedef struct {
    const char *algorithm;
    const char *providerPath;
    uint32_t    times;
    uint32_t    seconds;
    int32_t     presetId;
    bool        footprint;
} BenchOptions;

static void PrintUsage(void)
{
    printf("Usage: hifhe_benchmark [options]\n");
    printf("Options:\n");
    printf("  -a <pattern>   Module or module-operation to run, e.g. Bgv, Kernel*,\n");
    printf("                 Bgv-Encrypt, *Ntt. Default: all.\n");
    printf("  -t <times>     Iterations per measurement (overrides the module default)\n");
    printf("  -s <seconds>   Run each measurement for this long instead of a fixed count\n");
    printf("  -p <preset>    Parameter set to run. Default: every preset the module lists.\n");
    printf("  -P <path>      Directory holding libhifhe_provider.so (default ../../build,\n");
    printf("                 or $HIFHE_PROVIDER_PATH)\n");
    printf("  -m             Print the memory footprint report and exit\n");
    printf("  -h             This message\n");
    printf("\nPresets:");
    for (size_t i = 0; i < SIZEOF(g_presetMap); i++) {
        printf("%s %s", (i == 0u) ? "" : ",", g_presetMap[i].s);
    }
    printf("\n");
}

static void ParseOptions(int argc, char **argv, BenchOptions *opts)
{
    int c;
    while ((c = getopt(argc, argv, "a:t:s:p:P:mh")) != -1) {
        switch (c) {
            case 'a':
                opts->algorithm = optarg;
                break;
            case 't':
                opts->times = (uint32_t)atoi(optarg);
                break;
            case 's':
                opts->seconds = (uint32_t)atoi(optarg);
                break;
            case 'p':
                opts->presetId = PresetStr2Id(optarg);
                if (opts->presetId == -1) {
                    printf("Unknown preset: %s\n", optarg);
                    exit(1);
                }
                break;
            case 'P':
                opts->providerPath = optarg;
                break;
            case 'm':
                opts->footprint = true;
                break;
            case 'h':
                PrintUsage();
                exit(0);
            default:
                PrintUsage();
                exit(1);
        }
    }
}

/* "Bgv" matches the module. "Bgv-Encrypt" also selects one operation. A
 * leading or trailing '*' wildcards that end. */
bool MatchAlgorithm(const char *pattern, const char *name)
{
    if (pattern == NULL) {
        return true;
    }
    size_t nameLen = strlen(name);

    /* Operation-only selector such as "*-Encrypt" or "*Ntt". Every module is
     * a candidate and MatchOperation does the filtering. */
    if (pattern[0] == '*') {
        return true;
    }

    const char *hyphen = strchr(pattern, '-');
    size_t headLen = (hyphen != NULL) ? (size_t)(hyphen - pattern) : strlen(pattern);

    if (headLen > 0u && pattern[headLen - 1u] == '*') {
        headLen--;
        return (nameLen >= headLen) && (strncasecmp(name, pattern, headLen) == 0);
    }
    return (headLen == nameLen) && (strncasecmp(name, pattern, headLen) == 0);
}

/* Returns the mask of operations the pattern selects within one module. */
static uint32_t MatchOperation(const char *pattern, const BenchCtx *bench)
{
    const CtxOps *ctxOps = bench->ctxOps;
    size_t nameLen = strlen(bench->name);
    const char *wanted = NULL;

    if (pattern != NULL) {
        const char *hyphen = strchr(pattern, '-');
        if (hyphen != NULL) {
            wanted = hyphen + 1;
        } else if (pattern[0] == '*' && pattern[1] != '\0') {
            wanted = pattern + 1;
        }
    }
    if (wanted == NULL || *wanted == '\0') {
        return HIFHE_BENCH_ALL;
    }

    uint32_t mask = 0u;
    for (int32_t i = 0; i < ctxOps->opsNum; i++) {
        const Operation *op = &ctxOps->ops[i];
        /* op->name is "<Module><Op>". Compare past the module prefix. */
        const char *opPart = (strlen(op->name) > nameLen) ? (op->name + nameLen) : op->name;
        if (strcasecmp(opPart, wanted) == 0) {
            mask |= op->id;
        }
    }
    return mask;
}

static void RunBenchCase(const CtxOps *ctxOps, const Operation *op,
                         const BenchExecOptions *execOpts)
{
    void *ctx = NULL;
    int32_t ret = ctxOps->setUp(&ctx, execOpts->presetId);
    if (ret != HIFHE_SUCCESS) {
        printf("Failed to set up %s (%s): %08x\n", op->name,
               BenchPresetName(execOpts->presetId), ret);
        g_benchFailureCount++;
        return;
    }
    ret = op->oper(ctx, execOpts);
    if (ret != HIFHE_SUCCESS) {
        printf("Failed to run %s: %08x\n", op->name, ret);
        g_benchFailureCount++;
    }
    ctxOps->tearDown(ctx);
}

/* ---------------- memory footprint ---------------- */

static void FootprintOne(int32_t presetId)
{
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(
        NULL, HIFHE_PKEY_BGV, CRYPT_EAL_PKEY_CIPHER_OPERATE, HIFHE_PROVIDER_ATTR);
    if (ctx == NULL) {
        printf("%-22s  <context creation failed>\n", BenchPresetName(presetId));
        return;
    }
    int32_t id = presetId;
    uint32_t n = 0u, level = 0u, pkLen = 0u, skLen = 0u, ctLen = 0u, ptLen = 0u;
    if (CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &id, sizeof(id)) != HIFHE_SUCCESS
        || CRYPT_EAL_PkeyGen(ctx) != HIFHE_SUCCESS) {
        printf("%-22s  <keygen failed>\n", BenchPresetName(presetId));
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return;
    }
    (void)CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE, &n, sizeof(n));
    (void)CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_LEVEL, &level, sizeof(level));
    (void)CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PUBKEY_LEN, &pkLen, sizeof(pkLen));
    (void)CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PRVKEY_LEN, &skLen, sizeof(skLen));
    (void)CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen));
    (void)CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, &ptLen, sizeof(ptLen));

    /* Twiddle tables are the context's dominant allocation. One block per
     * ciphertext modulus plus one for plainMod, each
     * HIFHE_NTT_TABLE_WORDS(polyDegree) uint64 covering forward and inverse
     * twiddles and their Shoup quotients. The slot map is uint32[polyDegree]
     * and exists only after a slot-mapped encode has run. */
    uint64_t block     = (uint64_t)HIFHE_NTT_TABLE_WORDS(n) * sizeof(uint64_t);
    uint64_t cipherTbl = block * level;
    uint64_t plainTbl  = block;
    uint64_t slotMap   = (uint64_t)n * sizeof(uint32_t);

    printf("%-22s %6u %6u %10" PRIu64 " %10" PRIu64 " %8" PRIu64 " %10" PRIu64
           " %9u %9u %9u\n",
           BenchPresetName(presetId), n, level,
           cipherTbl, plainTbl, slotMap, cipherTbl + plainTbl + slotMap,
           ptLen, ctLen, pkLen);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}

static void FootprintReport(int32_t only)
{
    printf("Memory footprint, bytes. The table columns are the context's own\n");
    printf("working set; plaintext / ciphertext / pubkey are wire sizes.\n");
    printf("Relin and Galois key sizes are absent because\n");
    printf("HIFHE_CTRL_BGV_GET_RELIN_KEY_LEN and HIFHE_CTRL_BGV_GET_GALOIS_KEYS_LEN are\n");
    printf("stubs that always report 0.\n\n");
    printf("%-22s %6s %6s %10s %10s %8s %10s %9s %9s %9s\n",
           "preset", "N", "limbs", "cipherTbl", "plainTbl", "slotMap",
           "tableTotal", "plaintext", "cipher", "pubkey");
    for (size_t i = 0; i < SIZEOF(g_presetMap); i++) {
        if (only != -1 && g_presetMap[i].id != only) {
            continue;
        }
        FootprintOne(g_presetMap[i].id);
    }
}

/* ---------------- main ---------------- */

static int32_t BenchmarkInit(const char *providerPath)
{
    int32_t ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_PROVIDER);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_EAL_ProviderSetLoadPath(NULL, providerPath);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to set provider path '%s': %08x\n", providerPath, ret);
        return ret;
    }
    ret = CRYPT_EAL_ProviderLoad(NULL, BSL_SAL_LIB_FMT_LIBSO, "hifhe_provider", NULL, NULL);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to load hifhe_provider from '%s': %08x\n", providerPath, ret);
    }
    return ret;
}

int main(int argc, char **argv)
{
    BenchOptions opts = {
        .algorithm    = NULL,
        .providerPath = NULL,
        .times        = 0u,
        .seconds      = 0u,
        .presetId     = -1,
        .footprint    = false,
    };
    ParseOptions(argc, argv, &opts);

    if (opts.providerPath == NULL) {
        const char *env = getenv("HIFHE_PROVIDER_PATH");
        opts.providerPath = (env != NULL) ? env : "../../build";
    }
    if (BenchmarkInit(opts.providerPath) != CRYPT_SUCCESS) {
        return 1;
    }

    if (opts.footprint) {
        FootprintReport(opts.presetId);
        CRYPT_EAL_RandDeinitEx(NULL);
        return 0;
    }


    InitBenchRegistry();
    printf("%-38s, %8s, %12s, %14s, %14s, %14s\n",
           "module operation", "slots", "run times", "elapsed(ms)", "us/op", "ops/s");

    bool hasMatch = false;
    for (size_t i = 0; i < SIZEOF(g_benchs); i++) {
        const BenchCtx *bench = g_benchs[i];
        if (!MatchAlgorithm(opts.algorithm, bench->name)) {
            continue;
        }
        uint32_t opMask = MatchOperation(opts.algorithm, bench);
        if (opMask == 0u) {
            continue;
        }
        hasMatch = true;

        BenchExecOptions execOpts = {
            .times    = (opts.times != 0u) ? opts.times : bench->times,
            .seconds  = (opts.seconds != 0u) ? opts.seconds : bench->seconds,
            .presetId = 0,
        };

        for (int32_t j = 0; j < bench->ctxOps->opsNum; j++) {
            const Operation *op = &bench->ctxOps->ops[j];
            if ((op->id & opMask) == 0u) {
                continue;
            }
            if (opts.presetId != -1) {
                execOpts.presetId = opts.presetId;
                RunBenchCase(bench->ctxOps, op, &execOpts);
                continue;
            }
            for (uint32_t k = 0; k < bench->presetIdsNum; k++) {
                execOpts.presetId = bench->presetIds[k];
                RunBenchCase(bench->ctxOps, op, &execOpts);
            }
        }
    }

    BgvBenchReleaseCache();
    CRYPT_EAL_RandDeinitEx(NULL);
    if (!hasMatch) {
        printf("No benchmark matched: %s\n",
               (opts.algorithm != NULL) ? opts.algorithm : "*");
        return 1;
    }
    return (g_benchFailureCount != 0u) ? 1 : 0;
}
