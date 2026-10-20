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
 * Benchmark harness modelled on testcode/benchmark in openHiTLS. A module
 * registers a CtxOps (setUp, tearDown and a list of Operations). The driver
 * walks the registry and prints one CSV row per measurement.
 *
 * Two things differ from the upstream harness:
 *   - No payload-length sweep. A BGV message is always polyDegree slots, so
 *     the size dimension is the parameter set rather than a byte count. The
 *     slots column reports polyDegree.
 *   - Operation ids are HiFHE's own. The upstream KEY_GEN / ENC / SIGN set does
 *     not describe encode, relinearize or mod-switch.
 */

#ifndef HIFHE_BENCHMARK_H
#define HIFHE_BENCHMARK_H

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "hifhe_err.h"

static inline uint64_t BenchNowNs(void)
{
    struct timespec now = {0};
#if defined(CLOCK_MONOTONIC)
    const clockid_t clockId = CLOCK_MONOTONIC;
#else
    const clockid_t clockId = CLOCK_REALTIME;
#endif
    if (clock_gettime(clockId, &now) != 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static inline double BenchOpsPerSec(uint64_t count, uint64_t elapsedNs)
{
    if (elapsedNs == 0u) {
        return 0.0;
    }
    return ((double)count * 1000000000.0) / (double)elapsedNs;
}

static inline double BenchUsPerOp(uint64_t count, uint64_t elapsedNs)
{
    if (count == 0u) {
        return 0.0;
    }
    return (double)elapsedNs / (double)count / 1000.0;
}

/* Run func a fixed number of times. rc must equal ok on every iteration. The
 * first failure stops the loop and reports. */
#define BENCH_TIMES(func, rc, ok, slots, times, header)                                  \
    {                                                                                    \
        uint32_t benchTimes = (uint32_t)(times);                                         \
        uint64_t start = BenchNowNs();                                                   \
        for (uint32_t i = 0; i < benchTimes; i++) {                                      \
            rc = func;                                                                   \
            if (rc != ok) {                                                              \
                printf("Error: %s, ret = %08x\n", #func, rc);                            \
                break;                                                                   \
            }                                                                            \
        }                                                                                \
        uint64_t elapsed = BenchNowNs() - start;                                         \
        printf("%-38s, %8d, %12u, %14.2f, %14.3f, %14.2f\n", header, (int)(slots),       \
               benchTimes, (double)elapsed / 1000000.0,                                  \
               BenchUsPerOp(benchTimes, elapsed), BenchOpsPerSec(benchTimes, elapsed));  \
    }

/* Run func until the accumulated time reaches secs. */
#define BENCH_SECONDS(func, rc, ok, slots, secs, header)                                 \
    {                                                                                    \
        uint64_t totalTime = (uint64_t)(secs) * 1000000000ULL;                           \
        uint64_t elapsed = 0u;                                                           \
        uint64_t cnt = 0u;                                                               \
        while (elapsed < totalTime) {                                                    \
            uint64_t start = BenchNowNs();                                               \
            rc = func;                                                                   \
            elapsed += BenchNowNs() - start;                                             \
            if (rc != ok) {                                                              \
                printf("Error: %s, ret = %08x\n", #func, rc);                            \
                break;                                                                   \
            }                                                                            \
            cnt++;                                                                       \
        }                                                                                \
        printf("%-38s, %8d, %12" PRIu64 ", %14.2f, %14.3f, %14.2f\n", header,            \
               (int)(slots), cnt, (double)elapsed / 1000000.0,                           \
               BenchUsPerOp(cnt, elapsed), BenchOpsPerSec(cnt, elapsed));                \
    }

#define BENCH_RUN(func, rc, ok, slots, opts, header)                        \
    do {                                                                    \
        if ((opts)->seconds != 0u) {                                        \
            BENCH_SECONDS(func, rc, ok, slots, (opts)->seconds, header);    \
        } else {                                                            \
            BENCH_TIMES(func, rc, ok, slots, (opts)->times, header);        \
        }                                                                   \
    } while (0)

#define BENCH_RUN_VA(func, rc, ok, slots, opts, headerFmt, ...)     \
    do {                                                            \
        char header[128] = {0};                                     \
        snprintf(header, sizeof(header), headerFmt, ##__VA_ARGS__); \
        BENCH_RUN(func, rc, ok, slots, opts, header);               \
    } while (0)

#define SIZEOF(a) (sizeof(a) / sizeof((a)[0]))

/* Operation count from a compound literal, so a module lists its operations
 * once instead of once for the count and once for the table. */
#define COUNT_OPS(...) (sizeof((Operation[]){__VA_ARGS__}) / sizeof(Operation))

/* ---- operation ids ----
 * A bitmask so -a Bgv-Encrypt can select a single operation. */
#define HIFHE_BENCH_KEYGEN     0x00000001u
#define HIFHE_BENCH_ENCODE     0x00000002u
#define HIFHE_BENCH_DECODE     0x00000004u
#define HIFHE_BENCH_ENCRYPT    0x00000008u
#define HIFHE_BENCH_DECRYPT    0x00000010u
#define HIFHE_BENCH_ADD        0x00000020u
#define HIFHE_BENCH_MUL        0x00000040u
#define HIFHE_BENCH_RELIN      0x00000080u
#define HIFHE_BENCH_ROTATE     0x00000100u
#define HIFHE_BENCH_MODSWITCH  0x00000200u
#define HIFHE_BENCH_NTT        0x00000400u
#define HIFHE_BENCH_INTT       0x00000800u
#define HIFHE_BENCH_TABLE      0x00001000u
#define HIFHE_BENCH_ARITH      0x00002000u
#define HIFHE_BENCH_CTXBUILD   0x00004000u
#define HIFHE_BENCH_RERAND     0x00008000u
#define HIFHE_BENCH_ALL        0xffffffffu

typedef struct Operation_ Operation;
typedef struct CtxOps_ CtxOps;
typedef struct BenchCtx_ BenchCtx;

typedef struct {
    uint32_t times;
    uint32_t seconds;
    int32_t  presetId;
} BenchExecOptions;

/* A module owns whatever state its operations need. The driver only passes
 * the pointer around. setUp receives the preset so it can size that state. */
typedef int32_t (*BenchSetUp)(void **ctx, int32_t presetId);
typedef void    (*BenchTearDown)(void *ctx);
typedef int32_t (*BenchOpFn)(void *ctx, const BenchExecOptions *opts);

struct Operation_ {
    uint32_t    id;
    const char *name;   /* "<Module><Op>", matched against -a <Module>-<Op> */
    BenchOpFn   oper;
};

struct CtxOps_ {
    int32_t       opsNum;
    BenchSetUp    setUp;
    BenchTearDown tearDown;
    Operation     ops[];
};

struct BenchCtx_ {
    const char    *name;
    const CtxOps  *ctxOps;
    const int32_t *presetIds;
    uint32_t       presetIdsNum;
    uint32_t       times;
    uint32_t       seconds;
};

#define DEFINE_OPER(id, oper) {id, #oper, oper}

/* Variadic, unlike the upstream fixed KEY_GEN/ENC/DEC/SIGN/VERIFY sets. HiFHE
 * modules do not share one operation vocabulary. */
#define DEFINE_HIFHE_OPS(alg, ...)                       \
    enum { alg##_OPS_NUM = COUNT_OPS(__VA_ARGS__) };   \
    static const CtxOps alg##CtxOps = {                \
        .opsNum   = alg##_OPS_NUM,                     \
        .setUp    = alg##SetUp,                        \
        .tearDown = alg##TearDown,                     \
        .ops      = {__VA_ARGS__},                     \
    }

#define DEFINE_BENCH_CTX_TIMES(alg, pIds, pIdsNum, ts) \
    static const BenchCtx g_##alg##BenchCtx = {        \
        .name         = #alg,                          \
        .ctxOps       = &alg##CtxOps,                  \
        .presetIds    = pIds,                          \
        .presetIdsNum = pIdsNum,                       \
        .times        = ts,                            \
        .seconds      = 0u,                            \
    };                                                 \
    const BenchCtx *BenchmarkGet##alg(void)            \
    {                                                  \
        return &g_##alg##BenchCtx;                     \
    }

/* Provided by the driver. */
bool        MatchAlgorithm(const char *pattern, const char *name);
const char *BenchPresetName(int32_t presetId);

#endif /* HIFHE_BENCHMARK_H */
