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

#ifndef HIFHE_BENCHMARK_REGISTRY_H
#define HIFHE_BENCHMARK_REGISTRY_H


typedef struct BenchCtx_ BenchCtx;

/* Add a module to the list for its algorithm, and put it in that algorithm's
 * benchmark file; CMake selects the file by the same switch.
 *
 * A module calls its algorithm directly, so one built out of the provider
 * must not be named here either: the reference would not link. The list
 * below is empty when BGV is off. */
#ifdef HIFHE_ENABLE_BGV
#ifdef HITLS_PROVIDER
#define BENCHMARK_LIST_BGV(X) \
    X(Kernel)                 \
    X(Bgv)
#else
#define BENCHMARK_LIST_BGV(X) X(Kernel)
#endif
#else
#define BENCHMARK_LIST_BGV(X)
#endif

#define BENCHMARK_LIST(X) BENCHMARK_LIST_BGV(X)

#define DECLARE_BENCH_GETTER(name) const BenchCtx *BenchmarkGet##name(void);

BENCHMARK_LIST(DECLARE_BENCH_GETTER)

#undef DECLARE_BENCH_GETTER

#endif /* HIFHE_BENCHMARK_REGISTRY_H */
