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
 * Negacyclic NTT over Z_q[x]/(x^N+1).
 *
 *   roots[k]    = psi^brv(k, log2 N)
 *   invRoots[k] = psi^-brv(k, log2 N)
 *
 * Elementwise operations are index-agnostic, so the bit-reversed layout needs
 * no shuffles.
 *
 * Butterfly twiddles are fixed for the whole transform, so each is stored with
 * its Shoup quotient floor(w * 2^64 / q) and the modular reduction becomes two
 * multiplications and a subtraction. Coefficients stay in [0, 4q) between
 * layers and are reduced in one closing pass. Both require q < 2^62;
 * Kernel_Prime_FindProth caps bits at 62.
 */

#include "kernel/ntt.h"
#include "kernel/modulus.h"
#include "kernel/prime.h"

static uint32_t BitReverse(uint32_t x, uint32_t bits)
{
    uint32_t r = 0u;
    for (uint32_t i = 0; i < bits; ++i) {
        r = (r << 1) | (x & 1u);
        x >>= 1;
    }
    return r;
}

static uint64_t MulMod(uint64_t a, uint64_t b, Modulus q)
{
    return (uint64_t)(((ModulusWide)a * (ModulusWide)b) % (ModulusWide)q);
}

static uint64_t PowMod(uint64_t base, uint64_t exp, Modulus q)
{
    uint64_t r = 1u % q;
    base %= q;
    while (exp > 0u) {
        if (exp & 1u) r = MulMod(r, base, q);
        base = MulMod(base, base, q);
        exp >>= 1;
    }
    return r;
}

/* Modular inverse via Fermat's little theorem (q prime). */
static uint64_t InvMod(uint64_t a, Modulus q)
{
    return PowMod(a, q - 2u, q);
}

/* Shoup quotient floor(w * 2^64 / q) for a fixed multiplier w < q. */
static uint64_t ShoupQuot(uint64_t w, Modulus q)
{
    return (uint64_t)((((ModulusWide)w) << 64) / (ModulusWide)q);
}

/* Returns w * x mod q in [0, 2q). Requires w < q < 2^62. x may be any
 * uint64. */
static inline uint64_t ShoupMulLazy(uint64_t x, uint64_t w, uint64_t wq, uint64_t q)
{
    uint64_t hi = (uint64_t)(((ModulusWide)x * (ModulusWide)wq) >> 64);
    return x * w - hi * q;
}

static HIFHE_ERROR FillStruct(NttTables *tbl, const uint64_t *buf,
                            Modulus q, uint32_t polyDegree)
{
    uint32_t logN = 0u;
    for (uint32_t v = polyDegree; v > 1u; v >>= 1) logN++;

    const uint64_t *scalars = buf + 4u * (size_t)polyDegree;
    tbl->q            = q;
    tbl->polyDegree   = polyDegree;
    tbl->logN         = logN;
    tbl->roots        = buf;
    tbl->invRoots     = buf + polyDegree;
    tbl->rootsQuot    = buf + 2u * (size_t)polyDegree;
    tbl->invRootsQuot = buf + 3u * (size_t)polyDegree;
    tbl->nInvModQ     = scalars[0];
    tbl->nInvQuot     = scalars[1];
    return Kernel_BarrettConst_Init(&tbl->barrett, q);
}

HIFHE_ERROR Kernel_Ntt_AttachTables(NttTables *tbl, const uint64_t *buf,
                                  Modulus q, uint32_t polyDegree)
{
    if (tbl == NULL || buf == NULL) return HIFHE_NULL_INPUT;
    if (polyDegree == 0u || (polyDegree & (polyDegree - 1u)) != 0u) {
        return HIFHE_PARAM_INVALID;
    }
    return FillStruct(tbl, buf, q, polyDegree);
}

HIFHE_ERROR Kernel_Ntt_BuildTables(NttTables *tbl, uint64_t *buf,
                                 Modulus q, uint32_t polyDegree)
{
    if (tbl == NULL || buf == NULL) return HIFHE_NULL_INPUT;
    if (polyDegree == 0u || (polyDegree & (polyDegree - 1u)) != 0u) {
        return HIFHE_PARAM_INVALID;
    }
    uint32_t logN = 0u;
    for (uint32_t v = polyDegree; v > 1u; v >>= 1) logN++;

    uint64_t psi = 0u;
    int32_t ret = Kernel_Prime_PrimitiveRoot2N(&psi, q, polyDegree);
    if (ret != HIFHE_SUCCESS) return ret;
    uint64_t psiInv = InvMod(psi, q);

    uint64_t *roots        = buf;
    uint64_t *invRoots     = buf + polyDegree;
    uint64_t *rootsQuot    = buf + 2u * (size_t)polyDegree;
    uint64_t *invRootsQuot = buf + 3u * (size_t)polyDegree;
    uint64_t *scalars      = buf + 4u * (size_t)polyDegree;

    /* Build psi^j by repeated multiplication, then permute. One
     * exponentiation per entry would cost a log N factor more. The ascending
     * powers are staged in the quotient arrays and overwritten below. */
    uint64_t *pow = rootsQuot;
    uint64_t *powInv = invRootsQuot;
    pow[0] = 1u % q;
    powInv[0] = 1u % q;
    for (uint32_t j = 1; j < polyDegree; ++j) {
        pow[j] = MulMod(pow[j - 1u], psi, q);
        powInv[j] = MulMod(powInv[j - 1u], psiInv, q);
    }
    for (uint32_t k = 0; k < polyDegree; ++k) {
        uint32_t r = BitReverse(k, logN);
        roots[k] = pow[r];
        invRoots[k] = powInv[r];
    }
    for (uint32_t k = 0; k < polyDegree; ++k) {
        rootsQuot[k] = ShoupQuot(roots[k], q);
        invRootsQuot[k] = ShoupQuot(invRoots[k], q);
    }

    scalars[0] = InvMod((uint64_t)polyDegree, q);
    scalars[1] = ShoupQuot(scalars[0], q);

    return FillStruct(tbl, buf, q, polyDegree);
}

/* Forward negacyclic NTT (DIT, Cooley-Tukey), in place. Input is in standard
 * order below q, output in bit-reversed order below q. Intermediates reach 4q
 * and the closing pass reduces them. */
HIFHE_ERROR Kernel_Ntt_Forward(uint64_t *a, const NttTables *tbl)
{
    if (a == NULL || tbl == NULL) return HIFHE_NULL_INPUT;
    Modulus q = tbl->q;
    uint64_t q2 = q << 1;
    uint32_t N = tbl->polyDegree;
    uint32_t t = N;
    for (uint32_t m = 1; m < N; m <<= 1) {
        t >>= 1;
        for (uint32_t i = 0; i < m; ++i) {
            uint32_t j1 = 2u * i * t;
            uint32_t j2 = j1 + t;
            uint64_t w  = tbl->roots[m + i];
            uint64_t wq = tbl->rootsQuot[m + i];
            for (uint32_t j = j1; j < j2; ++j) {
                uint64_t x = a[j];
                if (x >= q2) x -= q2;
                uint64_t y = ShoupMulLazy(a[j + t], w, wq, q);
                a[j]     = x + y;
                a[j + t] = x - y + q2;
            }
        }
    }
    for (uint32_t j = 0; j < N; ++j) {
        uint64_t v = a[j];
        if (v >= q2) v -= q2;
        if (v >= q)  v -= q;
        a[j] = v;
    }
    return HIFHE_SUCCESS;
}

/* Inverse negacyclic NTT (DIF, Gentleman-Sande), in place. Input is in
 * bit-reversed order below q, output in standard order below q.
 *
 * The N^-1 scaling is applied in the final layer instead of a separate pass
 * over all N coefficients. */
HIFHE_ERROR Kernel_Ntt_Inverse(uint64_t *a, const NttTables *tbl)
{
    if (a == NULL || tbl == NULL) return HIFHE_NULL_INPUT;
    Modulus q = tbl->q;
    uint64_t q2 = q << 1;
    uint32_t N = tbl->polyDegree;
    uint64_t nInv = tbl->nInvModQ, nInvQ = tbl->nInvQuot;

    if (N == 1u) {
        uint64_t v = ShoupMulLazy(a[0], nInv, nInvQ, q);
        a[0] = (v >= q) ? v - q : v;
        return HIFHE_SUCCESS;
    }

    uint32_t t = 1u;
    for (uint32_t m = N; m > 2u; m >>= 1) {
        uint32_t j1 = 0u;
        uint32_t h  = m >> 1;
        for (uint32_t i = 0; i < h; ++i) {
            uint32_t j2 = j1 + t;
            uint64_t w  = tbl->invRoots[h + i];
            uint64_t wq = tbl->invRootsQuot[h + i];
            for (uint32_t j = j1; j < j2; ++j) {
                uint64_t x = a[j], y = a[j + t];
                uint64_t u = x + y;
                if (u >= q2) u -= q2;
                a[j]     = u;
                a[j + t] = ShoupMulLazy(x - y + q2, w, wq, q);
            }
            j1 = j1 + 2u * t;
        }
        t <<= 1;
    }

    /* Last layer: m == 2, so h == 1 and the only twiddle is invRoots[1].
     * Both outputs are scaled by N^-1 here. */
    uint64_t w  = tbl->invRoots[1];
    uint64_t wq = tbl->invRootsQuot[1];
    for (uint32_t j = 0; j < t; ++j) {
        uint64_t x = a[j], y = a[j + t];
        uint64_t u = x + y;
        if (u >= q2) u -= q2;
        uint64_t v = x - y + q2;

        uint64_t ru = ShoupMulLazy(u, nInv, nInvQ, q);
        if (ru >= q) ru -= q;
        uint64_t rv = ShoupMulLazy(v, w, wq, q);
        if (rv >= q) rv -= q;
        rv = ShoupMulLazy(rv, nInv, nInvQ, q);
        if (rv >= q) rv -= q;

        a[j]     = ru;
        a[j + t] = rv;
    }
    return HIFHE_SUCCESS;
}
