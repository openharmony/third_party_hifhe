# HiFHE benchmark

Timing and footprint harness for the BGV provider, built along the lines of
`platform/openhitls/testcode/benchmark`: a module registers a `CtxOps`
(`setUp` / `tearDown` / a list of `Operation`s), the driver walks the registry
and prints one CSV row per measurement.

Two things differ from the upstream harness, because HiFHE does not have the
shape it assumes:

- **No payload-length sweep.** A BGV message is always `polyDegree` slots, so
  the size dimension is the parameter set, not a byte count. The `slots`
  column reports `polyDegree`.
- **HiFHE's own operation ids.** The upstream `KEY_GEN` / `ENC` / `SIGN` set does
  not describe encode, relinearize or mod-switch.

## Building

Needs `build/libhifhe_provider.so`, so run `build_hifhe.sh` first.

```sh
bash testcode/script/build_benchmark.sh          # build
bash testcode/script/build_benchmark.sh asan     # build with AddressSanitizer
bash testcode/script/build_benchmark.sh run      # build, then run everything
bash testcode/script/build_benchmark.sh clean
bash testcode/script/build_benchmark.sh --disable bgv   # trim a module set out
```

This configures `testcode/benchmark` standalone and takes a couple of seconds,
which is what you want between edits. The binary lands in `testcode/output/`.

Each module belongs to an algorithm and calls it directly, so it is built only
when that algorithm is in the provider. The switches follow
`build/include/hifhe_config.h` by default and can be forced either way, as
CMake options (`-DHIFHE_BGV=OFF`, `-DHIFHE_CKKS=ON`) or through the script
(`--enable`/`--disable ckks|bgv`), matching `build_hifhe.sh`. Selecting
nothing is a configuration error rather than an empty binary: there would be
nothing to measure. `Kernel` and `Bgv` are both BGV modules; CKKS has none
yet, so `-DHIFHE_CKKS=ON` alone selects nothing.

It also builds as part of the SDV tree with `-DBUILD_BENCHMARK=ON`, but that
path pays for the test-suite generation and compiles the suites at `-O0`. The
benchmark target forces `-O2` on itself either way — a benchmark at `-O0`
measures the compiler, not the library.

## Running

```sh
bash testcode/script/execute_benchmark.sh    # every module, every preset

Arguments pass straight through, so the binary can also be driven directly:

cd testcode/output
./hifhe_benchmark                       # every module, every preset
./hifhe_benchmark -a Kernel             # one module
./hifhe_benchmark -a Bgv-Encrypt        # one operation
./hifhe_benchmark -a *NttForward        # one operation across modules
./hifhe_benchmark -p bgv-2048-48-17bit  # one preset
./hifhe_benchmark -s 3                  # 3 seconds per row instead of a fixed count
./hifhe_benchmark -m                    # memory footprint report
./hifhe_benchmark -h
```

The benchmark modules call `CRYPT_BGV_*` directly rather than through the EAL
dispatch, so no provider registration is needed. `-P <dir>` (or
`HIFHE_PROVIDER_PATH`, default `../../build`) is still honoured for the
footprint report, which does go through the EAL.

## Modules

Both live in `bgv_bench.c`.

**`Kernel`** — the transforms and the modular arithmetic under them, with
serialization and key management out of the picture. This is the view to
optimise against: the public-API numbers move only as far as these do.

`NttForward` / `NttInverse` run under the first ciphertext modulus,
`PlainNttForward` / `PlainNttInverse` under the plaintext modulus,
`TableBuild` is the twiddle-table cost for one modulus, and `MulDot` / `Add`
are the pointwise operations that make up a ciphertext product.

`Add` is the useful control: it is the same loop shape as `MulDot` with no
modular reduction in it, so the gap between the two is what reduction costs.

The transforms run in place with no reset between iterations. A forward NTT's
output is a valid forward NTT input — every element stays below q — so
repeating it does identical work, and the timing is not diluted by a memcpy
the library would never perform.

**`Bgv`** — what a caller going through `CRYPT_BGV_*` pays. Every figure
includes the wire encoding on both ends, because that surface takes and
returns serialized buffers. For the cheap operations that overhead is most of
the number, which is worth knowing.

Contexts are created with `CRYPT_BGV_NewCtxWithCache` against one handle held for
the whole run, so the NTT tables are computed once and every later `setUp`
reads them. That keeps table construction out of the per-operation rows — a
row should measure the operation, not the ring it runs in — and it is how a
caller that opens and closes contexts is meant to work. `CtxCreate+Free` is
the row the cache exists to move: it is a full context build with the tables
already in hand.

The handle is released by `BgvBenchReleaseCache` when the driver exits.

`MulCtCt` is labelled `(+relin)` when a relin key is installed, because
`CRYPT_BGV_HEMul` relinearizes before returning in that case. `Relinearize`
measures the standalone ctrl on a size-3 ciphertext captured before the relin
key was generated — once the key exists, a size-3 ciphertext can no longer be
obtained through the public API.

Rows that do not apply are skipped rather than failed: `ModSwitch` on a
single-limb chain, `Rotate` without Galois keys.

## Footprint report

`-m` prints per-preset byte counts: the context's twiddle tables (the dominant
allocation), the slot map, and the wire sizes of a plaintext, a ciphertext and
a public key.

Relin and Galois key sizes are absent because `HIFHE_CTRL_BGV_GET_RELIN_KEY_LEN` and
`HIFHE_CTRL_BGV_GET_GALOIS_KEYS_LEN` are stubs that always report 0. Reporting a
hardcoded zero as if it were a measurement would be worse than leaving the
columns out; fill them in when those ctrls are implemented.

## Adding a module

Define its operations with `DEFINE_HIFHE_OPS` and its parameter list with
`DEFINE_BENCH_CTX_TIMES`, then add `X(<Name>)` to the algorithm's list in
`benchmark_registry.h`.

A module belongs in its algorithm's file, so another BGV module goes in
`bgv_bench.c` alongside `Kernel` and `Bgv`. A new algorithm gets its own
`<alg>_bench.c`, listed in `CMakeLists.txt` under that algorithm's switch.
