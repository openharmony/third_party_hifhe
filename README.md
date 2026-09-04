# HiFHE

HiFHE is a homomorphic-encryption provider library for openHiTLS. It currently
provides CKKS.

## Features

- openHiTLS provider discovery, contexts, and lifecycle management.
- CKKS parameters, key generation, key import/export, encoding, encryption, and
  decryption.
- Shared, static, algorithm-trimmed, ASan, and coverage builds.
- Generated tests based on the openHiTLS SDV framework.

CKKS provides approximate homomorphic arithmetic over real and complex values.

## Build

Requirements: CMake 3.16 or newer, a C11 compiler, and openHiTLS. The helper
script clones and builds openHiTLS when `--hitls_dir` is omitted. By default it
builds both `libhifhe_provider.so` and `libhifhe_provider.a`.

```sh
bash testcode/script/build_hifhe.sh
```

Use an existing openHiTLS checkout:

```sh
bash testcode/script/build_hifhe.sh --hitls_dir /path/to/openHiTLS
# This workspace:
bash testcode/script/build_hifhe.sh --hitls_dir /usr1/cq/openhitls/openhitls
```

Build one library type:

```sh
bash testcode/script/build_hifhe.sh shared
bash testcode/script/build_hifhe.sh static
```

Use CMake directly with an already-built openHiTLS checkout:

```sh
cmake -S . -B build \
    -DHITLS_ROOT_PATH=/path/to/openHiTLS \
    -DHITLS_LIB_DIR=/path/to/openHiTLS/build \
    -DHIFHE_BUILD_SHARED=ON \
    -DHIFHE_BUILD_STATIC=ON \
    -DHIFHE_CKKS=ON \
    -DHIFHE_ENABLE_ASAN=OFF \
    -DHIFHE_ENABLE_GCOV=OFF
cmake --build build --parallel
```

CMake options:

| Variable | Default | Description |
| --- | --- | --- |
| `HITLS_ROOT_PATH` | `platform/openhitls` | openHiTLS source directory |
| `HITLS_LIB_DIR` | `${HITLS_ROOT_PATH}/build` | `hitls_crypto` and `hitls_bsl` directory |
| `HIFHE_BUILD_SHARED` | `ON` | Build `libhifhe_provider.so` |
| `HIFHE_BUILD_STATIC` | `ON` | Build `libhifhe_provider.a` |
| `HIFHE_CKKS` | `ON` | Compile CKKS into the provider |
| `HIFHE_ENABLE_ASAN` | `OFF` | Enable AddressSanitizer |
| `HIFHE_ENABLE_GCOV` | `OFF` | Enable coverage |

At least one library type must be enabled. Trim CKKS with either interface:

```sh
bash testcode/script/build_hifhe.sh --enable ckks
bash testcode/script/build_hifhe.sh --disable ckks
```

`HIFHE_CKKS=OFF` excludes all CKKS sources and records the result in the
generated `build/include/hifhe_config.h`.

Install with `cmake --install build --prefix /path/to/prefix`.

## Test

Build:

```sh
bash testcode/script/build_sdv.sh
```

Tests require the shared provider. Select one suite with:

```sh
bash testcode/script/build_sdv.sh run-tests=test_suite_sdv_hifhe_ckks
```

Run:

```sh
bash testcode/script/execute_sdv.sh
```
