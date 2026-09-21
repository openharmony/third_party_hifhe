# HiFHE

HiFHE is a homomorphic-encryption provider library for openHiTLS. It currently
provides CKKS and BGV.

## Features

### 1. Common capabilities

- openHiTLS provider integration, algorithm registration and discovery, and
  provider lifecycle management.
- Compiled algorithm feature queries through `HIFHE_GetFeatures`.
- Shared, static, algorithm-trimmed, ASan, and coverage builds.
- Generated tests based on the openHiTLS SDV framework.

### 2. Currently supported algorithms and capabilities

#### CKKS

- Parameter configuration and algorithm context creation, duplication, and cleanup.
- Key generation and public/private key import/export.
- Complex vector encoding and decoding, public-key encryption, and private-key
  decryption.
- Key management and encryption/decryption through the openHiTLS provider interface.

Interfaces for homomorphic ciphertext addition, multiplication, rotation,
rescaling, and bootstrapping are not yet available.

#### BGV

- Parameter configuration and algorithm context creation, duplication, and cleanup.
- Key generation and public/private key import/export.
- Packed encoding and decoding of integer vectors, public-key encryption, and
  private-key decryption.
- Homomorphic addition and multiplication, relinearization, modulus switching,
  rotation, and rerandomization.

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
    -DHIFHE_BGV=ON \
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
| `HIFHE_BGV` | `ON` | Compile BGV into the provider |
| `HIFHE_ENABLE_ASAN` | `OFF` | Enable AddressSanitizer |
| `HIFHE_ENABLE_GCOV` | `OFF` | Enable coverage |

At least one library type must be enabled. CKKS and BGV can be selected
independently:

```sh
bash testcode/script/build_hifhe.sh --enable ckks
bash testcode/script/build_hifhe.sh --disable ckks
bash testcode/script/build_hifhe.sh --enable bgv
bash testcode/script/build_hifhe.sh --disable bgv
```

`HIFHE_CKKS=OFF` or `HIFHE_BGV=OFF` excludes the corresponding sources and
records the result in the generated `build/include/hifhe_config.h`.

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
