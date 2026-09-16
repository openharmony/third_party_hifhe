# HiFHE

HiFHE 是面向 openHiTLS 的同态加密 provider 密码库。目前提供 CKKS 算法。

## 功能

### 1. 公共能力

- 对接 openHiTLS provider，提供算法注册、查询及 provider 生命周期管理。
- 提供已编译算法能力查询接口 `HIFHE_GetFeatures`。
- 支持动态库、静态库、算法裁剪、ASan 和覆盖率构建。
- 提供基于 openHiTLS SDV 框架的生成式测试。

### 2. 当前支持的算法与能力

当前支持 CKKS：

- 参数配置、算法上下文创建、复制和释放。
- 密钥生成、公私钥导入导出。
- 复数向量编码与解码、公钥加密和私钥解密。
- 通过 openHiTLS provider 调用密钥管理和加解密接口。

尚未提供密文同态加法、乘法、旋转、重缩放及自举接口。

## 构建

依赖 CMake 3.16 或更高版本、C11 编译器和 openHiTLS。不传
`--hitls_dir` 时，脚本会下载并编译 openHiTLS。默认同时生成
`libhifhe_provider.so` 和 `libhifhe_provider.a`。

```sh
bash testcode/script/build_hifhe.sh
```

使用已有 openHiTLS：

```sh
bash testcode/script/build_hifhe.sh --hitls_dir /path/to/openHiTLS
# 当前工作区：
bash testcode/script/build_hifhe.sh --hitls_dir /usr1/cq/openhitls/openhitls
```

只生成一种库：

```sh
bash testcode/script/build_hifhe.sh shared
bash testcode/script/build_hifhe.sh static
```

使用已编译的 openHiTLS 直接执行 CMake：

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

CMake 配置：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `HITLS_ROOT_PATH` | `platform/openhitls` | openHiTLS 源码目录 |
| `HITLS_LIB_DIR` | `${HITLS_ROOT_PATH}/build` | `hitls_crypto`、`hitls_bsl` 库目录 |
| `HIFHE_BUILD_SHARED` | `ON` | 生成 `libhifhe_provider.so` |
| `HIFHE_BUILD_STATIC` | `ON` | 生成 `libhifhe_provider.a` |
| `HIFHE_CKKS` | `ON` | 将 CKKS 编译进 provider |
| `HIFHE_ENABLE_ASAN` | `OFF` | 启用 AddressSanitizer |
| `HIFHE_ENABLE_GCOV` | `OFF` | 启用覆盖率 |

至少启用一种库类型。两种 CKKS 裁剪方式：

```sh
bash testcode/script/build_hifhe.sh --enable ckks
bash testcode/script/build_hifhe.sh --disable ckks
```

`HIFHE_CKKS=OFF` 会排除全部 CKKS 源码，并将结果写入生成的
`build/include/hifhe_config.h`。

安装命令：`cmake --install build --prefix /path/to/prefix`。

## 测试

编译：

```sh
bash testcode/script/build_sdv.sh
```

用例依赖动态 provider。只编译一个套件：

```sh
bash testcode/script/build_sdv.sh run-tests=test_suite_sdv_hifhe_ckks
```

运行：

```sh
bash testcode/script/execute_sdv.sh
```
