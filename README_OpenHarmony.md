# HiFHE
本仓库包含开源软件HiFHE，为OpenHarmony提供面向openHiTLS的同态加密provider密码库。

## 概述

HiFHE是面向openHiTLS的同态加密provider库，对接openHiTLS provider机制，提供算法注册、查询及provider生命周期管理。HiFHE当前支持CKKS和BGV两种同态加密算法，支持动态库、静态库、算法裁剪、ASan和覆盖率等多种构建方式。

## 特性简介

功能特性主要包含如下：

- 公共能力：对接openHiTLS provider，提供算法注册、查询及provider生命周期管理；提供已编译算法能力查询接口HIFHE_GetFeatures；支持动态库、静态库、算法裁剪、ASan和覆盖率构建；提供基于openHiTLS SDV框架的生成式测试。
- CKKS算法：支持参数配置、算法上下文创建/复制/释放、密钥生成与公私钥导入导出、复数向量编码与解码、公钥加密和私钥解密，可通过openHiTLS provider调用密钥管理和加解密接口。
- BGV算法：支持参数配置、算法上下文创建/复制/释放、密钥生成与公私钥导入导出、整数向量批编码与解码、公钥加密和私钥解密，以及密文同态加乘、重线性化、模切换、旋转和重随机化。

## 构建指导

适配OpenHarmony平台的编译脚本请见[gn构建脚本](BUILD.gn)。


以rk3568平台为例，编译命令为：
```bash
./build.sh --product-name rk3568 --ccache --build-target hifhe
```
编译完成后会在out/rk3568/thirdparty/hifhe目录下生成所有的动态库。

## OpenHarmony如何使用hifhe

OpenHarmony中系统部件需要在BUILD.gn中引用hifhe部件以使用hifhe。
 
```
// BUILD.gn
external_deps += [ "hifhe:hifhe" ]
```

## License

Mulan PSL v2

见[LICENSE](LICENSE).
