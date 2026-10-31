# HiFHE API 使用说明

本文描述当前实现，覆盖 [导出清单](cmake/hifhe.exports) 中的 17 个原生接口和 1 个 Provider 入口，
以及应用通过 openHiTLS 调用 HiFHE 的方式。声明见
[hifhe.h](include/hifhe.h)、[hifhe_types.h](include/hifhe_types.h)、[hifhe_err.h](include/hifhe_err.h)。

## 1. 接入与通用约束

### 1.1 接口范围

| 接入方式 | 应用持有的数据 | 当前能力 |
| --- | --- | --- |
| 原生 C API | `HIFHE_Ctx *`、`HIFHE_HEText *` | BGV 参数预设、编解码、密钥生成、加解密、加法、密文×明文、取负、加噪、序列化 |
| openHiTLS Provider | `CRYPT_EAL_PkeyCtx *`、字节缓冲区、`BSL_Param` | BGV 同上；启用 CKKS 时还支持复数向量加解密 |

原生接口包含 `hifhe.h` 即可，无需定义 `HITLS_PROVIDER`。Provider 应用还需定义该宏，包含 openHiTLS 头文件，
并使用开启 Provider 特性构建的 `libhifhe.so`。宏只控制声明可见性，不能补齐库中已裁剪的实现。

公共接口不提供公私钥导入导出、密文×密文、重线性化、自举、旋转或自定义算法回调。
`HIFHE_New(HIFHE_CKKS)` 在启用 CKKS 时可创建句柄，但原生接口没有 CKKS 参数配置和复数编解码入口；
CKKS 的完整使用流程走 Provider。

### 1.2 初始化与调用顺序

原生应用先调用 openHiTLS 的
`CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND)`。
它返回 0 才能继续；所有 HiFHE 对象释放后，再用相同选项调用 `CRYPT_EAL_Cleanup`。
Provider 的初始化顺序见第 5 节。两者都是 openHiTLS 接口，不在 HiFHE 导出清单中。

```text
初始化 openHiTLS
  → HIFHE_New
  → 可选：设置 LUT 缓存
  → HIFHE_SetParaById
  → 可选：设置种子
  → HIFHE_KeyGen（需要加解密的一方）
  → Encode → Encrypt → Add / Mul / Ctrl → Decrypt → Decode
  → 释放 HEText、Ctx
  → 清理 openHiTLS
```

同进程计算直接传 `HIFHE_HEText *`。跨进程或网络传输时，发送方 `Serialize`，接收方 `Deserialize`。
接收方先配置相同算法和预设；反序列化不会替它配置上下文，也不会导入密钥。

### 1.3 对象、缓冲区与并发

| 项目 | 约束 |
| --- | --- |
| `HIFHE_Ctx` | 不透明句柄，持有参数和密钥。只能用 `HIFHE_New` 创建、`HIFHE_Free` 释放 |
| `HIFHE_HEText` | 不透明的明文或密文对象。只能由库产生，用 `HIFHE_HETextFree` 释放；不得复制结构体或强转其他库对象 |
| 对象输出 `HIFHE_HEText **out` | `out` 非 NULL，且调用前 `*out == NULL`；成功交付新对象，失败不替换输出指针 |
| 对象输入 | 调用方仍持有对象。除 `SET_NEGATE` 外，下述接口不修改输入对象 |
| 释放顺序 | HEText 不依赖原 Ctx 的存活，可在原 Ctx 释放后单独释放。继续计算时仍需另一个匹配的 Ctx |
| 字节、整数缓冲区 | 调用方分配和释放；库不保留 `Encode`、`Deserialize` 的输入缓冲区 |
| 空指针 | 仅允许各接口明确列出的 NULL；已释放或伪造的非 NULL 指针不属于合法输入 |
| 长度单位 | `Encode/Decode` 的 `count` 是元素数；序列化、Ctrl、Provider 的长度是字节数 |
| 并发 | 同一 Ctx 或可变 HEText 的访问由调用方串行化；接口未承诺同一句柄可并发使用 |

对象计算要求算法和参数指纹一致。处理密文时，若上下文持有密钥，还要求密钥来源一致；
两个密文相加也要求来源一致。无密钥服务端不要另行生成自己的密钥，否则会拒绝客户端密文。
来源标识用于一致性检查，不提供数据来源认证。

BGV 按槽计算，结果为 `结果 mod t`，其中 t 是明文模数。输入槽值应满足 `0 <= value < t`。
少于 N 个输入槽时，其余槽补零；单元素输入只设置第一个槽，不会广播到全部槽。
解码始终返回 N 个槽。接口没有剩余噪声查询或任意计算深度保证；调用成功不等于噪声超限后的结果仍正确。

### 1.4 返回值

除创建、释放和错误查询接口外，成功返回 `HIFHE_SUCCESS`（0），失败返回错误码。
先检查当前调用的返回值，再读取错误栈；成功调用不会清除历史错误。

长度查询分两次调用：第一次传 NULL 输出缓冲区，预期返回 `HIFHE_BUFFER_TOO_SMALL`，并取得所需长度；
分配后第二次传入实际容量。长度查询仍会校验上下文和输入，不能忽略其他错误。

## 2. 上下文、内存与密钥

### 2.1 HIFHE_SetMemFuncs：设置内存分配函数

```c
typedef void *(*HIFHE_MallocFunc)(uint32_t len);
typedef void (*HIFHE_FreeFunc)(void *ptr);

/**
 * @brief 设置 HiFHE 内存分配与释放回调。
 * @param[in] mallocFunc 分配回调；参数为 uint32_t 字节数，分配失败返回 NULL。
 * @param[in] freeFunc 释放回调；与 mallocFunc 同时为 NULL 时恢复 malloc/free。
 * @retval HIFHE_SUCCESS 成功。
 * @retval Other 错误码，参见 hifhe_err.h。
 * @note 两个回调必须成对设置。在创建任何 HiFHE 资源前调用，资源存活期间不得切换。
 */
int32_t HIFHE_SetMemFuncs(HIFHE_MallocFunc mallocFunc, HIFHE_FreeFunc freeFunc);
```

分配回调接收字节数，失败返回 NULL，并应满足普通 `malloc` 的对齐要求。库不会请求零字节或向释放回调传 NULL。

该设置作用于 HiFHE 自身的内存封装，不替换 openHiTLS 内部的分配器。应用自建的缓冲区仍由应用释放。
不要并发更换回调。
当前实现释放时使用全局现有回调，不为每块内存保存原分配器。

调用形式：`HIFHE_SetMemFuncs(AppMalloc, AppFree)`；其中 `AppMalloc` 的参数必须是 `uint32_t`，
不能直接把参数为 `size_t` 的标准 `malloc` 强转后传入。

### 2.2 HIFHE_New：创建上下文

```c
/**
 * @brief 创建指定算法的上下文，初始不含参数和密钥。
 * @param[in] algId 算法 ID，取 HIFHE_ALG_ID 中已启用的算法值。
 * @return 成功返回新上下文，由调用方使用 HIFHE_Free 释放；失败返回 NULL。
 * @note 失败后可立即调用 HIFHE_ErrPeekLastError 查询错误。
 */
HIFHE_Ctx *HIFHE_New(int32_t algId);
```

调用形式：`HIFHE_Ctx *ctx = HIFHE_New(HIFHE_BGV)`，必须检查 `ctx != NULL` 后再使用。

### 2.3 HIFHE_SetParaById：选择 BGV 预设

```c
/**
 * @brief 使用预设配置 BGV 参数，不生成密钥。
 * @param[in,out] ctx 尚未配置参数的 BGV 上下文。
 * @param[in] paramId 预设 ID，取 HIFHE_BGV_PRESET 中的值。
 * @retval HIFHE_SUCCESS 成功。
 * @retval Other 错误码，参见 hifhe_err.h。
 * @note 每个上下文只能成功配置一次；失败可重试，更换参数需新建上下文。
 */
int32_t HIFHE_SetParaById(HIFHE_Ctx *ctx, int32_t paramId);
```

| `paramId` | N / 槽数 | 密文模数配置 | 明文模数 t |
| --- | ---: | --- | --- |
| `HIFHE_BGV_DEFAULT` | 2048 | 固定的 48 位模数 | 按 17 位搜索 |
| `HIFHE_BGV_2048_48` | 2048 | 搜索 1 个 48 位模数 | 按 17 位搜索 |
| `HIFHE_BGV_8192_44x4` | 8192 | 实际位数为 43、43、44、44 | 按 20 位搜索 |
| `HIFHE_BGV_2048_48_17BIT` | 2048 | 1 个 48 位模数 | 65537 |
| `HIFHE_BGV_4096_44x2_17BIT` | 4096 | 2 个 44 位模数 | 65537 |
| `HIFHE_BGV_8192_44x4_17BIT` | 8192 | 实际位数为 43、43、44、44 | 65537 |

预设名不是安全强度或计算深度承诺。当前公共接口没有查询 t 的命令；以下示例使用 t 明确为 65537 的预设。
通信双方使用同一个预设 ID；不要因为 N 或位数相同就认为不同 ID 的序列化数据可以互换。
预设定义见 [params_preset.c](src/bgv/src/bgv/params_preset.c)。

调用形式：`HIFHE_SetParaById(ctx, HIFHE_BGV_4096_44x2_17BIT)`。

### 2.4 HIFHE_KeyGen：生成密钥对

```c
/**
 * @brief 根据上下文参数生成公私钥对，供加解密使用。
 * @param[in,out] ctx 已配置参数、尚未生成密钥的上下文。
 * @retval HIFHE_SUCCESS 成功。
 * @retval Other 错误码，参见 hifhe_err.h。
 * @note 密钥由上下文持有，随 HIFHE_Free 释放；生成失败不替换原状态。
 */
int32_t HIFHE_KeyGen(HIFHE_Ctx *ctx);
```

加密方调用 `HIFHE_KeyGen(ctx)`；只做 Add、Mul、加噪的服务端不需要调用。

### 2.5 HIFHE_Free / HIFHE_HETextFree：释放资源

```c
/**
 * @brief 释放上下文及其参数和密钥。
 * @param[in] ctx 待释放的上下文；NULL 不执行操作。
 * @return 无。
 * @note 不释放独立的 HEText 对象；调用后需自行将 ctx 置为 NULL。
 */
void HIFHE_Free(HIFHE_Ctx *ctx);

/**
 * @brief 释放明文或密文对象及其数据。
 * @param[in] object 待释放的 HEText 对象；NULL 不执行操作。
 * @return 无。
 * @note 可在原上下文释放后调用；调用后需自行将 object 置为 NULL。
 */
void HIFHE_HETextFree(HIFHE_HEText *object);
```

不能使用 `free` 或 `BSL_SAL_Free` 释放这些句柄。

## 3. 编码、计算与传输

以下对象输出均要求调用前 `*out == NULL`；输入对象须满足第 1.3 节的匹配约束。

### 3.1 HIFHE_Encode：整数编码

```c
/**
 * @brief 将 BGV 整数槽值编码为同态运算所需的明文对象。
 * @param[in] ctx 已配置参数的 BGV 上下文，无需密钥。
 * @param[in] values count 个 uint64_t 元素，每个值小于明文模数 t。
 * @param[in] count 输入元素个数，范围为 1 到配置槽数 N。
 * @param[out] out 接收新明文对象；out 非 NULL，且调用前 *out == NULL。
 * @retval HIFHE_SUCCESS 成功。
 * @retval Other 错误码，参见 hifhe_err.h。
 * @note 编码不加密；未提供的槽补零。库不保留 values 缓冲区。
 */
int32_t HIFHE_Encode(const HIFHE_Ctx *ctx, const uint64_t *values, uint32_t count, HIFHE_HEText **out);
```

调用形式：`HIFHE_Encode(ctx, values, count, &plaintext)`。

### 3.2 HIFHE_Encrypt：明文加密

```c
/**
 * @brief 使用上下文中的公钥，将明文对象加密为密文对象。
 * @param[in,out] ctx 已配置参数并生成密钥的上下文。
 * @param[in] plaintext 算法和参数与 ctx 匹配的明文对象。
 * @param[out] ciphertext 接收新密文对象；地址非 NULL，且调用前 *ciphertext == NULL。
 * @retval HIFHE_SUCCESS 成功。
 * @retval Other 错误码，参见 hifhe_err.h。
 * @note 输入明文不变；原始整数需先通过 HIFHE_Encode 转换为明文对象。
 */
int32_t HIFHE_Encrypt(HIFHE_Ctx *ctx, const HIFHE_HEText *plaintext, HIFHE_HEText **ciphertext);
```

调用形式：`HIFHE_Encrypt(ctx, plaintext, &ciphertext)`。

### 3.3 HIFHE_Add：加法与取负

```c
/**
 * @brief 对 BGV 槽值执行加法或带取负标志的减法，结果按明文模数取模。
 * @param[in] ctx 与两个操作数匹配的已配置 BGV 上下文，无需密钥。
 * @param[in] para1 密文对象；设置 SET_NEGATE 后，该操作数按负值参与计算。
 * @param[in] para2 无取负标志的明文或同源密文；仅 para1 已标记取负时允许为 NULL。
 * @param[out] out 接收新密文对象；out 非 NULL，且调用前 *out == NULL。
 * @retval HIFHE_SUCCESS 成功。
 * @retval Other 错误码，参见 hifhe_err.h。
 * @note 输入对象不变；para1 的取负标志保留，输出对象不带取负标志。
 */
int32_t HIFHE_Add(const HIFHE_Ctx *ctx, const HIFHE_HEText *para1, const HIFHE_HEText *para2, HIFHE_HEText **out);
```

逐槽计算规则：

| `para1` 状态 | `para2` | 结果 |
| --- | --- | --- |
| 普通密文 | 明文或密文 | `(para1 + para2) mod t` |
| 已设置 `SET_NEGATE` | 明文或密文 | `(para2 - para1) mod t` |
| 已设置 `SET_NEGATE` | NULL | `(-para1) mod t` |
| 普通密文 | NULL | 不支持 |

没有单独的 Sub/Neg 公共函数。调用形式：先 `HIFHE_Ctrl(ctx, HIFHE_CTRL_BGV_SET_NEGATE, query, NULL, 0)`，
再 `HIFHE_Add(ctx, query, bucketPlaintext, &difference)`，得到 `bucket - query`。

### 3.4 HIFHE_Mul：密文乘明文

```c
/**
 * @brief 将 BGV 密文与明文逐槽相乘，结果按明文模数取模。
 * @param[in] ctx 与两个操作数匹配的已配置 BGV 上下文，无需密钥。
 * @param[in] para1 无取负标志的密文对象，不能为 NULL。
 * @param[in] para2 明文乘数对象，不能为 NULL。
 * @param[out] out 接收新密文对象；out 非 NULL，且调用前 *out == NULL。
 * @retval HIFHE_SUCCESS 成功。
 * @retval Other 错误码，参见 hifhe_err.h。
 * @note 输入对象不变；不支持交换明密文入参或密文乘密文。
 */
int32_t HIFHE_Mul(const HIFHE_Ctx *ctx, const HIFHE_HEText *para1, const HIFHE_HEText *para2, HIFHE_HEText **out);
```

调用形式：先编码明文乘数，再 `HIFHE_Mul(ctx, ciphertext, multiplierPlaintext, &product)`。
若希望全部槽乘以同一数，应编码 N 个相同乘数；只编码一个乘数会使其余槽乘以零。

### 3.5 HIFHE_Decrypt：密文解密

```c
/**
 * @brief 使用私钥将密文解密为明文对象。
 * @param[in,out] ctx 参数匹配且持有该密文对应私钥的上下文。
 * @param[in] ciphertext 无取负标志的密文对象。
 * @param[out] plaintext 接收新明文对象；地址非 NULL，且调用前 *plaintext == NULL。
 * @retval HIFHE_SUCCESS 成功。
 * @retval Other 错误码，参见 hifhe_err.h。
 * @note 输入密文不变；需再调用 HIFHE_Decode 取得整数槽值。
 */
int32_t HIFHE_Decrypt(HIFHE_Ctx *ctx, const HIFHE_HEText *ciphertext, HIFHE_HEText **plaintext);
```

调用形式：`HIFHE_Decrypt(ctx, ciphertext, &plaintext)`。

### 3.6 HIFHE_Decode：明文解码

```c
/**
 * @brief 将 BGV 明文对象还原为全部 N 个整数槽值，输出范围为 [0, t)。
 * @param[in] ctx 与明文匹配的已配置 BGV 上下文，无需密钥。
 * @param[in] plaintext 待解码的明文对象。
 * @param[out] values 调用方提供的 uint64_t 数组；NULL 用于查询所需元素数。
 * @param[in,out] count 非 NULL；输入数组容量，成功或容量不足时输出实际或所需元素数。
 * @retval HIFHE_SUCCESS 成功。
 * @retval Other 错误码，参见 hifhe_err.h。
 * @note values 为 NULL 或容量不足时，返回 HIFHE_BUFFER_TOO_SMALL 并更新 *count。
 *       查询时将 *count 初始化为 0；values 与 count 的存储区不得重叠。
 */
int32_t HIFHE_Decode(const HIFHE_Ctx *ctx, const HIFHE_HEText *plaintext, uint64_t *values, uint32_t *count);
```

输出槽值不会自动解释为有符号整数。长度查询或容量不足时不写数值缓冲区。

调用顺序：`count = 0` → `HIFHE_Decode(ctx, plaintext, NULL, &count)` →
分配 `count * sizeof(uint64_t)` → 再调用 Decode。即使 Encode 只有一个槽，Decode 也需要容纳 N 个槽。

### 3.7 HIFHE_Serialize：对象转字节流

```c
/**
 * @brief 将明文或密文对象转换为可存储、传输的 HiFHE 字节流。
 * @param[in] ctx 与对象匹配的已配置上下文。
 * @param[in] object 无取负标志的明文或密文对象。
 * @param[out] out 调用方提供的字节缓冲区；NULL 用于查询所需字节数。
 * @param[in,out] outLen 非 NULL；输入字节容量，成功或容量不足时输出实际或所需字节数。
 * @retval HIFHE_SUCCESS 成功。
 * @retval Other 错误码，参见 hifhe_err.h。
 * @note out 为 NULL 或容量不足时，返回 HIFHE_BUFFER_TOO_SMALL 并更新 *outLen。
 *       查询时将 *outLen 初始化为 0；out 与 outLen 不得重叠；输入对象不变。
 */
int32_t HIFHE_Serialize(const HIFHE_Ctx *ctx, const HIFHE_HEText *object, uint8_t *out, uint32_t *outLen);
```

长度查询或容量不足时不写输出缓冲区。当前单个序列化对象上限为 64 MiB（含头部）。

调用顺序：`len = 0` → `HIFHE_Serialize(ctx, object, NULL, &len)` → 分配 len 字节 → 再序列化。
序列化明文不会加密；序列化密文不包含公私钥，也不提供完整性认证。

### 3.8 HIFHE_Deserialize：字节流转对象

```c
/**
 * @brief 从一个完整的 HiFHE 字节流创建独立的明文或密文对象。
 * @param[in] ctx 已配置相同算法、预设和参数的上下文；若持有密钥，还须匹配密文来源。
 * @param[in] data 完整的单个序列化对象，不能为 NULL。
 * @param[in] dataLen 有效数据字节数，包含头部，不是缓冲区容量。
 * @param[out] object 接收新对象；地址非 NULL，且调用前 *object == NULL。
 * @retval HIFHE_SUCCESS 成功。
 * @retval Other 错误码，参见 hifhe_err.h。
 * @note 不配置上下文或导入密钥。库不保留 data，成功后可释放输入缓冲区。
 */
int32_t HIFHE_Deserialize(const HIFHE_Ctx *ctx, const uint8_t *data, uint32_t dataLen, HIFHE_HEText **object);
```

一次只能读取一个对象，不能拼接多个对象作为输入。无需密钥即可接收密文，但已有密钥须匹配密文来源。

调用形式：`HIFHE_Deserialize(receiver, wire, wireLen, &received)`。
该格式用于 HiFHE 原生接口和 HiFHE Provider 互通，不能直接读取 SEAL、OpenFHE 的序列化对象。

## 4. HIFHE_Ctrl 命令

```c
/**
 * @brief 执行 BGV 参数控制、长度查询、取负标记或加噪命令。
 * @param[in,out] ctx BGV 上下文；SET_LUT_CACHE 在配置参数前调用，其余命令需已配置参数。
 * @param[in] cmd 命令 ID，取 HIFHE_CMD 中的值。
 * @param[in,out] text SET_NEGATE 或 RERANDOMIZE 使用的密文对象；其他命令传 NULL。
 * @param[in,out] value 命令参数或结果地址；类型由 cmd 决定，SET_NEGATE 传 NULL。
 * @param[in] valueLen value 的字节数，必须与命令要求一致。
 * @retval HIFHE_SUCCESS 成功。
 * @retval Other 错误码，参见 hifhe_err.h。
 * @note 各命令的参数类型、调用时机和输出对象归属见下表。
 */
int32_t HIFHE_Ctrl(HIFHE_Ctx *ctx, int32_t cmd, HIFHE_HEText *text, void *value, uint32_t valueLen);
```

| `cmd` | `text` | `value` / `valueLen` | 前置条件和结果 |
| --- | --- | --- | --- |
| `HIFHE_CTRL_BGV_SET_LUT_CACHE` | NULL | `uint32_t *`，`sizeof(uint32_t)` | 在 SetParaById 前设置，0 关闭、1 开启，默认 0；每个上下文持有自己的表。配置参数后调用返回 `HIFHE_BAD_STATE` |
| `HIFHE_CTRL_BGV_SET_SEED` | NULL | 32 字节种子，32 | 参数已配置，KeyGen 尚未成功；库复制种子。已有密钥返回 `HIFHE_BAD_STATE` |
| `HIFHE_CTRL_BGV_GET_POLY_DEGREE` | NULL | `uint32_t *` 输出，`sizeof(uint32_t)` | 参数已配置；返回 N，也就是槽数，不是安全位数 |
| `HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN` | NULL | `uint32_t *` 输出，`sizeof(uint32_t)` | 参数已配置；返回当前预设完整层级明文的序列化字节数 |
| `HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN` | NULL | `uint32_t *` 输出，`sizeof(uint32_t)` | 参数已配置；返回当前预设新生成的两分量密文的序列化字节数 |
| `HIFHE_CTRL_BGV_SET_NEGATE` | 密文 | NULL，0 | 设置供 Add 使用的取负标志，不立即计算；重复设置不会切换回正数 |
| `HIFHE_CTRL_BGV_RERANDOMIZE` | 无取负标志的密文 | `HIFHE_HEText **`，`sizeof(HIFHE_HEText *)` | 输出指针初值为 NULL；生成加噪后的新密文，无需密钥，原密文不变 |

GET 长度命令不接收对象，不能代替已有对象的精确长度查询；已有对象使用 Serialize 查询。
SET_NEGATE 成功后，该对象只能作为 Add 的 `para1` 或释放；Decrypt、Mul、Serialize、加噪均返回 `HIFHE_BAD_STATE`。
公共接口没有清除标志的命令。Add 的结果不带标志，可以继续乘法、加噪或传输。

RERANDOMIZE 增加噪声，不是自举，不会恢复噪声预算。固定种子用于可复现测试，不应复用于实际业务的密钥生成。
设置种子也不替代 openHiTLS 随机服务初始化；不能据此承诺完整序列化结果逐字节相同。

调用示例（每次调用均应检查 `ret`）：

```c
uint32_t enabled = 1;
ret = HIFHE_Ctrl(ctx, HIFHE_CTRL_BGV_SET_LUT_CACHE, NULL, &enabled, sizeof(enabled)); // 配置参数前
ret = HIFHE_Ctrl(ctx, HIFHE_CTRL_BGV_SET_SEED, NULL, seed, 32); // 配置参数后、生成密钥前
uint32_t n = 0;
ret = HIFHE_Ctrl(ctx, HIFHE_CTRL_BGV_GET_POLY_DEGREE, NULL, &n, sizeof(n));
uint32_t ptLen = 0, ctLen = 0;
ret = HIFHE_Ctrl(ctx, HIFHE_CTRL_BGV_GET_PLAINTEXT_LEN, NULL, &ptLen, sizeof(ptLen));
ret = HIFHE_Ctrl(ctx, HIFHE_CTRL_BGV_GET_CIPHERTEXT_LEN, NULL, &ctLen, sizeof(ctLen));
HIFHE_HEText *noisy = NULL;
ret = HIFHE_Ctrl(ctx, HIFHE_CTRL_BGV_RERANDOMIZE, ciphertext, &noisy, sizeof(noisy));
```

## 5. openHiTLS Provider 接入

以下 `CRYPT_EAL_Pkey*` 函数由 openHiTLS 提供，调用 HiFHE 注册的回调；它们不是额外的 HiFHE 导出符号。
Provider 的长度全部按字节计算，BGV 输入输出明密文采用与原生 Serialize 相同的格式。
`CRYPT_EAL_PkeyCtx *` 与 `HIFHE_Ctx *` 不能强转互用。

### 5.1 加载、配置与释放

按顺序调用，每步检查返回值：

| 步骤 | 调用 | 约束 |
| --- | --- | --- |
| 初始化 | `CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL)` | 在加载 Provider 前执行 |
| 指定目录 | `CRYPT_EAL_ProviderSetLoadPath(NULL, providerDir)` | `providerDir` 是存放 `libhifhe.so` 的目录 |
| 加载 | `CRYPT_EAL_ProviderLoad(NULL, BSL_SAL_LIB_FMT_LIBSO, "hifhe", NULL, NULL)` | 库及其依赖必须可加载 |
| 创建 | `CRYPT_EAL_ProviderPkeyNewCtx(NULL, HIFHE_BGV, CRYPT_EAL_PKEY_CIPHER_OPERATE, HIFHE_PROVIDER_ATTR)` | 返回 NULL 表示失败；属性为 `"provider=hifhe"` |
| 设置预设 | `CRYPT_EAL_PkeySetParaById(ctx, (CRYPT_PKEY_ParaId)HIFHE_BGV_4096_44x2_17BIT)` | 每个 BGV 上下文只成功配置一次 |
| 生成密钥 | `CRYPT_EAL_PkeyGen(ctx)` | 仅加解密方需要，不能重复生成 |
| 复制上下文 | `CRYPT_EAL_PkeyDupCtx(ctx)` | 复制现有参数和密钥状态；返回新句柄或 NULL，新句柄也须单独释放 |
| 释放 | `CRYPT_EAL_PkeyFreeCtx(ctx)` | 先释放所有 Provider 上下文 |
| 卸载 | `CRYPT_EAL_ProviderUnload(NULL, BSL_SAL_LIB_FMT_LIBSO, "hifhe")` | 对象仍在使用时不得卸载 |
| 清理 | `CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL)` | 最后执行 |

Provider 返回值可能来自 HiFHE 或 openHiTLS EAL。未注册的功能可能在 EAL 层直接被拒绝。
`CRYPT_CTRL_GET_BITS` 当前返回不支持，不能用通用 GetKeyBits/GetKeyLen 估算同态密文缓冲区或安全强度。

### 5.2 BGV 参数数组

`BSL_Param` 字段依次为 `key, valueType, value, valueLen, useLen`；输入项 `useLen` 初始化为 0。
每个数组以 `BSL_PARAM_END` 结束。只传表中允许的键，不得重复键；所有实际参数项的 `value` 均须非 NULL。

| EAL 接口 | 输入 `BSL_Param` | 输出 |
| --- | --- | --- |
| `CRYPT_EAL_PkeyHEMsgEncode` | 一项 `HIFHE_PARAM_BGV_MSG`，OCTETS，主机字节序 `uint64_t[count]`，长度 `count * sizeof(uint64_t)` | 序列化明文 |
| `CRYPT_EAL_PkeyHEMsgDecode` | 一项 `HIFHE_PARAM_BGV_PLAINTEXT`，OCTETS，序列化明文 | 主机字节序 N 个 `uint64_t`，所需字节数为 `N * sizeof(uint64_t)` |
| `CRYPT_EAL_PkeyHEAdd` | 必填 `CRYPT_PARAM_PKEY_HE_CIPHERTEXT1`；第二项选择 `CRYPT_PARAM_PKEY_HE_CIPHERTEXT2` 或 `HIFHE_PARAM_BGV_PLAINTEXT`；可选 NEGATE | 序列化密文 |
| `CRYPT_EAL_PkeyHEMul` | `CRYPT_PARAM_PKEY_HE_CIPHERTEXT1` 和 `HIFHE_PARAM_BGV_PLAINTEXT` | 序列化密文 |

加法、乘法的操作数都是 OCTETS 格式的序列化对象。第二个密文和明文不能同时传入。
HEAdd 的 `HIFHE_PARAM_BGV_NEGATE` 是 OCTETS，指向一个值为 1 的 `uint8_t`，长度为 1；
存在该项时计算 `第二操作数 - 第一密文`，省略第二操作数则仅取负。HEMul 不接受 NEGATE。

这些接口统一使用下列签名形式，函数名按表替换：

```c
int32_t CRYPT_EAL_PkeyHEMsgEncode(const CRYPT_EAL_PkeyCtx *ctx, const BSL_Param *input,
    uint8_t *out, uint32_t *outLen);
```

`outLen` 是容量/实际长度，不能为 NULL。传 `out = NULL` 查询长度，预期返回 `HIFHE_BUFFER_TOO_SMALL`；
输入数组、输入对象及上下文仍必须有效。结果缓冲区由应用分配，下一次调用前重新填写容量。

BGV 加解密直接接收序列化字节，不使用 `BSL_Param`：

```c
int32_t CRYPT_EAL_PkeyEncrypt(const CRYPT_EAL_PkeyCtx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen);
int32_t CRYPT_EAL_PkeyDecrypt(const CRYPT_EAL_PkeyCtx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen);
```

Encrypt 的输入是编码后的序列化明文，输出序列化密文；Decrypt 反之。两者都支持 NULL 输出查询长度，
但要求上下文已生成相应密钥。Decrypt 的输出还要经过 HEMsgDecode 才是整数数组。

### 5.3 Provider Ctrl

```c
int32_t CRYPT_EAL_PkeyCtrl(CRYPT_EAL_PkeyCtx *ctx, int32_t cmd, void *args, uint32_t len);
```

LUT、种子、多项式次数和两种长度查询复用第 4 节命令，`args = value`、`len = valueLen`，约束相同。
Provider 不支持通过 SET_NEGATE Ctrl 设置对象标志，取负使用 HEAdd 的 NEGATE 参数。

加噪有独立参数格式，不能照搬原生 `HIFHE_HEText **`：

```c
BSL_Param noise[] = {
    {CRYPT_PARAM_PKEY_HE_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, ciphertext, ciphertextLen, 0},
    {CRYPT_PARAM_PKEY_HE_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, output, capacity, 0},
    BSL_PARAM_END
};
ret = CRYPT_EAL_PkeyCtrl(ctx, HIFHE_CTRL_BGV_RERANDOMIZE, noise, 0);
```

`output` 必须非 NULL。成功后 `noise[1].useLen` 是实际字节数；容量不足时返回 `HIFHE_BUFFER_TOO_SMALL`，
`useLen` 是所需字节数，`valueLen` 不会自动改成新容量。
若要查询现有密文加噪所需大小，可令输出指向一个有效字节、`valueLen = 0`，读取 `useLen` 后分配并重试。
不要传 NULL 输出值；参数解析会将其视为 `HIFHE_NULL_INPUT`。

### 5.4 CKKS Provider

库需启用 `HIFHE_CKKS` 和 `HITLS_PROVIDER`。创建时使用 `HIFHE_CKKS`，通过
`CRYPT_EAL_PkeySetParaEx(ctx, params)` 配置以下五项，均为必填，无省略默认值。
每项类型为 `BSL_PARAM_TYPE_UINT32`、长度为 `sizeof(uint32_t)`，末尾加 `BSL_PARAM_END`。

| 参数键 | 含义和约束 |
| --- | --- |
| `HIFHE_PARAM_CKKS_N` | N 是 4096 到 16384 的 2 的幂 |
| `HIFHE_PARAM_CKKS_Q_BITS` | `30 <= qBits <= 60`，Q 为 `2^qBits` |
| `HIFHE_PARAM_CKKS_P_BITS` | `0 < pBits < qBits`，编码缩放因子为 `2^pBits` |
| `HIFHE_PARAM_CKKS_SIGMA_MILLI` | 固定为 3200，采样标准差为 3.2 |
| `HIFHE_PARAM_CKKS_SLOTS` | 正的 2 的幂，且不大于 `N / 2` |

配置成功后调用 `CRYPT_EAL_PkeyGen`。参数和密钥都不能重复设置。
上述范围是实现的入参限制，不表示所有组合都具有相同安全强度或解密精度。

CKKS 与 BGV 的 Encrypt/Decrypt 数据含义不同：

| 操作 | 输入 | 输出 |
| --- | --- | --- |
| `CRYPT_EAL_PkeyEncrypt` | 主机内存中的 `double complex[count]`，以 `const uint8_t *` 传入，长度为 `count * sizeof(double complex)` | 序列化密文 |
| `CRYPT_EAL_PkeyDecrypt` | 序列化密文 | `slots` 个 `double complex` 的字节表示，不是序列化明文 |

要求 `1 <= count <= slots`；不足的槽补零。实部和虚部均须有限，且缩放后绝对值小于 `2^(qBits - 1)`。
不满足返回 `HIFHE_VALUE_OUT_OF_RANGE`。加解密内部完成复数编解码，解密结果是近似值，应按业务误差容限比较。
当前 CKKS Provider 不注册 HEAdd、HEMul、HEMsgEncode、HEMsgDecode；不支持第 4 节 BGV 命令。
完整调用见 [CKKS Provider 用例](testcode/sdv/ckks/test_suite_sdv_hifhe_ckks_provider.c)。

### 5.5 CRYPT_EAL_ProviderInit：加载器入口

```c
/**
 * @brief 初始化 Provider，向加载器交付算法回调表和 Provider 状态。
 * @param[in] mgrCtx 加载器提供的管理上下文，不能为 NULL。
 * @param[in] param 保留参数，当前忽略，可为 NULL。
 * @param[in] capFuncs 管理回调表，以 id == 0 结束，须提供非空的 CRYPT_EAL_CAP_MGRCTXCTRL 回调。
 * @param[out] outFuncs 非 NULL；接收静态 Provider 回调表，调用方不释放该表。
 * @param[out] provCtx 非 NULL；接收 Provider 状态，由加载器通过 free 回调释放。
 * @retval HIFHE_SUCCESS 成功。
 * @retval Other 错误码，参见 hifhe_err.h。
 * @note 由 Provider 加载器调用，应用通过 ProviderLoad 间接使用。
 */
int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param, CRYPT_EAL_Func *capFuncs,
    CRYPT_EAL_Func **outFuncs, void **provCtx);
```

## 6. 错误查询与错误码

### 6.1 HIFHE_ErrPeekError / HIFHE_ErrPeekLastError

```c
/**
 * @brief 查看当前线程错误栈中最早保留的错误。
 * @param[out] file 接收错误发生的源码文件名；可为 NULL，返回字符串不得修改或释放。
 * @param[out] line 接收错误发生的源码行号；可为 NULL。
 * @retval HIFHE_SUCCESS 错误栈为空。
 * @retval Other 栈中记录的错误码，参见 hifhe_err.h。
 * @note 不弹出错误；栈空时不修改 file 和 line。
 */
int32_t HIFHE_ErrPeekError(const char **file, uint32_t *line);

/**
 * @brief 查看当前线程错误栈中最新记录的错误。
 * @param[out] file 接收错误发生的源码文件名；可为 NULL，返回字符串不得修改或释放。
 * @param[out] line 接收错误发生的源码行号；可为 NULL。
 * @retval HIFHE_SUCCESS 错误栈为空。
 * @retval Other 栈中记录的错误码，参见 hifhe_err.h。
 * @note 不弹出错误；栈空时不修改 file 和 line。应在调用失败后立即查询。
 */
int32_t HIFHE_ErrPeekLastError(const char **file, uint32_t *line);
```

每线程最多保留 `HIFHE_ERR_STACK_DEPTH`（20）条，满后丢弃最早一条；成功调用不清栈，公共接口没有清栈或弹出函数。
NULL 缓冲区长度查询不入栈，真实的小缓冲区失败会入栈。错误栈用于定位，当前调用的返回值用于判断成败。
Provider 在 openHiTLS 层拒绝的调用不一定有 HiFHE 错误记录。

```c
const char *file = NULL;
uint32_t line = 0;
int32_t code = HIFHE_ErrPeekLastError(&file, &line);
if (code != HIFHE_SUCCESS) {
    fprintf(stderr, "HiFHE: 0x%08x at %s:%u\n", (unsigned)code, file, line);
}
```

### 6.2 错误处理表

代码使用枚举常量判断，不依赖其递增数值。下表覆盖公开错误枚举；并非每个错误都能通过当前原生能力触发。

| 错误码 | 含义与处理 |
| --- | --- |
| `HIFHE_SUCCESS` | 成功；错误查询接口中表示栈空 |
| `HIFHE_NOT_SUPPORTED` | 算法、命令或操作未实现或被裁剪 |
| `HIFHE_NULL_INPUT` | 缺少必填指针 |
| `HIFHE_INVALID_ARGUMENT` | 参数组合、取值关系或额外参数不合法 |
| `HIFHE_PARAM_INVALID` | 参数结构不合法，例如分配回调未成对设置、Provider 参数键重复 |
| `HIFHE_PARAM_NOT_SET` | 先设置参数 |
| `HIFHE_PARAM_ID_INVALID` | 预设 ID 不存在 |
| `HIFHE_PARAM_REPEATED_SET` | 当前上下文已配置参数；更换参数应新建上下文 |
| `HIFHE_KEY_NOT_SET` | 加解密缺少所需密钥 |
| `HIFHE_KEY_REPEATED_SET` | 当前上下文已生成密钥 |
| `HIFHE_INVALID_LENGTH` | 元素数、参数长度或序列化长度不合法 |
| `HIFHE_VALUE_OUT_OF_RANGE` | 槽值、标志值或其他数值越界 |
| `HIFHE_BUFFER_TOO_SMALL` | 按返回的所需长度分配或扩容，再调用 |
| `HIFHE_BUFFER_OVERLAP` | 输出缓冲区与长度变量重叠，应分开存储 |
| `HIFHE_OUTPUT_NOT_EMPTY` | 对象输出指针初值非 NULL；先释放旧对象并置空 |
| `HIFHE_TEXT_TYPE_MISMATCH` | 明文、密文类型不符合操作要求 |
| `HIFHE_ALG_MISMATCH` | 对象与上下文算法不一致 |
| `HIFHE_PARAM_MISMATCH` | 参数指纹或序列化预设不一致 |
| `HIFHE_KEY_MISMATCH` | 密文来源与上下文密钥或另一密文不一致 |
| `HIFHE_BAD_STATE` | 当前阶段不允许操作，例如已有密钥后设种子、直接解密带取负标志的对象 |
| `HIFHE_SERDES_FAIL` | 数据格式或内容校验失败 |
| `HIFHE_VERSION_NOT_SUPPORTED` | 序列化版本不受支持 |
| `HIFHE_LIMIT_EXCEEDED` | 超过实现的资源或数据大小上限 |
| `HIFHE_MEMORY_ERROR` | 分配失败 |
| `HIFHE_RANDOM_ERROR` | 随机数服务失败 |
| `HIFHE_HASH_ERROR` | Hash/XOF 操作失败 |
| `HIFHE_DECODE_ERROR` | 算法解码失败 |
| `HIFHE_INTERNAL` | 内部计算或状态异常，应保留返回码和错误位置 |
| `HIFHE_CONTEXT_MISMATCH` | 底层算法上下文不匹配 |
| `HIFHE_CT_DEGREE_MISMATCH` | 底层密文结构或分量配置不匹配 |
| `HIFHE_NO_RELIN_KEY`、`HIFHE_NO_GALOIS_KEY` | 底层操作缺少重线性化或旋转密钥；对应能力未作为当前公共接口开放 |
| `HIFHE_MODSWITCH_EXHAUSTED`、`HIFHE_DEPTH_EXCEEDED` | 底层模数链或深度限制；不是当前公共接口的噪声预算查询机制 |

## 7. 完整原生调用示例

A 只加密一次。B 不生成密钥，通过字节流接收密文，计算 `factor * (bucket - query)` 并加噪；
A 接收结果后解密、解码。前两个槽预期为 10、12，其余为零。
示例中的 `Transfer` 只模拟传输：Serialize 后的字节可以换成网络发送，Deserialize 放在接收端执行。

保存以下代码为 `api_example.c`：

```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "hifhe.h"
#include "crypt_eal_init.h"

static int32_t Transfer(const HIFHE_Ctx *sender, const HIFHE_HEText *text,
    const HIFHE_Ctx *receiver, HIFHE_HEText **out)
{
    uint32_t len = 0;
    int32_t ret = HIFHE_Serialize(sender, text, NULL, &len);
    if (ret != HIFHE_BUFFER_TOO_SMALL) {
        return ret;
    }
    uint8_t *wire = malloc(len);
    if (wire == NULL) {
        return HIFHE_MEMORY_ERROR;
    }
    ret = HIFHE_Serialize(sender, text, wire, &len);
    if (ret == HIFHE_SUCCESS) {
        ret = HIFHE_Deserialize(receiver, wire, len, out);
    }
    free(wire);
    return ret;
}

int main(void)
{
    const uint64_t init = CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_RAND;
    int32_t ret = CRYPT_EAL_Init(init);
    if (ret != HIFHE_SUCCESS) {
        return 1;
    }
    HIFHE_Ctx *a = HIFHE_New(HIFHE_BGV);
    HIFHE_Ctx *b = HIFHE_New(HIFHE_BGV);
    HIFHE_HEText *pt = NULL, *ct = NULL, *received = NULL;
    HIFHE_HEText *bucketPt = NULL, *factorPt = NULL, *difference = NULL;
    HIFHE_HEText *product = NULL, *noisy = NULL, *reply = NULL, *answer = NULL;
    uint64_t *decoded = NULL;
    uint64_t query[] = {3, 7}, bucket[] = {8, 10}, factor[] = {2, 4};
    uint32_t count = 0;
    int status = 1;
    if (a == NULL || b == NULL) {
        ret = HIFHE_ErrPeekLastError(NULL, NULL);
        goto cleanup;
    }
    ret = HIFHE_SetParaById(a, HIFHE_BGV_4096_44x2_17BIT);
    if (ret != HIFHE_SUCCESS) {
        goto cleanup;
    }
    ret = HIFHE_SetParaById(b, HIFHE_BGV_4096_44x2_17BIT);
    if (ret != HIFHE_SUCCESS) {
        goto cleanup;
    }
    ret = HIFHE_KeyGen(a);
    if (ret != HIFHE_SUCCESS) {
        goto cleanup;
    }
    ret = HIFHE_Encode(a, query, 2, &pt);
    if (ret != HIFHE_SUCCESS) {
        goto cleanup;
    }
    ret = HIFHE_Encrypt(a, pt, &ct);
    if (ret != HIFHE_SUCCESS) {
        goto cleanup;
    }
    ret = Transfer(a, ct, b, &received);
    if (ret != HIFHE_SUCCESS) {
        goto cleanup;
    }
    ret = HIFHE_Encode(b, bucket, 2, &bucketPt);
    if (ret != HIFHE_SUCCESS) {
        goto cleanup;
    }
    ret = HIFHE_Encode(b, factor, 2, &factorPt);
    if (ret != HIFHE_SUCCESS) {
        goto cleanup;
    }
    ret = HIFHE_Ctrl(b, HIFHE_CTRL_BGV_SET_NEGATE, received, NULL, 0);
    if (ret != HIFHE_SUCCESS) {
        goto cleanup;
    }
    ret = HIFHE_Add(b, received, bucketPt, &difference);
    if (ret != HIFHE_SUCCESS) {
        goto cleanup;
    }
    ret = HIFHE_Mul(b, difference, factorPt, &product);
    if (ret != HIFHE_SUCCESS) {
        goto cleanup;
    }
    ret = HIFHE_Ctrl(b, HIFHE_CTRL_BGV_RERANDOMIZE, product, &noisy, sizeof(noisy));
    if (ret != HIFHE_SUCCESS) {
        goto cleanup;
    }
    ret = Transfer(b, noisy, a, &reply);
    if (ret != HIFHE_SUCCESS) {
        goto cleanup;
    }
    ret = HIFHE_Decrypt(a, reply, &answer);
    if (ret != HIFHE_SUCCESS) {
        goto cleanup;
    }
    ret = HIFHE_Decode(a, answer, NULL, &count);
    if (ret != HIFHE_BUFFER_TOO_SMALL) {
        goto cleanup;
    }
    decoded = calloc(count, sizeof(*decoded));
    if (decoded == NULL) {
        ret = HIFHE_MEMORY_ERROR;
        goto cleanup;
    }
    ret = HIFHE_Decode(a, answer, decoded, &count);
    if (ret != HIFHE_SUCCESS) {
        goto cleanup;
    }
    if (count != 4096 || decoded[0] != 10 || decoded[1] != 12) {
        fprintf(stderr, "unexpected result\n");
        goto cleanup;
    }
    for (uint32_t i = 2; i < count; i++) {
        if (decoded[i] != 0) {
            fprintf(stderr, "unexpected padding\n");
            goto cleanup;
        }
    }
    puts("OK: 10, 12");
    status = 0;
cleanup:
    if (ret != HIFHE_SUCCESS) {
        fprintf(stderr, "error: 0x%08x\n", (unsigned)ret);
    }
    HIFHE_HETextFree(pt);
    HIFHE_HETextFree(ct);
    HIFHE_HETextFree(received);
    HIFHE_HETextFree(bucketPt);
    HIFHE_HETextFree(factorPt);
    HIFHE_HETextFree(difference);
    HIFHE_HETextFree(product);
    HIFHE_HETextFree(noisy);
    HIFHE_HETextFree(reply);
    HIFHE_HETextFree(answer);
    free(decoded);
    HIFHE_Free(a);
    HIFHE_Free(b);
    CRYPT_EAL_Cleanup(init);
    return status;
}
```

使用本仓库 build 目录和已构建的 openHiTLS 编译，按实际路径修改：

```sh
HIFHE_ROOT=/path/to/HiFHE
HITLS_ROOT=/path/to/openHiTLS
cc -std=c11 -Wall -Wextra -Werror api_example.c \
    -I"$HIFHE_ROOT/include" -I"$HITLS_ROOT/include/crypto" -I"$HITLS_ROOT/include/bsl" \
    -L"$HIFHE_ROOT/build" -L"$HITLS_ROOT/build" \
    -lhifhe -lhitls_crypto -lhitls_bsl -o api_example
LD_LIBRARY_PATH="$HIFHE_ROOT/build:$HITLS_ROOT/build" ./api_example
```

Provider 的完整流程见 [hifhe_bgv_provider_demo.c](testcode/demo/hifhe_bgv_provider_demo.c)。
原生/Provider 字节互通用例见
[test_suite_sdv_hifhe_bgv_provider.c](testcode/sdv/bgv/test_suite_sdv_hifhe_bgv_provider.c)。
