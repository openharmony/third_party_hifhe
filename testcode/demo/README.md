# HiFHE demos

Two leaked-string demos using public headers only.
Build with BGV enabled. The Provider demo also requires HITLS_PROVIDER and a shared
library; it is omitted when Provider support is disabled.

| Source | Executable | FHE calls |
|---|---|---|
| hifhe_bgv_provider_demo.c | hifhe_bgv_provider_demo | openHiTLS EAL through the HiFHE Provider |
| hifhe_bgv_demo.c | hifhe_bgv_demo | Native HIFHE_* object APIs |

```sh
bash testcode/script/build_hifhe.sh
bash testcode/script/build_demo.sh
./testcode/output/demo/hifhe_bgv_provider_demo
./testcode/output/demo/hifhe_bgv_demo
ctest --test-dir testcode/demo/build --output-on-failure
```

The Provider executable loads libhifhe.so. HIFHE_PROVIDER_PATH overrides its
load directory; the default is the repository build directory. The native
executable links libhifhe directly and does not load a Provider. Neither uses
the internal test module. Both also build with BUILD_DEMO=ON under testcode.

Both use N=4096, t=65537, slots=4096, and mulDepth=0. A generates a key pair;
B generates and imports no keys. A encodes and encrypts once per query:

```text
A: SHA3-256(secret)[0..7] -> four 16-bit fields -> Encode -> Encrypt -> B
B: Encode(bucket) -> bucket-query -> multiply by nonzero masks -> add noise -> A
A: Decrypt -> Decode -> find the entry whose four fields are zero
```

The Provider version uses SetParaById, HEMsgEncode, Encrypt, HEAdd, HEMul,
Ctrl, Decrypt, and HEMsgDecode. NEGATE and the bucket plaintext share one HEAdd.
Buffer capacities come from length queries; the host DRBG uses system entropy.
It checks that B has no private key.

The native version uses SetParaById and HEText objects. Ctrl
sets the query's negation flag; one Add computes bucket-query. Serialize and
Deserialize explicitly transfer the request and response as bytes.

Both exit successfully only when hunter2 matches index 7 and the absent
query produces no match. Provider initialization and buffer allocation occur before
the query loop.

The public API omits custom parameters, key import/export, and ciphertext/ciphertext
multiplication. Both demos use the 4096 preset with ciphertext multiplication depth zero.

Both demos initialize openHiTLS before creating FHE contexts. Algorithm kernels
use their existing random interfaces; no service pointers are injected.

Provider / native interoperability is covered by the [Provider SDV tests](../README.md).
