# HiFHE Security Policy

Canonical URL: https://gitcode.com/openHiTLS/HiFHE/blob/main/SECURITY.md

Adapted from the [openHiTLS security policy](https://gitcode.com/openHiTLS/openhitls/blob/main/SECURITY.md).

This document defines HiFHE's security scope and side-channel requirements.
For vulnerability reporting, severity assessment, and coordinated disclosure,
see the openHiTLS [vulnerability management page](https://www.openhitls.net/zh/support/vulnerability-management.html).

A Chinese translation is available in [SECURITY_zh.md](SECURITY_zh.md).
If the versions differ, this English version is authoritative.

## 1. Scope

### 1.1 Components in scope

This policy covers all production code shipped in this repository, including:

- Provider registration, dispatch, and lifecycle management in `src/provider/`.
- BGV parameters, key generation, encoding, encryption, decryption,
  serialization, and polynomial arithmetic in `src/bgv/`.
- Public interfaces in `include/`.
- Build configuration that affects the delivered libraries.

Future production modules are also in scope. Defects confined to openHiTLS or
other dependencies belong to their upstream projects; HiFHE integration defects
remain in scope.

### 1.2 Candidate vulnerabilities

- Memory corruption, out-of-bounds access, use-after-free, uninitialized reads,
  or crashes reachable through attacker-controlled input.
- Key generation, randomness, sampling, or arithmetic flaws that weaken
  confidentiality or violate the intended cryptographic behavior.
- Invalid parameters, malformed keys or ciphertexts, integer overflow, or
  inconsistent lengths that bypass validation or corrupt internal state.
- Unintended disclosure of private keys, plaintext, or secret intermediate data,
  including through context duplication, cleanup, or serialization.
- Attacker-triggered denial of service caused by parsing or validation defects.
- Side channels affecting secret data, as described in section 2.

Reports should identify the affected revision, build options, input path,
reproduction steps, and security impact.

### 1.3 API usage

API calls must follow preconditions explicitly documented in public headers or
API documentation. Failures caused solely by violating those preconditions are
API misuse; malformed-input handling defects reached through otherwise valid
calls remain in scope.

## 2. Side-channel requirements

These requirements apply to cryptographic paths handling sensitive data,
including sampling, big-number and polynomial arithmetic, encoding, encryption,
and decryption, and HiFHE's use of dependency APIs.

- **Secret-independent control flow:** branch conditions, loop bounds, and
  early exits must not depend on sensitive values.
- **Secret-independent memory access:** addresses, array indices, and table
  lookups must not expose sensitive values.
- **Constant-time comparison:** comparisons of secret-derived buffers must not
  stop at the first mismatching byte.
- **Observable timing:** exploitable timing leakage visible to a remote attacker
  is in scope on common GCC/Clang builds at `-O2` or `-Os`, and on the default
  CMake Release build (`-O3` with the current GCC configuration). Direct timing
  observation that the platform cannot reasonably mitigate is also in scope;
  this does not extend to the physical emission measurements in section 2.2.

Execution time may depend on public parameters such as polynomial degree,
modulus size, and slot count. Timing differences caused solely by public inputs
are not secret leakage. A value derived from a secret is not public merely
because an internal routine uses it as a length, index, or branch condition.

### 2.1 Review criteria

- Avoid secret-dependent branches, loop bounds, memory addresses, and lookups
  that expose sensitive data.
- Use constant-time comparison when comparing secret-derived buffers.
- Assess timing leakage across sampling, big-number arithmetic, encoding,
  encryption, and decryption, including calls into dependencies.
- Treat exploitable remote timing leakage as a candidate vulnerability.
  Assess the actual build, including the default CMake Release configuration;
  an optimization flag alone does not exclude a report.

### 2.2 Limits of assurance

This policy does not certify resistance to co-resident microarchitectural
attacks, physical observation, fault injection, or hardware defects. Such
reports require assessment of both HiFHE and the deployment platform; this
limitation does not establish that a reported software defect is safe.

## 3. Policy versioning

The version on this repository's `main` branch is authoritative. Changes to
scope or side-channel requirements must be reflected in both language versions.
