# HiFHE tests

Tests use the openHiTLS generated SDV framework ported from PQCP.

Each suite has matching `.c` and `.data` files under `sdv/`.
Feature-dependent cases query the loaded provider and skip at runtime.

```sh
bash testcode/script/build_sdv.sh
bash testcode/script/build_sdv.sh run-tests=test_suite_sdv_hifhe_ckks
bash testcode/script/execute_sdv.sh
```
