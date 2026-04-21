# Third-Party License Summary

This repository is not single-license at the file level.

- Repository-owned files marked with `SPDX-License-Identifier: Apache-2.0` are
  covered by the Apache License 2.0 in [LICENSE](./LICENSE).
- Third-party `pppd`-derived files under
  [`src/plugins/pppoeclient/pppox/pppd/`](./src/plugins/pppoeclient/pppox/pppd/) retain their upstream
  license notices.
- The controlling license terms for those files are the SPDX identifiers and
  header notices in each source file.

## `src/plugins/pppoeclient/pppox/pppd/` SPDX Summary

| SPDX identifier | Files |
| --- | --- |
| `Apache-2.0` | `ppp_stubs.c`, `sys-vpp.c`, `sys-vpp.h` |
| `BSD-4.3TAHOE` | `slcompress.h`, `vjcompress.h` |
| `BSD-Attribution-HPND-disclaimer` | `fsm.c`, `fsm.h`, `if_ppp.h`, `ipcp.c`, `ipcp.h`, `ipv6cp.c`, `ipv6cp.h`, `lcp.c`, `lcp.h`, `magic.c`, `magic.h`, `options.c`, `pathnames.h`, `pppd.h`, `upap.c`, `upap.h` |
| `Mackerras-3-Clause` | `ecp.h` |
| `Mackerras-3-Clause-acknowledgment` | `ccp.c`, `ccp.h`, `chap-md5.c`, `chap-md5.h`, `chap-new.c`, `chap-new.h`, `utils.c` |
| `Mackerras-3-Clause AND Mackerras-3-Clause-acknowledgment` | `ecp.c`, `ppp-comp.h`, `pppio.h`, `ppp_defs.h` |
| `Mackerras-3-Clause-acknowledgment AND BSD-Attribution-HPND-disclaimer` | `auth.c` |
| `RSA-MD` | `md5.c`, `md5.h` |
| `Sun-PPP` | `eap.h` |

## Practical Interpretation

- The top-level repository is distributed primarily under Apache License 2.0
  for repository-owned code.
- The `pppd` subtree is a collection of adapted third-party files with mixed
  upstream licenses.
- If you redistribute this repository or package binaries produced from it,
  keep both [LICENSE](./LICENSE) and this file, and preserve the original file
  headers in `src/plugins/pppoeclient/pppox/pppd/`.
