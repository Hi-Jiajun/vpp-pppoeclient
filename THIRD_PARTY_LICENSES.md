# Third-Party License Summary

This repository is **not single-license at the file level**. Mind the branch
layout: the plugin source tree lives on the `master` branch, while `main` holds
the README, the packaging scripts, the CI workflows and these license
documents.

- Repository-owned files carrying `SPDX-License-Identifier: Apache-2.0` (the
  scripts and workflows on `main`, the plugin sources on `master`) are covered
  by the Apache License 2.0 text in [LICENSE](./LICENSE).
- The `master` branch vendors third-party `pppd`-derived sources under
  `pppox/pppd/`. They keep their upstream copyright and license notices, and the
  controlling terms are the SPDX identifiers and header notices in each file.
- When redistributing this repository or the prebuilt plugin packages, keep
  [LICENSE](./LICENSE), [NOTICE](./NOTICE) and this file alongside the
  sources / binaries.

Mixed-license sources (branch `master`):
`https://github.com/Hi-Jiajun/vpp-pppoeclient/tree/master/pppox/pppd`

Upstream working branch:
`https://github.com/Hi-Jiajun/vpp/tree/feat/pr-pppoeclient/src/plugins/pppoeclient/pppox/pppd`

## File-level SPDX summary (`master` branch, `pppox/pppd/`)

| SPDX identifier | Files |
| --- | --- |
| `Apache-2.0` | `sys-vpp.c`, `sys-vpp.h` |
| `BSD-Attribution-HPND-disclaimer` | `fsm.c`, `fsm.h`, `if_ppp.h`, `ipcp.c`, `ipcp.h`, `ipv6cp.c`, `ipv6cp.h`, `lcp.c`, `lcp.h`, `magic.c`, `magic.h`, `pathnames.h`, `pppd.h`, `upap.c`, `upap.h` |
| `Mackerras-3-Clause AND Mackerras-3-Clause-acknowledgment` | `ppp_defs.h`, `pppio.h` |
| `Mackerras-3-Clause-acknowledgment` | `chap-md5.c`, `chap-md5.h`, `chap-new.c`, `chap-new.h`, `utils.c` |
| `Mackerras-3-Clause-acknowledgment AND BSD-Attribution-HPND-disclaimer` | `auth.c` |

`README.import` in that directory is repository-owned Apache-2.0 documentation.

## License texts

The notices below are reproduced from the `master` branch file headers with
nothing changed except the removal of the C comment prefix (` * `). They are
included here so that source and binary redistributions — including the
prebuilt packages, which ship this file — carry the copyright notices, the
list of conditions and the disclaimers, as clauses 2/4 of these licenses
require.

### `BSD-Attribution-HPND-disclaimer` — `pppox/pppd/fsm.c`

```
fsm.c - {Link, IP} Control Protocol Finite State Machine.

Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in
   the documentation and/or other materials provided with the
   distribution.

3. The name "Carnegie Mellon University" must not be used to
   endorse or promote products derived from this software without
   prior written permission. For permission or any legal
   details, please contact
     Office of Technology Transfer
     Carnegie Mellon University
     5000 Forbes Avenue
     Pittsburgh, PA  15213-3890
     (412) 268-4387, fax: (412) 268-7395
     tech-transfer@andrew.cmu.edu

4. Redistributions of any form whatsoever must retain the following
   acknowledgment:
   "This product includes software developed by Computing Services
    at Carnegie Mellon University (http://www.cmu.edu/computing/)."

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

### `Mackerras-3-Clause-acknowledgment` — `pppox/pppd/chap-md5.c`

```
chap-md5.c - New CHAP/MD5 implementation.

Copyright (c) 2003 Paul Mackerras. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. The name(s) of the authors of this software must not be used to
   endorse or promote products derived from this software without
   prior written permission.

3. Redistributions of any form whatsoever must retain the following
   acknowledgment:
   "This product includes software developed by Paul Mackerras
    <paulus@samba.org>".

THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

### `Mackerras-3-Clause AND Mackerras-3-Clause-acknowledgment` — `pppox/pppd/ppp_defs.h`

```
ppp_defs.h - PPP definitions.

Copyright (c) 1984 Paul Mackerras. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in
   the documentation and/or other materials provided with the
   distribution.

3. The name(s) of the authors of this software must not be used to
   endorse or promote products derived from this software without
   prior written permission.

4. Redistributions of any form whatsoever must retain the following
   acknowledgment:
   "This product includes software developed by Paul Mackerras
    <paulus@samba.org>".

THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

### `Mackerras-3-Clause-acknowledgment AND BSD-Attribution-HPND-disclaimer` — `pppox/pppd/auth.c`

```
auth.c - PPP authentication and phase control.

Copyright (c) 1993-2002 Paul Mackerras. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. The name(s) of the authors of this software must not be used to
   endorse or promote products derived from this software without
   prior written permission.

3. Redistributions of any form whatsoever must retain the following
   acknowledgment:
   "This product includes software developed by Paul Mackerras
    <paulus@samba.org>".

THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

Derived from main.c, which is:

Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in
   the documentation and/or other materials provided with the
   distribution.

3. The name "Carnegie Mellon University" must not be used to
   endorse or promote products derived from this software without
   prior written permission. For permission or any legal
   details, please contact
     Office of Technology Transfer
     Carnegie Mellon University
     5000 Forbes Avenue
     Pittsburgh, PA  15213-3890
     (412) 268-4387, fax: (412) 268-7395
     tech-transfer@andrew.cmu.edu

4. Redistributions of any form whatsoever must retain the following
   acknowledgment:
   "This product includes software developed by Computing Services
    at Carnegie Mellon University (http://www.cmu.edu/computing/)."

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

## Practical interpretation

- The repository is distributed primarily under Apache License 2.0 for
  repository-owned code; the `pppd` subtree is a collection of adapted
  third-party files under the permissive licenses listed above. No GPL code is
  present in this repository.
- Redistributing the sources: keep `LICENSE`, `NOTICE`, this file and the
  original file headers intact.
- Redistributing binaries (including the prebuilt plugin packages): ship this
  file together with `LICENSE` and `NOTICE`, and honour the acknowledgment
  clauses — the `*-acknowledgment` and `BSD-Attribution-HPND-disclaimer` texts
  ask for the quoted "This product includes software developed by ..." lines.
