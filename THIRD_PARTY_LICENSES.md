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
| `BSD-4.3TAHOE` | `slcompress.h`, `vjcompress.h` |
| `BSD-Attribution-HPND-disclaimer` | `fsm.c`, `fsm.h`, `if_ppp.h`, `ipcp.c`, `ipcp.h`, `ipv6cp.c`, `ipv6cp.h`, `lcp.c`, `lcp.h`, `magic.c`, `magic.h`, `options.c`, `pathnames.h`, `pppd.h`, `upap.c`, `upap.h` |
| `Mackerras-3-Clause` | `ecp.h` |
| `Mackerras-3-Clause AND Mackerras-3-Clause-acknowledgment` | `ecp.c`, `ppp-comp.h`, `ppp_defs.h`, `pppio.h` |
| `Mackerras-3-Clause-acknowledgment` | `ccp.c`, `ccp.h`, `chap-md5.c`, `chap-md5.h`, `chap-new.c`, `chap-new.h`, `utils.c` |
| `Mackerras-3-Clause-acknowledgment AND BSD-Attribution-HPND-disclaimer` | `auth.c` |
| `RSA-MD` | `md5.c`, `md5.h` |
| `Sun-PPP` | `eap.h` |

`README.import` in that directory is repository-owned Apache-2.0 documentation.

## License texts

The notices below are reproduced from the `master` branch file headers with
nothing changed except the removal of the C comment prefix (` * `). They are
included here so that source and binary redistributions — including the
prebuilt packages, which ship this file — carry the copyright notices, the
list of conditions and the disclaimers, as clauses 2/4 of these licenses
require.

### `BSD-4.3TAHOE` — `pppox/pppd/slcompress.h`

```
Definitions for tcp compression routines.

$Id: slcompress.h,v 1.4 1994/09/21 06:50:08 paulus Exp $

Copyright (c) 1989 Regents of the University of California.
All rights reserved.

Redistribution and use in source and binary forms are permitted
provided that the above copyright notice and this paragraph are
duplicated in all such forms and that any documentation,
advertising materials, and other materials related to such
distribution and use acknowledge that the software was developed
by the University of California, Berkeley.  The name of the
University may not be used to endorse or promote products derived
from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.

Van Jacobson (van@helios.ee.lbl.gov), Dec 31, 1989:
- Initial distribution.
```

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

### `Mackerras-3-Clause` — `pppox/pppd/ecp.h`

```
ecp.h - Definitions for PPP Encryption Control Protocol.

Copyright (c) 2002 Google, Inc.
All rights reserved.

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

THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

$Id: ecp.h,v 1.2 2003/01/10 07:12:36 fcusack Exp $
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

### `Mackerras-3-Clause AND Mackerras-3-Clause-acknowledgment` — `pppox/pppd/ecp.c`

```
ecp.c - PPP Encryption Control Protocol.

Copyright (c) 2002 Google, Inc.
All rights reserved.

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

THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

Derived from ccp.c, which is:

Copyright (c) 1994-2002 Paul Mackerras. All rights reserved.

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

### `RSA-MD` — `pppox/pppd/md5.c`

```
 ***********************************************************************
 ** md5.c -- the source code for MD5 routines                         **
 ** RSA Data Security, Inc. MD5 Message-Digest Algorithm              **
 ** Created: 2/17/90 RLR                                              **
 ** Revised: 1/91 SRD,AJ,BSK,JT Reference C ver., 7/10 constant corr. **
 ***********************************************************************

 ***********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved.  **
 **                                                                   **
 ** License to copy and use this software is granted provided that    **
 ** it is identified as the "RSA Data Security, Inc. MD5 Message-     **
 ** Digest Algorithm" in all material mentioning or referencing this  **
 ** software or this function.                                        **
 **                                                                   **
 ** License is also granted to make and use derivative works          **
 ** provided that such works are identified as "derived from the RSA  **
 ** Data Security, Inc. MD5 Message-Digest Algorithm" in all          **
 ** material mentioning or referencing the derived work.              **
 **                                                                   **
 ** RSA Data Security, Inc. makes no representations concerning       **
 ** either the merchantability of this software or the suitability    **
 ** of this software for any particular purpose.  It is provided "as  **
 ** is" without express or implied warranty of any kind.              **
 **                                                                   **
 ** These notices must be retained in any copies of any part of this  **
 ** documentation and/or software.                                    **
 ***********************************************************************
```

### `Sun-PPP` — `pppox/pppd/eap.h`

```
eap.h - Extensible Authentication Protocol for PPP (RFC 2284)

Copyright (c) 2001 by Sun Microsystems, Inc.
All rights reserved.

Non-exclusive rights to redistribute, modify, translate, and use
this software in source and binary forms, in whole or in part, is
hereby granted, provided that the above copyright notice is
duplicated in any source form, and that neither the name of the
copyright holder nor the author is used to endorse or promote
products derived from this software.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.

Original version by James Carlson

$Id: eap.h,v 1.2 2003/06/11 23:56:26 paulus Exp $
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
  clauses — the BSD-4.3TAHOE text asks that related materials acknowledge that
  the software was developed by the University of California, Berkeley, and the
  `*-acknowledgment` texts ask for the quoted "This product includes software
  developed by ..." lines.
