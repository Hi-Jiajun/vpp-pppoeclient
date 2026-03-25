# 🚀 VPP PPPoE Client Plugin

[![stars](https://img.shields.io/github/stars/Hi-Jiajun/vpp-pppoeclient?style=flat-square&logo=github&label=stars)](https://github.com/Hi-Jiajun/vpp-pppoeclient/stargazers)
[![forks](https://img.shields.io/github/forks/Hi-Jiajun/vpp-pppoeclient?style=flat-square&logo=github&label=forks)](https://github.com/Hi-Jiajun/vpp-pppoeclient/network/members)
[![issues](https://img.shields.io/github/issues/Hi-Jiajun/vpp-pppoeclient?style=flat-square&logo=github&label=issues)](https://github.com/Hi-Jiajun/vpp-pppoeclient/issues)
[![license](https://img.shields.io/github/license/Hi-Jiajun/vpp-pppoeclient?style=flat-square&label=license)](./LICENSE)

> A standalone mirror of the `pppoeclient` and `pppox` plugins from
> [`Hi-Jiajun/vpp`](https://github.com/Hi-Jiajun/vpp/tree/feat/pr-pppoeclient), focused on PPPoE
> client support for FD.io VPP.

🌏 [中文 README](./README.md)

---

## ✨ Overview

This repository extracts the PPPoE client related plugins from the upstream VPP fork so they can be
reviewed, synced, and vendored independently from the full VPP source tree.

The implementation is split into two plugins:

| Plugin | Responsibility |
| --- | --- |
| `pppoeclient` | PPPoE discovery, session lifecycle, session lookup, data-plane encapsulation and decapsulation |
| `pppox` | PPP control plane, authentication, IPv4/IPv6 negotiation, and pppd-derived protocol handling |

Together they provide a complete PPPoE client running inside VPP user space.

## 📌 Current Sync Status

- 🌿 Upstream branch: `feat/pr-pppoeclient`
- 🔖 Synced upstream commit: `0ebbd46e8771257ca9462277e966f948f90e9343`

## 🔄 Sync From Upstream

This repository can sync only the upstream directories that belong to this project:

- `src/plugins/pppoeclient`
- `src/plugins/pppox`

The repo now supports an `upstream` remote:

- `upstream`: `https://github.com/Hi-Jiajun/vpp.git`

It also includes a helper script:

- [scripts/sync-from-upstream.ps1](./scripts/sync-from-upstream.ps1)
- [scripts/sync-from-upstream.sh](./scripts/sync-from-upstream.sh)

Run it from PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\sync-from-upstream.ps1
```

The script will:

- ensure the `upstream` remote exists
- fetch `feat/pr-pppoeclient`
- perform a sparse clone of the upstream repository
- mirror only `src/plugins/pppoeclient` and `src/plugins/pppox`
- print the exact upstream commit used for the sync

Run it on Linux or macOS:

```bash
chmod +x ./scripts/sync-from-upstream.sh
./scripts/sync-from-upstream.sh
```

Check only, without modifying local files:

```bash
./scripts/sync-from-upstream.sh --check
```

## 🤖 Automated Check

The repository now includes a GitHub Actions workflow:

- `.github/workflows/check-upstream-sync.yml`

It automatically checks whether the plugin directories in this repository still match upstream on:

- manual dispatch
- daily schedule
- relevant `push` and `pull_request` events

If [src/plugins/pppoeclient](./src/plugins/pppoeclient) or [src/plugins/pppox](./src/plugins/pppox)
drift from upstream `feat/pr-pppoeclient`, the workflow will fail.

## 🚀 Automated Releases

The repository also includes an automatic release workflow:

- `.github/workflows/auto-release.yml`

It creates a GitHub Release automatically when `master` receives project-related updates in:

- `src/plugins/pppoeclient/**`
- `src/plugins/pppox/**`
- `README.md`
- `README_EN.md`
- `scripts/**`

The current prebuilt package target is the latest stable tag from official `FDio/vpp`:

- the workflow auto-detects the latest stable tag
- you can still override it manually through the `vpp_ref` workflow input

Release behavior:

- each commit gets an automatic tag based on its short SHA, for example `auto-da21b11`
- the same commit will not create duplicate releases
- the release targets the exact commit and includes generated notes
- each release uploads prebuilt packages for:
  - Debian / Ubuntu as `.deb`
  - RPM-based distributions as `.rpm`
- the current build matrix includes:
  - Ubuntu 24.04
  - Debian 12
  - Rocky Linux 9
- the prebuilt workflow pulls from the official repository:
  - `https://github.com/FDio/vpp.git`
- when no tag is specified manually, the workflow resolves the latest official stable tag automatically
- these packages contain prebuilt plugin binaries and API JSON files:
  - `pppoeclient_plugin.so`
  - `pppox_plugin.so`
  - `pppoeclient.api.json`
  - `pppox.api.json`
- installed paths follow common VPP system locations, for example:
  - Debian / Ubuntu: `/usr/lib/x86_64-linux-gnu/vpp_plugins`
  - RPM-based systems: `/usr/lib64/vpp_plugins`
- if you prefer source integration instead of prebuilt packages, the README still documents that workflow

## 🧩 Highlights

- 🔄 Full PPPoE lifecycle: `PADI`, `PADO`, `PADR`, `PADS`, `PADT`
- 🔐 PAP and CHAP authentication through the integrated `pppox` control plane
- 🌐 IPv4 via IPCP and IPv6 via IPv6CP
- 🛣️ Separate `add-default-route4` and `add-default-route6` controls
- 🧭 Peer DNS import through IPCP into `/etc/ppp/resolv.conf`
- 🔁 Live sync for auth, DNS, and route settings after session creation
- 🧪 Rich `show pppoe client detail` output for runtime inspection
- 🧱 Session lookup keyed by ingress interface + AC MAC + PPPoE session ID
- 🏷️ VLAN sub-interface aware PPPoE L2 header handling
- 📏 TCP MSS clamp on PPP session traffic

## 🗂️ Repository Layout

```text
src/plugins/
|-- pppoeclient/
|   |-- CMakeLists.txt
|   |-- node.c
|   |-- pppoeclient.api
|   |-- pppoeclient.c
|   |-- pppoeclient.h
|   |-- pppoeclient_api.c
|   `-- pppoeclient_error.def
`-- pppox/
    |-- CMakeLists.txt
    |-- cli.c
    |-- node.c
    |-- pppox.api
    |-- pppox.c
    |-- pppox.h
    |-- pppox_api.c
    `-- pppd/
        |-- lcp.c / lcp.h
        |-- ipcp.c / ipcp.h
        |-- ipv6cp.c / ipv6cp.h
        |-- chap-new.c / chap-new.h
        |-- upap.c / upap.h
        |-- sys-vpp.c / sys-vpp.h
        `-- ...
```

## 🛠️ Requirements

- Linux
- A VPP source tree, tested mainly with VPP `26.02`
- `cmake`, `ninja`, and a working compiler toolchain
- A lower interface suitable for PPPoE access

## 📦 Build

### Option 1: build from the full VPP fork

```bash
git clone https://github.com/Hi-Jiajun/vpp.git -b feat/pr-pppoeclient
cd vpp
make install-dep
make build-release
```

### Option 2: vendor these plugins into an existing VPP tree

```bash
git clone https://github.com/Hi-Jiajun/vpp-pppoeclient.git
cp -r vpp-pppoeclient/src/plugins/pppoeclient /path/to/vpp/src/plugins/
cp -r vpp-pppoeclient/src/plugins/pppox /path/to/vpp/src/plugins/
cd /path/to/vpp
ninja -C build-root/build-vpp-native/vpp pppox_plugin pppoeclient_plugin vpp vppctl
```

## ▶️ Run VPP

```bash
sudo vpp unix { nodaemon cli-listen /tmp/vpp-cli.sock } \
  dpdk { dev 0000:01:00.0 { name dpdk0 } } \
  plugins {
    plugin pppox_plugin.so { enable }
    plugin pppoeclient_plugin.so { enable }
  }
```

## ⚡ Quick Start

```bash
# 1. Bring the lower interface up
set interface state dpdk0 up
set interface mtu packet 1500 dpdk0

# 2. Create a PPPoE client
create pppoe client sw-if-index 1 host-uniq 1234

# 3. Configure authentication and options
set pppoe client 0 username YOUR_USER password YOUR_PASS \
  mtu 1492 mru 1492 use-peer-dns add-default-route
```

💡 If your access network uses a VLAN sub-interface, create and enable that VPP sub-interface
first, then bind the PPPoE client to its `sw-if-index`.

## 🧭 CLI Reference

### `pppoeclient`

```text
create pppoe client sw-if-index <nn> host-uniq <nn> [del]
show pppoe client
show pppoe client detail
set pppoe client <index> username <user> password <pass> \
  [mtu <n>] [mru <n>] [timeout <n>] \
  [use-peer-dns] [add-default-route | add-default-route4 | add-default-route6]
```

#### `set pppoe client` options

| Option | Meaning |
| --- | --- |
| `mtu <n>` | PPP MTU |
| `mru <n>` | PPP MRU |
| `timeout <n>` | PPP timeout value |
| `use-peer-dns` | Accept IPCP DNS and write `/etc/ppp/resolv.conf` |
| `add-default-route` | Enable both IPv4 and IPv6 default routes |
| `add-default-route4` | Enable IPv4 default route only |
| `add-default-route6` | Enable IPv6 default route only |

Notes:

- `use-peer-route` is still accepted as a compatibility alias for enabling both default routes.
- Re-running `set pppoe client ...` updates the existing client and attempts to sync the live
  PPPoX session.

### `pppox`

The control-plane plugin also exposes a direct auth CLI:

```text
pppox set auth sw-if-index <nn> username <string> password <string>
```

In normal PPPoE client usage, credentials are usually configured through `set pppoe client`.

## 🧪 Common Flows

### Dual-stack default routes

```bash
set pppoe client 0 username USER password PASS add-default-route
```

### IPv4 default route only

```bash
set pppoe client 0 username USER password PASS add-default-route4
```

### IPv6 default route only

```bash
set pppoe client 0 username USER password PASS add-default-route6
```

### DHCPv6-PD after PPP is up

```bash
dhcp6 client pppox0
dhcp6 pd client pppox0 prefix group wan-pd
set ip6 address pppox0 prefix group wan-pd ::1/64
```

## 🔍 Operational Checks

Useful commands:

```bash
show pppoe client
show pppoe client detail
show interface
show ip fib table 0
show ip6 fib
```

`show pppoe client detail` currently includes:

- client state and PPPoE session ID
- learned AC MAC and AC-Name
- bound PPPoX interface and PPP unit
- negotiated IPv4 local and peer addresses
- IPv6 local and peer information plus source information
- peer DNS addresses
- active auth, MTU/MRU, timeout, and route-related flags

## 📈 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Hi-Jiajun/vpp-pppoeclient&type=Date)](https://star-history.com/#Hi-Jiajun/vpp-pppoeclient&Date)

## 🔌 Binary API

Current API definition files:

- `src/plugins/pppoeclient/pppoeclient.api`
- `src/plugins/pppox/pppox.api`

Defined request and reply messages include:

- `pppoeclient_add_del`
- `pppoeclient_add_del_reply`
- `pppoeclient_dump`
- `pppoeclient_details`
- `pppox_set_auth`
- `pppox_set_auth_reply`

Notes:

- `pppoeclient_dump` triggers `pppoeclient_details` messages.
- `pppoeclient_details` currently carries `sw_if_index` and `host_uniq`.
- For richer operational state, the CLI output is still the most useful interface.

## 📚 References

- [FD.io VPP](https://github.com/FDio/vpp)
- [Hi-Jiajun/vpp](https://github.com/Hi-Jiajun/vpp/tree/feat/pr-pppoeclient)
- [pppd](https://ppp.samba.org/)
- [raydonetworks/vpp-pppoeclient](https://github.com/raydonetworks/vpp-pppoeclient) - initial public repository of this plugin
- [RFC 2516](https://www.rfc-editor.org/rfc/rfc2516)
- [RFC 1661](https://www.rfc-editor.org/rfc/rfc1661)
- [RFC 1332](https://www.rfc-editor.org/rfc/rfc1332)
- [RFC 5072](https://www.rfc-editor.org/rfc/rfc5072)

## 💖 Support

If this project helps you, support is appreciated.

| WeChat Pay | Alipay |
| --- | --- |
| <img src="https://Hi-Jiajun.github.io/picx-images-hosting/wechat_qrcode.icohq9bcf.webp" height="260" alt="WeChat Pay QR code"> | <img src="https://Hi-Jiajun.github.io/picx-images-hosting/alipay_qrcode.7p45v27tjq.webp" height="260" alt="Alipay QR code"> |

## 📄 License

This project is licensed under the [Apache License 2.0](./LICENSE).

The adapted `pppd` sources under `src/plugins/pppox/pppd/` retain their original BSD-style
license notices in the file headers.
