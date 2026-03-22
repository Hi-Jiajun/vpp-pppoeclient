# VPP PPPoE Client Plugin

[![Stars](https://img.shields.io/github/stars/Hi-Jiajun/vpp-pppoeclient?style=for-the-badge&logo=github&color=f4c542)](https://github.com/Hi-Jiajun/vpp-pppoeclient/stargazers)
[![Forks](https://img.shields.io/github/forks/Hi-Jiajun/vpp-pppoeclient?style=for-the-badge&logo=github&color=8cc751)](https://github.com/Hi-Jiajun/vpp-pppoeclient/network/members)
[![Issues](https://img.shields.io/github/issues/Hi-Jiajun/vpp-pppoeclient?style=for-the-badge&logo=github&color=ea6a5a)](https://github.com/Hi-Jiajun/vpp-pppoeclient/issues)
[![License](https://img.shields.io/github/license/Hi-Jiajun/vpp-pppoeclient?style=for-the-badge&color=5b9bd5)](./LICENSE)

[Chinese README](./README_CN.md)

This repository is the standalone mirror of the `pppoeclient` and `pppox` plugins from
[`Hi-Jiajun/vpp`](https://github.com/Hi-Jiajun/vpp) on branch
[`feat/pr-pppoeclient`](https://github.com/Hi-Jiajun/vpp/tree/feat/pr-pppoeclient).
It is intended for users who want to review, track, or vendor only the PPPoE client related
plugin sources instead of the full VPP tree.

## Overview

The implementation is split into two plugins:

| Plugin | Responsibility |
| --- | --- |
| `pppoeclient` | PPPoE discovery, session lifecycle, session lookup, data-plane encapsulation/decapsulation |
| `pppox` | PPP control plane, authentication, IPv4/IPv6 negotiation, and pppd-derived protocol handling |

Together they provide a complete PPPoE client inside VPP user space.

## What Is In This Version

This standalone repository currently tracks the plugin content from:

- Upstream branch: `feat/pr-pppoeclient`
- Synced commit: `ee002b08dffaed8cf94a3b1f193619950ebbfca9`

Highlights of the current codebase:

- Full PPPoE discovery and teardown: `PADI`, `PADO`, `PADR`, `PADS`, `PADT`
- PAP and CHAP authentication through the integrated `pppox` control plane
- IPv4 via IPCP and IPv6 via IPv6CP, with optional DHCPv6 / DHCPv6-PD on top
- Separate control flags for `add-default-route4` and `add-default-route6`
- Peer DNS import through IPCP and `/etc/ppp/resolv.conf`
- Live sync of auth, peer DNS, and default-route settings after session creation
- Detailed `show pppoe client detail` output including AC name, PPPoX interface, IPv4/IPv6 state, and peer DNS
- Session lookup keyed by ingress interface + AC MAC + PPPoE session ID
- Support for VLAN sub-interfaces when building/parsing the PPPoE L2 header
- TCP MSS clamp on PPP session traffic in the data path

## Repository Layout

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

## Requirements

- Linux
- A VPP source tree, tested with VPP `26.02`
- `cmake`, `ninja`, and a working compiler toolchain
- A NIC or lower interface suitable for PPPoE access

## Build

### Option 1: Build from the full VPP fork

```bash
git clone https://github.com/Hi-Jiajun/vpp.git -b feat/pr-pppoeclient
cd vpp
make install-dep
make build-release
```

### Option 2: Vendor these plugins into an existing VPP tree

```bash
git clone https://github.com/Hi-Jiajun/vpp-pppoeclient.git
cp -r vpp-pppoeclient/src/plugins/pppoeclient /path/to/vpp/src/plugins/
cp -r vpp-pppoeclient/src/plugins/pppox /path/to/vpp/src/plugins/
cd /path/to/vpp
ninja -C build-root/build-vpp-native/vpp pppox_plugin pppoeclient_plugin vpp vppctl
```

## Run VPP

```bash
sudo vpp unix { nodaemon cli-listen /tmp/vpp-cli.sock } \
  dpdk { dev 0000:01:00.0 { name dpdk0 } } \
  plugins {
    plugin pppox_plugin.so { enable }
    plugin pppoeclient_plugin.so { enable }
  }
```

## Quick Start

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

If your access network uses a VLAN sub-interface, create and bring up the VPP sub-interface first,
then bind the PPPoE client to that sub-interface's `sw-if-index`.

## CLI Reference

### `pppoeclient`

```text
create pppoe client sw-if-index <nn> host-uniq <nn> [del]
show pppoe client
show pppoe client detail
set pppoe client <index> username <user> password <pass> \
  [mtu <n>] [mru <n>] [timeout <n>] \
  [use-peer-dns] [add-default-route | add-default-route4 | add-default-route6]
```

`set pppoe client` options:

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
- Re-running `set pppoe client ...` updates the existing client and attempts to sync the live PPPoX session.

### `pppox`

The control-plane plugin also exposes a direct auth CLI:

```text
pppox set auth sw-if-index <nn> username <string> password <string>
```

In normal PPPoE client usage you usually configure credentials through `set pppoe client`.

## Example Flows

### IPv4 + IPv6 default routes

```bash
set pppoe client 0 username USER password PASS add-default-route
```

### IPv4 only

```bash
set pppoe client 0 username USER password PASS add-default-route4
```

### IPv6 only

```bash
set pppoe client 0 username USER password PASS add-default-route6
```

### Use DHCPv6-PD after PPP comes up

```bash
dhcp6 client pppox0
dhcp6 pd client pppox0 prefix group wan-pd
set ip6 address pppox0 prefix group wan-pd ::1/64
```

## Operational Checks

Useful commands:

```bash
show pppoe client
show pppoe client detail
show interface
show ip fib table 0
show ip6 fib
```

`show pppoe client detail` now includes:

- client state and PPPoE session ID
- learned AC MAC and AC-Name
- bound PPPoX interface and PPP unit
- negotiated IPv4 local/peer addresses
- IPv6 local/peer information and source
- peer DNS addresses
- active auth and route-related flags

## Binary API

Current API files in this repository:

- `src/plugins/pppoeclient/pppoeclient.api`
- `src/plugins/pppox/pppox.api`

The currently exposed messages are intentionally small:

- `pppoeclient_add_del`
- `pppoeclient_dump`
- `pppox_set_auth`

The `pppoeclient_dump` reply currently returns the client `sw_if_index` and `host_uniq`.
For richer operational state, the CLI output is still the most useful interface.

## References

- [FD.io VPP](https://github.com/FDio/vpp)
- [Hi-Jiajun/vpp](https://github.com/Hi-Jiajun/vpp/tree/feat/pr-pppoeclient)
- [pppd](https://ppp.samba.org/)
- [RaydoNetworks/ppp-vpp](https://github.com/pppoe/ppp-vpp)
- [RFC 2516](https://www.rfc-editor.org/rfc/rfc2516)
- [RFC 1661](https://www.rfc-editor.org/rfc/rfc1661)
- [RFC 1332](https://www.rfc-editor.org/rfc/rfc1332)
- [RFC 5072](https://www.rfc-editor.org/rfc/rfc5072)

## Support

If this project helps you, support is appreciated.

| WeChat Pay | Alipay |
| --- | --- |
| <img src="https://Hi-Jiajun.github.io/picx-images-hosting/wechat_qrcode.icohq9bcf.webp" height="260" alt="WeChat Pay QR code"> | <img src="https://Hi-Jiajun.github.io/picx-images-hosting/alipay_qrcode.7p45v27tjq.webp" height="260" alt="Alipay QR code"> |

## License

This project is licensed under the [Apache License 2.0](./LICENSE).

The adapted `pppd` sources under `src/plugins/pppox/pppd/` retain their original BSD-style
license notices in the file headers.
