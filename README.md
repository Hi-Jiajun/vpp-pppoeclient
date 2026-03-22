

<h1 align="center">VPP PPPoE Client Plugin</h1>

<p align="center">
  <strong>A high-performance PPPoE client implementation for <a href="https://fd.io/">FD.io VPP</a></strong>
</p>

<p align="center">
  <a href="https://github.com/Hi-Jiajun/vpp-pppoeclient/stargazers"><img src="https://img.shields.io/github/stars/Hi-Jiajun/vpp-pppoeclient?style=for-the-badge&logo=github&color=f4c542" alt="Stars"/></a>
  <a href="https://github.com/Hi-Jiajun/vpp-pppoeclient/network/members"><img src="https://img.shields.io/github/forks/Hi-Jiajun/vpp-pppoeclient?style=for-the-badge&logo=github&color=8cc751" alt="Forks"/></a>
  <a href="https://github.com/Hi-Jiajun/vpp-pppoeclient/issues"><img src="https://img.shields.io/github/issues/Hi-Jiajun/vpp-pppoeclient?style=for-the-badge&logo=github&color=ea6a5a" alt="Issues"/></a>
  <a href="./LICENSE"><img src="https://img.shields.io/github/license/Hi-Jiajun/vpp-pppoeclient?style=for-the-badge&color=5b9bd5" alt="License"/></a>
</p>

<p align="center">
  <a href="./README_CN.md">🇨🇳 中文文档</a> •
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#cli-reference">CLI Reference</a> •
  <a href="#acknowledgments">Acknowledgments</a>
</p>

---

## 📖 Overview

This project provides two VPP plugins that together implement a **complete PPPoE client** — running entirely within VPP's user-space, high-performance data-plane pipeline.

| Plugin | Role |
|:------:|------|
| **`pppoeclient`** | PPPoE discovery (PADI/PADO/PADR/PADS/PADT), session management, data-plane encapsulation & decapsulation |
| **`pppox`** | PPP control-plane engine (LCP, IPCP, IPv6CP, PAP, CHAP), adapted from the open-source [pppd](https://ppp.samba.org/) |

---

## ✨ Features

| Category | Details |
|----------|---------|
| 🔗 **PPPoE Lifecycle** | Full PADI → PADO → PADR → PADS → Session → PADT |
| 🔒 **Authentication** | PAP and CHAP (MD5) |
| 🌐 **Dual Stack** | IPv4 via IPCP, IPv6 via IPv6CP + DHCPv6 / DHCPv6-PD |
| 🛣️ **Route Control** | `add-default-route4` (IPv4 only), `add-default-route6` (IPv6 only), or both |
| 📡 **DNS** | Peer DNS via IPCP → `/etc/ppp/resolv.conf` |
| 📐 **TCP MSS Clamp** | Auto-clamp for IPv4 (max 1452) and IPv6 (max 1432) SYN packets |
| 🔄 **Auto-Reconnect** | Automatic session re-establishment on link failure |
| ⚡ **Performance** | Dual-loop data-plane processing, zero-copy forwarding |

---

## 📂 Project Structure

```
src/plugins/
├── pppoeclient/                # PPPoE Client Plugin
│   ├── pppoeclient.h/c        # Core: discovery, session, CLI
│   ├── node.c                  # Data-plane RX/TX nodes
│   ├── pppoeclient.api        # Binary API definitions
│   ├── pppoeclient_api.c      # API handlers
│   └── pppoeclient_error.def  # Error counters
│
└── pppox/                      # PPP Control-Plane Plugin
    ├── pppox.h/c               # Virtual interface, control dispatch
    ├── cli.c / node.c          # CLI & input node
    ├── pppox.api / pppox_api.c # Binary API
    └── pppd/                   # Adapted pppd engines
        ├── lcp.c/h             # Link Control Protocol
        ├── ipcp.c/h            # IP Control Protocol
        ├── ipv6cp.c/h          # IPv6 Control Protocol
        ├── chap-new.c/h        # CHAP authentication
        ├── upap.c/h            # PAP authentication
        ├── fsm.c/h             # Finite State Machine
        ├── sys-vpp.c/h         # VPP system adaptation
        └── ...
```

---

## 🔧 Prerequisites

- **VPP** 24.02+ source tree (tested on 26.02)
- **DPDK** (bundled with VPP)
- **Linux** with DPDK-compatible NIC
- `cmake` / `ninja` / `gcc`

---

## 🚀 Quick Start

### Build

```bash
# Clone the full VPP fork with plugins pre-integrated
git clone https://github.com/Hi-Jiajun/vpp.git -b pppoeclient-plugin-fix
cd vpp

# First-time build
make install-dep && make build-release

# Or incremental
ninja -C build-root/build-vpp-native/vpp \
    pppox_plugin pppoeclient_plugin vpp vppctl
```

<details>
<summary>💡 Using this repo standalone (copy into existing VPP tree)</summary>

```bash
git clone https://github.com/Hi-Jiajun/vpp-pppoeclient.git
cp -r vpp-pppoeclient/src/plugins/pppoeclient /path/to/vpp/src/plugins/
cp -r vpp-pppoeclient/src/plugins/pppox       /path/to/vpp/src/plugins/
cd /path/to/vpp && ninja -C build-root/build-vpp-native/vpp \
    pppox_plugin pppoeclient_plugin
```

</details>

### Run

```bash
# Start VPP
sudo vpp unix { nodaemon cli-listen /tmp/vpp-cli.sock } \
    dpdk { dev 0000:01:00.0 { name dpdk0 } } \
    plugins {
      plugin pppox_plugin.so { enable }
      plugin pppoeclient_plugin.so { enable }
    }
```

### Configure (vppctl)

```bash
# 1. Bring up interface
set interface state dpdk0 up
set interface mtu packet 1500 dpdk0

# 2. Create PPPoE client
create pppoe client sw-if-index 1 host-uniq 1234

# 3. Set credentials & options
set pppoe client 0 username YOUR_USER password YOUR_PASS \
    mtu 1492 mru 1492 use-peer-dns add-default-route
```

### Separate IPv4 / IPv6 Default Route

```bash
# IPv4 only
set pppoe client 0 username USER password PASS add-default-route4

# IPv6 only
set pppoe client 0 username USER password PASS add-default-route6

# Both (same as add-default-route)
set pppoe client 0 username USER password PASS add-default-route4 add-default-route6
```

### IPv6 with DHCPv6-PD

```bash
dhcp6 client pppox0
dhcp6 pd client pppox0 prefix group wan-pd
set ip6 address pppox0 prefix group wan-pd ::1/64
```

### Monitor

```bash
show pppoe client detail     # Full status
show ip fib table 0          # IPv4 routes
show ip6 fib                 # IPv6 routes
ping 223.5.5.5               # IPv4 test
ping 2400:3200::1            # IPv6 test
```

---

## 📋 CLI Reference

### Commands

| Command | Description |
|---------|-------------|
| `create pppoe client sw-if-index <N> host-uniq <ID>` | Create client |
| `create pppoe client sw-if-index <N> host-uniq <ID> del` | Delete client |
| `set pppoe client <idx> username <U> password <P> [opts]` | Configure client |
| `show pppoe client [detail]` | Show status |

### Options for `set pppoe client`

| Option | Description |
|--------|-------------|
| `mtu <N>` | PPP MTU (default: 1492) |
| `mru <N>` | PPP MRU (default: 1492) |
| `timeout <N>` | Timeout value |
| `use-peer-dns` | Use DNS from peer |
| `add-default-route` | Add IPv4 **and** IPv6 default route |
| `add-default-route4` | Add IPv4 default route only |
| `add-default-route6` | Add IPv6 default route only |

---

## 📊 Star History

<p align="center">
  <a href="https://star-history.com/#Hi-Jiajun/vpp-pppoeclient&Date">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=Hi-Jiajun/vpp-pppoeclient&type=Date&theme=dark" />
      <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=Hi-Jiajun/vpp-pppoeclient&type=Date" />
      <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=Hi-Jiajun/vpp-pppoeclient&type=Date" width="600" />
    </picture>
  </a>
</p>

---

## 📚 References

- [FD.io VPP](https://github.com/FDio/vpp) — High-performance packet processing framework
- [Hi-Jiajun/vpp (pppoeclient-plugin-fix)](https://github.com/Hi-Jiajun/vpp/tree/pppoeclient-plugin-fix) — Full VPP fork with plugins integrated
- [pppd](https://ppp.samba.org/) — The PPP control-plane engine this project adapts
- [RaydoNetworks/ppp-vpp](https://github.com/pppoe/ppp-vpp) — Original PPPoE/PPPoX plugin concept
- [RFC 2516](https://www.rfc-editor.org/rfc/rfc2516) — PPPoE specification
- [RFC 1661](https://www.rfc-editor.org/rfc/rfc1661) — PPP
- [RFC 1332](https://www.rfc-editor.org/rfc/rfc1332) — IPCP
- [RFC 5072](https://www.rfc-editor.org/rfc/rfc5072) — IPv6 over PPP

---

## 🙏 Acknowledgments

- [FD.io VPP](https://fd.io/) community for the excellent networking framework
- [RaydoNetworks](https://github.com/pppoe/ppp-vpp) for the original PPPoE/PPPoX plugin concept
- [pppd](https://ppp.samba.org/) project for the robust PPP protocol engine
- All contributors who tested and provided feedback

---

## ☕ Support

If this project has been helpful to you, consider buying me a coffee!

<p align="center">
  <img src="https://Hi-Jiajun.github.io/picx-images-hosting/wechat_qrcode.icohq9bcf.webp" alt="WeChat Pay" height="260"/>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <img src="https://Hi-Jiajun.github.io/picx-images-hosting/alipay_qrcode.7p45v27tjq.webp" alt="Alipay" height="260"/>
</p>
<p align="center">
  <em>WeChat Pay &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Alipay</em>
</p>

---

## 📄 License

This project is licensed under the [Apache License 2.0](./LICENSE).

The adapted `pppd` code in `src/plugins/pppox/pppd/` retains its original BSD-style license. See individual source file headers for details.
