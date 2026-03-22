

<h1 align="center">VPP PPPoE 客户端插件</h1>

<p align="center">
  <strong>基于 <a href="https://fd.io/">FD.io VPP</a> 的高性能 PPPoE 客户端实现</strong>
</p>

<p align="center">
  <a href="https://github.com/Hi-Jiajun/vpp-pppoeclient/stargazers"><img src="https://img.shields.io/github/stars/Hi-Jiajun/vpp-pppoeclient?style=for-the-badge&logo=github&color=f4c542" alt="Stars"/></a>
  <a href="https://github.com/Hi-Jiajun/vpp-pppoeclient/network/members"><img src="https://img.shields.io/github/forks/Hi-Jiajun/vpp-pppoeclient?style=for-the-badge&logo=github&color=8cc751" alt="Forks"/></a>
  <a href="https://github.com/Hi-Jiajun/vpp-pppoeclient/issues"><img src="https://img.shields.io/github/issues/Hi-Jiajun/vpp-pppoeclient?style=for-the-badge&logo=github&color=ea6a5a" alt="Issues"/></a>
  <a href="./LICENSE"><img src="https://img.shields.io/github/license/Hi-Jiajun/vpp-pppoeclient?style=for-the-badge&color=5b9bd5" alt="License"/></a>
</p>

<p align="center">
  <a href="./README.md">🇬🇧 English</a> •
  <a href="#功能特性">功能特性</a> •
  <a href="#快速开始">快速开始</a> •
  <a href="#命令参考">命令参考</a> •
  <a href="#致谢">致谢</a>
</p>

---

## 📖 概述

本项目提供两个 VPP 插件，共同实现**完整的 PPPoE 客户端** — 完全运行在 VPP 用户态高性能数据面流水线中。

| 插件 | 职责 |
|:----:|------|
| **`pppoeclient`** | PPPoE 发现（PADI/PADO/PADR/PADS/PADT）、会话管理、数据面封装与解封装 |
| **`pppox`** | PPP 控制面引擎（LCP、IPCP、IPv6CP、PAP、CHAP），基于开源 [pppd](https://ppp.samba.org/) 适配 |

---

## ✨ 功能特性

| 分类 | 详情 |
|------|------|
| 🔗 **PPPoE 生命周期** | 完整 PADI → PADO → PADR → PADS → 会话 → PADT |
| 🔒 **认证** | PAP 和 CHAP (MD5) |
| 🌐 **双栈支持** | IPv4 通过 IPCP 协商，IPv6 通过 IPv6CP + DHCPv6 / DHCPv6-PD |
| 🛣️ **路由控制** | `add-default-route4`（仅 IPv4）、`add-default-route6`（仅 IPv6）或同时设置 |
| 📡 **DNS 获取** | 通过 IPCP 获取对端 DNS → `/etc/ppp/resolv.conf` |
| 📐 **TCP MSS 钳制** | 自动钳制 IPv4（最大 1452）和 IPv6（最大 1432）SYN 包 |
| 🔄 **自动重连** | 链路故障后自动重新建立会话 |
| ⚡ **高性能** | 双循环数据面处理，零拷贝转发 |

---

## 📂 项目结构

```
src/plugins/
├── pppoeclient/                # PPPoE 客户端插件
│   ├── pppoeclient.h/c        # 核心：发现、会话、CLI
│   ├── node.c                  # 数据面 RX/TX 节点
│   ├── pppoeclient.api        # 二进制 API 定义
│   ├── pppoeclient_api.c      # API 处理器
│   └── pppoeclient_error.def  # 错误计数器
│
└── pppox/                      # PPP 控制面插件
    ├── pppox.h/c               # 虚拟接口、控制分发
    ├── cli.c / node.c          # CLI 和输入节点
    ├── pppox.api / pppox_api.c # 二进制 API
    └── pppd/                   # 适配的 pppd 引擎
        ├── lcp.c/h             # 链路控制协议
        ├── ipcp.c/h            # IP 控制协议
        ├── ipv6cp.c/h          # IPv6 控制协议
        ├── chap-new.c/h        # CHAP 认证
        ├── upap.c/h            # PAP 认证
        ├── fsm.c/h             # 有限状态机
        ├── sys-vpp.c/h         # VPP 系统适配层
        └── ...
```

---

## 🔧 环境要求

- **VPP** 24.02+ 源码（已在 26.02 上测试通过）
- **DPDK**（VPP 内置）
- **Linux** + 支持 DPDK 的网卡
- `cmake` / `ninja` / `gcc`

---

## 🚀 快速开始

### 编译

```bash
# 克隆已集成插件的 VPP 完整分支
git clone https://github.com/Hi-Jiajun/vpp.git -b pppoeclient-plugin-fix
cd vpp

# 首次编译
make install-dep && make build-release

# 增量编译
ninja -C build-root/build-vpp-native/vpp \
    pppox_plugin pppoeclient_plugin vpp vppctl
```

<details>
<summary>💡 单独使用本仓库（复制到已有 VPP 源码树）</summary>

```bash
git clone https://github.com/Hi-Jiajun/vpp-pppoeclient.git
cp -r vpp-pppoeclient/src/plugins/pppoeclient /path/to/vpp/src/plugins/
cp -r vpp-pppoeclient/src/plugins/pppox       /path/to/vpp/src/plugins/
cd /path/to/vpp && ninja -C build-root/build-vpp-native/vpp \
    pppox_plugin pppoeclient_plugin
```

</details>

### 启动 VPP

```bash
sudo vpp unix { nodaemon cli-listen /tmp/vpp-cli.sock } \
    dpdk { dev 0000:01:00.0 { name dpdk0 } } \
    plugins {
      plugin pppox_plugin.so { enable }
      plugin pppoeclient_plugin.so { enable }
    }
```

### 配置（vppctl）

```bash
# 1. 启用物理接口
set interface state dpdk0 up
set interface mtu packet 1500 dpdk0

# 2. 创建 PPPoE 客户端
create pppoe client sw-if-index 1 host-uniq 1234

# 3. 配置认证和选项
set pppoe client 0 username 宽带账号 password 宽带密码 \
    mtu 1492 mru 1492 use-peer-dns add-default-route
```

### IPv4/IPv6 默认路由分离

```bash
# 仅 IPv4 默认路由
set pppoe client 0 username 账号 password 密码 add-default-route4

# 仅 IPv6 默认路由
set pppoe client 0 username 账号 password 密码 add-default-route6

# 同时添加（等同于 add-default-route）
set pppoe client 0 username 账号 password 密码 add-default-route4 add-default-route6
```

### IPv6 配合 DHCPv6-PD

```bash
dhcp6 client pppox0
dhcp6 pd client pppox0 prefix group wan-pd
set ip6 address pppox0 prefix group wan-pd ::1/64
```

### 状态查看与测试

```bash
show pppoe client detail     # 详细状态
show ip fib table 0          # IPv4 路由表
show ip6 fib                 # IPv6 路由表
ping 223.5.5.5               # IPv4 连通测试
ping 2400:3200::1            # IPv6 连通测试
```

---

## 📋 命令参考

### 命令列表

| 命令 | 说明 |
|------|------|
| `create pppoe client sw-if-index <N> host-uniq <ID>` | 创建客户端 |
| `create pppoe client sw-if-index <N> host-uniq <ID> del` | 删除客户端 |
| `set pppoe client <idx> username <U> password <P> [选项]` | 配置客户端 |
| `show pppoe client [detail]` | 查看状态 |

### `set pppoe client` 选项

| 选项 | 说明 |
|------|------|
| `mtu <N>` | PPP MTU（默认 1492） |
| `mru <N>` | PPP MRU（默认 1492） |
| `timeout <N>` | 超时值 |
| `use-peer-dns` | 使用对端 DNS |
| `add-default-route` | 同时添加 IPv4 **和** IPv6 默认路由 |
| `add-default-route4` | 仅添加 IPv4 默认路由 |
| `add-default-route6` | 仅添加 IPv6 默认路由 |

---

## 📊 Star 趋势

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

## 📚 参考资料

- [FD.io VPP](https://github.com/FDio/vpp) — 高性能包处理框架
- [Hi-Jiajun/vpp (pppoeclient-plugin-fix)](https://github.com/Hi-Jiajun/vpp/tree/pppoeclient-plugin-fix) — 集成了本插件的完整 VPP 分支
- [pppd](https://ppp.samba.org/) — 本项目适配的 PPP 控制面引擎
- [RaydoNetworks/ppp-vpp](https://github.com/pppoe/ppp-vpp) — PPPoE/PPPoX 插件原始概念
- [RFC 2516](https://www.rfc-editor.org/rfc/rfc2516) — PPPoE 规范
- [RFC 1661](https://www.rfc-editor.org/rfc/rfc1661) — PPP 协议
- [RFC 1332](https://www.rfc-editor.org/rfc/rfc1332) — IPCP
- [RFC 5072](https://www.rfc-editor.org/rfc/rfc5072) — PPP 上的 IPv6

---

## 🙏 致谢

- [FD.io VPP](https://fd.io/) 社区提供的卓越网络框架
- [RaydoNetworks](https://github.com/pppoe/ppp-vpp) 提供的 PPPoE/PPPoX 插件原始概念和初始实现
- [pppd](https://ppp.samba.org/) 项目提供的健壮 PPP 协议引擎
- 所有参与测试和提供反馈的贡献者

---

## ☕ 赞赏支持

如果本项目对您有帮助，欢迎赞赏支持！

<p align="center">
  <img src="https://Hi-Jiajun.github.io/picx-images-hosting/wechat_qrcode.icohq9bcf.webp" alt="微信赞赏" height="260"/>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <img src="https://Hi-Jiajun.github.io/picx-images-hosting/alipay_qrcode.7p45v27tjq.webp" alt="支付宝赞赏" height="260"/>
</p>
<p align="center">
  <em>微信支付 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 支付宝</em>
</p>

---

## 📄 许可证

本项目使用 [Apache License 2.0](./LICENSE) 授权。

`src/plugins/pppox/pppd/` 中适配的 pppd 代码保留其原始 BSD 风格许可证，详见各源文件头部。
