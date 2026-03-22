# VPP PPPoE Client 插件

[![Stars](https://img.shields.io/github/stars/Hi-Jiajun/vpp-pppoeclient?style=for-the-badge&logo=github&color=f4c542)](https://github.com/Hi-Jiajun/vpp-pppoeclient/stargazers)
[![Forks](https://img.shields.io/github/forks/Hi-Jiajun/vpp-pppoeclient?style=for-the-badge&logo=github&color=8cc751)](https://github.com/Hi-Jiajun/vpp-pppoeclient/network/members)
[![Issues](https://img.shields.io/github/issues/Hi-Jiajun/vpp-pppoeclient?style=for-the-badge&logo=github&color=ea6a5a)](https://github.com/Hi-Jiajun/vpp-pppoeclient/issues)
[![License](https://img.shields.io/github/license/Hi-Jiajun/vpp-pppoeclient?style=for-the-badge&color=5b9bd5)](./LICENSE)

[English](./README.md)

这个仓库是 [`Hi-Jiajun/vpp`](https://github.com/Hi-Jiajun/vpp) 的
[`feat/pr-pppoeclient`](https://github.com/Hi-Jiajun/vpp/tree/feat/pr-pppoeclient) 分支中
`pppoeclient` 与 `pppox` 两个插件目录的独立镜像仓库，方便单独查看、同步和集成 PPPoE
Client 相关代码，而不必维护整个 VPP 源码树。

## 概述

当前实现由两个插件组成：

| 插件 | 作用 |
| --- | --- |
| `pppoeclient` | 负责 PPPoE 发现、会话生命周期管理、会话查表、数据面封装与解封装 |
| `pppox` | 负责 PPP 控制面、认证、IPv4/IPv6 协商，以及移植自 `pppd` 的协议处理逻辑 |

两者配合后，可以在 VPP 用户态内实现完整的 PPPoE Client。

## 当前版本说明

本仓库目前同步自：

- 上游分支：`feat/pr-pppoeclient`
- 同步提交：`ee002b08dffaed8cf94a3b1f193619950ebbfca9`

当前代码相较于早期版本，主要包含这些能力：

- 完整支持 `PADI`、`PADO`、`PADR`、`PADS`、`PADT`
- 通过 `pppox` 控制面支持 PAP 和 CHAP 认证
- 支持 IPCP 获取 IPv4，支持 IPv6CP 获取 IPv6 链路信息
- 支持 `add-default-route4` 与 `add-default-route6` 分离控制
- 支持从 IPCP 获取 Peer DNS，并写入 `/etc/ppp/resolv.conf`
- 支持在会话已建立后动态同步认证、DNS、默认路由等配置
- `show pppoe client detail` 输出更完整，包含 AC-Name、PPPoX 接口、IPv4/IPv6 状态、DNS 等信息
- PPPoE Session 查表键包含入接口、AC MAC、Session ID，避免多会话场景冲突
- 处理 VLAN 子接口场景时可正确识别和构造二层 PPPoE 头
- 数据面仍包含 TCP MSS Clamp 逻辑

## 仓库结构

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

## 环境要求

- Linux
- 一套可编译的 VPP 源码树，当前主要按 VPP `26.02` 验证
- `cmake`、`ninja`、编译工具链
- 可用于 PPPoE 接入的下层接口

## 编译方式

### 方式一：直接使用完整 VPP 分支

```bash
git clone https://github.com/Hi-Jiajun/vpp.git -b feat/pr-pppoeclient
cd vpp
make install-dep
make build-release
```

### 方式二：将本仓库插件拷贝进现有 VPP 树

```bash
git clone https://github.com/Hi-Jiajun/vpp-pppoeclient.git
cp -r vpp-pppoeclient/src/plugins/pppoeclient /path/to/vpp/src/plugins/
cp -r vpp-pppoeclient/src/plugins/pppox /path/to/vpp/src/plugins/
cd /path/to/vpp
ninja -C build-root/build-vpp-native/vpp pppox_plugin pppoeclient_plugin vpp vppctl
```

## 启动 VPP

```bash
sudo vpp unix { nodaemon cli-listen /tmp/vpp-cli.sock } \
  dpdk { dev 0000:01:00.0 { name dpdk0 } } \
  plugins {
    plugin pppox_plugin.so { enable }
    plugin pppoeclient_plugin.so { enable }
  }
```

## 快速开始

```bash
# 1. 启用下层接口
set interface state dpdk0 up
set interface mtu packet 1500 dpdk0

# 2. 创建 PPPoE Client
create pppoe client sw-if-index 1 host-uniq 1234

# 3. 配置认证和选项
set pppoe client 0 username YOUR_USER password YOUR_PASS \
  mtu 1492 mru 1492 use-peer-dns add-default-route
```

如果运营商接入在 VLAN 子接口上，建议先在 VPP 中创建并启用对应子接口，再把 PPPoE Client 绑定到该
子接口的 `sw-if-index`。

## CLI 命令

### `pppoeclient`

```text
create pppoe client sw-if-index <nn> host-uniq <nn> [del]
show pppoe client
show pppoe client detail
set pppoe client <index> username <user> password <pass> \
  [mtu <n>] [mru <n>] [timeout <n>] \
  [use-peer-dns] [add-default-route | add-default-route4 | add-default-route6]
```

`set pppoe client` 支持的参数：

| 参数 | 说明 |
| --- | --- |
| `mtu <n>` | PPP MTU |
| `mru <n>` | PPP MRU |
| `timeout <n>` | PPP 超时值 |
| `use-peer-dns` | 接收 IPCP 下发的 DNS，并写入 `/etc/ppp/resolv.conf` |
| `add-default-route` | 同时启用 IPv4 和 IPv6 默认路由 |
| `add-default-route4` | 仅启用 IPv4 默认路由 |
| `add-default-route6` | 仅启用 IPv6 默认路由 |

补充说明：

- `use-peer-route` 仍然保留为兼容别名，等价于同时开启 IPv4/IPv6 默认路由。
- 对已存在的客户端再次执行 `set pppoe client ...` 时，会尝试把变更同步到正在运行的 PPPoX 会话。

### `pppox`

控制面插件还提供了一个直接设置认证信息的 CLI：

```text
pppox set auth sw-if-index <nn> username <string> password <string>
```

通常 PPPoE Client 场景下，直接使用 `set pppoe client` 即可。

## 常见配置示例

### 同时启用 IPv4 / IPv6 默认路由

```bash
set pppoe client 0 username USER password PASS add-default-route
```

### 仅启用 IPv4 默认路由

```bash
set pppoe client 0 username USER password PASS add-default-route4
```

### 仅启用 IPv6 默认路由

```bash
set pppoe client 0 username USER password PASS add-default-route6
```

### PPP 建立后继续跑 DHCPv6-PD

```bash
dhcp6 client pppox0
dhcp6 pd client pppox0 prefix group wan-pd
set ip6 address pppox0 prefix group wan-pd ::1/64
```

## 运行与排障

常用查看命令：

```bash
show pppoe client
show pppoe client detail
show interface
show ip fib table 0
show ip6 fib
```

当前版本的 `show pppoe client detail` 重点会展示：

- Client 当前状态与 PPPoE Session ID
- 学到的 AC MAC 和 AC-Name
- 关联的 PPPoX 接口与 PPP 单元号
- 协商得到的 IPv4 本端 / 对端地址
- IPv6 本端 / 对端地址、来源信息、默认路由状态
- Peer DNS 地址
- 当前认证用户、MTU/MRU、超时、路由和 DNS 开关

## Binary API

当前仓库中的 API 文件包括：

- `src/plugins/pppoeclient/pppoeclient.api`
- `src/plugins/pppox/pppox.api`

当前暴露的消息主要有：

- `pppoeclient_add_del`
- `pppoeclient_dump`
- `pppox_set_auth`

其中 `pppoeclient_dump` 当前返回的重点是客户端 `sw_if_index` 与 `host_uniq`。如果要看更完整的运行时
状态，CLI 仍然是最直接的方式。

## 参考资料

- [FD.io VPP](https://github.com/FDio/vpp)
- [Hi-Jiajun/vpp](https://github.com/Hi-Jiajun/vpp/tree/feat/pr-pppoeclient)
- [pppd](https://ppp.samba.org/)
- [RaydoNetworks/ppp-vpp](https://github.com/pppoe/ppp-vpp)
- [RFC 2516](https://www.rfc-editor.org/rfc/rfc2516)
- [RFC 1661](https://www.rfc-editor.org/rfc/rfc1661)
- [RFC 1332](https://www.rfc-editor.org/rfc/rfc1332)
- [RFC 5072](https://www.rfc-editor.org/rfc/rfc5072)

## 支持

如果这个项目对你有帮助，欢迎支持。

| 微信支付 | 支付宝 |
| --- | --- |
| <img src="https://Hi-Jiajun.github.io/picx-images-hosting/wechat_qrcode.icohq9bcf.webp" height="260" alt="微信支付收款码"> | <img src="https://Hi-Jiajun.github.io/picx-images-hosting/alipay_qrcode.7p45v27tjq.webp" height="260" alt="支付宝收款码"> |

## 许可证

本项目采用 [Apache License 2.0](./LICENSE)。

`src/plugins/pppox/pppd/` 目录下移植的 `pppd` 代码，仍保留各源文件头部中的原始 BSD 风格许可证说明。
