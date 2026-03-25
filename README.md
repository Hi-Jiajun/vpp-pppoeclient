# 🚀 VPP PPPoE Client 插件

[![stars](https://img.shields.io/github/stars/Hi-Jiajun/vpp-pppoeclient?style=flat-square&logo=github&label=stars)](https://github.com/Hi-Jiajun/vpp-pppoeclient/stargazers)
[![forks](https://img.shields.io/github/forks/Hi-Jiajun/vpp-pppoeclient?style=flat-square&logo=github&label=forks)](https://github.com/Hi-Jiajun/vpp-pppoeclient/network/members)
[![issues](https://img.shields.io/github/issues/Hi-Jiajun/vpp-pppoeclient?style=flat-square&logo=github&label=issues)](https://github.com/Hi-Jiajun/vpp-pppoeclient/issues)
[![license](https://img.shields.io/github/license/Hi-Jiajun/vpp-pppoeclient?style=flat-square&label=license)](./LICENSE)

> 这是从 [`Hi-Jiajun/vpp`](https://github.com/Hi-Jiajun/vpp/tree/feat/pr-pppoeclient) 中拆分出来的
> `pppoeclient` 和 `pppox` 插件独立镜像仓库，专注于 FD.io VPP 下的 PPPoE Client 能力。

🌏 [English README](./README_EN.md)

---

## ✨ 项目概述

这个仓库把 PPPoE Client 相关插件从完整 VPP Fork 中单独抽离出来，方便独立查看、同步、集成和维护，
不需要每次都处理完整的 VPP 源码树。

当前实现由两个插件组成：

| 插件 | 作用 |
| --- | --- |
| `pppoeclient` | 负责 PPPoE 发现、会话生命周期管理、会话查表、数据面封装与解封装 |
| `pppox` | 负责 PPP 控制面、认证、IPv4/IPv6 协商，以及移植自 `pppd` 的协议处理逻辑 |

两者组合后，可以在 VPP 用户态中实现完整的 PPPoE Client。

## 📌 当前同步状态

- 🌿 上游分支：`feat/pr-pppoeclient`
- 🔖 当前同步的上游提交：`0ebbd46e8771257ca9462277e966f948f90e9343`

## 🔄 同步上游

这个仓库已经可以把上游 VPP Fork 中“只和本项目相关”的目录同步下来，范围固定为：

- `src/plugins/pppoeclient`
- `src/plugins/pppox`

仓库里已经支持 `upstream` 远端：

- `upstream`: `https://github.com/Hi-Jiajun/vpp.git`

也提供了一键同步脚本：

- [scripts/sync-from-upstream.ps1](./scripts/sync-from-upstream.ps1)
- [scripts/sync-from-upstream.sh](./scripts/sync-from-upstream.sh)

在 PowerShell 中运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\sync-from-upstream.ps1
```

这个脚本会：

- 自动检查并补充 `upstream` 远端
- 拉取 `feat/pr-pppoeclient`
- 稀疏克隆上游仓库，只取插件相关目录
- 镜像同步 `src/plugins/pppoeclient` 和 `src/plugins/pppox`
- 输出本次同步对应的上游 commit

在 Linux / macOS 中运行：

```bash
chmod +x ./scripts/sync-from-upstream.sh
./scripts/sync-from-upstream.sh
```

只检查是否与上游一致，不改本地文件：

```bash
./scripts/sync-from-upstream.sh --check
```

## 🤖 自动检查

仓库新增了 GitHub Action：

- `.github/workflows/check-upstream-sync.yml`

它会在这些场景自动检查当前仓库中的插件目录是否仍与上游一致：

- 手动触发
- 每天定时检查
- 涉及插件目录、同步脚本或工作流本身的 `push` / `pull_request`

如果检测到 [src/plugins/pppoeclient](./src/plugins/pppoeclient) 或 [src/plugins/pppox](./src/plugins/pppox)
与上游 `feat/pr-pppoeclient` 不一致，Action 会失败。

## 🚀 自动发布 Release

仓库还新增了自动发布工作流：

- `.github/workflows/auto-release.yml`

它会在 `master` 分支有项目相关更新时自动创建 GitHub Release，触发范围包括：

- `src/plugins/pppoeclient/**`
- `src/plugins/pppox/**`
- `README.md`
- `README_EN.md`
- `scripts/**`

当前预编译包默认针对官方 `FDio/vpp` 的“最新稳定 tag”：

- workflow 会自动探测最新稳定 tag
- 也可以在手动触发 workflow 时显式指定 `vpp_ref`

发布规则：

- 每个提交按短 SHA 自动生成一个 tag，例如 `auto-da21b11`
- 同一个提交如果已经发过 Release，就不会重复创建
- Release 会自动指向对应提交并附带自动生成的说明
- Release 会自动上传这几类预编译包：
  - Debian / Ubuntu 用的 `.deb`
  - RPM 系列发行版用的 `.rpm`
- 当前矩阵包括：
  - Ubuntu 24.04
  - Debian 12
  - Rocky Linux 9
- 预编译 workflow 拉取的是官方仓库：
  - `https://github.com/FDio/vpp.git`
- 预编译 workflow 在未手工指定时，会自动解析官方最新稳定 tag
- 这些包包含预编译插件二进制和 API JSON：
  - `pppoeclient_plugin.so`
  - `pppox_plugin.so`
  - `pppoeclient.api.json`
  - `pppox.api.json`
- 安装后插件文件会落到系统 VPP 常用目录，例如：
  - Debian / Ubuntu: `/usr/lib/x86_64-linux-gnu/vpp_plugins`
  - RPM 系列: `/usr/lib64/vpp_plugins`
- 如果你不想使用预编译包，也可以直接按本文档中的源码方式拷贝到 VPP 树中编译

## 🧩 当前版本亮点

- 🔄 完整支持 `PADI`、`PADO`、`PADR`、`PADS`、`PADT`
- 🔐 通过 `pppox` 控制面支持 PAP 和 CHAP 认证
- 🌐 支持 IPCP 获取 IPv4，支持 IPv6CP 获取 IPv6
- 🛣️ 支持 `add-default-route4` 和 `add-default-route6` 分离控制
- 🧭 支持从 IPCP 获取 Peer DNS，并写入 `/etc/ppp/resolv.conf`
- 🔁 支持会话建立后动态同步认证、DNS、默认路由等配置
- 🧪 `show pppoe client detail` 输出更完整，便于排障
- 🧱 PPPoE Session 查表键包含入接口、AC MAC、Session ID
- 🏷️ 支持 VLAN 子接口场景下的 PPPoE 二层头处理
- 📏 数据面仍保留 TCP MSS Clamp 逻辑

## 🗂️ 仓库结构

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

## 🛠️ 环境要求

- Linux
- 一套可编译的 VPP 源码树，当前主要按 VPP `26.02` 验证
- `cmake`、`ninja` 和可用的编译工具链
- 可用于 PPPoE 接入的下层接口

## 📦 编译方式

### 方式一：直接使用完整 VPP Fork

```bash
git clone https://github.com/Hi-Jiajun/vpp.git -b feat/pr-pppoeclient
cd vpp
make install-dep
make build-release
```

### 方式二：把本仓库插件拷贝进现有 VPP 树

```bash
git clone https://github.com/Hi-Jiajun/vpp-pppoeclient.git
cp -r vpp-pppoeclient/src/plugins/pppoeclient /path/to/vpp/src/plugins/
cp -r vpp-pppoeclient/src/plugins/pppox /path/to/vpp/src/plugins/
cd /path/to/vpp
ninja -C build-root/build-vpp-native/vpp pppox_plugin pppoeclient_plugin vpp vppctl
```

## ▶️ 启动 VPP

```bash
sudo vpp unix { nodaemon cli-listen /tmp/vpp-cli.sock } \
  dpdk { dev 0000:01:00.0 { name dpdk0 } } \
  plugins {
    plugin pppox_plugin.so { enable }
    plugin pppoeclient_plugin.so { enable }
  }
```

## ⚡ 快速开始

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

💡 如果运营商接入跑在 VLAN 子接口上，建议先在 VPP 里创建并启用对应子接口，再把 PPPoE Client
绑定到那个子接口的 `sw-if-index`。

## 🧭 CLI 命令参考

### `pppoeclient`

```text
create pppoe client sw-if-index <nn> host-uniq <nn> [del]
show pppoe client
show pppoe client detail
set pppoe client <index> username <user> password <pass> \
  [mtu <n>] [mru <n>] [timeout <n>] \
  [use-peer-dns] [add-default-route | add-default-route4 | add-default-route6]
```

#### `set pppoe client` 参数说明

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

- `use-peer-route` 仍然保留为兼容别名，等价于同时开启 IPv4 和 IPv6 默认路由。
- 对已存在的客户端再次执行 `set pppoe client ...` 时，会尝试把变更同步到正在运行的 PPPoX 会话。

### `pppox`

控制面插件还提供了一个直接设置认证信息的 CLI：

```text
pppox set auth sw-if-index <nn> username <string> password <string>
```

通常 PPPoE Client 场景下，直接使用 `set pppoe client` 配置账号密码即可。

## 🧪 常见配置场景

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

## 🔍 运行与排障

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
- 协商得到的 IPv4 本端和对端地址
- IPv6 本端和对端信息，以及地址来源说明
- Peer DNS 地址
- 当前认证、MTU/MRU、超时和默认路由相关开关

## 📈 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Hi-Jiajun/vpp-pppoeclient&type=Date)](https://star-history.com/#Hi-Jiajun/vpp-pppoeclient&Date)

## 🔌 Binary API

当前仓库中的 API 定义文件包括：

- `src/plugins/pppoeclient/pppoeclient.api`
- `src/plugins/pppox/pppox.api`

目前定义的请求和回复消息包括：

- `pppoeclient_add_del`
- `pppoeclient_add_del_reply`
- `pppoeclient_dump`
- `pppoeclient_details`
- `pppox_set_auth`
- `pppox_set_auth_reply`

补充说明：

- `pppoeclient_dump` 会触发发送 `pppoeclient_details`
- `pppoeclient_details` 当前只携带 `sw_if_index` 和 `host_uniq`
- 如果要看更完整的运行时状态，CLI 仍然是最直接的方式

## 📚 参考资料

- [FD.io VPP](https://github.com/FDio/vpp)
- [Hi-Jiajun/vpp](https://github.com/Hi-Jiajun/vpp/tree/feat/pr-pppoeclient)
- [pppd](https://ppp.samba.org/)
- [raydonetworks/vpp-pppoeclient](https://github.com/raydonetworks/vpp-pppoeclient) - 该插件的初版公开仓库
- [RFC 2516](https://www.rfc-editor.org/rfc/rfc2516)
- [RFC 1661](https://www.rfc-editor.org/rfc/rfc1661)
- [RFC 1332](https://www.rfc-editor.org/rfc/rfc1332)
- [RFC 5072](https://www.rfc-editor.org/rfc/rfc5072)

## 💖 支持

如果这个项目对你有帮助，欢迎支持。

| 微信支付 | 支付宝 |
| --- | --- |
| <img src="https://Hi-Jiajun.github.io/picx-images-hosting/wechat_qrcode.icohq9bcf.webp" height="260" alt="微信支付收款码"> | <img src="https://Hi-Jiajun.github.io/picx-images-hosting/alipay_qrcode.7p45v27tjq.webp" height="260" alt="支付宝收款码"> |

## 📄 许可证

本项目采用 [Apache License 2.0](./LICENSE)。

`src/plugins/pppox/pppd/` 目录下移植的 `pppd` 代码，仍保留各源文件头部中的原始 BSD 风格许可证说明。
