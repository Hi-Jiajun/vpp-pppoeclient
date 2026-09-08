# 性能基准测试

> **测试日期**：2026-09-09
> **插件版本**：`v26.10-rc0~425-g3ee242713`（`feat/pr-pppoeclient` @ `8ca924fcb`）
> **测试性质**：短时摸底（5 秒量级），用于判断当前实现的性能量级；
> 完整稳定性与压力测试计划使用 TRex 进行。

## 1. 测试环境

| 角色 | 配置 |
|---|---|
| 宿主机 | Proxmox VE，测试 VM 122 |
| VM 122 | Ubuntu 24.04，8 vCPU，kernel 6.8 |
| 网卡 | Mellanox ConnectX-4 LX VF（10 GbE），DPDK 直通 VPP |
| VPP | v26.10-rc0，`main-core 0` + `corelist-workers 1-3`，DPDK |
| PPPoE 服务器 | MikroTik CHR 7.24.2（8 vCPU），`service-name vpp-test` |
| 打流端 | Windows 主机，iperf3 3.21 |
| MTU / MSS | 1492 / 1452 |

链路：Windows → CHR PPPoE Server → VM 122（VPP pppoeclient）。

## 2. 控制面（50 并发会话）

| 指标 | 当前版本 | 修复前（每接口 TX 节点泄漏） |
|---|---|---|
| 创建 50 条客户端（CLI） | 2–3 ms | ~98 ms |
| 删除 50 条客户端 | 3–4 ms | ~12 ms |
| 50 条会话全部建立 | ~1.09 s（≈46 会话/秒） | — |
| 每会话 VPP 堆内存 | ~20 KB（首次，含 pool 扩容）；~5 KB（稳态增量） | ~57 KB |
| 孤儿 graph node | 0 | 99（50 会话） |
| 共享节点名 | 重命名/删除后仍为 `pppoeclient-session-output` | 被改成 `pppoxN-output` |

> 说明：CLI 创建耗时是插件侧处理时间（约 0.06 ms/会话）；
> 端到端 46 会话/秒由 CHR 的 PADI/LCP/CHAP/IPCP 握手往返决定，不是插件瓶颈。

## 3. 数据面吞吐（5 秒短测，10G VF）

| 场景 | 结果 | 备注 |
|---|---|---|
| TCP 单流 | 8.06 Gbps | |
| TCP 单流反向 | 5.57 Gbps | 347 次重传 |
| TCP 4 流 | 9.23 Gbps | 接近 10G 线速 |
| TCP 4 流反向 | 7.83 Gbps | 2363 次重传 |
| UDP 1 Gbps | 999 Mbps，0% 丢包 | |
| UDP 5 Gbps（正向） | 实际 2.26 Gbps，0% 丢包 | 单线程收发限制 |
| UDP 5 Gbps（反向） | 3.90 Gbps，22% 丢包 | |
| UDP 10 Gbps（反向） | 4.17 Gbps，47% 丢包 | |

10G 网卡在 PPPoE + TCP/IP 开销下的实际可用吞吐约 9.4–9.5 Gbps，
4 流 TCP 9.23 Gbps 已达线速的 92–93%。

## 4. 单核转发极限（VPP packet-generator）

用已建立会话的 PPPoE 帧（114 字节）注入 `TenGigabitEthernet2/0/0`，
单个 worker 核 5 秒结果：

| 指标 | 结果 |
|---|---|
| 转发速率 | **27.78 Mpps/核** |
| `pppoeclient-dispatch` | 13.2 cycles/包 |
| `pppoeclient-session-input` | 23.2 cycles/包 |
| PPPoE 路径合计 | **36.4 cycles/包** |
| `ip4-input` + `ip4-lookup` | 8.2 + 8.6 cycles/包 |
| 完整 L3 路径 | ~53 cycles/包 |

## 5. CPU 占用

| 组件 | 8.7 Gbps（TCP 4 流）时 |
|---|---|
| RouterOS CHR（8 vCPU） | 13–15% 总计（ethernet 5.5–6.8%，bridging 4–5%，firewall 2.3–2.5%） |
| VM Linux 侧 | ~0.8 核 `sys` |
| VPP worker | DPDK 轮询模式，常态 ~100%；需用 cycles/packet 衡量真实开销 |

## 6. 这些数字是什么水平

- **27.78 Mpps/核**：10G 网卡跑满 64B 最小包需要 14.88 Mpps，单核约为其 1.9 倍；
  1500B 大包等效 330+ Gbps。普通 VPP IPv4 转发通常 20–40 Mpps/核，
  本插件处于同一量级，PPPoE 封装仅增加约 36 cycles/包。
- **36.4 cycles/包**：约 12 ns/包（3 GHz）。Linux 内核 rp-pppoe/pppd 单核通常
  1–2 Gbps，本实现约快 10–50 倍。
- **9.23 Gbps（TCP 4 流）**：10G 网卡实际可用上限约 9.4–9.5 Gbps，已达 92–93%，
  属于“10G 线速级”。
- **46 会话/秒（端到端）**：受 CHR 握手限制；插件自身约 16000 会话/秒
  （0.06 ms/会话），生产 BRAS 通常数百到数千新建/秒，插件侧有充足余量。
- **~20 KB/会话**：纯转发客户端很省内存；带 QoS/ACL/计费的商用 BRAS
  常见几百 KB 到 1 MB+/用户。

## 7. 说明与限制

- 本次为 5 秒短测，数据用于量级判断，不代表长期稳定性。
- 吞吐受限于 10G VF 与虚拟化路径；CHR 与 VM 共享同一台 PVE 宿主机。
- UDP 反向丢包主要来自接收端 iperf3 单线程，TCP 吞吐更能代表实际转发能力。
- 完整性能/稳定性测试计划使用 TRex，覆盖 64B–1500B 混合包长、长时间运行、
  会话震荡等场景。
