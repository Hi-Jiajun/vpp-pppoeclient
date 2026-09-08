# Performance Benchmarks

> **Date**: 2026-09-09
> **Plugin version**: `v26.10-rc0~425-g3ee242713` (`feat/pr-pppoeclient` @ `8ca924fcb`)
> **Scope**: short 5-second smoke benchmarks to establish the performance class;
> full stability and stress testing will be done with TRex.

## 1. Environment

| Role | Configuration |
|---|---|
| Hypervisor | Proxmox VE, test VM 122 |
| VM 122 | Ubuntu 24.04, 8 vCPU, kernel 6.8 |
| NIC | Mellanox ConnectX-4 LX VF (10 GbE), passed through to VPP via DPDK |
| VPP | v26.10-rc0, `main-core 0` + `corelist-workers 1-3`, DPDK |
| PPPoE server | MikroTik CHR 7.24.2 (8 vCPU), `service-name vpp-test` |
| Traffic source | Windows host, iperf3 3.21 |
| MTU / MSS | 1492 / 1452 |

Path: Windows → CHR PPPoE server → VM 122 (VPP pppoeclient).

## 2. Control plane (50 concurrent sessions)

| Metric | Current | Before the per-interface TX node fix |
|---|---|---|
| Create 50 clients (CLI) | 2–3 ms | ~98 ms |
| Delete 50 clients | 3–4 ms | ~12 ms |
| Establish all 50 sessions | ~1.09 s (≈46 sessions/s) | — |
| VPP heap per session | ~20 KB first time (incl. pool growth); ~5 KB steady-state | ~57 KB |
| Orphan graph nodes | 0 | 99 (50 sessions) |
| Shared node name | stays `pppoeclient-session-output` after rename/delete | renamed to `pppoxN-output` |

> The CLI create time is plugin-side processing (~0.06 ms/session).
> The end-to-end 46 sessions/s is limited by the CHR PADI/LCP/CHAP/IPCP
> handshake round trips, not by the plugin.

## 3. Dataplane throughput (5 s, 10G VF)

| Scenario | Result | Notes |
|---|---|---|
| TCP single stream | 8.06 Gbps | |
| TCP single stream reverse | 5.57 Gbps | 347 retransmits |
| TCP 4 streams | 9.23 Gbps | near 10G line rate |
| TCP 4 streams reverse | 7.83 Gbps | 2363 retransmits |
| UDP 1 Gbps | 999 Mbps, 0% loss | |
| UDP 5 Gbps forward | 2.26 Gbps actual, 0% loss | single-thread send/receive limit |
| UDP 5 Gbps reverse | 3.90 Gbps, 22% loss | |
| UDP 10 Gbps reverse | 4.17 Gbps, 47% loss | |

With PPPoE and TCP/IP overhead, a 10G NIC delivers about 9.4–9.5 Gbps of
goodput; 9.23 Gbps over 4 TCP streams is 92–93% of line rate.

## 4. Single-core limit (VPP packet generator)

A 114-byte PPPoE session frame injected on `TenGigabitEthernet2/0/0` for
5 seconds on one worker core:

| Metric | Result |
|---|---|
| Forwarding rate | **27.78 Mpps/core** |
| `pppoeclient-dispatch` | 13.2 cycles/packet |
| `pppoeclient-session-input` | 23.2 cycles/packet |
| PPPoE path total | **36.4 cycles/packet** |
| `ip4-input` + `ip4-lookup` | 8.2 + 8.6 cycles/packet |
| Full L3 path | ~53 cycles/packet |

## 5. CPU usage

| Component | At 8.7 Gbps (TCP 4 streams) |
|---|---|
| RouterOS CHR (8 vCPU) | 13–15% total (ethernet 5.5–6.8%, bridging 4–5%, firewall 2.3–2.5%) |
| VM Linux side | ~0.8 core `sys` |
| VPP workers | DPDK poll mode, ~100% by design; use cycles/packet for real cost |

## 6. What these numbers mean

- **27.78 Mpps/core**: a 10G NIC needs 14.88 Mpps for minimum-size 64B frames,
  so one core handles ~1.9x that; at 1500B it is equivalent to 330+ Gbps.
  Plain VPP IPv4 forwarding is typically 20–40 Mpps/core, so the plugin is in
  the same class; PPPoE encapsulation adds only ~36 cycles/packet.
- **36.4 cycles/packet**: about 12 ns/packet at 3 GHz. Linux kernel
  rp-pppoe/pppd typically tops out at 1–2 Gbps on one core; this is roughly
  10–50x faster.
- **9.23 Gbps (TCP 4 streams)**: 92–93% of the ~9.4–9.5 Gbps goodput ceiling
  of a 10G NIC — effectively 10G line rate.
- **46 sessions/s end-to-end**: limited by the CHR handshake; the plugin itself
  can do ~16,000 sessions/s (0.06 ms/session). Production BRAS platforms
  usually handle hundreds to thousands of new sessions/s, so the plugin has
  plenty of headroom.
- **~20 KB/session**: lean for a pure forwarding client; commercial BRAS
  platforms with QoS/ACL/accounting commonly use hundreds of KB to 1 MB+ per
  subscriber.

## 7. Caveats

- These are 5-second smoke tests, useful for orders of magnitude, not for
  long-term stability claims.
- Throughput is capped by the 10G VF and the virtualization path; the CHR and
  the VM share the same PVE host.
- UDP reverse loss is dominated by the single-threaded iperf3 receiver; TCP
  throughput is the better indicator of forwarding capability.
- Full performance/stability testing with TRex is planned, covering 64B–1500B
  mixed packet sizes, long runs, and session churn.
