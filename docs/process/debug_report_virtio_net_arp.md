# VirtIO-Net ARP 接收故障调试报告

## 1. 问题概述

在实现 ARP 自测流程时，系统能够成功发送 ARP Probe 包并触发 TX 中断，但无法接收网关（10.0.2.2）回复的 ARP Reply 包。

- 症状：日志显示 `net: arp probe sent` 和 TX 相关 IRQ（Used Ring 更新），但没有 RX 帧到达的日志。
- 初步判断：TX 路径正常，RX 路径存在问题，设备无法将数据写入驱动提供的接收缓冲区，或驱动无法正确读取已接收的数据。

## 2. 调试与排查过程

### 阶段一：初始化时序调整

- 尝试：将填充 RX 描述符和通知的逻辑移到 `DRIVER_OK` 之后。
- 理由：VirtIO 规范要求驱动在 `DRIVER_OK` 之前不得通知设备。
- 结果：失败，现象依旧。

### 阶段二：缓冲区对齐与内存类型

- 尝试：将 RX 缓冲区从 `static mut` 字节数组（BSS 段）改为 `#[repr(align(16))]`，随后升级为 `align(4096)`。
- 理由：VirtIO/DMA 对缓冲区地址对齐有要求；静态数组可能跨页或存在缓存一致性问题。
- 结果：失败。

### 阶段三：动态页分配与物理地址验证

- 尝试：改用 `mm::alloc_frame()` 为每个 RX 描述符分配独立 4K 页，并维护 `RX_BUFFER_PTRS` 表记录物理地址。
- 理由：确保缓冲区物理连续、页对齐，且位于有效内存区域。
- 结果：失败。但日志确认分配的物理地址（如 `0x8052c000`）有效。

### 阶段四：严格遵循初始化规范（Pre-fill）

- 尝试：重构初始化流程为 Pre-fill RX -> 设置 `DRIVER_OK` -> Notify，并增加 `STATUS_FAILED` 检查。
- 理由：避免设备在 `DRIVER_OK` 时看到空的 Avail Ring。
- 结果：失败，但排除设备拒绝配置的可能性（`STATUS_FAILED` 未置位）。

### 阶段五：协议头长度匹配（根因发现）

- 分析：驱动协商了 `VIRTIO_F_VERSION_1`（VirtIO Modern）特性。
- 发现：Modern 设备头部是 12 字节，但代码使用了 Legacy 的 10 字节头部。
- 后果：驱动将 `num_buffers` 的 2 字节当作以太网帧内容，导致 MAC 地址解析错误，ARP Reply 被静默丢弃。
- 修复：将 `VIRTIO_NET_HDR_LEN` 修改为 12。

## 3. 根因分析

根因是 VirtIO 头部长度不匹配：

- Legacy 头部长度为 10 字节。
- Modern 头部长度为 12 字节（`virtio_net_hdr_mrg_rxbuf`）。

由于协商了 `VIRTIO_F_VERSION_1`，设备按 12 字节头部写入。驱动仍以 10 字节偏移解析，导致以太网帧被破坏，ARP Reply 被丢弃。

## 4. 最终解决方案

关键修复点如下：

1. 修正头部长度：

```rust
const VIRTIO_NET_HDR_LEN: usize = 12;
```

2. 保留最佳实践：

- 使用 `mm::alloc_frame()` 分配 4K 对齐的 RX 缓冲区。
- 使用 Pre-fill -> `DRIVER_OK` -> Notify 的初始化顺序。
- 清理调试过程中引入的临时日志。

## 5. 验证结果

执行冒烟测试：

```bash
NET=1 EXPECT_NET=1 make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu
```

结果：通过。日志中出现以下关键行：

- `virtio-net: ready mac=52:54:00:12:34:56`
- `net: arp probe sent to 10.0.2.2`
- `net: arp reply from 10.0.2.2`

结论：ARP 双向收发路径恢复正常。
