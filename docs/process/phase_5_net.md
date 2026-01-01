# phase_5_net.md

## 目标
- 规划 virtio-net 与协议栈适配路线与性能目标。

## 进展
- 新增 `axnet` 抽象与 `NetDevice`/`NetError` 基础接口，作为协议栈接入边界。
- 引入 virtio-net(mmio) 最小驱动：RX/TX 双队列、静态缓冲区、IRQ 触发完成确认。
- QEMU 脚本支持 `NET=1` 启用 virtio-net 设备，冒烟可检查 `virtio-net: ready`。

## 问题与定位
- 当前为驱动落地阶段，尚未发现阻断性问题。

## 解决与验证
- `NET=1 EXPECT_NET=1 make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu`
- 待协议栈接入后补充 ping/iperf/redis 基准验证。

## 下一步
- 接入轻量协议栈（ARP/IP/UDP/TCP）与 socket 语义。
- 追加 ping/iperf/redis 基准与稳定性回归。
