# phase_5_net.md

## 目标
- 规划 virtio-net 与协议栈适配路线与性能目标。

## 进展
- 新增 `axnet` 抽象与 `NetDevice`/`NetError` 基础接口，作为协议栈接入边界。
- 引入 virtio-net(mmio) 最小驱动：RX/TX 双队列、静态缓冲区、IRQ 触发完成确认。
- QEMU 脚本支持 `NET=1` 启用 virtio-net 设备，冒烟可检查 `virtio-net: ready`。
- 接入 smoltcp 协议栈：静态 IP `10.0.2.15/24`、默认网关 `10.0.2.2`，空闲循环驱动轮询。
- 增加 ARP probe 自检路径，启动后主动请求网关 MAC，记录 ARP Reply 以验证 RX/IRQ。
- 增加 ICMP Echo 请求路径，内核启动时尝试向网关发送 ping。
- 增加 socket 表与 TCP/UDP 基础 API，系统调用入口完成 socket/bind/connect/listen/accept/sendto/recvfrom。
- socket accept/send/recv 在阻塞模式下挂入 net 等待队列，poll 触发后唤醒重试。
- idle loop 切换到独立 idle stack，避免 boot stack 溢出导致 BSS 被污染。
- 修正 virtio-net 现代特性头部长度为 12 字节，并对齐 TX 缓冲区，ARP Reply 已可观测。

## 问题与定位
- QEMU user-net 下 ARP probe 已发送但 RX 帧未进入，定位为 virtio 现代特性头部长度不匹配导致帧损坏。

## 解决与验证
- `NET=1 EXPECT_NET=1 make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu`
- 日志包含 virtio-net ready、net: arp probe sent、net: arp reply from 10.0.2.2，ARP 路径恢复正常。
- 待协议栈接入后补充 ping/iperf/redis 基准验证。

## 下一步
- 接入轻量协议栈（ARP/IP/UDP/TCP）与 socket 语义。
- 追加 ping/iperf/redis 基准与稳定性回归。
