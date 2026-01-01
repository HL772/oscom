# 07_net.md

## 目标
- 支持 virtio-net 驱动与基础 TCP/IP 协议栈接入。
- 提供统一的 NetDevice 接口给上层 socket/网络服务。
- 兼顾吞吐与稳定性，满足 OSComp 网络测例。

## 设计
- virtio-net 驱动提供 `rx/tx` 环形队列与中断通知。
- 网络协议栈优先采用轻量实现（如 smoltcp 思路），接口隔离便于替换。
- `NetDevice` 负责提交/接收包缓冲，协议栈负责协议解析与重组。
- 优先减少拷贝：驱动 DMA 缓冲与协议栈 PacketBuffer 复用。
- 网络定时器与重传计时统一依赖 `time` 模块。
- 先落地最小 `axnet` 抽象与 virtio-net RAW 帧读写，协议栈后续接入。
- smoltcp 接入使用静态地址配置（QEMU user-net: 10.0.2.15/24, gw 10.0.2.2），轮询在空闲上下文触发。
- 对本机 IPv4 目的地址的发送帧进行 loopback 注入，支持单机 TCP 自测。
- `sockaddr_in` 解析严格按网络字节序处理，避免用户态传参导致目标地址反转。
- 连接进行中保持 net poll，避免缺中断时 TCP 建连停滞。
- 启动后发送一次 ARP probe 探测网关，收到应答即认为 RX/IRQ 路径可用。
- socket 就绪判定通过 `SocketTable` 的监听标记区分 `accept` 与 `recv` 语义，`poll/ppoll` 走统一判定入口。
- TCP loopback 自测使用内核内置 loopback 设备，避免依赖外部网络环境。

## 关键数据结构
- `NetDevice`：网卡设备抽象（send/recv/irq）。
- `PacketBuffer`：包缓冲与引用计数。
- `SocketTable`：socket 句柄管理与 fd 映射。
- `SocketSlot`：记录 socket 句柄、端口与是否处于监听状态。
- `NetConfig`：IP/网关/掩码等配置。
- `VirtioNetQueue`：virtio-net 描述符/avail/used 队列。

## 关键流程图或伪代码
```text
rx_irq
  -> driver.rx()
  -> protocol_stack.poll()
  -> socket_ready()
  -> wake(net_waiters)

socket_read(fd)
  -> dequeue packet
  -> copy to user buffer
```

## 风险与权衡
- 协议栈与驱动缓冲区不一致会引入额外拷贝与延迟。
- 高吞吐下中断风暴需要 NAPI/轮询策略缓解。
- 与用户态 socket 语义对齐需要较多细节处理。

## 测试点
- 基础连通性：ping/UDP echo。
- TCP 建连与收发：iperf 基准。
- TCP loopback：`NET=1 NET_LOOPBACK_TEST=1 make test-qemu-smoke` 观察 `net: tcp loopback ok`。
- 用户态 TCP echo：`NET=1 TCP_ECHO_TEST=1 make test-qemu-smoke` 观察 `tcp-echo: ok`（覆盖 socket syscall 路径）。
- 用户态 UDP echo：`NET=1 UDP_ECHO_TEST=1 make test-qemu-smoke` 观察 `udp-echo: ok`（覆盖 datagram syscall 路径）。
- 应用层：git clone/push、redis 基本命令回归。
- QEMU: `NET=1 EXPECT_NET=1 make test-qemu-smoke` 检查 virtio-net ready + ARP reply。
