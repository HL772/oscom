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

## 关键数据结构
- `NetDevice`：网卡设备抽象（send/recv/irq）。
- `PacketBuffer`：包缓冲与引用计数。
- `SocketTable`：socket 句柄管理与 fd 映射。
- `NetConfig`：IP/网关/掩码等配置。
- `VirtioNetQueue`：virtio-net 描述符/avail/used 队列。

## 关键流程图或伪代码
```text
rx_irq
  -> driver.rx()
  -> protocol_stack.poll()
  -> socket_ready()

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
- 应用层：git clone/push、redis 基本命令回归。
