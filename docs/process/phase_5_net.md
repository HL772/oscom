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
- 完善 TCP accept/recv/send 语义：监听标记区分 accept/read 语义，poll/ppoll 走 socket 就绪判定。
- 增加 TCP loopback 自测路径（内核 loopback 设备），冒烟测试可验证 accept/recv/send 语义。
- 为本机 IPv4 目的地址注入 loopback 队列，支持用户态 `/tcp_echo` 单机互连。
- 新增用户态 TCP echo 程序 `/tcp_echo`，冒烟测试可覆盖 socket syscall 端到端路径。
- TCP echo 增加非阻塞 connect + ppoll + SO_ERROR 校验，覆盖 EINPROGRESS 与连接完成语义。
- TCP echo 增加连接失败路径验证（本地无监听端口），校验 SO_ERROR 映射为 ConnRefused/NetUnreach。
- sys_connect 在 POLLHUP 时回读 socket error（若存在）并映射到 Errno，完善失败错误码一致性。
- TCP echo 使用 sendmsg/recvmsg + iovec 分段收发，覆盖 stream 聚散 I/O 路径。
- TCP echo 覆盖 getsockname/getpeername 地址回读，验证本地/对端端口一致性。
- 新增用户态 UDP echo 程序 `/udp_echo`，冒烟测试可覆盖 datagram send/recv 路径。
- 修正 `sockaddr_in` 地址解析的网络字节序处理，避免本机连接被解析成错误 IP。
- 连接中（SYN 期间）持续触发 net poll，避免无中断场景下 connect 卡死。
- idle loop 切换到独立 idle stack，避免 boot stack 溢出导致 BSS 被污染。
- 修正 virtio-net 现代特性头部长度为 12 字节，并对齐 TX 缓冲区，ARP Reply 已可观测。
- 增加 getsockname/getpeername 与 SO_ERROR/setsockopt/shutdown 最小实现，补齐用户态 socket 语义。
- 支持 SO_RCVTIMEO/SO_SNDTIMEO 并在 send/recv/accept 阻塞路径中应用超时。
- sys_connect 在阻塞模式下遵循 SO_SNDTIMEO 超时设置。
- 增加 sendmsg/recvmsg 最小实现，支持 iovec 聚散发送与接收。
- 增加 sendmmsg/recvmmsg 批量收发支持，UDP 自测覆盖多包路径。
- UDP 自测补充 SO_RCVTIMEO 超时校验，覆盖超时错误码路径。
- UDP 自测覆盖 SO_SNDTIMEO get/set 校验，验证超时选项的回读一致性。
- 增加 `scripts/net_baseline.sh`，串行执行 net/net-loopback/tcp-echo/udp-echo 并归档日志。
- 增加 `scripts/net_perf_baseline.sh` 与 `docs/process/net_perf_baseline_template.md`，用于记录 iperf3/redis 基线。
- 增加用户态 `apps/net_bench` 作为性能基线临时 /init，支持 TCP 吞吐接收与字节统计输出。
- 使用 `net_bench` 完成 net-perf 脚本闭环验证，记录见 `docs/process/net_perf_baseline_2026-01-01.md`。
- 增加 `scripts/net_perf_send.py` 作为 hostfwd 发送端，补齐 net-perf 吞吐注入路径。
- `net_bench` 增加 8 字节长度头协议，保证吞吐统计稳定输出。
- TCP 接收后触发 net poll，避免窗口更新停滞导致大包吞吐卡住。
- sys_recvfrom 在 TCP 收包后主动触发 poll，保证长流量场景持续推进。
- 增加周期性 net poll（idle/tick）并记录 TCP recv window 变化，64K 基线通过；1MiB 需提高 TIMEOUT 以完成。
- net-perf 支持 PERF_QEMU_TIMEOUT 直传 QEMU 超时，避免大流量基准被 5s 超时截断。

## 问题与定位
- QEMU user-net 下 ARP probe 已发送但 RX 帧未进入，定位为 virtio 现代特性头部长度不匹配导致帧损坏。

## 解决与验证
- `NET=1 EXPECT_NET=1 make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu`
- `NET=1 TCP_ECHO_TEST=1 EXPECT_TCP_ECHO=1 make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu`
- 日志包含 virtio-net ready、net: arp probe sent、net: arp reply from 10.0.2.2，ARP 路径恢复正常。
- 日志包含 `tcp-echo: ok`，用户态 TCP echo 覆盖 connect/accept/send/recv 路径。
- 调试过程与根因分析记录：`docs/process/debug_report_virtio_net_arp.md`，`docs/process/debug_report_tcp_echo.md`。
- 待协议栈接入后补充 ping/iperf/redis 基准验证。
- net-perf 基线临时以 `net_bench` 验证脚本闭环，后续替换为 iperf3/redis。

## 下一步
- 接入轻量协议栈（ARP/IP/UDP/TCP）与 socket 语义。
- 追加 ping/iperf/redis 基准与稳定性回归。
