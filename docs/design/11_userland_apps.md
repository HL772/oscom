# 11_userland_apps.md

## 目标
- 明确 iperf3/redis 等用户态应用的适配路线与依赖清单。
- 建立“系统调用覆盖矩阵”，驱动内核兼容性优先级。
- 为 net-perf 进入真实应用基线做好构建与打包准备。

## 设计
- 分阶段推进：
  1) 调用面分析：在 host 侧用 `strace` 记录 iperf3/redis 的 syscall 序列（无网络场景下可用 `--help`/本地回环）。
  2) 覆盖矩阵：将 syscall 归类为必须/可选/替代路径，输出表格。
  3) 最小 libc 策略：优先静态链接（musl），避免动态加载器依赖；需在引入前评估工具链与许可。
  4) 运行时适配：补齐 `mmap/munmap/mprotect`、`epoll`/`eventfd`/`clock_*` 等关键 syscall。
  5) 打包：提供 `scripts/build_iperf3.sh`/`scripts/build_redis.sh` 与 rootfs 复制规则。
- DNS/配置依赖：优先使用 IP 直连，避免依赖 `/etc/resolv.conf` 与复杂 NSS。
- 网络测试：iperf3 作为吞吐基线，redis 作为请求/响应基线（get/set、pipeline）。

## 覆盖矩阵（待填充）
| syscall | iperf3 | redis | 备注 |
| --- | --- | --- | --- |
| read/write/open/close | - | - | 基础 I/O |
| socket/connect/bind/listen/accept | - | - | 网络核心路径 |
| mmap/munmap/mprotect | - | - | 内存映射 |
| epoll/eventfd/timerfd | - | - | 事件与定时器 |
| futex/clone | - | - | 线程/同步 |
| clock_gettime/nanosleep | - | - | 时间 |

## 采集状态
- 当前主机未检测到 `strace`/`iperf3`/`redis-server`，需要安装后再生成覆盖矩阵。
- 采集脚本：`scripts/collect_syscall_matrix.sh`。

## 关键数据结构
- `SyscallCoverageMatrix`：记录 syscall -> 状态/风险/测试点。
- `AppProfile`：每个应用的构建方式、依赖与运行参数。
- `RootfsRecipe`：rootfs 复制清单与校验规则。

## 关键流程图或伪代码
```text
strace app -> syscall list
  -> classify (must/optional)
  -> implement missing syscalls
  -> build static app
  -> pack rootfs -> run qemu -> record baseline
```

## 风险与权衡
- 动态链接器依赖（ld.so）会大幅增加 syscall 需求与 loader 复杂度。
- 复杂应用可能依赖 `epoll`/`mmap`/`mremap` 等内核特性，需逐步补齐。
- 大型二进制对内存与栈空间要求高，需要评估可用内存与栈大小。

## 测试点
- `strace iperf3 -s --help` / `strace redis-server --help` 的 syscall 覆盖清单。
- QEMU 运行 iperf3/redis 基线（iperf3 client->server，redis ping/set/get）。
- net-perf 与 tcp_echo/udp_echo 回归通过。
