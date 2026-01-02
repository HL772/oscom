<pre style="line-height: 1.05; font-weight: 600;">
<span style="color:#2cc9c9;">                  .::::::.</span>
<span style="color:#34d3d3;">               .::::::::::::.</span>
<span style="color:#4a91ff;">             .::::::----::::::.</span>
<span style="color:#6b7bff;">           .::::::--------::::::.</span>
<span style="color:#8a69ff;">         .::::::----====----::::::.</span>
<span style="color:#a55bff;">       .::::::----========----::::::.</span>
<span style="color:#b14cff;">     .::::::----==========----::::::.</span>
<span style="color:#b14cff;">    ::::::----====++++====----::::::</span>
<span style="color:#a55bff;">     '::::----====++++====----::::'</span>
<span style="color:#8a69ff;">       '::----====++++====----::'</span>
<span style="color:#4a91ff;">         '--====++++++++====--'</span>
<span style="color:#34d3d3;">             '==++++++++=='</span>
<span style="color:#2cc9c9;">                 '===='</span>
</pre>

# Project Aurora (极光内核)

面向 OSComp 内核赛道的 Rust 组件化操作系统内核工程。目标是提供**可复现构建**、**清晰架构分层**、**可验证功能与测试**、**完整过程文档**的竞赛级交付。

---

## 目录

- [项目定位与目标](#项目定位与目标)
- [实现状态一览](#实现状态一览)
- [平台支持矩阵](#平台支持矩阵)
- [架构与模块分层](#架构与模块分层)
- [关键实现要点（当前已有）](#关键实现要点当前已有)
- [创新点与工程实践](#创新点与工程实践)
- [仓库结构](#仓库结构)
- [构建环境与依赖](#构建环境与依赖)
- [构建/运行/测试](#构建运行测试)
- [RootFS 制作与用户态程序](#rootfs-制作与用户态程序)
- [网络与性能测试](#网络与性能测试)
- [系统调用与兼容性](#系统调用与兼容性)
- [日志与调试](#日志与调试)
- [设计文档与过程文档](#设计文档与过程文档)
- [交付与导出工具](#交付与导出工具)
- [许可证与第三方声明](#许可证与第三方声明)

---

## 项目定位与目标

Project Aurora 旨在实现一个**Rust 组件化**、**面向 OSComp 内核赛道可复现交付**的内核工程。核心目标包括：

- **可复现构建/测试**：所有构建、运行、测试均通过 `Makefile` + `scripts/` 一键复现。
- **分层架构与可替换性**：Apps / Modules / Core / HAL 分层，模块通过 Trait 交互，减少穿透调用。
- **竞赛对齐**：覆盖 QEMU RISC-V64 基础启动链路，具备文件系统与网络的冒烟路径，逐步扩展到更多场景。
- **过程可追溯**：设计文档、过程文档、日志导出脚本齐备，配合 CHANGELOG 与工具导出。

---

## 实现状态一览

说明：
- `[x]` 已实现并有测试覆盖
- `[~]` 已实现基础路径，持续完善中
- `[ ]` 规划中

### 启动与基础设施
- `[x]` RISC-V64 QEMU 启动链路（OpenSBI + virt 机器）
- `[x]` Trap/中断基础框架，支持用户态切换
- `[x]` 基础调度框架（RunQueue + 时间片触发）
- `[x]` 内核日志与控制台输出
- `[x]` 最小异步执行器（无堆、固定槽位）

### 内存管理
- `[x]` Sv39 页表、用户/内核页映射
- `[x]` 基础 CoW 缺页路径（用户态写时复制）
- `[~]` brk/mmap 基础语义（用户堆扩展）
- `[~]` 内核栈安全边界与 guard 页

### 进程与系统调用
- `[x]` 基础用户态入口与 `execve` 载入流程
- `[~]` `waitpid`/futex/ppoll 语义完善
- `[~]` syscall 兼容性与 errno 映射持续补齐

### 文件系统
- `[x]` VFS 基础框架
- `[~]` ext4：挂载/目录查找/读写基础路径
- `[~]` FAT32：基本读写路径与一致性修复
- `[ ]` Page cache / writeback 框架完善

### 网络
- `[x]` virtio-net 驱动与 smoltcp 适配
- `[~]` TCP/UDP 连接与收发路径（echo 测试覆盖）
- `[~]` poll/窗口更新策略持续完善

### 测试与工具
- `[x]` QEMU smoke 测试脚本
- `[x]` 自研 TCP/UDP/FS 用户态冒烟程序
- `[~]` 性能基线脚本（net perf）
- `[x]` 提交物导出工具（`tools/export_submission.sh`）

> 详细计划见 `docs/design/` 与 `docs/process/`。

---

## 平台支持矩阵

| 平台 | 状态 | 备注 |
| --- | --- | --- |
| QEMU RISC-V64 (virt) | 已支持 | `scripts/run.sh`/`scripts/test_qemu_smoke.sh` |
| QEMU LoongArch64 | 规划中 | Makefile 预留入口，脚本未启用 |
| 实板 RISC-V64 | 规划中 | 需要平台适配与驱动补齐 |
| 实板 LoongArch64 | 规划中 | 需要平台适配与驱动补齐 |

---

## 架构与模块分层

```
+--------------------------------------------------+
| Apps (userspace tests / tools)                  |
|  - tcp_echo / udp_echo / fs_smoke / net_bench    |
+------------------------+-------------------------+
| Modules (kernel services)                        |
|  - axruntime / axfs / axnet                       |
+------------------------+-------------------------+
| Core (shared libs)                                |
|  - axvfs, scheduler, page_table helpers, etc.     |
+------------------------+-------------------------+
| HAL/Arch/Drivers                                 |
|  - arch/ (RISC-V trap/entry)                      |
|  - drivers/ (virtio-blk/net)                      |
+--------------------------------------------------+
```

**设计原则**：
- 模块间通过 Trait 接口交互，避免跨层全局可变状态。
- `unsafe` 使用必须有清晰 Safety Invariant 说明。
- 构建与测试必须脚本化，避免“只在某台机器可用”。

---

## 关键实现要点（当前已有）

- **RISC-V trap 入口与用户态切换**：覆盖用户态 ecall/中断回内核路径。
- **内核栈与 guard 页**：任务栈配套 guard 页，降低越界风险。
- **基础 CoW 路径**：用户态写时复制缺页处理，避免完整页表复制。
- **ext4 基础读写**：挂载、目录查找与基础读写路径（冒烟测试覆盖）。
- **virtio-net + smoltcp**：ARP/TCP/UDP 基础路径，echo 程序覆盖。
- **最小 async executor**：无堆协作式调度，适合 I/O 轮询与驱动回调。

---

## 创新点与工程实践

- **内核内最小 async 执行器**：固定槽位、无堆分配，适配早期启动与驱动回调场景。
- **网络轮询 + 中断混合驱动**：在 idle loop 中定时 poll，降低窗口更新延迟。
- **ext4 extent 读写路径**：支持多级 extent 索引的基础读写与测试用例。
- **严格可复现脚本化流程**：所有构建/运行/测试均有脚本入口。

详细设计与取舍见 `docs/design/09_innovations.md`。

---

## 仓库结构

```
.
├── Cargo.toml                # Rust workspace
├── Makefile                  # 统一入口 (make help)
├── rust-toolchain.toml       # Rust toolchain pin
├── modules/                  # 内核服务层 (axruntime/axfs/axnet)
├── crates/                   # 可 host 侧单测的通用库
├── arch/                     # 架构相关入口与 trap
├── drivers/                  # 设备驱动
├── apps/                     # 用户态测试程序 (tcp/udp/fs/net)
├── scripts/                  # 构建/运行/测试脚本
├── tools/                    # 提交物导出与日志
├── docs/                     # 设计与过程文档
├── build_env/                # 构建环境说明
├── tests/                    # 自研测试清单
└── THIRD_PARTY_NOTICES.md    # 第三方依赖说明
```

---

## 构建环境与依赖

**Rust 工具链**：见 `rust-toolchain.toml`

**目标平台**：`riscv64gc-unknown-none-elf`

**Ubuntu/Debian 依赖**：见 `build_env/apt-deps.txt`

```
# 示例
sudo apt-get install -y build-essential clang lld qemu-system-riscv64 gdb-multiarch e2fsprogs python3
rustup target add riscv64gc-unknown-none-elf
```

---

## 构建/运行/测试

### 常用命令

```bash
make help
make fmt
make clippy
make build ARCH=riscv64 PLATFORM=qemu
make run ARCH=riscv64 PLATFORM=qemu FS=path/to/ext4.img
make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu
make test-oscomp ARCH=riscv64 PLATFORM=qemu
```

> 当前 `scripts/run.sh` 与 `scripts/test_qemu_smoke.sh` 仅支持 `ARCH=riscv64 PLATFORM=qemu`。

### 典型工作流（一步步）

1) 编译内核
```bash
make build ARCH=riscv64 PLATFORM=qemu
```

2) 生成 ext4 根文件系统
```bash
make rootfs-ext4 OUT=build/rootfs.ext4 SIZE=16M
```

3) 启动 QEMU
```bash
make run ARCH=riscv64 PLATFORM=qemu FS=build/rootfs.ext4
```

4) 冒烟测试
```bash
make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu FS=build/rootfs.ext4
```

### QEMU 相关参数

以下参数在 `scripts/run.sh` 与 `scripts/test_qemu_smoke.sh` 中生效：

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `QEMU_BIN` | QEMU 可执行文件 | `qemu-system-riscv64` |
| `BIOS` | OpenSBI/BIOS 路径 | `default` |
| `MEM` | 内存大小 | `512M` |
| `SMP` | CPU 核数 | `1` |
| `TIMEOUT` | 测试超时 | `5` |
| `NET_HOSTFWD` | user net 端口转发 | 为空 |

### 关键环境变量

| 变量 | 含义 | 典型值 |
| --- | --- | --- |
| `ARCH` | 架构 | `riscv64` |
| `PLATFORM` | 平台 | `qemu` |
| `MODE` | 构建模式 | `debug` / `release` |
| `FS` | ext4 镜像路径 | `build/rootfs.ext4` |
| `NET` | 启用 virtio-net | `1` |
| `USER_TEST` | 启用用户态 ecall 测试 | `1` |
| `EXPECT_EXT4` | 校验 ext4 mount 日志 | `1` |
| `EXT4_WRITE_TEST` | ext4 写入冒烟路径 | `1` |
| `EXPECT_EXT4_WRITE` | 检查 ext4 写入日志 | `1` |
| `EXPECT_EXT4_ISSUE` | 检查 `/etc/issue` 内容 | `Aurora ext4 test` |
| `TCP_ECHO_TEST` | TCP echo 用户态测试 | `1` |
| `EXPECT_TCP_ECHO` | 检查 TCP echo 日志 | `1` |
| `UDP_ECHO_TEST` | UDP echo 用户态测试 | `1` |
| `EXPECT_UDP_ECHO` | 检查 UDP echo 日志 | `1` |
| `FS_SMOKE_TEST` | 文件系统冒烟测试 | `1` |
| `EXPECT_FS_SMOKE` | 检查 FS smoke 日志 | `1` |
| `NET_LOOPBACK_TEST` | 触发内核 loopback 自测 | `1` |
| `EXPECT_NET` | 检查 virtio-net ready 日志 | `1` |
| `EXPECT_NET_LOOPBACK` | 检查 loopback 日志 | `1` |

---

### 自研测试集合（无官方测例）

- `make test-oscomp ARCH=riscv64 PLATFORM=qemu` 会读取 `tests/self/cases.txt` 中的用例列表。
- 日志输出目录：`build/selftest/`
- 用例与日志格式说明见 `tests/self/README.md`

## RootFS 制作与用户态程序

### ext4 RootFS

使用脚本构建 ext4 镜像：

```bash
make rootfs-ext4 OUT=build/rootfs.ext4 SIZE=16M
```

脚本位于 `scripts/mkfs_ext4.sh`，依赖：
- `mke2fs` (e2fsprogs)
- `python3`（用于生成默认 `/init`）

`mkfs_ext4.sh` 支持附加用户态二进制与扩展目录：

- `INIT_ELF`：指定 `/init` ELF
- `TCP_ECHO_ELF` / `UDP_ECHO_ELF` / `FS_SMOKE_ELF`：附加测试程序
- `EXTRA_ROOTFS_DIR`：将目录整体拷贝进 rootfs

### 新增用户态程序流程

1) 在 `apps/` 下创建 no_std 程序（syscall 方式）  
2) 提供构建脚本（参考 `scripts/build_tcp_echo.sh`）  
3) 将 ELF 通过 `mkfs_ext4.sh` 放入镜像  
4) 在 `scripts/test_qemu_smoke.sh` 增加开关与期望日志  

### 用户态测试程序

| 程序 | 作用 | 构建脚本 | 运行方式 |
| --- | --- | --- | --- |
| `tcp_echo` | TCP echo 覆盖 socket/bind/listen/accept/send/recv | `scripts/build_tcp_echo.sh` | `TCP_ECHO_TEST=1 make test-qemu-smoke ...` |
| `udp_echo` | UDP echo 覆盖 send/recv/msg | `scripts/build_udp_echo.sh` | `UDP_ECHO_TEST=1 make test-qemu-smoke ...` |
| `fs_smoke` | 文件系统读写/seek/IOV | `scripts/build_fs_smoke.sh` | `FS_SMOKE_TEST=1 make test-qemu-smoke ...` |
| `net_bench` | 简易吞吐接收端（性能基线） | `scripts/build_net_bench.sh` | `make test-net-perf ...` |

---

## 网络与性能测试

### 网络基线 (功能)

```bash
make test-net-baseline ARCH=riscv64 PLATFORM=qemu
```

该目标依次运行：
- `NET=1` 基础启动
- Loopback 测试
- TCP echo
- UDP echo

日志输出目录：`build/net-baseline/`

### 网络性能基线

```bash
make test-net-perf ARCH=riscv64 PLATFORM=qemu \
  PERF_INIT_ELF=path/to/init.elf \
  PERF_ROOTFS_DIR=path/to/rootfs_dir
```

说明：
- `PERF_INIT_ELF`：自定义 `/init`（通常运行 net_bench）
- `PERF_ROOTFS_DIR`：额外放置到 ext4 的目录
- 发送脚本：`scripts/net_perf_send.py`

日志输出目录：`build/net-perf/`

---

## 系统调用与兼容性

- 系统调用矩阵统计：
  ```bash
  ./scripts/collect_syscall_matrix.sh
  ```
- ABI 设计与 errno 映射参考：
  - `docs/design/05_syscall_abi.md`
  - `docs/process/phase_3_process_syscall.md`
- 当前用户态测试用例目录：`tests/self/`

---

## 日志与调试

- **QEMU 冒烟日志**：`build/qemu-smoke.log`
- **GDB 调试**：
  ```bash
  make gdb ARCH=riscv64 PLATFORM=qemu
  ```
- **系统调用矩阵**：`scripts/collect_syscall_matrix.sh`

常见日志标记（用于快速判断测试是否通过）：
- `Aurora kernel booting`：内核启动 banner
- `virtio-net: ready`：网卡初始化完成
- `net: arp reply`：ARP 接收路径可用
- `tcp-echo: ok` / `udp-echo: ok`：用户态网络测试通过
- `fs-smoke: ok`：文件系统冒烟测试通过
- `net-bench: ready` / `net-bench: rx_bytes=...`：性能基线判据

---

## 设计文档与过程文档

**设计文档**（`docs/design/`）：
- `00_overview.md`
- `01_boot.md`
- `02_trap_interrupt.md`
- `03_memory.md`
- `04_task_process.md`
- `05_syscall_abi.md`
- `06_fs_vfs.md`
- `07_net.md`
- `08_driver_model.md`
- `09_innovations.md`
- `10_testing_benchmark.md`

**过程文档**（`docs/process/`）：
- `phase_0_kickoff.md` ... `phase_6_oscomp_hardening.md`
- `weekly_devlog_YYYYWww.md`
- `debug_report_*.md`

---

## 交付与导出工具

- `tools/export_submission.sh`：打包 dist/，包含源码、文档、测试脚本
- `tools/export_git_history.sh`：导出 git log/shortlog 到 docs/process

---

## 许可证与第三方声明

- 许可证：`LICENSE`
- 第三方依赖清单：`THIRD_PARTY_NOTICES.md`

---

## 参考项目

以下项目为架构与工程实践的参考来源（非代码直接拷贝）：
- ArceOS（Rust 组件化 OS，模块划分与接口设计参考）
- Unikraft（unikernel 构建理念与最小化路径参考）
- Linux Kernel（syscall/errno 语义与接口行为参考）
- smoltcp（嵌入式网络栈实现风格参考）

---

## 提交规范与协作约定

- Commit message：Angular 规范（例如 `feat(runtime): ...`）
- 禁止重写历史（不使用 `git push --force`）
- 变更功能必须同步更新文档与脚本

---

如需更详细的设计与实现细节，请从 `docs/design/00_overview.md` 开始阅读。
