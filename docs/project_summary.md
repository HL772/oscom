# Project Aurora 内核项目总结（全量、通俗版）

> 覆盖范围说明  
> 本文覆盖 README 与 `docs/design/*.md` 中列出的全部模块、功能、流程、脚本与工具。  
> 每一项都说明“做了什么”和“怎么做的（方法 + 通俗解释）”，并标出实现状态（已实现 / 基础路径 / 规划）。

## 1. 项目定位与目标

**项目定位**  
Project Aurora（极光内核）是面向 OSComp 内核赛道的 Rust 组件化内核工程，核心强调“可复现交付”和“模块化扩展”。

**核心目标与方法**
- **可复现构建/测试**：统一通过 `Makefile` + `scripts/` 脚本完成构建/运行/测试。  
  通俗解释：把“要手动做的一堆步骤”变成可重复的按钮，避免“只在我电脑上能跑”。
- **模块化分层**：Apps / Modules / Core / HAL/Arch/Drivers 分层，模块通过 Trait 接口交互。  
  通俗解释：像搭积木，每一块只做自己的事，接口清晰，后续替换更容易。
- **竞赛对齐**：优先覆盖 QEMU RISC‑V64 启动链路、文件系统与网络冒烟路径。  
  通俗解释：先让“跑起来 + 路径正确 + 可测”，再提升深度与性能。
- **过程可追溯**：设计文档、过程文档、日志导出脚本齐备。  
  通俗解释：每一步都有记录，出了问题能定位到来源。

## 2. 平台支持矩阵（实现状态）

- **QEMU RISC‑V64 (virt)**：已支持  
  方法：`scripts/run.sh` / `scripts/test_qemu_smoke.sh` 固定参数，依赖 OpenSBI。
- **QEMU LoongArch64**：规划中（Makefile 入口保留，脚本未启用）
- **实板 RISC‑V64 / LoongArch64**：规划中（需平台适配与驱动补齐）

## 3. 架构分层与仓库结构

**分层结构**
```
Apps (用户态测试/工具)
Modules (axruntime/axfs/axnet)
Core (axvfs 等通用库)
HAL/Arch/Drivers (架构入口 + 设备驱动)
```
通俗解释：上层只依赖下层，下层不反向依赖上层，结构更稳。

**仓库目录**
- `modules/`：内核服务层（axruntime/axfs/axnet）
- `crates/`：可在 host 侧单测的通用库
- `arch/`：架构相关入口与 trap
- `drivers/`：设备驱动（virtio 等）
- `apps/`：用户态测试程序（tcp/udp/fs/shell 等）
- `scripts/`：构建/运行/测试脚本
- `tools/`：导出与辅助脚本
- `docs/`：设计与过程文档
- `tests/`：自研测试清单

## 4. 启动链路（Boot）【已实现】

**关键方法与通俗解释**
1) **`entry.S` 早期汇编入口**  
   - 关中断、设置早期栈、清 BSS、跳转 Rust 入口  
   - 通俗解释：让 CPU 有一个“安全的工作台”，再进入 Rust 世界。

2) **`rust_main` 初始化流程**  
   - 解析 DTB、初始化内存/中断/时钟/驱动、启用分页  
   - 通俗解释：读设备树就像读“硬件配置清单”，然后按清单初始化各部件。

3) **固件与平台**  
   - QEMU 使用 OpenSBI 作为固件入口  
   - 通俗解释：OpenSBI 像“引导程序”，先把内核安全地交接给 OS。

4) **日志与控制台（已实现）**  
   - UART 串口作为早期控制台输出  
   - 通俗解释：启动时先把“说话渠道”建立起来，方便调试。

3) **早期堆栈扩容**  
   - boot stack 扩容到 64KB，避免深栈路径溢出  
   - 通俗解释：给启动期预留更大的“临时工作区”。

## 5. Trap/中断与用户态切换【已实现】

**核心方法**
- **trap 入口（汇编）保存现场**：保存通用寄存器 + CSR（sstatus/sepc/scause/stval）  
  通俗解释：中断时先“拍照保存状态”，处理完再恢复。
- **Rust trap 处理**：识别 U‑mode ecall，分发 syscall  
  通俗解释：用户态“敲门”，内核“查号分发”。
- **trap 返回**：`__trap_return` 恢复寄存器并 `sret` 回用户态  
  通俗解释：把刚才的“快照”还原回去。
- **定时器 tick**：使用 SBI `set_timer`，周期性触发调度  
  通俗解释：像闹钟，提醒调度器“该换人了”。
- **外部中断（PLIC）**：claim/complete 分发设备 IRQ  
  通俗解释：中断控制器像“电话总机”，把设备中断转给具体驱动处理。
- **页错误 CoW**：写时复制页 fault 触发分配新页并复制  
  通俗解释：父子共享只读页，写入时再“复制一份自己改”。

## 6. 内存管理（MM）【已实现/基础路径】

**方法与解释**
- **地址类型封装**（PhysAddr/VirtAddr、PhysPageNum/VirtPageNum）  
  通俗解释：用不同“单位”避免把物理地址当虚拟地址乱用。
- **Sv39 页表**  
  通俗解释：三级页表，让虚拟地址映射到物理地址。
- **Bump 帧分配器**（早期最小实现）  
  通俗解释：像指针往后挪，每次拿一块内存，不回收，适合 bring‑up。
- **身份映射 + 大页**  
  通俗解释：内核启动早期让“虚拟地址=物理地址”，简单可靠。
- **UserPtr/UserSlice**  
  通俗解释：用户态指针要验证合法性再读写，防止越权。
- **CoW 机制**  
  - fork/clone 共享页表，写入时复制  
  - 通俗解释：节省内存，同时保持语义正确。
- **内核栈 + guard page**  
  通俗解释：给内核栈加“防护栏”，越界立即异常。

## 7. 进程/任务与调度【已实现/基础路径】

**方法与解释**
- **Process/Task 分离**  
  通俗解释：进程是资源容器，任务是调度单位。
- **RunQueue + RR**  
  通俗解释：一个“排队队列”，按顺序轮流运行。
- **tick 驱动调度**  
  通俗解释：时钟到点就发起切换请求。
- **WaitQueue/SleepQueue**  
  通俗解释：任务要等事件就挂起，事件到来再唤醒。
- **waitpid 回收 Zombie**  
  通俗解释：子进程退出变“僵尸”，父进程负责回收资源。
- **fd 表按进程隔离**  
  通俗解释：每个进程有自己的“打开文件表”。

## 8. 系统调用 ABI 与覆盖【已实现/持续完善】

**ABI 方法**
- RISC‑V 约定：`a7`=syscall 号，`a0-a5`=参数，返回 `a0`  
  通俗解释：系统调用像函数调用，但参数走寄存器。
- 内核内部用 `Result<usize, Errno>`，返回时转成 `-errno`  
  通俗解释：统一错误码出口，用户态能直接判断失败原因。
- 用户态指针通过 `UserPtr/UserSlice` 校验  
  通俗解释：防止用户传“坏指针”让内核崩溃。

**已覆盖/占位 syscall（完整列表，按类别）**

1) **基础 I/O 与文件路径**
   - `read`, `write`, `readv`, `writev`
   - `open`, `openat`, `close`, `dup`, `dup3`
   - `lseek`, `pread64`, `pwrite64`, `preadv`, `pwritev`
   - `fstat`, `newfstatat`, `statx`, `statfs`, `fstatfs`
   - `getdents64`, `getcwd`, `chdir`, `fchdir`
   - `access`/`faccessat`, `readlink`/`readlinkat`
   - `ftruncate` + `O_TRUNC`
   - `mknodat`, `symlinkat`, `linkat`, `renameat`, `renameat2`（占位校验）
   - `fchmodat`, `fchownat`, `utimensat`（占位校验）

2) **进程/线程与调度**
   - `getpid`, `getppid`, `gettid`
   - `clone`（fork 语义 + CoW，支持 CLONE_*TID）
   - `wait4`, `waitpid`
   - `exit`, `exit_group`
   - `sched_yield`, `sched_getaffinity`, `sched_setaffinity`
   - `setpgid`, `getpgid`, `getsid`, `setsid`, `getpgrp`, `setpgrp`
   - `set_tid_address`

3) **内存相关**
   - `brk`
   - `mmap`, `munmap`, `mprotect`（匿名私有映射与 MAP_FIXED）
   - `madvise`（占位返回成功）

4) **时间与时钟**
   - `clock_gettime`, `clock_gettime64`
   - `clock_getres`, `clock_getres_time64`
   - `gettimeofday`
   - `nanosleep`

5) **同步与并发**
   - `futex`（FUTEX_WAIT/FUTEX_WAKE + PRIVATE）
   - `eventfd2`, `timerfd_*`
   - `poll`, `ppoll`, `epoll_*`（占位轮询）
   - `pipe2`

6) **网络与套接字**
   - `socket`, `bind`, `connect`, `listen`, `accept`, `accept4`
   - `sendto`, `recvfrom`
   - `SOCK_NONBLOCK`/`SOCK_CLOEXEC` 标志位处理

7) **终端与设备**
   - `ioctl`（TIOCGWINSZ/TIOCSWINSZ/TIOCGPGRP/TIOCSPGRP/TIOCSCTTY/TCGETS/TCSETS*）
   - `/dev/null`、`/dev/zero` 最小语义

8) **系统信息与身份**
   - `uname`, `sysinfo`
   - `getuid`, `geteuid`, `getgid`, `getegid`, `getresuid`, `getresgid`
   - `getgroups`, `setgroups`
   - `getrusage`
   - `getrandom`
   - `getcpu`
   - `prctl(PR_SET_NAME/PR_GET_NAME)`
   - `umask`, `getrlimit`, `prlimit64`
   - `set_robust_list`, `get_robust_list`
   - `rt_sigaction`, `rt_sigprocmask`
   - `fcntl`（F_GETFL/F_SETFL/O_NONBLOCK/O_APPEND、F_GETFD/F_SETFD）
   - `sync`

9) **不可用占位**
   - `rseq` → ENOSYS  
   - `arch_prctl`（riscv 无此 ABI）→ ENOSYS

**实现方法补充说明（通俗版）**
- `read/write`：文件句柄内部带偏移，读写后更新偏移；`pread/pwrite` 不更新偏移  
  通俗解释：`read` 像“从当前书页读”，`pread` 像“指定页读，不翻页”。
- `open/openat`：统一走 VFS 路径解析（挂载表 + 目录遍历）  
  通俗解释：先找到“所在文件系统”，再找文件 inode。
- `getdents64`：直接调用 VFS 的 `read_dir` 枚举目录项  
  通俗解释：不用自己拼目录结构，由文件系统提供目录项列表。
- `sync`：触发挂载表 `flush_all`，刷回 block cache 脏块  
  通俗解释：把“还在内存里”的修改强制写入磁盘。
- `execve`：用 VFS 读 `/init` ELF，解析段、映射到用户页表，再构建 argv/envp 栈  
  通俗解释：把一个 ELF 程序装进内存并设置好“启动现场”。
- `brk/mmap`：按页分配用户内存，mmap 支持匿名私有映射与 MAP_FIXED  
  通俗解释：给进程“扩容堆”或“申请一段新内存区域”。
- `futex`：以地址作为 key 的等待队列，PRIVATE 用虚拟地址，非 PRIVATE 用物理地址  
  通俗解释：同一地址的线程可以“约定在这里等待/唤醒”。
- `poll/ppoll/epoll`：最小轮询 + sleep‑retry  
  通俗解释：先看一遍有没有就绪，没有就睡一小会儿再看。
- `pipe2`：内存环形缓冲区，满/空时阻塞或返回 EAGAIN  
  通俗解释：像一个“有容量的管道”。
- `socket`：fd 与 axnet socket 句柄绑定，阻塞时进入 net 等待队列  
  通俗解释：把网络连接当作一种“特殊文件”来读写。

## 9. 文件系统与 VFS（全链路）

### 9.1 VFS 抽象（已实现）
**方法**
- 使用 `axvfs::VfsOps` 统一 `lookup/read/write/read_dir/metadata`  
  通俗解释：给不同文件系统提供统一“接口插槽”。
- `MountTable` 按最长前缀匹配路径  
  通俗解释：路径解析像“找最近的挂载点”。

### 9.2 RootFS 选择与回退（已实现）
**方法**
1) 优先挂载 virtio‑blk 上的 ext4/FAT32 镜像  
2) 失败则回退到内存 FAT32 ramdisk  
通俗解释：有“外置硬盘”就用硬盘，没有就用内存盘。
补充：内存 FAT32 ramdisk 内置 `fatlog.txt`，用于写路径自测。

### 9.3 BlockCache（已实现）
**方法**：固定行数的写回缓存  
通俗解释：把热数据先放在“内存缓存”，需要时再刷回磁盘，减少频繁 I/O。

**具体做法**
- 通过 `BlockDevice` trait 统一块设备接口
- `BlockCache` 以“块”为单位缓存读写
- 写入时标记为 dirty，`flush` 时写回设备
- 适合作为 ext4/FAT32 的底层缓存

### 9.4 ext4（基础路径已实现）

**主要实现方法**
- **superblock 解析**：检查魔数、block size、inode size  
  通俗解释：先读“文件系统身份证”。
- **组描述符**：获取 inode bitmap / block bitmap / inode table 位置  
  通俗解释：找到“图书馆目录”和“书架位置”。
- **inode 读取/写回**：解析 `mode/size/flags/blocks`  
  通俗解释：inode 就是“文件的说明书”。
- **目录遍历（dirent）**：按 ext4 变长目录项扫描  
  通俗解释：目录是一串“记录块”，每条记录长度不固定。
- **读路径**：逻辑块 → 物理块映射  
  - extents（depth 0/1/2）  
  - 传统 direct + single‑indirect（兼容路径）  
  - 稀疏文件读到“空洞”时返回 0 填充  
  通俗解释：支持“连续块映射”和“指针跳转”两种方式。
- **写路径（最小集）**：  
  - create/write/truncate 基础语义  
  - extent depth 0/1/2 写入  
  - single‑indirect 扩展  
  - 单块组位图分配  

**限制与取舍**
- 未实现 journaling 与 `metadata_csum`  
  通俗解释：写路径简化，宿主机工具可能提示“校验不一致”。
- 未实现跨块组分配与复杂一致性维护  
  通俗解释：先保证“能写能读”，复杂场景后续补齐。

### 9.5 FAT32（基础路径已实现）

**主要实现方法**
- 解析 BPB（BIOS 参数块）得到 FAT/簇/根目录布局  
  通俗解释：读 FAT32 的“磁盘说明书”。
- 目录项遍历 + 簇链遍历，实现文件读取  
  通俗解释：文件数据像“链表”，需要按链条找完整内容。
- 写入路径支持扩展簇链与更新目录项大小  
  通俗解释：文件变大时要给它“新增链条”。
- truncate 扩展时零填充  

### 9.5.1 页缓存/写回（规划）
- 规划引入 Page Cache / Write‑back 框架  
  通俗解释：把文件页先缓存在内存里，再成批写回，提升性能并减少磁盘抖动。

### 9.6 memfs/devfs/procfs（占位/基础）

**方法**
- memfs 作为最小 VFS 实现  
  - 提供 `/dev/null`、`/dev/zero`  
  - `/tmp/log` 用于最小写路径验证  
- devfs/procfs 目前为挂载点占位  

### 9.7 RootFS 制作与用户态注入（已实现）

**方法**
- `tools/build_init_elf.py` 生成最小 `/init` ELF  
  通俗解释：自动生成“内核启动的第一个用户程序”。
- `scripts/mkfs_ext4.sh` 制作 ext4 镜像  
  - 支持注入 `INIT_ELF`/`SHELL_ELF`/`TCP_ECHO_ELF`/`UDP_ECHO_ELF`/`FS_SMOKE_ELF`
  - 支持 `EXTRA_ROOTFS_DIR` 目录整合  
  - 默认写入 `/etc/issue` 与 `/etc/large` 作为读写样例  

---

## 10. 驱动模型与设备支持【已实现/基础路径】

**方法**
- DTB 枚举 virtio‑mmio 设备  
  通俗解释：扫描硬件清单，找到设备位置和 IRQ。
- 驱动统一生命周期：`probe -> init -> irq_handler`  
  通俗解释：像安装新设备，先识别再初始化，最后处理中断。
- DMA 抽象放在 HAL 层，驱动只使用接口  
  通俗解释：不同平台 DMA 细节不同，驱动不用关心。

**已实现驱动**
- **virtio‑blk**  
  - 单队列同步读写  
  - IRQ 完成优先，缺中断时轮询  
  通俗解释：像“单车道仓库”，一次处理一个请求。
- **virtio‑net**  
  - RX/TX 双队列  
  - IRQ + 轮询混合  
  通俗解释：既响应中断，也定时检查，避免漏包。

---

## 11. 网络子系统【已实现/基础路径】

**方法**
- `NetDevice` 抽象 + virtio‑net 驱动  
  通俗解释：驱动只负责收发包，协议栈处理“包内容”。
- smoltcp 风格协议栈适配  
  - 静态 IP：10.0.2.15/24  
  - ARP 探测网关，验证 RX/IRQ  
  - loopback 注入，支持单机 TCP 自测  
- idle loop 中定期 poll 网络与 async 任务  
  通俗解释：即便没有中断，也会主动检查网络是否有包。  
- socket 语义与 fd 表结合  
  - 非阻塞 connect → EINPROGRESS  
  - 重复 connect → EALREADY  
  - 失败映射 ECONNREFUSED/ENETUNREACH  

---

## 12. 异步执行器与创新点【已实现/规划】

### 12.1 已实现：最小 async 执行器
**方法**
- `modules/axruntime/src/async_exec.rs` 提供静态任务槽 + 就绪队列  
  通俗解释：没有堆分配，用固定“格子”放任务。
- `idle_loop` 周期性 `poll()` 推进任务  
  通俗解释：空闲时顺便推动异步任务前进。
- `yield_now` 提供协作式让渡  
  通俗解释：任务主动“举手让别人先跑”。
**当前限制**
- 任务槽容量固定（`MAX_ASYNC_TASKS`）  
- 任务需为 `'static`  
- 还未与所有驱动 I/O 完全打通  

### 12.2 规划创新点
- eBPF 动态观测  
  通俗解释：像给内核装“运行时探针”，随时插入监控逻辑。
- io_uring-like 异步接口  
  通俗解释：批量提交 I/O 请求，减少系统调用次数。
- RISC‑V AIA 用户态中断  
  通俗解释：硬件支持时，部分中断直接送到用户态，提高效率。

---

## 13. 用户态程序与交互式 Shell【已实现】

### 13.1 用户态应用列表
- `apps/tcp_echo`：TCP echo  
- `apps/udp_echo`：UDP echo  
- `apps/fs_smoke`：文件系统冒烟  
- `apps/net_bench`：性能基线接收端  
- `apps/shell`：交互式 shell  

**构建脚本**
- `scripts/build_tcp_echo.sh`
- `scripts/build_udp_echo.sh`
- `scripts/build_fs_smoke.sh`
- `scripts/build_net_bench.sh`
- `scripts/build_shell.sh`

### 13.2 交互式 Shell 命令（完整）
`help`、`echo`、`ls`、`cat`、`cd`、`pwd`、`exit`、`clear`、`head`、`tail`、`wc`、`stat`、`sleep`、`hexdump`、`touch`、`append`、`sync`

通俗解释：shell 是“手工验证工具”，可以直接创建文件、读写内容、查看目录。
启动时会显示 Aurora ASCII banner 与 OS/Arch/Platform/FS/Net/Shell 摘要信息。

### 13.3 用户态适配路线（规划）
- iperf3 / redis 适配：先 `strace` 收集 syscall → 覆盖矩阵 → 交叉编译 → rootfs 打包  
  通俗解释：先知道“应用需要什么”，再补齐内核能力。
 - `scripts/stage_userland_apps.sh` 支持把已构建的应用批量放入 rootfs  
 - 预留脚本：`scripts/build_iperf3.sh` / `scripts/build_redis.sh`

---

## 14. 构建环境与依赖（已实现）

**工具链**
- Rust toolchain 由 `rust-toolchain.toml` 固定
- 目标：`riscv64gc-unknown-none-elf`

**系统依赖（Ubuntu/Debian）**
`build-essential clang lld qemu-system-riscv64 gdb-multiarch e2fsprogs python3`

---

## 15. 构建/运行/测试流程（已实现）

**典型工作流**
1) `make build ARCH=riscv64 PLATFORM=qemu`  
2) `make rootfs-ext4 OUT=build/rootfs.ext4 SIZE=16M`  
3) `make run ARCH=riscv64 PLATFORM=qemu FS=build/rootfs.ext4`  
4) `make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu FS=build/rootfs.ext4`

**QEMU 参数（脚本生效）**
- `QEMU_BIN`、`BIOS`、`MEM`、`SMP`、`TIMEOUT`、`NET_HOSTFWD`
- 脚本固定 `virtio-mmio.force-legacy=false`（使用现代 virtio‑mmio 接口）

**关键环境变量**
- `ARCH` / `PLATFORM` / `MODE`  
- `FS`：ext4 镜像路径  
- `NET` / `NET_LOOPBACK_TEST` / `EXPECT_NET` / `EXPECT_NET_LOOPBACK`  
- `USER_TEST`  
- `SHELL_TEST` / `EXPECT_SHELL`  
- `FS_SMOKE_TEST` / `EXPECT_FS_SMOKE`  
- `EXT4_WRITE_TEST` / `EXPECT_EXT4` / `EXPECT_EXT4_WRITE` / `EXPECT_EXT4_ISSUE`  
- `TCP_ECHO_TEST` / `EXPECT_TCP_ECHO`  
- `UDP_ECHO_TEST` / `EXPECT_UDP_ECHO`  

---

## 16. 测试与基准（已实现/规划）

**测试分层**
- Host 单测（crates）  
- QEMU smoke  
- 自研测试集合（`tests/self/`）  
- 网络基线/性能基线  

**关键脚本**
- `scripts/test_qemu_smoke.sh`  
- `scripts/test_oscomp.sh`  
- `scripts/net_baseline.sh`  
- `scripts/net_perf_baseline.sh`  

**日志目录**
- `build/qemu-smoke.log`
- `build/selftest/`
- `build/net-baseline/`
- `build/net-perf/`

**补充说明**
- `scripts/test_oscomp.sh` 读取 `tests/self/cases.txt` 批量执行用例

**常用测试入口**
- `make test-qemu-smoke`  
- `USER_TEST=1 make test-qemu-smoke`  
- `EXT4_WRITE_TEST=1 EXPECT_EXT4=1 make test-qemu-smoke`  
- `NET=1 TCP_ECHO_TEST=1 make test-qemu-smoke`  
- `FS_SMOKE_TEST=1 make test-qemu-smoke`  
- `make test-oscomp`  
- `make test-net-baseline`  
- `make test-net-perf`  

**性能基线补充**
- 发送端脚本：`scripts/net_perf_send.py`
- 相关参数：`PERF_INIT_ELF`、`PERF_ROOTFS_DIR`、`PERF_HOST_PORT`、`PERF_QEMU_TIMEOUT`、`PERF_IO_TIMEOUT`

---

## 17. 日志与调试

- QEMU 冒烟日志：`build/qemu-smoke.log`
- GDB 调试：`make gdb ARCH=riscv64 PLATFORM=qemu`
- syscall 矩阵：`scripts/collect_syscall_matrix.sh`
  - 采集依赖 ptrace 权限，权限不足时需要提升执行权限

---

## 18. 工具与交付

- `tools/export_submission.sh`：导出提交物
- `tools/export_git_history.sh`：导出 git 历史
- `build_env/`：环境依赖说明

---

## 19. 设计与过程文档（全覆盖）

**设计文档（docs/design）**
- `00_overview.md`：总体设计与目标
- `01_boot.md`：启动链路
- `02_trap_interrupt.md`：陷入与中断
- `03_memory.md`：内存管理
- `04_task_process.md`：进程/调度
- `05_syscall_abi.md`：syscall ABI 与覆盖
- `06_fs_vfs.md`：VFS 与文件系统
- `07_net.md`：网络栈
- `08_driver_model.md`：驱动模型
- `09_innovations.md`：创新路线
- `10_testing_benchmark.md`：测试与基准
- `11_userland_apps.md`：应用适配路线

**过程文档（docs/process）**
- `phase_*`、`weekly_devlog_*`、`debug_report_*` 记录开发过程

---

## 20. 许可证、第三方与参考

- 许可证：`LICENSE`
- 第三方依赖清单：`THIRD_PARTY_NOTICES.md`
- 参考来源：ArceOS / Unikraft / Linux Kernel / smoltcp

---

## 21. 协作规范

- Commit message：Angular 规范（如 `feat(runtime): ...`）  
- 禁止重写历史（不使用 `git push --force`）  

---

## 22. 总结（通俗版一句话）

Aurora 是一个“用 Rust 搭积木的内核工程”：  
- 启动、内存、调度、系统调用、文件系统、网络、驱动都已经打通了基础路径；  
- 通过脚本化和模块化，把“能跑、能测、可复现”作为核心底线；  
- 在此基础上逐步引入 async/eBPF/io_uring 等创新方向。  
