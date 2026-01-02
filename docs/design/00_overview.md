# 00_overview.md

## 目标
- 提供 OSComp 赛道可复现内核工程，覆盖 QEMU RISC-V64/LoongArch64 与对应实板。
- 阶段一以 QEMU RISC-V64 为首要 bring-up 目标。
- 保持组件化与分层结构，确保模块可替换、可测试。
- 满足关键应用与测例（busybox、git、vim、gcc、rustc）。

## 设计
- Apps / Modules / Core / HAL 四层，依赖方向从上到下。
- 模块间通过 Trait/接口解耦，避免穿透调用与全局可变状态。
- 跨平台差异通过 platforms/ 配置与 arch/ 入口隔离。
- 用户态应用适配路线见 `docs/design/11_userland_apps.md`。

## 关键数据结构
- BootInfo/PlatformDesc：启动参数与平台能力描述。
- PageTable/FrameAllocator：内存管理核心对象。
- TaskControlBlock/ProcessControlBlock：任务/进程状态。
- Inode/Dentry/File/VfsMount：VFS 关键对象。
- SyscallTable/ErrnoMap：系统调用与错误码映射。

## 关键流程图或伪代码
```text
entry.S -> rust_main -> early_init()
         -> initcalls (log/alloc/mm/driver/fs)
         -> create init task -> schedule -> userspace
```

## 风险与权衡
- 异步内核与抢占调度混合，调试复杂度上升。
- 多平台支持扩大构建/测试矩阵。
- Linux 兼容性与实现复杂度之间的取舍。

## 测试点
- make build/run/test-qemu-smoke 基础流程。
- crates/ 的 host 侧单元测试。
- 关键应用场景回归（busybox/git/vim/gcc/rustc）。
