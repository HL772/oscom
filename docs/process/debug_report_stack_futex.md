# Aurora OS Kernel Debug Report: Ext4 Hole & Stack Overflow

**日期**: 2026-01-01
**模块**: axfs (Ext4), axruntime (Memory, Stack, Syscall)
**平台**: RISC-V 64 (QEMU)
**状态**: 已修复

## 1. 问题背景 (Background)

在执行 `make test-qemu-smoke` 进行冒烟测试时，内核无法通过测试。主要表现为：

1. **早期现象**：`sys_execve("/init")` 失败，返回 `Inval` (Invalid Argument)，导致 `/etc/issue` 无法打印。
2. **中期现象**：修复文件读取后，测试卡死在 `sys_futex`，此时 `timeout` 参数变成了巨大的垃圾数值（如 `2152666960`），导致无限等待或 QEMU 超时。

## 2. 调试过程时间线 (Timeline)

### 阶段一：文件系统“稀疏文件”问题

* **现象**：`sys_execve` 加载 `/init` 时报错 `Inval`。调试发现读取的 ELF 头数据不正确（全 0 或截断）。
* **分析**：`/init` 是 ELF 可执行文件，通常包含未分配的块（Holes/Sparse File）。Ext4 的 `read_from_inode` 实现中，遇到 `map_block` 返回 `None` 时直接返回了 `Ok(total)` 停止读取，导致文件被错误截断。
* **修复**：修改 `modules/axfs/src/ext4.rs`，当遇到未分配块时，显式填充 0 并继续读取后续块，而非提前返回。
* **结果**：`/init` 的 ELF 头（Magic Number）读取正确，但测试流程随后卡死。

### 阶段二：Futex 参数污染与内存“幽灵”数据

* **现象**：`sys_futex` 的 `WAIT` 操作在第二次调用时，传入的 `timespec` 结构体本应是 `{0, 0}`，但在内核打印中显示为 `{2152666960, 15}`。
* **数据分析**：
* `2152666960` 转换为十六进制是 `0x80502750`。
* 这是一个典型的 **内核虚拟地址**（RISC-V `0x80200000` 起始）。
* 这表明用户态栈或数据页被内核数据“踩踏”了。


* **排除假设**：
1. **COW (Copy-On-Write) 失败？** 尝试禁用 COW，无效。
2. **物理页未清零/脏数据？** 在 `mm::alloc_frame` 中强制 `memset(0)`，无效。
3. **空闲链表竞态？** 给 `push/pop_free_frame` 加上关中断保护，无效。
4. **用户态布局越界？** 怀疑 `sys_ppoll` 等系统调用写越界，将 `USER_FUTEX_TS_VA` 移到页末 `0xF00` 处。**结果：污染依然存在，并未避开。**



### 阶段三：锁定“内核栈溢出” (Root Cause Found)

* **关键实验**：在 `sys_futex` 中打印 `timeout` 指针的物理地址 (PA) 和当前内核栈指针 (SP) 的物理地址。
* **日志证据**：
```text
timeout_va=0x40001f00 -> pa=0x804f0f00
sp=0x804f2280         -> sp_pa=0x804f2280

```


* **物理布局分析**：
* 用户数据页 PA: `0x804f0000` ~ `0x804f1000`
* 内核栈页 PA: `0x804f1000` ~ `0x804f3000` (假设 2 页)
* **结论**：用户数据页在物理内存上**紧贴**在内核栈的下方。
* RISC-V 栈向下增长。当内核栈发生下溢（Stack Overflow/Underflow）时，它直接覆盖了低地址的物理页——即用户数据页。


* **验证**：`0x8050...` 等垃圾数据实际上是 Trap Handler 保存寄存器（Context Save）时压入栈的 `ra` (Return Address) 或 `fp`。

### 阶段四：伴生问题 `sys_clone: NoMem`

* **原因**：内核栈初始化 (`KernelStack::new`) 依赖于连续的物理页。由于系统运行一段时间后内存碎片化，`alloc_frame` 无法保证从 Free List 中取出的页是物理连续的，导致分配失败。

## 3. 根本原因 (Root Cause Analysis)

1. **内核栈空间不足与保护缺失**：默认 2 页（8KB）的内核栈在深层调用路径（如文件系统操作 + 详细 Debug 打印）下耗尽。且没有 Guard Page，导致溢出直接破坏相邻物理页。
2. **物理内存分配策略缺陷**：内核栈要求物理连续，但简单的 Free List 分配器无法保证这一点，且容易导致用户页与内核栈页物理相邻，增加了“踩踏”风险。

## 4. 解决方案 (Fix Implementation)

### 1. 内存管理层 (`modules/axruntime/src/mm.rs`)

* **新增连续帧分配接口**：扩展 `BumpFrameAllocator`，实现 `alloc_contiguous` 方法，允许绕过 Free List，直接从未分配区域获取物理连续的页帧。
```rust
pub fn alloc_contiguous_frames(count: usize) -> Option<PhysPageNum> { ... }

```



### 2. 栈管理层 (`modules/axruntime/src/stack.rs`)

* **增加栈大小**：将 `STACK_PAGES` 从 2 页提升至 4 页（16KB）。
* **引入 Guard Page**：分配 `N+1` 页，将最低地址的一页作为 Guard Page（留空不使用）。内核栈底设置在 Guard Page 之上。如果再次发生溢出，将踩到无用的 Guard Page，而非用户数据。
```rust
let alloc_pages = STACK_PAGES + 1;
let start_frame = mm::alloc_contiguous_frames(alloc_pages)?;
let base = start_frame.addr().as_usize() + PAGE_SIZE; // 跳过第一页

```



### 3. 文件系统层 (`modules/axfs/src/ext4.rs`)

* **修复稀疏读**：在 `read_from_inode` 中正确处理 `map_block` 返回 `None` 的情况，填充 0 并继续循环。

## 5. 结论 (Conclusion)

本次 Debug 揭示了操作系统内核中“物理地址别名”问题的隐蔽性。用户态看到的虚拟地址和内核栈看似无关，但在物理内存层面可能紧邻。

通过引入 **Guard Page** 和 **物理连续分配器**，我们不仅解决了本次的数据损坏问题，还彻底解决了 `sys_clone` 在内存碎片化后的 `NoMem` 问题，显著提升了系统的稳定性。