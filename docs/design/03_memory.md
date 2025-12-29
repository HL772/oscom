# 03_memory.md

## 目标
- 建立最小可扩展的内存管理骨架（地址类型、页表布局、帧分配接口）。
- 为后续 buddy/slab、CoW、demand paging 提供统一基础。

## 设计
- 地址类型以 `PhysAddr/VirtAddr` 新类型封装，避免混用。
- Sv39 页表布局常量化，提供 PTE 基础标志位与 PPN 编解码。
- 早期使用简单的 bump frame allocator 作为占位，后续替换为 buddy。
- 通过 DTB 解析得到物理内存范围，作为初始化输入。
- 早期页表采用 Sv39 identity 映射，使用 2MiB 页覆盖内核内存区域。
- 帧分配器起始地址使用 `ekernel` 对齐后的位置，避免覆盖内核镜像。
- 页表页通过早期帧分配器动态分配，避免固定静态页表。
- 增加页表遍历与用户指针翻译辅助，为 syscall 访问用户内存做准备。
- 引入 `UserPtr`/`UserSlice` 封装用户态访问与复制路径。
- 引入 CoW 标记位（PTE_COW），fork 时克隆用户页表并将可写页降级为只读。
- 写入触发页错误时，分配新页并复制旧内容，恢复可写权限。
- 增加帧引用计数与空闲栈，支持 fork/exec/exit 后回收用户页与页表页。

## 关键数据结构
- `PhysAddr/VirtAddr`：物理/虚拟地址封装与对齐工具。
- `PhysPageNum/VirtPageNum`：页号封装，便于页表映射。
- `PageTableEntry`：PTE 编解码与标志位管理。
- `BumpFrameAllocator`：最小可用帧分配占位实现。
- `alloc_frame`：早期帧分配接口（无回收）。
- `PageTable`：页表页从 `alloc_frame` 分配并清零。
- `translate_user_ptr`：基于当前页表的用户指针翻译与权限检查。
- `UserPtr/UserSlice`：用户指针与缓冲区访问封装。
- `UserPtr` 内部复用 `UserSlice`，支持跨页结构体读写。
- `memory_size`：暴露物理内存大小供系统信息查询。
- `PTE_COW`：软件保留位标记写时复制页。
- `clone_user_root`：克隆用户页表并设置 CoW 标志。
- `handle_cow_fault`：处理写时复制页错误，复制页面并更新 PTE。
- `release_user_root`：释放用户页与页表页，并回收帧到空闲栈。

## 关键流程图或伪代码
```text
init_mm
  -> parse memory map (DTB)
  -> init frame allocator
  -> build kernel page table (Sv39 identity)
  -> enable paging (satp + sfence.vma)
```

## 风险与权衡
- 早期 bump allocator 无回收能力，仅用于 bring-up。
- Sv39 细节处理不当会导致页表映射错误与异常。
- 1GiB 范围内映射的截断风险需在后续细化。
- 当前帧分配范围限制在 identity 映射的 1GiB 区间内。
- 空闲帧复用仍缺乏隔离与清零策略，后续需补齐。

## 测试点
- QEMU 启动后基本内存分配 sanity check。
- fork/clone 写入路径触发 CoW 页错误并成功恢复。
