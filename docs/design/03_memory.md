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

## 关键数据结构
- `PhysAddr/VirtAddr`：物理/虚拟地址封装与对齐工具。
- `PhysPageNum/VirtPageNum`：页号封装，便于页表映射。
- `PageTableEntry`：PTE 编解码与标志位管理。
- `BumpFrameAllocator`：最小可用帧分配占位实现。
- `alloc_frame`：早期帧分配接口（无回收）。
- `PageTable`：页表页从 `alloc_frame` 分配并清零。
- `translate_user_ptr`：基于当前页表的用户指针翻译与权限检查。
- `UserPtr/UserSlice`：用户指针与缓冲区访问封装。

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

## 测试点
- QEMU 启动后基本内存分配 sanity check。
- 后续引入 fork/exec 后验证 CoW 与需求分页。
