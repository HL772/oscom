# phase_2_mm.md

## 目标
- 搭建内存管理基础骨架，支持后续 buddy/slab 与页表映射。

## 进展
- 增加地址/页号新类型与 Sv39 PTE 编解码。
- 添加最小帧分配器占位（bump allocator）。
- 在内核入口完成 mm 初始化占位调用。
- 接入 DTB 解析获取物理内存范围输入。
- 建立 Sv39 identity 页表并启用 paging（satp + sfence.vma）。
- 帧分配器使用 ekernel 之后的内存区间，限制在 1GiB identity 映射内。
- 页表页改为从帧分配器动态分配。
- 增加用户指针翻译与 UserPtr/UserSlice，支撑 syscall 访问用户内存。
- 引入 PTE_COW 标记与 clone_user_root，fork 时复制页表并将可写页降级为只读。
- page fault 处理 CoW 写入，分配新页并复制数据。
- 增加帧引用计数与空闲帧复用，释放用户页与页表页。

## 问题与定位
- 空闲帧复用曾缺乏清零/隔离策略，可能携带历史数据。
- 内核栈页与用户数据页物理相邻，深层调用导致栈下溢时会污染用户态数据。
- 当前仅处理 4KiB 页级别 CoW，未覆盖大页映射场景。

## 解决与验证
- 在 `alloc_frame` 中增加清零，避免复用页残留干扰用户态数据结构。
- 空闲帧栈 push/pop 包裹关中断，避免中断重入导致的双重分配。
- 内核栈改为使用 bump 连续页分配并预留 guard page，降低栈下溢破坏用户页风险。
- 通过 `make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu` 进行基础验证。

## 下一步
- 引入帧回收与页引用计数，完善 CoW 生命周期。
- 支持 demand paging 与更完整的页错误处理。
