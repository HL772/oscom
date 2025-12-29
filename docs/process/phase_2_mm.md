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

## 问题与定位
- bump allocator 无回收，CoW 写入后旧页无法释放。
- 当前仅处理 4KiB 页级别 CoW，未覆盖大页映射场景。

## 解决与验证
- 通过 `make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu` 进行基础验证。

## 下一步
- 引入帧回收与页引用计数，完善 CoW 生命周期。
- 支持 demand paging 与更完整的页错误处理。
