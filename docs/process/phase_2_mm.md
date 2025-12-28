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

## 问题与定位
- 尚未接入设备树内存布局，无法真正分配可用物理内存。
- 页表实际映射与启用流程尚未实现。

## 解决与验证
- 当前为结构性 scaffolding，通过 `make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu` 进行基础验证。

## 下一步
- 接入 DTB 内存区域解析。
- 实现内核页表构建与启用。
