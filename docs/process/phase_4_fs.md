# phase_4_fs.md

## 目标
- 规划 VFS/FAT32/ext4 适配路线与测试矩阵。

## 进展
- 当前阶段进入 VFS 骨架搭建。
- 新增 `crates/axvfs` 作为早期 VFS trait 骨架，采用 `InodeId` 句柄便于后续替换实现。
- 新增 `modules/axfs` memfs 占位实现，并在 `getdents64` 目录枚举中复用 memfs 的静态目录项。
- openat/newfstatat 改为走 memfs 路径解析与元数据查询，逐步替换 syscall 中的硬编码路径。

## 问题与定位
- 尚未进入实现阶段，暂无问题记录。

## 解决与验证
- 待实现后补充 git/vim/gcc 等应用场景验证。

## 下一步
- 完成 VFS/FAT32/ext4 最小读写后进入网络阶段。
