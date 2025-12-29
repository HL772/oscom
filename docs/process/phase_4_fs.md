# phase_4_fs.md

## 目标
- 规划 VFS/FAT32/ext4 适配路线与测试矩阵。

## 进展
- 当前阶段进入 VFS 骨架搭建。
- 新增 `crates/axvfs` 作为早期 VFS trait 骨架，采用 `InodeId` 句柄便于后续替换实现。
- 新增 `modules/axfs` memfs 占位实现，并在 `getdents64` 目录枚举中复用 memfs 的静态目录项。
- openat/newfstatat 改为走 memfs 路径解析与元数据查询，逐步替换 syscall 中的硬编码路径。
- 增加 memfs 的基础解析/元数据单元测试，验证 `/dev/null` 等路径解析。
- faccessat/statx/readlinkat 改用 memfs 路径解析，统一早期路径行为。
- statfs 路径解析改用 memfs，避免硬编码路径判断。
- mknodat/mkdirat/unlinkat/linkat/renameat* 以及 fchmodat/fchownat/utimensat 改用 memfs 路径解析。
- /init 读取改用 memfs read_at 并携带内置 ELF 镜像。
- fstat 对伪节点改用 memfs 元数据。
- memfs 增加 parent+basename 解析，用于校验 create/unlink/rename 的父目录路径。
- memfs 读路径扩展到 `/dev/null` 与 `/dev/zero`。
- memfs 读取统一走 read_at，并通过 fd offset 维护文件读位置。
- memfs 写路径支持 `/dev/null` 与 `/dev/zero`，readlinkat 走 memfs 入口占位。
- 引入 MountTable 挂载表，预留 `/`、`/dev`、`/proc` 挂载点，路径解析改为最长前缀匹配。
- 新增 devfs/procfs 占位实现，/dev 路径解析与元数据读取走 devfs。

## 问题与定位
- 尚未进入实现阶段，暂无问题记录。

## 解决与验证
- 待实现后补充 git/vim/gcc 等应用场景验证。

## 下一步
- 完成 VFS/FAT32/ext4 最小读写后进入网络阶段。
