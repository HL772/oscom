# 06_fs_vfs.md

## 目标
- 建立统一 VFS 抽象，支持 FAT32/ext4 挂载与路径解析。
- 引入页缓存与写回策略，提升 I/O 性能并保证一致性。
- 满足 OSComp 关键应用（busybox/git/vim/gcc/rustc）文件语义需求。

## 设计
- VFS 以 `Inode`/`File` trait 为核心，提供统一的 `lookup/read/write/stat` 接口。
- 早期阶段先以 `InodeId` 句柄定义 VFS trait，避免引入全局分配器；后续再切换到 `Arc<dyn Inode>` 形式。
- 挂载点采用 `MountTable` 管理，根文件系统可切换 FAT32/ext4。
- 路径解析走 dentry 缓存，减少重复 lookup。
- 页缓存以页为单位缓存文件数据，写入采用 write-back + 定期刷盘。
- 块设备通过 `BlockDevice` 抽象接入 virtio-block。
- 权限与时间戳语义对齐 Linux，错误码通过 errno 映射返回。

## 关键数据结构
- `SuperBlock`：文件系统实例与全局状态。
- `Inode`：文件元数据与操作入口。
- `Dentry`：路径解析缓存与目录项关系。
- `File`：打开文件句柄与读写偏移。
- `PageCache`/`BufferCache`：页/块缓存与脏页写回管理。
- `MountTable`：挂载点与根目录管理。

## 关键流程图或伪代码
```text
open(path)
  -> lookup dentry
  -> inode = dentry.inode
  -> file = inode.open()

read(file, off, len)
  -> page = page_cache.get(inode, off)
  -> if miss: read block -> fill page
  -> copy to user buffer
```

## 风险与权衡
- ext4 元数据复杂，正确性实现成本高。
- write-back 提升性能但增加崩溃一致性风险，需要日志或简化策略。
- 缓存占用内存与命中率需要平衡。

## 测试点
- 基础文件操作：创建/读写/删除/重命名。
- 大文件读写与多目录层级路径解析。
- git/vim/gcc/rustc 关键路径回归。
- ext4 镜像挂载与一致性测试（读写后比对）。
