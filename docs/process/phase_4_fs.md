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
- memfs 添加 `/tmp/log` 可写文件，占位提供最小写入路径。
- 引入 MountTable 挂载表，预留 `/`、`/dev`、`/proc` 挂载点，路径解析改为最长前缀匹配。
- 新增 devfs/procfs 占位实现，/dev 路径解析与元数据读取走 devfs。
- 新增 BlockDevice trait 与 BlockCache 直通占位，作为后续块设备与缓存接入骨架。
- 增加 FAT32 BPB 解析与根簇定位骨架，预留目录与数据读取实现入口。
- 增加 ext4 superblock 解析与根 inode 占位，补齐最小元数据读取入口。
- 增加 /proc 挂载点的目录句柄占位，getdents64 返回最小 `.`/`..` 项。
- VFS trait 增加 `read_dir` 目录枚举接口，`getdents64` 走统一目录遍历返回。
- FAT32 完成目录项解析 + 簇链读取，支持 `/init` 文件读取与根目录枚举。
- FAT32 写路径支持更新目录项大小与扩展簇链，覆盖文件增长与多簇写入。
- FAT32 目录项更新支持子目录查找，新增子目录写入回读的 host 测试。
- FAT32 增加最小 create 支持（短文件名、预分配簇），新增根目录与子目录创建测试。
- FAT32 create 已接入 openat 的 O_CREAT/O_EXCL 路径，便于用户态创建文件。
- 使用内存块设备构建 FAT32 ramdisk 挂载为 rootfs，`/init` 通过 VFS 读取。
- ext4 增加组描述符 + inode 表读取，目录查找与只读读路径打通。
- fd 表改为记录通用 VFS 句柄，open/read/write/stat/getdents64 统一走 VFS。
- 新增 DTB virtio-mmio 枚举与 MMIO 映射，初始化 virtio-blk 驱动作为 BlockDevice。
- rootfs 支持 virtio-blk 外部镜像挂载 ext4/FAT32，失败回退到 ramdisk。
- ramdisk rootfs 允许写回到内存镜像，支持 FAT32 写入回读验证。
- virtio-blk 请求等待改为 IRQ 唤醒 + wait queue 阻塞；无 IRQ 时回退轮询。
- 新增 `tools/build_init_elf.py` 与 `scripts/mkfs_ext4.sh` 生成最小 ext4 镜像用于 QEMU 测试。
- ext4 读路径扩展到 extent 树深度>0 与间接块（single/double/triple）。
- 增加 extent 树与间接块覆盖的单元测试。
- 新增 ext4 `/init` VFS 读取自测用例，覆盖根目录与 `/etc` 的 read_dir offset 枚举、多块读路径与 `/etc/issue`/`/etc/large` 读取。
- QEMU 启动时输出 `vfs: mounted ext4 rootfs`，ext4 冒烟用例强制检查该标记。
- `/init` 用户态程序增加 `/etc/issue` 读取并在 ext4 冒烟中检查输出。
- 用户态自测增加 FAT32 文件写入回读路径，ramdisk 用例验证写入回读日志。
- ext4 读路径将块读取 scratch 缓冲迁移到共享区，避免内核栈溢出。

## 问题与定位
- ext4 extent 深度>0 与间接块读路径已经补齐，后续仍需覆盖写路径。

## 解决与验证
- 已通过 `make test-oscomp ARCH=riscv64 PLATFORM=qemu`（ramdisk/ext4 自研自测）。
- `cargo test -p axfs`
- `AXFS_EXT4_IMAGE=build/rootfs.ext4 cargo test -p axfs ext4_init_image`
- `make rootfs-ext4`
- `EXPECT_EXT4=1 USER_TEST=1 make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu FS=build/rootfs.ext4`
- `make test-oscomp ARCH=riscv64 PLATFORM=qemu`（自研测例覆盖 ramdisk/ext4 启动与 /init execve）
- `cargo test -p axfs`
- `EXPECT_FAT32=1 USER_TEST=1 make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu`

## 下一步
- 完成 VFS/FAT32/ext4 最小读写后进入网络阶段。
