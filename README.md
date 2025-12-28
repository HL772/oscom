# Project Aurora

面向 OSComp 内核赛道的 Rust 组件化内核工程。

## 快速入口
- 设计文档：`docs/design/`
- 过程文档：`docs/process/`
- 构建/测试入口：`Makefile`

## 常用命令
```bash
make help
make build ARCH=riscv64 PLATFORM=qemu
make run ARCH=riscv64 PLATFORM=qemu FS=path/to/ext4.img
make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu FS=path/to/ext4.img
```

当前阶段仅接入 RISC-V64 QEMU 最小启动链路。

## 目录结构
- `modules/` 内核服务层
- `crates/` 可在 host 侧单测的通用库
- `platforms/` 平台配置
- `apps/` 用户态/测试程序
- `arch/` 架构相关代码
- `drivers/` 设备驱动
- `scripts/` 构建/运行/测试脚本
- `tools/` 导出与日志采集工具
- `docs/` 设计文档与过程文档
