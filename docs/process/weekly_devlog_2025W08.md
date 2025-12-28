# weekly_devlog_2025W08.md

## 周目标
- 建立仓库最小骨架与交付物入口。

## 本周进展
- 初始化目录结构与 Rust workspace/toolchain。
- 添加 Makefile 与 scripts/ 入口脚本并接入 RISC-V64 QEMU。
- 实现最小内核启动链路与 SBI 控制台输出。
- 选定 MIT License 并补齐第三方声明占位。
- QEMU 冒烟测试已跑通。
- 完成 S 态 trap 基础框架接入。
- 开始内存管理骨架（地址类型、PTE、bump allocator 占位）。
- 接入 DTB 解析以发现内存与 UART 信息。
- DTB 接入后 QEMU 冒烟测试仍通过。
- 建立 Sv39 identity 页表并启用分页。
- 接入 timebase-frequency 并启用定时器 tick。

## 问题
- OSComp 测例与 FS/Net 尚未接入。
- 多平台支持仍待完善。

## 下周计划
- 完成内存管理与陷入/中断基础框架。
- 接入最小文件系统与用户态加载流程。
