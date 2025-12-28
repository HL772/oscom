# 01_boot.md

## 目标
- 规范启动链路，覆盖 QEMU RISC-V64/LoongArch64 与实板。
- 建立最小可运行内核入口与平台初始化流程。

## 设计
- 链接脚本定义内核加载地址与段布局（.text/.rodata/.data/.bss）。
- `entry.S` 负责关中断、设置早期栈、清理 BSS、跳转 Rust 入口。
- Rust 入口 `rust_main` 完成早期日志、DTB 解析、内存/中断/时钟等子系统初始化，并开启早期分页与定时器 tick。
- 平台差异通过 `platforms/` 配置与 `arch/` 入口隔离。

## 关键数据结构
- BootInfo：启动参数、内存布局、设备树/ACPI 指针。
- PlatformDesc：平台能力与设备信息抽象。
- EarlyUart：早期串口输出封装。
- DtbInfo：从设备树提取的内存与设备信息。

## 关键流程图或伪代码
```text
entry.S
  -> disable_interrupts
  -> setup_stack
  -> clear_bss
  -> jump rust_main

rust_main
  -> early_log_init
  -> parse_bootinfo
  -> init_platform
  -> init_subsystems
  -> start_init_task
```

## 风险与权衡
- 早期日志便于调试，但可能影响启动性能。
- 不同引导环境（OpenSBI/UEFI/bootloader）差异导致路径分叉。

## 测试点
- QEMU 启动打印与基本异常/中断。
- 最小 init 任务运行与退出。
