# phase_0_kickoff.md

## 目标
- 完成仓库结构与构建/测试入口的最小骨架。
- 固定工具链并准备交付物目录与脚本。

## 进展
- 完成目录骨架与 workspace/toolchain 配置。
- 添加 Makefile 与 scripts/ 入口脚本（占位）。
- 初始化 docs/design 与 docs/process 骨架。
- 添加导出脚本与交付物占位（tools/、build_env/、LICENSE 等）。

## 问题与定位
- 许可证与初始目标平台尚未确认。
- 构建/运行/测试脚本当前为占位，尚未接入真实流程。

## 解决与验证
- 当前阶段以结构与入口为主，未执行构建/测试验证。

## 下一步
- 确定首个目标平台（建议先 QEMU RISC-V64）。
- 建立最小启动链路（链接脚本、entry.S、rust_main）。
- 接入最小可运行的 build/run/test-qemu-smoke。
