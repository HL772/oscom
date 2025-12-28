# Changelog

## Unreleased
- Bootstrap RISC-V64 QEMU minimal kernel (entry.S, linker script, SBI console).
- Wire build/run/gdb/test-qemu-smoke scripts for the initial bring-up.
- Add MIT license and third-party notices placeholder.
- Add memory management scaffolding (address types, PTE layout, bump allocator stub).
- Add DTB parsing to discover memory and UART information at boot.
- Enable early Sv39 paging with an identity-mapped kernel page table.
- Enable periodic timer ticks using SBI set_timer and DTB timebase frequency.
- Enter an idle loop after early initialization to keep the kernel running.
- Track timer tick count in a dedicated time module.
- Add a basic sleep_ms helper driven by timer ticks.
- Initialize a bump frame allocator starting after ekernel within identity map.
- Allocate early page tables from the frame allocator.
- Add a Waiter helper for timeout-based waiting.
- Add a WaitQueue helper with notify_one/notify_all.
- Add minimal run queue and scheduler tick hook scaffolding.
