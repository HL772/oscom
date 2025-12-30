#![no_std]
#![no_main]

mod console;
mod dtb;
mod sbi;
mod trap;
mod mm;
mod cpu;
mod time;
mod sleep;
mod sleep_queue;
mod wait;
mod wait_queue;
mod futex;
mod syscall;
mod user;
mod fs;
mod virtio_blk;
mod task_wait_queue;
mod task;
mod scheduler;
mod runtime;
mod context;
mod stack;
mod config;
mod process;

use core::panic::PanicInfo;

core::arch::global_asm!(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../arch/riscv64/entry.S")));
core::arch::global_asm!(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../arch/riscv64/trap.S")));
core::arch::global_asm!(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../arch/riscv64/context.S")));

#[no_mangle]
pub extern "C" fn rust_main(hart_id: usize, dtb_addr: usize) -> ! {
    trap::init();
    crate::println!("Aurora kernel booting...");
    crate::println!("hart_id={:#x} dtb={:#x}", hart_id, dtb_addr);
    let dtb_info = match dtb::parse(dtb_addr) {
        Ok(info) => info,
        Err(err) => {
            crate::println!("dtb parse error: {}", err);
            dtb::DtbInfo::default()
        }
    };

    if let Some(region) = dtb_info.uart {
        crate::println!(
            "dtb: uart base={:#x} size={:#x}",
            region.base,
            region.size
        );
    }

    if let Some(freq) = dtb_info.timebase_frequency {
        crate::println!("dtb: timebase-frequency={}Hz", freq);
    }

    for region in dtb_info.virtio_mmio_regions() {
        crate::println!(
            "dtb: virtio-mmio base={:#x} size={:#x}",
            region.base,
            region.size
        );
    }

    mm::init(dtb_info.memory, dtb_info.virtio_mmio_regions());
    fs::init(dtb_info.virtio_mmio_regions());

    let timebase = dtb_info.timebase_frequency.unwrap_or(10_000_000);
    let tick_hz = config::DEFAULT_TICK_HZ;
    let interval = time::init(timebase, tick_hz);
    crate::println!("timer: tick={}Hz interval={} ticks", tick_hz, interval);
    trap::enable_timer_interrupt(interval);

    runtime::init();

    if config::ENABLE_USER_TEST {
        if let Some(ctx) = user::prepare_user_test() {
            crate::println!("user: spawn user task entry={:#x}", ctx.entry);
            if runtime::spawn_user(ctx).is_none() {
                crate::println!("user: spawn failed");
            }
        } else {
            crate::println!("user: setup failed, continue in kernel");
        }
    }

    runtime::idle_loop();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    crate::println!("panic: {}", info);
    sbi::shutdown();
}
