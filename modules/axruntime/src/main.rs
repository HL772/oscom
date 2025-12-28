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
mod wait;
mod wait_queue;
mod task;
mod scheduler;
mod runtime;

use core::panic::PanicInfo;

core::arch::global_asm!(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../arch/riscv64/entry.S")));
core::arch::global_asm!(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../arch/riscv64/trap.S")));

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

    mm::init(dtb_info.memory);

    let timebase = dtb_info.timebase_frequency.unwrap_or(10_000_000);
    let tick_hz = 10u64;
    let interval = time::init(timebase, tick_hz);
    crate::println!("timer: tick={}Hz interval={} ticks", tick_hz, interval);
    trap::enable_timer_interrupt(interval);

    runtime::init();

    cpu::idle_loop();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    crate::println!("panic: {}", info);
    sbi::shutdown();
}
