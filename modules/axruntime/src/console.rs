//! Console output helpers and formatting macros.

use core::fmt::{self, Write};

use crate::sbi;

struct Console;

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            sbi::console_putchar(byte);
        }
        Ok(())
    }
}

/// Write formatted arguments to the SBI console.
pub(crate) fn print(args: fmt::Arguments) {
    let mut console = Console;
    console.write_fmt(args).ok();
}

/// Print without a trailing newline.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::console::print(format_args!($($arg)*))
    };
}

/// Print with a trailing newline.
#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n")
    };
    ($fmt:expr $(, $($arg:tt)*)?) => {
        $crate::print!(concat!($fmt, "\n") $(, $($arg)*)?)
    };
}
