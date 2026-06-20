//! Tiny formatted output over raw `write(2)`, plus print macros.

use core::fmt::{self, Write};

use crate::sys;

/// A writable file descriptor usable with `core::fmt`.
pub struct Fd(pub usize);

impl Write for Fd {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut buf = s.as_bytes();
        while !buf.is_empty() {
            match sys::write(self.0, buf) {
                Ok(0) | Err(_) => return Err(fmt::Error),
                Ok(n) => buf = &buf[n..],
            }
        }
        Ok(())
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    let _ = Fd(sys::STDOUT).write_fmt(args);
}

#[doc(hidden)]
pub fn _eprint(args: fmt::Arguments) {
    let _ = Fd(sys::STDERR).write_fmt(args);
}

#[macro_export]
macro_rules! print {
    ($($a:tt)*) => { $crate::io::_print(format_args!($($a)*)) };
}

#[macro_export]
macro_rules! println {
    ()           => { $crate::io::_print(format_args!("\n")) };
    ($($a:tt)*)  => { $crate::io::_print(format_args!("{}\n", format_args!($($a)*))) };
}

#[macro_export]
macro_rules! eprintln {
    ()           => { $crate::io::_eprint(format_args!("\n")) };
    ($($a:tt)*)  => { $crate::io::_eprint(format_args!("{}\n", format_args!($($a)*))) };
}
