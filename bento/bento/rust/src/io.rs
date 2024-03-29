/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2020 Samantha Miller, Kaiyuan Zhang, Danyang Zhuo, Tom
      Anderson, Ang Chen, University of Washington
 *
 * Partially based on code from fishinabarrel/linux-kernel-module-rust on Github
 *
 */

use core;

use core::cmp;

#[allow(unused_unsafe)]
#[macro_export]
macro_rules! c_str {
    ($arg:expr) => {
        concat!($arg, '\x00')
    };
}

// From kernel/print/printk.c
const LOG_LINE_MAX: usize = 1024 - 32;

// From fishinabarrel/linux-kernel-module-rust
/// Empty structure that uses libcore's `fmt::Write` trait to provide support for writing formatted
/// Arguments lists (as generated by the built-in `format_args!()` macro`)
pub struct KernelDebugWriter {
    data: [u8; LOG_LINE_MAX],
    pos: usize,
}

impl KernelDebugWriter {
    pub fn new() -> KernelDebugWriter {
        KernelDebugWriter {
            data: [0u8; LOG_LINE_MAX],
            pos: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.pos]
    }
}

impl core::fmt::Write for KernelDebugWriter {
    fn write_str(&mut self, message: &str) -> core::fmt::Result {
        #[allow(unused_unsafe)]
        let copy_len = cmp::min(LOG_LINE_MAX - self.pos, message.as_bytes().len());
        self.data[self.pos..self.pos + copy_len].copy_from_slice(&message.as_bytes()[..copy_len]);
        self.pos += copy_len;
        Ok(())
    }
}

#[macro_export]
macro_rules! print {
    // Static (zero-allocation) implementation that uses compile-time `concat!()` only
    ($fmt:expr) => ({
    use $crate::c_str;
	let msg = c_str!($fmt);
	let ptr = msg.as_ptr() as *const $crate::kernel::raw::c_char;
	unsafe {
	    $crate::kernel::ffi::_printk(ptr);
	}
    });

    // Dynamic implementation that processes format arguments
    ($fmt:expr, $($arg:tt)*) => ({
	use ::core::fmt::Write;
	use $crate::io::KernelDebugWriter;

	let mut writer = KernelDebugWriter::new();
	writer.write_fmt(format_args!(concat!($fmt, "\n"), $($arg)*)).unwrap();
    unsafe {
	    $crate::kernel::ffi::printk(writer.as_bytes().as_ptr() as *const $crate::kernel::raw::c_char);
    }
    });
}

#[macro_export]
macro_rules! println {
    ($fmt:expr)              => ({
        use $crate::print;
        //print!(concat!($fmt, "\n"))
        print!($fmt)
    });
    ($fmt:expr, $($arg:tt)+) => ({
        use $crate::print;
        //print!(concat!($fmt, "\n"), $($arg)*)
        print!($fmt, $($arg)*)
    });
}

#[macro_export]
macro_rules! printk {
    ($fmt:expr) => {{
        let msg = c_str!($fmt);
        let ptr = msg.as_ptr() as *const kernel::raw::c_char;
        unsafe {
            $crate::kernel::ffi::printk(ptr);
        }
    }};
}
