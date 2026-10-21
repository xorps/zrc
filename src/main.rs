//! zrc: an OCI container runtime with no libc, no heap and no panics.
//!
//! It builds for the bare `*-unknown-none` targets, enters through
//! `xorpio::entry!`, and reaches the kernel only through xorpio's syscalls.
//! Memory is static or on the stack, sized to kernel limits; strings from
//! argv and `config.json` are used in place. Release builds prove they
//! cannot panic: the panic handler calls a symbol that does not exist, so
//! any panic path the optimizer leaves in fails the link.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

mod caps;
mod cgroup;
mod cli;
mod container;
mod fixed;
mod init;
mod io;
mod json;
mod oci;
mod path;
mod proc;
mod rootfs;
mod seccomp;
mod state;
#[cfg(feature = "sysbox")]
mod sysbox;

use xorpio::io::{STDOUT, write_all};
use xorpio::process;

use crate::cli::Command;
use crate::container::{ARENA, report};

#[cfg(not(test))]
xorpio::entry!(main);

/// Exit status for usage errors, as runc's.
const USAGE_ERROR: i32 = 2;

fn main() -> i32 {
    // Runtime files get exactly the modes zrc asks for; the container
    // process gets the umask of its spec.
    process::umask(0);
    // No descriptor zrc was handed may reach a container.
    if let Err(e) = xorpio::io::close_range(3, u32::MAX, xorpio::io::CLOSE_RANGE_CLOEXEC) {
        return report("close_range", &e);
    }
    let cmd = match cli::parse(process::args()) {
        Ok(cmd) => cmd,
        Err(e) => {
            io::fail("usage", &e);
            return USAGE_ERROR;
        }
    };
    match cmd {
        Command::Create(a) => {
            let Some(arena) = ARENA.take() else { return 1 };
            container::create(&a, arena).map_or_else(|e| report("create", &e), |()| 0)
        }
        Command::Run(a) => {
            let Some(arena) = ARENA.take() else { return 1 };
            container::run(&a, arena).unwrap_or_else(|e| report("run", &e))
        }
        Command::Start { root, id } => {
            container::start(root, id).map_or_else(|e| report("start", &e), |()| 0)
        }
        Command::State { root, id } => {
            container::state(root, id).map_or_else(|e| report("state", &e), |()| 0)
        }
        Command::Kill {
            root,
            id,
            signal,
            all,
        } => container::kill(root, id, signal, all).map_or_else(|e| report("kill", &e), |()| 0),
        Command::Delete { root, id, force } => {
            container::delete(root, id, force).map_or_else(|e| report("delete", &e), |()| 0)
        }
        Command::Version => print(&[
            "zrc version ",
            env!("CARGO_PKG_VERSION"),
            "\nspec: ",
            state::OCI_VERSION,
            "\n",
        ]),
        Command::Help => print(&[cli::USAGE]),
    }
}

fn print(parts: &[&str]) -> i32 {
    for part in parts {
        if let Err(e) = write_all(STDOUT, part.as_bytes()) {
            return report("write", &e);
        }
    }
    0
}

#[cfg(all(not(test), not(debug_assertions), not(zrc_find_panics)))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe extern "C" {
        /// Never defined: referencing it fails the link of any release
        /// build that still contains a panic.
        fn zrc_release_build_must_not_panic() -> !;
    }
    unsafe { zrc_release_build_must_not_panic() }
}

/// Debug builds keep overflow checks, which can panic; `--cfg
/// zrc_find_panics` links a release build anyway to locate panic paths
/// (`make panics`).
#[cfg(all(not(test), any(debug_assertions, zrc_find_panics)))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    let _ = write_all(xorpio::io::STDERR, b"zrc: panic\n");
    process::exit(101)
}
