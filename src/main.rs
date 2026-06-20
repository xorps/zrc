//! zrc — a libc-free, zero-dependency OCI container runtime.
//!
//! We build for the bare-metal `*-unknown-none` targets so nothing links libc,
//! supply our own `_start` (see `arch/`), and talk to the kernel exclusively
//! through raw syscalls. The only "runtime" is `core` + `alloc` (with our own
//! `mmap`-backed allocator in `heap`).

#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
mod io;
mod arch;
mod caps;
mod cgroup;
mod container;
mod heap;
mod json;
mod oci;
mod seccomp;
mod state;
mod sys;

#[cfg(feature = "sysbox")]
mod sysbox;

use alloc::vec::Vec;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    eprintln!("zrc: panic: {}", info);
    sys::exit_group(101)
}

/// Real entry point, tail-called from the arch-specific `_start` with the
/// original stack pointer (which points at `argc`).
#[no_mangle]
pub unsafe extern "C" fn rust_start(stack_top: *const usize) -> ! {
    let argc = *stack_top;
    let argv = stack_top.add(1) as *const *const u8;

    let mut args: Vec<&'static str> = Vec::with_capacity(argc);
    for i in 0..argc {
        let p = *argv.add(i);
        args.push(cstr(p));
    }

    sys::exit_group(run(&args))
}

/// Borrow a NUL-terminated C string as a `&str` (lossy: invalid UTF-8 → "").
unsafe fn cstr(p: *const u8) -> &'static str {
    if p.is_null() {
        return "";
    }
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    let bytes = core::slice::from_raw_parts(p, n);
    core::str::from_utf8(bytes).unwrap_or("")
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Top-level dispatch. Mirrors the runc CLI surface: global options (notably
/// `--root`) precede the subcommand, which has its own options and operands.
/// We accept and ignore the globals containerd passes that don't apply yet
/// (`--log`, `--log-format`, `--debug`, `--systemd-cgroup`).
fn run(args: &[&str]) -> i32 {
    let prog = args.first().copied().unwrap_or("zrc");
    let mut root = crate::state::DEFAULT_ROOT;
    let mut i = 1;

    while i < args.len() {
        match args[i] {
            "--root" => {
                i += 1;
                match args.get(i) {
                    Some(r) => root = r,
                    None => return arg_err("--root requires a directory"),
                }
            }
            // value-taking globals we ignore
            "--log" | "--log-format" => i += 1,
            // flag globals we ignore
            "--debug" | "--systemd-cgroup" => {}
            "-h" | "--help" | "help" => {
                usage(prog);
                return 0;
            }
            "-v" | "--version" | "version" => {
                print_version();
                return 0;
            }
            s if s.starts_with('-') => {
                // Unknown global: skip rather than fail (forward-compat with shim).
            }
            _ => break, // subcommand
        }
        i += 1;
    }

    let cmd = match args.get(i) {
        Some(c) => *c,
        None => {
            usage(prog);
            return 0;
        }
    };
    let rest = &args[i + 1..];

    match cmd {
        "run" => cmd_run(rest),
        "create" => cmd_create(root, rest),
        "start" => match positional(rest) {
            Some(id) => container::start(root, id),
            None => arg_err("start requires <id>"),
        },
        "state" => match positional(rest) {
            Some(id) => container::state_cmd(root, id),
            None => arg_err("state requires <id>"),
        },
        "kill" => cmd_kill(root, rest),
        "delete" => cmd_delete(root, rest),
        other => {
            eprintln!("zrc: unknown command '{}'", other);
            usage(prog);
            1
        }
    }
}

fn arg_err(msg: &str) -> i32 {
    eprintln!("zrc: {}", msg);
    1
}

/// First non-flag operand.
fn positional<'a>(rest: &[&'a str]) -> Option<&'a str> {
    rest.iter().copied().find(|a| !a.starts_with('-'))
}

/// Pull the value following `name` (or its short alias) from `rest`.
fn opt_value<'a>(rest: &[&'a str], names: &[&str]) -> Option<&'a str> {
    let mut i = 0;
    while i < rest.len() {
        if names.contains(&rest[i]) {
            return rest.get(i + 1).copied();
        }
        i += 1;
    }
    None
}

/// `zrc run [-b dir] <id>` — synchronous create+start (handy for testing).
fn cmd_run(rest: &[&str]) -> i32 {
    let bundle = opt_value(rest, &["-b", "--bundle"]).unwrap_or(".");
    let id = positional_skipping(rest).unwrap_or("default");
    container::run(bundle, id)
}

/// `zrc create -b <dir> [--pid-file f] [--console-socket s] <id>`
fn cmd_create(root: &str, rest: &[&str]) -> i32 {
    let bundle = opt_value(rest, &["-b", "--bundle"]).unwrap_or(".");
    let pid_file = opt_value(rest, &["--pid-file"]);
    let console = opt_value(rest, &["--console-socket"]);
    let id = match positional_skipping(rest) {
        Some(id) => id,
        None => return arg_err("create requires <id>"),
    };
    container::create(root, id, bundle, pid_file, console)
}

/// `zrc kill <id> [signal]` (signal defaults to SIGTERM).
fn cmd_kill(root: &str, rest: &[&str]) -> i32 {
    let mut ops = rest.iter().copied().filter(|a| !a.starts_with('-'));
    let id = match ops.next() {
        Some(id) => id,
        None => return arg_err("kill requires <id>"),
    };
    let sig = ops.next().unwrap_or("SIGTERM");
    container::kill_cmd(root, id, sig)
}

/// `zrc delete [-f|--force] <id>`
fn cmd_delete(root: &str, rest: &[&str]) -> i32 {
    let force = rest.iter().any(|a| *a == "-f" || *a == "--force");
    let id = match positional(rest) {
        Some(id) => id,
        None => return arg_err("delete requires <id>"),
    };
    container::delete_cmd(root, id, force)
}

/// Like `positional`, but skips the value of known value-taking flags so the
/// `<id>` operand isn't confused with, say, a bundle path.
fn positional_skipping<'a>(rest: &[&'a str]) -> Option<&'a str> {
    const VALUE_FLAGS: &[&str] = &["-b", "--bundle", "--pid-file", "--console-socket"];
    let mut i = 0;
    while i < rest.len() {
        let a = rest[i];
        if VALUE_FLAGS.contains(&a) {
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        return Some(a);
    }
    None
}

fn print_version() {
    // runc-style version block so tools that scrape it are satisfied.
    println!("zrc version {}", VERSION);
    println!("spec: {}", crate::state::OCI_VERSION);
    println!("target: {}", arch_name());
}

fn arch_name() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "linux/amd64"
    } else if cfg!(target_arch = "aarch64") {
        "linux/arm64"
    } else {
        "linux/unknown"
    }
}

fn usage(prog: &str) {
    println!("zrc {} — libc-free OCI runtime", VERSION);
    println!();
    println!("usage: {} [--root dir] <command> [args]", prog);
    println!();
    println!("commands:");
    println!("  create -b <dir> [--pid-file f] [--console-socket s] <id>");
    println!("  start  <id>            release a created container");
    println!("  state  <id>            print OCI state JSON");
    println!("  kill   <id> [signal]   signal a container (default SIGTERM)");
    println!("  delete [-f] <id>       remove a stopped container");
    println!("  run    -b <dir> <id>   create+start synchronously (testing)");
    println!("  version                print version");
}
