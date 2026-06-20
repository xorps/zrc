//! AArch64 Linux syscall ABI.
//!
//! Convention: number in `x8`, args in `x0..x5`, result in `x0`, via `svc #0`.
//! Note the syscall *numbers* are the asm-generic table and differ from x86-64.

use core::arch::asm;

// Process entry. At exec, `sp` points at argc and is already 16-byte aligned.
core::arch::global_asm!(
    ".text",
    ".globl _start",
    ".type _start, @function",
    "_start:",
    "  mov x29, xzr",        // clear frame pointer
    "  mov x30, xzr",        // clear link register
    "  mov x0, sp",          // arg0 = stack_top (points at argc)
    "  and sp, x0, #-16",    // keep sp 16-byte aligned
    "  bl rust_start",       // -> crate::rust_start(*const usize) -> !
    "  brk #1",              // unreachable
);

#[inline]
pub unsafe fn syscall0(n: usize) -> usize {
    let r;
    asm!("svc #0", in("x8") n, lateout("x0") r, options(nostack));
    r
}

#[inline]
pub unsafe fn syscall1(n: usize, a1: usize) -> usize {
    let r;
    asm!("svc #0", in("x8") n, inlateout("x0") a1 => r, options(nostack));
    r
}

#[inline]
pub unsafe fn syscall2(n: usize, a1: usize, a2: usize) -> usize {
    let r;
    asm!("svc #0", in("x8") n, inlateout("x0") a1 => r, in("x1") a2, options(nostack));
    r
}

#[inline]
pub unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> usize {
    let r;
    asm!("svc #0", in("x8") n, inlateout("x0") a1 => r, in("x1") a2, in("x2") a3,
        options(nostack));
    r
}

#[inline]
pub unsafe fn syscall4(n: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> usize {
    let r;
    asm!("svc #0", in("x8") n, inlateout("x0") a1 => r, in("x1") a2, in("x2") a3,
        in("x3") a4, options(nostack));
    r
}

#[inline]
pub unsafe fn syscall5(n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> usize {
    let r;
    asm!("svc #0", in("x8") n, inlateout("x0") a1 => r, in("x1") a2, in("x2") a3,
        in("x3") a4, in("x4") a5, options(nostack));
    r
}

#[inline]
pub unsafe fn syscall6(
    n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize,
) -> usize {
    let r;
    asm!("svc #0", in("x8") n, inlateout("x0") a1 => r, in("x1") a2, in("x2") a3,
        in("x3") a4, in("x4") a5, in("x5") a6, options(nostack));
    r
}

/// AArch64 syscall numbers (asm-generic `unistd.h`).
pub mod nr {
    pub const MKNODAT: usize = 33;
    pub const MKDIRAT: usize = 34;
    pub const SYMLINKAT: usize = 36;
    pub const UMOUNT2: usize = 39;
    pub const MOUNT: usize = 40;
    pub const PIVOT_ROOT: usize = 41;
    pub const CHDIR: usize = 49;
    pub const FCHDIR: usize = 50;
    pub const CHROOT: usize = 51;
    pub const FCHMODAT: usize = 53;
    pub const IOCTL: usize = 29;
    pub const OPENAT: usize = 56;
    pub const CLOSE: usize = 57;
    pub const READ: usize = 63;
    pub const WRITE: usize = 64;
    pub const READLINKAT: usize = 78;
    pub const NEWFSTATAT: usize = 79;
    pub const EXIT: usize = 93;
    pub const EXIT_GROUP: usize = 94;
    pub const UNSHARE: usize = 97;
    pub const SECCOMP: usize = 277;
    pub const NANOSLEEP: usize = 101;
    pub const PIPE2: usize = 59;
    pub const DUP3: usize = 24;
    pub const UNLINKAT: usize = 35;
    pub const GETPPID: usize = 173;
    pub const SETHOSTNAME: usize = 161;
    pub const PRCTL: usize = 167;
    pub const CAPGET: usize = 90;
    pub const CAPSET: usize = 91;
    pub const PRLIMIT64: usize = 261;
    pub const GETPID: usize = 172;
    pub const GETUID: usize = 174;
    pub const GETGID: usize = 176;
    pub const KILL: usize = 129;
    pub const SETGID: usize = 144;
    pub const SETUID: usize = 146;
    pub const SETGROUPS: usize = 159;
    pub const SETNS: usize = 268;
    pub const MUNMAP: usize = 215;
    pub const CLONE: usize = 220;
    pub const EXECVE: usize = 221;
    pub const MMAP: usize = 222;
    pub const WAIT4: usize = 260;
}
