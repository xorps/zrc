//! x86-64 Linux syscall ABI.
//!
//! Convention: number in `rax`, args in `rdi, rsi, rdx, r10, r8, r9`,
//! result in `rax`. The `syscall` instruction clobbers `rcx` and `r11`.

use core::arch::asm;

// Process entry. At exec, %rsp points at argc; everything (argv, envp, auxv)
// follows on the stack. We must capture %rsp *before* any prologue touches it,
// so this is hand-written asm that hands the original stack pointer to Rust.
core::arch::global_asm!(
    ".text",
    ".globl _start",
    ".type _start, @function",
    "_start:",
    "  xor ebp, ebp",        // mark outermost frame
    "  mov rdi, rsp",        // arg0 = stack_top (points at argc)
    "  and rsp, -16",        // 16-byte align before the call
    "  call rust_start",     // -> crate::rust_start(*const usize) -> !
    "  ud2",                 // unreachable
);

#[inline]
pub unsafe fn syscall0(n: usize) -> usize {
    let r;
    asm!("syscall", inlateout("rax") n => r,
        lateout("rcx") _, lateout("r11") _, options(nostack));
    r
}

#[inline]
pub unsafe fn syscall1(n: usize, a1: usize) -> usize {
    let r;
    asm!("syscall", inlateout("rax") n => r, in("rdi") a1,
        lateout("rcx") _, lateout("r11") _, options(nostack));
    r
}

#[inline]
pub unsafe fn syscall2(n: usize, a1: usize, a2: usize) -> usize {
    let r;
    asm!("syscall", inlateout("rax") n => r, in("rdi") a1, in("rsi") a2,
        lateout("rcx") _, lateout("r11") _, options(nostack));
    r
}

#[inline]
pub unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> usize {
    let r;
    asm!("syscall", inlateout("rax") n => r, in("rdi") a1, in("rsi") a2, in("rdx") a3,
        lateout("rcx") _, lateout("r11") _, options(nostack));
    r
}

#[inline]
pub unsafe fn syscall4(n: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> usize {
    let r;
    asm!("syscall", inlateout("rax") n => r, in("rdi") a1, in("rsi") a2, in("rdx") a3,
        in("r10") a4, lateout("rcx") _, lateout("r11") _, options(nostack));
    r
}

#[inline]
pub unsafe fn syscall5(n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> usize {
    let r;
    asm!("syscall", inlateout("rax") n => r, in("rdi") a1, in("rsi") a2, in("rdx") a3,
        in("r10") a4, in("r8") a5, lateout("rcx") _, lateout("r11") _, options(nostack));
    r
}

#[inline]
pub unsafe fn syscall6(
    n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize,
) -> usize {
    let r;
    asm!("syscall", inlateout("rax") n => r, in("rdi") a1, in("rsi") a2, in("rdx") a3,
        in("r10") a4, in("r8") a5, in("r9") a6,
        lateout("rcx") _, lateout("r11") _, options(nostack));
    r
}

/// x86-64 syscall numbers (`asm/unistd_64.h`).
pub mod nr {
    pub const READ: usize = 0;
    pub const WRITE: usize = 1;
    pub const CLOSE: usize = 3;
    pub const IOCTL: usize = 16;
    pub const MMAP: usize = 9;
    pub const MUNMAP: usize = 11;
    pub const PRCTL: usize = 157;
    pub const CAPGET: usize = 125;
    pub const CAPSET: usize = 126;
    pub const PRLIMIT64: usize = 302;
    pub const PIVOT_ROOT: usize = 155;
    pub const CHROOT: usize = 161;
    pub const SETHOSTNAME: usize = 170;
    pub const MOUNT: usize = 165;
    pub const UMOUNT2: usize = 166;
    pub const CLONE: usize = 56;
    pub const EXECVE: usize = 59;
    pub const WAIT4: usize = 61;
    pub const CHDIR: usize = 80;
    pub const FCHDIR: usize = 81;
    pub const GETUID: usize = 102;
    pub const GETGID: usize = 104;
    pub const SETUID: usize = 105;
    pub const SETGID: usize = 106;
    pub const SETGROUPS: usize = 116;
    pub const GETPPID: usize = 110;
    pub const NANOSLEEP: usize = 35;
    pub const PIPE2: usize = 293;
    pub const DUP3: usize = 292;
    pub const UNLINKAT: usize = 263;
    pub const UNSHARE: usize = 272;
    pub const SECCOMP: usize = 317;
    pub const SETNS: usize = 308;
    pub const GETPID: usize = 39;
    pub const KILL: usize = 62;
    pub const EXIT: usize = 60;
    pub const EXIT_GROUP: usize = 231;
    pub const OPENAT: usize = 257;
    pub const MKDIRAT: usize = 258;
    pub const MKNODAT: usize = 259;
    pub const SYMLINKAT: usize = 266;
    pub const NEWFSTATAT: usize = 262;
    pub const FCHMODAT: usize = 268;
}
