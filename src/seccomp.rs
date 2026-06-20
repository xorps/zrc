//! seccomp-bpf syscall filtering.
//!
//! We assemble a classic-BPF program from the OCI `linux.seccomp` section and
//! install it with `seccomp(SECCOMP_SET_MODE_FILTER)`. Filtering is at the
//! syscall-name level (per-argument rules in the spec are not yet applied).
//! `SCMP_ACT_NOTIFY` is treated as ALLOW for now — real user-notification is the
//! Sysbox-interception milestone.

use alloc::vec::Vec;

use crate::oci::Seccomp;
use crate::sys;

// ---- BPF encoding ----
const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const BPF_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K

// seccomp_data field offsets.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;

// SECCOMP_RET_* action words.
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_KILL_THREAD: u32 = 0x0000_0000;
const RET_TRAP: u32 = 0x0003_0000;
const RET_ERRNO: u32 = 0x0005_0000;
const RET_TRACE: u32 = 0x7ff0_0000;
const RET_LOG: u32 = 0x7ffc_0000;
const RET_ALLOW: u32 = 0x7fff_0000;
const RET_USER_NOTIF: u32 = 0x7fc0_0000;

// SCMP_ACT_NOTIFY only becomes a real user-notification when the sysbox feature
// is built; otherwise it degrades to ALLOW so a notify-using profile still runs.
#[cfg(feature = "sysbox")]
const NOTIFY_RET: u32 = RET_USER_NOTIF;
#[cfg(not(feature = "sysbox"))]
const NOTIFY_RET: u32 = RET_ALLOW;

#[cfg(target_arch = "x86_64")]
const NATIVE_AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const NATIVE_AUDIT_ARCH: u32 = 0xC000_00B7;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter { code, jt: 0, jf: 0, k }
}
fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

fn action_ret(action: &str, errno: u16) -> u32 {
    match action {
        "SCMP_ACT_KILL" | "SCMP_ACT_KILL_THREAD" => RET_KILL_THREAD,
        "SCMP_ACT_KILL_PROCESS" => RET_KILL_PROCESS,
        "SCMP_ACT_TRAP" => RET_TRAP,
        "SCMP_ACT_ERRNO" => RET_ERRNO | (errno as u32 & 0xffff),
        "SCMP_ACT_TRACE" => RET_TRACE | (errno as u32 & 0xffff),
        "SCMP_ACT_LOG" => RET_LOG,
        "SCMP_ACT_ALLOW" => RET_ALLOW,
        "SCMP_ACT_NOTIFY" => NOTIFY_RET,
        _ => RET_ERRNO | 1, // unknown → EPERM, fail safe
    }
}

fn has_notify(sc: &Seccomp) -> bool {
    NOTIFY_RET == RET_USER_NOTIF
        && (sc.default_action == "SCMP_ACT_NOTIFY"
            || sc.rules.iter().any(|r| r.action == "SCMP_ACT_NOTIFY"))
}

/// Build the filter program. Each matched syscall jumps to an inline RET, so
/// jump offsets stay tiny regardless of how many syscalls are listed.
fn build(sc: &Seccomp) -> (Vec<SockFilter>, usize) {
    let mut p = Vec::new();
    let mut unknown = 0usize;

    // Reject foreign architectures outright (classic seccomp hardening).
    p.push(stmt(BPF_LD_W_ABS, OFF_ARCH));
    p.push(jump(BPF_JEQ_K, NATIVE_AUDIT_ARCH, 1, 0)); // match → skip the kill
    p.push(stmt(BPF_RET_K, RET_KILL_PROCESS));

    // Load the syscall number for the comparisons below.
    p.push(stmt(BPF_LD_W_ABS, OFF_NR));

    for rule in &sc.rules {
        let ret = action_ret(&rule.action, rule.errno);
        for name in &rule.names {
            match syscall_nr(name) {
                Some(nr) => {
                    // if A == nr: fall to the RET (jt=0); else skip it (jf=1)
                    p.push(jump(BPF_JEQ_K, nr, 0, 1));
                    p.push(stmt(BPF_RET_K, ret));
                }
                None => unknown += 1,
            }
        }
    }

    p.push(stmt(BPF_RET_K, action_ret(&sc.default_action, sc.default_errno)));
    (p, unknown)
}

/// Assemble and install the filter. Sets NO_NEW_PRIVS (required unless we hold
/// CAP_SYS_ADMIN). Call this last — after any syscalls the runtime itself needs.
///
/// Returns the user-notification fd (`>= 0`) when the profile uses
/// `SCMP_ACT_NOTIFY` and this is a sysbox build; otherwise `-1`. The caller is
/// responsible for handing a returned fd to a supervisor (see `supervise`).
pub fn install(sc: &Seccomp) -> Result<i32, &'static str> {
    let (prog, unknown) = build(sc);
    if unknown > 0 {
        eprintln!(
            "zrc: warning: {} seccomp syscall name(s) unknown to zrc and not filtered",
            unknown
        );
    }
    if prog.len() > 0xffff {
        return Err("seccomp program too large");
    }

    let _ = sys::prctl(sys::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    let notify = has_notify(sc);
    let flags = if notify {
        sys::SECCOMP_FILTER_FLAG_NEW_LISTENER
    } else {
        0
    };

    let fprog = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };
    let ret = sys::seccomp(
        sys::SECCOMP_SET_MODE_FILTER,
        flags,
        &fprog as *const SockFprog as usize,
    )
    .map_err(|_| "seccomp install")?;

    Ok(if notify { ret as i32 } else { -1 })
}

/// The seccomp user-notification supervisor loop (sysbox builds only). Runs in
/// a forked child that inherits `fd`; the kernel blocks each intercepted syscall
/// until we respond. This is the seam where `mount`, `setns`, etc. get emulated;
/// for now we acknowledge them with a synthesized success so the in-container
/// workload makes progress while we report what was intercepted.
///
/// Never returns — when the target dies, the pid namespace tears this down too.
#[cfg(feature = "sysbox")]
pub fn supervise(fd: usize) -> ! {
    loop {
        let mut req = sys::SeccompNotif::default();
        match sys::ioctl(
            fd,
            sys::SECCOMP_IOCTL_NOTIF_RECV,
            &mut req as *mut sys::SeccompNotif as usize,
        ) {
            Ok(_) => {}
            Err(4) => continue, // EINTR
            Err(_) => sys::exit_group(0), // listener gone → done
        }

        eprintln!(
            "zrc: sysbox: intercepted syscall nr={} from pid={} (args: {:#x} {:#x} {:#x})",
            req.data.nr, req.pid, req.data.args[0], req.data.args[1], req.data.args[3]
        );

        // Emulation handlers land here. Default: acknowledge with success.
        let resp = sys::SeccompNotifResp {
            id: req.id,
            val: 0,
            error: 0,
            flags: 0,
        };
        let _ = sys::ioctl(
            fd,
            sys::SECCOMP_IOCTL_NOTIF_SEND,
            &resp as *const sys::SeccompNotifResp as usize,
        );
    }
}

/// Syscall name → number for the native arch. Returns `None` for names we don't
/// know or that don't exist on this arch (those simply aren't filtered).
#[cfg(target_arch = "x86_64")]
fn syscall_nr(name: &str) -> Option<u32> {
    Some(match name {
        "read" => 0, "write" => 1, "open" => 2, "close" => 3, "stat" => 4,
        "fstat" => 5, "lstat" => 6, "poll" => 7, "lseek" => 8, "mmap" => 9,
        "mprotect" => 10, "munmap" => 11, "brk" => 12, "rt_sigaction" => 13,
        "rt_sigprocmask" => 14, "rt_sigreturn" => 15, "ioctl" => 16,
        "pread64" => 17, "pwrite64" => 18, "readv" => 19, "writev" => 20,
        "access" => 21, "pipe" => 22, "select" => 23, "sched_yield" => 24,
        "mremap" => 25, "msync" => 26, "madvise" => 28, "dup" => 32, "dup2" => 33,
        "nanosleep" => 35, "getpid" => 39, "sendfile" => 40, "socket" => 41,
        "connect" => 42, "accept" => 43, "sendto" => 44, "recvfrom" => 45,
        "sendmsg" => 46, "recvmsg" => 47, "shutdown" => 48, "bind" => 49,
        "listen" => 50, "getsockname" => 51, "setsockopt" => 54, "getsockopt" => 55,
        "clone" => 56, "fork" => 57, "vfork" => 58, "execve" => 59, "exit" => 60,
        "wait4" => 61, "kill" => 62, "uname" => 63, "fcntl" => 72, "fsync" => 74,
        "getcwd" => 79, "chdir" => 80, "rename" => 82, "mkdir" => 83, "rmdir" => 84,
        "creat" => 85, "link" => 86, "unlink" => 87, "symlink" => 88,
        "readlink" => 89, "chmod" => 90, "fchmod" => 91, "chown" => 92,
        "umask" => 95, "getrlimit" => 97, "getuid" => 102, "getgid" => 104,
        "setuid" => 105, "setgid" => 106, "geteuid" => 107, "getegid" => 108,
        "setpgid" => 109, "getppid" => 110, "setsid" => 112, "getgroups" => 115,
        "setgroups" => 116, "setresuid" => 117, "setresgid" => 119, "ptrace" => 101,
        "prctl" => 157, "arch_prctl" => 158, "setrlimit" => 160, "chroot" => 161,
        "mount" => 165, "umount2" => 166, "reboot" => 169, "sethostname" => 170,
        "init_module" => 175, "delete_module" => 176, "gettid" => 186,
        "futex" => 202, "sched_getaffinity" => 204, "getdents64" => 217,
        "set_tid_address" => 218, "clock_gettime" => 228, "clock_nanosleep" => 230,
        "exit_group" => 231, "epoll_ctl" => 233, "openat" => 257, "mkdirat" => 258,
        "mknodat" => 259, "fchownat" => 260, "newfstatat" => 262, "unlinkat" => 263,
        "renameat" => 264, "linkat" => 265, "symlinkat" => 266, "readlinkat" => 267,
        "fchmodat" => 268, "faccessat" => 269, "pselect6" => 270, "ppoll" => 271,
        "unshare" => 272, "set_robust_list" => 273, "splice" => 275,
        "utimensat" => 280, "epoll_pwait" => 281, "eventfd2" => 290,
        "epoll_create1" => 291, "dup3" => 292, "pipe2" => 293, "prlimit64" => 302,
        "seccomp" => 317, "getrandom" => 318, "memfd_create" => 319,
        "execveat" => 322, "statx" => 332, "rseq" => 334, "clone3" => 435,
        "close_range" => 436, "openat2" => 437, "faccessat2" => 439,
        "fchmodat2" => 452,
        _ => return None,
    })
}

#[cfg(target_arch = "aarch64")]
fn syscall_nr(name: &str) -> Option<u32> {
    Some(match name {
        "io_setup" => 0, "getcwd" => 17, "eventfd2" => 19, "epoll_create1" => 20,
        "epoll_ctl" => 21, "epoll_pwait" => 22, "dup" => 23, "dup3" => 24,
        "fcntl" => 25, "ioctl" => 29, "mknodat" => 33, "mkdirat" => 34,
        "unlinkat" => 35, "symlinkat" => 36, "linkat" => 37, "renameat" => 38,
        "umount2" => 39, "mount" => 40, "pivot_root" => 41, "statfs" => 43,
        "ftruncate" => 46, "faccessat" => 48, "chdir" => 49, "fchmod" => 52,
        "fchmodat" => 53, "fchownat" => 54, "fchown" => 55, "openat" => 56,
        "close" => 57, "pipe2" => 59, "getdents64" => 61, "lseek" => 62,
        "read" => 63, "write" => 64, "readv" => 65, "writev" => 66, "pread64" => 67,
        "pwrite64" => 68, "ppoll" => 73, "splice" => 76, "readlinkat" => 78,
        "newfstatat" => 79, "fstat" => 80, "fsync" => 82, "utimensat" => 88,
        "exit" => 93, "exit_group" => 94, "futex" => 98, "set_robust_list" => 99,
        "nanosleep" => 101, "clock_gettime" => 113, "clock_nanosleep" => 115,
        "sched_yield" => 124, "kill" => 129, "rt_sigaction" => 134,
        "rt_sigprocmask" => 135, "rt_sigreturn" => 139, "setpgid" => 154,
        "setsid" => 157, "getgroups" => 158, "setgroups" => 159, "uname" => 160,
        "sethostname" => 161, "getrlimit" => 163, "setrlimit" => 164, "umask" => 166,
        "prctl" => 167, "getpid" => 172, "getppid" => 173, "getuid" => 174,
        "geteuid" => 175, "getgid" => 176, "getegid" => 177, "gettid" => 178,
        "socket" => 198, "bind" => 200, "listen" => 201, "accept" => 202,
        "connect" => 203, "getsockname" => 204, "sendto" => 206, "recvfrom" => 207,
        "setsockopt" => 208, "getsockopt" => 209, "brk" => 214, "munmap" => 215,
        "mremap" => 216, "clone" => 220, "execve" => 221, "mmap" => 222,
        "mprotect" => 226, "madvise" => 233, "wait4" => 260, "prlimit64" => 261,
        "renameat2" => 276, "seccomp" => 277, "getrandom" => 278, "memfd_create" => 279,
        "execveat" => 281, "statx" => 291, "rseq" => 293, "reboot" => 142,
        "ptrace" => 117, "init_module" => 105, "delete_module" => 106,
        "unshare" => 97, "setresuid" => 147, "setresgid" => 149, "setuid" => 146,
        "setgid" => 144, "chroot" => 51, "clone3" => 435, "close_range" => 436,
        "openat2" => 437, "faccessat2" => 439, "fchmodat2" => 452,
        _ => return None,
    })
}
