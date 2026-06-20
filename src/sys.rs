//! Typed, safe-ish wrappers over the raw arch syscalls.
//!
//! Linux returns errors as a small negative value in the [-4095, -1] range
//! (encoded as a large `usize`); everything else is a success value.

use alloc::vec::Vec;

use crate::arch::{self, nr};

/// A raw errno. We keep it as a plain `i32` to avoid pulling in any table.
pub type Errno = i32;

/// Build a NUL-terminated C string from a Rust `&str`.
pub fn cstr(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() + 1);
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    v
}

#[inline]
fn cptr(c: &[u8]) -> usize {
    c.as_ptr() as usize
}

#[inline]
fn decode(r: usize) -> Result<usize, Errno> {
    let s = r as isize;
    if s < 0 && s >= -4095 {
        Err(-s as i32)
    } else {
        Ok(r)
    }
}

// ---- mmap flags/prot ----
pub const PROT_READ: usize = 0x1;
pub const PROT_WRITE: usize = 0x2;
pub const MAP_PRIVATE: usize = 0x2;
pub const MAP_ANONYMOUS: usize = 0x20;

// ---- standard fds ----
pub const STDIN: usize = 0;
pub const STDOUT: usize = 1;
pub const STDERR: usize = 2;

#[inline]
pub fn write(fd: usize, buf: &[u8]) -> Result<usize, Errno> {
    decode(unsafe { arch::syscall3(nr::WRITE, fd, buf.as_ptr() as usize, buf.len()) })
}

#[inline]
pub fn read(fd: usize, buf: &mut [u8]) -> Result<usize, Errno> {
    decode(unsafe { arch::syscall3(nr::READ, fd, buf.as_mut_ptr() as usize, buf.len()) })
}

#[inline]
pub fn close(fd: usize) -> Result<usize, Errno> {
    decode(unsafe { arch::syscall1(nr::CLOSE, fd) })
}

#[inline]
pub fn getpid() -> i32 {
    // getpid never fails.
    unsafe { arch::syscall0(nr::GETPID) as i32 }
}

/// Anonymous private mapping of `len` bytes (read+write). Returns base address.
#[inline]
pub fn mmap_anon(len: usize) -> Result<*mut u8, Errno> {
    let r = unsafe {
        arch::syscall6(
            nr::MMAP,
            0,
            len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            usize::MAX, // fd = -1
            0,
        )
    };
    decode(r).map(|a| a as *mut u8)
}

#[inline]
pub fn munmap(addr: *mut u8, len: usize) -> Result<usize, Errno> {
    decode(unsafe { arch::syscall2(nr::MUNMAP, addr as usize, len) })
}

/// Terminate the whole process (all threads) with `code`. Never returns.
#[inline]
pub fn exit_group(code: i32) -> ! {
    unsafe {
        arch::syscall1(nr::EXIT_GROUP, code as usize);
        // exit_group never returns; loop to satisfy `!`.
        core::hint::unreachable_unchecked()
    }
}

// ---- open flags ----
pub const AT_FDCWD: usize = (-100isize) as usize;
pub const O_RDONLY: usize = 0;
pub const O_WRONLY: usize = 0o1;
pub const O_RDWR: usize = 0o2;
pub const O_CREAT: usize = 0o100;
pub const O_DIRECTORY: usize = 0o200000;
pub const O_CLOEXEC: usize = 0o2000000;
pub const O_PATH: usize = 0o10000000;

// ---- mount flags (linux/mount.h) ----
pub const MS_RDONLY: usize = 1;
pub const MS_NOSUID: usize = 2;
pub const MS_NODEV: usize = 4;
pub const MS_NOEXEC: usize = 8;
pub const MS_REMOUNT: usize = 32;
pub const MS_BIND: usize = 4096;
pub const MS_REC: usize = 16384;
pub const MS_PRIVATE: usize = 1 << 18;
pub const MS_SLAVE: usize = 1 << 19;
pub const MS_SHARED: usize = 1 << 20;
pub const MS_RELATIME: usize = 1 << 21;
pub const MS_STRICTATIME: usize = 1 << 24;
pub const MNT_DETACH: usize = 2;

// ---- clone/namespace flags ----
pub const CLONE_NEWNS: usize = 0x0002_0000;
pub const CLONE_NEWCGROUP: usize = 0x0200_0000;
pub const CLONE_NEWUTS: usize = 0x0400_0000;
pub const CLONE_NEWIPC: usize = 0x0800_0000;
pub const CLONE_NEWUSER: usize = 0x1000_0000;
pub const CLONE_NEWPID: usize = 0x2000_0000;
pub const CLONE_NEWNET: usize = 0x4000_0000;
pub const SIGCHLD: usize = 17;

#[inline]
pub fn openat(dirfd: usize, path: &str, flags: usize, mode: usize) -> Result<usize, Errno> {
    let p = cstr(path);
    decode(unsafe { arch::syscall4(nr::OPENAT, dirfd, cptr(&p), flags, mode) })
}

/// Open and read an entire file into a `Vec<u8>`.
pub fn read_file(path: &str) -> Result<Vec<u8>, Errno> {
    let fd = openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0)?;
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match read(fd, &mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => {
                let _ = close(fd);
                return Err(e);
            }
        }
    }
    let _ = close(fd);
    Ok(out)
}

#[inline]
pub fn mkdirat(dirfd: usize, path: &str, mode: usize) -> Result<usize, Errno> {
    let p = cstr(path);
    decode(unsafe { arch::syscall3(nr::MKDIRAT, dirfd, cptr(&p), mode) })
}

/// Create a directory, treating "already exists" (EEXIST) as success.
pub fn mkdir_p1(path: &str, mode: usize) -> Result<(), Errno> {
    match mkdirat(AT_FDCWD, path, mode) {
        Ok(_) => Ok(()),
        Err(17) => Ok(()), // EEXIST
        Err(e) => Err(e),
    }
}

#[inline]
pub fn chdir(path: &str) -> Result<usize, Errno> {
    let p = cstr(path);
    decode(unsafe { arch::syscall1(nr::CHDIR, cptr(&p)) })
}

#[inline]
pub fn chroot(path: &str) -> Result<usize, Errno> {
    let p = cstr(path);
    decode(unsafe { arch::syscall1(nr::CHROOT, cptr(&p)) })
}

#[inline]
pub fn sethostname(name: &str) -> Result<usize, Errno> {
    decode(unsafe { arch::syscall2(nr::SETHOSTNAME, name.as_ptr() as usize, name.len()) })
}

#[inline]
pub fn unshare(flags: usize) -> Result<usize, Errno> {
    decode(unsafe { arch::syscall1(nr::UNSHARE, flags) })
}

/// `mount(2)`. `source`, `fstype`, and `data` may be `None`.
pub fn mount(
    source: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: usize,
    data: Option<&str>,
) -> Result<usize, Errno> {
    let src = source.map(cstr);
    let tgt = cstr(target);
    let fst = fstype.map(cstr);
    let dat = data.map(cstr);
    let sp = src.as_ref().map_or(0, |c| cptr(c));
    let fp = fst.as_ref().map_or(0, |c| cptr(c));
    let dp = dat.as_ref().map_or(0, |c| cptr(c));
    decode(unsafe { arch::syscall5(nr::MOUNT, sp, cptr(&tgt), fp, flags, dp) })
}

#[inline]
pub fn umount2(target: &str, flags: usize) -> Result<usize, Errno> {
    let p = cstr(target);
    decode(unsafe { arch::syscall2(nr::UMOUNT2, cptr(&p), flags) })
}

#[inline]
pub fn pivot_root(new_root: &str, put_old: &str) -> Result<usize, Errno> {
    let n = cstr(new_root);
    let o = cstr(put_old);
    decode(unsafe { arch::syscall2(nr::PIVOT_ROOT, cptr(&n), cptr(&o)) })
}

#[inline]
pub fn symlinkat(target: &str, newdirfd: usize, linkpath: &str) -> Result<usize, Errno> {
    let t = cstr(target);
    let l = cstr(linkpath);
    decode(unsafe { arch::syscall3(nr::SYMLINKAT, cptr(&t), newdirfd, cptr(&l)) })
}

#[inline]
pub fn mknodat(dirfd: usize, path: &str, mode: usize, dev: usize) -> Result<usize, Errno> {
    let p = cstr(path);
    decode(unsafe { arch::syscall4(nr::MKNODAT, dirfd, cptr(&p), mode, dev) })
}

#[inline]
pub fn setuid(uid: u32) -> Result<usize, Errno> {
    decode(unsafe { arch::syscall1(nr::SETUID, uid as usize) })
}

#[inline]
pub fn setgid(gid: u32) -> Result<usize, Errno> {
    decode(unsafe { arch::syscall1(nr::SETGID, gid as usize) })
}

#[inline]
pub fn setgroups(gids: &[u32]) -> Result<usize, Errno> {
    decode(unsafe { arch::syscall2(nr::SETGROUPS, gids.len(), gids.as_ptr() as usize) })
}

pub const O_TRUNC: usize = 0o1000;
pub const O_NONBLOCK: usize = 0o4000;
pub const S_IFIFO: usize = 0o010000;
pub const AT_REMOVEDIR: usize = 0x200;

/// Write `buf` to `path`, creating/truncating it. Returns on success.
pub fn write_file(path: &str, buf: &[u8], mode: usize) -> Result<(), Errno> {
    let fd = openat(AT_FDCWD, path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode)?;
    let mut off = 0;
    while off < buf.len() {
        match write(fd, &buf[off..]) {
            Ok(0) => {
                let _ = close(fd);
                return Err(5); // EIO
            }
            Ok(n) => off += n,
            Err(4) => continue, // EINTR
            Err(e) => {
                let _ = close(fd);
                return Err(e);
            }
        }
    }
    let _ = close(fd);
    Ok(())
}

/// Create a named pipe (FIFO) at `path`.
pub fn mkfifo(path: &str, mode: usize) -> Result<(), Errno> {
    mknodat(AT_FDCWD, path, S_IFIFO | mode, 0).map(|_| ())
}

/// `pipe2(2)` → (read_fd, write_fd).
pub fn pipe2(flags: usize) -> Result<(usize, usize), Errno> {
    let mut fds = [0i32; 2];
    decode(unsafe { arch::syscall2(nr::PIPE2, fds.as_mut_ptr() as usize, flags) })?;
    Ok((fds[0] as usize, fds[1] as usize))
}

#[inline]
pub fn unlinkat(dirfd: usize, path: &str, flags: usize) -> Result<usize, Errno> {
    let p = cstr(path);
    decode(unsafe { arch::syscall3(nr::UNLINKAT, dirfd, cptr(&p), flags) })
}

/// Remove a file, treating ENOENT as success.
pub fn unlink(path: &str) -> Result<(), Errno> {
    match unlinkat(AT_FDCWD, path, 0) {
        Ok(_) | Err(2) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Remove a directory, treating ENOENT as success.
pub fn rmdir(path: &str) -> Result<(), Errno> {
    match unlinkat(AT_FDCWD, path, AT_REMOVEDIR) {
        Ok(_) | Err(2) => Ok(()),
        Err(e) => Err(e),
    }
}

#[inline]
pub fn getppid() -> i32 {
    unsafe { arch::syscall0(nr::GETPPID) as i32 }
}

/// Sleep for roughly `ms` milliseconds (ignores early wakeups).
pub fn sleep_ms(ms: u64) {
    // struct timespec { i64 sec; i64 nsec; }
    let ts: [i64; 2] = [(ms / 1000) as i64, ((ms % 1000) * 1_000_000) as i64];
    let _ = unsafe { arch::syscall2(nr::NANOSLEEP, ts.as_ptr() as usize, 0) };
}

#[inline]
pub fn getuid() -> u32 {
    unsafe { arch::syscall0(nr::GETUID) as u32 }
}

#[inline]
pub fn getgid() -> u32 {
    unsafe { arch::syscall0(nr::GETGID) as u32 }
}

/// Send `byte` over `fd`, retrying on EINTR/partial writes.
pub fn write_all(fd: usize, buf: &[u8]) -> Result<(), Errno> {
    let mut off = 0;
    while off < buf.len() {
        match write(fd, &buf[off..]) {
            Ok(0) => return Err(5),
            Ok(n) => off += n,
            Err(4) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Read exactly `buf.len()` bytes (or fewer on EOF). Returns bytes read.
pub fn read_full(fd: usize, buf: &mut [u8]) -> Result<usize, Errno> {
    let mut off = 0;
    while off < buf.len() {
        match read(fd, &mut buf[off..]) {
            Ok(0) => break,
            Ok(n) => off += n,
            Err(4) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(off)
}

pub const PR_SET_KEEPCAPS: usize = 8;
pub const PR_CAPBSET_DROP: usize = 24;
pub const PR_SET_NO_NEW_PRIVS: usize = 38;
pub const PR_CAP_AMBIENT: usize = 47;
pub const PR_CAP_AMBIENT_RAISE: usize = 2;
pub const PR_CAP_AMBIENT_CLEAR_ALL: usize = 4;

/// `_LINUX_CAPABILITY_VERSION_3` — 64-bit caps in two 32-bit words.
pub const CAP_VERSION_3: u32 = 0x2008_0522;

#[inline]
pub fn prctl(op: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> Result<usize, Errno> {
    decode(unsafe { arch::syscall5(nr::PRCTL, op, a2, a3, a4, a5) })
}

/// `struct __user_cap_header_struct { u32 version; i32 pid; }`
#[repr(C)]
pub struct CapHeader {
    pub version: u32,
    pub pid: i32,
}

/// `struct __user_cap_data_struct { u32 effective, permitted, inheritable; }`
/// capset/capget take an array of two (low 32 caps, high 32 caps).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CapData {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

#[inline]
pub fn capset(header: &CapHeader, data: &[CapData; 2]) -> Result<usize, Errno> {
    decode(unsafe {
        arch::syscall2(
            nr::CAPSET,
            header as *const CapHeader as usize,
            data.as_ptr() as usize,
        )
    })
}

pub const SECCOMP_SET_MODE_FILTER: usize = 1;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: usize = 1 << 3;
pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

// seccomp user-notification ioctls (arch-independent _IO encodings).
pub const SECCOMP_IOCTL_NOTIF_RECV: usize = 0xC050_2100;
pub const SECCOMP_IOCTL_NOTIF_SEND: usize = 0xC018_2101;
pub const SECCOMP_IOCTL_NOTIF_ID_VALID: usize = 0x4008_2102;

/// `struct seccomp_data` — the syscall context the kernel hands to a filter.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

/// `struct seccomp_notif` — one pending intercepted syscall.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

/// `struct seccomp_notif_resp` — the supervisor's verdict for a notification.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

/// `seccomp(operation, flags, args)`. With NEW_LISTENER the return value is the
/// notification fd.
#[inline]
pub fn seccomp(operation: usize, flags: usize, args: usize) -> Result<usize, Errno> {
    decode(unsafe { arch::syscall3(nr::SECCOMP, operation, flags, args) })
}

#[inline]
pub fn ioctl(fd: usize, request: usize, arg: usize) -> Result<usize, Errno> {
    decode(unsafe { arch::syscall3(nr::IOCTL, fd, request, arg) })
}

/// `struct rlimit64 { u64 cur; u64 max; }`
#[repr(C)]
pub struct Rlimit64 {
    pub cur: u64,
    pub max: u64,
}

#[inline]
pub fn prlimit64(pid: i32, resource: u32, new: &Rlimit64) -> Result<usize, Errno> {
    decode(unsafe {
        arch::syscall4(
            nr::PRLIMIT64,
            pid as usize,
            resource as usize,
            new as *const Rlimit64 as usize,
            0, // old = NULL
        )
    })
}

#[inline]
pub fn kill(pid: i32, sig: i32) -> Result<usize, Errno> {
    decode(unsafe { arch::syscall2(nr::KILL, pid as usize, sig as usize) })
}

/// `fork(2)` implemented via `clone(SIGCHLD, NULL, ...)` — portable across
/// x86-64 and aarch64 (the latter has no `fork` syscall). Returns the child
/// pid in the parent and `0` in the child.
#[inline]
pub fn fork() -> Result<i32, Errno> {
    // With a NULL stack and no tid/tls pointers the per-arch argument-order
    // differences after `flags` are irrelevant (all zero).
    decode(unsafe { arch::syscall5(nr::CLONE, SIGCHLD, 0, 0, 0, 0) }).map(|r| r as i32)
}

/// `clone(2)` with extra namespace flags (still NULL stack ⇒ fork semantics).
#[inline]
pub fn clone_ns(extra_flags: usize) -> Result<i32, Errno> {
    decode(unsafe { arch::syscall5(nr::CLONE, SIGCHLD | extra_flags, 0, 0, 0, 0) }).map(|r| r as i32)
}

/// `execve(2)`. `argv`/`envp` must be NULL-terminated arrays of C strings.
/// Returns only on failure.
#[inline]
pub fn execve(path: &[u8], argv: *const *const u8, envp: *const *const u8) -> Errno {
    let r = unsafe {
        arch::syscall3(
            nr::EXECVE,
            path.as_ptr() as usize,
            argv as usize,
            envp as usize,
        )
    };
    match decode(r) {
        Ok(_) => 0,
        Err(e) => e,
    }
}

/// `wait4(pid, &status, options, NULL)`. Returns `(pid, status)`.
pub fn wait4(pid: i32, options: usize) -> Result<(i32, i32), Errno> {
    let mut status: i32 = 0;
    let r = decode(unsafe {
        arch::syscall4(
            nr::WAIT4,
            pid as usize,
            &mut status as *mut i32 as usize,
            options,
            0,
        )
    })?;
    Ok((r as i32, status))
}

/// Decode a wait status into an exit code (mirrors WIFEXITED/WEXITSTATUS and
/// WIFSIGNALED/WTERMSIG → 128+signal, the shell convention).
pub fn exit_code_from_status(status: i32) -> i32 {
    if status & 0x7f == 0 {
        (status >> 8) & 0xff // WEXITSTATUS
    } else {
        128 + (status & 0x7f) // killed by signal
    }
}
