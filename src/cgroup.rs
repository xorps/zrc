//! cgroup v2: the container's leaf cgroup, its limits and its device filter.
//!
//! The leaf is created and configured before the container exists; the init
//! is then cloned straight into it (`CLONE_INTO_CGROUP`), so no process of
//! the container ever runs outside its limits. Controllers are enabled only
//! where a limit needs them.

use core::ffi::CStr;
use core::time::Duration;

use xorpio::Errno;
use xorpio::bpf::{self, Insn, op};
use xorpio::fs::{self, OpenHow, resolve};
use xorpio::io::{AsRawFd, Fd};

use crate::fixed::{Fixed, Full};
use crate::io::{Msg, Report, Truncated};
use crate::oci::{Device, DeviceRule, Resources, Str};

pub const ROOT: &CStr = c"/sys/fs/cgroup";

/// Lookups below the cgroup root may not leave it or follow symlinks.
const CONFINED: u64 = resolve::BENEATH | resolve::NO_SYMLINKS | resolve::NO_XDEV;

/// Whether `name` is a plain file name: no `/`, not `.` or `..`.
pub fn is_file_name(name: &[u8]) -> bool {
    !name.is_empty() && name != b"." && name != b".." && !name.contains(&b'/')
}

/// A file written in the leaf cgroup, for error messages.
#[derive(Clone, Copy, Debug)]
pub enum File {
    Named(&'static CStr),
    Unified(Str),
    /// `hugetlb.<size>.max`
    Hugetlb(Str),
}

#[derive(Clone, Copy, Debug)]
pub enum SetupError {
    OpenRoot(Errno),
    /// `cgroupsPath` is empty, systemd-style (`slice:prefix:name`) or has `.`
    /// or `..` components.
    InvalidPath,
    /// The leaf cgroup already exists.
    Exists,
    Mkdir(Errno),
    Open(Errno),
    ReadControllers(Errno),
    Enable {
        controller: &'static str,
        errno: Errno,
    },
    Write {
        file: File,
        errno: Errno,
    },
    /// `memory.swap` without `memory.limit`, or smaller than it.
    InvalidSwap,
    DeviceFilter(Errno),
}

impl Report for SetupError {
    fn report<const N: usize>(&self, m: &mut Msg<N>) {
        match *self {
            Self::OpenRoot(e) => m.str("open ").cstr(ROOT).str(": ").errno(e),
            Self::InvalidPath => m.str("unsupported cgroupsPath"),
            Self::Exists => m.str("the container's cgroup already exists"),
            Self::Mkdir(e) => m.str("mkdir: ").errno(e),
            Self::Open(e) => m.str("open: ").errno(e),
            Self::ReadControllers(e) => m.str("read cgroup.subtree_control: ").errno(e),
            Self::Enable { controller, errno } => m
                .str("enable controller ")
                .str(controller)
                .str(": ")
                .errno(errno),
            Self::Write { file, errno } => {
                m.str("write ");
                match file {
                    File::Named(name) => m.cstr(name),
                    File::Unified(name) => m.cstr(name),
                    File::Hugetlb(size) => m.str("hugetlb.").cstr(size).str(".max"),
                };
                m.str(": ").errno(errno)
            }
            Self::InvalidSwap => m.str("memory.swap needs a memory.limit no larger than it"),
            Self::DeviceFilter(e) => m.str("attach device filter: ").errno(e),
        };
    }
}

/// Controllers by bit, in the order the kernel lists them.
const CONTROLLERS: [&str; 8] = [
    "cpuset", "cpu", "io", "memory", "hugetlb", "pids", "rdma", "misc",
];
const CPUSET: u8 = 1 << 0;
const CPU: u8 = 1 << 1;
const MEMORY: u8 = 1 << 3;
const HUGETLB: u8 = 1 << 4;
const PIDS: u8 = 1 << 5;

/// The controllers `res` needs.
fn needed(res: &Resources) -> u8 {
    let mut c = 0;
    if res.memory_limit.is_some() || res.memory_reservation.is_some() || res.memory_swap.is_some() {
        c |= MEMORY;
    }
    if res.cpu_shares.is_some()
        || res.cpu_quota.is_some()
        || res.cpu_period.is_some()
        || res.cpu_burst.is_some()
        || res.cpu_idle.is_some()
    {
        c |= CPU;
    }
    if res.cpus.is_some() || res.mems.is_some() {
        c |= CPUSET;
    }
    if res.pids_limit.is_some() {
        c |= PIDS;
    }
    if !res.hugepages.is_empty() {
        c |= HUGETLB;
    }
    for (file, _) in &res.unified {
        let prefix = file
            .to_bytes()
            .split(|&b| b == b'.')
            .next()
            .unwrap_or_default();
        if let Some(bit) = CONTROLLERS.iter().position(|n| n.as_bytes() == prefix) {
            c |= 1 << bit;
        }
    }
    c
}

fn open_dir(dir: &impl AsRawFd, name: &CStr) -> Result<Fd, Errno> {
    let how = OpenHow {
        flags: u64::from(fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC),
        mode: 0,
        resolve: CONFINED,
    };
    fs::openat2(dir, name, &how)
}

fn write_file(dir: &Fd, name: &CStr, value: &[u8]) -> Result<(), Errno> {
    let how = OpenHow {
        flags: u64::from(fs::O_WRONLY | fs::O_CLOEXEC),
        mode: 0,
        resolve: CONFINED,
    };
    let f = fs::openat2(dir, name, &how)?;
    // A cgroup file takes one value per write.
    let n = f.write(value)?;
    if n != value.len() {
        return Err(Errno::EIO);
    }
    f.close()
}

/// Enables the controllers in `want` for the children of `dir`.
fn enable(dir: &Fd, want: u8) -> Result<(), SetupError> {
    if want == 0 {
        return Ok(());
    }
    let mut have = [0u8; 256];
    let how = OpenHow {
        flags: u64::from(fs::O_RDONLY | fs::O_CLOEXEC),
        mode: 0,
        resolve: CONFINED,
    };
    let f =
        fs::openat2(dir, c"cgroup.subtree_control", &how).map_err(SetupError::ReadControllers)?;
    let n = fs::read_full(&f, &mut have).map_err(SetupError::ReadControllers)?;
    let have = have.get(..n).unwrap_or_default();
    for (bit, name) in CONTROLLERS.iter().enumerate() {
        if want & (1 << bit) == 0
            || have
                .split(|c| c.is_ascii_whitespace())
                .any(|w| w == name.as_bytes())
        {
            continue;
        }
        let err = |errno| SetupError::Enable {
            controller: name,
            errno,
        };
        let mut cmd = Msg::<16>::new();
        let cmd = cmd
            .str("+")
            .str(name)
            .finish()
            .map_err(|Truncated| err(Errno::ERANGE))?;
        write_file(dir, c"cgroup.subtree_control", cmd).map_err(err)?;
    }
    Ok(())
}

/// Creates the leaf cgroup `path` (relative to [`ROOT`]), applies `res`,
/// allows access to `devices` (the container's `linux.devices`), and returns
/// the leaf directory for `CLONE_INTO_CGROUP`.
pub fn create(path: &CStr, res: &Resources, devices: &[Device]) -> Result<Fd, SetupError> {
    let bytes = path.to_bytes();
    if bytes.contains(&b':') {
        return Err(SetupError::InvalidPath);
    }
    let root = fs::openat(
        &fs::CWD,
        ROOT,
        fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC,
        0,
    )
    .map_err(SetupError::OpenRoot)?;
    let want = needed(res);

    let mut parts = bytes
        .split(|&c| c == b'/')
        .filter(|c| !c.is_empty())
        .peekable();
    if parts.peek().is_none() {
        return Err(SetupError::InvalidPath);
    }
    let mut parent = root;
    loop {
        let part = parts.next().ok_or(SetupError::InvalidPath)?;
        if !is_file_name(part) {
            return Err(SetupError::InvalidPath);
        }
        let leaf = parts.peek().is_none();
        enable(&parent, want)?;
        let mut name = [0u8; 256];
        let name = name
            .get_mut(..=part.len())
            .and_then(|n| {
                crate::fixed::copy(n.get_mut(..part.len())?, part);
                CStr::from_bytes_with_nul(n).ok()
            })
            .ok_or(SetupError::InvalidPath)?;
        match fs::mkdirat(&parent, name, 0o755) {
            Ok(()) => {}
            Err(Errno::EEXIST) if !leaf => {}
            Err(Errno::EEXIST) => return Err(SetupError::Exists),
            Err(e) => return Err(SetupError::Mkdir(e)),
        }
        let dir = open_dir(&parent, name).map_err(SetupError::Open);
        if !leaf {
            parent = dir?;
            continue;
        }
        // The leaf is ours: remove it again if it cannot be set up.
        let configured = dir.and_then(|dir| {
            apply(&dir, res)?;
            attach_device_filter(&dir, res.devices.as_slice(), devices)
                .map_err(SetupError::DeviceFilter)?;
            Ok(dir)
        });
        if configured.is_err()
            && let Err(e) = fs::unlinkat(&parent, name, fs::AT_REMOVEDIR)
        {
            crate::io::fail("cleanup: cgroup", &e);
        }
        return configured;
    }
}

/// A value for a cgroup file.
#[derive(Clone, Copy)]
enum Value<'v> {
    /// A limit where any negative number means no limit (`max`).
    Limit(i64),
    Count(u64),
    Int(i64),
    Text(&'v [u8]),
}

fn write_value(dir: &Fd, file: File, name: &CStr, value: Value<'_>) -> Result<(), SetupError> {
    let err = |errno| SetupError::Write { file, errno };
    let mut m = Msg::<24>::new();
    let text = match value {
        Value::Limit(v) if v < 0 => b"max",
        Value::Limit(v) => m.i64(v).finish().map_err(|Truncated| err(Errno::ERANGE))?,
        Value::Count(v) => m.u64(v).finish().map_err(|Truncated| err(Errno::ERANGE))?,
        Value::Int(v) => m.i64(v).finish().map_err(|Truncated| err(Errno::ERANGE))?,
        Value::Text(t) => t,
    };
    write_file(dir, name, text).map_err(err)
}

fn apply(dir: &Fd, res: &Resources) -> Result<(), SetupError> {
    let set =
        |name: &'static CStr, value: Value<'_>| write_value(dir, File::Named(name), name, value);
    if let Some(limit) = res.memory_limit {
        set(c"memory.max", Value::Limit(limit))?;
    }
    if let Some(low) = res.memory_reservation {
        set(c"memory.low", Value::Limit(low))?;
    }
    if let Some(swap) = res.memory_swap {
        // OCI's swap is memory plus swap; cgroup v2 limits swap alone.
        let swap_only = match (swap, res.memory_limit) {
            (s, _) if s < 0 => -1,
            (_, None) => return Err(SetupError::InvalidSwap),
            (_, Some(limit)) if limit < 0 => -1,
            (s, Some(limit)) => s
                .checked_sub(limit)
                .filter(|v| *v >= 0)
                .ok_or(SetupError::InvalidSwap)?,
        };
        set(c"memory.swap.max", Value::Limit(swap_only))?;
    }
    if let Some(shares) = res.cpu_shares {
        // cgroup v1 shares (2..262144) to v2 weight (1..10000), as runc does.
        let weight = if shares < 2 {
            1
        } else {
            (1 + ((shares - 2) * 9999) / 262_142).clamp(1, 10_000)
        };
        set(c"cpu.weight", Value::Count(weight))?;
    }
    if res.cpu_quota.is_some() || res.cpu_period.is_some() {
        let mut m = Msg::<48>::new();
        match res.cpu_quota {
            Some(q) if q > 0 => m.i64(q),
            _ => m.str("max"),
        };
        m.str(" ").u64(res.cpu_period.unwrap_or(100_000));
        let text = m.finish().map_err(|Truncated| SetupError::Write {
            file: File::Named(c"cpu.max"),
            errno: Errno::ERANGE,
        })?;
        set(c"cpu.max", Value::Text(text))?;
    }
    if let Some(burst) = res.cpu_burst {
        set(c"cpu.max.burst", Value::Count(burst))?;
    }
    if let Some(idle) = res.cpu_idle {
        set(c"cpu.idle", Value::Int(idle))?;
    }
    if let Some(cpus) = res.cpus {
        set(c"cpuset.cpus", Value::Text(cpus.to_bytes()))?;
    }
    if let Some(mems) = res.mems {
        set(c"cpuset.mems", Value::Text(mems.to_bytes()))?;
    }
    if let Some(limit) = res.pids_limit {
        set(c"pids.max", Value::Limit(limit))?;
    }
    for &(size, limit) in &res.hugepages {
        let file = File::Hugetlb(size);
        let mut name = Msg::<64>::new();
        name.str("hugetlb.").cstr(size).str(".max").bytes(&[0]);
        let name = name.c_str().ok_or(SetupError::Write {
            file,
            errno: Errno::ENAMETOOLONG,
        })?;
        write_value(dir, file, name, Value::Count(limit))?;
    }
    for &(file, value) in &res.unified {
        write_value(
            dir,
            File::Unified(file),
            file,
            Value::Text(value.to_bytes()),
        )?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub enum DestroyError {
    OpenRoot(Errno),
    Open(Errno),
    Kill(Errno),
    /// The cgroup still has members after its processes were killed.
    Busy,
    /// Child cgroups nest deeper than zrc follows.
    TooDeep,
    Rmdir(Errno),
}

impl Report for DestroyError {
    fn report<const N: usize>(&self, m: &mut Msg<N>) {
        match *self {
            Self::OpenRoot(e) => m.str("open ").cstr(ROOT).str(": ").errno(e),
            Self::Open(e) => m.str("open the container's cgroup: ").errno(e),
            Self::Kill(e) => m.str("write cgroup.kill: ").errno(e),
            Self::Busy => m.str("cgroup still busy after killing its processes"),
            Self::TooDeep => m.str("child cgroups nest too deeply"),
            Self::Rmdir(e) => m.str("rmdir: ").errno(e),
        };
    }
}

/// Child cgroups may nest this deep below a container's cgroup.
const MAX_NESTING: u32 = 32;

fn open_root() -> Result<Fd, Errno> {
    fs::openat(
        &fs::CWD,
        ROOT,
        fs::O_RDONLY | fs::O_DIRECTORY | fs::O_CLOEXEC,
        0,
    )
}

/// Calls `f` with the name of each child cgroup of `dir` until it returns
/// `Some`. Directories are re-read from the start each call, so `f` may
/// remove the child it was given.
fn first_child<T>(
    dir: &Fd,
    mut f: impl FnMut(&CStr) -> Result<Option<T>, Errno>,
) -> Result<Option<T>, Errno> {
    let rd = open_dir(dir, c".")?;
    let mut buf = [0u8; 2048];
    loop {
        let n = fs::getdents(&rd, &mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        for e in fs::DirEntries(buf.get(..n).unwrap_or_default()) {
            let name = e.name.to_bytes();
            if e.kind != fs::DT_DIR || name == b"." || name == b".." {
                continue;
            }
            if let Some(v) = f(e.name)? {
                return Ok(Some(v));
            }
        }
    }
}

/// Removes the cgroup `name` in `parent`, children first. Killed members
/// linger until reaped by their parent, so a busy cgroup is retried for
/// about two seconds.
fn remove_tree(parent: &Fd, name: &CStr, depth: u32) -> Result<(), DestroyError> {
    let dir = match open_dir(parent, name) {
        Ok(dir) => dir,
        Err(Errno::ENOENT) => return Ok(()),
        Err(e) => return Err(DestroyError::Open(e)),
    };
    // Each pass removes one child, then lists again.
    while first_child(&dir, |child| Ok(Some(remove_child(&dir, child, depth))))
        .map_err(DestroyError::Open)?
        .transpose()?
        .is_some()
    {}
    drop(dir);
    for _ in 0..200 {
        match fs::unlinkat(parent, name, fs::AT_REMOVEDIR) {
            Ok(()) | Err(Errno::ENOENT) => return Ok(()),
            Err(Errno::EBUSY) => {}
            Err(e) => return Err(DestroyError::Rmdir(e)),
        }
        xorpio::time::sleep(Duration::from_millis(10)).map_err(DestroyError::Rmdir)?;
    }
    Err(DestroyError::Busy)
}

fn remove_child(dir: &Fd, child: &CStr, depth: u32) -> Result<(), DestroyError> {
    if depth >= MAX_NESTING {
        return Err(DestroyError::TooDeep);
    }
    remove_tree(dir, child, depth + 1)
}

/// Kills every process in the leaf cgroup `path` and its children, and
/// removes them. A cgroup that does not exist is already destroyed.
pub fn destroy(path: &CStr) -> Result<(), DestroyError> {
    let root = open_root().map_err(DestroyError::OpenRoot)?;
    let rel = relative(path);
    let leaf = match open_dir(&root, rel) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => return Ok(()),
        Err(e) => return Err(DestroyError::Open(e)),
    };
    // cgroup.kill covers the whole subtree, atomically.
    write_file(&leaf, c"cgroup.kill", b"1").map_err(DestroyError::Kill)?;
    drop(leaf);
    remove_tree(&root, rel, 0)
}

/// Sends `sig` to every process in the cgroup `path` and its children.
pub fn signal_all(path: &CStr, sig: i32) -> Result<(), Errno> {
    let root = open_root()?;
    let leaf = open_dir(&root, relative(path))?;
    if sig == xorpio::process::sig::SIGKILL {
        // Atomic, and without the pid-reuse window of reading pids first.
        return write_file(&leaf, c"cgroup.kill", b"1");
    }
    signal_tree(&leaf, sig, 0)
}

fn signal_tree(dir: &Fd, sig: i32, depth: u32) -> Result<(), Errno> {
    let how = OpenHow {
        flags: u64::from(fs::O_RDONLY | fs::O_CLOEXEC),
        mode: 0,
        resolve: CONFINED,
    };
    let procs = fs::openat2(dir, c"cgroup.procs", &how)?;
    let mut buf = [0u8; 4096];
    let mut pid: i32 = 0;
    loop {
        let n = fs::read_full(&procs, &mut buf)?;
        for &c in buf.get(..n).unwrap_or_default() {
            match c {
                b'0'..=b'9' => {
                    pid = pid
                        .checked_mul(10)
                        .and_then(|p| p.checked_add(i32::from(c - b'0')))
                        .ok_or(Errno::EINVAL)?;
                }
                b'\n' => {
                    match xorpio::process::kill(pid, sig) {
                        // Exited since the list was read.
                        Ok(()) | Err(Errno::ESRCH) => {}
                        Err(e) => return Err(e),
                    }
                    pid = 0;
                }
                _ => return Err(Errno::EINVAL),
            }
        }
        if n < buf.len() {
            break;
        }
    }
    if depth >= MAX_NESTING {
        return Err(Errno::ELOOP);
    }
    // Children are listed once: none is removed here.
    let mut done = 0usize;
    loop {
        let mut index = 0usize;
        let found = first_child(dir, |child| {
            index += 1;
            if index <= done {
                return Ok(None);
            }
            let sub = open_dir(dir, child)?;
            signal_tree(&sub, sig, depth + 1).map(Some)
        })?;
        if found.is_none() {
            return Ok(());
        }
        done += 1;
    }
}

/// `path` without leading slashes, so it resolves beneath the root.
pub fn relative(path: &CStr) -> &CStr {
    let skip = path.to_bytes().iter().take_while(|&&c| c == b'/').count();
    path.to_bytes_with_nul()
        .get(skip..)
        .and_then(|b| CStr::from_bytes_with_nul(b).ok())
        .unwrap_or(path)
}

// ---- device filter ----
//
// cgroup v2 has no devices controller: access to device nodes is decided by
// an eBPF program attached to the cgroup. Without one, a process with
// CAP_MKNOD could create and open any host device.

/// The devices every container gets (see `rootfs::DEFAULT_DEVICES`, plus
/// the pty multiplexer and ptys). Like runc, these are allowed whatever the
/// spec's rules say: OCI requires runtimes to provide them.
const DEFAULT_RULES: [DeviceRule; 8] = [
    allow_char(1, Some(3)), // null
    allow_char(1, Some(5)), // zero
    allow_char(1, Some(7)), // full
    allow_char(1, Some(8)), // random
    allow_char(1, Some(9)), // urandom
    allow_char(5, Some(0)), // tty
    allow_char(5, Some(2)), // ptmx
    allow_char(136, None),  // pts/*
];

const fn allow_char(major: u32, minor: Option<u32>) -> DeviceRule {
    DeviceRule {
        allow: true,
        kind: b'c',
        major: Some(major),
        minor,
        access: 1 | 2 | 4,
    }
}

const DEV_BLOCK: i32 = 1;
const DEV_CHAR: i32 = 2;
const MAX_FILTER: usize =
    8 * (crate::oci::MAX_DEVICE_RULES + crate::oci::MAX_DEVICES + DEFAULT_RULES.len()) + 8;

/// Compiles the device rules and attaches the program to `cgroup`. Like
/// runc, the default devices and the container's own `devices` are allowed
/// whatever `rules` say; otherwise later rules win and no match denies.
fn attach_device_filter(
    cgroup: &Fd,
    rules: &[DeviceRule],
    devices: &[Device],
) -> Result<(), Errno> {
    let mut prog = Fixed::<Insn, MAX_FILTER>::new();
    let given = devices.iter().filter_map(|d| {
        let kind = match d.kind {
            fs::S_IFCHR => b'c',
            fs::S_IFBLK => b'b',
            // FIFOs are not devices.
            _ => return None,
        };
        Some(DeviceRule {
            allow: true,
            kind,
            major: Some(d.major),
            minor: Some(d.minor),
            access: 1 | 2 | 4,
        })
    });
    let ordered = DEFAULT_RULES
        .iter()
        .copied()
        .chain(given)
        .chain(rules.iter().rev().copied());
    compile_device_filter(ordered, &mut prog).map_err(|Full| Errno::E2BIG)?;
    let fd = bpf::prog_load(bpf::PROG_TYPE_CGROUP_DEVICE, prog.as_slice(), c"GPL")?;
    bpf::prog_attach(cgroup, &fd, bpf::ATTACH_CGROUP_DEVICE, bpf::F_ALLOW_MULTI)
}

/// The program, over `struct bpf_cgroup_dev_ctx { u32 access_type; u32 major;
/// u32 minor; }` in r1, with `access_type = access << 16 | type`.
/// `rules` are in the order they are checked: the first match decides.
fn compile_device_filter<const N: usize>(
    rules: impl Iterator<Item = DeviceRule>,
    prog: &mut Fixed<Insn, N>,
) -> Result<(), Full> {
    // r2 = type, r3 = access, r4 = major, r5 = minor
    prog.push(Insn::new(op::LDX_MEM_W, 2, 1, 0, 0))?;
    prog.push(Insn::new(op::ALU32_AND_K, 2, 0, 0, 0xffff))?;
    prog.push(Insn::new(op::LDX_MEM_W, 3, 1, 0, 0))?;
    prog.push(Insn::new(op::ALU32_RSH_K, 3, 0, 0, 16))?;
    prog.push(Insn::new(op::LDX_MEM_W, 4, 1, 4, 0))?;
    prog.push(Insn::new(op::LDX_MEM_W, 5, 1, 8, 0))?;
    // A rule without conditions always matches, and the verifier rejects
    // code after it.
    for rule in rules {
        let mut block = Fixed::<Insn, 12>::new();
        // `off` is patched below to jump past the end of the block.
        let next = i16::MAX;
        match rule.kind {
            b'c' => block.push(Insn::new(op::JMP32_JNE_K, 2, 0, next, DEV_CHAR))?,
            b'b' => block.push(Insn::new(op::JMP32_JNE_K, 2, 0, next, DEV_BLOCK))?,
            _ => {}
        }
        if rule.access & 7 != 7 {
            // Requested access must be a subset of the rule's.
            block.push(Insn::new(op::ALU64_MOV_X, 1, 3, 0, 0))?;
            block.push(Insn::new(
                op::ALU32_AND_K,
                1,
                0,
                0,
                (!rule.access & 7) as i32,
            ))?;
            block.push(Insn::new(op::JMP32_JNE_K, 1, 0, next, 0))?;
        }
        if let Some(major) = rule.major {
            block.push(Insn::new(op::JMP32_JNE_K, 4, 0, next, major as i32))?;
        }
        if let Some(minor) = rule.minor {
            block.push(Insn::new(op::JMP32_JNE_K, 5, 0, next, minor as i32))?;
        }
        let unconditional = block.is_empty();
        block.push(Insn::new(op::ALU64_MOV_K, 0, 0, 0, i32::from(rule.allow)))?;
        block.push(Insn::new(op::JMP_EXIT, 0, 0, 0, 0))?;
        let len = block.len();
        for (i, insn) in block.as_mut_slice().iter_mut().enumerate() {
            if insn.off == next {
                insn.off = (len - i - 1) as i16;
            }
        }
        for &insn in &block {
            prog.push(insn)?;
        }
        if unconditional {
            return Ok(());
        }
    }
    // No rule matched: deny.
    prog.push(Insn::new(op::ALU64_MOV_K, 0, 0, 0, 0))?;
    prog.push(Insn::new(op::JMP_EXIT, 0, 0, 0, 0))?;
    Ok(())
}
