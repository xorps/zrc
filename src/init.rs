//! The container init: everything between `clone3` and `execve`.
//!
//! All setup happens before the init reports readiness, so `create` can
//! report any failure; afterwards only the exec is left. A failure travels
//! to the parent as a fixed 16-byte record naming the step, and the parent
//! looks up the subject (mount destination, path, ...) in its own copy of
//! the spec.

use core::ffi::{CStr, c_char};
use core::ptr;

use xorpio::Errno;
use xorpio::fs;
use xorpio::io::{AsRawFd, Fd, write_all};
use xorpio::ns;
use xorpio::process::{self, pr};

use crate::caps;
use crate::io::{Msg, Report, Truncated};
use crate::oci::{MAX_ARGS, MAX_ENV, Spec, Str};
use crate::path::PATH_MAX;
use crate::rootfs;

/// The steps of the init, in order. Values are part of the wire format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Step {
    JoinNamespace = 1,
    AwaitIdMaps,
    UnshareCgroup,
    RootPropagation,
    BindRootfs,
    OpenRootfs,
    MountSource,
    MountCreate,
    MountOption,
    MountAttr,
    MountTarget,
    MountAttach,
    MountPropagation,
    DefaultDevice,
    DevSymlink,
    Device,
    MaskPath,
    ReadonlyPath,
    Hostname,
    Domainname,
    PivotRoot,
    DetachOldRoot,
    RootReadonly,
    Sysctl,
    OomScoreAdj,
    Rlimit,
    AppArmor,
    SeLinux,
    FindExecutable,
    Seccomp,
    Bounding,
    KeepCaps,
    Setgroups,
    Setgid,
    Setuid,
    Capset,
    Ambient,
    Chdir,
    NoNewPrivs,
    CheckFifo,
    Exec,
}

const STEPS: [Step; 41] = [
    Step::JoinNamespace,
    Step::AwaitIdMaps,
    Step::UnshareCgroup,
    Step::RootPropagation,
    Step::BindRootfs,
    Step::OpenRootfs,
    Step::MountSource,
    Step::MountCreate,
    Step::MountOption,
    Step::MountAttr,
    Step::MountTarget,
    Step::MountAttach,
    Step::MountPropagation,
    Step::DefaultDevice,
    Step::DevSymlink,
    Step::Device,
    Step::MaskPath,
    Step::ReadonlyPath,
    Step::Hostname,
    Step::Domainname,
    Step::PivotRoot,
    Step::DetachOldRoot,
    Step::RootReadonly,
    Step::Sysctl,
    Step::OomScoreAdj,
    Step::Rlimit,
    Step::AppArmor,
    Step::SeLinux,
    Step::FindExecutable,
    Step::Seccomp,
    Step::Bounding,
    Step::KeepCaps,
    Step::Setgroups,
    Step::Setgid,
    Step::Setuid,
    Step::Capset,
    Step::Ambient,
    Step::Chdir,
    Step::NoNewPrivs,
    Step::CheckFifo,
    Step::Exec,
];

impl Step {
    fn from_u8(v: u8) -> Option<Self> {
        STEPS.get(usize::from(v).checked_sub(1)?).copied()
    }

    fn describe(self) -> &'static str {
        match self {
            Self::JoinNamespace => "join namespace",
            Self::AwaitIdMaps => "wait for uid/gid maps",
            Self::UnshareCgroup => "create cgroup namespace",
            Self::RootPropagation => "set propagation of the mount tree",
            Self::BindRootfs => "bind-mount rootfs",
            Self::OpenRootfs => "open rootfs",
            Self::MountSource => "mount: open source",
            Self::MountCreate => "mount: create filesystem",
            Self::MountOption => "mount: fsconfig",
            Self::MountAttr => "mount: set attributes",
            Self::MountTarget => "mount: create target",
            Self::MountAttach => "mount: attach",
            Self::MountPropagation => "mount: set propagation",
            Self::DefaultDevice => "bind default device",
            Self::DevSymlink => "create /dev symlink",
            Self::Device => "create device",
            Self::MaskPath => "mask path",
            Self::ReadonlyPath => "make path read-only",
            Self::Hostname => "set hostname",
            Self::Domainname => "set domainname",
            Self::PivotRoot => "pivot_root",
            Self::DetachOldRoot => "detach old root",
            Self::RootReadonly => "make rootfs read-only",
            Self::Sysctl => "write sysctl",
            Self::OomScoreAdj => "write oom_score_adj",
            Self::Rlimit => "set rlimit",
            Self::AppArmor => "set AppArmor profile",
            Self::SeLinux => "set SELinux label",
            Self::FindExecutable => "find executable",
            Self::Seccomp => "install seccomp filter",
            Self::Bounding => "drop from bounding set",
            Self::KeepCaps => "keep capabilities across setuid",
            Self::Setgroups => "setgroups",
            Self::Setgid => "setresgid",
            Self::Setuid => "setresuid",
            Self::Capset => "capset",
            Self::Ambient => "set ambient capabilities",
            Self::Chdir => "chdir to process.cwd",
            Self::NoNewPrivs => "set no_new_privs",
            Self::CheckFifo => "reach exec.fifo through /proc/self/fd",
            Self::Exec => "execve",
        }
    }
}

/// A failed step as sent over the sync pipe. `index` and `sub` say which
/// item of the step's list failed (mount, option, path, capability, ...).
#[derive(Clone, Copy, Debug)]
pub struct Fail {
    pub step: Step,
    pub index: u32,
    pub sub: u32,
    pub errno: Errno,
}

pub const NONE: u32 = u32::MAX;

pub trait At<T> {
    /// Tags an errno with the step that produced it.
    fn at(self, step: Step) -> Result<T, Fail>;
    /// Tags an errno with the step and the item it was working on.
    fn at_item(self, step: Step, index: usize, sub: u32) -> Result<T, Fail>;
}

impl<T> At<T> for Result<T, Errno> {
    #[inline]
    fn at(self, step: Step) -> Result<T, Fail> {
        self.map_err(|errno| Fail {
            step,
            index: NONE,
            sub: NONE,
            errno,
        })
    }

    #[inline]
    fn at_item(self, step: Step, index: usize, sub: u32) -> Result<T, Fail> {
        self.map_err(|errno| Fail {
            step,
            index: index as u32,
            sub,
            errno,
        })
    }
}

/// Size of a record on the sync pipe.
pub const RECORD: usize = 16;
const READY: u8 = 0;
const FAILED: u8 = 1;

fn encode(fail: Option<Fail>) -> [u8; RECORD] {
    let mut r = [0u8; RECORD];
    let Some(f) = fail else { return r };
    let [e0, e1, e2, e3] = f.errno.raw().to_le_bytes();
    let [i0, i1, i2, i3] = f.index.to_le_bytes();
    let [s0, s1, s2, s3] = f.sub.to_le_bytes();
    r = [
        FAILED,
        f.step as u8,
        0,
        0,
        e0,
        e1,
        e2,
        e3,
        i0,
        i1,
        i2,
        i3,
        s0,
        s1,
        s2,
        s3,
    ];
    r
}

/// What the init reported.
pub enum Status {
    Ready,
    Failed(Fail),
}

/// The record was not one the init writes.
#[derive(Clone, Copy, Debug)]
pub struct Garbled;

pub fn decode(r: &[u8; RECORD]) -> Result<Status, Garbled> {
    let [
        tag,
        step,
        _,
        _,
        e0,
        e1,
        e2,
        e3,
        i0,
        i1,
        i2,
        i3,
        s0,
        s1,
        s2,
        s3,
    ] = *r;
    match tag {
        READY => Ok(Status::Ready),
        FAILED => Ok(Status::Failed(Fail {
            step: Step::from_u8(step).ok_or(Garbled)?,
            errno: Errno::from_raw(i32::from_le_bytes([e0, e1, e2, e3])),
            index: u32::from_le_bytes([i0, i1, i2, i3]),
            sub: u32::from_le_bytes([s0, s1, s2, s3]),
        })),
        _ => Err(Garbled),
    }
}

/// A [`Fail`] with what it failed on, looked up in the spec, for messages.
#[derive(Clone, Copy, Debug)]
pub struct InitError {
    pub fail: Fail,
    pub subject: Option<&'static [u8]>,
    pub detail: Option<&'static [u8]>,
}

impl InitError {
    pub fn new(fail: Fail, spec: &'static Spec) -> Self {
        let i = fail.index as usize;
        let s = |v: Option<Str>| v.map(CStr::to_bytes);
        let mount = spec.mounts.as_slice().get(i);
        let (subject, detail) = match fail.step {
            Step::MountSource
            | Step::MountCreate
            | Step::MountAttr
            | Step::MountTarget
            | Step::MountAttach
            | Step::MountPropagation => (s(mount.map(|m| m.destination)), None),
            Step::MountOption => (
                s(mount.map(|m| m.destination)),
                match fail.sub {
                    NONE => Some(&b"source"[..]),
                    sub => mount
                        .and_then(|m| spec.fs_opts(m).get(sub as usize))
                        .map(|o| o.key.to_bytes()),
                },
            ),
            Step::DefaultDevice => (rootfs::DEFAULT_DEVICES.get(i).map(|d| d.to_bytes()), None),
            Step::DevSymlink => (
                rootfs::DEV_SYMLINKS.get(i).map(|(name, _)| name.to_bytes()),
                None,
            ),
            Step::Device => (s(spec.devices.as_slice().get(i).map(|d| d.path)), None),
            Step::MaskPath => (s(spec.masked_paths.as_slice().get(i).copied()), None),
            Step::ReadonlyPath => (s(spec.readonly_paths.as_slice().get(i).copied()), None),
            Step::Sysctl => (s(spec.sysctls.as_slice().get(i).map(|c| c.path)), None),
            Step::JoinNamespace => (
                s(spec.namespaces.join.as_slice().get(i).map(|&(_, p)| p)),
                None,
            ),
            Step::Bounding | Step::Ambient if fail.index != NONE => {
                (Some(caps::name(fail.index)), None)
            }
            Step::Chdir => (s(spec.process.cwd), None),
            Step::FindExecutable | Step::Exec => {
                (s(spec.process.args.as_slice().first().copied()), None)
            }
            _ => (None, None),
        };
        Self {
            fail,
            subject,
            detail,
        }
    }
}

impl Report for InitError {
    fn report<const N: usize>(&self, m: &mut Msg<N>) {
        m.str(self.fail.step.describe());
        if let Some(subject) = self.subject {
            m.str(" ").bytes(subject);
        }
        if let Some(detail) = self.detail {
            m.str(" '").bytes(detail).str("'");
        }
        m.str(": ").errno(self.fail.errno);
    }
}

/// Buffers for the exec: the NULL-terminated pointer arrays and the
/// resolved executable path.
pub struct ExecBufs {
    pub argv: [*const c_char; MAX_ARGS + 1],
    pub envp: [*const c_char; MAX_ENV + 1],
    pub path: [u8; PATH_MAX],
}

impl ExecBufs {
    pub const fn new() -> Self {
        Self {
            argv: [ptr::null(); MAX_ARGS + 1],
            envp: [ptr::null(); MAX_ENV + 1],
            path: [0; PATH_MAX],
        }
    }
}

/// How the init hands over to the user process.
pub enum Handover {
    /// `create`: wait on `exec.fifo` (an `O_PATH` fd) for `start`.
    Fifo(Fd),
    /// `run`: exec right away; the sync pipe, closed by the exec, tells
    /// the parent it succeeded.
    Direct,
}

pub struct Init<'a> {
    pub spec: &'static Spec,
    pub bundle: &'a CStr,
    /// The leaf cgroup's path, relative to the cgroup root.
    pub cgroup: &'a CStr,
    /// Mount and cgroup namespaces to join, opened by the parent, at the
    /// index of their spec entry. The parent joins the others itself.
    pub join: &'a [Option<(u64, Fd)>],
    pub sync: Fd,
    /// The read end of the parent's "id maps written" pipe.
    pub await_maps: Option<Fd>,
    pub handover: Handover,
    pub exec: &'a mut ExecBufs,
}

/// Runs the init. Never returns: it ends in `execve` or exits.
pub fn run(init: Init<'_>) -> ! {
    let Init {
        spec,
        bundle,
        cgroup,
        join,
        sync,
        await_maps,
        handover,
        exec,
    } = init;
    let ctx = rootfs::Ctx {
        spec,
        bundle,
        cgroup,
    };
    let prepared = setup(&ctx, join, await_maps, &handover, exec);
    let path = match prepared {
        Ok(path) => path,
        Err(fail) => {
            // The parent learns of the failure from this record, or from
            // the pipe closing if even this write fails.
            let _ = write_all(sync.as_raw_fd(), &encode(Some(fail)));
            process::exit(1);
        }
    };
    if let Err(errno) = write_all(sync.as_raw_fd(), &encode(None)) {
        process::exit(128 + (errno.raw() & 0x7f));
    }
    match handover {
        Handover::Direct => {
            let errno = execve(path, exec);
            // Same as above: a lost record still closes the pipe.
            let _ = write_all(
                sync.as_raw_fd(),
                &encode(Some(Fail {
                    step: Step::Exec,
                    index: NONE,
                    sub: NONE,
                    errno,
                })),
            );
            process::exit(127);
        }
        Handover::Fifo(fifo) => {
            drop(sync);
            // Blocks until `start` opens the FIFO for reading. The init
            // may lack permission on the state directory, so it goes
            // through its O_PATH fd instead.
            let mut m = Msg::new();
            let w = match fd_path(&fifo, &mut m)
                .and_then(|p| fs::openat(&fs::CWD, p, fs::O_WRONLY | fs::O_CLOEXEC, 0))
            {
                Ok(w) => w,
                Err(errno) => process::exit(128 + (errno.raw() & 0x7f)),
            };
            let errno = execve(path, exec);
            // `start` reads the errno; on success the exec closed `w`.
            let _ = write_all(w.as_raw_fd(), &errno.raw().to_le_bytes());
            process::exit(127);
        }
    }
}

/// `/proc/self/fd/<fd>`, built in `m`.
fn fd_path<'m>(fd: &Fd, m: &'m mut Msg<32>) -> Result<&'m CStr, Errno> {
    m.str("/proc/self/fd/")
        .i64(i64::from(fd.as_raw_fd()))
        .bytes(&[0]);
    m.c_str().ok_or(Errno::ENAMETOOLONG)
}

fn execve(path: Exe, bufs: &mut ExecBufs) -> Errno {
    let path = match path {
        Exe::Given(p) => p,
        Exe::Found => match CStr::from_bytes_until_nul(&bufs.path) {
            Ok(p) => p,
            Err(_no_nul) => return Errno::ENAMETOOLONG,
        },
    };
    process::execve(path, &bufs.argv, &bufs.envp)
}

/// Where the executable is.
#[derive(Clone, Copy)]
enum Exe {
    /// `args[0]` itself, which contains a `/`.
    Given(Str),
    /// Found on `PATH`, in [`ExecBufs::path`].
    Found,
}

fn setup(
    ctx: &rootfs::Ctx<'_>,
    join: &[Option<(u64, Fd)>],
    await_maps: Option<Fd>,
    handover: &Handover,
    exec: &mut ExecBufs,
) -> Result<Exe, Fail> {
    let spec = ctx.spec;
    let proc = &spec.process;

    // The parent joined the rest (see `container::spawn`).
    for (i, j) in join.iter().enumerate() {
        if let Some((flag, fd)) = j {
            ns::setns(fd, *flag).at_item(Step::JoinNamespace, i, NONE)?;
        }
    }

    if let Some(r) = await_maps {
        let mut b = [0u8; 1];
        match fs::read_full(&r, &mut b) {
            Ok(1) => {}
            // The parent closed the pipe without writing: it failed and
            // reports why itself.
            Ok(_) => process::exit(1),
            Err(e) => return Err(e).at(Step::AwaitIdMaps),
        }
    }
    if spec.namespaces.new & ns::NEWCGROUP != 0 {
        // The init already sits in its cgroup, which becomes the root.
        ns::unshare(ns::NEWCGROUP).at(Step::UnshareCgroup)?;
    }

    let mut sources = rootfs::prepare(ctx)?;
    if spec.namespaces.has(ns::NEWUSER) {
        // Become the namespace's root: host root is not mapped in it, and
        // an unmapped owner cannot create files (EOVERFLOW).
        process::setresgid(0, 0, 0).at(Step::Setgid)?;
        process::setresuid(0, 0, 0).at(Step::Setuid)?;
    }
    rootfs::build(ctx, &mut sources)?;
    drop(sources);

    if let Some(adj) = proc.oom_score_adj {
        let mut v = Msg::<24>::new();
        v.i64(adj);
        let v = v
            .finish()
            .map_err(|Truncated| Errno::ERANGE)
            .at(Step::OomScoreAdj)?;
        write_proc(c"/proc/self/oom_score_adj", v).at(Step::OomScoreAdj)?;
    }
    for (i, &(resource, limit)) in proc.rlimits.iter().enumerate() {
        process::prlimit(0, resource, &limit).at_item(Step::Rlimit, i, NONE)?;
    }
    if let Some(profile) = proc.apparmor_profile {
        let mut v = Msg::<512>::new();
        v.str("exec ").cstr(profile);
        let v = v
            .finish()
            .map_err(|Truncated| Errno::ENAMETOOLONG)
            .at(Step::AppArmor)?;
        match write_proc(c"/proc/self/attr/apparmor/exec", v) {
            // Kernels before 5.8 have no per-LSM directory.
            Err(Errno::ENOENT) => write_proc(c"/proc/self/attr/exec", v),
            other => other,
        }
        .at(Step::AppArmor)?;
    }
    if let Some(label) = proc.selinux_label {
        write_proc(c"/proc/self/attr/exec", label.to_bytes()).at(Step::SeLinux)?;
    }

    let exe = find_executable(spec, exec).at(Step::FindExecutable)?;
    fill(&mut exec.argv, proc.args.as_slice()).at(Step::Exec)?;
    fill(&mut exec.envp, proc.env.as_slice()).at(Step::Exec)?;

    // Without no_new_privs, installing the filter needs CAP_SYS_ADMIN, so it
    // goes in before the capabilities are dropped; the profile must then
    // allow the remaining setup calls, as with runc.
    if !proc.no_new_privileges
        && let Some(prog) = &spec.seccomp
    {
        crate::seccomp::install(prog).at(Step::Seccomp)?;
    }

    if let Some(sets) = &proc.capabilities {
        caps::restrict_bounding(sets.bounding).map_err(|e| Fail {
            step: Step::Bounding,
            index: e.cap,
            sub: NONE,
            errno: e.errno,
        })?;
        process::prctl(pr::SET_KEEPCAPS, 1, 0, 0, 0).at(Step::KeepCaps)?;
    }
    if let Some(cwd) = proc.cwd {
        fs::chdir(cwd).at(Step::Chdir)?;
    }
    process::setgroups(proc.additional_gids.as_slice()).at(Step::Setgroups)?;
    process::setresgid(proc.gid, proc.gid, proc.gid).at(Step::Setgid)?;
    process::setresuid(proc.uid, proc.uid, proc.uid).at(Step::Setuid)?;
    if let Some(sets) = &proc.capabilities {
        caps::set(sets).at(Step::Capset)?;
        process::prctl(pr::SET_KEEPCAPS, 0, 0, 0, 0).at(Step::KeepCaps)?;
        caps::set_ambient(sets.ambient).map_err(|e| match e {
            caps::AmbientError::Clear(errno) => Fail {
                step: Step::Ambient,
                index: NONE,
                sub: NONE,
                errno,
            },
            caps::AmbientError::Raise(e) => Fail {
                step: Step::Ambient,
                index: e.cap,
                sub: NONE,
                errno: e.errno,
            },
        })?;
    }
    process::umask(proc.umask.unwrap_or(0o022));

    if proc.no_new_privileges {
        process::prctl(pr::SET_NO_NEW_PRIVS, 1, 0, 0, 0).at(Step::NoNewPrivs)?;
        if let Some(prog) = &spec.seccomp {
            crate::seccomp::install(prog).at(Step::Seccomp)?;
        }
    }

    if let Handover::Fifo(fifo) = handover {
        // The FIFO is reopened through /proc after readiness; make sure that
        // works now, while a failure can still be reported.
        let mut m = Msg::new();
        let path = fd_path(fifo, &mut m).at(Step::CheckFifo)?;
        fs::statx(&fs::CWD, path, 0).at(Step::CheckFifo)?;
    }
    Ok(exe)
}

/// Fills a NULL-terminated pointer array for `execve`.
fn fill(dst: &mut [*const c_char], strs: &[Str]) -> Result<(), Errno> {
    let n = strs.len();
    if n >= dst.len() {
        return Err(Errno::E2BIG);
    }
    for (slot, s) in dst.iter_mut().zip(strs) {
        *slot = s.as_ptr();
    }
    if let Some(end) = dst.get_mut(n) {
        *end = ptr::null();
    }
    Ok(())
}

const DEFAULT_PATH: &[u8] = b"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Resolves `args[0]` the way `execvp` would: as given if it contains a `/`,
/// otherwise in the first `PATH` directory holding an executable file. As
/// with execvp, entries that do not have the file are skipped, and finding
/// it only without execute permission is `EACCES`.
fn find_executable(spec: &Spec, exec: &mut ExecBufs) -> Result<Exe, Errno> {
    let proc = &spec.process;
    let prog = *proc.args.as_slice().first().ok_or(Errno::ENOENT)?;
    if prog.to_bytes().contains(&b'/') {
        return Ok(Exe::Given(prog));
    }
    let path = proc
        .env
        .iter()
        .find_map(|e| e.to_bytes().strip_prefix(b"PATH="))
        .unwrap_or(DEFAULT_PATH);
    let mut denied = false;
    for dir in path.split(|&c| c == b':') {
        // An empty entry means the working directory, as for execvp.
        let dir: &[u8] = if dir.is_empty() { b"." } else { dir };
        let mut m = Msg::<PATH_MAX>::new();
        m.bytes(dir).str("/").bytes(prog.to_bytes()).bytes(&[0]);
        // A candidate longer than PATH_MAX cannot exist; skip it as execvp does.
        let Some(cand) = m.c_str() else { continue };
        match fs::statx(&fs::CWD, cand, 0) {
            Ok(st) if st.mode & fs::S_IFMT == fs::S_IFREG && st.mode & 0o111 != 0 => {
                let bytes = cand.to_bytes_with_nul();
                let dst = exec
                    .path
                    .get_mut(..bytes.len())
                    .ok_or(Errno::ENAMETOOLONG)?;
                crate::fixed::copy(dst, bytes);
                return Ok(Exe::Found);
            }
            Ok(_) | Err(Errno::EACCES) => denied = true,
            Err(Errno::ENOENT | Errno::ENOTDIR | Errno::ELOOP | Errno::ENAMETOOLONG) => {}
            Err(e) => return Err(e),
        }
    }
    Err(if denied { Errno::EACCES } else { Errno::ENOENT })
}

/// Writes `value` to a file in /proc, which takes it in one write.
fn write_proc(path: &CStr, value: &[u8]) -> Result<(), Errno> {
    let f = fs::openat(&fs::CWD, path, fs::O_WRONLY | fs::O_CLOEXEC, 0)?;
    let n = f.write(value)?;
    if n != value.len() {
        return Err(Errno::EIO);
    }
    f.close()
}
