//! The runc-compatible verbs containerd's shim drives — `create`, `start`,
//! `state`, `kill`, `delete` — plus `run` (create and start in one, waiting
//! for the container to exit).

use core::ffi::CStr;

use xorpio::Errno;
use xorpio::epoll::{self, Epoll, Event};
use xorpio::fs;
use xorpio::io::{self as xio, AsRawFd, Fd, STDOUT};
use xorpio::ns;
use xorpio::process::{self, CloneArgs, Forked, Pid, clone, sig};

use crate::cgroup;
use crate::fixed::Once;
use crate::init::{self, ExecBufs, Handover, Init, InitError, RECORD, Status as InitStatus};
use crate::io::{self, Msg, Report, Truncated};
use crate::oci::{self, IdMap, Spec, SpecError};
use crate::path::PATH_MAX;
use crate::proc;
use crate::state::{self, FIFO, Id, State, Status};

/// The largest `config.json` accepted. It sits in `.bss`, so only the
/// pages a config actually fills are ever touched.
pub const CONFIG_MAX: usize = 4 << 20;

/// Everything big, allocated once, statically.
pub struct Arena {
    config: [u8; CONFIG_MAX],
    spec: Spec,
    exec: ExecBufs,
}

// The raw pointers in `exec` point into `config`, which is just as static.
unsafe impl Send for Arena {}

pub static ARENA: Once<Arena> = Once::new(Arena {
    config: [0; CONFIG_MAX],
    spec: Spec::new(),
    exec: ExecBufs::new(),
});

// ---- errors ----

#[derive(Clone, Copy, Debug)]
pub enum ConfigError {
    OpenBundle(Errno),
    Open(Errno),
    Read(Errno),
    TooLarge,
    Spec(SpecError),
    /// The container asks for sysbox mode, which this build lacks.
    #[cfg(not(feature = "sysbox"))]
    SysboxUnavailable,
}

impl Report for ConfigError {
    fn report<const N: usize>(&self, m: &mut Msg<N>) {
        match *self {
            Self::OpenBundle(e) => m.str("open bundle: ").errno(e),
            Self::Open(e) => m.str("open config.json: ").errno(e),
            Self::Read(e) => m.str("read config.json: ").errno(e),
            Self::TooLarge => m.str("config.json is larger than 4 MiB"),
            Self::Spec(e) => {
                m.str("config.json: ");
                e.report(m);
                m
            }
            #[cfg(not(feature = "sysbox"))]
            Self::SysboxUnavailable => {
                m.str("the org.zrc.sysbox annotation needs zrc built with --features sysbox")
            }
        };
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CreateError {
    StateRoot(Errno),
    Exists,
    StateDir(Errno),
    Config(ConfigError),
    BundlePath(Errno),
    Cgroup(cgroup::SetupError),
    Fifo(Errno),
    Pipe(Errno),
    OpenNamespace {
        path: oci::Str,
        errno: Errno,
    },
    JoinNamespace {
        path: oci::Str,
        errno: Errno,
    },
    Clone(Errno),
    IdMap {
        file: &'static str,
        errno: Errno,
    },
    Init(InitError),
    /// The init exited without reporting.
    InitDied,
    Sync(Errno),
    SyncGarbled,
    StartTime(Errno),
    SaveState(Errno),
    PidFile(Errno),
    Wait(Errno),
}

impl From<ConfigError> for CreateError {
    fn from(e: ConfigError) -> Self {
        Self::Config(e)
    }
}

impl Report for CreateError {
    fn report<const N: usize>(&self, m: &mut Msg<N>) {
        match *self {
            Self::StateRoot(e) => m.str("open state root: ").errno(e),
            Self::Exists => m.str("a container with this id already exists"),
            Self::StateDir(e) => m.str("create state directory: ").errno(e),
            Self::Config(e) => {
                e.report(m);
                m
            }
            Self::BundlePath(e) => m.str("resolve bundle path: ").errno(e),
            Self::Cgroup(e) => {
                m.str("cgroup: ");
                e.report(m);
                m
            }
            Self::Fifo(e) => m.str("create exec.fifo: ").errno(e),
            Self::Pipe(e) => m.str("pipe: ").errno(e),
            Self::OpenNamespace { path, errno } => {
                m.str("open namespace ").cstr(path).str(": ").errno(errno)
            }
            Self::JoinNamespace { path, errno } => {
                m.str("join namespace ").cstr(path).str(": ").errno(errno)
            }
            Self::Clone(e) => m.str("clone3: ").errno(e),
            Self::IdMap { file, errno } => m.str("write ").str(file).str(": ").errno(errno),
            Self::Init(e) => {
                m.str("init: ");
                e.report(m);
                m
            }
            Self::InitDied => m.str("init exited without reporting"),
            Self::Sync(e) => m.str("read from init: ").errno(e),
            Self::SyncGarbled => m.str("garbled message from init"),
            Self::StartTime(e) => m.str("read init start time: ").errno(e),
            Self::SaveState(e) => m.str("save state: ").errno(e),
            Self::PidFile(e) => m.str("write pid file: ").errno(e),
            Self::Wait(e) => m.str("wait4: ").errno(e),
        };
    }
}

/// Errors of looking up an existing container.
#[derive(Clone, Copy, Debug)]
pub enum LookupError {
    StateRoot(Errno),
    NotFound,
    Open(Errno),
    Load(state::LoadError),
    Proc(Errno),
}

impl Report for LookupError {
    fn report<const N: usize>(&self, m: &mut Msg<N>) {
        match *self {
            Self::StateRoot(e) => m.str("open state root: ").errno(e),
            Self::NotFound => m.str("no such container"),
            Self::Open(e) => m.str("open state: ").errno(e),
            Self::Load(e) => {
                e.report(m);
                m
            }
            Self::Proc(e) => m.str("check init process: ").errno(e),
        };
    }
}

// ---- shared ----

/// Reads and decodes `<bundle>/config.json` into the arena.
fn load(
    bundle: &'static CStr,
    arena: &'static mut Arena,
) -> Result<(Fd, &'static Spec, &'static mut ExecBufs), ConfigError> {
    let Arena { config, spec, exec } = arena;
    let dir = fs::openat(
        &fs::CWD,
        bundle,
        fs::O_PATH | fs::O_DIRECTORY | fs::O_CLOEXEC,
        0,
    )
    .map_err(ConfigError::OpenBundle)?;
    let f = fs::openat(&dir, c"config.json", fs::O_RDONLY | fs::O_CLOEXEC, 0)
        .map_err(ConfigError::Open)?;
    let n = fs::read_full(&f, config).map_err(ConfigError::Read)?;
    if n == config.len() {
        return Err(ConfigError::TooLarge);
    }
    let config: &'static mut [u8] = config.get_mut(..n).unwrap_or_default();
    spec.parse(config).map_err(ConfigError::Spec)?;
    if spec.sysbox {
        #[cfg(feature = "sysbox")]
        crate::sysbox::prepare(spec).map_err(ConfigError::Spec)?;
        #[cfg(not(feature = "sysbox"))]
        return Err(ConfigError::SysboxUnavailable);
    }
    spec.validate().map_err(ConfigError::Spec)?;
    Ok((dir, spec, exec))
}

/// The cgroup path: `linux.cgroupsPath`, or `/zrc/<id>` built in `buf`.
fn cgroup_path<'m>(
    spec: &Spec,
    id: Id,
    buf: &'m mut Msg<PATH_MAX>,
) -> Result<&'m CStr, CreateError> {
    if let Some(p) = spec.cgroups_path {
        return Ok(p);
    }
    buf.str("/zrc/").cstr(id.0).bytes(&[0]);
    buf.c_str()
        .ok_or(CreateError::Cgroup(cgroup::SetupError::InvalidPath))
}

struct Child {
    pid: Pid,
    pidfd: Fd,
    sync: Fd,
}

impl Child {
    /// Kills and reaps a child that will not be handed over.
    fn abort(&self) {
        match process::pidfd_send_signal(&self.pidfd, sig::SIGKILL) {
            Ok(()) | Err(Errno::ESRCH) => {}
            Err(e) => io::fail("kill init", &e),
        }
        if let Err(e) = reap(self.pid) {
            io::fail("reap init", &e);
        }
    }
}

/// Waits for `pid` and returns its wait status.
fn reap(pid: Pid) -> Result<process::WaitStatus, Errno> {
    loop {
        match process::wait4(pid, 0) {
            Ok((_, status)) => return Ok(status),
            Err(Errno::EINTR) => {}
            Err(e) => return Err(e),
        }
    }
}

fn write_id_maps(pid: Pid, spec: &Spec) -> Result<(), CreateError> {
    let mut dir = Msg::<32>::new();
    dir.str("/proc/").i64(i64::from(pid)).bytes(&[0]);
    let dir = dir.c_str().ok_or(CreateError::IdMap {
        file: "uid_map",
        errno: Errno::ENAMETOOLONG,
    })?;
    let dir = fs::openat(
        &fs::CWD,
        dir,
        fs::O_PATH | fs::O_DIRECTORY | fs::O_CLOEXEC,
        0,
    )
    .map_err(|errno| CreateError::IdMap {
        file: "uid_map",
        errno,
    })?;
    let files: [(&'static str, &CStr, &[IdMap]); 2] = [
        ("uid_map", c"uid_map", spec.uid_maps.as_slice()),
        ("gid_map", c"gid_map", spec.gid_maps.as_slice()),
    ];
    for (file, name, maps) in files {
        let err = |errno| CreateError::IdMap { file, errno };
        // The kernel takes a map in one write of less than a page.
        let mut text = Msg::<4096>::new();
        for m in maps {
            text.u64(m.container.into())
                .str(" ")
                .u64(m.host.into())
                .str(" ")
                .u64(m.size.into())
                .str("\n");
        }
        let text = text.finish().map_err(|Truncated| err(Errno::E2BIG))?;
        let f = fs::openat(&dir, name, fs::O_WRONLY | fs::O_CLOEXEC, 0).map_err(err)?;
        if f.write(text).map_err(err)? != text.len() {
            return Err(err(Errno::EIO));
        }
        f.close().map_err(err)?;
    }
    Ok(())
}

/// Clones the init into `cgroup` and returns once it awaits the parent no
/// more (id maps written).
/// `bundle` and `cgroup_path` are paths for the init to open in its own
/// mount namespace; `cgroup` is the leaf it is cloned into.
fn spawn(
    spec: &'static Spec,
    bundle: &CStr,
    cgroup: &Fd,
    cgroup_path: &CStr,
    handover: Handover,
    exec: &'static mut ExecBufs,
) -> Result<Child, CreateError> {
    let (sync_r, sync_w) = xio::pipe(fs::O_CLOEXEC).map_err(CreateError::Pipe)?;
    let new_user = spec.namespaces.new & ns::NEWUSER != 0;
    let maps = if new_user {
        Some(xio::pipe(fs::O_CLOEXEC).map_err(CreateError::Pipe)?)
    } else {
        None
    };

    // Namespaces are joined while zrc still has the host's privileges, and
    // before clone3 creates the new ones, so that those belong to a joined
    // user namespace. This process exits once the init is set up, so it
    // joins them itself: a user namespace last, as it gives up the host's
    // privileges. Mount and cgroup namespaces would change what this process
    // sees, so the init joins those.
    let mut join: [Option<(u64, Fd)>; 8] = Default::default();
    let mut user = None;
    for (slot, &(flag, path)) in join.iter_mut().zip(spec.namespaces.join.iter()) {
        let fd = fs::openat(&fs::CWD, path, fs::O_RDONLY | fs::O_CLOEXEC, 0)
            .map_err(|errno| CreateError::OpenNamespace { path, errno })?;
        match flag {
            ns::NEWNS | ns::NEWCGROUP => *slot = Some((flag, fd)),
            ns::NEWUSER => user = Some((path, fd)),
            _ => {
                ns::setns(&fd, flag).map_err(|errno| CreateError::JoinNamespace { path, errno })?
            }
        }
    }
    if let Some((path, fd)) = user {
        ns::setns(&fd, ns::NEWUSER).map_err(|errno| CreateError::JoinNamespace { path, errno })?;
    }

    let mut pidfd: i32 = -1;
    let args = CloneArgs {
        // The cgroup namespace is created by the init, once in its cgroup.
        flags: (spec.namespaces.new & !ns::NEWCGROUP) | clone::PIDFD | clone::INTO_CGROUP,
        pidfd: &mut pidfd as *mut i32 as u64,
        exit_signal: sig::SIGCHLD as u64,
        cgroup: cgroup.as_raw_fd() as u64,
        ..CloneArgs::default()
    };
    // zrc is single-threaded.
    match unsafe { process::clone3(&args) }.map_err(CreateError::Clone)? {
        Forked::Child => {
            drop(sync_r);
            let await_maps = maps.map(|(r, w)| {
                drop(w);
                r
            });
            init::run(Init {
                spec,
                bundle,
                cgroup: cgroup_path,
                join: &join,
                sync: sync_w,
                await_maps,
                handover,
                exec,
            })
        }
        Forked::Parent(pid) => {
            drop(sync_w);
            drop(handover);
            let child = Child {
                pid,
                pidfd: unsafe { Fd::from_raw(pidfd) },
                sync: sync_r,
            };
            if let Some((r, w)) = maps {
                drop(r);
                let written = write_id_maps(pid, spec).and_then(|()| {
                    w.write(&[0]).map(drop).map_err(|errno| CreateError::IdMap {
                        file: "maps-ready pipe",
                        errno,
                    })
                });
                if let Err(e) = written {
                    child.abort();
                    return Err(e);
                }
            }
            Ok(child)
        }
    }
}

/// Reads the init's next record: `Ok(true)` ready, `Ok(false)` the pipe
/// closed without one.
fn read_record(sync: &Fd, spec: &'static Spec) -> Result<bool, CreateError> {
    let mut rec = [0u8; RECORD];
    match fs::read_full(sync, &mut rec).map_err(CreateError::Sync)? {
        0 => return Ok(false),
        RECORD => {}
        _ => return Err(CreateError::SyncGarbled),
    }
    match init::decode(&rec).map_err(|init::Garbled| CreateError::SyncGarbled)? {
        InitStatus::Ready => Ok(true),
        InitStatus::Failed(f) => Err(CreateError::Init(InitError::new(f, spec))),
    }
}

fn await_ready(child: &Child, spec: &'static Spec) -> Result<(), CreateError> {
    match read_record(&child.sync, spec)? {
        true => Ok(()),
        false => Err(CreateError::InitDied),
    }
}

fn destroy_cgroup(path: &CStr) {
    if let Err(e) = cgroup::destroy(path) {
        io::fail("cleanup: cgroup", &e);
    }
}

// ---- create ----

pub struct CreateArgs {
    pub root: &'static CStr,
    pub id: Id,
    pub bundle: &'static CStr,
    pub pid_file: Option<&'static CStr>,
}

pub fn create(a: &CreateArgs, arena: &'static mut Arena) -> Result<(), CreateError> {
    let root = state::open_root(a.root).map_err(CreateError::StateRoot)?;
    match fs::mkdirat(&root, a.id.0, 0o700) {
        Ok(()) => {}
        Err(Errno::EEXIST) => return Err(CreateError::Exists),
        Err(e) => return Err(CreateError::StateDir(e)),
    }
    let res = create_in(&root, a, arena);
    if res.is_err()
        && let Err(e) = state::remove(&root, a.id)
    {
        io::fail("cleanup: state", &e);
    }
    res
}

fn create_in(root: &Fd, a: &CreateArgs, arena: &'static mut Arena) -> Result<(), CreateError> {
    let dir = state::open_dir(root, a.id).map_err(CreateError::StateDir)?;
    let (bundle, spec, exec) = load(a.bundle, arena)?;

    // The state records the bundle's absolute path, as OCI requires.
    let mut link = Msg::<32>::new();
    link.str("/proc/self/fd/")
        .i64(i64::from(bundle.as_raw_fd()))
        .bytes(&[0]);
    let link = link
        .c_str()
        .ok_or(CreateError::BundlePath(Errno::ENAMETOOLONG))?;
    let mut bundle_path = [0u8; PATH_MAX];
    let room = bundle_path.get_mut(..PATH_MAX - 1).unwrap_or_default();
    let n = fs::readlinkat(&fs::CWD, link, room).map_err(CreateError::BundlePath)?;
    let bundle_path = bundle_path
        .get(..=n)
        .and_then(|b| CStr::from_bytes_with_nul(b).ok())
        .ok_or(CreateError::BundlePath(Errno::ENAMETOOLONG))?;

    let mut default_cg = Msg::<PATH_MAX>::new();
    let cg_path = cgroup_path(spec, a.id, &mut default_cg)?;
    // Recorded before anything exists to clean up, so that `delete` can
    // always find the cgroup; pid 0 means there is no init yet.
    let pending = State {
        pid: 0,
        start_time: 0,
        status: Status::Created,
        bundle: bundle_path,
        cgroup: cg_path,
    };
    pending.save(&dir).map_err(CreateError::SaveState)?;
    let cg = cgroup::create(cg_path, &spec.resources, spec.devices.as_slice())
        .map_err(CreateError::Cgroup)?;
    drop(bundle);
    let started = Started {
        spec,
        dir: &dir,
        bundle_path,
        cgroup: &cg,
        cgroup_path: cg_path,
    };
    let res = create_container(&started, a.pid_file, exec);
    if res.is_err() {
        drop(cg);
        destroy_cgroup(cg_path);
    }
    res
}

/// What `create` has set up before the init is cloned.
struct Started<'a> {
    spec: &'static Spec,
    dir: &'a Fd,
    /// Absolute, so the init finds it whatever its working directory.
    bundle_path: &'a CStr,
    cgroup: &'a Fd,
    cgroup_path: &'a CStr,
}

fn create_container(
    s: &Started<'_>,
    pid_file: Option<&CStr>,
    exec: &'static mut ExecBufs,
) -> Result<(), CreateError> {
    // 0622 so the init can open it for writing as any user; it gets in
    // through an O_PATH fd, so the 0700 state directory stays shut.
    fs::mknodat(s.dir, FIFO, fs::S_IFIFO | 0o622, 0).map_err(CreateError::Fifo)?;
    let fifo = fs::openat(s.dir, FIFO, fs::O_PATH | fs::O_CLOEXEC, 0).map_err(CreateError::Fifo)?;
    let child = spawn(
        s.spec,
        s.bundle_path,
        s.cgroup,
        s.cgroup_path,
        Handover::Fifo(fifo),
        exec,
    )?;
    let res = record_created(s, &child, pid_file);
    if res.is_err() {
        child.abort();
    }
    res
}

fn record_created(
    s: &Started<'_>,
    child: &Child,
    pid_file: Option<&CStr>,
) -> Result<(), CreateError> {
    await_ready(child, s.spec)?;
    let start_time = proc::stat(child.pid)
        .map_err(CreateError::StartTime)?
        .start_time;
    let st = State {
        pid: child.pid,
        start_time,
        status: Status::Created,
        bundle: s.bundle_path,
        cgroup: s.cgroup_path,
    };
    st.save(s.dir).map_err(CreateError::SaveState)?;
    if let Some(pf) = pid_file {
        write_pid_file(pf, child.pid).map_err(CreateError::PidFile)?;
    }
    Ok(())
}

fn write_pid_file(path: &CStr, pid: Pid) -> Result<(), Errno> {
    let mut m = Msg::<16>::new();
    m.i64(i64::from(pid));
    let f = fs::openat(
        &fs::CWD,
        path,
        fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_CLOEXEC,
        0o644,
    )?;
    xio::write_all(
        f.as_raw_fd(),
        m.finish().map_err(|Truncated| Errno::ERANGE)?,
    )?;
    f.close()
}

// ---- run ----

pub struct RunArgs {
    pub id: Id,
    pub bundle: &'static CStr,
}

/// Creates and starts the container, waits for it, and returns its exit
/// code (128 + signal if killed).
pub fn run(a: &RunArgs, arena: &'static mut Arena) -> Result<i32, CreateError> {
    let (bundle, spec, exec) = load(a.bundle, arena)?;
    let mut default_cg = Msg::<PATH_MAX>::new();
    let cg_path = cgroup_path(spec, a.id, &mut default_cg)?;
    let cg = cgroup::create(cg_path, &spec.resources, spec.devices.as_slice())
        .map_err(CreateError::Cgroup)?;
    drop(bundle);
    let res = run_container(spec, a.bundle, &cg, cg_path, exec);
    drop(cg);
    destroy_cgroup(cg_path);
    res
}

fn run_container(
    spec: &'static Spec,
    bundle: &CStr,
    cg: &Fd,
    cg_path: &CStr,
    exec: &'static mut ExecBufs,
) -> Result<i32, CreateError> {
    let child = spawn(spec, bundle, cg, cg_path, Handover::Direct, exec)?;
    if let Err(e) = await_exec(&child, spec) {
        child.abort();
        return Err(e);
    }
    let status = reap(child.pid).map_err(CreateError::Wait)?;
    Ok(status
        .exit_code()
        .or(status.signal().map(|s| 128 + s))
        .unwrap_or(1))
}

/// Waits for readiness, then for the exec: after readiness the sync pipe
/// closes on a successful exec, or carries the exec's failure.
fn await_exec(child: &Child, spec: &'static Spec) -> Result<(), CreateError> {
    await_ready(child, spec)?;
    match read_record(&child.sync, spec)? {
        false => Ok(()),
        true => Err(CreateError::SyncGarbled),
    }
}

// ---- start ----

#[derive(Clone, Copy, Debug)]
pub enum StartError {
    Lookup(LookupError),
    NotCreated(Status),
    OpenFifo(Errno),
    Wait(Errno),
    /// The init exited before running the process.
    InitDied,
    /// `execve` of the container process failed.
    Exec(Errno),
    SaveState(Errno),
    RemoveFifo(Errno),
}

impl From<LookupError> for StartError {
    fn from(e: LookupError) -> Self {
        Self::Lookup(e)
    }
}

impl Report for StartError {
    fn report<const N: usize>(&self, m: &mut Msg<N>) {
        match *self {
            Self::Lookup(e) => {
                e.report(m);
                m
            }
            Self::NotCreated(s) => m.str("container is ").str(s.as_str()).str(", not created"),
            Self::OpenFifo(e) => m.str("open exec.fifo: ").errno(e),
            Self::Wait(e) => m.str("wait for init: ").errno(e),
            Self::InitDied => m.str("init exited before starting the process"),
            Self::Exec(e) => m.str("execve: ").errno(e),
            Self::SaveState(e) => m.str("save state: ").errno(e),
            Self::RemoveFifo(e) => m.str("remove exec.fifo: ").errno(e),
        };
    }
}

/// An existing container's state directory, state and live init.
struct Found<'b> {
    root: Fd,
    dir: Fd,
    state: State<'b>,
    init: proc::Init,
}

fn find<'b>(root: &CStr, id: Id, buf: &'b mut state::Buf) -> Result<Found<'b>, LookupError> {
    let root = state::open_root(root).map_err(LookupError::StateRoot)?;
    let dir = match state::open_dir(&root, id) {
        Ok(dir) => dir,
        Err(Errno::ENOENT) => return Err(LookupError::NotFound),
        Err(e) => return Err(LookupError::Open(e)),
    };
    let state = State::load(&dir, buf).map_err(LookupError::Load)?;
    let init = proc::find(state.pid, state.start_time).map_err(LookupError::Proc)?;
    Ok(Found {
        root,
        dir,
        state,
        init,
    })
}

pub fn start(root: &CStr, id: Id) -> Result<(), StartError> {
    let mut buf = [0u8; core::mem::size_of::<state::Buf>()];
    let Found {
        dir,
        mut state,
        init,
        ..
    } = find(root, id, &mut buf)?;
    let pidfd = match (state.status, init) {
        (Status::Created, proc::Init::Alive(fd)) => fd,
        (Status::Created, proc::Init::Gone) => return Err(StartError::NotCreated(Status::Stopped)),
        (status, _) => return Err(StartError::NotCreated(status)),
    };

    // Opening the read end releases the init's blocking open of the write
    // end. Then either the exec closes it (success), the init writes the
    // exec's errno, or the init dies.
    let fifo = fs::openat(&dir, FIFO, fs::O_RDONLY | fs::O_NONBLOCK | fs::O_CLOEXEC, 0)
        .map_err(StartError::OpenFifo)?;
    let ep = Epoll::new().map_err(StartError::Wait)?;
    ep.add(&fifo, epoll::IN, 0).map_err(StartError::Wait)?;
    ep.add(&pidfd, epoll::IN, 1).map_err(StartError::Wait)?;
    let mut events = [Event::EMPTY; 2];
    let fifo_ready = loop {
        let ready = match ep.wait(&mut events, -1) {
            Ok(ready) => ready,
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(StartError::Wait(e)),
        };
        if !ready.is_empty() {
            break ready.iter().any(|e| e.token() == 0);
        }
    };
    let mut errno = [0u8; 4];
    let n = match xio::read(fifo.as_raw_fd(), &mut errno) {
        Ok(n) => n,
        // Nothing written and the init still holds the write end: only
        // possible if the init died first, without opening it.
        Err(Errno::EAGAIN) if !fifo_ready => 0,
        Err(e) => return Err(StartError::Wait(e)),
    };
    if n == errno.len() {
        return Err(StartError::Exec(Errno::from_raw(i32::from_le_bytes(errno))));
    }
    if !fifo_ready || n != 0 {
        return Err(StartError::InitDied);
    }

    state.status = Status::Running;
    state.save(&dir).map_err(StartError::SaveState)?;
    fs::unlinkat(&dir, FIFO, 0).map_err(StartError::RemoveFifo)
}

// ---- state ----

#[derive(Clone, Copy, Debug)]
pub enum StateError {
    Lookup(LookupError),
    TooLong,
    Write(Errno),
}

impl Report for StateError {
    fn report<const N: usize>(&self, m: &mut Msg<N>) {
        match *self {
            Self::Lookup(e) => {
                e.report(m);
                m
            }
            Self::TooLong => m.str("state does not fit the output buffer"),
            Self::Write(e) => m.str("write: ").errno(e),
        };
    }
}

/// Prints the OCI state of the container as JSON.
pub fn state(root: &CStr, id: Id) -> Result<(), StateError> {
    let mut buf = [0u8; core::mem::size_of::<state::Buf>()];
    let Found { state, init, .. } = find(root, id, &mut buf).map_err(StateError::Lookup)?;
    let (status, pid) = match init {
        proc::Init::Alive(_) => (state.status, state.pid),
        proc::Init::Gone => (Status::Stopped, 0),
    };
    // Escaping can grow a path up to six times.
    let mut m = Msg::<{ 14 * PATH_MAX }>::new();
    m.str("{\"ociVersion\":\"")
        .str(state::OCI_VERSION)
        .str("\",\"id\":");
    m.json_str(id.0.to_bytes());
    m.str(",\"status\":\"")
        .str(status.as_str())
        .str("\",\"pid\":")
        .i64(i64::from(pid));
    m.str(",\"bundle\":")
        .json_str(state.bundle.to_bytes())
        .str("}\n");
    let out = m.finish().map_err(|Truncated| StateError::TooLong)?;
    xio::write_all(STDOUT, out).map_err(StateError::Write)
}

// ---- kill ----

#[derive(Clone, Copy, Debug)]
pub enum KillError {
    Lookup(LookupError),
    NotRunning,
    Signal(Errno),
    /// Signalling every process of the container's cgroup failed.
    SignalAll(Errno),
}

impl Report for KillError {
    fn report<const N: usize>(&self, m: &mut Msg<N>) {
        match *self {
            Self::Lookup(e) => {
                e.report(m);
                m
            }
            // containerd matches this wording (runc's).
            Self::NotRunning => m.str("container not running"),
            Self::Signal(e) => m.str("signal init: ").errno(e),
            Self::SignalAll(e) => m.str("signal cgroup members: ").errno(e),
        };
    }
}

pub fn kill(root: &CStr, id: Id, signal: i32, all: bool) -> Result<(), KillError> {
    let mut buf = [0u8; core::mem::size_of::<state::Buf>()];
    let Found { state, init, .. } = find(root, id, &mut buf).map_err(KillError::Lookup)?;
    if all {
        // Also after the init exited: what is left in the cgroup is the point.
        return cgroup::signal_all(state.cgroup, signal).map_err(KillError::SignalAll);
    }
    let proc::Init::Alive(pidfd) = init else {
        return Err(KillError::NotRunning);
    };
    match process::pidfd_send_signal(&pidfd, signal) {
        // It exited after the lookup.
        Err(Errno::ESRCH) => Err(KillError::NotRunning),
        other => other.map_err(KillError::Signal),
    }
}

// ---- delete ----

#[derive(Clone, Copy, Debug)]
pub enum DeleteError {
    Lookup(LookupError),
    /// Started and still running, and `--force` was not given.
    Running,
    Kill(Errno),
    Cgroup(cgroup::DestroyError),
    Remove(Errno),
}

impl Report for DeleteError {
    fn report<const N: usize>(&self, m: &mut Msg<N>) {
        match *self {
            Self::Lookup(e) => {
                e.report(m);
                m
            }
            Self::Running => m.str("container is running; stop it or use --force"),
            Self::Kill(e) => m.str("kill init: ").errno(e),
            Self::Cgroup(e) => {
                m.str("cgroup: ");
                e.report(m);
                m
            }
            Self::Remove(e) => m.str("remove state: ").errno(e),
        };
    }
}

pub fn delete(root: &CStr, id: Id, force: bool) -> Result<(), DeleteError> {
    let mut buf = [0u8; core::mem::size_of::<state::Buf>()];
    let Found {
        root,
        dir,
        state,
        init,
    } = match find(root, id, &mut buf) {
        Ok(found) => found,
        Err(LookupError::NotFound) if force => return Ok(()),
        // A create killed before writing its first state left no cgroup
        // and no init, only the directory.
        Err(LookupError::Load(_)) if force => {
            let root = state::open_root(root)
                .map_err(|e| DeleteError::Lookup(LookupError::StateRoot(e)))?;
            return state::remove(&root, id).map_err(DeleteError::Remove);
        }
        Err(e) => return Err(DeleteError::Lookup(e)),
    };
    if let proc::Init::Alive(pidfd) = &init {
        // A created container has not run anything yet; like runc, delete
        // it without --force.
        if state.status == Status::Running && !force {
            return Err(DeleteError::Running);
        }
        match process::pidfd_send_signal(pidfd, sig::SIGKILL) {
            Ok(()) | Err(Errno::ESRCH) => {}
            Err(e) => return Err(DeleteError::Kill(e)),
        }
    }
    // Kills whatever else is left in the cgroup and waits for it to empty.
    cgroup::destroy(state.cgroup).map_err(DeleteError::Cgroup)?;
    drop(dir);
    state::remove(&root, id).map_err(DeleteError::Remove)
}

/// Writes `zrc: <verb>: <err>` and returns the exit status for errors.
pub fn report(verb: &str, err: &impl Report) -> i32 {
    io::fail(verb, err);
    1
}
