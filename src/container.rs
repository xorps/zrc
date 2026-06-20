//! Container lifecycle: the runc-compatible verbs containerd's `runc-v2` shim
//! drives — `create`, `start`, `state`, `kill`, `delete` — plus the synchronous
//! `run` convenience. All are one-shot: each process sets up or pokes the
//! container and exits; the container's init process and `state.json` persist.
//!
//! Build sequence inside the init (PID 1 of the new namespaces):
//!   1. build_rootfs  — mounts, pivot_root, hostname        (at `create`)
//!   2. block on exec.fifo                                  (released by `start`)
//!   3. finalize_and_exec — no_new_privs, drop privs, exec  (at `start`)
//!
//! Keeping a pre-pivot O_PATH handle to the state dir lets the init reach
//! `exec.fifo` by `openat` even after it has pivoted away from the host rootfs.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::caps;
use crate::cgroup;
use crate::json;
use crate::oci::{IdMap, Spec};
use crate::state::{State, Status};
use crate::sys;

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

// ===========================================================================
// run — synchronous create+start in one process (handy for testing)
// ===========================================================================

pub fn run(bundle: &str, _id: &str) -> i32 {
    let mut spec = match load_spec(bundle) {
        Ok(s) => s,
        Err(code) => return code,
    };
    apply_sysbox(&mut spec);
    let rootfs = resolve(bundle, &spec.root_path);
    let (ns_flags, mount_ns) = ns_flags(&spec);
    let cg = cgroup_path(&spec, _id);

    let prep = match open_prep_pipe(&spec) {
        Ok(p) => p,
        Err(c) => return c,
    };

    match sys::clone_ns(ns_flags) {
        Ok(0) => {
            if !child_prep(&spec, prep) {
                eprintln!("zrc: container prep (maps/cgroup) failed");
                sys::exit_group(126);
            }
            if let Err(m) = build_rootfs(&spec, &rootfs, mount_ns) {
                eprintln!("zrc: container setup failed: {}", m);
                sys::exit_group(127);
            }
            match finalize_and_exec(&spec) {
                Ok(()) => sys::exit_group(0),
                Err(m) => {
                    eprintln!("zrc: {}", m);
                    sys::exit_group(127);
                }
            }
        }
        Ok(pid) => {
            if let Err(m) = parent_prep(pid, &spec, &cg, prep) {
                eprintln!("zrc: {}: container prep", m);
                let _ = sys::kill(pid, 9);
                return 1;
            }
            let code = reap(pid);
            if uses_cgroup(&spec) {
                cgroup::destroy(&cg);
            }
            code
        }
        Err(e) => {
            eprintln!("zrc: clone failed: errno {} (need privileges/namespaces?)", e);
            1
        }
    }
}

// ===========================================================================
// create
// ===========================================================================

pub fn create(
    root: &str,
    id: &str,
    bundle: &str,
    pid_file: Option<&str>,
    _console_socket: Option<&str>,
) -> i32 {
    if State::load(root, id).is_ok() {
        eprintln!("zrc: container '{}' already exists", id);
        return 1;
    }

    let mut spec = match load_spec(bundle) {
        Ok(s) => s,
        Err(code) => return code,
    };
    apply_sysbox(&mut spec);
    let rootfs = resolve(bundle, &spec.root_path);
    let cg = cgroup_path(&spec, id);

    let sdir = crate::state::state_dir(root, id);
    mkdir_p(&sdir);
    let fifo = format!("{}/exec.fifo", sdir);
    let _ = sys::unlink(&fifo);
    if let Err(e) = sys::mkfifo(&fifo, 0o600) {
        eprintln!("zrc: cannot create exec.fifo: errno {}", e);
        return 1;
    }

    let (ns_flags, mount_ns) = ns_flags(&spec);

    // Sync pipe: init reports "rootfs ready" (byte 0) or a failure code.
    let (sync_r, sync_w) = match sys::pipe2(sys::O_CLOEXEC) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("zrc: pipe2 failed: errno {}", e);
            return 1;
        }
    };

    // Prep pipe: parent → child, signalling maps written + cgroup placement done.
    let prep = match open_prep_pipe(&spec) {
        Ok(p) => p,
        Err(c) => return c,
    };

    match sys::clone_ns(ns_flags) {
        Ok(0) => {
            let _ = sys::close(sync_r);
            init_child(&spec, &rootfs, &sdir, sync_w, mount_ns, prep) // diverges
        }
        Ok(pid) => {
            let _ = sys::close(sync_w);
            if let Err(m) = parent_prep(pid, &spec, &cg, prep) {
                eprintln!("zrc: {}: container prep", m);
                let _ = sys::kill(pid, 9);
                let _ = sys::wait4(pid, 0);
                cleanup_state(root, id);
                return 1;
            }
            let mut b = [0u8; 1];
            let n = sys::read_full(sync_r, &mut b).unwrap_or(0);
            let _ = sys::close(sync_r);

            if n == 0 || b[0] != 0 {
                eprintln!(
                    "zrc: container init failed (code {})",
                    if n == 0 { -1 } else { b[0] as i32 }
                );
                let _ = sys::wait4(pid, 0);
                cleanup_state(root, id);
                return 1;
            }

            let st = State {
                id: id.into(),
                pid,
                bundle: bundle.into(),
                rootfs,
                fifo,
                cgroup: if uses_cgroup(&spec) {
                    cg
                } else {
                    String::new()
                },
                status: Status::Created,
            };
            if let Err(e) = st.save(root) {
                eprintln!("zrc: cannot write state: errno {}", e);
                let _ = sys::kill(pid, 9);
                cleanup_state(root, id);
                return 1;
            }
            if let Some(pf) = pid_file {
                let _ = sys::write_file(pf, format!("{}", pid).as_bytes(), 0o644);
            }
            0
        }
        Err(e) => {
            eprintln!("zrc: clone failed: errno {} (need privileges/namespaces?)", e);
            cleanup_state(root, id);
            1
        }
    }
}

/// The container init: prepares the rootfs, signals readiness, blocks on the
/// FIFO, then execs the user process when `start` releases it.
fn init_child(
    spec: &Spec,
    rootfs: &str,
    sdir: &str,
    sync_w: usize,
    mount_ns: bool,
    prep: Option<(usize, usize)>,
) -> ! {
    // Block until the parent has written our id maps and placed us in our
    // cgroup; then (if requested) enter the cgroup namespace.
    if !child_prep(spec, prep) {
        eprintln!("zrc: init: prep (maps/cgroup) failed");
        let _ = sys::write_all(sync_w, &[3]);
        sys::exit_group(126);
    }

    // Handle to the state dir, captured before we pivot away from it.
    let dirfd = match sys::openat(
        sys::AT_FDCWD,
        sdir,
        sys::O_PATH | sys::O_DIRECTORY | sys::O_CLOEXEC,
        0,
    ) {
        Ok(fd) => fd,
        Err(_) => {
            let _ = sys::write_all(sync_w, &[1]);
            sys::exit_group(126);
        }
    };

    if let Err(m) = build_rootfs(spec, rootfs, mount_ns) {
        eprintln!("zrc: init: {}", m);
        let _ = sys::write_all(sync_w, &[2]);
        sys::exit_group(127);
    }

    // Rootfs is ready — tell `create` it may return.
    let _ = sys::write_all(sync_w, &[0]);
    let _ = sys::close(sync_w);

    // Block until `start` opens the FIFO for reading.
    match sys::openat(dirfd, "exec.fifo", sys::O_WRONLY, 0) {
        Ok(fd) => {
            let _ = sys::write_all(fd, &[0]);
            let _ = sys::close(fd);
        }
        Err(e) => {
            eprintln!("zrc: init: fifo open failed: errno {}", e);
            sys::exit_group(126);
        }
    }
    let _ = sys::close(dirfd);

    match finalize_and_exec(spec) {
        Ok(()) => sys::exit_group(0),
        Err(m) => {
            eprintln!("zrc: init: {}", m);
            sys::exit_group(127);
        }
    }
}

// ===========================================================================
// start / state / kill / delete
// ===========================================================================

pub fn start(root: &str, id: &str) -> i32 {
    let st = match State::load(root, id) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("zrc: no such container '{}'", id);
            return 1;
        }
    };
    if st.status != Status::Created {
        eprintln!("zrc: cannot start container in status '{}'", st.status.as_str());
        return 1;
    }
    if !pid_alive(st.pid) {
        eprintln!("zrc: container init (pid {}) is gone", st.pid);
        return 1;
    }

    // Releasing the init: open the FIFO for reading; the init's blocked
    // O_WRONLY open returns, it writes a byte, we read it, and it execs.
    let fd = match sys::openat(sys::AT_FDCWD, &st.fifo, sys::O_RDONLY, 0) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("zrc: cannot open exec.fifo: errno {}", e);
            return 1;
        }
    };
    let mut b = [0u8; 1];
    let _ = sys::read_full(fd, &mut b);
    let _ = sys::close(fd);

    let mut st = st;
    st.status = Status::Running;
    let _ = st.save(root);
    let _ = sys::unlink(&st.fifo); // consumed
    0
}

pub fn state_cmd(root: &str, id: &str) -> i32 {
    let st = match State::load(root, id) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("zrc: no such container '{}'", id);
            return 1;
        }
    };
    let status = if pid_alive(st.pid) {
        st.status
    } else {
        Status::Stopped
    };
    println!("{}", st.to_oci_json(status));
    0
}

pub fn kill_cmd(root: &str, id: &str, sig: &str) -> i32 {
    let st = match State::load(root, id) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("zrc: no such container '{}'", id);
            return 1;
        }
    };
    let signum = match parse_signal(sig) {
        Some(n) => n,
        None => {
            eprintln!("zrc: unknown signal '{}'", sig);
            return 1;
        }
    };
    match sys::kill(st.pid, signum) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("zrc: kill failed: errno {}", e);
            1
        }
    }
}

pub fn delete_cmd(root: &str, id: &str, force: bool) -> i32 {
    let st = match State::load(root, id) {
        Ok(s) => s,
        Err(_) => {
            if force {
                return 0;
            }
            eprintln!("zrc: no such container '{}'", id);
            return 1;
        }
    };

    if pid_alive(st.pid) {
        if force {
            let _ = sys::kill(st.pid, 9);
        } else {
            eprintln!("zrc: cannot delete running container '{}' (use --force)", id);
            return 1;
        }
    }
    if !st.cgroup.is_empty() {
        cgroup::destroy(&st.cgroup);
    }
    cleanup_state(root, id);
    0
}

// ===========================================================================
// shared build phases
// ===========================================================================

/// Phase 1 — establish the container's filesystem view (runs at `create`).
///
/// We deliberately run setup with the init's original (host) credentials: in a
/// userns the init's real uid is still the host uid that created the namespace,
/// which retains DAC-override over the runtime's own files (exec.fifo, state)
/// while also holding full caps inside the userns. The drop to the mapped
/// container identity happens last, in finalize_and_exec, just before exec.
fn build_rootfs(spec: &Spec, rootfs: &str, mount_ns: bool) -> Result<(), &'static str> {
    if mount_ns {
        let _ = sys::mount(None, "/", None, sys::MS_REC | sys::MS_PRIVATE, None);
        sys::mount(Some(rootfs), rootfs, None, sys::MS_BIND | sys::MS_REC, None)
            .map_err(|_| "bind-mount rootfs")?;
        setup_mounts(spec, rootfs);
    }

    if let Some(h) = &spec.hostname {
        let _ = sys::sethostname(h);
    }

    if mount_ns {
        pivot_into(rootfs)?;
        if spec.root_readonly {
            let _ = sys::mount(
                None,
                "/",
                None,
                sys::MS_BIND | sys::MS_REMOUNT | sys::MS_RDONLY,
                None,
            );
        }
    } else {
        sys::chroot(rootfs).map_err(|_| "chroot")?;
        sys::chdir("/").map_err(|_| "chdir /")?;
    }
    Ok(())
}

/// Phase 2 — apply process-level restrictions and exec (runs at `start`).
///
/// Order matters: rlimits and the bounding-set drop happen while we still hold
/// privileges; then we switch uid/gid (with KEEPCAPS so permitted caps survive);
/// then we re-raise effective/ambient caps; no_new_privs and exec go last.
fn finalize_and_exec(spec: &Spec) -> Result<(), &'static str> {
    let userns = spec.has_user_ns();
    let p = &spec.process;

    // Resource limits — apply before dropping privileges (raising some needs
    // CAP_SYS_RESOURCE).
    for rl in &p.rlimits {
        let lim = sys::Rlimit64 {
            cur: rl.soft,
            max: rl.hard,
        };
        if let Err(e) = sys::prlimit64(0, rl.resource, &lim) {
            eprintln!("zrc: warning: rlimit {} failed: errno {}", rl.resource, e);
        }
    }

    // In a userns we must setgid/setuid even to id 0: that *assumes* the mapped
    // container-root identity (host range), shedding the host credentials used
    // for setup. Without a userns we only switch when the spec asks.
    let switch_uid = userns || p.uid != 0 || p.gid != 0;

    if let Some(caps) = &p.capabilities {
        caps::restrict_bounding(caps, switch_uid);
    }

    if !p.additional_gids.is_empty() {
        let _ = sys::setgroups(&p.additional_gids);
    }
    if userns || p.gid != 0 {
        sys::setgid(p.gid).map_err(|_| "setgid")?;
    }
    if userns || p.uid != 0 {
        sys::setuid(p.uid).map_err(|_| "setuid")?;
    }

    if let Some(caps) = &p.capabilities {
        // KEEPCAPS leaves effective cleared after setuid; capset restores it.
        let _ = sys::prctl(sys::PR_SET_KEEPCAPS, 0, 0, 0, 0);
        caps::apply_after_setuid(caps)?;
    }

    sys::chdir(&p.cwd).map_err(|_| "chdir to process.cwd")?;

    // seccomp goes last, after every syscall the runtime itself still needs, so
    // a default-deny profile only has to permit execve. (install() sets NNP.)
    if let Some(sc) = &spec.seccomp {
        let _notify_fd = crate::seccomp::install(sc)?;
        // If the profile uses SCMP_ACT_NOTIFY (sysbox builds), fork a supervisor
        // that inherits the notify fd and services interceptions while we exec.
        #[cfg(feature = "sysbox")]
        if _notify_fd >= 0 {
            match sys::fork() {
                Ok(0) => crate::seccomp::supervise(_notify_fd as usize), // diverges
                Ok(_) => {
                    let _ = sys::close(_notify_fd as usize);
                }
                Err(e) => {
                    eprintln!("zrc: warning: seccomp supervisor fork failed: errno {}", e);
                }
            }
        }
    } else if p.no_new_privileges {
        let _ = sys::prctl(sys::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }

    exec(&p.args, &p.env)
}

fn setup_mounts(spec: &Spec, rootfs: &str) {
    for m in &spec.mounts {
        let target = join(rootfs, &m.destination);
        mkdir_p(&target);

        let (flags, data) = m.parse_options();
        let (source, fstype) = if m.is_bind() {
            (m.source.as_deref(), None)
        } else {
            (m.source.as_deref().or(m.typ.as_deref()), m.typ.as_deref())
        };

        if let Err(e) = sys::mount(source, &target, fstype, flags, data.as_deref()) {
            eprintln!(
                "zrc: warning: mount {} (type {:?}) failed: errno {}",
                m.destination, m.typ, e
            );
        }
    }
}

fn pivot_into(rootfs: &str) -> Result<(), &'static str> {
    sys::chdir(rootfs).map_err(|_| "chdir rootfs")?;
    sys::pivot_root(".", ".").map_err(|_| "pivot_root")?;
    let _ = sys::umount2(".", sys::MNT_DETACH);
    sys::chdir("/").map_err(|_| "chdir / after pivot")?;
    Ok(())
}

fn exec(args: &[String], env: &[String]) -> Result<(), &'static str> {
    let prog = args.first().ok_or("empty args")?;
    let path = find_program(prog, env).ok_or("executable not found in container")?;

    let argv_c: Vec<Vec<u8>> = args.iter().map(|a| sys::cstr(a)).collect();
    let mut argv_p: Vec<*const u8> = argv_c.iter().map(|c| c.as_ptr()).collect();
    argv_p.push(core::ptr::null());

    let env_c: Vec<Vec<u8>> = env.iter().map(|e| sys::cstr(e)).collect();
    let mut env_p: Vec<*const u8> = env_c.iter().map(|c| c.as_ptr()).collect();
    env_p.push(core::ptr::null());

    let errno = sys::execve(&path, argv_p.as_ptr(), env_p.as_ptr());
    eprintln!("zrc: execve {} failed: errno {}", prog, errno);
    Err("execve failed")
}

// ===========================================================================
// helpers
// ===========================================================================

/// Apply Sysbox mode if the container opted in. Compiled-in behavior is gated
/// on the `sysbox` cargo feature; without it we warn and run as a plain OCI
/// container (the toggle is doubly fail-safe: build-time and per-container).
fn apply_sysbox(spec: &mut Spec) {
    if !spec.sysbox_requested() {
        return;
    }
    #[cfg(feature = "sysbox")]
    {
        crate::sysbox::prepare(spec);
    }
    #[cfg(not(feature = "sysbox"))]
    {
        eprintln!(
            "zrc: warning: container requests sysbox mode (org.zrc.sysbox) but this \
             build lacks --features sysbox; running as a standard OCI container"
        );
    }
}

fn load_spec(bundle: &str) -> Result<Spec, i32> {
    let cfg_path = join(bundle, "config.json");
    let cfg = sys::read_file(&cfg_path).map_err(|e| {
        eprintln!("zrc: cannot read {}: errno {}", cfg_path, e);
        1
    })?;
    let v = json::parse(&cfg).map_err(|e| {
        eprintln!("zrc: config.json parse error at byte {}: {}", e.at, e.msg);
        1
    })?;
    Spec::from_json(&v).map_err(|e| {
        eprintln!("zrc: invalid config: {}", e);
        1
    })
}

fn ns_flags(spec: &Spec) -> (usize, bool) {
    let mut flags = 0usize;
    for ns in &spec.namespaces {
        // The cgroup namespace is created later, by the child via unshare, so
        // that its root is the leaf cgroup the child has by then been moved into.
        if ns.typ == "cgroup" {
            continue;
        }
        flags |= ns.clone_flag();
    }
    (flags, flags & sys::CLONE_NEWNS != 0)
}

/// Relative cgroup path under the cgroup2 root. Honors `linux.cgroupsPath` when
/// it's a plain path; systemd-style `slice:prefix:name` isn't supported yet, so
/// we fall back to a derived `/zrc/<id>`.
fn cgroup_path(spec: &Spec, id: &str) -> String {
    match &spec.cgroups_path {
        Some(p) if p.starts_with('/') && !p.contains(':') => p.clone(),
        Some(p) if !p.is_empty() && !p.contains(':') => format!("/{}", p),
        _ => format!("/zrc/{}", id),
    }
}

// ---- parent→child "prep" handshake (id maps + cgroup placement) ----
//
// When a userns or cgroup ns is in play, the child must pause after clone until
// the parent has (a) written its uid/gid maps and (b) moved it into its leaf
// cgroup. The parent signals readiness over a pipe; the child then unshares the
// cgroup namespace so its root is that leaf.

/// Create the prep pipe iff the parent has prep work the child must await.
fn open_prep_pipe(spec: &Spec) -> Result<Option<(usize, usize)>, i32> {
    if !spec.has_user_ns() && !spec.has_cgroup_ns() {
        return Ok(None);
    }
    match sys::pipe2(sys::O_CLOEXEC) {
        Ok(p) => Ok(Some(p)),
        Err(e) => {
            eprintln!("zrc: pipe2 (prep) failed: errno {}", e);
            Err(1)
        }
    }
}

/// Child side: await the parent's "prepared" byte, then enter the cgroup ns.
fn child_prep(spec: &Spec, prep: Option<(usize, usize)>) -> bool {
    if let Some((r, w)) = prep {
        let _ = sys::close(w);
        let mut b = [0u8; 1];
        let ok = sys::read_full(r, &mut b).unwrap_or(0) == 1 && b[0] == 0;
        let _ = sys::close(r);
        if !ok {
            return false;
        }
    }
    if spec.has_cgroup_ns() {
        // We are now inside our leaf cgroup; make it the cgroup-ns root.
        let _ = sys::unshare(sys::CLONE_NEWCGROUP);
    }
    true
}

/// Parent side: write id maps, place the child in its cgroup, then signal. On
/// failure the write end closes without a byte, so the child sees EOF and bails.
fn parent_prep(
    pid: i32,
    spec: &Spec,
    cg: &str,
    prep: Option<(usize, usize)>,
) -> Result<(), &'static str> {
    let do_work = || -> Result<(), &'static str> {
        if spec.has_user_ns() {
            write_id_maps(pid, spec)?;
        }
        if !spec.resources.is_empty() || spec.has_cgroup_ns() {
            cgroup::setup(cg, pid, &spec.resources);
        }
        Ok(())
    };

    match prep {
        None => do_work(),
        Some((r, w)) => {
            let _ = sys::close(r);
            let res = do_work();
            if res.is_ok() {
                let _ = sys::write_all(w, &[0]);
            }
            let _ = sys::close(w);
            res
        }
    }
}

/// Whether this container gets a dedicated cgroup (for limits and/or a cgroup
/// ns root) — used to decide if `delete` should reap the cgroup directory.
fn uses_cgroup(spec: &Spec) -> bool {
    !spec.resources.is_empty() || spec.has_cgroup_ns()
}

/// Write `/proc/<pid>/{uid_map,gid_map}` (and `setgroups=deny` if the kernel
/// demands it). With no mappings in the spec we default to mapping container
/// root to the caller's own uid/gid (size 1) — the minimal rootless mapping.
fn write_id_maps(pid: i32, spec: &Spec) -> Result<(), &'static str> {
    let uid_maps = if spec.uid_mappings.is_empty() {
        alloc::vec![IdMap { container_id: 0, host_id: sys::getuid(), size: 1 }]
    } else {
        spec.uid_mappings.clone()
    };
    let gid_maps = if spec.gid_mappings.is_empty() {
        alloc::vec![IdMap { container_id: 0, host_id: sys::getgid(), size: 1 }]
    } else {
        spec.gid_mappings.clone()
    };

    let upath = format!("/proc/{}/uid_map", pid);
    sys::write_file(&upath, format_maps(&uid_maps).as_bytes(), 0).map_err(|_| "uid_map")?;

    let gpath = format!("/proc/{}/gid_map", pid);
    let gdata = format_maps(&gid_maps);
    match sys::write_file(&gpath, gdata.as_bytes(), 0) {
        Ok(()) => {}
        Err(1) => {
            // EPERM: unprivileged writers must disable setgroups first.
            let _ = sys::write_file(&format!("/proc/{}/setgroups", pid), b"deny", 0);
            sys::write_file(&gpath, gdata.as_bytes(), 0).map_err(|_| "gid_map")?;
        }
        Err(_) => return Err("gid_map"),
    }
    Ok(())
}

fn format_maps(maps: &[IdMap]) -> String {
    let mut s = String::new();
    for m in maps {
        s.push_str(&format!("{} {} {}\n", m.container_id, m.host_id, m.size));
    }
    s
}

fn reap(pid: i32) -> i32 {
    loop {
        match sys::wait4(pid, 0) {
            Ok((_, status)) => return sys::exit_code_from_status(status),
            Err(4) => continue,
            Err(e) => {
                eprintln!("zrc: wait4 failed: errno {}", e);
                return 1;
            }
        }
    }
}

/// A pid is "alive" if `kill(pid, 0)` succeeds or fails with EPERM (exists but
/// not ours); ESRCH means it's gone.
fn pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    match sys::kill(pid, 0) {
        Ok(_) => {}
        Err(1) => return true,  // EPERM: exists, not ours
        Err(_) => return false, // ESRCH etc.
    }
    // Exists in the table — but a reaped-by-nobody process lingers as a zombie,
    // which is logically "stopped". (With containerd's subreaper shim the init
    // is reaped instantly and we never reach here.)
    !is_zombie(pid)
}

/// Parse `/proc/<pid>/stat` state field. The third field is the state char,
/// sitting just past the last ')' (comm may itself contain parens/spaces).
fn is_zombie(pid: i32) -> bool {
    let path = format!("/proc/{}/stat", pid);
    if let Ok(buf) = sys::read_file(&path) {
        if let Some(rp) = buf.iter().rposition(|&c| c == b')') {
            return buf.get(rp + 2) == Some(&b'Z');
        }
    }
    false
}

fn cleanup_state(root: &str, id: &str) {
    let dir = crate::state::state_dir(root, id);
    let _ = sys::unlink(&format!("{}/exec.fifo", dir));
    let _ = sys::unlink(&format!("{}/state.json", dir));
    let _ = sys::rmdir(&dir);
}

fn parse_signal(s: &str) -> Option<i32> {
    if let Ok(n) = parse_i32(s) {
        return Some(n);
    }
    let name = s.strip_prefix("SIG").unwrap_or(s);
    let n = match name {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "ILL" => 4,
        "ABRT" => 6,
        "KILL" => 9,
        "USR1" => 10,
        "SEGV" => 11,
        "USR2" => 12,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        "CONT" => 18,
        "STOP" => 19,
        "TSTP" => 20,
        _ => return None,
    };
    Some(n)
}

fn parse_i32(s: &str) -> Result<i32, ()> {
    if s.is_empty() {
        return Err(());
    }
    let b = s.as_bytes();
    let (neg, digits) = if b[0] == b'-' { (true, &b[1..]) } else { (false, b) };
    if digits.is_empty() {
        return Err(());
    }
    let mut v: i32 = 0;
    for &c in digits {
        if !c.is_ascii_digit() {
            return Err(());
        }
        v = v.checked_mul(10).ok_or(())?.checked_add((c - b'0') as i32).ok_or(())?;
    }
    Ok(if neg { -v } else { v })
}

fn find_program(prog: &str, env: &[String]) -> Option<Vec<u8>> {
    if prog.contains('/') {
        return Some(sys::cstr(prog));
    }
    let path = env
        .iter()
        .find_map(|e| e.strip_prefix("PATH="))
        .unwrap_or(DEFAULT_PATH);
    for dir in path.split(':') {
        if dir.is_empty() {
            continue;
        }
        let cand = join(dir, prog);
        if exists(&cand) {
            return Some(sys::cstr(&cand));
        }
    }
    None
}

fn exists(path: &str) -> bool {
    match sys::openat(sys::AT_FDCWD, path, sys::O_RDONLY | sys::O_CLOEXEC, 0) {
        Ok(fd) => {
            let _ = sys::close(fd);
            true
        }
        Err(_) => false,
    }
}

fn join(base: &str, rel: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), rel.trim_start_matches('/'))
}

fn resolve(bundle: &str, root_path: &str) -> String {
    if root_path.starts_with('/') {
        String::from(root_path)
    } else {
        join(bundle, root_path)
    }
}

fn mkdir_p(path: &str) {
    let mut cur = String::new();
    for comp in path.split('/') {
        if comp.is_empty() {
            continue;
        }
        cur.push('/');
        cur.push_str(comp);
        let _ = sys::mkdir_p1(&cur, 0o755);
    }
}
