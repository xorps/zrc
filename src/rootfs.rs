//! The container's filesystem, built with the file-descriptor mount API.
//!
//! Every mount is created detached, given its attributes (so a read-only
//! bind is never writable, not even briefly), and attached to a target that
//! was resolved inside the rootfs with `RESOLVE_IN_ROOT`: a symlink in the
//! image cannot redirect a mount onto the host.

use core::ffi::CStr;

use xorpio::Errno;
use xorpio::fs::{self, OpenHow, resolve};
use xorpio::io::Fd;
use xorpio::mount::{self as mnt, MountAttr, attr, fsconfig};
use xorpio::ns;

use crate::init::{At, Fail, NONE, Step};
use crate::oci::{MAX_DEVICES, MAX_MOUNTS, MAX_PATHS, Mount, MountKind, Spec};
use crate::path::{self, Leaf};

/// Paths, not fds: an fd opened before the init got its own mount
/// namespace points into the host's, and mounts there cannot be cloned.
pub struct Ctx<'a> {
    pub spec: &'static Spec,
    /// The bundle directory, which relative paths are resolved against.
    pub bundle: &'a CStr,
    /// The container's leaf cgroup, relative to the cgroup root.
    pub cgroup: &'a CStr,
}

/// Device nodes every container gets when it has its own `/dev`, bound from
/// the host's (which also works in a user namespace, where mknod does not).
pub const DEFAULT_DEVICES: [&CStr; 6] = [
    c"/dev/null",
    c"/dev/zero",
    c"/dev/full",
    c"/dev/random",
    c"/dev/urandom",
    c"/dev/tty",
];

/// `(name in /dev, target)`.
pub const DEV_SYMLINKS: [(&CStr, &CStr); 5] = [
    (c"fd", c"/proc/self/fd"),
    (c"stdin", c"/proc/self/fd/0"),
    (c"stdout", c"/proc/self/fd/1"),
    (c"stderr", c"/proc/self/fd/2"),
    (c"ptmx", c"pts/ptmx"),
];

/// Lookups inside the rootfs treat it as `/`.
const IN_ROOT: u64 = resolve::IN_ROOT | resolve::NO_MAGICLINKS;

const CLONE: u32 = mnt::OPEN_TREE_CLONE | mnt::OPEN_TREE_CLOEXEC;
const ATTACH: u32 = mnt::MOVE_MOUNT_F_EMPTY_PATH | mnt::MOVE_MOUNT_T_EMPTY_PATH;

fn recursive(r: bool) -> u32 {
    if r { fs::AT_RECURSIVE } else { 0 }
}

fn setattr(tree: &Fd, flags: u32, set: u64, clr: u64, propagation: u64) -> Result<(), Errno> {
    let a = MountAttr {
        attr_set: set,
        attr_clr: clr,
        propagation,
        userns_fd: 0,
    };
    mnt::mount_setattr(tree, fs::EMPTY, fs::AT_EMPTY_PATH | flags, &a)
}

/// Opens `path` inside the rootfs if it exists.
fn find(root: &Fd, path: &CStr) -> Result<Option<Fd>, Errno> {
    let how = OpenHow {
        flags: u64::from(fs::O_PATH | fs::O_CLOEXEC),
        mode: 0,
        resolve: IN_ROOT,
    };
    match fs::openat2(root, path, &how) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Opens `path` inside the rootfs, creating it and its parents if missing.
fn target(root: &Fd, path: &CStr, leaf: Leaf) -> Result<Fd, Errno> {
    path::open_or_create(root, path, leaf, fs::O_PATH, IN_ROOT, 0o755)
}

/// Attaches the detached mount `tree` at `dest` inside the rootfs.
fn attach(root: &Fd, tree: &Fd, dest: &CStr) -> Result<(), Errno> {
    let leaf = if fs::statx(tree, fs::EMPTY, fs::AT_EMPTY_PATH)?.is_dir() {
        Leaf::Dir
    } else {
        Leaf::File
    };
    let to = target(root, dest, leaf)?;
    mnt::move_mount(tree, fs::EMPTY, &to, fs::EMPTY, ATTACH)
}

/// Clones the host path `path` as a detached mount.
fn host_tree(path: &CStr) -> Result<Fd, Errno> {
    mnt::open_tree(&fs::CWD, path, CLONE)
}

/// Everything the container takes from the host, opened while the init
/// still has the host's identity: as the root of a new user namespace it
/// may lack permission to reach these paths at all.
pub struct Sources {
    root: Fd,
    /// Detached trees of bind (and cgroup bind) mounts, by mount index.
    mounts: [Option<Fd>; MAX_MOUNTS],
    default_devices: [Option<Fd>; DEFAULT_DEVICES.len()],
    /// Host devices to bind, in a user namespace (by device index).
    devices: [Option<Fd>; MAX_DEVICES],
    /// A `/dev/null` for each masked path that turns out to be a file.
    nulls: [Option<Fd>; MAX_PATHS],
}

fn has_dev_mount(spec: &Spec) -> bool {
    spec.mounts
        .iter()
        .any(|m| m.destination.to_bytes() == b"/dev")
}

/// The first phase: binds the rootfs onto itself (pivot_root needs a mount)
/// and opens every host-side source as a detached mount.
pub fn prepare(ctx: &Ctx<'_>) -> Result<Sources, Fail> {
    let spec = ctx.spec;
    // Mount events must not propagate from the container to the host;
    // without a setting the tree becomes a recursive slave, as with runc.
    let propagation = match spec.rootfs_propagation {
        0 => mnt::MS_SLAVE | mnt::MS_REC,
        p => p,
    };
    mnt::mount(None, c"/", None, mnt::MS_REC | propagation, None).at(Step::RootPropagation)?;

    let bundle = fs::openat(
        &fs::CWD,
        ctx.bundle,
        fs::O_PATH | fs::O_DIRECTORY | fs::O_CLOEXEC,
        0,
    )
    .at(Step::OpenRootfs)?;
    let root_path = spec.root.ok_or(Errno::EINVAL).at(Step::BindRootfs)?;
    let tree = mnt::open_tree(&bundle, root_path, CLONE | fs::AT_RECURSIVE).at(Step::BindRootfs)?;
    mnt::move_mount(
        &tree,
        fs::EMPTY,
        &bundle,
        root_path,
        mnt::MOVE_MOUNT_F_EMPTY_PATH,
    )
    .at(Step::BindRootfs)?;
    drop(tree);
    let root = fs::openat(
        &bundle,
        root_path,
        fs::O_PATH | fs::O_DIRECTORY | fs::O_CLOEXEC,
        0,
    )
    .at(Step::OpenRootfs)?;

    let mut src = Sources {
        root,
        mounts: [const { None }; MAX_MOUNTS],
        default_devices: [const { None }; DEFAULT_DEVICES.len()],
        devices: [const { None }; MAX_DEVICES],
        nulls: [const { None }; MAX_PATHS],
    };
    for ((i, m), slot) in spec.mounts.iter().enumerate().zip(src.mounts.iter_mut()) {
        let at = |errno| Fail {
            step: Step::MountSource,
            index: i as u32,
            sub: NONE,
            errno,
        };
        *slot = match m.kind {
            MountKind::Bind { recursive: rec } => {
                let source = m.source.ok_or(Errno::EINVAL).map_err(at)?;
                Some(mnt::open_tree(&bundle, source, CLONE | recursive(rec)).map_err(at)?)
            }
            // Without its own cgroup namespace a fresh cgroup2 mount would
            // show the host's whole hierarchy; bind the container's cgroup.
            MountKind::New if is_cgroup(m) && !spec.namespaces.has(ns::NEWCGROUP) => {
                let cgroups = fs::openat(
                    &fs::CWD,
                    crate::cgroup::ROOT,
                    fs::O_PATH | fs::O_DIRECTORY | fs::O_CLOEXEC,
                    0,
                )
                .map_err(at)?;
                Some(
                    mnt::open_tree(&cgroups, crate::cgroup::relative(ctx.cgroup), CLONE)
                        .map_err(at)?,
                )
            }
            // sysfs can only be mounted with privilege over the network
            // namespace; in a user namespace without its own, bind the
            // host's instead, as runc does.
            MountKind::New
                if m.fstype.is_some_and(|t| t.to_bytes() == b"sysfs")
                    && spec.namespaces.has(ns::NEWUSER)
                    && spec.namespaces.new & ns::NEWNET == 0 =>
            {
                Some(mnt::open_tree(&fs::CWD, c"/sys", CLONE | fs::AT_RECURSIVE).map_err(at)?)
            }
            MountKind::New => None,
        };
    }
    if has_dev_mount(spec) {
        for ((i, dev), slot) in DEFAULT_DEVICES
            .iter()
            .enumerate()
            .zip(src.default_devices.iter_mut())
        {
            if !spec
                .devices
                .iter()
                .any(|d| d.path.to_bytes() == dev.to_bytes())
            {
                *slot = Some(host_tree(dev).at_item(Step::DefaultDevice, i, NONE)?);
            }
        }
    }
    if spec.namespaces.has(ns::NEWUSER) {
        // In a user namespace device nodes cannot be created, only bound.
        for ((i, d), slot) in spec.devices.iter().enumerate().zip(src.devices.iter_mut()) {
            *slot = Some(host_tree(d.path).at_item(Step::Device, i, NONE)?);
        }
    }
    for (i, slot) in src
        .nulls
        .iter_mut()
        .take(spec.masked_paths.len())
        .enumerate()
    {
        *slot = Some(host_tree(c"/dev/null").at_item(Step::MaskPath, i, NONE)?);
    }
    Ok(src)
}

/// The second phase: mounts, devices, masks, hostname, and the pivot.
pub fn build(ctx: &Ctx<'_>, src: &mut Sources) -> Result<(), Fail> {
    let spec = ctx.spec;
    let root = &src.root;

    for ((i, m), tree) in spec.mounts.iter().enumerate().zip(src.mounts.iter_mut()) {
        mount_one(spec, root, i, m, tree.take())?;
    }

    if has_dev_mount(spec) {
        for (i, tree) in src.default_devices.iter().enumerate() {
            if let (Some(tree), Some(dev)) = (tree, DEFAULT_DEVICES.get(i)) {
                attach(root, tree, dev).at_item(Step::DefaultDevice, i, NONE)?;
            }
        }
        let dev = target(root, c"/dev", Leaf::Dir).at(Step::DevSymlink)?;
        for (i, (name, to)) in DEV_SYMLINKS.iter().enumerate() {
            match fs::symlinkat(to, &dev, name) {
                Ok(()) | Err(Errno::EEXIST) => {}
                Err(e) => return Err(e).at_item(Step::DevSymlink, i, NONE),
            }
        }
    }
    for ((i, d), tree) in spec.devices.iter().enumerate().zip(src.devices.iter()) {
        if let Some(tree) = tree {
            attach(root, tree, d.path).at_item(Step::Device, i, NONE)?;
            continue;
        }
        let dev = fs::makedev(d.major, d.minor)
            .ok_or(Errno::EOVERFLOW)
            .at_item(Step::Device, i, NONE)?;
        let mode = d.kind | d.mode.unwrap_or(0o666);
        let node = target(root, d.path, Leaf::Node { mode, dev }).at_item(Step::Device, i, NONE)?;
        if d.uid.is_some() || d.gid.is_some() {
            // -1 leaves an id unchanged.
            let uid = d.uid.unwrap_or(u32::MAX);
            let gid = d.gid.unwrap_or(u32::MAX);
            fs::fchownat(&node, fs::EMPTY, uid, gid, fs::AT_EMPTY_PATH).at_item(
                Step::Device,
                i,
                NONE,
            )?;
        }
    }

    // Before masks and read-only paths: /proc/sys is usually one of those.
    if !spec.sysctls.is_empty() {
        let how = OpenHow {
            flags: u64::from(fs::O_PATH | fs::O_DIRECTORY | fs::O_CLOEXEC),
            mode: 0,
            resolve: IN_ROOT,
        };
        let sys = fs::openat2(root, c"/proc/sys", &how).at_item(Step::Sysctl, 0, NONE)?;
        for (i, s) in spec.sysctls.iter().enumerate() {
            write_sysctl(&sys, s.path, s.value).at_item(Step::Sysctl, i, NONE)?;
        }
    }

    for ((i, path), null) in spec
        .masked_paths
        .iter()
        .enumerate()
        .zip(src.nulls.iter_mut())
    {
        mask(root, path, null.take()).at_item(Step::MaskPath, i, NONE)?;
    }
    for (i, path) in spec.readonly_paths.iter().enumerate() {
        make_readonly(root, path).at_item(Step::ReadonlyPath, i, NONE)?;
    }

    if let Some(h) = spec.hostname {
        ns::sethostname(h.to_bytes()).at(Step::Hostname)?;
    }
    if let Some(d) = spec.domainname {
        ns::setdomainname(d.to_bytes()).at(Step::Domainname)?;
    }

    // pivot_root(".", ".") stacks the old root on the new one; detaching
    // it (made a slave first, so the unmount stays in the container)
    // leaves the new root alone.
    fs::fchdir(root).at(Step::PivotRoot)?;
    mnt::pivot_root(c".", c".").at(Step::PivotRoot)?;
    mnt::mount(None, c".", None, mnt::MS_SLAVE | mnt::MS_REC, None).at(Step::DetachOldRoot)?;
    mnt::umount2(c".", mnt::MNT_DETACH).at(Step::DetachOldRoot)?;
    fs::chdir(c"/").at(Step::DetachOldRoot)?;

    if spec.root_readonly {
        let ro = MountAttr {
            attr_set: attr::RDONLY,
            ..MountAttr::default()
        };
        mnt::mount_setattr(&fs::CWD, c"/", 0, &ro).at(Step::RootReadonly)?;
    }
    Ok(())
}

fn is_cgroup(m: &Mount) -> bool {
    m.fstype
        .is_some_and(|t| matches!(t.to_bytes(), b"cgroup" | b"cgroup2"))
}

fn mount_one(spec: &Spec, root: &Fd, i: usize, m: &Mount, opened: Option<Fd>) -> Result<(), Fail> {
    let at = |step| {
        move |errno| Fail {
            step,
            index: i as u32,
            sub: NONE,
            errno,
        }
    };
    // Bind sources were opened by `prepare`; everything else is new.
    let fresh = opened.is_none();
    let tree = match opened {
        Some(tree) => tree,
        None => {
            let fstype = if is_cgroup(m) {
                Some(c"cgroup2")
            } else {
                m.fstype
            };
            let fstype = fstype.ok_or(Errno::EINVAL).map_err(at(Step::MountCreate))?;
            let fsfd = mnt::fsopen(fstype, mnt::FSOPEN_CLOEXEC).map_err(at(Step::MountCreate))?;
            if let Some(source) = m.source {
                mnt::fsconfig(
                    &fsfd,
                    fsconfig::SET_STRING,
                    Some(c"source"),
                    Some(source),
                    0,
                )
                .at_item(Step::MountOption, i, NONE)?;
            }
            for (j, opt) in spec.fs_opts(m).iter().enumerate() {
                let cmd = if opt.value.is_some() {
                    fsconfig::SET_STRING
                } else {
                    fsconfig::SET_FLAG
                };
                mnt::fsconfig(&fsfd, cmd, Some(opt.key), opt.value, 0).at_item(
                    Step::MountOption,
                    i,
                    j as u32,
                )?;
            }
            mnt::fsconfig(&fsfd, fsconfig::CMD_CREATE, None, None, 0)
                .map_err(at(Step::MountCreate))?;
            mnt::fsmount(&fsfd, mnt::FSMOUNT_CLOEXEC, m.attr_set).map_err(at(Step::MountCreate))?
        }
    };

    // A new filesystem got its attributes from fsmount.
    if !fresh && (m.attr_set | m.attr_clr) != 0 {
        setattr(&tree, 0, m.attr_set, m.attr_clr, 0).map_err(at(Step::MountAttr))?;
    }
    if (m.rec_attr_set | m.rec_attr_clr) != 0 {
        setattr(&tree, fs::AT_RECURSIVE, m.rec_attr_set, m.rec_attr_clr, 0)
            .map_err(at(Step::MountAttr))?;
    }

    let leaf = if fresh
        || fs::statx(&tree, fs::EMPTY, fs::AT_EMPTY_PATH)
            .map_err(at(Step::MountSource))?
            .is_dir()
    {
        Leaf::Dir
    } else {
        Leaf::File
    };
    let to = target(root, m.destination, leaf).map_err(at(Step::MountTarget))?;
    mnt::move_mount(&tree, fs::EMPTY, &to, fs::EMPTY, ATTACH).map_err(at(Step::MountAttach))?;
    if m.propagation != 0 {
        // `tree` now refers to the attached mount.
        setattr(&tree, recursive(m.propagation_rec), 0, 0, m.propagation)
            .map_err(at(Step::MountPropagation))?;
    }
    Ok(())
}

/// Hides `path`: an empty read-only tmpfs over a directory, `/dev/null`
/// over anything else. A path that does not exist needs no hiding.
fn mask(root: &Fd, path: &CStr, null: Option<Fd>) -> Result<(), Errno> {
    let Some(to) = find(root, path)? else {
        return Ok(());
    };
    let tree = if fs::statx(&to, fs::EMPTY, fs::AT_EMPTY_PATH)?.is_dir() {
        let fsfd = mnt::fsopen(c"tmpfs", mnt::FSOPEN_CLOEXEC)?;
        mnt::fsconfig(&fsfd, fsconfig::CMD_CREATE, None, None, 0)?;
        mnt::fsmount(&fsfd, mnt::FSMOUNT_CLOEXEC, attr::RDONLY)?
    } else {
        null.ok_or(Errno::EBADF)?
    };
    mnt::move_mount(&tree, fs::EMPTY, &to, fs::EMPTY, ATTACH)
}

/// Covers `path` with a read-only bind of itself. A path that does not
/// exist has nothing to protect.
fn make_readonly(root: &Fd, path: &CStr) -> Result<(), Errno> {
    let Some(to) = find(root, path)? else {
        return Ok(());
    };
    let tree = mnt::open_tree(&to, fs::EMPTY, CLONE | fs::AT_EMPTY_PATH | fs::AT_RECURSIVE)?;
    setattr(&tree, fs::AT_RECURSIVE, attr::RDONLY, 0, 0)?;
    mnt::move_mount(&tree, fs::EMPTY, &to, fs::EMPTY, ATTACH)
}

/// Writes `value` to `path` below the container's `/proc/sys`.
fn write_sysctl(sys: &Fd, path: &CStr, value: &CStr) -> Result<(), Errno> {
    let how = OpenHow {
        flags: u64::from(fs::O_WRONLY | fs::O_CLOEXEC),
        mode: 0,
        resolve: resolve::BENEATH | resolve::NO_SYMLINKS | resolve::NO_XDEV,
    };
    let f = fs::openat2(sys, path, &how)?;
    let value = value.to_bytes();
    if f.write(value)? != value.len() {
        return Err(Errno::EIO);
    }
    f.close()
}
