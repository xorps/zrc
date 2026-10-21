//! The OCI runtime spec (`config.json`), decoded in one pass straight into
//! the forms the kernel takes: capability masks, `MOUNT_ATTR_*` flags,
//! namespace flags, a compiled seccomp program. Strings borrow the config
//! buffer (see [`json`](crate::json)), so nothing is copied.
//!
//! Fields zrc does not implement are an error when set, never silently
//! dropped; only fields for other platforms and informational ones are
//! skipped.

use core::ffi::CStr;

use xorpio::fs;
use xorpio::mount::{self, attr};
use xorpio::ns;
use xorpio::process::Rlimit;

use crate::caps;
use crate::fixed::{Fixed, Full};
use crate::io::{Msg, Report};
use crate::json::{self, Parser};
use crate::seccomp;

pub type Str = &'static CStr;

/// `UID_GID_MAP_MAX_EXTENTS`.
pub const MAX_ID_MAPS: usize = 340;
/// `NGROUPS_MAX`.
pub const MAX_GROUPS: usize = 65536;
/// `RLIM_NLIMITS`.
pub const MAX_RLIMITS: usize = 16;
pub const MAX_ARGS: usize = 4096;
pub const MAX_ENV: usize = 16384;
pub const MAX_MOUNTS: usize = 512;
pub const MAX_FS_OPTS: usize = 2048;
pub const MAX_DEVICES: usize = 1024;
pub const MAX_DEVICE_RULES: usize = 1024;
pub const MAX_PATHS: usize = 128;
pub const MAX_SYSCTLS: usize = 256;
pub const MAX_CGROUP_FILES: usize = 128;
pub const MAX_HUGEPAGES: usize = 8;

#[derive(Clone, Copy, Debug)]
pub enum SpecError {
    Json(json::Error),
    /// A required field is absent.
    Missing(&'static str),
    TooMany {
        field: &'static str,
        max: usize,
    },
    /// A name the field does not accept, such as an unknown capability.
    Unknown {
        field: &'static str,
        value: Str,
    },
    Duplicate {
        field: &'static str,
        value: Str,
    },
    /// A malformed value, at this byte offset.
    Invalid {
        field: &'static str,
        at: usize,
    },
    /// A setting zrc does not implement.
    Unsupported(&'static str),
    Seccomp(seccomp::CompileError),
}

impl From<json::Error> for SpecError {
    fn from(e: json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<seccomp::CompileError> for SpecError {
    fn from(e: seccomp::CompileError) -> Self {
        Self::Seccomp(e)
    }
}

impl Report for SpecError {
    fn report<const N: usize>(&self, m: &mut Msg<N>) {
        match *self {
            Self::Json(e) => e.report(m),
            Self::Missing(field) => {
                m.str("missing ").str(field);
            }
            Self::TooMany { field, max } => {
                m.str("more than ")
                    .u64(max as u64)
                    .str(" entries in ")
                    .str(field);
            }
            Self::Unknown { field, value } => {
                m.str("unknown ").str(field).str(" '").cstr(value).str("'");
            }
            Self::Duplicate { field, value } => {
                m.str("duplicate ")
                    .str(field)
                    .str(" '")
                    .cstr(value)
                    .str("'");
            }
            Self::Invalid { field, at } => {
                m.str("invalid ").str(field).str(" at byte ").u64(at as u64);
            }
            Self::Unsupported(field) => {
                m.str(field).str(" is not supported");
            }
            Self::Seccomp(e) => {
                m.str("linux.seccomp: ");
                e.report(m);
            }
        }
    }
}

type Result<T> = core::result::Result<T, SpecError>;

fn push<T: Copy, const N: usize>(
    list: &mut Fixed<T, N>,
    item: T,
    field: &'static str,
) -> Result<()> {
    list.push(item)
        .map_err(|Full| SpecError::TooMany { field, max: N })
}

/// A spec as zrc applies it.
pub struct Spec {
    pub root: Option<Str>,
    pub root_readonly: bool,
    pub hostname: Option<Str>,
    pub domainname: Option<Str>,
    pub process: Process,
    pub mounts: Fixed<Mount, MAX_MOUNTS>,
    /// Filesystem options of all mounts; each [`Mount`] owns a range.
    pub fs_opts: Fixed<FsOpt, MAX_FS_OPTS>,
    pub namespaces: Namespaces,
    pub uid_maps: Fixed<IdMap, MAX_ID_MAPS>,
    pub gid_maps: Fixed<IdMap, MAX_ID_MAPS>,
    pub cgroups_path: Option<Str>,
    pub resources: Resources,
    pub devices: Fixed<Device, MAX_DEVICES>,
    pub masked_paths: Fixed<Str, MAX_PATHS>,
    pub readonly_paths: Fixed<Str, MAX_PATHS>,
    pub sysctls: Fixed<Sysctl, MAX_SYSCTLS>,
    /// `MS_*` propagation for the container's mount tree; 0 for the
    /// default, `rslave`. (Zero keeps this static in `.bss`.)
    pub rootfs_propagation: u64,
    pub seccomp: Option<seccomp::Program>,
    /// The `org.zrc.sysbox` annotation asks for a system container.
    pub sysbox: bool,
}

pub struct Process {
    pub args: Fixed<Str, MAX_ARGS>,
    pub env: Fixed<Str, MAX_ENV>,
    pub cwd: Option<Str>,
    pub uid: u32,
    pub gid: u32,
    pub umask: Option<u32>,
    pub additional_gids: Fixed<u32, MAX_GROUPS>,
    pub no_new_privileges: bool,
    pub capabilities: Option<caps::Sets>,
    pub rlimits: Fixed<(u32, Rlimit), MAX_RLIMITS>,
    pub oom_score_adj: Option<i64>,
    pub apparmor_profile: Option<Str>,
    pub selinux_label: Option<Str>,
}

#[derive(Clone, Copy)]
pub struct Mount {
    pub destination: Str,
    pub source: Option<Str>,
    pub fstype: Option<Str>,
    pub kind: MountKind,
    /// `MOUNT_ATTR_*` to set and clear on this mount alone...
    pub attr_set: u64,
    pub attr_clr: u64,
    /// ...and on it and every mount below it (the `r*` options).
    pub rec_attr_set: u64,
    pub rec_attr_clr: u64,
    /// `MS_*` propagation, applied recursively if `propagation_rec`.
    pub propagation: u64,
    pub propagation_rec: bool,
    /// This mount's range of [`Spec::fs_opts`].
    pub fs_opts: (u16, u16),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MountKind {
    Bind {
        recursive: bool,
    },
    /// A new filesystem of `fstype`.
    New,
}

/// A filesystem option for `fsconfig`: `key=value`, or a flag.
#[derive(Clone, Copy)]
pub struct FsOpt {
    pub key: Str,
    pub value: Option<Str>,
}

#[derive(Clone, Copy)]
pub struct IdMap {
    pub container: u32,
    pub host: u32,
    pub size: u32,
}

/// Which namespaces to create, and which existing ones to join.
pub struct Namespaces {
    /// `CLONE_NEW*` flags of the namespaces to create.
    pub new: u64,
    /// `(CLONE_NEW* flag, path)` of the namespaces to join.
    pub join: Fixed<(u64, Str), 8>,
}

impl Namespaces {
    /// Whether the container has its own namespace of this type, new or joined.
    pub fn has(&self, flag: u64) -> bool {
        self.new & flag != 0 || self.join.iter().any(|&(f, _)| f == flag)
    }
}

pub struct Resources {
    pub memory_limit: Option<i64>,
    pub memory_reservation: Option<i64>,
    /// Memory plus swap, as OCI defines it.
    pub memory_swap: Option<i64>,
    pub cpu_shares: Option<u64>,
    pub cpu_quota: Option<i64>,
    pub cpu_period: Option<u64>,
    pub cpu_burst: Option<u64>,
    pub cpu_idle: Option<i64>,
    pub cpus: Option<Str>,
    pub mems: Option<Str>,
    pub pids_limit: Option<i64>,
    /// `(page size, limit)`, e.g. `("2MB", 0)`.
    pub hugepages: Fixed<(Str, u64), MAX_HUGEPAGES>,
    /// Raw cgroup v2 files to write: `(file name, value)`.
    pub unified: Fixed<(Str, Str), MAX_CGROUP_FILES>,
    /// Device access rules; anything they and the defaults do not allow is
    /// denied (see `cgroup::DEFAULT_RULES`).
    pub devices: Fixed<DeviceRule, MAX_DEVICE_RULES>,
}

/// A `linux.resources.devices` rule. Later rules take precedence.
#[derive(Clone, Copy)]
pub struct DeviceRule {
    pub allow: bool,
    /// `b'a'` (all), `b'c'` or `b'b'`.
    pub kind: u8,
    pub major: Option<u32>,
    pub minor: Option<u32>,
    /// `BPF_DEVCG_ACC_*` bits: 1 mknod, 2 read, 4 write.
    pub access: u32,
}

/// A device node to create in the container.
#[derive(Clone, Copy)]
pub struct Device {
    pub path: Str,
    /// `S_IFCHR`, `S_IFBLK` or `S_IFIFO`.
    pub kind: u32,
    pub major: u32,
    pub minor: u32,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

#[derive(Clone, Copy)]
pub struct Sysctl {
    /// The path below `/proc/sys`: the key with `.` replaced by `/`.
    pub path: Str,
    pub value: Str,
}

impl Spec {
    pub const fn new() -> Self {
        Self {
            root: None,
            root_readonly: false,
            hostname: None,
            domainname: None,
            process: Process {
                args: Fixed::new(),
                env: Fixed::new(),
                cwd: None,
                uid: 0,
                gid: 0,
                umask: None,
                additional_gids: Fixed::new(),
                no_new_privileges: false,
                capabilities: None,
                rlimits: Fixed::new(),
                oom_score_adj: None,
                apparmor_profile: None,
                selinux_label: None,
            },
            mounts: Fixed::new(),
            fs_opts: Fixed::new(),
            namespaces: Namespaces {
                new: 0,
                join: Fixed::new(),
            },
            uid_maps: Fixed::new(),
            gid_maps: Fixed::new(),
            cgroups_path: None,
            resources: Resources {
                memory_limit: None,
                memory_reservation: None,
                memory_swap: None,
                cpu_shares: None,
                cpu_quota: None,
                cpu_period: None,
                cpu_burst: None,
                cpu_idle: None,
                cpus: None,
                mems: None,
                pids_limit: None,
                hugepages: Fixed::new(),
                unified: Fixed::new(),
                devices: Fixed::new(),
            },
            devices: Fixed::new(),
            masked_paths: Fixed::new(),
            readonly_paths: Fixed::new(),
            sysctls: Fixed::new(),
            rootfs_propagation: 0,
            seccomp: None,
            sysbox: false,
        }
    }

    /// The filesystem options of `m`.
    pub fn fs_opts(&self, m: &Mount) -> &[FsOpt] {
        let (start, len) = (m.fs_opts.0 as usize, m.fs_opts.1 as usize);
        self.fs_opts
            .as_slice()
            .get(start..start + len)
            .unwrap_or_default()
    }

    /// Decodes `buf` into `self`, which must be fresh from [`Spec::new`].
    pub fn parse(&mut self, buf: &'static mut [u8]) -> Result<()> {
        let mut p = Parser::new(buf);
        let mut o = p.object()?;
        while let Some(key) = o.next(&mut p)? {
            match key.to_bytes() {
                b"root" => self.parse_root(&mut p)?,
                b"process" => self.parse_process(&mut p)?,
                b"hostname" => self.hostname = Some(p.str()?),
                b"domainname" => self.domainname = Some(p.str()?),
                b"mounts" => self.parse_mounts(&mut p)?,
                b"linux" => self.parse_linux(&mut p)?,
                b"annotations" => self.parse_annotations(&mut p)?,
                b"hooks" => require_empty(&mut p, "hooks")?,
                // Version, and sections for other platforms.
                _ => p.skip()?,
            }
        }
        p.end()?;
        if self.root.is_none() {
            return Err(SpecError::Missing("root.path"));
        }
        if self.process.args.is_empty() {
            return Err(SpecError::Missing("process.args"));
        }
        Ok(())
    }

    /// Checks settings that depend on each other, once the spec is final.
    pub fn validate(&self) -> Result<()> {
        let ns = &self.namespaces;
        if ns.new & ns::NEWNS == 0 {
            // Without its own mount namespace the container would mount
            // over the host.
            return Err(SpecError::Missing("a new mount namespace"));
        }
        if (self.hostname.is_some() || self.domainname.is_some()) && !ns.has(ns::NEWUTS) {
            // It would rename the host.
            return Err(SpecError::Missing(
                "a uts namespace for hostname/domainname",
            ));
        }
        if ns.new & ns::NEWUSER != 0 {
            if self.uid_maps.is_empty() {
                return Err(SpecError::Missing(
                    "linux.uidMappings for the new user namespace",
                ));
            }
            if self.gid_maps.is_empty() {
                return Err(SpecError::Missing(
                    "linux.gidMappings for the new user namespace",
                ));
            }
        } else if !self.uid_maps.is_empty() || !self.gid_maps.is_empty() {
            return Err(SpecError::Missing(
                "a new user namespace for linux.uidMappings",
            ));
        }
        if let Some(c) = &self.process.capabilities {
            // The kernel only raises ambient capabilities that are both
            // permitted and inheritable (runc warns and skips the rest).
            if c.ambient & !(c.permitted & c.inheritable) != 0 {
                return Err(SpecError::Missing(
                    "process.capabilities.ambient entries in permitted and inheritable",
                ));
            }
        }
        for m in &self.mounts {
            if matches!(m.kind, MountKind::Bind { .. }) && m.source.is_none() {
                return Err(SpecError::Missing("mounts[].source of a bind mount"));
            }
        }
        Ok(())
    }

    fn parse_root(&mut self, p: &mut Parser<'static>) -> Result<()> {
        let mut o = p.object()?;
        while let Some(key) = o.next(p)? {
            match key.to_bytes() {
                b"path" => self.root = Some(p.str()?),
                b"readonly" => self.root_readonly = p.bool()?,
                _ => p.skip()?,
            }
        }
        Ok(())
    }

    fn parse_process(&mut self, p: &mut Parser<'static>) -> Result<()> {
        let proc = &mut self.process;
        let mut o = p.object()?;
        while let Some(key) = o.next(p)? {
            match key.to_bytes() {
                b"args" => str_list(p, &mut proc.args, "process.args")?,
                b"env" => str_list(p, &mut proc.env, "process.env")?,
                b"cwd" => proc.cwd = Some(p.str()?),
                b"terminal" => {
                    if p.bool()? {
                        return Err(SpecError::Unsupported("process.terminal"));
                    }
                }
                b"user" => {
                    let mut u = p.object()?;
                    while let Some(key) = u.next(p)? {
                        match key.to_bytes() {
                            b"uid" => proc.uid = p.u32()?,
                            b"gid" => proc.gid = p.u32()?,
                            b"umask" => proc.umask = Some(p.u32()?),
                            b"additionalGids" => {
                                proc.additional_gids.clear();
                                let mut a = p.array()?;
                                while a.next(p)? {
                                    let gid = p.u32()?;
                                    push(
                                        &mut proc.additional_gids,
                                        gid,
                                        "process.user.additionalGids",
                                    )?;
                                }
                            }
                            _ => p.skip()?,
                        }
                    }
                }
                b"noNewPrivileges" => proc.no_new_privileges = p.bool()?,
                b"capabilities" => proc.capabilities = Some(caps::parse(p)?),
                b"rlimits" => parse_rlimits(p, &mut proc.rlimits)?,
                b"oomScoreAdj" => proc.oom_score_adj = Some(p.i64()?),
                b"apparmorProfile" => proc.apparmor_profile = Some(p.str()?),
                b"selinuxLabel" => proc.selinux_label = Some(p.str()?),
                b"scheduler" => require_empty(p, "process.scheduler")?,
                b"ioPriority" => require_empty(p, "process.ioPriority")?,
                b"execCPUAffinity" => require_empty(p, "process.execCPUAffinity")?,
                _ => p.skip()?,
            }
        }
        Ok(())
    }

    fn parse_mounts(&mut self, p: &mut Parser<'static>) -> Result<()> {
        self.mounts.clear();
        self.fs_opts.clear();
        let mut a = p.array()?;
        while a.next(p)? {
            let m = parse_mount(p, &mut self.fs_opts)?;
            push(&mut self.mounts, m, "mounts")?;
        }
        Ok(())
    }

    fn parse_linux(&mut self, p: &mut Parser<'static>) -> Result<()> {
        let mut o = p.object()?;
        while let Some(key) = o.next(p)? {
            match key.to_bytes() {
                b"namespaces" => parse_namespaces(p, &mut self.namespaces)?,
                b"uidMappings" => parse_id_maps(p, &mut self.uid_maps, "linux.uidMappings")?,
                b"gidMappings" => parse_id_maps(p, &mut self.gid_maps, "linux.gidMappings")?,
                b"cgroupsPath" => self.cgroups_path = Some(p.str()?),
                b"resources" => parse_resources(p, &mut self.resources)?,
                b"devices" => parse_devices(p, &mut self.devices)?,
                b"maskedPaths" => str_list(p, &mut self.masked_paths, "linux.maskedPaths")?,
                b"readonlyPaths" => str_list(p, &mut self.readonly_paths, "linux.readonlyPaths")?,
                b"sysctl" => parse_sysctls(p, &mut self.sysctls)?,
                b"rootfsPropagation" => {
                    let at = p.offset();
                    let v = p.str()?;
                    self.rootfs_propagation = match propagation(v.to_bytes()) {
                        Some((mount::MS_SHARED, _)) => return Err(SpecError::Unsupported(SHARED)),
                        Some((flag, true)) => flag | mount::MS_REC,
                        Some((flag, false)) => flag,
                        None => {
                            return Err(SpecError::Invalid {
                                field: "linux.rootfsPropagation",
                                at,
                            });
                        }
                    };
                }
                b"seccomp" => seccomp::compile(p, self.seccomp.insert(seccomp::Program::new()))?,
                b"mountLabel" => return Err(SpecError::Unsupported("linux.mountLabel")),
                b"intelRdt" => require_empty(p, "linux.intelRdt")?,
                b"personality" => require_empty(p, "linux.personality")?,
                b"timeOffsets" => require_empty(p, "linux.timeOffsets")?,
                b"memoryPolicy" => require_empty(p, "linux.memoryPolicy")?,
                b"netDevices" => require_empty(p, "linux.netDevices")?,
                _ => p.skip()?,
            }
        }
        Ok(())
    }

    fn parse_annotations(&mut self, p: &mut Parser<'static>) -> Result<()> {
        let mut o = p.object()?;
        while let Some(key) = o.next(p)? {
            if key.to_bytes() != b"org.zrc.sysbox" {
                p.skip()?;
                continue;
            }
            let at = p.offset();
            self.sysbox = match p.str()?.to_bytes() {
                b"true" | b"1" => true,
                b"false" | b"0" => false,
                _ => {
                    return Err(SpecError::Invalid {
                        field: "annotation org.zrc.sysbox",
                        at,
                    });
                }
            };
        }
        Ok(())
    }
}

fn str_list<const N: usize>(
    p: &mut Parser<'static>,
    list: &mut Fixed<Str, N>,
    field: &'static str,
) -> Result<()> {
    // A repeated key replaces the earlier list, as in Go's encoding/json.
    list.clear();
    let mut a = p.array()?;
    while a.next(p)? {
        let s = p.str()?;
        push(list, s, field)?;
    }
    Ok(())
}

/// Accepts a value only if it sets nothing: `null`, `false`, `0`, `""`, or
/// arrays and objects of such values.
fn require_empty(p: &mut Parser<'static>, field: &'static str) -> Result<()> {
    fn empty(p: &mut Parser<'static>, field: &'static str, depth: u32) -> Result<()> {
        let unsupported = SpecError::Unsupported(field);
        if depth == 0 {
            return Err(unsupported);
        }
        match p.peek_token()? {
            b'{' => {
                let mut o = p.object()?;
                while o.next(p)?.is_some() {
                    empty(p, field, depth - 1)?;
                }
            }
            b'[' => {
                let mut a = p.array()?;
                while a.next(p)? {
                    empty(p, field, depth - 1)?;
                }
            }
            b'"' => {
                if !p.str()?.is_empty() {
                    return Err(unsupported);
                }
            }
            b't' | b'f' => {
                if p.bool()? {
                    return Err(unsupported);
                }
            }
            b'n' => {
                p.null()?;
            }
            _ => {
                if p.i64()? != 0 {
                    return Err(unsupported);
                }
            }
        }
        Ok(())
    }
    empty(p, field, 8)
}

fn parse_rlimits(
    p: &mut Parser<'static>,
    out: &mut Fixed<(u32, Rlimit), MAX_RLIMITS>,
) -> Result<()> {
    out.clear();
    let mut a = p.array()?;
    while a.next(p)? {
        let mut resource = None;
        let mut limit = Rlimit::default();
        let mut o = p.object()?;
        while let Some(key) = o.next(p)? {
            match key.to_bytes() {
                b"type" => {
                    let name = p.str()?;
                    let r = rlimit_resource(name.to_bytes()).ok_or(SpecError::Unknown {
                        field: "process.rlimits type",
                        value: name,
                    })?;
                    if out.iter().any(|&(have, _)| have == r) {
                        return Err(SpecError::Duplicate {
                            field: "process.rlimits type",
                            value: name,
                        });
                    }
                    resource = Some(r);
                }
                b"soft" => limit.cur = p.u64()?,
                b"hard" => limit.max = p.u64()?,
                _ => p.skip()?,
            }
        }
        let resource = resource.ok_or(SpecError::Missing("process.rlimits[].type"))?;
        push(out, (resource, limit), "process.rlimits")?;
    }
    Ok(())
}

/// `RLIMIT_*` numbers (asm-generic, shared by x86_64 and aarch64).
fn rlimit_resource(name: &[u8]) -> Option<u32> {
    Some(match name {
        b"RLIMIT_CPU" => 0,
        b"RLIMIT_FSIZE" => 1,
        b"RLIMIT_DATA" => 2,
        b"RLIMIT_STACK" => 3,
        b"RLIMIT_CORE" => 4,
        b"RLIMIT_RSS" => 5,
        b"RLIMIT_NPROC" => 6,
        b"RLIMIT_NOFILE" => 7,
        b"RLIMIT_MEMLOCK" => 8,
        b"RLIMIT_AS" => 9,
        b"RLIMIT_LOCKS" => 10,
        b"RLIMIT_SIGPENDING" => 11,
        b"RLIMIT_MSGQUEUE" => 12,
        b"RLIMIT_NICE" => 13,
        b"RLIMIT_RTPRIO" => 14,
        b"RLIMIT_RTTIME" => 15,
        _ => return None,
    })
}

/// Shared propagation needs the container's mounts to stay peers of the
/// host's, which the slave mount tree zrc builds does not give: refuse it
/// rather than silently not propagate.
const SHARED: &str = "shared mount propagation";

/// A propagation option: its `MS_*` flag and whether it is recursive.
fn propagation(opt: &[u8]) -> Option<(u64, bool)> {
    Some(match opt {
        b"private" => (mount::MS_PRIVATE, false),
        b"rprivate" => (mount::MS_PRIVATE, true),
        b"shared" => (mount::MS_SHARED, false),
        b"rshared" => (mount::MS_SHARED, true),
        b"slave" => (mount::MS_SLAVE, false),
        b"rslave" => (mount::MS_SLAVE, true),
        b"unbindable" => (mount::MS_UNBINDABLE, false),
        b"runbindable" => (mount::MS_UNBINDABLE, true),
        _ => return None,
    })
}

/// A mount attribute option: `(attr_set, attr_clr)`.
fn mount_attr(opt: &[u8]) -> Option<(u64, u64)> {
    Some(match opt {
        b"ro" => (attr::RDONLY, 0),
        b"rw" => (0, attr::RDONLY),
        b"nosuid" => (attr::NOSUID, 0),
        b"suid" => (0, attr::NOSUID),
        b"nodev" => (attr::NODEV, 0),
        b"dev" => (0, attr::NODEV),
        b"noexec" => (attr::NOEXEC, 0),
        b"exec" => (0, attr::NOEXEC),
        b"nosymfollow" => (attr::NOSYMFOLLOW, 0),
        b"symfollow" => (0, attr::NOSYMFOLLOW),
        b"nodiratime" => (attr::NODIRATIME, 0),
        b"diratime" => (0, attr::NODIRATIME),
        // The access-time mode is one field: clearing ATIME selects it.
        b"relatime" => (attr::RELATIME, attr::ATIME),
        b"noatime" => (attr::NOATIME, attr::ATIME),
        b"strictatime" => (attr::STRICTATIME, attr::ATIME),
        _ => return None,
    })
}

fn parse_mount(p: &mut Parser<'static>, fs_opts: &mut Fixed<FsOpt, MAX_FS_OPTS>) -> Result<Mount> {
    let mut m = Mount {
        destination: c"",
        source: None,
        fstype: None,
        kind: MountKind::New,
        attr_set: 0,
        attr_clr: 0,
        rec_attr_set: 0,
        rec_attr_clr: 0,
        propagation: 0,
        propagation_rec: false,
        fs_opts: (0, 0),
    };
    let mut destination = None;
    let start = fs_opts.len();
    let mut o = p.object()?;
    while let Some(key) = o.next(p)? {
        match key.to_bytes() {
            b"destination" => destination = Some(p.str()?),
            b"source" => m.source = Some(p.str()?),
            b"type" => m.fstype = Some(p.str()?),
            b"options" => {
                let mut a = p.array()?;
                while a.next(p)? {
                    let at = p.offset();
                    let opt = p.string_mut()?;
                    mount_option(&mut m, opt, fs_opts, at)?;
                }
            }
            b"uidMappings" => require_empty(p, "mounts[].uidMappings")?,
            b"gidMappings" => require_empty(p, "mounts[].gidMappings")?,
            _ => p.skip()?,
        }
    }
    m.destination = destination.ok_or(SpecError::Missing("mounts[].destination"))?;
    if m.fstype.is_some_and(|t| t.to_bytes() == b"bind") && m.kind == MountKind::New {
        m.kind = MountKind::Bind { recursive: false };
    }
    let len = fs_opts.len() - start;
    if len > 0 && m.kind != MountKind::New {
        return Err(SpecError::Unsupported("filesystem options on a bind mount"));
    }
    m.fs_opts = (start as u16, len as u16);
    if m.kind == MountKind::New && m.fstype.is_none() {
        return Err(SpecError::Missing("mounts[].type"));
    }
    Ok(m)
}

/// Sorts one mount option into flags or a filesystem option. `opt` is the
/// option's bytes in the config buffer, NUL included; a `key=value` option
/// is split in place by overwriting the `=` with a NUL.
fn mount_option(
    m: &mut Mount,
    opt: &'static mut [u8],
    fs_opts: &mut Fixed<FsOpt, MAX_FS_OPTS>,
    at: usize,
) -> Result<()> {
    let text = opt.split_last().map_or(&[][..], |(_, t)| t);
    if let Some((set, clr)) = mount_attr(text) {
        m.attr_set = (m.attr_set & !clr) | set;
        m.attr_clr = (m.attr_clr & !set) | clr;
        return Ok(());
    }
    if let Some((set, clr)) = text.strip_prefix(b"r").and_then(mount_attr) {
        m.rec_attr_set = (m.rec_attr_set & !clr) | set;
        m.rec_attr_clr = (m.rec_attr_clr & !set) | clr;
        return Ok(());
    }
    if let Some((flag, rec)) = propagation(text) {
        if flag == mount::MS_SHARED {
            return Err(SpecError::Unsupported(SHARED));
        }
        m.propagation = flag;
        m.propagation_rec = rec;
        return Ok(());
    }
    match text {
        b"bind" => m.kind = MountKind::Bind { recursive: false },
        b"rbind" => m.kind = MountKind::Bind { recursive: true },
        b"remount" | b"tmpcopyup" | b"idmap" | b"ridmap" | b"copy-symlink" => {
            return Err(SpecError::Unsupported(
                "mount option remount/tmpcopyup/idmap",
            ));
        }
        _ => {
            let invalid = SpecError::Invalid {
                field: "mount option",
                at,
            };
            let opt = match opt.iter().position(|&c| c == b'=') {
                None => FsOpt {
                    key: CStr::from_bytes_with_nul(opt).map_err(|_interior_nul| invalid)?,
                    value: None,
                },
                Some(eq) => {
                    let (key, value) = opt.split_at_mut(eq + 1);
                    if let Some(sep) = key.last_mut() {
                        *sep = 0;
                    }
                    FsOpt {
                        key: CStr::from_bytes_with_nul(key).map_err(|_interior_nul| invalid)?,
                        value: Some(
                            CStr::from_bytes_with_nul(value).map_err(|_interior_nul| invalid)?,
                        ),
                    }
                }
            };
            push(fs_opts, opt, "mount options")?;
        }
    }
    Ok(())
}

fn ns_flag(name: &[u8]) -> Option<u64> {
    Some(match name {
        b"mount" => ns::NEWNS,
        b"pid" => ns::NEWPID,
        b"network" => ns::NEWNET,
        b"ipc" => ns::NEWIPC,
        b"uts" => ns::NEWUTS,
        b"user" => ns::NEWUSER,
        b"cgroup" => ns::NEWCGROUP,
        b"time" => ns::NEWTIME,
        _ => return None,
    })
}

fn parse_namespaces(p: &mut Parser<'static>, out: &mut Namespaces) -> Result<()> {
    out.new = 0;
    out.join.clear();
    let mut a = p.array()?;
    while a.next(p)? {
        let mut kind = None;
        let mut path = None;
        let mut o = p.object()?;
        while let Some(key) = o.next(p)? {
            match key.to_bytes() {
                b"type" => {
                    let name = p.str()?;
                    let flag = ns_flag(name.to_bytes()).ok_or(SpecError::Unknown {
                        field: "linux.namespaces type",
                        value: name,
                    })?;
                    kind = Some((flag, name));
                }
                b"path" => path = Some(p.str()?),
                _ => p.skip()?,
            }
        }
        let (flag, name) = kind.ok_or(SpecError::Missing("linux.namespaces[].type"))?;
        if out.has(flag) {
            return Err(SpecError::Duplicate {
                field: "linux.namespaces type",
                value: name,
            });
        }
        match path {
            Some(path) if !path.is_empty() => {
                push(&mut out.join, (flag, path), "linux.namespaces")?
            }
            _ => out.new |= flag,
        }
    }
    if out.new & ns::NEWTIME != 0 {
        // A time namespace takes effect only after an exec, with offsets
        // written beforehand; zrc writes none.
        return Err(SpecError::Unsupported("a new time namespace"));
    }
    Ok(())
}

fn parse_id_maps(
    p: &mut Parser<'static>,
    out: &mut Fixed<IdMap, MAX_ID_MAPS>,
    field: &'static str,
) -> Result<()> {
    out.clear();
    let mut a = p.array()?;
    while a.next(p)? {
        let mut m = IdMap {
            container: 0,
            host: 0,
            size: 0,
        };
        let mut o = p.object()?;
        while let Some(key) = o.next(p)? {
            match key.to_bytes() {
                b"containerID" => m.container = p.u32()?,
                b"hostID" => m.host = p.u32()?,
                b"size" => m.size = p.u32()?,
                _ => p.skip()?,
            }
        }
        push(out, m, field)?;
    }
    Ok(())
}

fn parse_resources(p: &mut Parser<'static>, r: &mut Resources) -> Result<()> {
    let mut o = p.object()?;
    while let Some(key) = o.next(p)? {
        match key.to_bytes() {
            b"memory" => {
                let mut m = p.object()?;
                while let Some(key) = m.next(p)? {
                    match key.to_bytes() {
                        b"limit" => r.memory_limit = nonzero(p.i64()?),
                        b"reservation" => r.memory_reservation = nonzero(p.i64()?),
                        b"swap" => r.memory_swap = nonzero(p.i64()?),
                        b"kernel" => require_empty(p, "linux.resources.memory.kernel")?,
                        b"kernelTCP" => require_empty(p, "linux.resources.memory.kernelTCP")?,
                        b"swappiness" => require_empty(p, "linux.resources.memory.swappiness")?,
                        b"disableOOMKiller" => {
                            require_empty(p, "linux.resources.memory.disableOOMKiller")?
                        }
                        _ => p.skip()?,
                    }
                }
            }
            b"cpu" => {
                let mut c = p.object()?;
                while let Some(key) = c.next(p)? {
                    match key.to_bytes() {
                        b"shares" => r.cpu_shares = Some(p.u64()?).filter(|&v| v != 0),
                        b"quota" => r.cpu_quota = Some(p.i64()?),
                        b"period" => r.cpu_period = Some(p.u64()?),
                        b"burst" => r.cpu_burst = Some(p.u64()?),
                        b"idle" => r.cpu_idle = Some(p.i64()?),
                        b"cpus" => r.cpus = Some(p.str()?),
                        b"mems" => r.mems = Some(p.str()?),
                        b"realtimeRuntime" => {
                            require_empty(p, "linux.resources.cpu.realtimeRuntime")?
                        }
                        b"realtimePeriod" => {
                            require_empty(p, "linux.resources.cpu.realtimePeriod")?
                        }
                        _ => p.skip()?,
                    }
                }
            }
            b"pids" => {
                let mut c = p.object()?;
                while let Some(key) = c.next(p)? {
                    match key.to_bytes() {
                        b"limit" => r.pids_limit = nonzero(p.i64()?),
                        _ => p.skip()?,
                    }
                }
            }
            b"hugepageLimits" => {
                r.hugepages.clear();
                let mut a = p.array()?;
                while a.next(p)? {
                    let (mut size, mut limit) = (None, None);
                    let mut h = p.object()?;
                    while let Some(key) = h.next(p)? {
                        match key.to_bytes() {
                            b"pageSize" => size = Some(p.str()?),
                            b"limit" => limit = Some(p.u64()?),
                            _ => p.skip()?,
                        }
                    }
                    let size = size.ok_or(SpecError::Missing("hugepageLimits[].pageSize"))?;
                    let limit = limit.ok_or(SpecError::Missing("hugepageLimits[].limit"))?;
                    push(
                        &mut r.hugepages,
                        (size, limit),
                        "linux.resources.hugepageLimits",
                    )?;
                }
            }
            b"unified" => {
                r.unified.clear();
                let mut u = p.object()?;
                while let Some(file) = u.next(p)? {
                    let value = p.str()?;
                    if !crate::cgroup::is_file_name(file.to_bytes()) {
                        return Err(SpecError::Unknown {
                            field: "linux.resources.unified file",
                            value: file,
                        });
                    }
                    push(&mut r.unified, (file, value), "linux.resources.unified")?;
                }
            }
            b"devices" => {
                let rules = &mut r.devices;
                rules.clear();
                let mut a = p.array()?;
                while a.next(p)? {
                    let rule = parse_device_rule(p)?;
                    push(rules, rule, "linux.resources.devices")?;
                }
            }
            b"blockIO" => require_empty(p, "linux.resources.blockIO")?,
            b"network" => require_empty(p, "linux.resources.network")?,
            b"rdma" => require_empty(p, "linux.resources.rdma")?,
            _ => p.skip()?,
        }
    }
    Ok(())
}

/// runc treats 0 as unset for memory, cpu shares and pids limits.
fn nonzero(v: i64) -> Option<i64> {
    (v != 0).then_some(v)
}

/// A device number in a rule: absent or `-1` is a wildcard.
fn dev_number(p: &mut Parser<'static>, field: &'static str) -> Result<Option<u32>> {
    let at = p.offset();
    match p.i64()? {
        -1 => Ok(None),
        n => u32::try_from(n)
            .map(Some)
            .map_err(|_negative| SpecError::Invalid { field, at }),
    }
}

fn parse_device_rule(p: &mut Parser<'static>) -> Result<DeviceRule> {
    let mut rule = DeviceRule {
        allow: false,
        kind: b'a',
        major: None,
        minor: None,
        access: 1 | 2 | 4,
    };
    let mut o = p.object()?;
    while let Some(key) = o.next(p)? {
        match key.to_bytes() {
            b"allow" => rule.allow = p.bool()?,
            b"type" => {
                let at = p.offset();
                rule.kind = match p.str()?.to_bytes() {
                    b"a" => b'a',
                    b"c" => b'c',
                    b"b" => b'b',
                    _ => {
                        return Err(SpecError::Invalid {
                            field: "devices[].type",
                            at,
                        });
                    }
                };
            }
            b"major" => rule.major = dev_number(p, "devices[].major")?,
            b"minor" => rule.minor = dev_number(p, "devices[].minor")?,
            b"access" => {
                let at = p.offset();
                let mut access = 0;
                for &c in p.str()?.to_bytes() {
                    access |= match c {
                        b'm' => 1,
                        b'r' => 2,
                        b'w' => 4,
                        _ => {
                            return Err(SpecError::Invalid {
                                field: "devices[].access",
                                at,
                            });
                        }
                    };
                }
                rule.access = access;
            }
            _ => p.skip()?,
        }
    }
    Ok(rule)
}

fn parse_devices(p: &mut Parser<'static>, out: &mut Fixed<Device, MAX_DEVICES>) -> Result<()> {
    out.clear();
    let mut a = p.array()?;
    while a.next(p)? {
        let mut d = Device {
            path: c"",
            kind: 0,
            major: 0,
            minor: 0,
            mode: None,
            uid: None,
            gid: None,
        };
        let mut path = None;
        let mut o = p.object()?;
        while let Some(key) = o.next(p)? {
            match key.to_bytes() {
                b"path" => path = Some(p.str()?),
                b"type" => {
                    let at = p.offset();
                    d.kind = match p.str()?.to_bytes() {
                        b"c" | b"u" => fs::S_IFCHR,
                        b"b" => fs::S_IFBLK,
                        b"p" => fs::S_IFIFO,
                        _ => {
                            return Err(SpecError::Invalid {
                                field: "linux.devices[].type",
                                at,
                            });
                        }
                    };
                }
                b"major" => d.major = p.u32()?,
                b"minor" => d.minor = p.u32()?,
                b"fileMode" => d.mode = Some(p.u32()? & 0o7777),
                b"uid" => d.uid = Some(p.u32()?),
                b"gid" => d.gid = Some(p.u32()?),
                _ => p.skip()?,
            }
        }
        d.path = path.ok_or(SpecError::Missing("linux.devices[].path"))?;
        if d.kind == 0 {
            return Err(SpecError::Missing("linux.devices[].type"));
        }
        push(out, d, "linux.devices")?;
    }
    Ok(())
}

fn parse_sysctls(p: &mut Parser<'static>, out: &mut Fixed<Sysctl, MAX_SYSCTLS>) -> Result<()> {
    out.clear();
    let mut o = p.object()?;
    loop {
        let at = p.offset();
        let Some(key) = o.next_mut(p)? else { break };
        // `net.ipv4.ip_forward` is the file `net/ipv4/ip_forward` below
        // /proc/sys; a `/` in a key stands for a `.` in a file name (as in
        // `net.ipv4.conf.eth0/100.forwarding`). Rewrite the key in place.
        for c in key.iter_mut() {
            *c = match *c {
                b'.' => b'/',
                b'/' => b'.',
                c => c,
            };
        }
        let path = CStr::from_bytes_with_nul(key).map_err(|_interior_nul| SpecError::Invalid {
            field: "linux.sysctl key",
            at,
        })?;
        let valid = path
            .to_bytes()
            .split(|&c| c == b'/')
            .all(|seg| !seg.is_empty() && seg != b"." && seg != b"..");
        if !valid {
            return Err(SpecError::Unknown {
                field: "linux.sysctl key",
                value: path,
            });
        }
        let value = p.str()?;
        push(out, Sysctl { path, value }, "linux.sysctl")?;
    }
    Ok(())
}
