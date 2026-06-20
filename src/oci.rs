//! The subset of the OCI runtime spec (`config.json`) that `zrc` understands.
//!
//! We deliberately model only what we act on today (root, process, mounts,
//! namespaces, hostname). Unknown fields are ignored, which keeps us forward
//! compatible with richer bundles produced by Docker/containerd.

use alloc::string::String;
use alloc::vec::Vec;

use crate::json::Value;
use crate::sys;

pub struct Spec {
    pub root_path: String,
    pub root_readonly: bool,
    pub hostname: Option<String>,
    pub process: Process,
    pub mounts: Vec<Mount>,
    pub namespaces: Vec<Namespace>,
    pub uid_mappings: Vec<IdMap>,
    pub gid_mappings: Vec<IdMap>,
    pub cgroups_path: Option<String>,
    pub resources: Resources,
    pub seccomp: Option<Seccomp>,
    pub annotations: Vec<(String, String)>,
}

/// `linux.seccomp`. We model syscall-name-level filtering (the common case);
/// per-arg rules are not yet applied.
pub struct Seccomp {
    pub default_action: String,
    pub default_errno: u16,
    pub rules: Vec<SeccompRule>,
}

pub struct SeccompRule {
    pub names: Vec<String>,
    pub action: String,
    pub errno: u16,
}

/// `linux.resources` — the cgroup v2 knobs we currently honor. Each is optional;
/// `None` means "leave the kernel default".
#[derive(Default)]
pub struct Resources {
    pub memory_limit: Option<i64>, // memory.max  (bytes; -1 → "max")
    pub memory_swap: Option<i64>,  // memory.swap.max
    pub cpu_shares: Option<u64>,   // → cpu.weight (converted)
    pub cpu_quota: Option<i64>,    // cpu.max quota (-1 → "max")
    pub cpu_period: Option<u64>,   // cpu.max period (default 100000)
    pub cpu_cpus: Option<String>,  // cpuset.cpus
    pub cpu_mems: Option<String>,  // cpuset.mems
    pub pids_limit: Option<i64>,   // pids.max (-1 → "max")
}

impl Resources {
    pub fn is_empty(&self) -> bool {
        self.memory_limit.is_none()
            && self.memory_swap.is_none()
            && self.cpu_shares.is_none()
            && self.cpu_quota.is_none()
            && self.cpu_cpus.is_none()
            && self.cpu_mems.is_none()
            && self.pids_limit.is_none()
    }
}

/// A `/proc/<pid>/{uid,gid}_map` line: `container_id host_id size`.
#[derive(Clone, Copy)]
pub struct IdMap {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

impl Spec {
    pub fn has_user_ns(&self) -> bool {
        self.namespaces.iter().any(|n| n.typ == "user")
    }
    pub fn has_cgroup_ns(&self) -> bool {
        self.namespaces.iter().any(|n| n.typ == "cgroup")
    }
    pub fn annotation(&self, key: &str) -> Option<&str> {
        self.annotations
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
    /// Per-container runtime toggle for Sysbox mode.
    pub fn sysbox_requested(&self) -> bool {
        matches!(
            self.annotation("org.zrc.sysbox"),
            Some("true") | Some("1") | Some("enabled") | Some("yes")
        )
    }
}

pub struct Process {
    pub cwd: String,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub uid: u32,
    pub gid: u32,
    pub additional_gids: Vec<u32>,
    pub terminal: bool,
    pub no_new_privileges: bool,
    pub capabilities: Option<Capabilities>,
    pub rlimits: Vec<Rlimit>,
}

/// Capability sets as raw OCI names (e.g. "CAP_NET_BIND_SERVICE"); converted to
/// bitmasks in `caps`.
#[derive(Default)]
pub struct Capabilities {
    pub bounding: Vec<String>,
    pub effective: Vec<String>,
    pub permitted: Vec<String>,
    pub inheritable: Vec<String>,
    pub ambient: Vec<String>,
}

pub struct Rlimit {
    pub resource: u32,
    pub soft: u64,
    pub hard: u64,
}

pub struct Mount {
    pub destination: String,
    pub typ: Option<String>,
    pub source: Option<String>,
    pub options: Vec<String>,
}

pub struct Namespace {
    pub typ: String,
    pub path: Option<String>,
}

impl Namespace {
    /// CLONE_* flag for this namespace, or 0 for ones we don't create
    /// (e.g. "user" — needs uid/gid maps we don't write yet).
    pub fn clone_flag(&self) -> usize {
        match self.typ.as_str() {
            "mount" => sys::CLONE_NEWNS,
            "pid" => sys::CLONE_NEWPID,
            "uts" => sys::CLONE_NEWUTS,
            "ipc" => sys::CLONE_NEWIPC,
            "network" => sys::CLONE_NEWNET,
            "cgroup" => sys::CLONE_NEWCGROUP,
            "user" => sys::CLONE_NEWUSER,
            _ => 0,
        }
    }
}

impl Mount {
    /// Translate option strings into `(flags, data)` for `mount(2)`.
    /// Recognized flags are consumed; the rest become comma-joined fs data
    /// (e.g. `mode=755`, `size=65536k`).
    pub fn parse_options(&self) -> (usize, Option<String>) {
        let mut flags = 0usize;
        let mut data: Vec<&str> = Vec::new();
        for o in &self.options {
            let f = match o.as_str() {
                "ro" => sys::MS_RDONLY,
                "rw" => 0,
                "nosuid" => sys::MS_NOSUID,
                "nodev" => sys::MS_NODEV,
                "noexec" => sys::MS_NOEXEC,
                "relatime" => sys::MS_RELATIME,
                "strictatime" => sys::MS_STRICTATIME,
                "remount" => sys::MS_REMOUNT,
                "bind" => sys::MS_BIND,
                "rbind" => sys::MS_BIND | sys::MS_REC,
                "private" => sys::MS_PRIVATE,
                "rprivate" => sys::MS_PRIVATE | sys::MS_REC,
                "slave" => sys::MS_SLAVE,
                "rslave" => sys::MS_SLAVE | sys::MS_REC,
                "shared" => sys::MS_SHARED,
                "rec" => sys::MS_REC,
                other => {
                    data.push(other);
                    continue;
                }
            };
            flags |= f;
        }
        let data = if data.is_empty() {
            None
        } else {
            Some(data.join(","))
        };
        (flags, data)
    }

    pub fn is_bind(&self) -> bool {
        self.options
            .iter()
            .any(|o| o == "bind" || o == "rbind")
    }
}

fn parse_seccomp(v: Option<&Value>) -> Option<Seccomp> {
    let s = v?;
    let default_action = s.get("defaultAction").and_then(Value::as_str)?.into();
    let default_errno = s
        .get("defaultErrnoRet")
        .and_then(Value::as_u64)
        .unwrap_or(1) as u16; // EPERM
    let mut rules = Vec::new();
    if let Some(arr) = s.get("syscalls").and_then(Value::as_array) {
        for r in arr {
            let action = match r.get("action").and_then(Value::as_str) {
                Some(a) => a.into(),
                None => continue,
            };
            let names = r.get("names").map(Value::as_str_vec).unwrap_or_default();
            if names.is_empty() {
                continue;
            }
            let errno = r
                .get("errnoRet")
                .and_then(Value::as_u64)
                .unwrap_or(default_errno as u64) as u16;
            rules.push(SeccompRule {
                names,
                action,
                errno,
            });
        }
    }
    Some(Seccomp {
        default_action,
        default_errno,
        rules,
    })
}

fn parse_capabilities(v: Option<&Value>) -> Option<Capabilities> {
    let c = v?;
    let set = |name: &str| c.get(name).map(Value::as_str_vec).unwrap_or_default();
    Some(Capabilities {
        bounding: set("bounding"),
        effective: set("effective"),
        permitted: set("permitted"),
        inheritable: set("inheritable"),
        ambient: set("ambient"),
    })
}

fn parse_rlimits(v: Option<&Value>) -> Vec<Rlimit> {
    let mut out = Vec::new();
    if let Some(arr) = v.and_then(Value::as_array) {
        for r in arr {
            let typ = match r.get("type").and_then(Value::as_str) {
                Some(t) => t,
                None => continue,
            };
            if let Some(resource) = rlimit_resource(typ) {
                out.push(Rlimit {
                    resource,
                    soft: r.get("soft").and_then(Value::as_u64).unwrap_or(0),
                    hard: r.get("hard").and_then(Value::as_u64).unwrap_or(0),
                });
            }
        }
    }
    out
}

/// OCI rlimit name → `RLIMIT_*` resource number (asm-generic; same on both arches).
fn rlimit_resource(name: &str) -> Option<u32> {
    Some(match name {
        "RLIMIT_CPU" => 0,
        "RLIMIT_FSIZE" => 1,
        "RLIMIT_DATA" => 2,
        "RLIMIT_STACK" => 3,
        "RLIMIT_CORE" => 4,
        "RLIMIT_RSS" => 5,
        "RLIMIT_NPROC" => 6,
        "RLIMIT_NOFILE" => 7,
        "RLIMIT_MEMLOCK" => 8,
        "RLIMIT_AS" => 9,
        "RLIMIT_LOCKS" => 10,
        "RLIMIT_SIGPENDING" => 11,
        "RLIMIT_MSGQUEUE" => 12,
        "RLIMIT_NICE" => 13,
        "RLIMIT_RTPRIO" => 14,
        "RLIMIT_RTTIME" => 15,
        _ => return None,
    })
}

fn parse_resources(v: Option<&Value>) -> Resources {
    let mut r = Resources::default();
    let res = match v {
        Some(res) => res,
        None => return r,
    };
    if let Some(mem) = res.get("memory") {
        r.memory_limit = mem.get("limit").and_then(Value::as_i64);
        r.memory_swap = mem.get("swap").and_then(Value::as_i64);
    }
    if let Some(cpu) = res.get("cpu") {
        r.cpu_shares = cpu.get("shares").and_then(Value::as_u64);
        r.cpu_quota = cpu.get("quota").and_then(Value::as_i64);
        r.cpu_period = cpu.get("period").and_then(Value::as_u64);
        r.cpu_cpus = cpu.get("cpus").and_then(Value::as_str).map(String::from);
        r.cpu_mems = cpu.get("mems").and_then(Value::as_str).map(String::from);
    }
    if let Some(pids) = res.get("pids") {
        r.pids_limit = pids.get("limit").and_then(Value::as_i64);
    }
    r
}

fn parse_id_maps(v: Option<&Value>) -> Vec<IdMap> {
    let mut out = Vec::new();
    if let Some(arr) = v.and_then(Value::as_array) {
        for m in arr {
            let container_id = m.get("containerID").and_then(Value::as_u64).unwrap_or(0) as u32;
            let host_id = m.get("hostID").and_then(Value::as_u64).unwrap_or(0) as u32;
            let size = m.get("size").and_then(Value::as_u64).unwrap_or(0) as u32;
            if size > 0 {
                out.push(IdMap {
                    container_id,
                    host_id,
                    size,
                });
            }
        }
    }
    out
}

impl Spec {
    pub fn from_json(v: &Value) -> Result<Spec, &'static str> {
        let root = v.get("root").ok_or("missing 'root'")?;
        let root_path = root
            .get("path")
            .and_then(Value::as_str)
            .ok_or("missing 'root.path'")?
            .into();
        let root_readonly = root
            .get("readonly")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let hostname = v.get("hostname").and_then(Value::as_str).map(String::from);

        let p = v.get("process").ok_or("missing 'process'")?;
        let user = p.get("user");
        let process = Process {
            cwd: p
                .get("cwd")
                .and_then(Value::as_str)
                .unwrap_or("/")
                .into(),
            args: p.get("args").map(Value::as_str_vec).unwrap_or_default(),
            env: p.get("env").map(Value::as_str_vec).unwrap_or_default(),
            uid: user
                .and_then(|u| u.get("uid"))
                .and_then(Value::as_u64)
                .unwrap_or(0) as u32,
            gid: user
                .and_then(|u| u.get("gid"))
                .and_then(Value::as_u64)
                .unwrap_or(0) as u32,
            additional_gids: user
                .and_then(|u| u.get("additionalGids"))
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_u64).map(|g| g as u32).collect())
                .unwrap_or_default(),
            terminal: p.get("terminal").and_then(Value::as_bool).unwrap_or(false),
            no_new_privileges: p
                .get("noNewPrivileges")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            capabilities: parse_capabilities(p.get("capabilities")),
            rlimits: parse_rlimits(p.get("rlimits")),
        };
        if process.args.is_empty() {
            return Err("process.args is empty");
        }

        let mut mounts = Vec::new();
        if let Some(arr) = v.get("mounts").and_then(Value::as_array) {
            for m in arr {
                let destination = match m.get("destination").and_then(Value::as_str) {
                    Some(d) => d.into(),
                    None => continue,
                };
                mounts.push(Mount {
                    destination,
                    typ: m.get("type").and_then(Value::as_str).map(String::from),
                    source: m.get("source").and_then(Value::as_str).map(String::from),
                    options: m.get("options").map(Value::as_str_vec).unwrap_or_default(),
                });
            }
        }

        let linux = v.get("linux");

        let mut namespaces = Vec::new();
        if let Some(arr) = linux
            .and_then(|l| l.get("namespaces"))
            .and_then(Value::as_array)
        {
            for n in arr {
                if let Some(typ) = n.get("type").and_then(Value::as_str) {
                    namespaces.push(Namespace {
                        typ: typ.into(),
                        path: n.get("path").and_then(Value::as_str).map(String::from),
                    });
                }
            }
        }

        let uid_mappings = parse_id_maps(linux.and_then(|l| l.get("uidMappings")));
        let gid_mappings = parse_id_maps(linux.and_then(|l| l.get("gidMappings")));

        let cgroups_path = linux
            .and_then(|l| l.get("cgroupsPath"))
            .and_then(Value::as_str)
            .map(String::from);
        let resources = parse_resources(linux.and_then(|l| l.get("resources")));
        let seccomp = parse_seccomp(linux.and_then(|l| l.get("seccomp")));

        let mut annotations = Vec::new();
        if let Some(Value::Object(m)) = v.get("annotations") {
            for (k, val) in m {
                if let Some(s) = val.as_str() {
                    annotations.push((k.clone(), s.into()));
                }
            }
        }

        Ok(Spec {
            root_path,
            root_readonly,
            hostname,
            process,
            mounts,
            namespaces,
            uid_mappings,
            gid_mappings,
            cgroups_path,
            resources,
            seccomp,
            annotations,
        })
    }
}
