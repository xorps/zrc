//! cgroup v2 (unified hierarchy) resource limits.
//!
//! Runs on the runtime (host) side, where `/sys/fs/cgroup` is the real cgroup2
//! mount: we create a leaf cgroup for the container, enable controllers down the
//! chain, write the limit files, and attach the init pid. Everything is
//! best-effort — a missing controller or a delegated/locked-down host shouldn't
//! abort the run, so failures warn rather than fail.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::oci::Resources;
use crate::sys;

const ROOT: &str = "/sys/fs/cgroup";
const CONTROLLERS: [&str; 4] = ["+cpu", "+memory", "+pids", "+cpuset"];

/// True if the host exposes a cgroup v2 unified hierarchy.
fn v2_available() -> bool {
    match sys::openat(
        sys::AT_FDCWD,
        "/sys/fs/cgroup/cgroup.controllers",
        sys::O_RDONLY | sys::O_CLOEXEC,
        0,
    ) {
        Ok(fd) => {
            let _ = sys::close(fd);
            true
        }
        Err(_) => false,
    }
}

/// Create `rel_path` under the cgroup2 root, apply `res`, and move `pid` in.
pub fn setup(rel_path: &str, pid: i32, res: &Resources) {
    if !v2_available() {
        eprintln!("zrc: warning: cgroup v2 unavailable; skipping resource limits");
        return;
    }

    let comps: Vec<&str> = rel_path.split('/').filter(|c| !c.is_empty()).collect();
    if comps.is_empty() {
        return;
    }

    // The root must delegate controllers to its children.
    enable_subtree(ROOT);

    let mut cur = String::from(ROOT);
    for (i, comp) in comps.iter().enumerate() {
        cur.push('/');
        cur.push_str(comp);
        if let Err(e) = sys::mkdir_p1(&cur, 0o755) {
            eprintln!("zrc: warning: mkdir cgroup '{}' failed: errno {}", cur, e);
        }
        // Every ancestor of the leaf must enable controllers for its children;
        // the leaf itself only hosts the process.
        if i + 1 < comps.len() {
            enable_subtree(&cur);
        }
    }

    apply(&cur, res);

    let procs = format!("{}/cgroup.procs", cur);
    if let Err(e) = sys::write_file(&procs, format!("{}", pid).as_bytes(), 0) {
        eprintln!("zrc: warning: cgroup attach (pid {}) failed: errno {}", pid, e);
    }
}

/// Remove the container's leaf cgroup. Kills any stragglers via `cgroup.kill`,
/// then retries `rmdir` a few times — a just-exited member can briefly linger as
/// a zombie (until its reaper collects it) and hold the directory EBUSY.
pub fn destroy(rel_path: &str) {
    let trimmed = rel_path.trim_start_matches('/');
    if trimmed.is_empty() {
        return;
    }
    let full = format!("{}/{}", ROOT, trimmed);

    // cgroup.kill (v2) SIGKILLs every member of the subtree.
    let _ = sys::write_file(&format!("{}/cgroup.kill", full), b"1", 0);

    for attempt in 0..10 {
        if sys::rmdir(&full).is_ok() {
            return;
        }
        if attempt < 9 {
            sys::sleep_ms(20);
        }
    }
}

/// Enable each controller individually so a single unavailable one doesn't
/// reject the whole write.
fn enable_subtree(dir: &str) {
    let path = format!("{}/cgroup.subtree_control", dir);
    for c in CONTROLLERS {
        let _ = sys::write_file(&path, c.as_bytes(), 0);
    }
}

fn apply(dir: &str, res: &Resources) {
    if let Some(m) = res.memory_limit {
        write_limit(dir, "memory.max", m);
    }
    if let Some(s) = res.memory_swap {
        write_limit(dir, "memory.swap.max", s);
    }
    if let Some(p) = res.pids_limit {
        write_limit(dir, "pids.max", p);
    }
    if let Some(q) = res.cpu_quota {
        let period = res.cpu_period.unwrap_or(100_000);
        let val = if q < 0 {
            format!("max {}", period)
        } else {
            format!("{} {}", q, period)
        };
        write_str(dir, "cpu.max", &val);
    }
    if let Some(sh) = res.cpu_shares {
        write_str(dir, "cpu.weight", &format!("{}", shares_to_weight(sh)));
    }
    if let Some(c) = &res.cpu_cpus {
        write_str(dir, "cpuset.cpus", c);
    }
    if let Some(m) = &res.cpu_mems {
        write_str(dir, "cpuset.mems", m);
    }
}

/// cgroup v1 `cpu.shares` → cgroup v2 `cpu.weight` (the conversion systemd uses).
fn shares_to_weight(shares: u64) -> u64 {
    if shares < 2 {
        return 1;
    }
    let w = 1 + ((shares - 2) * 9999) / 262_142;
    w.clamp(1, 10_000)
}

fn write_limit(dir: &str, file: &str, v: i64) {
    let val = if v < 0 {
        String::from("max")
    } else {
        format!("{}", v)
    };
    write_str(dir, file, &val);
}

fn write_str(dir: &str, file: &str, val: &str) {
    let path = format!("{}/{}", dir, file);
    if let Err(e) = sys::write_file(&path, val.as_bytes(), 0) {
        eprintln!("zrc: warning: set {} = '{}' failed: errno {}", file, val, e);
    }
}
