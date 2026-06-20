//! Sysbox-style system-container support (compiled in only with
//! `--features sysbox`, and active per-container only when the
//! `org.zrc.sysbox` annotation opts in — see `Spec::sysbox_requested`).
//!
//! The goal is to run system-level workloads (systemd, Docker, Kubernetes)
//! *inside* an unprivileged container. That rests on three pillars; this module
//! is where each lands:
//!   1. auto user-namespacing (DONE here — apply the userns + maps if absent),
//!   2. emulated `/proc` & `/sys` so inner daemons see coherent kernel state
//!      (PENDING — FUSE-backed),
//!   3. seccomp-notify interception of `mount`, `setns`, … to emulate them
//!      safely (PENDING — listener loop + per-syscall handlers).

use crate::oci::{IdMap, Namespace, Spec};

/// Default host base for the auto user-namespace mapping when the bundle didn't
/// specify one. Mirrors the common Sysbox/`subuid` convention.
const DEFAULT_HOST_BASE: u32 = 100_000;
const DEFAULT_RANGE: u32 = 65_536;

/// Apply Sysbox defaults to a parsed spec, in place, before the container is
/// created. Only the pieces we can do safely today are applied; the emulation
/// pillars are wired here as they land.
pub fn prepare(spec: &mut Spec) {
    eprintln!("zrc: sysbox mode enabled for this container");

    // Pillar 1 — a system container always gets its own user namespace so that
    // in-container root is unprivileged on the host.
    if !spec.has_user_ns() {
        spec.namespaces.push(Namespace {
            typ: "user".into(),
            path: None,
        });
    }
    if spec.uid_mappings.is_empty() {
        spec.uid_mappings.push(IdMap {
            container_id: 0,
            host_id: DEFAULT_HOST_BASE,
            size: DEFAULT_RANGE,
        });
    }
    if spec.gid_mappings.is_empty() {
        spec.gid_mappings.push(IdMap {
            container_id: 0,
            host_id: DEFAULT_HOST_BASE,
            size: DEFAULT_RANGE,
        });
    }

    // A dedicated cgroup namespace, so inner cgroup-aware daemons see a clean root.
    if !spec.has_cgroup_ns() {
        spec.namespaces.push(Namespace {
            typ: "cgroup".into(),
            path: None,
        });
    }

    // Until ID-mapped mounts land, the rootfs must be owned by the mapped host
    // range; flag that rather than failing obscurely at exec.
    eprintln!(
        "zrc: sysbox: rootfs must be owned by host uid/gid {}..{} \
         (ID-mapped mounts not yet implemented)",
        DEFAULT_HOST_BASE,
        DEFAULT_HOST_BASE + DEFAULT_RANGE
    );

    // Pillar 2 & 3 (emulated /proc & /sys, seccomp-notify interception) attach
    // here next.
}
