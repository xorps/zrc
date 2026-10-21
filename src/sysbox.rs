//! Sysbox-style system containers (built with `--features sysbox`, and used
//! only by containers with the `org.zrc.sysbox=true` annotation).
//!
//! A system container runs system software (systemd, Docker) as an
//! unprivileged user on the host. zrc provides the namespace part: its own
//! user namespace, mapping container root to an unprivileged host range,
//! and its own cgroup namespace.
//!
//! The rest of Sysbox needs a long-lived agent next to the container, which
//! a one-shot runtime cannot be: emulated `/proc` and `/sys` (Sysbox serves
//! them over FUSE) and seccomp-notify interception of `mount` and friends.
//! Until ID-mapped mounts are wired in, the rootfs must be owned by the
//! mapped host range.

use xorpio::ns;

use crate::oci::{IdMap, Spec, SpecError};

/// The host range container ids map to without explicit mappings, by the
/// common `/etc/subuid` convention.
const HOST_BASE: u32 = 100_000;
const RANGE: u32 = 65_536;

/// Adds what a system container needs and the spec did not ask for.
pub fn prepare(spec: &mut Spec) -> Result<(), SpecError> {
    let default = IdMap {
        container: 0,
        host: HOST_BASE,
        size: RANGE,
    };
    if !spec.namespaces.has(ns::NEWUSER) {
        spec.namespaces.new |= ns::NEWUSER;
        if spec.uid_maps.is_empty() {
            spec.uid_maps
                .push(default)
                .map_err(|_full| SpecError::TooMany {
                    field: "linux.uidMappings",
                    max: crate::oci::MAX_ID_MAPS,
                })?;
        }
        if spec.gid_maps.is_empty() {
            spec.gid_maps
                .push(default)
                .map_err(|_full| SpecError::TooMany {
                    field: "linux.gidMappings",
                    max: crate::oci::MAX_ID_MAPS,
                })?;
        }
    }
    if !spec.namespaces.has(ns::NEWCGROUP) {
        spec.namespaces.new |= ns::NEWCGROUP;
    }
    Ok(())
}
