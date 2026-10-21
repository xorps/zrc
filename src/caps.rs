//! Linux capabilities, as 64-bit masks indexed by `CAP_*` number.

use xorpio::Errno;
use xorpio::process::{self, CapSets, pr};

use crate::json::Parser;
use crate::oci::SpecError;

/// Capability names; the index is the `CAP_*` number. Ends at
/// `CAP_CHECKPOINT_RESTORE` (Linux 5.9), the last one defined.
const NAMES: [&[u8]; 41] = [
    b"CAP_CHOWN",
    b"CAP_DAC_OVERRIDE",
    b"CAP_DAC_READ_SEARCH",
    b"CAP_FOWNER",
    b"CAP_FSETID",
    b"CAP_KILL",
    b"CAP_SETGID",
    b"CAP_SETUID",
    b"CAP_SETPCAP",
    b"CAP_LINUX_IMMUTABLE",
    b"CAP_NET_BIND_SERVICE",
    b"CAP_NET_BROADCAST",
    b"CAP_NET_ADMIN",
    b"CAP_NET_RAW",
    b"CAP_IPC_LOCK",
    b"CAP_IPC_OWNER",
    b"CAP_SYS_MODULE",
    b"CAP_SYS_RAWIO",
    b"CAP_SYS_CHROOT",
    b"CAP_SYS_PTRACE",
    b"CAP_SYS_PACCT",
    b"CAP_SYS_ADMIN",
    b"CAP_SYS_BOOT",
    b"CAP_SYS_NICE",
    b"CAP_SYS_RESOURCE",
    b"CAP_SYS_TIME",
    b"CAP_SYS_TTY_CONFIG",
    b"CAP_MKNOD",
    b"CAP_LEASE",
    b"CAP_AUDIT_WRITE",
    b"CAP_AUDIT_CONTROL",
    b"CAP_SETFCAP",
    b"CAP_MAC_OVERRIDE",
    b"CAP_MAC_ADMIN",
    b"CAP_SYSLOG",
    b"CAP_WAKE_ALARM",
    b"CAP_BLOCK_SUSPEND",
    b"CAP_AUDIT_READ",
    b"CAP_PERFMON",
    b"CAP_BPF",
    b"CAP_CHECKPOINT_RESTORE",
];

/// The capability sets of `process.capabilities`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sets {
    pub bounding: u64,
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
    pub ambient: u64,
}

pub fn parse(p: &mut Parser<'static>) -> Result<Sets, SpecError> {
    let mut sets = Sets::default();
    let mut o = p.object()?;
    while let Some(key) = o.next(p)? {
        let set = match key.to_bytes() {
            b"bounding" => &mut sets.bounding,
            b"effective" => &mut sets.effective,
            b"permitted" => &mut sets.permitted,
            b"inheritable" => &mut sets.inheritable,
            b"ambient" => &mut sets.ambient,
            _ => {
                p.skip()?;
                continue;
            }
        };
        let mut a = p.array()?;
        while a.next(p)? {
            let name = p.str()?;
            let bit =
                NAMES
                    .iter()
                    .position(|&n| n == name.to_bytes())
                    .ok_or(SpecError::Unknown {
                        field: "capability",
                        value: name,
                    })?;
            *set |= 1 << bit;
        }
    }
    Ok(sets)
}

/// A capability operation failed for capability number `cap`.
#[derive(Clone, Copy, Debug)]
pub struct CapError {
    pub cap: u32,
    pub errno: Errno,
}

/// Removes every capability outside `keep` from the bounding set. Needs
/// `CAP_SETPCAP`.
pub fn restrict_bounding(keep: u64) -> Result<(), CapError> {
    for cap in 0..NAMES.len() as u32 {
        if keep & (1 << cap) == 0 {
            process::prctl(pr::CAPBSET_DROP, cap as usize, 0, 0, 0)
                .map_err(|errno| CapError { cap, errno })?;
        }
    }
    Ok(())
}

/// Sets the effective, permitted and inheritable sets.
pub fn set(sets: &Sets) -> Result<(), Errno> {
    process::capset(&CapSets {
        effective: sets.effective,
        permitted: sets.permitted,
        inheritable: sets.inheritable,
    })
}

#[derive(Clone, Copy, Debug)]
pub enum AmbientError {
    Clear(Errno),
    Raise(CapError),
}

/// Replaces the ambient set, which needs each capability to be permitted and
/// inheritable already.
pub fn set_ambient(ambient: u64) -> Result<(), AmbientError> {
    process::prctl(pr::CAP_AMBIENT, pr::CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
        .map_err(AmbientError::Clear)?;
    for cap in 0..NAMES.len() as u32 {
        if ambient & (1 << cap) != 0 {
            process::prctl(pr::CAP_AMBIENT, pr::CAP_AMBIENT_RAISE, cap as usize, 0, 0)
                .map_err(|errno| AmbientError::Raise(CapError { cap, errno }))?;
        }
    }
    Ok(())
}

/// The name of capability `cap`, for messages.
pub fn name(cap: u32) -> &'static [u8] {
    NAMES.get(cap as usize).copied().unwrap_or(b"CAP_?")
}
