//! Linux capabilities: bounding-set restriction, the permitted/effective/
//! inheritable sets via `capset`, and the ambient set via `prctl`.
//!
//! Split into two phases because of how `setuid` interacts with caps:
//!   * `restrict_bounding` + `keep_caps` run *before* the uid/gid switch
//!     (need CAP_SETPCAP, and KEEPCAPS so permitted survives setuid);
//!   * `apply_after_setuid` runs *after*, re-raising effective from permitted
//!     and setting the ambient set that persists across execve.

use crate::oci::Capabilities;
use crate::sys;

/// Highest capability we know about (CAP_CHECKPOINT_RESTORE). Used to iterate
/// the bounding set.
const CAP_LAST: u8 = 40;

/// Map an OCI capability name to its bit number.
fn cap_bit(name: &str) -> Option<u8> {
    Some(match name {
        "CAP_CHOWN" => 0,
        "CAP_DAC_OVERRIDE" => 1,
        "CAP_DAC_READ_SEARCH" => 2,
        "CAP_FOWNER" => 3,
        "CAP_FSETID" => 4,
        "CAP_KILL" => 5,
        "CAP_SETGID" => 6,
        "CAP_SETUID" => 7,
        "CAP_SETPCAP" => 8,
        "CAP_LINUX_IMMUTABLE" => 9,
        "CAP_NET_BIND_SERVICE" => 10,
        "CAP_NET_BROADCAST" => 11,
        "CAP_NET_ADMIN" => 12,
        "CAP_NET_RAW" => 13,
        "CAP_IPC_LOCK" => 14,
        "CAP_IPC_OWNER" => 15,
        "CAP_SYS_MODULE" => 16,
        "CAP_SYS_RAWIO" => 17,
        "CAP_SYS_CHROOT" => 18,
        "CAP_SYS_PTRACE" => 19,
        "CAP_SYS_PACCT" => 20,
        "CAP_SYS_ADMIN" => 21,
        "CAP_SYS_BOOT" => 22,
        "CAP_SYS_NICE" => 23,
        "CAP_SYS_RESOURCE" => 24,
        "CAP_SYS_TIME" => 25,
        "CAP_SYS_TTY_CONFIG" => 26,
        "CAP_MKNOD" => 27,
        "CAP_LEASE" => 28,
        "CAP_AUDIT_WRITE" => 29,
        "CAP_AUDIT_CONTROL" => 30,
        "CAP_SETFCAP" => 31,
        "CAP_MAC_OVERRIDE" => 32,
        "CAP_MAC_ADMIN" => 33,
        "CAP_SYSLOG" => 34,
        "CAP_WAKE_ALARM" => 35,
        "CAP_BLOCK_SUSPEND" => 36,
        "CAP_AUDIT_READ" => 37,
        "CAP_PERFMON" => 38,
        "CAP_BPF" => 39,
        "CAP_CHECKPOINT_RESTORE" => 40,
        _ => return None,
    })
}

/// OR a list of capability names into a 64-bit mask.
fn mask(names: &[alloc::string::String]) -> u64 {
    let mut m = 0u64;
    for n in names {
        if let Some(b) = cap_bit(n) {
            m |= 1u64 << b;
        }
    }
    m
}

/// Pre-setuid: drop bounding-set caps not requested, and (if we'll drop uid)
/// keep permitted caps across the switch.
pub fn restrict_bounding(caps: &Capabilities, will_switch_uid: bool) {
    let bounding = mask(&caps.bounding);
    for c in 0..=CAP_LAST {
        if bounding & (1u64 << c) == 0 {
            // Already-dropped caps return EINVAL; ignore.
            let _ = sys::prctl(sys::PR_CAPBSET_DROP, c as usize, 0, 0, 0);
        }
    }
    if will_switch_uid {
        let _ = sys::prctl(sys::PR_SET_KEEPCAPS, 1, 0, 0, 0);
    }
}

/// Post-setuid: set permitted/effective/inheritable, then the ambient set.
pub fn apply_after_setuid(caps: &Capabilities) -> Result<(), &'static str> {
    let eff = mask(&caps.effective);
    let prm = mask(&caps.permitted);
    let inh = mask(&caps.inheritable);

    let header = sys::CapHeader {
        version: sys::CAP_VERSION_3,
        pid: 0,
    };
    let data = [
        sys::CapData {
            effective: eff as u32,
            permitted: prm as u32,
            inheritable: inh as u32,
        },
        sys::CapData {
            effective: (eff >> 32) as u32,
            permitted: (prm >> 32) as u32,
            inheritable: (inh >> 32) as u32,
        },
    ];
    sys::capset(&header, &data).map_err(|_| "capset")?;

    // Ambient caps survive execve into a non-root process. Clear, then raise.
    let amb = mask(&caps.ambient);
    let _ = sys::prctl(sys::PR_CAP_AMBIENT, sys::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
    for c in 0..=CAP_LAST {
        if amb & (1u64 << c) != 0 {
            let _ = sys::prctl(
                sys::PR_CAP_AMBIENT,
                sys::PR_CAP_AMBIENT_RAISE,
                c as usize,
                0,
                0,
            );
        }
    }
    Ok(())
}
