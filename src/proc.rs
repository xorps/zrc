//! Process identity and liveness from `/proc/<pid>/stat`.

use xorpio::Errno;
use xorpio::fs;
use xorpio::io::Fd;
use xorpio::process::{self, Pid};

use crate::io::Msg;
use crate::state::parse_u64;

/// The fields zrc reads from `/proc/<pid>/stat`.
pub struct Stat {
    /// `R`, `S`, `Z`, ...
    pub state: u8,
    /// Clock ticks after boot when the process started.
    pub start_time: u64,
}

pub fn stat(pid: Pid) -> Result<Stat, Errno> {
    let mut path = Msg::<32>::new();
    path.str("/proc/").i64(pid as i64).str("/stat").bytes(&[0]);
    let path = path.c_str().ok_or(Errno::ENAMETOOLONG)?;
    let f = fs::openat(&fs::CWD, path, fs::O_RDONLY | fs::O_CLOEXEC, 0)?;
    let mut buf = [0u8; 1024];
    let n = fs::read_full(&f, &mut buf)?;
    let text = buf.get(..n).unwrap_or_default();
    // The command name in field 2 may itself contain spaces and parens, so
    // the fields are counted from the last ')'.
    let after = text.iter().rposition(|&c| c == b')').ok_or(Errno::EINVAL)?;
    let mut fields = text
        .get(after + 1..)
        .unwrap_or_default()
        .split(|&c| c == b' ')
        .filter(|f| !f.is_empty());
    let state = fields
        .next()
        .and_then(|f| f.first().copied())
        .ok_or(Errno::EINVAL)?;
    // Field 3 was the state; field 22 is the start time.
    let start_time = fields.nth(18).and_then(parse_u64).ok_or(Errno::EINVAL)?;
    Ok(Stat { state, start_time })
}

/// A live handle on a container's init.
pub enum Init {
    /// Running (or stopped by a signal, but not exited).
    Alive(Fd),
    /// Exited, or its pid now belongs to another process.
    Gone,
}

/// Finds the process `pid` if it is still the one that started at
/// `start_time`. The pidfd keeps that identity from changing afterwards.
pub fn find(pid: Pid, start_time: u64) -> Result<Init, Errno> {
    // A state written before the init was cloned.
    if pid <= 0 {
        return Ok(Init::Gone);
    }
    let pidfd = match process::pidfd_open(pid) {
        Ok(fd) => fd,
        Err(Errno::ESRCH) => return Ok(Init::Gone),
        Err(e) => return Err(e),
    };
    match stat(pid) {
        Ok(st) if st.start_time == start_time && st.state != b'Z' && st.state != b'X' => {
            Ok(Init::Alive(pidfd))
        }
        Ok(_) | Err(Errno::ENOENT) | Err(Errno::ESRCH) => Ok(Init::Gone),
        Err(e) => Err(e),
    }
}
