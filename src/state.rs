//! What survives between zrc invocations: `<root>/<id>/state`, plus the
//! `exec.fifo` that `start` opens to release the init.
//!
//! The state file is private to zrc, so it is not JSON: it is the fields
//! below, each ended by a NUL. Paths cannot contain NUL, so nothing needs
//! escaping and loading borrows the strings straight from the read buffer.

use core::ffi::CStr;

use xorpio::Errno;
use xorpio::fs::{self, OpenHow};
use xorpio::io::{AsRawFd, Fd};
use xorpio::process::Pid;

use crate::io::{Msg, Report, Truncated};
use crate::path::PATH_MAX;

pub const DEFAULT_ROOT: &CStr = c"/run/zrc";
pub const OCI_VERSION: &str = "1.2.0";

const MAGIC: &[u8] = b"zrc1";
const FILE: &CStr = c"state";
const TMP: &CStr = c"state.tmp";
pub const FIFO: &CStr = c"exec.fifo";

/// A container id: one path component of `[A-Za-z0-9_+.-]`, not `.` or `..`.
#[derive(Clone, Copy)]
pub struct Id(pub &'static CStr);

#[derive(Clone, Copy, Debug)]
pub struct InvalidId;

impl Report for InvalidId {
    fn report<const N: usize>(&self, m: &mut Msg<N>) {
        m.str("container ids are 1-255 characters of [A-Za-z0-9_+.-], not '.' or '..'");
    }
}

impl Id {
    pub fn new(id: &'static CStr) -> Result<Self, InvalidId> {
        let b = id.to_bytes();
        let ok = !b.is_empty()
            && b.len() <= 255
            && b != b"."
            && b != b".."
            && b.iter()
                .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'+' | b'.' | b'-'));
        if ok { Ok(Self(id)) } else { Err(InvalidId) }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Created,
    Running,
    Stopped,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Running => "running",
            Self::Stopped => "stopped",
        }
    }
}

/// A container's recorded state.
pub struct State<'a> {
    pub pid: Pid,
    /// The init's start time in clock ticks since boot (`/proc/<pid>/stat`
    /// field 22), which tells it apart from a later process with its pid.
    pub start_time: u64,
    /// `Created` or `Running`; whether it has stopped is checked live.
    pub status: Status,
    pub bundle: &'a CStr,
    pub cgroup: &'a CStr,
}

/// Room for the fields: two paths and some numbers.
pub type Buf = [u8; 2 * PATH_MAX + 64];

/// Opens the state root, creating it (0700) if needed.
pub fn open_root(root: &CStr) -> Result<Fd, Errno> {
    crate::path::open_or_create(
        &fs::CWD,
        root,
        crate::path::Leaf::Dir,
        fs::O_PATH | fs::O_DIRECTORY,
        0,
        0o700,
    )
}

/// Opens an existing container's directory.
pub fn open_dir(root: &Fd, id: Id) -> Result<Fd, Errno> {
    let how = OpenHow {
        flags: u64::from(fs::O_PATH | fs::O_DIRECTORY | fs::O_CLOEXEC),
        mode: 0,
        resolve: fs::resolve::BENEATH | fs::resolve::NO_SYMLINKS,
    };
    fs::openat2(root, id.0, &how)
}

#[derive(Clone, Copy, Debug)]
pub enum LoadError {
    Open(Errno),
    Read(Errno),
    /// The file is not a state file zrc wrote.
    Corrupt,
}

impl Report for LoadError {
    fn report<const N: usize>(&self, m: &mut Msg<N>) {
        match *self {
            Self::Open(e) => m.str("open state: ").errno(e),
            Self::Read(e) => m.str("read state: ").errno(e),
            Self::Corrupt => m.str("state file is corrupt"),
        };
    }
}

impl<'a> State<'a> {
    pub fn load(dir: &Fd, buf: &'a mut Buf) -> Result<Self, LoadError> {
        let f = fs::openat(dir, FILE, fs::O_RDONLY | fs::O_CLOEXEC, 0).map_err(LoadError::Open)?;
        let n = fs::read_full(&f, buf).map_err(LoadError::Read)?;
        let data: &'a [u8] = buf.get(..n).unwrap_or_default();
        let mut fields = data.split_inclusive(|&c| c == 0);
        let mut next = || fields.next().ok_or(LoadError::Corrupt);
        let text = |f: &'a [u8]| f.split_last().map_or(&[][..], |(_, t)| t);
        if text(next()?) != MAGIC {
            return Err(LoadError::Corrupt);
        }
        let pid = parse_u64(text(next()?))
            .and_then(|v| i32::try_from(v).ok())
            .ok_or(LoadError::Corrupt)?;
        let start_time = parse_u64(text(next()?)).ok_or(LoadError::Corrupt)?;
        let status = match text(next()?) {
            b"created" => Status::Created,
            b"running" => Status::Running,
            _ => return Err(LoadError::Corrupt),
        };
        let cstr =
            |f: &'a [u8]| CStr::from_bytes_with_nul(f).map_err(|_interior_nul| LoadError::Corrupt);
        let bundle = cstr(next()?)?;
        let cgroup = cstr(next()?)?;
        Ok(Self {
            pid,
            start_time,
            status,
            bundle,
            cgroup,
        })
    }

    /// Writes the state atomically: to a temporary file, then renamed.
    pub fn save(&self, dir: &Fd) -> Result<(), Errno> {
        let mut m = Msg::<{ 2 * PATH_MAX + 64 }>::new();
        m.bytes(MAGIC).bytes(&[0]);
        m.u64(self.pid as u64).bytes(&[0]);
        m.u64(self.start_time).bytes(&[0]);
        m.str(self.status.as_str()).bytes(&[0]);
        m.bytes(self.bundle.to_bytes_with_nul());
        m.bytes(self.cgroup.to_bytes_with_nul());
        let data = m.finish().map_err(|Truncated| Errno::ENAMETOOLONG)?;
        let f = fs::openat(
            dir,
            TMP,
            fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_CLOEXEC,
            0o600,
        )?;
        xorpio::io::write_all(f.as_raw_fd(), data)?;
        f.close()?;
        fs::renameat(dir, TMP, dir, FILE)
    }
}

/// Removes a container's state files and directory. Files already gone are
/// already removed.
pub fn remove(root: &Fd, id: Id) -> Result<(), Errno> {
    let dir = match open_dir(root, id) {
        Ok(dir) => dir,
        Err(Errno::ENOENT) => return Ok(()),
        Err(e) => return Err(e),
    };
    for name in [FIFO, TMP, FILE] {
        match fs::unlinkat(&dir, name, 0) {
            Ok(()) | Err(Errno::ENOENT) => {}
            Err(e) => return Err(e),
        }
    }
    drop(dir);
    match fs::unlinkat(root, id.0, fs::AT_REMOVEDIR) {
        Ok(()) | Err(Errno::ENOENT) => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn parse_u64(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0u64, |v, &c| {
        if !c.is_ascii_digit() {
            return None;
        }
        v.checked_mul(10)?.checked_add(u64::from(c - b'0'))
    })
}
