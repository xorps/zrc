//! Confined path walking: creating the missing directories of a path below a
//! directory, with every lookup resolved by `openat2` so symlinks cannot lead
//! outside it.

use core::ffi::CStr;

use xorpio::Errno;
use xorpio::fs::{self, OpenHow};
use xorpio::io::{AsRawFd, Fd, RawFd};

use crate::fixed::{Fixed, Full};

/// `PATH_MAX`: the kernel copies no longer path.
pub const PATH_MAX: usize = 4096;

/// A path copied into a stack buffer so it can be cut into NUL-terminated
/// pieces. Only needed when directories must be created; otherwise paths go
/// to the kernel as they are.
struct PathBuf {
    buf: [u8; PATH_MAX],
    len: usize,
}

impl PathBuf {
    fn new(path: &[u8]) -> Result<Self, Errno> {
        let mut buf = [0u8; PATH_MAX];
        // One byte stays free for the NUL.
        if path.len() >= PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        if let Some(dst) = buf.get_mut(..path.len()) {
            crate::fixed::copy(dst, path);
        }
        Ok(Self {
            buf,
            len: path.len(),
        })
    }

    /// `(start, end)` of each component, skipping empty ones.
    fn components(&self) -> Result<Fixed<(u16, u16), { PATH_MAX / 2 }>, Errno> {
        let mut out = Fixed::new();
        let mut start = 0;
        let path = self.buf.get(..self.len).unwrap_or_default();
        // A virtual `/` after the end closes the last component.
        let ends = path
            .iter()
            .enumerate()
            .map(|(i, &c)| (i, c))
            .chain([(self.len, b'/')]);
        for (i, c) in ends {
            if c == b'/' {
                if i > start {
                    out.push((start as u16, i as u16))
                        .map_err(|Full| Errno::ENAMETOOLONG)?;
                }
                start = i + 1;
            }
        }
        Ok(out)
    }

    /// Runs `f` on `buf[start..end]` as a C string, NUL-terminating it in
    /// place for the duration of the call.
    fn with<T>(
        &mut self,
        start: usize,
        end: usize,
        f: impl FnOnce(&CStr) -> T,
    ) -> Result<T, Errno> {
        let saved = *self.buf.get(end).ok_or(Errno::ENAMETOOLONG)?;
        if let Some(b) = self.buf.get_mut(end) {
            *b = 0;
        }
        let out = self
            .buf
            .get(start..=end)
            .and_then(|b| CStr::from_bytes_with_nul(b).ok())
            .map(f);
        if let Some(b) = self.buf.get_mut(end) {
            *b = saved;
        }
        // Only a NUL inside the path itself makes the conversion fail.
        out.ok_or(Errno::EINVAL)
    }
}

/// How the final component is created if it is missing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Leaf {
    Dir,
    /// An empty 0644 file.
    File,
    /// `mknod` with this mode (type and permissions) and device number.
    Node {
        mode: u32,
        dev: u32,
    },
}

/// Opens `path` below `root` with `flags`, creating it and any missing
/// parent directories (`mode`) and the final component as `leaf`. Every
/// lookup is confined by `resolve` (e.g. `RESOLVE_IN_ROOT`).
pub fn open_or_create(
    root: &impl AsRawFd,
    path: &CStr,
    leaf: Leaf,
    flags: u32,
    resolve: u64,
    mode: u32,
) -> Result<Fd, Errno> {
    let how = OpenHow {
        flags: u64::from(flags | fs::O_CLOEXEC),
        mode: 0,
        resolve,
    };
    match fs::openat2(root, path, &how) {
        Err(Errno::ENOENT) => {}
        found => return found,
    }
    let dir_how = OpenHow {
        flags: u64::from(fs::O_PATH | fs::O_DIRECTORY | fs::O_CLOEXEC),
        ..how
    };
    let mut buf = PathBuf::new(path.to_bytes())?;
    let parts = buf.components()?;
    // Names are created in their parent; an absolute path starts at `/`,
    // which `resolve` may map to `root` itself.
    let mut parent: Option<Fd> = match path.to_bytes().first() {
        Some(b'/') => Some(fs::openat2(root, c"/", &dir_how)?),
        _ => None,
    };
    for (i, &(start, end)) in parts.iter().enumerate() {
        let (start, end) = (start as usize, end as usize);
        let last = i + 1 == parts.len();
        // Create one name inside the parent, which was opened confined.
        let created = buf.with(start, end, |name| {
            let dir: RawFd = parent.as_ref().map_or(root.as_raw_fd(), Fd::as_raw_fd);
            match leaf {
                Leaf::File if last => fs::mknodat(&dir, name, fs::S_IFREG | 0o644, 0),
                Leaf::Node { mode, dev } if last => fs::mknodat(&dir, name, mode, dev),
                _ => fs::mkdirat(&dir, name, mode),
            }
        })?;
        match created {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(e) => return Err(e),
        }
        if !last {
            parent = Some(buf.with(0, end, |prefix| fs::openat2(root, prefix, &dir_how))??);
        }
    }
    fs::openat2(root, path, &how)
}
