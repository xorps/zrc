//! Message output without `core::fmt`: text is assembled in a stack buffer
//! and written with a single `write(2)`, so a line of up to `PIPE_BUF` bytes
//! reaches a pipe atomically.

use core::ffi::CStr;

use xorpio::Errno;
use xorpio::io::{RawFd, STDERR, write_all};

/// `PIPE_BUF`: the largest write a pipe delivers atomically.
pub const LINE: usize = 4096;

/// A byte buffer that remembers whether anything failed to fit.
pub struct Msg<const N: usize> {
    buf: [u8; N],
    len: usize,
    truncated: bool,
}

/// The output did not fit in its buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Truncated;

impl<const N: usize> Msg<N> {
    pub const fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
            truncated: false,
        }
    }

    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        let room = N - self.len;
        let n = b.len().min(room);
        if let (Some(dst), Some(src)) = (self.buf.get_mut(self.len..self.len + n), b.get(..n)) {
            crate::fixed::copy(dst, src);
            self.len += n;
        }
        self.truncated |= n < b.len();
        self
    }

    #[inline]
    pub fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    #[inline]
    pub fn cstr(&mut self, s: &CStr) -> &mut Self {
        self.bytes(s.to_bytes())
    }

    pub fn u64(&mut self, mut v: u64) -> &mut Self {
        let mut digits = [0u8; 20];
        let mut i = digits.len();
        loop {
            i -= 1;
            if let Some(d) = digits.get_mut(i) {
                *d = b'0' + (v % 10) as u8;
            }
            v /= 10;
            if v == 0 || i == 0 {
                break;
            }
        }
        self.bytes(digits.get(i..).unwrap_or_default())
    }

    pub fn i64(&mut self, v: i64) -> &mut Self {
        if v < 0 {
            self.bytes(b"-");
        }
        self.u64(v.unsigned_abs())
    }

    /// `ENOENT`, or `errno 1234` for numbers without a name.
    pub fn errno(&mut self, e: Errno) -> &mut Self {
        match e.name() {
            Some(name) => self.str(name),
            None => self.str("errno ").i64(e.raw() as i64),
        }
    }

    /// `b` as a JSON string, with quotes. Bytes from 0x80 up pass through,
    /// so valid UTF-8 stays valid.
    pub fn json_str(&mut self, b: &[u8]) -> &mut Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.bytes(b"\"");
        for &c in b {
            match c {
                b'"' => self.bytes(b"\\\""),
                b'\\' => self.bytes(b"\\\\"),
                b'\n' => self.bytes(b"\\n"),
                b'\r' => self.bytes(b"\\r"),
                b'\t' => self.bytes(b"\\t"),
                0..0x20 => self.bytes(&[
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    HEX[(c >> 4) as usize],
                    HEX[(c & 0xf) as usize],
                ]),
                _ => self.bytes(&[c]),
            };
        }
        self.bytes(b"\"")
    }

    /// The contents as a C string, if they fit and end in the one NUL.
    pub fn c_str(&self) -> Option<&CStr> {
        CStr::from_bytes_with_nul(self.finish().ok()?).ok()
    }

    /// The contents, or `Truncated` if anything was cut off.
    pub fn finish(&self) -> Result<&[u8], Truncated> {
        if self.truncated {
            return Err(Truncated);
        }
        Ok(self.buf.get(..self.len).unwrap_or_default())
    }

    /// Writes the contents to `fd`, ending a cut-off message with `...`.
    pub fn write_to(&mut self, fd: RawFd) -> Result<(), Errno> {
        if self.truncated {
            let start = self.len.saturating_sub(4);
            if let Some(tail) = self.buf.get_mut(start..self.len) {
                crate::fixed::copy(tail, b"...\n");
            }
        }
        write_all(fd, self.buf.get(..self.len).unwrap_or_default())
    }
}

/// An error that can describe itself.
pub trait Report {
    fn report<const N: usize>(&self, m: &mut Msg<N>);
}

impl Report for Errno {
    fn report<const N: usize>(&self, m: &mut Msg<N>) {
        m.errno(*self);
    }
}

/// Writes `zrc: <context>: <err>` to stderr.
pub fn fail(context: &str, err: &impl Report) {
    let mut m = Msg::<LINE>::new();
    m.str("zrc: ").str(context).str(": ");
    err.report(&mut m);
    m.str("\n");
    // Nothing is left to tell about a failure to write to stderr; the exit
    // status still reports the original error.
    let _ = m.write_to(STDERR);
}
