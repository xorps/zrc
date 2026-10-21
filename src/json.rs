//! An in-place, zero-copy JSON pull parser.
//!
//! The parser consumes a mutable buffer front to back. Each string is
//! unescaped where it sits (an escape is never shorter than what it decodes
//! to) and NUL-terminated over its closing quote, then split off and handed
//! out as a `&CStr` that borrows the buffer: no string is ever copied, and
//! the result can go straight to a syscall.
//!
//! The caller drives the parse with the shape it expects, using [`Object`]
//! and [`Array`] cursors and calling [`Parser::skip`] for values it ignores,
//! which still validates them.

use core::ffi::CStr;
use core::mem;

use crate::io::{Msg, Report};

/// What was wrong, and the byte offset where it was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub at: usize,
    pub kind: ErrorKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    UnexpectedEnd,
    /// Something other than the expected token.
    Expected(&'static str),
    InvalidEscape,
    /// A control character inside a string.
    ControlChar,
    /// `\u0000`, which a C string cannot hold.
    EmbeddedNul,
    /// A number that is not an integer of the expected type.
    InvalidInteger,
    TooDeep,
    TrailingData,
}

impl Report for Error {
    fn report<const N: usize>(&self, m: &mut Msg<N>) {
        match self.kind {
            ErrorKind::UnexpectedEnd => m.str("unexpected end of input"),
            ErrorKind::Expected(what) => m.str("expected ").str(what),
            ErrorKind::InvalidEscape => m.str("invalid escape sequence"),
            ErrorKind::ControlChar => m.str("control character in string"),
            ErrorKind::EmbeddedNul => m.str("string contains \\u0000"),
            ErrorKind::InvalidInteger => m.str("integer expected or out of range"),
            ErrorKind::TooDeep => m.str("nested too deeply"),
            ErrorKind::TrailingData => m.str("data after the top-level value"),
        };
        m.str(" at byte ").u64(self.at as u64);
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// The deepest nesting [`Parser::skip`] accepts.
const MAX_DEPTH: u32 = 128;

pub struct Parser<'a> {
    rest: &'a mut [u8],
    /// Offset of `rest` within the original buffer, for error positions.
    at: usize,
}

impl<'a> Parser<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { rest: buf, at: 0 }
    }

    #[inline]
    fn err(&self, kind: ErrorKind) -> Error {
        Error { at: self.at, kind }
    }

    /// The byte offset of the next token, for error messages.
    pub fn offset(&mut self) -> usize {
        self.ws();
        self.at
    }

    /// The first byte of the next value, without consuming it.
    pub fn peek_token(&mut self) -> Result<u8> {
        self.next_token()
    }

    #[inline]
    fn peek(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    /// Drops `n` bytes from the front.
    #[inline]
    fn advance(&mut self, n: usize) {
        let rest = mem::take(&mut self.rest);
        let n = n.min(rest.len());
        self.rest = rest.get_mut(n..).unwrap_or_default();
        self.at += n;
    }

    fn ws(&mut self) {
        let n = self
            .rest
            .iter()
            .position(|&c| !matches!(c, b' ' | b'\t' | b'\n' | b'\r'))
            .unwrap_or(self.rest.len());
        self.advance(n);
    }

    /// Skips whitespace and returns the next byte without consuming it.
    fn next_token(&mut self) -> Result<u8> {
        self.ws();
        self.peek().ok_or(self.err(ErrorKind::UnexpectedEnd))
    }

    fn expect(&mut self, byte: u8, what: &'static str) -> Result<()> {
        if self.next_token()? != byte {
            return Err(self.err(ErrorKind::Expected(what)));
        }
        self.advance(1);
        Ok(())
    }

    fn literal(&mut self, word: &[u8]) -> Result<()> {
        if !self.rest.starts_with(word) {
            return Err(self.err(ErrorKind::Expected("a value")));
        }
        self.advance(word.len());
        Ok(())
    }

    /// Checks that only whitespace remains.
    pub fn end(mut self) -> Result<()> {
        self.ws();
        match self.peek() {
            None => Ok(()),
            Some(_) => Err(self.err(ErrorKind::TrailingData)),
        }
    }

    /// Consumes `null` if it is next. OCI treats an explicit `null` like an
    /// absent field.
    pub fn null(&mut self) -> Result<bool> {
        if self.next_token()? == b'n' {
            self.literal(b"null")?;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn bool(&mut self) -> Result<bool> {
        match self.next_token()? {
            b't' => self.literal(b"true").map(|()| true),
            b'f' => self.literal(b"false").map(|()| false),
            _ => Err(self.err(ErrorKind::Expected("true or false"))),
        }
    }

    /// The span of a number's text, validated against the JSON grammar.
    fn number_len(&self) -> Result<usize> {
        let b = &*self.rest;
        let digits = |from: usize| {
            b.get(from..)
                .unwrap_or_default()
                .iter()
                .take_while(|c| c.is_ascii_digit())
                .count()
        };
        let mut i = usize::from(b.first() == Some(&b'-'));
        let int = digits(i);
        if int == 0 || (int > 1 && b.get(i) == Some(&b'0')) {
            return Err(self.err(ErrorKind::Expected("a number")));
        }
        i += int;
        if b.get(i) == Some(&b'.') {
            let frac = digits(i + 1);
            if frac == 0 {
                return Err(self.err(ErrorKind::Expected("a number")));
            }
            i += 1 + frac;
        }
        if matches!(b.get(i), Some(b'e' | b'E')) {
            i += 1;
            if matches!(b.get(i), Some(b'+' | b'-')) {
                i += 1;
            }
            let exp = digits(i);
            if exp == 0 {
                return Err(self.err(ErrorKind::Expected("a number")));
            }
            i += exp;
        }
        Ok(i)
    }

    /// An integer in `i64` range, without fraction or exponent.
    pub fn i64(&mut self) -> Result<i64> {
        self.ws();
        let len = self.number_len()?;
        let text = self.rest.get(..len).unwrap_or_default();
        let (neg, digits) = match text.split_first() {
            Some((b'-', rest)) => (true, rest),
            _ => (false, text),
        };
        let mut v: i64 = 0;
        for &c in digits {
            if !c.is_ascii_digit() {
                return Err(self.err(ErrorKind::InvalidInteger));
            }
            let d = i64::from(c - b'0');
            v = v
                .checked_mul(10)
                .and_then(|v| {
                    if neg {
                        v.checked_sub(d)
                    } else {
                        v.checked_add(d)
                    }
                })
                .ok_or(self.err(ErrorKind::InvalidInteger))?;
        }
        self.advance(len);
        Ok(v)
    }

    /// A non-negative integer up to `u64::MAX`.
    pub fn u64(&mut self) -> Result<u64> {
        self.ws();
        let len = self.number_len()?;
        let text = self.rest.get(..len).unwrap_or_default();
        let mut v: u64 = 0;
        for &c in text {
            if !c.is_ascii_digit() {
                return Err(self.err(ErrorKind::InvalidInteger));
            }
            v = v
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(c - b'0')))
                .ok_or(self.err(ErrorKind::InvalidInteger))?;
        }
        self.advance(len);
        Ok(v)
    }

    pub fn u32(&mut self) -> Result<u32> {
        let at = self.at;
        let v = self.u64()?;
        u32::try_from(v).map_err(|_too_big| Error {
            at,
            kind: ErrorKind::InvalidInteger,
        })
    }

    /// A string, unescaped in place, as the mutable bytes including the
    /// terminating NUL. Callers may rewrite bytes before the NUL.
    pub fn string_mut(&mut self) -> Result<&'a mut [u8]> {
        self.expect(b'"', "a string")?;
        let buf = &mut *self.rest;
        let (mut r, mut w) = (0usize, 0usize);
        let at = self.at;
        let fail = |off: usize, kind| Error { at: at + off, kind };
        loop {
            let c = *buf.get(r).ok_or(fail(r, ErrorKind::UnexpectedEnd))?;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = *buf.get(r + 1).ok_or(fail(r, ErrorKind::UnexpectedEnd))?;
                    let simple = match e {
                        b'"' => Some(b'"'),
                        b'\\' => Some(b'\\'),
                        b'/' => Some(b'/'),
                        b'b' => Some(0x08),
                        b'f' => Some(0x0c),
                        b'n' => Some(b'\n'),
                        b'r' => Some(b'\r'),
                        b't' => Some(b'\t'),
                        b'u' => None,
                        _ => return Err(fail(r, ErrorKind::InvalidEscape)),
                    };
                    if let Some(byte) = simple {
                        put(buf, &mut w, &[byte]);
                        r += 2;
                        continue;
                    }
                    let (ch, used) =
                        unicode_escape(buf, r).ok_or(fail(r, ErrorKind::InvalidEscape))?;
                    if ch == '\0' {
                        return Err(fail(r, ErrorKind::EmbeddedNul));
                    }
                    let mut utf8 = [0u8; 4];
                    put(buf, &mut w, ch.encode_utf8(&mut utf8).as_bytes());
                    r += used;
                }
                0..0x20 => return Err(fail(r, ErrorKind::ControlChar)),
                _ => {
                    put(buf, &mut w, &[c]);
                    r += 1;
                }
            }
        }
        // `w <= r`, so the NUL lands at or before the closing quote at `r`.
        if let Some(nul) = buf.get_mut(w) {
            *nul = 0;
        }
        let rest = mem::take(&mut self.rest);
        let (head, tail) = rest.split_at_mut(r.saturating_add(1).min(rest.len()));
        self.rest = tail;
        self.at += head.len();
        head.get_mut(..=w).ok_or(fail(r, ErrorKind::UnexpectedEnd))
    }

    /// A string, unescaped in place.
    pub fn str(&mut self) -> Result<&'a CStr> {
        let at = self.at;
        let bytes = self.string_mut()?;
        CStr::from_bytes_with_nul(bytes).map_err(|_interior_nul| Error {
            at,
            kind: ErrorKind::EmbeddedNul,
        })
    }

    pub fn object(&mut self) -> Result<Object> {
        self.expect(b'{', "an object")?;
        Ok(Object { first: true })
    }

    pub fn array(&mut self) -> Result<Array> {
        self.expect(b'[', "an array")?;
        Ok(Array { first: true })
    }

    /// Skips one value of any type, checking that it is well formed.
    pub fn skip(&mut self) -> Result<()> {
        // One bit per open container: 1 for an object, 0 for an array.
        let mut stack: u128 = 0;
        let mut depth: u32 = 0;
        // Set after a value: the next token must be `,` or a closing bracket.
        let mut after_value = false;
        loop {
            if after_value && depth == 0 {
                return Ok(());
            }
            let c = self.next_token()?;
            if after_value {
                let in_object = stack & 1 == 1;
                match (c, in_object) {
                    (b',', true) => {
                        self.advance(1);
                        self.str()?;
                        self.expect(b':', "':'")?;
                        after_value = false;
                    }
                    (b',', false) => {
                        self.advance(1);
                        after_value = false;
                    }
                    (b'}', true) | (b']', false) => {
                        self.advance(1);
                        stack >>= 1;
                        depth -= 1;
                    }
                    _ => return Err(self.err(ErrorKind::Expected("',' or a closing bracket"))),
                }
                continue;
            }
            match c {
                b'{' | b'[' => {
                    if depth == MAX_DEPTH {
                        return Err(self.err(ErrorKind::TooDeep));
                    }
                    self.advance(1);
                    let object = c == b'{';
                    stack = (stack << 1) | u128::from(object);
                    depth += 1;
                    let close = if object { b'}' } else { b']' };
                    if self.next_token()? == close {
                        self.advance(1);
                        stack >>= 1;
                        depth -= 1;
                        after_value = true;
                    } else if object {
                        self.str()?;
                        self.expect(b':', "':'")?;
                    }
                    continue;
                }
                b'"' => {
                    self.string_mut()?;
                }
                b't' => self.literal(b"true")?,
                b'f' => self.literal(b"false")?,
                b'n' => self.literal(b"null")?,
                _ => {
                    let len = self.number_len()?;
                    self.advance(len);
                }
            }
            after_value = true;
        }
    }
}

/// Writes `bytes` at `*w` and advances it. The caller guarantees the write
/// stays behind the read position.
#[inline]
fn put(buf: &mut [u8], w: &mut usize, bytes: &[u8]) {
    if let Some(dst) = buf.get_mut(*w..*w + bytes.len()) {
        crate::fixed::copy(dst, bytes);
    }
    *w += bytes.len();
}

fn hex4(buf: &[u8], at: usize) -> Option<u32> {
    let digits = buf.get(at..at + 4)?;
    let mut v = 0u32;
    for &c in digits {
        v = (v << 4) | char::from(c).to_digit(16)?;
    }
    Some(v)
}

/// Decodes `\uXXXX`, or a `\uXXXX\uXXXX` surrogate pair, starting at the
/// backslash at `r`. Returns the character and the bytes consumed.
fn unicode_escape(buf: &[u8], r: usize) -> Option<(char, usize)> {
    let hi = hex4(buf, r + 2)?;
    if !(0xD800..0xDC00).contains(&hi) {
        return char::from_u32(hi).map(|c| (c, 6));
    }
    if buf.get(r + 6..r + 8)? != b"\\u" {
        return None;
    }
    let lo = hex4(buf, r + 8)?;
    if !(0xDC00..0xE000).contains(&lo) {
        return None;
    }
    char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)).map(|c| (c, 12))
}

/// Iterates the keys of an object; read or skip each value before asking for
/// the next key. Keys whose value is `null` are skipped, as OCI treats them
/// like absent keys.
pub struct Object {
    first: bool,
}

impl Object {
    pub fn next<'a>(&mut self, p: &mut Parser<'a>) -> Result<Option<&'a CStr>> {
        let at = p.at;
        match self.next_mut(p)? {
            None => Ok(None),
            Some(key) => CStr::from_bytes_with_nul(key)
                .map(Some)
                .map_err(|_interior_nul| Error {
                    at,
                    kind: ErrorKind::EmbeddedNul,
                }),
        }
    }

    /// Like [`next`](Self::next), but hands out the key's bytes, NUL
    /// included, for rewriting in place.
    pub fn next_mut<'a>(&mut self, p: &mut Parser<'a>) -> Result<Option<&'a mut [u8]>> {
        loop {
            let c = p.next_token()?;
            if c == b'}' {
                p.advance(1);
                return Ok(None);
            }
            if !mem::take(&mut self.first) {
                if c != b',' {
                    return Err(p.err(ErrorKind::Expected("',' or '}'")));
                }
                p.advance(1);
            }
            let key = p.string_mut()?;
            p.expect(b':', "':'")?;
            if !p.null()? {
                return Ok(Some(key));
            }
        }
    }
}

/// Iterates the elements of an array; `next` returns `true` when an element
/// follows, which the caller must then read or skip.
pub struct Array {
    first: bool,
}

impl Array {
    pub fn next(&mut self, p: &mut Parser<'_>) -> Result<bool> {
        let c = p.next_token()?;
        if c == b']' {
            p.advance(1);
            return Ok(false);
        }
        if !mem::take(&mut self.first) {
            if c != b',' {
                return Err(p.err(ErrorKind::Expected("',' or ']'")));
            }
            p.advance(1);
        }
        Ok(true)
    }
}
