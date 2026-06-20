//! A small, allocation-light JSON parser — just enough for OCI `config.json`.
//!
//! Recursive descent over UTF-8 bytes. Numbers are kept as `i64` when integral
//! (uids, namespace types, resource limits are all integers in the spec) and
//! fall back to `f64` otherwise. No streaming, no SIMD — config files are tiny.

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Array(Vec<Value>),
    /// Preserves insertion order; lookups are linear (objects are small).
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Float(f) => Some(*f as i64),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.as_i64().and_then(|i| if i >= 0 { Some(i as u64) } else { None })
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Convenience: array of strings (skips non-strings).
    pub fn as_str_vec(&self) -> Vec<String> {
        match self {
            Value::Array(a) => a
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            _ => Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct ParseError {
    pub at: usize,
    pub msg: &'static str,
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

pub fn parse(input: &[u8]) -> Result<Value, ParseError> {
    let mut p = Parser { b: input, i: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != p.b.len() {
        return Err(p.err("trailing data after JSON value"));
    }
    Ok(v)
}

impl<'a> Parser<'a> {
    fn err(&self, msg: &'static str) -> ParseError {
        ParseError { at: self.i, msg }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn ws(&mut self) {
        while let Some(c) = self.peek() {
            match c {
                b' ' | b'\t' | b'\n' | b'\r' => self.i += 1,
                _ => break,
            }
        }
    }

    fn value(&mut self) -> Result<Value, ParseError> {
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') | Some(b'f') => self.boolean(),
            Some(b'n') => self.null(),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            _ => Err(self.err("expected a JSON value")),
        }
    }

    fn expect(&mut self, c: u8, msg: &'static str) -> Result<(), ParseError> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(self.err(msg))
        }
    }

    fn lit(&mut self, s: &[u8]) -> bool {
        if self.b[self.i..].starts_with(s) {
            self.i += s.len();
            true
        } else {
            false
        }
    }

    fn null(&mut self) -> Result<Value, ParseError> {
        if self.lit(b"null") {
            Ok(Value::Null)
        } else {
            Err(self.err("invalid literal"))
        }
    }

    fn boolean(&mut self) -> Result<Value, ParseError> {
        if self.lit(b"true") {
            Ok(Value::Bool(true))
        } else if self.lit(b"false") {
            Ok(Value::Bool(false))
        } else {
            Err(self.err("invalid literal"))
        }
    }

    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.i;
        let mut is_float = false;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        while let Some(c) = self.peek() {
            match c {
                b'0'..=b'9' => self.i += 1,
                b'.' | b'e' | b'E' | b'+' | b'-' => {
                    is_float = true;
                    self.i += 1;
                }
                _ => break,
            }
        }
        let s = core::str::from_utf8(&self.b[start..self.i]).map_err(|_| self.err("bad number"))?;
        if is_float {
            parse_f64(s)
                .map(Value::Float)
                .ok_or_else(|| self.err("bad float"))
        } else {
            s.parse_i64()
                .map(Value::Int)
                .or_else(|| parse_f64(s).map(Value::Float))
                .ok_or_else(|| self.err("bad integer"))
        }
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.expect(b'"', "expected '\"'")?;
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or_else(|| self.err("unterminated string"))?;
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.peek().ok_or_else(|| self.err("bad escape"))?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'u' => {
                            let cp = self.hex4()?;
                            // Surrogate pair handling.
                            if (0xD800..=0xDBFF).contains(&cp) {
                                if self.peek() == Some(b'\\') {
                                    self.i += 1;
                                    self.expect(b'u', "expected low surrogate")?;
                                    let lo = self.hex4()?;
                                    let c = 0x10000
                                        + (((cp - 0xD800) as u32) << 10)
                                        + (lo - 0xDC00) as u32;
                                    out.push(char::from_u32(c).unwrap_or('\u{FFFD}'));
                                } else {
                                    out.push('\u{FFFD}');
                                }
                            } else {
                                out.push(char::from_u32(cp as u32).unwrap_or('\u{FFFD}'));
                            }
                        }
                        _ => return Err(self.err("invalid escape")),
                    }
                }
                _ => {
                    // Copy this byte and any continuation bytes of a UTF-8 seq.
                    out.push(c as char);
                    // Note: `c as char` only correct for ASCII; handle multibyte:
                    if c >= 0x80 {
                        // Back up and decode the whole code point properly.
                        out.pop();
                        let start = self.i - 1;
                        let len = utf8_len(c);
                        let end = (start + len).min(self.b.len());
                        if let Ok(s) = core::str::from_utf8(&self.b[start..end]) {
                            if let Some(ch) = s.chars().next() {
                                out.push(ch);
                                self.i = start + ch.len_utf8();
                            }
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    fn hex4(&mut self) -> Result<u16, ParseError> {
        let mut v: u16 = 0;
        for _ in 0..4 {
            let c = self.peek().ok_or_else(|| self.err("bad \\u escape"))?;
            self.i += 1;
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return Err(self.err("bad hex digit")),
            };
            v = (v << 4) | d as u16;
        }
        Ok(v)
    }

    fn array(&mut self) -> Result<Value, ParseError> {
        self.expect(b'[', "expected '['")?;
        let mut out = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Array(out));
        }
        loop {
            self.ws();
            out.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
        Ok(Value::Array(out))
    }

    fn object(&mut self) -> Result<Value, ParseError> {
        self.expect(b'{', "expected '{'")?;
        let mut out: Vec<(String, Value)> = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Object(out));
        }
        loop {
            self.ws();
            let key = self.string()?;
            self.ws();
            self.expect(b':', "expected ':'")?;
            self.ws();
            let val = self.value()?;
            out.push((key, val));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
        Ok(Value::Object(out))
    }
}

fn utf8_len(lead: u8) -> usize {
    if lead < 0x80 {
        1
    } else if lead >> 5 == 0b110 {
        2
    } else if lead >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

// `core` has no `f64::from_str`, so we provide a small (lossy-tolerant) parser.
fn parse_f64(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    let mut i = 0;
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let mut mant: f64 = 0.0;
    let mut any = false;
    while i < b.len() && b[i].is_ascii_digit() {
        mant = mant * 10.0 + (b[i] - b'0') as f64;
        i += 1;
        any = true;
    }
    if i < b.len() && b[i] == b'.' {
        i += 1;
        let mut scale = 0.1;
        while i < b.len() && b[i].is_ascii_digit() {
            mant += (b[i] - b'0') as f64 * scale;
            scale *= 0.1;
            i += 1;
            any = true;
        }
    }
    if !any {
        return None;
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        i += 1;
        let mut eneg = false;
        if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
            eneg = b[i] == b'-';
            i += 1;
        }
        let mut exp: i32 = 0;
        while i < b.len() && b[i].is_ascii_digit() {
            exp = exp * 10 + (b[i] - b'0') as i32;
            i += 1;
        }
        let mut p = 1.0f64;
        for _ in 0..exp {
            p *= 10.0;
        }
        mant = if eneg { mant / p } else { mant * p };
    }
    if i != b.len() {
        return None;
    }
    Some(if neg { -mant } else { mant })
}

// `str::parse::<i64>` exists in core, but go through a tiny helper trait so the
// number path reads cleanly and we control overflow behavior.
trait ParseI64 {
    fn parse_i64(&self) -> Option<i64>;
}

impl ParseI64 for str {
    fn parse_i64(&self) -> Option<i64> {
        let b = self.as_bytes();
        if b.is_empty() {
            return None;
        }
        let (neg, digits) = if b[0] == b'-' {
            (true, &b[1..])
        } else {
            (false, b)
        };
        if digits.is_empty() {
            return None;
        }
        let mut v: i64 = 0;
        for &c in digits {
            if !c.is_ascii_digit() {
                return None;
            }
            v = v.checked_mul(10)?.checked_add((c - b'0') as i64)?;
        }
        Some(if neg { -v } else { v })
    }
}
