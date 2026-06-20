//! On-disk container state — the only thing that survives between the one-shot
//! `zrc` invocations. Stored under `<root>/<id>/state.json` (root defaults to
//! `/run/zrc`, overridable with the global `--root`, as containerd expects).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::json::{self, Value};
use crate::sys;

pub const OCI_VERSION: &str = "1.0.2";
pub const DEFAULT_ROOT: &str = "/run/zrc";

#[derive(Clone, Copy, PartialEq)]
pub enum Status {
    Creating,
    Created,
    Running,
    Stopped,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Creating => "creating",
            Status::Created => "created",
            Status::Running => "running",
            Status::Stopped => "stopped",
        }
    }
    fn parse(s: &str) -> Status {
        match s {
            "creating" => Status::Creating,
            "running" => Status::Running,
            "stopped" => Status::Stopped,
            _ => Status::Created,
        }
    }
}

pub struct State {
    pub id: String,
    pub pid: i32,
    pub bundle: String,
    pub rootfs: String,
    pub fifo: String,
    pub cgroup: String,
    pub status: Status,
}

pub fn state_dir(root: &str, id: &str) -> String {
    format!("{}/{}", root.trim_end_matches('/'), id)
}

fn state_file(root: &str, id: &str) -> String {
    format!("{}/state.json", state_dir(root, id))
}

impl State {
    /// Persist state atomically-ish: write then rename would be ideal, but a
    /// plain truncating write is adequate for one-shot writers under a per-id
    /// directory (no concurrent writers to the same id in practice).
    pub fn save(&self, root: &str) -> Result<(), sys::Errno> {
        sys::write_file(&state_file(root, &self.id), self.to_internal_json().as_bytes(), 0o600)
    }

    pub fn load(root: &str, id: &str) -> Result<State, sys::Errno> {
        let buf = sys::read_file(&state_file(root, id))?;
        let v = json::parse(&buf).map_err(|_| 22)?; // EINVAL on corrupt state
        Ok(State {
            id: v.get("id").and_then(Value::as_str).unwrap_or(id).into(),
            pid: v.get("pid").and_then(Value::as_i64).unwrap_or(0) as i32,
            bundle: v.get("bundle").and_then(Value::as_str).unwrap_or("").into(),
            rootfs: v.get("rootfs").and_then(Value::as_str).unwrap_or("").into(),
            fifo: v.get("fifo").and_then(Value::as_str).unwrap_or("").into(),
            cgroup: v.get("cgroup").and_then(Value::as_str).unwrap_or("").into(),
            status: Status::parse(v.get("status").and_then(Value::as_str).unwrap_or("created")),
        })
    }

    /// Our private persisted form (a superset of the OCI state).
    fn to_internal_json(&self) -> String {
        let mut s = String::new();
        s.push('{');
        push_kv_str(&mut s, "ociVersion", OCI_VERSION, true);
        push_kv_str(&mut s, "id", &self.id, false);
        push_kv_str(&mut s, "status", self.status.as_str(), false);
        push_kv_int(&mut s, "pid", self.pid as i64);
        push_kv_str(&mut s, "bundle", &self.bundle, false);
        push_kv_str(&mut s, "rootfs", &self.rootfs, false);
        push_kv_str(&mut s, "fifo", &self.fifo, false);
        push_kv_str(&mut s, "cgroup", &self.cgroup, false);
        s.push('}');
        s
    }

    /// The exact shape the OCI runtime spec defines for `state` stdout.
    pub fn to_oci_json(&self, status: Status) -> String {
        let mut s = String::new();
        s.push('{');
        push_kv_str(&mut s, "ociVersion", OCI_VERSION, true);
        push_kv_str(&mut s, "id", &self.id, false);
        push_kv_str(&mut s, "status", status.as_str(), false);
        push_kv_int(&mut s, "pid", self.pid as i64);
        push_kv_str(&mut s, "bundle", &self.bundle, false);
        s.push_str(",\"annotations\":{}");
        s.push('}');
        s
    }
}

fn push_kv_str(out: &mut String, key: &str, val: &str, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":\"");
    escape_into(out, val);
    out.push('"');
}

fn push_kv_int(out: &mut String, key: &str, val: i64) {
    out.push_str(",\"");
    out.push_str(key);
    out.push_str("\":");
    let mut buf = itoa(val);
    out.push_str(core::str::from_utf8(&buf).unwrap_or("0"));
    buf.clear();
}

fn escape_into(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

/// `core` has no integer `Display`-to-bytes helper we can borrow cheaply here,
/// so format an `i64` by hand.
fn itoa(mut v: i64) -> Vec<u8> {
    if v == 0 {
        return alloc::vec![b'0'];
    }
    let neg = v < 0;
    // Work in i128 to handle i64::MIN without overflow on negation.
    let mut n = (v as i128).unsigned_abs();
    let _ = &mut v;
    let mut digits = Vec::new();
    while n > 0 {
        digits.push(b'0' + (n % 10) as u8);
        n /= 10;
    }
    if neg {
        digits.push(b'-');
    }
    digits.reverse();
    digits
}
