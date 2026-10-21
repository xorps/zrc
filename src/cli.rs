//! Command-line parsing, following runc's surface: global options, then a
//! command with its own options and operands. Flags take values as
//! `--flag value` or `--flag=value`.

use core::ffi::CStr;

use xorpio::process::{CStrs, sig};

use crate::container::{CreateArgs, RunArgs};
use crate::io::{Msg, Report};
use crate::oci::Str;
use crate::state::{self, Id};

pub enum Command {
    Create(CreateArgs),
    Run(RunArgs),
    Start {
        root: Str,
        id: Id,
    },
    State {
        root: Str,
        id: Id,
    },
    Kill {
        root: Str,
        id: Id,
        signal: i32,
        all: bool,
    },
    Delete {
        root: Str,
        id: Id,
        force: bool,
    },
    Version,
    Help,
}

#[derive(Clone, Copy, Debug)]
pub enum UsageError {
    UnknownCommand(Str),
    UnknownFlag(Str),
    MissingValue(Str),
    MissingId(&'static str),
    ExtraOperand(Str),
    InvalidId(Str),
    UnknownSignal(Str),
    Unsupported(&'static str),
}

impl Report for UsageError {
    fn report<const N: usize>(&self, m: &mut Msg<N>) {
        match *self {
            Self::UnknownCommand(c) => m.str("unknown command '").cstr(c).str("' (see zrc --help)"),
            Self::UnknownFlag(f) => m.str("unknown option '").cstr(f).str("'"),
            Self::MissingValue(f) => m.str("option '").cstr(f).str("' needs a value"),
            Self::MissingId(cmd) => m.str(cmd).str(" needs a container id"),
            Self::ExtraOperand(a) => m.str("unexpected argument '").cstr(a).str("'"),
            Self::InvalidId(id) => {
                m.str("invalid container id '").cstr(id).str("': ");
                state::InvalidId.report(m);
                m
            }
            Self::UnknownSignal(s) => m.str("unknown signal '").cstr(s).str("'"),
            Self::Unsupported(f) => m.str(f).str(" is not supported"),
        };
    }
}

type Result<T> = core::result::Result<T, UsageError>;

enum Tok {
    /// `name` without dashes or `=value`; `inline` is the `=value` part.
    Flag {
        raw: Str,
        name: &'static [u8],
        inline: Option<Str>,
    },
    Operand(Str),
}

struct Tokens {
    args: CStrs,
    next: usize,
    /// After `--` everything is an operand.
    operands_only: bool,
}

impl Tokens {
    fn next(&mut self) -> Option<Tok> {
        let raw = self.args.get(self.next)?;
        self.next += 1;
        let b = raw.to_bytes();
        if self.operands_only || b.len() < 2 || b.first() != Some(&b'-') {
            return Some(Tok::Operand(raw));
        }
        if b == b"--" {
            self.operands_only = true;
            return self.next();
        }
        let body = b.strip_prefix(b"--").or(b.strip_prefix(b"-")).unwrap_or(b);
        let (name, inline) = match body.iter().position(|&c| c == b'=') {
            // The value shares the argument's terminating NUL: no copy.
            Some(eq) => (
                body.get(..eq).unwrap_or_default(),
                raw.to_bytes_with_nul()
                    .get(b.len() - body.len() + eq + 1..)
                    .and_then(|v| CStr::from_bytes_with_nul(v).ok()),
            ),
            None => (body, None),
        };
        Some(Tok::Flag { raw, name, inline })
    }

    /// The value of flag `raw`: inline, or the next argument.
    fn value(&mut self, raw: Str, inline: Option<Str>) -> Result<Str> {
        if let Some(v) = inline {
            return Ok(v);
        }
        let v = self
            .args
            .get(self.next)
            .ok_or(UsageError::MissingValue(raw))?;
        self.next += 1;
        Ok(v)
    }
}

fn id(operand: Option<Str>, cmd: &'static str) -> Result<Id> {
    let raw = operand.ok_or(UsageError::MissingId(cmd))?;
    Id::new(raw).map_err(|state::InvalidId| UsageError::InvalidId(raw))
}

pub fn parse(args: CStrs) -> Result<Command> {
    let mut t = Tokens {
        args,
        next: 1,
        operands_only: false,
    };
    let mut root = state::DEFAULT_ROOT;
    let cmd = loop {
        match t.next() {
            None => return Ok(Command::Help),
            Some(Tok::Operand(cmd)) => break cmd,
            Some(Tok::Flag { raw, name, inline }) => match name {
                b"root" => root = t.value(raw, inline)?,
                // Logging destinations: zrc writes its errors to stderr.
                b"log" | b"log-format" => {
                    t.value(raw, inline)?;
                }
                b"debug" => {}
                b"systemd-cgroup" => return Err(UsageError::Unsupported("--systemd-cgroup")),
                b"h" | b"help" => return Ok(Command::Help),
                b"v" | b"version" => return Ok(Command::Version),
                _ => return Err(UsageError::UnknownFlag(raw)),
            },
        }
    };

    let mut operands: [Option<Str>; 2] = [None; 2];
    let mut n_operands = 0;
    let mut bundle: Str = c".";
    let mut pid_file = None;
    let (mut all, mut force) = (false, false);
    let verb = cmd.to_bytes();
    while let Some(tok) = t.next() {
        match tok {
            Tok::Operand(op) => {
                let slot = operands
                    .get_mut(n_operands)
                    .ok_or(UsageError::ExtraOperand(op))?;
                *slot = Some(op);
                n_operands += 1;
            }
            Tok::Flag { raw, name, inline } => match (verb, name) {
                (b"create" | b"run", b"b" | b"bundle") => bundle = t.value(raw, inline)?,
                (b"create", b"pid-file") => pid_file = Some(t.value(raw, inline)?),
                // zrc never creates a session keyring to begin with.
                (b"create" | b"run", b"no-new-keyring") => {}
                (b"create" | b"run", b"console-socket") => {
                    return Err(UsageError::Unsupported("--console-socket"));
                }
                (b"create" | b"run", b"no-pivot") => {
                    return Err(UsageError::Unsupported("--no-pivot"));
                }
                (b"create" | b"run", b"preserve-fds") => {
                    if t.value(raw, inline)?.to_bytes() != b"0" {
                        return Err(UsageError::Unsupported("--preserve-fds"));
                    }
                }
                (b"kill", b"a" | b"all") => all = true,
                (b"delete", b"f" | b"force") => force = true,
                _ => return Err(UsageError::UnknownFlag(raw)),
            },
        }
    }
    let [first, second] = operands;
    let only_id = |cmd| {
        if let Some(extra) = second {
            return Err(UsageError::ExtraOperand(extra));
        }
        id(first, cmd)
    };
    Ok(match verb {
        b"create" => Command::Create(CreateArgs {
            root,
            id: only_id("create")?,
            bundle,
            pid_file,
        }),
        b"run" => Command::Run(RunArgs {
            id: only_id("run")?,
            bundle,
        }),
        b"start" => Command::Start {
            root,
            id: only_id("start")?,
        },
        b"state" => Command::State {
            root,
            id: only_id("state")?,
        },
        b"kill" => Command::Kill {
            root,
            id: id(first, "kill")?,
            signal: match second {
                None => sig::SIGTERM,
                Some(s) => signal(s).ok_or(UsageError::UnknownSignal(s))?,
            },
            all,
        },
        b"delete" => Command::Delete {
            root,
            id: only_id("delete")?,
            force,
        },
        b"version" => Command::Version,
        b"help" => Command::Help,
        _ => return Err(UsageError::UnknownCommand(cmd)),
    })
}

const SIGNALS: [&[u8]; 31] = [
    b"HUP", b"INT", b"QUIT", b"ILL", b"TRAP", b"ABRT", b"BUS", b"FPE", b"KILL", b"USR1", b"SEGV",
    b"USR2", b"PIPE", b"ALRM", b"TERM", b"STKFLT", b"CHLD", b"CONT", b"STOP", b"TSTP", b"TTIN",
    b"TTOU", b"URG", b"XCPU", b"XFSZ", b"VTALRM", b"PROF", b"WINCH", b"IO", b"PWR", b"SYS",
];

/// A signal by number (1-64) or name, with or without `SIG`.
fn signal(s: &CStr) -> Option<i32> {
    let b = s.to_bytes();
    if let Some(n) = state::parse_u64(b) {
        return (1..=64).contains(&n).then_some(n as i32);
    }
    let name = b.strip_prefix(b"SIG").unwrap_or(b);
    SIGNALS
        .iter()
        .position(|&n| n == name)
        .map(|i| i as i32 + 1)
}

pub const USAGE: &str = "\
zrc - an allocation-free OCI container runtime

usage: zrc [--root dir] <command> [options] <id>

commands:
  create [-b bundle] [--pid-file file] <id>  set up a container, ready to start
  start  <id>                                run the container's process
  state  <id>                                print the OCI state as JSON
  kill   [--all] <id> [signal]               signal the container (default SIGTERM)
  delete [--force] <id>                      remove a stopped container
  run    [-b bundle] <id>                    create, start and wait for exit
  version

global options:
  --root dir         state directory (default /run/zrc)
  --log, --log-format, --debug
                     accepted for runc compatibility; errors go to stderr
";
