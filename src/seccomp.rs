//! Compiles `linux.seccomp` into a classic BPF program while it is parsed.
//!
//! Layout of the program:
//!
//! ```text
//!   load arch; foreign architecture -> kill process
//!   load nr;   x32 syscall (x86_64, but not -1) -> kill process
//!   rules, first match wins:
//!     no args:   jeq nr1 -> ret | jeq nr2 -> ret | ... ; ja +1 ; ret ACTION
//!     with args: jeq nr else next; <arg checks, any false -> next>; ret ACTION; next: load nr
//!   ret DEFAULT
//! ```
//!
//! Syscall names this architecture lacks are left out of the program, as
//! libseccomp does: profiles list syscalls of every architecture. Only the
//! native architecture is allowed; others (including x86 and x32 on x86_64)
//! are killed.

use xorpio::Errno;
use xorpio::seccomp::{self as sc, SockFilter, bpf, data, ret};
use xorpio::sys::nr;

use crate::fixed::Fixed;
use crate::io::{Msg, Report};
use crate::json::Parser;
use crate::oci::{SpecError, Str};

pub struct Program {
    pub insns: Fixed<SockFilter, { sc::MAX_INSNS }>,
    /// `SECCOMP_FILTER_FLAG_*`.
    pub flags: u32,
}

impl Program {
    pub const fn new() -> Self {
        Self {
            insns: Fixed::new(),
            flags: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CompileError {
    UnknownAction(Str),
    UnknownOperator(Str),
    UnknownFlag(Str),
    /// An argument index outside 0..6.
    ArgIndex(u32),
    /// An errno outside the 16 bits seccomp returns.
    Errno(u32),
    /// More than `BPF_MAXINSNS` instructions.
    TooLarge,
    TooManyNames,
    TooManyArgs,
    /// `SCMP_ACT_NOTIFY` and `listenerPath`: no notification agent support.
    Notify,
    /// Docker profile `includes`/`excludes`, which only Docker resolves.
    Conditional,
}

impl Report for CompileError {
    fn report<const N: usize>(&self, m: &mut Msg<N>) {
        match *self {
            Self::UnknownAction(a) => m.str("unknown action '").cstr(a).str("'"),
            Self::UnknownOperator(o) => m.str("unknown operator '").cstr(o).str("'"),
            Self::UnknownFlag(f) => m.str("unknown flag '").cstr(f).str("'"),
            Self::ArgIndex(i) => m.str("argument index ").u64(i as u64).str(" out of range"),
            Self::Errno(e) => m.str("errnoRet ").u64(e as u64).str(" out of range"),
            Self::TooLarge => m.str("program exceeds 4096 instructions"),
            Self::TooManyNames => m.str("too many names in one rule"),
            Self::TooManyArgs => m.str("too many args in one rule"),
            Self::Notify => m.str("SCMP_ACT_NOTIFY and listenerPath are not supported"),
            Self::Conditional => m.str("rule includes/excludes are not supported"),
        };
    }
}

type Result<T> = core::result::Result<T, SpecError>;

const EPERM: u32 = Errno::EPERM.raw() as u32;
const MAX_RULE_NAMES: usize = 1024;
const MAX_RULE_ARGS: usize = 8;
/// x32 syscalls on x86_64 carry this bit in their number.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

#[derive(Clone, Copy)]
enum Op {
    Ne,
    Lt,
    Le,
    Eq,
    Ge,
    Gt,
    MaskedEq,
}

#[derive(Clone, Copy)]
struct Arg {
    index: u32,
    value: u64,
    value_two: u64,
    op: Op,
}

struct Rule {
    names: Fixed<Str, MAX_RULE_NAMES>,
    action: Option<Str>,
    errno: Option<u32>,
    args: Fixed<Arg, MAX_RULE_ARGS>,
}

fn emit(prog: &mut Program, insn: SockFilter) -> Result<usize> {
    let at = prog.insns.len();
    prog.insns
        .push(insn)
        .map_err(|_full| SpecError::Seccomp(CompileError::TooLarge))?;
    Ok(at)
}

fn action(name: Str, errno: Option<u32>) -> Result<u32> {
    let errno = errno.unwrap_or(EPERM);
    let data = || {
        if errno > 0xffff {
            return Err(SpecError::Seccomp(CompileError::Errno(errno)));
        }
        Ok(errno)
    };
    Ok(match name.to_bytes() {
        b"SCMP_ACT_KILL" | b"SCMP_ACT_KILL_THREAD" => ret::KILL_THREAD,
        b"SCMP_ACT_KILL_PROCESS" => ret::KILL_PROCESS,
        b"SCMP_ACT_TRAP" => ret::TRAP,
        b"SCMP_ACT_ERRNO" => ret::ERRNO | data()?,
        b"SCMP_ACT_TRACE" => ret::TRACE | data()?,
        b"SCMP_ACT_LOG" => ret::LOG,
        b"SCMP_ACT_ALLOW" => ret::ALLOW,
        b"SCMP_ACT_NOTIFY" => return Err(SpecError::Seccomp(CompileError::Notify)),
        _ => return Err(SpecError::Seccomp(CompileError::UnknownAction(name))),
    })
}

/// Compiles the `linux.seccomp` object at `p` into `prog`, which must be empty.
pub fn compile(p: &mut Parser<'static>, prog: &mut Program) -> Result<()> {
    emit(prog, SockFilter::stmt(bpf::LD_W_ABS, data::ARCH))?;
    emit(prog, SockFilter::jump(bpf::JMP_JEQ_K, sc::AUDIT_ARCH, 1, 0))?;
    emit(prog, SockFilter::stmt(bpf::RET_K, ret::KILL_PROCESS))?;
    emit(prog, SockFilter::stmt(bpf::LD_W_ABS, data::NR))?;
    #[cfg(target_arch = "x86_64")]
    {
        // -1 is a syscall a tracer chose to skip, not an x32 one.
        emit(prog, SockFilter::jump(bpf::JMP_JEQ_K, u32::MAX, 2, 0))?;
        emit(
            prog,
            SockFilter::jump(bpf::JMP_JGE_K, X32_SYSCALL_BIT, 0, 1),
        )?;
        emit(prog, SockFilter::stmt(bpf::RET_K, ret::KILL_PROCESS))?;
    }

    let mut default_action = None;
    let mut default_errno = None;
    let mut o = p.object()?;
    while let Some(key) = o.next(p)? {
        match key.to_bytes() {
            b"defaultAction" => default_action = Some(p.str()?),
            b"defaultErrnoRet" => default_errno = Some(p.u32()?),
            b"flags" => {
                let mut a = p.array()?;
                while a.next(p)? {
                    let f = p.str()?;
                    prog.flags |= match f.to_bytes() {
                        b"SECCOMP_FILTER_FLAG_TSYNC" => sc::flag::TSYNC,
                        b"SECCOMP_FILTER_FLAG_LOG" => sc::flag::LOG,
                        b"SECCOMP_FILTER_FLAG_SPEC_ALLOW" => sc::flag::SPEC_ALLOW,
                        b"SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV" => sc::flag::WAIT_KILLABLE_RECV,
                        _ => return Err(SpecError::Seccomp(CompileError::UnknownFlag(f))),
                    };
                }
            }
            b"listenerPath" => {
                if !p.str()?.is_empty() {
                    return Err(SpecError::Seccomp(CompileError::Notify));
                }
            }
            b"syscalls" => {
                let mut a = p.array()?;
                while a.next(p)? {
                    let mut rule = Rule {
                        names: Fixed::new(),
                        action: None,
                        errno: None,
                        args: Fixed::new(),
                    };
                    parse_rule(p, &mut rule)?;
                    emit_rule(prog, &rule)?;
                }
            }
            // `architectures`: only the native one is ever allowed.
            _ => p.skip()?,
        }
    }
    let default = default_action.ok_or(SpecError::Missing("linux.seccomp.defaultAction"))?;
    emit(
        prog,
        SockFilter::stmt(bpf::RET_K, action(default, default_errno)?),
    )?;
    Ok(())
}

fn parse_rule(p: &mut Parser<'static>, rule: &mut Rule) -> Result<()> {
    let mut o = p.object()?;
    while let Some(key) = o.next(p)? {
        match key.to_bytes() {
            b"names" => {
                let mut a = p.array()?;
                while a.next(p)? {
                    let name = p.str()?;
                    rule.names
                        .push(name)
                        .map_err(|_full| SpecError::Seccomp(CompileError::TooManyNames))?;
                }
            }
            b"action" => rule.action = Some(p.str()?),
            b"errnoRet" => rule.errno = Some(p.u32()?),
            b"args" => {
                let mut a = p.array()?;
                while a.next(p)? {
                    let arg = parse_arg(p)?;
                    rule.args
                        .push(arg)
                        .map_err(|_full| SpecError::Seccomp(CompileError::TooManyArgs))?;
                }
            }
            b"includes" | b"excludes" => {
                let mut c = p.object()?;
                if c.next(p)?.is_some() {
                    return Err(SpecError::Seccomp(CompileError::Conditional));
                }
            }
            _ => p.skip()?,
        }
    }
    Ok(())
}

fn parse_arg(p: &mut Parser<'static>) -> Result<Arg> {
    let mut arg = Arg {
        index: 0,
        value: 0,
        value_two: 0,
        op: Op::Eq,
    };
    let mut op = None;
    let mut o = p.object()?;
    while let Some(key) = o.next(p)? {
        match key.to_bytes() {
            b"index" => {
                arg.index = p.u32()?;
                if arg.index > 5 {
                    return Err(SpecError::Seccomp(CompileError::ArgIndex(arg.index)));
                }
            }
            b"value" => arg.value = p.u64()?,
            b"valueTwo" => arg.value_two = p.u64()?,
            b"op" => {
                let name = p.str()?;
                op = Some(match name.to_bytes() {
                    b"SCMP_CMP_NE" => Op::Ne,
                    b"SCMP_CMP_LT" => Op::Lt,
                    b"SCMP_CMP_LE" => Op::Le,
                    b"SCMP_CMP_EQ" => Op::Eq,
                    b"SCMP_CMP_GE" => Op::Ge,
                    b"SCMP_CMP_GT" => Op::Gt,
                    b"SCMP_CMP_MASKED_EQ" => Op::MaskedEq,
                    _ => return Err(SpecError::Seccomp(CompileError::UnknownOperator(name))),
                });
            }
            _ => p.skip()?,
        }
    }
    arg.op = op.ok_or(SpecError::Missing("linux.seccomp.syscalls[].args[].op"))?;
    Ok(arg)
}

fn emit_rule(prog: &mut Program, rule: &Rule) -> Result<()> {
    let action = action(
        rule.action
            .ok_or(SpecError::Missing("linux.seccomp.syscalls[].action"))?,
        rule.errno,
    )?;
    let numbers = rule
        .names
        .iter()
        .filter_map(|name| nr::by_name(name.to_bytes()))
        // Syscall numbers are below 1024 on every architecture.
        .map(|n| n as u32);

    if rule.args.is_empty() {
        // Up to 255 compares jump to one shared return.
        let mut chunk = Fixed::<u32, 255>::new();
        for n in numbers {
            if chunk.push(n).is_err() {
                emit_chunk(prog, chunk.as_slice(), action)?;
                chunk = Fixed::new();
                chunk
                    .push(n)
                    .map_err(|_full| SpecError::Seccomp(CompileError::TooManyNames))?;
            }
        }
        if !chunk.is_empty() {
            emit_chunk(prog, chunk.as_slice(), action)?;
        }
        return Ok(());
    }

    for n in numbers {
        let mut fails = Fixed::<(usize, bool), { MAX_RULE_ARGS * 3 + 1 }>::new();
        let mut fail = |prog: &mut Program, insn: SockFilter, on_true: bool| -> Result<()> {
            let at = emit(prog, insn)?;
            fails
                .push((at, on_true))
                .map_err(|_full| SpecError::Seccomp(CompileError::TooManyArgs))
        };
        fail(prog, SockFilter::jump(bpf::JMP_JEQ_K, n, 0, 0), false)?;
        for arg in &rule.args {
            emit_arg(prog, arg, &mut fail)?;
        }
        emit(prog, SockFilter::stmt(bpf::RET_K, action))?;
        let next = emit(prog, SockFilter::stmt(bpf::LD_W_ABS, data::NR))?;
        for &(at, on_true) in fails.iter() {
            let offset = u8::try_from(next - at - 1)
                .map_err(|_too_far| SpecError::Seccomp(CompileError::TooLarge))?;
            if let Some(insn) = prog.insns.as_mut_slice().get_mut(at) {
                if on_true {
                    insn.jt = offset;
                } else {
                    insn.jf = offset;
                }
            }
        }
    }
    Ok(())
}

/// `jeq n_i -> ret` for each number, falling through to `ja +1` past the `ret`.
fn emit_chunk(prog: &mut Program, numbers: &[u32], action: u32) -> Result<()> {
    let k = numbers.len();
    for (i, &n) in numbers.iter().enumerate() {
        // From compare i, the return is at k + 1; jumps count from i + 1.
        let jt =
            u8::try_from(k - i).map_err(|_too_far| SpecError::Seccomp(CompileError::TooLarge))?;
        emit(prog, SockFilter::jump(bpf::JMP_JEQ_K, n, jt, 0))?;
    }
    emit(prog, SockFilter::stmt(bpf::JMP_JA, 1))?;
    emit(prog, SockFilter::stmt(bpf::RET_K, action))?;
    Ok(())
}

/// Emits a 64-bit comparison of argument `arg.index` as 32-bit halves. The
/// condition holding falls through; failing jumps go through `fail`, which
/// records them for patching to the next rule.
fn emit_arg(
    prog: &mut Program,
    arg: &Arg,
    fail: &mut impl FnMut(&mut Program, SockFilter, bool) -> Result<()>,
) -> Result<()> {
    let hi = |v: u64| (v >> 32) as u32;
    let lo = |v: u64| v as u32;
    let ld_hi = SockFilter::stmt(bpf::LD_W_ABS, data::arg_hi(arg.index));
    let ld_lo = SockFilter::stmt(bpf::LD_W_ABS, data::arg_lo(arg.index));
    let v = arg.value;
    match arg.op {
        Op::Eq => {
            emit(prog, ld_hi)?;
            fail(prog, SockFilter::jump(bpf::JMP_JEQ_K, hi(v), 0, 0), false)?;
            emit(prog, ld_lo)?;
            fail(prog, SockFilter::jump(bpf::JMP_JEQ_K, lo(v), 0, 0), false)?;
        }
        Op::Ne => {
            emit(prog, ld_hi)?;
            // High halves differ: the condition holds, skip the low check.
            emit(prog, SockFilter::jump(bpf::JMP_JEQ_K, hi(v), 0, 2))?;
            emit(prog, ld_lo)?;
            fail(prog, SockFilter::jump(bpf::JMP_JEQ_K, lo(v), 0, 0), true)?;
        }
        Op::Gt | Op::Ge => {
            let cmp = if matches!(arg.op, Op::Gt) {
                bpf::JMP_JGT_K
            } else {
                bpf::JMP_JGE_K
            };
            emit(prog, ld_hi)?;
            // High half greater: holds, skip to the end.
            emit(prog, SockFilter::jump(bpf::JMP_JGT_K, hi(v), 3, 0))?;
            fail(prog, SockFilter::jump(bpf::JMP_JEQ_K, hi(v), 0, 0), false)?;
            emit(prog, ld_lo)?;
            fail(prog, SockFilter::jump(cmp, lo(v), 0, 0), false)?;
        }
        Op::Lt | Op::Le => {
            // Lt fails when lo >= v, Le when lo > v.
            let cmp = if matches!(arg.op, Op::Lt) {
                bpf::JMP_JGE_K
            } else {
                bpf::JMP_JGT_K
            };
            emit(prog, ld_hi)?;
            fail(prog, SockFilter::jump(bpf::JMP_JGT_K, hi(v), 0, 0), true)?;
            // High half smaller: holds, skip the low check.
            emit(prog, SockFilter::jump(bpf::JMP_JEQ_K, hi(v), 0, 2))?;
            emit(prog, ld_lo)?;
            fail(prog, SockFilter::jump(cmp, lo(v), 0, 0), true)?;
        }
        Op::MaskedEq => {
            let mask = v;
            let want = arg.value_two;
            emit(prog, ld_hi)?;
            emit(prog, SockFilter::stmt(bpf::ALU_AND_K, hi(mask)))?;
            fail(
                prog,
                SockFilter::jump(bpf::JMP_JEQ_K, hi(want), 0, 0),
                false,
            )?;
            emit(prog, ld_lo)?;
            emit(prog, SockFilter::stmt(bpf::ALU_AND_K, lo(mask)))?;
            fail(
                prog,
                SockFilter::jump(bpf::JMP_JEQ_K, lo(want), 0, 0),
                false,
            )?;
        }
    }
    Ok(())
}

/// Installs the program on the calling thread. Without no_new_privs this
/// needs `CAP_SYS_ADMIN`.
pub fn install(prog: &Program) -> core::result::Result<(), Errno> {
    sc::set_mode_filter(prog.flags, prog.insns.as_slice()).map(drop)
}
