//! Per-architecture syscall ABI and process entry point.
//!
//! Each submodule exposes the same surface:
//!   * `syscall0`..`syscall6` — raw syscall instruction wrappers
//!   * a `nr` module of syscall numbers (these differ per arch!)
//!   * the `_start` entry symbol (via `global_asm!`) which tail-calls
//!     `crate::rust_start(stack_top)`.

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;
