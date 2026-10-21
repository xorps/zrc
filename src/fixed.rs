//! Fixed-capacity storage: everything zrc holds lives in statics or on the
//! stack, sized to the kernel's own limits where it has one.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::slice;
use core::sync::atomic::{AtomicBool, Ordering};

/// Copies as much of `src` as fits into `dst` and returns the count.
///
/// Unlike `copy_from_slice` it has no length-mismatch panic for the
/// optimizer to leave behind; it still compiles to a `memcpy`.
#[inline]
pub fn copy(dst: &mut [u8], src: &[u8]) -> usize {
    let n = dst.len().min(src.len());
    for (d, s) in dst.iter_mut().zip(src) {
        *d = *s;
    }
    n
}

/// A list was already at capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

/// A vector with inline storage for up to `N` items.
pub struct Fixed<T: Copy, const N: usize> {
    len: usize,
    items: [MaybeUninit<T>; N],
}

impl<T: Copy, const N: usize> Fixed<T, N> {
    pub const CAPACITY: usize = N;

    pub const fn new() -> Self {
        Self {
            len: 0,
            items: [const { MaybeUninit::uninit() }; N],
        }
    }

    #[inline]
    pub fn push(&mut self, item: T) -> Result<(), Full> {
        let slot = self.items.get_mut(self.len).ok_or(Full)?;
        slot.write(item);
        self.len += 1;
        Ok(())
    }

    #[inline]
    pub fn clear(&mut self) {
        self.len = 0;
    }

    #[inline]
    pub fn as_slice(&self) -> &[T] {
        // The first `len` items are initialized.
        unsafe { slice::from_raw_parts(self.items.as_ptr().cast(), self.len) }
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { slice::from_raw_parts_mut(self.items.as_mut_ptr().cast(), self.len) }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn iter(&self) -> slice::Iter<'_, T> {
        self.as_slice().iter()
    }
}

impl<'a, T: Copy, const N: usize> IntoIterator for &'a Fixed<T, N> {
    type Item = &'a T;
    type IntoIter = slice::Iter<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// A static that hands out one `&'static mut` to its contents.
///
/// After `clone3` each process has its own copy, so the reference stays
/// exclusive in the child too.
pub struct Once<T> {
    taken: AtomicBool,
    cell: UnsafeCell<T>,
}

// The contents are only reachable through the single reference `take` hands out.
unsafe impl<T: Send> Sync for Once<T> {}

impl<T> Once<T> {
    pub const fn new(value: T) -> Self {
        Self {
            taken: AtomicBool::new(false),
            cell: UnsafeCell::new(value),
        }
    }

    /// Returns the contents the first time, `None` after that.
    // A `&mut` from `&self` is the point: the flag makes it the only one.
    #[allow(clippy::mut_from_ref)]
    pub fn take(&'static self) -> Option<&'static mut T> {
        if self.taken.swap(true, Ordering::AcqRel) {
            return None;
        }
        Some(unsafe { &mut *self.cell.get() })
    }
}
