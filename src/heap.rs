//! A minimal `#[global_allocator]`: a bump allocator over `mmap`'d arenas.
//!
//! `dealloc` is a no-op. That sounds reckless, but `zrc` performs exactly one
//! container operation per process and then exits, so reclaiming memory mid-run
//! buys nothing. This keeps the allocator a few dozen instructions with no
//! free-list bookkeeping. If a long-running mode ever appears, swap this out.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::sys;

const ARENA: usize = 32 * 1024 * 1024; // grow the heap a chunk at a time

struct Region {
    cur: usize,
    end: usize,
}

pub struct Bump {
    locked: AtomicBool,
    region: UnsafeCell<Region>,
}

// Safety: all access to `region` is serialized by the `locked` spinlock.
unsafe impl Sync for Bump {}

impl Bump {
    const fn new() -> Self {
        Bump {
            locked: AtomicBool::new(false),
            region: UnsafeCell::new(Region { cur: 0, end: 0 }),
        }
    }

    #[inline]
    fn lock(&self) {
        while self.locked.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }

    #[inline]
    fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }
}

unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.lock();
        let r = &mut *self.region.get();

        let align = layout.align().max(1);
        let mut p = (r.cur + align - 1) & !(align - 1);

        if p.checked_add(layout.size()).map_or(true, |e| e > r.end) {
            // Exhausted (or first allocation): reserve a fresh arena. We abandon
            // any tail of the previous arena -- acceptable for a bump allocator.
            let want = layout.size().max(ARENA);
            let want = (want + 4095) & !4095;
            match sys::mmap_anon(want) {
                Ok(base) => {
                    r.cur = base as usize;
                    r.end = r.cur + want;
                    p = (r.cur + align - 1) & !(align - 1);
                }
                Err(_) => {
                    self.unlock();
                    return core::ptr::null_mut();
                }
            }
        }

        r.cur = p + layout.size();
        self.unlock();
        p as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // intentionally empty; see module docs.
    }
}

#[global_allocator]
static HEAP: Bump = Bump::new();
