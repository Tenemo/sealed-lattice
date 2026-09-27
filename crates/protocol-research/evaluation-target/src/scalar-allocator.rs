//! A bounded system region for the standard library's pinned dlmalloc version.
//! The region grows as its allocations need it, each growth adding the
//! request or, when more, an eighth of its held pages, so its growths stay
//! few and it stays near what its allocations use. A growth in Chrome
//! briefly commits about as much again as the region already holds, so an
//! operation that knows what it will add plans it beside the bytes its live
//! allocations hold, and the next growth reaches that total at once rather
//! than adding it to memory that is already free. A helper instance lowers
//! its bound, which its jobs set, before its first allocation. An allocation
//! that finds no memory within the bound hands the call to the host, which
//! ends it, so the host tells exhaustion apart from a trap.
use core::{
    alloc::{GlobalAlloc, Layout},
    arch::wasm32,
    cell::UnsafeCell,
    ptr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[cfg(target_feature = "atomics")]
compile_error!("The evaluation allocator requires an unshared scalar Wasm instance.");

pub const MAXIMUM_LINEAR_MEMORY_BYTES: usize = 671_088_640;
const PAGE_BYTES: usize = 65_536;
/// The fewest pages a growing region adds at once.
const MINIMUM_GROWTH_PAGES: usize = 16;
// The instance's memory bound, which a helper instance lowers before its
// first allocation starts the region.
static LINEAR_MEMORY_BYTES: AtomicUsize = AtomicUsize::new(MAXIMUM_LINEAR_MEMORY_BYTES);
static ACQUIRED: AtomicBool = AtomicBool::new(false);
// The pages a growth brings the region to at least, which an operation's
// plan sets.
static PLANNED_PAGES: AtomicUsize = AtomicUsize::new(0);
// The bytes the instance's live allocations hold.
static LIVE: AtomicUsize = AtomicUsize::new(0);
// The highest address, exclusive, that any allocation has reached.
static HIGH_WATER: AtomicUsize = AtomicUsize::new(0);

/// The highest linear-memory address, exclusive, that any allocation of the
/// instance has reached: how much of its region the instance has used.
pub fn linear_memory_high_water() -> usize {
    HIGH_WATER.load(Ordering::Relaxed)
}

/// Lowers the instance's memory bound to whole pages before its first
/// allocation. Returns whether the bound applies.
pub fn limit_linear_memory(bytes: usize) -> bool {
    if ACQUIRED.load(Ordering::Relaxed)
        || bytes > MAXIMUM_LINEAR_MEMORY_BYTES
        || !bytes.is_multiple_of(PAGE_BYTES)
    {
        return false;
    }
    LINEAR_MEMORY_BYTES.store(bytes, Ordering::Relaxed);
    true
}

/// Plans the instance's memory: a growth brings the region at least to the
/// bytes its live allocations now hold and the planned bytes, within its
/// bound.
pub fn plan_linear_memory(bytes: usize) {
    let total = LIVE.load(Ordering::Relaxed).saturating_add(bytes);
    PLANNED_PAGES.store(total.div_ceil(PAGE_BYTES), Ordering::Relaxed);
}

#[link(wasm_import_module = "allocator")]
unsafe extern "C" {
    /// Ends the instance's current call after an allocation of the bytes
    /// found no memory within the bound. It never returns.
    fn exhausted(bytes: usize);
}

// Returns an allocation after recording its end, or ends the call when
// there was no memory for it.
fn available(pointer: *mut u8, bytes: usize) -> *mut u8 {
    if pointer.is_null() {
        // SAFETY: The import takes one integer and never returns.
        unsafe { exhausted(bytes) };
        wasm32::unreachable();
    }
    let end = pointer as usize + bytes;
    if end > HIGH_WATER.load(Ordering::Relaxed) {
        HIGH_WATER.store(end, Ordering::Relaxed);
    }
    pointer
}

struct SystemRegion;

// SAFETY: A successful call returns only newly grown, zero-filled Wasm pages.
// The scalar instance cannot interleave another allocation during memory_grow.
// The returned region is page aligned, non-overlapping, at least the request
// and below the fixed cap; dlmalloc joins it to the region that ends where it
// begins.
unsafe impl dlmalloc::Allocator for SystemRegion {
    fn alloc(&self, size: usize) -> (*mut u8, usize, u32) {
        ACQUIRED.store(true, Ordering::Relaxed);
        let previous_pages = wasm32::memory_size(0);
        let maximum_pages = LINEAR_MEMORY_BYTES.load(Ordering::Relaxed) / PAGE_BYTES;
        if previous_pages >= maximum_pages {
            return (ptr::null_mut(), 0, 0);
        }
        let remaining_pages = maximum_pages - previous_pages;
        let requested_pages = size.div_ceil(PAGE_BYTES);
        if requested_pages > remaining_pages {
            return (ptr::null_mut(), 0, 0);
        }
        let planned = PLANNED_PAGES.load(Ordering::Relaxed);
        let pages = if planned > previous_pages {
            requested_pages.max(planned - previous_pages)
        } else {
            requested_pages.max(previous_pages / 8)
        }
        .max(MINIMUM_GROWTH_PAGES)
        .min(remaining_pages);
        if wasm32::memory_grow(0, pages) != previous_pages {
            return (ptr::null_mut(), 0, 0);
        }
        (
            (previous_pages * PAGE_BYTES) as *mut u8,
            pages * PAGE_BYTES,
            0,
        )
    }
    fn remap(&self, _pointer: *mut u8, _old: usize, _new: usize, _can_move: bool) -> *mut u8 {
        ptr::null_mut()
    }
    fn free_part(&self, _pointer: *mut u8, _old: usize, _new: usize) -> bool {
        false
    }
    fn free(&self, _pointer: *mut u8, _size: usize) -> bool {
        false
    }
    fn can_release_part(&self, _flags: u32) -> bool {
        false
    }
    fn allocates_zeros(&self) -> bool {
        true
    }
    fn page_size(&self) -> usize {
        PAGE_BYTES
    }
}

struct ScalarAllocator(UnsafeCell<dlmalloc::Dlmalloc<SystemRegion>>);
// SAFETY: Atomics/shared-memory builds are rejected above. Allocator operations
// never yield, and the one import they call, once no memory is left, never
// returns into the instance, so the single worker cannot reenter them.
unsafe impl Sync for ScalarAllocator {}

// SAFETY: Each operation forwards the GlobalAlloc layout and ownership contract
// to the same dlmalloc version used by the pinned Rust toolchain. Only its system
// region acquisition differs; allocation, alignment, reuse and zeroing stay there.
unsafe impl GlobalAlloc for ScalarAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Exclusive scalar access and the caller's valid allocation layout.
        let pointer = unsafe { (*self.0.get()).malloc(layout.size(), layout.align()) };
        let pointer = available(pointer, layout.size());
        LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Same exclusive access; calloc preserves required zero initialization.
        let pointer = unsafe { (*self.0.get()).calloc(layout.size(), layout.align()) };
        let pointer = available(pointer, layout.size());
        LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: The caller supplies a live allocation and its original layout.
        unsafe { (*self.0.get()).free(pointer, layout.size(), layout.align()) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: The caller's original allocation and replacement size satisfy
        // GlobalAlloc; dlmalloc preserves the old allocation when it returns null.
        let moved =
            unsafe { (*self.0.get()).realloc(pointer, layout.size(), layout.align(), size) };
        let moved = available(moved, size);
        LIVE.fetch_add(size, Ordering::Relaxed);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        moved
    }
}

#[global_allocator]
static ALLOCATOR: ScalarAllocator = ScalarAllocator(UnsafeCell::new(
    dlmalloc::Dlmalloc::new_with_allocator(SystemRegion),
));
