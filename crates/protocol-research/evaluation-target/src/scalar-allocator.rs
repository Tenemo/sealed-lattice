//! One bounded system region for the standard library's pinned dlmalloc version.
//! Later allocations reuse that region instead of repeatedly growing Wasm memory.
use core::{
    alloc::{GlobalAlloc, Layout},
    arch::wasm32,
    cell::UnsafeCell,
    ptr,
};

#[cfg(target_feature = "atomics")]
compile_error!("The evaluation allocator requires an unshared scalar Wasm instance.");

pub const MAXIMUM_LINEAR_MEMORY_BYTES: usize = 671_088_640;
const PAGE_BYTES: usize = 65_536;
struct SystemRegion;

// SAFETY: A successful call returns only newly grown, zero-filled Wasm pages.
// The scalar instance cannot interleave another allocation during memory_grow.
// The returned region is page aligned, non-overlapping and below the fixed cap.
unsafe impl dlmalloc::Allocator for SystemRegion {
    fn alloc(&self, size: usize) -> (*mut u8, usize, u32) {
        let previous_pages = wasm32::memory_size(0);
        let maximum_pages = MAXIMUM_LINEAR_MEMORY_BYTES / PAGE_BYTES;
        if previous_pages >= maximum_pages {
            return (ptr::null_mut(), 0, 0);
        }
        let remaining_pages = maximum_pages - previous_pages;
        let available = remaining_pages * PAGE_BYTES;
        if size > available || wasm32::memory_grow(0, remaining_pages) != previous_pages {
            return (ptr::null_mut(), 0, 0);
        }
        ((previous_pages * PAGE_BYTES) as *mut u8, available, 0)
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
// neither yield nor call host imports, so the single worker cannot reenter them.
unsafe impl Sync for ScalarAllocator {}

// SAFETY: Each operation forwards the GlobalAlloc layout and ownership contract
// to the same dlmalloc version used by the pinned Rust toolchain. Only its system
// region acquisition differs; allocation, alignment, reuse and zeroing stay there.
unsafe impl GlobalAlloc for ScalarAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Exclusive scalar access and the caller's valid allocation layout.
        unsafe { (*self.0.get()).malloc(layout.size(), layout.align()) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Same exclusive access; calloc preserves required zero initialization.
        unsafe { (*self.0.get()).calloc(layout.size(), layout.align()) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: The caller supplies a live allocation and its original layout.
        unsafe { (*self.0.get()).free(pointer, layout.size(), layout.align()) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: The caller's original allocation and replacement size satisfy
        // GlobalAlloc; dlmalloc preserves the old allocation when it returns null.
        unsafe { (*self.0.get()).realloc(pointer, layout.size(), layout.align(), size) }
    }
}

#[global_allocator]
static ALLOCATOR: ScalarAllocator = ScalarAllocator(UnsafeCell::new(
    dlmalloc::Dlmalloc::new_with_allocator(SystemRegion),
));
