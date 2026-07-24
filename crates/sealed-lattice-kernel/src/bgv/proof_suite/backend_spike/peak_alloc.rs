//! Requested-heap high-water instrument for isolated native diagnostics.
//!
//! A `GlobalAlloc` wrapper over the system allocator that records the peak
//! live allocation size across a measured region. This is exact for requested
//! Rust heap bytes observed by the allocator; it is not process RSS, allocator
//! overhead, or WebAssembly linear-memory evidence. It is compiled only behind
//! the manual research feature and is not a protocol path.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) struct PeakTrackingAllocator;

static CURRENTLY_ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);

fn record_growth(added: usize) {
    let updated = CURRENTLY_ALLOCATED_BYTES.fetch_add(added, Ordering::Relaxed) + added;
    // Monotonic max without a lock: retry until the observed peak is at least
    // the current live total.
    let mut observed_peak = PEAK_ALLOCATED_BYTES.load(Ordering::Relaxed);
    while updated > observed_peak {
        match PEAK_ALLOCATED_BYTES.compare_exchange_weak(
            observed_peak,
            updated,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(seen) => observed_peak = seen,
        }
    }
}

fn record_shrink(removed: usize) {
    CURRENTLY_ALLOCATED_BYTES.fetch_sub(removed, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for PeakTrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_growth(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        record_shrink(layout.size());
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
        if !new_pointer.is_null() {
            if new_size >= layout.size() {
                record_growth(new_size - layout.size());
            } else {
                record_shrink(layout.size() - new_size);
            }
        }
        new_pointer
    }
}

/// Resets the peak to the current live total. Call immediately before a
/// measured region so the reported peak reflects only that region's growth.
pub(crate) fn reset_peak_to_current_live() {
    let live = CURRENTLY_ALLOCATED_BYTES.load(Ordering::Relaxed);
    PEAK_ALLOCATED_BYTES.store(live, Ordering::Relaxed);
}

pub(crate) fn current_live_bytes() -> usize {
    CURRENTLY_ALLOCATED_BYTES.load(Ordering::Relaxed)
}

pub(crate) fn peak_bytes() -> usize {
    PEAK_ALLOCATED_BYTES.load(Ordering::Relaxed)
}

/// Runs `region`, returning its value together with the heap high-water above
/// the live total at entry. The returned peak excludes memory already resident
/// before the region began.
pub(crate) fn measure_peak_delta<T>(region: impl FnOnce() -> T) -> (T, usize) {
    let live_at_entry = current_live_bytes();
    reset_peak_to_current_live();
    let value = region();
    let peak = peak_bytes().saturating_sub(live_at_entry);
    (value, peak)
}
