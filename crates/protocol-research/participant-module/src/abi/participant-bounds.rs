//! The participant bounds and each operation's memory plan.
use std::cell::RefCell;
use supported_profile::Profile;

thread_local! {static OUTPUT: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };}

fn publish(values: Vec<u64>) -> usize {
    OUTPUT.with(|output| {
        let count = values.len();
        *output.borrow_mut() = values;
        count
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn participant_bounds_pointer() -> usize {
    OUTPUT.with(|output| output.borrow().as_ptr() as usize)
}

/// Writes the shared bounds and returns their count of 64-bit words.
#[unsafe(no_mangle)]
pub extern "C" fn participant_limits() -> usize {
    publish(crate::participant_bounds::limits())
}

/// Writes a supported profile's bounds and returns their count of
/// 64-bit words, or zero for an unsupported profile.
#[unsafe(no_mangle)]
pub extern "C" fn participant_profile_bounds(participants: usize, options: usize) -> usize {
    Profile::new(participants, options).map_or_else(
        |_| publish(Vec::new()),
        |profile| publish(crate::participant_bounds::profile_bounds(profile)),
    )
}

/// The highest linear-memory address any allocation of this instance has
/// reached, which the worker reports with each operation.
#[unsafe(no_mangle)]
pub extern "C" fn linear_memory_high_water() -> usize {
    parallel_work::scalar_allocator::linear_memory_high_water()
}

// An operation's memory plan with the helpers, which evaluates the
// ranking program when `evaluation` is one.
fn plan(helpers: usize, evaluation: u32, share: fn(usize, bool) -> Option<usize>) -> usize {
    match evaluation {
        0 | 1 => share(helpers, evaluation == 1).unwrap_or(0),
        _ => 0,
    }
}

/// The bound of each helper of an operation with the helpers, or zero
/// without a plan. It allocates nothing.
#[unsafe(no_mangle)]
pub extern "C" fn helper_memory_bound(helpers: usize, evaluation: u32) -> usize {
    plan(helpers, evaluation, crate::memory_plan::helper_memory_bytes)
}

/// The bound of the worker of an operation with the helpers, or zero
/// without a plan. It allocates nothing.
#[unsafe(no_mangle)]
pub extern "C" fn worker_memory_bound(helpers: usize, evaluation: u32) -> usize {
    plan(helpers, evaluation, crate::memory_plan::worker_memory_bytes)
}

/// Bounds the worker's instance, before its first allocation, to its
/// share of the operation's memory plan. Returns zero when the bound
/// applies.
#[unsafe(no_mangle)]
pub extern "C" fn worker_reserve(helpers: usize, evaluation: u32) -> u32 {
    let bytes = worker_memory_bound(helpers, evaluation);
    u32::from(bytes == 0 || !parallel_work::scalar_allocator::limit_linear_memory(bytes))
}
