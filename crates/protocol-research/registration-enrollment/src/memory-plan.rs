//! The linear-memory plan of an operation's instances, which together stay
//! within the absolute bound. Each helper keeps the state its jobs share,
//! the rows of the proof shards it holds or, when the operation evaluates
//! the ranking program, the larger of those and the evaluation's kept
//! memory, since one worker's jobs either evaluate or prove, beside one
//! job's memory. The worker keeps what its helpers leave. Each instance
//! lowers its bound to its share before its first allocation, so an
//! operation that needs more ends pending rather than growing beyond it.
use parallel_work::{JOB_MEMORY_BYTES, MAXIMUM_HELPERS, MAXIMUM_LINEAR_MEMORY_BYTES, PAGE_BYTES};

/// The bound of each of an operation's helpers, or none beyond the most
/// helpers an operation starts.
pub fn helper_memory_bytes(helpers: usize, evaluation: bool) -> Option<usize> {
    if helpers == 0 || helpers > MAXIMUM_HELPERS {
        return None;
    }
    let rows = word_proof::rows::helper_rows_bytes(helpers);
    let kept = if evaluation {
        rns_arithmetic_probe::ranking::helper_memory_bytes(helpers)
    } else {
        0
    };
    Some((rows.max(kept) + JOB_MEMORY_BYTES).next_multiple_of(PAGE_BYTES))
}
/// The bound of an operation's worker beside its helpers: what they leave
/// of the absolute bound.
pub fn worker_memory_bytes(helpers: usize, evaluation: bool) -> Option<usize> {
    if helpers == 0 {
        return Some(MAXIMUM_LINEAR_MEMORY_BYTES);
    }
    MAXIMUM_LINEAR_MEMORY_BYTES.checked_sub(helpers * helper_memory_bytes(helpers, evaluation)?)
}

#[cfg(test)]
#[path = "memory-plan-tests.rs"]
mod tests;
