//! The exports through which a helper instance runs jobs. Every proof crate
//! includes the same job source with the same parameters, so the
//! registration proof's jobs serve every proof kind.
use parallel_work::helper;

/// Bounds a helper instance's memory, before its first allocation, to its
/// share of the memory plan of an operation with the helpers, which
/// evaluates the ranking program when `evaluation` is one. Returns zero
/// when the bound applies.
#[unsafe(no_mangle)]
pub extern "C" fn parallel_reserve(helpers: usize, evaluation: u32) -> u32 {
    let bytes = match evaluation {
        0 | 1 => crate::memory_plan::helper_memory_bytes(helpers, evaluation == 1),
        _ => None,
    };
    u32::from(!bytes.is_some_and(evaluation_target::limit_linear_memory))
}

/// A zeroed input buffer of the length, or zero beyond the job bound.
#[unsafe(no_mangle)]
pub extern "C" fn parallel_input(length: usize) -> usize {
    helper::input(length)
}

/// Names the length of the next job's streamed part, which the host serves
/// as the job reads it; zero beyond the job bound.
#[unsafe(no_mangle)]
pub extern "C" fn parallel_streamed(length: usize) -> u32 {
    helper::streamed(length)
}

/// Runs the job of the kind on the input; one for an unknown kind.
#[unsafe(no_mangle)]
pub extern "C" fn parallel_run(kind: u32) -> u32 {
    helper::run(
        &[
            &parallel_work::JOBS,
            &registration_credentials::JOBS,
            &registration_proof::jobs::JOBS,
            &setup_stream_kernel::JOBS,
            &setup_witness::JOBS,
            &rns_arithmetic_probe::JOBS,
            &evaluation_target::JOBS,
        ],
        kind,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn parallel_output_pointer() -> usize {
    helper::output_pointer()
}

#[unsafe(no_mangle)]
pub extern "C" fn parallel_output_length() -> usize {
    helper::output_length()
}

/// Clears and releases the job's buffers.
#[unsafe(no_mangle)]
pub extern "C" fn parallel_clear() {
    helper::clear()
}
