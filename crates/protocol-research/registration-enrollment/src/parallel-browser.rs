//! The exports through which a helper instance runs jobs. Every proof crate
//! includes the same job source with the same parameters, so the
//! registration proof's jobs serve every proof kind.
use parallel_work::helper;

/// Bounds a helper instance's memory, before its first allocation, to what
/// one of the helpers needs, with the evaluation's tables and kept keys when
/// the operation evaluates, since only the worker's own instance holds the
/// whole bound. Returns zero when the bound applies.
#[unsafe(no_mangle)]
pub extern "C" fn parallel_reserve(helpers: usize, evaluation: u32) -> u32 {
    let evaluation_bytes = match evaluation {
        0 => 0,
        1 => rns_arithmetic_probe::ranking::helper_memory_bytes(helpers),
        _ => return 1,
    };
    u32::from(!evaluation_target::limit_linear_memory(
        registration_proof::rows::helper_memory_bytes(helpers) + evaluation_bytes,
    ))
}

/// A zeroed input buffer of the length, or zero beyond the job bound.
#[unsafe(no_mangle)]
pub extern "C" fn parallel_input(length: usize) -> usize {
    helper::input(length)
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
