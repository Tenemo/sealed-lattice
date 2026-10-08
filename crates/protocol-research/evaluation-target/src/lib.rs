#![deny(unsafe_op_in_unsafe_fn)]
pub mod certification;
pub mod close;
#[path = "close-session.rs"]
pub mod close_session;
#[path = "completion-session.rs"]
pub mod completion_session;
mod interpolation;
pub mod program;
pub mod release;
#[path = "release-body.rs"]
pub mod release_body;
pub mod target;
#[path = "target-session.rs"]
pub mod target_session;
pub mod terminal;

/// Plans a helper instance's memory for the evaluation's jobs: a growth
/// brings it to the bytes its live allocations hold and the bytes its input
/// names, so its memory grows once to what those jobs hold rather than
/// beside memory it already has free.
pub static PLAN: parallel_work::Job = parallel_work::Job {
    kind: 0x0700,
    run: plan,
};
fn plan(input: &[u8]) -> Vec<u8> {
    let bytes = u64::from_le_bytes(input.try_into().expect("Planned length"));
    #[cfg(target_arch = "wasm32")]
    parallel_work::scalar_allocator::plan_linear_memory(bytes as usize);
    #[cfg(not(target_arch = "wasm32"))]
    let _ = bytes;
    Vec::new()
}
/// The jobs this crate defines.
pub static JOBS: [&parallel_work::Job; 1] = [&PLAN];

/// Each coefficient of a stored working value of the evaluation takes this
/// many bytes: its whole little-endian words.
pub fn stored_coefficient_bytes(profile: supported_profile::Profile) -> usize {
    encrypted_ranking::ranking::stored_value_bytes(profile)
        / (2 * encrypted_ranking::ranking::DEGREE)
}
